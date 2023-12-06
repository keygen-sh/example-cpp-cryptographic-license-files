#include "include/ed25519/ed25519.h"
#include "include/sha256/sha256.h"
#include "include/base64/base64.h"
#include "include/json/picojson.h"
#include <openssl/ssl.h>
#include <stdlib.h>
#include <assert.h>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>

// We don't need Ed25519 key generation
#define ED25519_NO_SEED

// split splits a string by delimiter into a vector of strings.
inline std::vector<std::string> split(std::string str, std::string delim, int n = 0)
{
  std::vector<std::string> vec;
  size_t pos;

  // Keep track of iterations for n
  int i = 0;

  while ((n == 0 || (n > 0 && i < n - 1)) && (pos = str.find(delim)) != std::string::npos)
  {
    vec.push_back(str.substr(0, pos));

    str = str.substr(pos + delim.size());

    i++;
  }

  vec.push_back(str); // Last word

  return vec;
}

// unhex convert a hex string to raw bytes.
inline void unhex(std::string str, unsigned char* bytes)
{
  std::stringstream converter;

  for (int i = 0; i < str.size(); i += 2)
  {
    int byte;

    converter << std::hex << str.substr(i, 2);
    converter >> byte;

    bytes[i / 2] = byte & 0xff;

    converter.str(std::string());
    converter.clear();
  }
}

// colorize adds ANSII color codes to a string.
inline std::string colorize(const std::string str, const int color_code)
{
  std::stringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// timetostr converts a time_t to an iso8601 formatted string.
std::string timetostr(const std::time_t t) {
  char buf[sizeof "2022-08-08T01:02:03Z"];

  strftime(buf, sizeof buf, "%FT%TZ", gmtime(&t));

  return std::string(buf);
}

// strtotime converts an iso8601 formatted string to a time_t.
std::time_t strtotime(const std::string s) {
  std::tm t {};

  strptime(s.c_str(), "%FT%T%z", &t);

  return timegm(&t);
}

// license_file represents a Keygen license file resource.
struct license_file
{
  std::string enc;
  std::string sig;
  std::string alg;
};

// entitlement represents a Keygen entitlement resource.
struct entitlement
{
  std::string id;
  std::string name;
  std::string code;
};

// product represents a Keygen product resource.
struct product
{
  std::string id;
  std::string name;
};

// policy represents a Keygen policy resource.
struct policy
{
  std::string id;
  std::string name;
};

// user represents a Keygen user resource.
struct user
{
  std::string id;
  std::string first_name;
  std::string last_name;
  std::string email;
  std::string status;
};

// license represents a Keygen license resource.
struct license
{
  std::string id;
  std::string name;
  std::string key;
  std::string status;
  std::time_t last_validated_at;
  std::time_t expires_at;
  std::time_t created_at;
  std::time_t updated_at;
  std::vector<entitlement> entitlements;
  struct product product;
  struct policy policy;
  struct user user;
};

// is_empty checks if the provided type is empty, used for structs.
template <typename T>
bool is_empty(T data) {
  auto mm = (unsigned char*) &data;
  return (*mm == 0) && memcmp(mm, mm + 1, sizeof(T) - 1) == 0;
}

// decode_license_file decodes a license file certificate into a JSON string.
std::string decode_license_file(const std::string cert)
{
  int size;

  // Remove header, footer and newlines
  std::string prefix = "-----BEGIN LICENSE FILE-----\n";
  std::string suffix = "-----END LICENSE FILE-----\n";

  std::string enc = cert.substr(prefix.length());
  enc = enc.substr(0, enc.length() - suffix.length());
  enc.erase(std::remove(enc.begin(), enc.end(), '\n'), enc.end());

  // Decode
  auto dec = unbase64(enc.c_str(), enc.size(), &size);
  std::string str(dec, dec + size);

  return str;
}

// import_license_file imports a license file from path and parses into in a license_file struct.
license_file import_license_file(const std::string path)
{
  license_file lic {};

  // Read path
  std::stringstream buf;
  std::ifstream f(path);
  buf << f.rdbuf();
  auto enc = buf.str();

  // Decode contents
  auto dec = decode_license_file(enc);
  if (dec.empty())
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Failed to decode license file"
              << std::endl;

    return lic;
  }

  // Parse JSON
  picojson::value value;

  auto err = picojson::parse(value, dec);
  if (!err.empty())
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Failed to parse license file: " << err
              << std::endl;

    return lic;
  }

  lic.enc = value.get("enc").to_str();
  lic.sig = value.get("sig").to_str();
  lic.alg = value.get("alg").to_str();

  return lic;
}

// verify_license_file verifies a license file using Ed25519.
bool verify_license_file(const std::string pubkey, license_file lic)
{
  if (lic.alg != "aes-256-gcm+ed25519")
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Unsupported license file algorithm '" << lic.alg << "'"
              << std::endl;

    return false;
  }

  // Convert signing data into bytes
  auto data = "license/" + lic.enc;
  auto data_bytes = reinterpret_cast<const unsigned char*>(data.c_str());
  auto data_size = data.size();

  // Decode signature into bytes
  auto sig = lic.sig;
  int sig_size;

  unsigned char* sig_bytes = unbase64(sig.c_str(), sig.size(), &sig_size);

  // Decode hex public key into bytes
  unsigned char key_bytes[32];

  unhex(pubkey, key_bytes);

  // Verify signature
  auto ok = ed25519_verify(sig_bytes, data_bytes, data_size, key_bytes);

  return (bool) ok;
}

// decrypt_license_file decrypts a license file with AES-256-GCM, returning the decrypted plaintext.
std::string decrypt_license_file(const std::string key, license_file lic)
{
  // Hash license key to get encryption key
  uint8_t key_bytes[32];

  sha256_easy_hash(key.c_str(), key.size(), key_bytes);

  // Parse the encoded data
  auto parts = split(lic.enc, ".", 3);
  auto ciphertext = parts.at(0);
  auto iv = parts.at(1);
  auto tag = parts.at(2);

  // Convert to bytes
  int ciphertext_size;
  int plaintext_size;
  int iv_size;
  int tag_size;
  int aes_size;

  auto ciphertext_bytes = unbase64(ciphertext.c_str(), ciphertext.size(), &ciphertext_size);
  auto iv_bytes = unbase64(iv.c_str(), iv.size(), &iv_size);
  auto tag_bytes = unbase64(tag.c_str(), tag.size(), &tag_size);
  auto plaintext_bytes = new unsigned char[ciphertext_size];

  // Initialize AES
  auto cipher = EVP_aes_256_gcm();
  auto ctx = EVP_CIPHER_CTX_new();

  // Decrypt
  EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, nullptr);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, tag_bytes);

  auto status = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_bytes, iv_bytes);
  if (status == 0)
  {
    return "";
  }

  status = EVP_DecryptUpdate(ctx, plaintext_bytes, &aes_size, ciphertext_bytes, ciphertext_size);
  if (status == 0)
  {
    return "";
  }

  // Finalize
  EVP_DecryptFinal_ex(ctx, nullptr, &aes_size);
  EVP_CIPHER_CTX_free(ctx);

  // Convert plaintext to string
  std::string plaintext(plaintext_bytes, plaintext_bytes + ciphertext_size);
  delete[] plaintext_bytes;

  return plaintext;
}

// parse_license parses a JSON string into a license struct.
license parse_license(const std::string dec)
{
  picojson::value value;
  license lcs {};

  auto err = picojson::parse(value, dec);
  if (!err.empty())
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Failed to parse license: " << err
              << std::endl;

    return lcs;
  }

  auto meta = value.get("meta");
  auto issued_at = strtotime(meta.get("issued").to_str());
  auto now = time(0);

  // Assert that current system time is not in the past.
  if (now < issued_at)
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "System clock is desynced!"
              << std::endl;

    return lcs;
  }

  auto ttl = meta.get("ttl");
  if (ttl.is<double>())
  {
    auto expires_at = strtotime(meta.get("expiry").to_str());

    // Assert that license file has not expired.
    if (now > expires_at)
    {
      std::cerr << colorize("[ERROR]", 31) << " "
                << "License file has expired!"
                << std::endl;

      return lcs;
    }
  }

  auto data = value.get("data");
  auto attrs = data.get("attributes");

  lcs.id = data.get("id").to_str();
  lcs.name = attrs.get("name").to_str();
  lcs.key = attrs.get("key").to_str();
  lcs.status = attrs.get("status").to_str();
  lcs.last_validated_at = strtotime(attrs.get("lastValidated").to_str());
  lcs.expires_at = strtotime(attrs.get("expiry").to_str());
  lcs.created_at = strtotime(attrs.get("created").to_str());
  lcs.updated_at = strtotime(attrs.get("updated").to_str());

  auto included = value.get("included");
  if (included.is<picojson::array>())
  {
    for (const auto &incl: included.get<picojson::array>())
    {
      auto type = incl.get("type").to_str();
      auto id = incl.get("id").to_str();
      auto attrs = incl.get("attributes");

      if (type == "entitlements")
      {
        entitlement entl {id};

        entl.name = attrs.get("name").to_str();
        entl.code = attrs.get("code").to_str();

        lcs.entitlements.push_back(entl);
      }

      if (type == "products")
      {
        product prod {id};

        prod.name = attrs.get("name").to_str();

        lcs.product = prod;
      }

      if (type == "policies")
      {
        policy pol {id};

        pol.name = attrs.get("name").to_str();

        lcs.policy = pol;
      }

      if (type == "users")
      {
        user usr {id};

        usr.first_name = attrs.get("firstName").to_str();
        usr.last_name = attrs.get("lastName").to_str();
        usr.email = attrs.get("email").to_str();
        usr.status = attrs.get("status").to_str();

        lcs.user = usr;
      }
    }
  }

  return lcs;
}

// main runs the example program.
int main(int argc, char* argv[])
{
  if (argc != 2)
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "No path given"
              << std::endl;

    return 1;
  }

  if (!getenv("KEYGEN_PUBLIC_KEY"))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_PUBLIC_KEY is missing"
              << std::endl;

    return 1;
  }

  if (!getenv("KEYGEN_LICENSE_KEY"))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_LICENSE_KEY is missing"
              << std::endl;

    return 1;
  }

  std::string pubkey = getenv("KEYGEN_PUBLIC_KEY");
  std::string secret = getenv("KEYGEN_LICENSE_KEY");
  std::string path = argv[1];

  std::cout << colorize("[INFO]", 34) << " "
              << "Importing..."
              << std::endl;

  auto lic = import_license_file(path);
  if (is_empty<license_file>(lic))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Path '" << path << "' is not a valid license file"
              << std::endl;

    return 1;
  }

  std::cout << colorize("[OK]", 32) << " "
            << "License file successfully imported!" << std::endl;

  std::cout << colorize("[INFO]", 34) << " "
              << "Verifying..."
              << std::endl;

  // Verify the license file signature
  auto ok = verify_license_file(pubkey, lic);
  if (ok)
  {
    std::cout << colorize("[OK]", 32) << " "
              << "License file successfully verified!"
              << std::endl;

    std::cout << colorize("[INFO]", 34) << " "
              << "Decrypting..."
              << std::endl;

    // Decrypt the license file
    auto dec = decrypt_license_file(secret, lic);
    if (dec.empty() || dec.at(0) != '{')
    {
      std::cerr << colorize("[ERROR]", 31) << " "
                << "Failed to decrypt license file!"
                << std::endl;

      return 1;
    }

    std::cout << colorize("[OK]", 32) << " "
              << "License file successfully decrypted!"
              << std::endl;

    std::cout << colorize("[INFO]", 34) << " "
              << "Parsing..."
              << std::endl;

    auto lcs = parse_license(dec);
    if (is_empty<license>(lcs))
    {
      std::cerr << colorize("[ERROR]", 31) << " "
                << "Failed to parse license!"
                << std::endl;

      return 1;
    }

    std::cout << colorize("[OK]", 32) << " "
              << "License successfully parsed!"
              << std::endl;

    std::cout << "name=" << colorize(lcs.name, 34) << std::endl
              << "key=" << colorize(lcs.key, 34) << std::endl
              << "status=" << colorize(lcs.status, 34) << std::endl
              << "last_validated_at=" << colorize(timetostr(lcs.last_validated_at), 34) << std::endl
              << "expires_at=" << colorize(timetostr(lcs.expires_at), 34) << std::endl
              << "created_at=" << colorize(timetostr(lcs.created_at), 34) << std::endl
              << "updated_at=" << colorize(timetostr(lcs.updated_at), 34) << std::endl
              << "entitlements=[";

    for (auto i = 0; i < lcs.entitlements.size(); i++)
    {
      auto entitlement = lcs.entitlements.at(i);
      std::cout << colorize(entitlement.code, 34);

      if (i < lcs.entitlements.size() - 1)
      {
        std::cout << ",";
      }
    }

    std::cout << "]" << std::endl
              << "product=" << colorize(lcs.product.id, 34) << std::endl
              << "policy=" << colorize(lcs.policy.id, 34) << std::endl
              << "user=" << colorize(lcs.user.id, 34) << std::endl;

    return 0;
  }
  else
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "License file signature is not valid!"
              << std::endl;

    return 1;
  }
}
