#include "client.hpp"

#include "../encrypt-decrypt/encrypt-decrypt.hpp"
#include "../utilities/utilities.hpp"
#include "../globals.hpp"


namespace client
{
	__forceinline std::string authentication()
	{
		char request[512];

		std::string tempory_cipher_key; 
		std::string tempory_iv_key; 

		std::vector<std::string> vector_tempory_key;

		std::string unprotect_request = utilities::get_random_string(48);

		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
			tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));
		
		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
			tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));

		std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);

		unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("pogvbufpcusmftrurrszycfefhidvdfs"), xorstr_("kspgywjaldzgwphn"));

		li(sprintf)(request, xorstr_("/client/authentication.php?a=%s&b=%s"), unprotect_request.c_str(), protect_request.c_str());
		std::string response = utilities::request_to_server(g_globals.server_side.ip, request);

		std::vector<std::string> split_key = utilities::split_string(response.c_str(), xorstr_(";"));

		g_globals.server_side.key.cipher = aes::decrypt(split_key[0], tempory_cipher_key, tempory_iv_key);
		g_globals.server_side.key.iv = aes::decrypt(split_key[1], tempory_cipher_key, tempory_iv_key);

		if (g_globals.server_side.key.cipher.size() != 32 || g_globals.server_side.key.iv.size() != 16)
			return xorstr_("internal_error");

		else if (response == aes::encrypt(xorstr_("data_error"), g_globals.server_side.key.cipher, g_globals.server_side.key.iv))
			return xorstr_("internal_error");


		return xorstr_("success");
	}
	__forceinline std::string Dll()
	{
		char request[512];

		std::string tempory_cipher_key;
		std::string tempory_iv_key;

		std::vector<std::string> vector_tempory_key;

		std::string unprotect_request = utilities::get_random_string(48);

		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 64)
			tempory_cipher_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));

		for (std::size_t pos = 0; pos < unprotect_request.size(); pos += 32)
			tempory_iv_key = vector_tempory_key.emplace_back(unprotect_request.data() + pos, unprotect_request.data() + min(pos + 32, unprotect_request.size()));

		std::string protect_request = aes::encrypt(unprotect_request.c_str(), tempory_cipher_key, tempory_iv_key);

		unprotect_request = aes::encrypt(unprotect_request.c_str(), xorstr_("pogvbufpcusmftrurrszycfefhidvdfs"), xorstr_("kspgywjaldzgwphn"));

		li(sprintf)(request, xorstr_("/client/InjectDLL.php?a=%s&b=%s"), unprotect_request.c_str(), protect_request.c_str());
		std::string response = utilities::request_to_server(g_globals.server_side.ip, request);

		return response;
	}
	__forceinline std::string valid_version()
	{
		char request[512];

		std::string version = aes::encrypt(g_globals.client_side.version, g_globals.server_side.key.cipher, g_globals.server_side.key.iv);

		li(sprintf)(request, xorstr_("/client/version.php?a=%s"), version.c_str());
		std::string response = utilities::request_to_server(g_globals.server_side.ip, request);

		if (response != aes::encrypt(xorstr_("incorrect_version"), g_globals.server_side.key.cipher, g_globals.server_side.key.iv))
		{
			std::vector<std::string> split_response = utilities::split_string(response.c_str(), xorstr_(";"));

			g_globals.server_side.version = aes::decrypt(split_response[0], g_globals.server_side.key.cipher, g_globals.server_side.key.iv);
			g_globals.server_side.status = aes::decrypt(split_response[1], g_globals.server_side.key.cipher, g_globals.server_side.key.iv);
		}
		else if (response == aes::encrypt(xorstr_("incorrect_version"), g_globals.server_side.key.cipher, g_globals.server_side.key.iv))
			g_globals.server_side.version = response;

		return response;
	}
	__forceinline std::string activation()
	{
		char request[512];

		std::string key = aes::encrypt(g_globals.client_side.data.key.c_str(), g_globals.server_side.key.cipher, g_globals.server_side.key.iv);
		std::string hwid = aes::encrypt(g_globals.client_side.data.hwid.c_str(), g_globals.server_side.key.cipher, g_globals.server_side.key.iv);

		li(sprintf)(request, xorstr_("/client/activation.php?a=%s&b=%s"), key.c_str(), hwid.c_str());
		std::string response = utilities::request_to_server(g_globals.server_side.ip, request);

		return response;
	}
}