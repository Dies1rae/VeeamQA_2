#include "HashChk.h"

namespace hshChk {
	CheckState HashChk::calculateFilehash(const std::string& src, const std::string& srchash, const HashType& type) const {
		std::string hash;
		std::ifstream src_(src, std::ios::binary);
		if (!src_.good()) {
			src_.close();
			return CheckState::NOT_FOUND;
		}
		src_.seekg (0, std::ios::end);
		long Length = src_.tellg();
		src_.seekg (0, std::ios::beg);    
		char * buffer = new char[Length];
		src_.read(buffer,Length);
		src_.close();
		if (type == HashType::MD5) {
			MD5_CTX md5handler;
			unsigned char md5digest[MD5_DIGEST_LENGTH];
			MD5_Init(&md5handler);
			MD5_Update(&md5handler, buffer, Length);
			src_.close();
			MD5_Final(md5digest, &md5handler);
			for (size_t ptr = 0; ptr < MD5_DIGEST_LENGTH; ptr++) {
				hash += "0123456789abcdef"[md5digest[ptr] / 16];
				hash += "0123456789abcdef"[md5digest[ptr] % 16];
			};
		} else if (type == HashType::SHA1) {
			src_.read(buffer,Length);
			SHA_CTX sha1handler;
			unsigned char sha1digest[SHA_DIGEST_LENGTH];
			SHA1_Init(&sha1handler);
			SHA1_Update(&sha1handler, buffer, Length);
			SHA1_Final(sha1digest, &sha1handler);
			for (size_t ptr = 0; ptr < SHA_DIGEST_LENGTH; ptr++) {
				hash += "0123456789abcdef"[sha1digest[ptr] / 16];
				hash += "0123456789abcdef"[sha1digest[ptr] % 16];
			}
		} else if (type == HashType::SHA256) {
			SHA256_CTX sha256handler;
			unsigned char sha256digest[SHA256_DIGEST_LENGTH];
			SHA256_Init(&sha256handler);
			SHA256_Update(&sha256handler, buffer, Length);
			SHA256_Final(sha256digest, &sha256handler);
			for (size_t ptr = 0; ptr < SHA256_DIGEST_LENGTH; ptr++) {
				hash += "0123456789abcdef"[sha256digest[ptr] / 16];
				hash += "0123456789abcdef"[sha256digest[ptr] % 16];
			}
		}
		if (hash == srchash) {
			return CheckState::OK;
		}
		return CheckState::FAIL;
	}

	void HashChk::printResults() const {
		for (const auto& [filename, status] : this->calculated_status) {
			std::cout << filename << ' ' << status << std::endl;
		}
	}

	std::vector<std::string> HashChk::stringTokinizd(const std::string& value) const {
		std::vector<std::string> parsed_cont;
		size_t pos = value.find( ' ' );
		size_t initialPos = 0;
		while (pos != std::string::npos) {
			parsed_cont.push_back(value.substr(initialPos, pos - initialPos));
			initialPos = pos + 1;
			pos =  value.find( ' ',  initialPos);
		}
		parsed_cont.push_back(value.substr(initialPos));
		return parsed_cont;
	}

	void HashChk::parseSrcFile() {
		std::ifstream src(this->in_file_);
		if (!src.good()) {
			src.close();
			throw std::runtime_error("Input file not found");
		}
		std::string file_info;
		while (std::getline(src, file_info)) {
			std::vector<std::string> parsed_cont = this->stringTokinizd(file_info);
			if (!parsed_cont[0].empty() && !parsed_cont[1].empty() && !parsed_cont[2].empty()) {
				if (parsed_cont[1] == "md5") {
					this->parsed_status[{ parsed_cont[0], HashType::MD5 }] = parsed_cont[2];
				} else if (parsed_cont[1] == "sha1") {
					this->parsed_status[{ parsed_cont[0], HashType::SHA1 }] = parsed_cont[2];
				} else if (parsed_cont[1] == "sha256") {
					this->parsed_status[{ parsed_cont[0], HashType::SHA256 }] = parsed_cont[2];
				} else {
					std::cerr << "Config string not correct" << std::endl;
					throw std::runtime_error("Config string not correct");
				}
			} else {
				std::cerr << "Config string not correct" << std::endl;
				throw std::runtime_error("Config string not correct");
			}
		}
	}

	void HashChk::calculateDstFiles() {
		this->checkDstPath();
		for (const auto& [file_hashtype, hash] : this->parsed_status) {
			this->calculated_status.push_back({file_hashtype.first, this->calculateFilehash(this->out_dir_ + file_hashtype.first, hash, file_hashtype.second)});
		}
	}

	void HashChk::checkDstPath() {
	#ifdef __linux__
		if (this->out_dir_[this->out_dir_.size() - 1] != '/') {
			this->out_dir_ += '/';
	}
	#elif _WIN32
		if (this->out_dir_[this->out_dir_.size() - 1] != '\\') {
			this->out_dir_ += '\\';
		}
	#endif
	}
}