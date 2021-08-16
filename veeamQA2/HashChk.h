#pragma once

#include "openssl/md5.h"
#include "openssl/sha.h"

#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <map>
#include <iostream>

namespace Hshchk {
	enum class HashType {
		MD5,
		SHA1,
		SHA256,
	};
	
	enum class CheckState {
		OK,
		FAIL,
		NOT_FOUND,
	};

	inline std::ostream& operator<<(std::ostream& os, const CheckState& obj) {
		switch (static_cast<int>(obj)) {
			case 0: os << "OK"; break;
			case 1: os << "FAIL"; break;
			case 2: os << "NOT FOUND"; break;
			default: break;
		}
		return os;
	}

	class HashChk {
	public:
		HashChk() = delete;

		HashChk(const std::string& infile, const std::string& outdir) : in_file_(infile), out_dir_(outdir) {}

		CheckState calculateFileHsh(const std::string& src, const std::string& srchsh, const HashType& type) const;

		void printResults() const;

		void parseSrcFile();

		void calculateDstFiles();

	private:
		void checkDstPAth();

		std::vector<std::string> stringTokinizd(const std::string& value) const;

		std::string in_file_;
		std::string out_dir_;
		std::map<std::pair<std::string, HashType>, std::string> parsed_status;
		std::vector<std::pair<std::string, CheckState>> calculated_status;
	};

} //namespace Hshchk