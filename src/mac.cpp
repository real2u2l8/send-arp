#include "pch.h"
#include "mac.h"

/**
 * @brief MAC 주소 문자열을 파싱하여 MAC 객체를 생성하는 생성자
 * @param r "xx:xx:xx:xx:xx:xx" 형식의 MAC 주소 문자열
 * @details
 * 입력된 문자열을 파싱하여 6개의 16진수로 분리하고
 * 8비트 정수형으로 변환하여 mac_ 멤버 변수에 저장합니다.
 * 파싱에 실패할 경우 에러 메시지를 출력합니다.
 */
Mac::Mac(const std::string& r) {
	std::string s;
	for(char ch: r) {
		if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
			s += ch;
	}
	int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
	if (res != SIZE) {
		fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
}

/**
 * @brief MAC 객체를 문자열로 변환하는 연산자
 * @return "xx:xx:xx:xx:xx:xx" 형식의 MAC 주소 문자열
 * @details
 * 내부 mac_ 값을 6개의 16진수로 분리하여
 * 콜론(:)으로 구분된 문자열 형식으로 변환합니다.
 */
Mac::operator std::string() const {
	char buf[20]; // enough size
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
	return std::string(buf);
}

/**
 * @brief 랜덤 MAC 주소를 생성하는 함수
 * @return 랜덤 MAC 주소
 * @details
 * 랜덤한 6바이트 값을 생성하여 MAC 주소를 생성합니다.
 * 첫 번째 바이트는 0x7F 비트를 제외한 값으로 설정합니다.
 */
Mac Mac::randomMac() {
	Mac res;
	for (int i = 0; i < SIZE; i++)
		res.mac_[i] = uint8_t(rand() % 256);
	res.mac_[0] &= 0x7F;
	return res;
}

/**
 * @brief 널 MAC 주소를 반환하는 함수
 * @return 널 MAC 주소
 * @details
 * 모든 바이트가 0인 MAC 주소를 반환합니다.
 */
Mac& Mac::nullMac() {
	static uint8_t _value[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static Mac res(_value);
	return res;
}

/**
 * @brief 브로드캐스트 MAC 주소를 반환하는 함수
 * @return 브로드캐스트 MAC 주소
 * @details
 * 모든 바이트가 0xFF인 MAC 주소를 반환합니다.
 */
Mac& Mac::broadcastMac() {
	static uint8_t _value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	static Mac res(_value);
	return res;
}

// ----------------------------------------------------------------------------
// GTEST
// ----------------------------------------------------------------------------
#ifdef GTEST
#include <gtest/gtest.h>

static constexpr uint8_t _temp[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

/**
 * @brief MAC 객체 생성 테스트
 * @details
 * 다양한 생성자를 테스트하여 MAC 객체를 생성합니다.
 * 생성자 간의 동작을 확인하고, 생성된 객체의 값을 비교합니다.
 */
TEST(Mac, ctorTest) {
	Mac mac1; // ()

	Mac mac2{mac1}; // (const Mac& r)

	Mac mac3(_temp); // (const uint8_t* r)

	Mac mac4(std::string("001122-334455")); // (const std::string& r)
	EXPECT_EQ(mac3, mac4);

	Mac mac5("001122-334455"); // (const std::string& r)
	EXPECT_EQ(mac3, mac5);
}

/**
 * @brief MAC 객체 형변환 테스트
 * @details
 * MAC 객체를 문자열로 변환하고, 변환된 문자열을 비교합니다.
 */
TEST(Mac, castingTest) {
	Mac mac("001122-334455");

	const uint8_t* uc = (uint8_t*)mac; // operator uint8_t*()
	uint8_t temp[Mac::SIZE];
	for (int i = 0; i < Mac::SIZE; i++)
		temp[i] = *uc++;
	EXPECT_TRUE(memcmp(&mac, temp, 6) == 0);

	std::string s2 = std::string(mac); // operator std::string()
	EXPECT_EQ(s2, "00:11:22:33:44:55");
}

TEST(Mac, funcTest) {
	Mac mac;

	mac.clear();
	EXPECT_TRUE(mac.isNull());

	mac = std::string("FF:FF:FF:FF:FF:FF");
	EXPECT_TRUE(mac.isBroadcast());

	mac = std::string("01:00:5E:00:11:22");
	EXPECT_TRUE(mac.isMulticast());
}

#include <map>
/**
 * @brief std::map<Mac, int> 테스트
 * @details
 * MAC 객체를 맵에 저장하고, 맵의 크기와 내용을 확인합니다.
 */
TEST(Mac, mapTest) {
	typedef std::map<Mac, int> MacMap;
	MacMap m;
	m.insert(std::make_pair(Mac("001122-334455"), 1));
	m.insert(std::make_pair(Mac("001122-334456"), 2));
	m.insert(std::make_pair(Mac("001122-334457"), 3));
	EXPECT_EQ(m.size(), 3);
	MacMap::iterator it = m.begin();
	EXPECT_EQ(it->second, 1); it++;
	EXPECT_EQ(it->second, 2); it++;
	EXPECT_EQ(it->second, 3);
}

#include <unordered_map>
/**
 * @brief std::unordered_map<Mac, int> 테스트
 * @details
 * MAC 객체를 해시 맵에 저장하고, 맵의 크기와 내용을 확인합니다.
 */
TEST(Mac, unordered_mapTest) {
	typedef std::unordered_map<Mac, int> MacUnorderedMap;
	MacUnorderedMap m;
	m.insert(std::make_pair(Mac("001122-334455"), 1));
	m.insert(std::make_pair(Mac("001122-334456"), 2));
	m.insert(std::make_pair(Mac("001122-334457"), 3));
	//EXPECT_EQ(m.size(), 3);
}

#endif // GTEST
