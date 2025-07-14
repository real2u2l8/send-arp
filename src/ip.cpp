#include "pch.h"
#include "ip.h"

/**
 * @brief IP 주소 문자열을 파싱하여 IP 객체를 생성하는 생성자
 * @param r "xxx.xxx.xxx.xxx" 형식의 IP 주소 문자열
 * @details
 * 입력된 문자열을 파싱하여 4개의 옥텟으로 분리하고
 * 32비트 정수형으로 변환하여 ip_ 멤버 변수에 저장합니다.
 * 파싱에 실패할 경우 에러 메시지를 출력합니다.
 */
Ip::Ip(const std::string r) {
	unsigned int a, b, c, d;
	int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != SIZE) {
		fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

/**
 * @brief IP 객체를 문자열로 변환하는 연산자
 * @return "xxx.xxx.xxx.xxx" 형식의 IP 주소 문자열
 * @details
 * 내부 ip_ 값을 4개의 옥텟으로 분리하여
 * 점(.)으로 구분된 문자열 형식으로 변환합니다.
 */
Ip::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(ip_ & 0xFF000000) >> 24,
		(ip_ & 0x00FF0000) >> 16,
		(ip_ & 0x0000FF00) >> 8,
		(ip_ & 0x000000FF));
	return std::string(buf);
}

#ifdef GTEST
#include <gtest/gtest.h>

/**
 * @brief IP 클래스의 생성자 테스트
 * @details
 * 기본 생성자, uint32_t 생성자, 문자열 생성자를 테스트합니다.
 * 서로 다른 방식으로 생성된 동일한 IP 주소의 객체를 비교합니다.
 */
TEST(Ip, ctorTest) {
	Ip ip1; // Ip()

	Ip ip2(0x7F000001); // Ip(const uint32_t r)

	Ip ip3("127.0.0.1"); // Ip(const std::string r);

	EXPECT_EQ(ip2, ip3);
}

/**
 * @brief IP 클래스의 형변환 연산자 테스트
 * @details
 * IP 객체를 uint32_t와 string으로 변환하는 기능을 테스트합니다.
 * 변환된 값이 예상한 값과 일치하는지 확인합니다.
 */
TEST(Ip, castingTest) {
	Ip ip("127.0.0.1");

	uint32_t ui = ip; // operator uint32_t() const
	EXPECT_EQ(ui, 0x7F000001);

	std::string s = std::string(ip); // explicit operator std::string()

	EXPECT_EQ(s, "127.0.0.1");
}

#endif // GTEST
