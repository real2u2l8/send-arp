#include "pch.h"
#include "ip.h"

/**
 * @brief IP �ּ� ���ڿ��� �Ľ��Ͽ� IP ��ü�� �����ϴ� ������
 * @param r "xxx.xxx.xxx.xxx" ������ IP �ּ� ���ڿ�
 * @details
 * �Էµ� ���ڿ��� �Ľ��Ͽ� 4���� �������� �и��ϰ�
 * 32��Ʈ ���������� ��ȯ�Ͽ� ip_ ��� ������ �����մϴ�.
 * �Ľ̿� ������ ��� ���� �޽����� ����մϴ�.
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
 * @brief IP ��ü�� ���ڿ��� ��ȯ�ϴ� ������
 * @return "xxx.xxx.xxx.xxx" ������ IP �ּ� ���ڿ�
 * @details
 * ���� ip_ ���� 4���� �������� �и��Ͽ�
 * ��(.)���� ���е� ���ڿ� �������� ��ȯ�մϴ�.
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
 * @brief IP Ŭ������ ������ �׽�Ʈ
 * @details
 * �⺻ ������, uint32_t ������, ���ڿ� �����ڸ� �׽�Ʈ�մϴ�.
 * ���� �ٸ� ������� ������ ������ IP �ּ��� ��ü�� ���մϴ�.
 */
TEST(Ip, ctorTest) {
	Ip ip1; // Ip()

	Ip ip2(0x7F000001); // Ip(const uint32_t r)

	Ip ip3("127.0.0.1"); // Ip(const std::string r);

	EXPECT_EQ(ip2, ip3);
}

/**
 * @brief IP Ŭ������ ����ȯ ������ �׽�Ʈ
 * @details
 * IP ��ü�� uint32_t�� string���� ��ȯ�ϴ� ����� �׽�Ʈ�մϴ�.
 * ��ȯ�� ���� ������ ���� ��ġ�ϴ��� Ȯ���մϴ�.
 */
TEST(Ip, castingTest) {
	Ip ip("127.0.0.1");

	uint32_t ui = ip; // operator uint32_t() const
	EXPECT_EQ(ui, 0x7F000001);

	std::string s = std::string(ip); // explicit operator std::string()

	EXPECT_EQ(s, "127.0.0.1");
}

#endif // GTEST
