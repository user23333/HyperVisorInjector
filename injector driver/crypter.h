#include <array>

using namespace std;

template <typename StrType> __declspec(noinline) constexpr unsigned short HashStr(StrType Data, int Len) {
	unsigned short CRC = 0xFFFF; while (Len--) {
		auto CurChar = *Data++; if (!CurChar) break;
		CRC ^= ToLower(CurChar) << 8; for (int i = 0; i < 8; i++)
			CRC = CRC & 0x8000 ? (CRC << 1) ^ 0x6491 : CRC << 1;
	} return CRC;
}
#define ConstHashStr(Str) [](){ constexpr unsigned short CRC = HashStr(Str, ConstStrLen(Str)); return CRC; }()

template <typename T = PVOID, typename A = PVOID>
__forceinline T EPtr(A Ptr) {
	typedef union {
		struct {
			USHORT Key1; USHORT Key2;
			USHORT Key3; USHORT Key4;
		}; ULONG64 Key;
	} CryptData;
	CryptData Key{ ConstHashStr(__TIME__), ConstHashStr(__DATE__),
		ConstHashStr(__FILE__), ConstHashStr(__TIMESTAMP__) };
	volatile LONG64 PtrData; volatile LONG64 VKey;
	InterlockedExchange64(&VKey, (ULONG64)Key.Key);
	InterlockedExchange64(&PtrData, (ULONG64)Ptr);
	PtrData ^= VKey; return (T)PtrData;
}

#define CountOf(Align, Size) ((((Size + Align - 1) / Align) * Align) / Align)

template<typename T>
using GetType = typename std::remove_const_t<std::remove_reference_t<T>>;

template <typename A, size_t N>
class CryptStr
{
private:
	volatile uint64_t Key;
	array<uint64_t, CountOf(8, sizeof(A[N]))> StrArray;

public:
	template <size_t... Is>
	__forceinline constexpr CryptStr(const A(&Str)[N], index_sequence<Is...>) noexcept :
		Key(GetKey()), StrArray{ Crypt(Str, Is)... } { }

	__forceinline constexpr auto GetKey() {
		return
			(uint64_t)((__TIME__[0] * __TIME__[6]) + __TIME__[1]) << 56 |
			(uint64_t)((__TIME__[1] * __TIME__[6]) + __TIME__[0]) << 48 |
			(uint64_t)((__TIME__[3] * __TIME__[6]) + __TIME__[4]) << 40 |
			(uint64_t)((__TIME__[4] * __TIME__[6]) + __TIME__[3]) << 32 |
			(uint64_t)((__TIME__[0] * __TIME__[7]) + __TIME__[1]) << 24 |
			(uint64_t)((__TIME__[1] * __TIME__[7]) + __TIME__[0]) << 16 |
			(uint64_t)((__TIME__[3] * __TIME__[7]) + __TIME__[4]) << 8 |
			(uint64_t)((__TIME__[4] * __TIME__[7]) + __TIME__[3]) << 0;
	}

	__forceinline constexpr const uint64_t Crypt(const A* Str, size_t Index) {
		auto StrPtr = (const uint8_t*)Str + (Index * 8);
		uint8_t Ret[8] = {
			((Index * 8) + 0) < Size() ? StrPtr[0] : (uint8_t)0,
			((Index * 8) + 1) < Size() ? StrPtr[1] : (uint8_t)0,
			((Index * 8) + 2) < Size() ? StrPtr[2] : (uint8_t)0,
			((Index * 8) + 3) < Size() ? StrPtr[3] : (uint8_t)0,
			((Index * 8) + 4) < Size() ? StrPtr[4] : (uint8_t)0,
			((Index * 8) + 5) < Size() ? StrPtr[5] : (uint8_t)0,
			((Index * 8) + 6) < Size() ? StrPtr[6] : (uint8_t)0,
			((Index * 8) + 7) < Size() ? StrPtr[7] : (uint8_t)0
		}; return *(uint64_t*)&Ret ^ Key;
	}

	__forceinline size_t Size() {
		return sizeof(A[N]);
	}

	__forceinline const auto Get() noexcept {
		return (const A*)StrArray.data();
	}

	__forceinline const auto GetDecrypted()
	{
		volatile const size_t Count = StrArray._Unchecked_end() - StrArray._Unchecked_begin();
		for (size_t i = 0; i < Count; StrArray[i] ^= Key, ++i);
		return (const A*)StrArray.data();
	}
};

#define EXor(Str) CryptStr<GetType<decltype(Str[0])>, sizeof(Str) / sizeof(Str[0])>(Str, make_index_sequence<CountOf(8, sizeof(Str))>())
#define E(Str) EXor(Str).GetDecrypted()