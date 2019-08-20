Return-Path: <kasan-dev+bncBCXLBLOA7IGBBGOC6DVAKGQEIWHXCOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 95C3196676
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 18:34:33 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id t9sf7348399wrx.9
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 09:34:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566318873; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRlsb3Sy9AbjA/E4gJVDTr2ANQ9992TxMsRwxGFS423oFKtCh5xouBHuBMaU5AeeZr
         UWkbFrmac6gsbzc97MFPUzXgsiT40FBuFpN5oplSXeHzEL5VJAT1x52DXggMqZ3gEN6K
         61kAHCms28Vsuccv9HUy8bYFz+hqaYvJeacoLEieoaYwYrpmJHtLPYCNifN2GFMzU7cC
         40IA243rflGAuZKuQ1puvQ6a8DtKunxn/rpjQc8a/1r1OKtWqemTyE5d1yAdDxxZKkDx
         U42kh31o5K4DNTPkpC3bMYCBKpw9cJBOwC9Xffbpu5hwU/M1u1xaCnwEFV0D0fzSNm9g
         p6zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=qXeRwhzkvKmeSct7Z8xPcqxYhM21681//2yC7C76HOY=;
        b=S32nLcJoWZjNDYfyVAZMECaSxDZB1G5C1YZ5RBnBoLkz5tYV8Spw/U256/jkZONhxi
         GLBD+CN721EQ+g86AQXqlXXBZuZzTl32HnkGkTRtpmwPxmbGHxfXAuDgmFgg84DGBYTI
         I4wNLDOXpucWgys8bobf5P5FXj8Ib3CGFEH0dY66qU7CUyC+czbje7cxwSi01c0dRhmi
         VmswCY0RJx/6UpgibF+y/TR1bxeyjCcV3EDy47oD67iNbusKyYZFgnltUG6sTkDg38lx
         tbDxjaFzhmc00vL0+R/71CO6s0VEQB2A5VLTQQxw4Ul7lOyiCaXlzTt1SI6jofgkIowX
         aBwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=jcEk1qot;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qXeRwhzkvKmeSct7Z8xPcqxYhM21681//2yC7C76HOY=;
        b=iBXh+xvGIlCGtDiRPCdqZjdXA2T0EKh+u1Va0kISzuxjDsvGO1RocWJoDO7lNJP1t2
         FNugDmR3C7JUxpaD+I2LnghA7Sn6FmOsBtl7i319GS1h+YyKC4Au+ltCHXvHbUnAje4u
         RAl71Xv023h6iDj5EK7TKpx+TnenkSkvKChdxHrpaUnhYOsKDXDjwYE8azGMxOAfVEQT
         sJ4Osbe9pUCmO4RNOVpQSloD5BPFSJe2MY48qACAWXl2N3fFKLYDXvAj9NqrUEmWCQDy
         DakCiSn6hMsVOu8c5yso2D7g1gr0+sdzKWHaxIkcyqxAux1imCPgPmXhqHbMC3FfwYvd
         sTYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qXeRwhzkvKmeSct7Z8xPcqxYhM21681//2yC7C76HOY=;
        b=kzF+tsn/gXLc0QI3F1DNf+V7BG8alWvnBSwZ9ogy4gvC76mC8TKWIlruUh6gKZN4al
         52+e2dY+nCRy6/fpl9+bxLJl5Zs4VLkS/6TOilurdn3WLYGcZvtHKIXaOodPXCx2rJY3
         TaIt/mLkjiQbZF7PGajUlrAFnu6ZEYO5hkLDQ6XkpDdjN4nl4jABNGRr7Qwpw3ZTil1v
         skqM0xgfRMOTvNpy5Tc6wJeyxZ7kgQ2nvqeSRNuAGTxjyzYQd3+emOXp9q0qxWgByr13
         I3p9oDNi7yOq+5+u/CAA8YHnvabbX3+kSVPGYI4Uf2ZdykMpnjLNuiuH9R6C2Urb9S8q
         LnGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWRe25vNn8A5GMOzHESAqpkfQH15QQT4nBLfaRAWde6y51qWeC5
	Yc4vfbuPR8Fq/kATxPWAQ2g=
X-Google-Smtp-Source: APXvYqxPREEg82RfkoiLl8MIJdzTsfKD2YPdJebfPJOWp4u8PUAboycJ3SQ/Hzh36LeKtUtV3HXRoA==
X-Received: by 2002:a05:600c:145:: with SMTP id w5mr900468wmm.75.1566318873253;
        Tue, 20 Aug 2019 09:34:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ab1b:: with SMTP id q27ls5706437wrc.7.gmail; Tue, 20 Aug
 2019 09:34:32 -0700 (PDT)
X-Received: by 2002:adf:f2c1:: with SMTP id d1mr36310498wrp.157.1566318872816;
        Tue, 20 Aug 2019 09:34:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566318872; cv=none;
        d=google.com; s=arc-20160816;
        b=GNuPi5BFrsMYY5APuUlW82uZKCW5R4T4J4VJoDBdY7NfG7dJgE8tdutZuGuRUt8LOp
         9lJIJPUnO6MGQR8s+zp7FpuSmzzK7FcRduRPpkrCdz9++VM2a3oUyC2zKU0XfGVxCYw/
         lkehk/rmmEM1invw04xMnQ7+r2+pReQhJ7uGexiCB1s6hXuW33vTNlkdTHPB66WCItqR
         KZsAwiyMfrqxwkLhCrJa2Jdb5dv0M4s85nhmPCnYLOx5g3tf7MTRAGEj/Vk+cz2KQjFJ
         v3MTr570+9ywYd/VqmIidYrdUkEnrX88I9/kzYMVUWr5vHj48jdZ2zEXq6TsPrM+mODW
         Vf3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=M46pFD8QK6LkV0J4+q5kgptn6gTa2un+Xy7n4gfSJPo=;
        b=JpmID3EK14WKbx/lbX/jAjhnPZ1oI9qt+GsdWU+HIJEys07M5maZVgwFK4rGv4u97v
         16kOzDGw72War5DyjQhx3ynjpvjfYX8//cHETXjGdL9gjkZNV93MIAv+cJYLpq0W22vC
         5XScW/gdUYKZoSVpEHTly3ZlIhaXNN3yw3yLh1wxMZLtQur2MZQHJBIG+J7wA6w/68TA
         OMm7+3zOh4gga6qwhx62BUyuyKcpGGsJVBO8DDl6Pb3Vb5rcb01Rbg3eCYU1Sdkc4yow
         s+dGpxSKtIvOQeHjEdPvyf981PhfrpfMRWzodCp1/Q43EYftK1GLAlEI1cXKmNm0cK30
         SyEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=jcEk1qot;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o4si984912wrp.4.2019.08.20.09.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Aug 2019 09:34:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46Cbwl6LzXz9v4gL;
	Tue, 20 Aug 2019 18:34:31 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id w-gSiBqPQhSj; Tue, 20 Aug 2019 18:34:31 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46Cbwl5Fhpz9v4gJ;
	Tue, 20 Aug 2019 18:34:31 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4467E8B7DA;
	Tue, 20 Aug 2019 18:34:32 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id o9cmSMSFdq5C; Tue, 20 Aug 2019 18:34:32 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B55248B7D5;
	Tue, 20 Aug 2019 18:34:31 +0200 (CEST)
Subject: Re: [PATCH v2 2/2] powerpc: support KASAN instrumentation of bitops
To: Daniel Axtens <dja@axtens.net>, linux-s390@vger.kernel.org,
 linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, Nicholas Piggin <npiggin@gmail.com>
References: <20190820024941.12640-1-dja@axtens.net>
 <20190820024941.12640-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <cb205dfa-bdea-8320-5aae-9d5d5bd98c91@c-s.fr>
Date: Tue, 20 Aug 2019 18:34:31 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190820024941.12640-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=jcEk1qot;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>



Le 20/08/2019 =C3=A0 04:49, Daniel Axtens a =C3=A9crit=C2=A0:
> The powerpc-specific bitops are not being picked up by the KASAN
> test suite.
>=20
> Instrumentation is done via the bitops/instrumented-{atomic,lock}.h
> headers. They require that arch-specific versions of bitop functions
> are renamed to arch_*. Do this renaming.
>=20
> For clear_bit_unlock_is_negative_byte, the current implementation
> uses the PG_waiters constant. This works because it's a preprocessor
> macro - so it's only actually evaluated in contexts where PG_waiters
> is defined. With instrumentation however, it becomes a static inline
> function, and all of a sudden we need the actual value of PG_waiters.
> Because of the order of header includes, it's not available and we
> fail to compile. Instead, manually specify that we care about bit 7.
> This is still correct: bit 7 is the bit that would mark a negative
> byte.
>=20
> While we're at it, replace __inline__ with inline across the file.
>=20
> Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Tested-by: Christophe Leroy <christophe.leroy@c-s.fr>

Now, I only have two KASAN tests which do not trigger any message:

	kasan test: kasan_alloca_oob_left out-of-bounds to left on alloca
	kasan test: kasan_alloca_oob_right out-of-bounds to right on alloca

Christophe

>=20
> --
> v2: Address Christophe review
> ---
>   arch/powerpc/include/asm/bitops.h | 51 ++++++++++++++++++-------------
>   1 file changed, 29 insertions(+), 22 deletions(-)
>=20
> diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm=
/bitops.h
> index 603aed229af7..28dcf8222943 100644
> --- a/arch/powerpc/include/asm/bitops.h
> +++ b/arch/powerpc/include/asm/bitops.h
> @@ -64,7 +64,7 @@
>  =20
>   /* Macro for generating the ***_bits() functions */
>   #define DEFINE_BITOP(fn, op, prefix)		\
> -static __inline__ void fn(unsigned long mask,	\
> +static inline void fn(unsigned long mask,	\
>   		volatile unsigned long *_p)	\
>   {						\
>   	unsigned long old;			\
> @@ -86,22 +86,22 @@ DEFINE_BITOP(clear_bits, andc, "")
>   DEFINE_BITOP(clear_bits_unlock, andc, PPC_RELEASE_BARRIER)
>   DEFINE_BITOP(change_bits, xor, "")
>  =20
> -static __inline__ void set_bit(int nr, volatile unsigned long *addr)
> +static inline void arch_set_bit(int nr, volatile unsigned long *addr)
>   {
>   	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
> +static inline void arch_clear_bit(int nr, volatile unsigned long *addr)
>   {
>   	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void clear_bit_unlock(int nr, volatile unsigned long *=
addr)
> +static inline void arch_clear_bit_unlock(int nr, volatile unsigned long =
*addr)
>   {
>   	clear_bits_unlock(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void change_bit(int nr, volatile unsigned long *addr)
> +static inline void arch_change_bit(int nr, volatile unsigned long *addr)
>   {
>   	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
> @@ -109,7 +109,7 @@ static __inline__ void change_bit(int nr, volatile un=
signed long *addr)
>   /* Like DEFINE_BITOP(), with changes to the arguments to 'op' and the o=
utput
>    * operands. */
>   #define DEFINE_TESTOP(fn, op, prefix, postfix, eh)	\
> -static __inline__ unsigned long fn(			\
> +static inline unsigned long fn(			\
>   		unsigned long mask,			\
>   		volatile unsigned long *_p)		\
>   {							\
> @@ -138,34 +138,34 @@ DEFINE_TESTOP(test_and_clear_bits, andc, PPC_ATOMIC=
_ENTRY_BARRIER,
>   DEFINE_TESTOP(test_and_change_bits, xor, PPC_ATOMIC_ENTRY_BARRIER,
>   	      PPC_ATOMIC_EXIT_BARRIER, 0)
>  =20
> -static __inline__ int test_and_set_bit(unsigned long nr,
> -				       volatile unsigned long *addr)
> +static inline int arch_test_and_set_bit(unsigned long nr,
> +					volatile unsigned long *addr)
>   {
>   	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_set_bit_lock(unsigned long nr,
> -				       volatile unsigned long *addr)
> +static inline int arch_test_and_set_bit_lock(unsigned long nr,
> +					     volatile unsigned long *addr)
>   {
>   	return test_and_set_bits_lock(BIT_MASK(nr),
>   				addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_clear_bit(unsigned long nr,
> -					 volatile unsigned long *addr)
> +static inline int arch_test_and_clear_bit(unsigned long nr,
> +					  volatile unsigned long *addr)
>   {
>   	return test_and_clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_change_bit(unsigned long nr,
> -					  volatile unsigned long *addr)
> +static inline int arch_test_and_change_bit(unsigned long nr,
> +					   volatile unsigned long *addr)
>   {
>   	return test_and_change_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
>   #ifdef CONFIG_PPC64
> -static __inline__ unsigned long clear_bit_unlock_return_word(int nr,
> -						volatile unsigned long *addr)
> +static inline unsigned long
> +clear_bit_unlock_return_word(int nr, volatile unsigned long *addr)
>   {
>   	unsigned long old, t;
>   	unsigned long *p =3D (unsigned long *)addr + BIT_WORD(nr);
> @@ -185,15 +185,18 @@ static __inline__ unsigned long clear_bit_unlock_re=
turn_word(int nr,
>   	return old;
>   }
>  =20
> -/* This is a special function for mm/filemap.c */
> -#define clear_bit_unlock_is_negative_byte(nr, addr)			\
> -	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(PG_waiters))
> +/*
> + * This is a special function for mm/filemap.c
> + * Bit 7 corresponds to PG_waiters.
> + */
> +#define arch_clear_bit_unlock_is_negative_byte(nr, addr)		\
> +	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(7))
>  =20
>   #endif /* CONFIG_PPC64 */
>  =20
>   #include <asm-generic/bitops/non-atomic.h>
>  =20
> -static __inline__ void __clear_bit_unlock(int nr, volatile unsigned long=
 *addr)
> +static inline void arch___clear_bit_unlock(int nr, volatile unsigned lon=
g *addr)
>   {
>   	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
>   	__clear_bit(nr, addr);
> @@ -215,14 +218,14 @@ static __inline__ void __clear_bit_unlock(int nr, v=
olatile unsigned long *addr)
>    * fls: find last (most-significant) bit set.
>    * Note fls(0) =3D 0, fls(1) =3D 1, fls(0x80000000) =3D 32.
>    */
> -static __inline__ int fls(unsigned int x)
> +static inline int fls(unsigned int x)
>   {
>   	return 32 - __builtin_clz(x);
>   }
>  =20
>   #include <asm-generic/bitops/builtin-__fls.h>
>  =20
> -static __inline__ int fls64(__u64 x)
> +static inline int fls64(__u64 x)
>   {
>   	return 64 - __builtin_clzll(x);
>   }
> @@ -239,6 +242,10 @@ unsigned long __arch_hweight64(__u64 w);
>  =20
>   #include <asm-generic/bitops/find.h>
>  =20
> +/* wrappers that deal with KASAN instrumentation */
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +#include <asm-generic/bitops/instrumented-lock.h>
> +
>   /* Little-endian versions */
>   #include <asm-generic/bitops/le.h>
>  =20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/cb205dfa-bdea-8320-5aae-9d5d5bd98c91%40c-s.fr.
