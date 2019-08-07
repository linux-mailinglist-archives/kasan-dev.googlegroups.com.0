Return-Path: <kasan-dev+bncBCXLBLOA7IGBBNGPVPVAKGQELR2W5MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 39FD084F59
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 17:01:09 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id l26sf56340229eda.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 08:01:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565190069; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjFW9q6MuwJKLIZM6i28cRFVtdHPnS79Ka/SAdtvq52nuuaJ8IrsZvXOif80xRSaII
         Flaz5EhFQ7PbjlCob1nmkLqvc39efLl5HGjcXDrz+IoztvAxgJm9OpNWzh6dJKwuOKQ6
         9VTnRFQrCOlNRosKcHoso/2c4BQGB6NLB4P7UeksEeb8P2fEk7JQyYzdJyJZUrbtQ+Mk
         Fz0KZvhwyQBNE91Q92/0rXMHd1KTynH7agCCFQK8/yneIJgRVdnJyy2895I2hYeRmdhW
         3Ew6c71G5yTcF2cqqCYY8ggYbh8EmhlSmbXB4HNW8R//bXJEmiQ9lfTNB/r3bOsiIpDW
         ylmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=q1wnWkHMtK+nuW5q0XebdlBX5pIapjwzU/ZzddrXTjg=;
        b=xcSIobdHaMJi+3bF8Qn5tK0YB2no7LQqY5Md+WJja/9lHEICf1K3HTyrn69CgQPJv9
         /w1Rka7Gn1HFTe46C8ROaJZadPSKU4mbsGagi0JfPS1AgoINJMZQyFxl2gXl+PlKi+lz
         WUFHX3C5zS2hRwLsUg+vJX9W+5dnrS5rfS68JUdRuAkvshIjQJvBK88xqFlaq5FtTK7Q
         z0MHl3OSFcbnDjkqXFkhuhHyVWRU7sMVnCCyb23CaObrB0yB+6tFm4i8IiApjdeMsGYi
         T/R5RkGVUmNEDlvKTyfTjJqUptgVe1uBTX/z1VSKsTNzGq3XHG6u2ulSXA4DXo57SP/l
         8aMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=sRJQtK8f;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q1wnWkHMtK+nuW5q0XebdlBX5pIapjwzU/ZzddrXTjg=;
        b=EvPKYTVsYvBiGDE84fH5Gx23C0TNehnAVPPWevYizq8HFYlB7tJUhw0VhkaeX6I2Vf
         t5XlIzBmeAG0pLdy5ttopAl5neVVs2dWCNPYepg4q/yXlMxDX70L8OuiRZQrH/IasrfO
         cjePMga54QmnKW1IiFLXLel1NggN8XT15msl1YnUcQVFV7ZaFo/ifbDAuN+6Jh9r0auy
         NKPydugBCAm3AsvE0QQ1eHeJRY+7/z7eW2+oj4hvLSO14FoKVTKdvmUrwAix2s+o2PMk
         G/+6mk4TuD5kXn9ISN1CttmDu9xJqC7mWfxvalhiMTVqhwupOClPIIQPdcc7HN69FTeD
         t0pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q1wnWkHMtK+nuW5q0XebdlBX5pIapjwzU/ZzddrXTjg=;
        b=UU53h3HuMrkkkjLFWbHL9nEVR2FN6EgcVa9U/vQmH7pxzMaYPxW//C7OwH3DQUXn1M
         KK4G+sTfknSyYatSGvEFnWGiFIW2yYcwXM6SxJJCMaK8c2kW092SivV1e5VQqGdi3eB2
         N5oaxMjwRUQli568DkINoUe/+1g5vr3xH7F5mX5ZEEtRY996aWkiAJ1m2lrm4QtvURrL
         oFtYBNtRtFirB5oV3fXMDfFIlfnTfK44aIAblVFQK41bFMYzjmXp4jrKBVZFV8fnmMgT
         FEA5xEpD5tW4nxUYT2D6vheGkNWche0dM+jhhuX6m5vJAlXPpiDTewM4lRvm/JbqdqWo
         r8XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXR4tgtG7Fci3Qj0nN0++6YVIO9aBhDMoN5RRGm13POF9z+fl5i
	MjwglfcBkiN/nVNzJXVqg1c=
X-Google-Smtp-Source: APXvYqzUr4pI3CemgpN5AkMmDdF3twNW3w0CogvT6YPMFZGWrmqA1IN7zDR+zspq7lKhLkpGT2pIyw==
X-Received: by 2002:a17:906:4b13:: with SMTP id y19mr8716428eju.145.1565190068973;
        Wed, 07 Aug 2019 08:01:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:94ce:: with SMTP id t14ls24843192eda.7.gmail; Wed, 07
 Aug 2019 08:01:08 -0700 (PDT)
X-Received: by 2002:a50:ad48:: with SMTP id z8mr10333387edc.66.1565190068416;
        Wed, 07 Aug 2019 08:01:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565190068; cv=none;
        d=google.com; s=arc-20160816;
        b=vT1Cb0DlhYSBsDxuk5Os36tkMq0WZBjM4Y34wPxMC/1ck4OWCmS3z05R8X6hNlMeOQ
         A5i8BaQs6af2lVe4uYax0KA6JY/Tqd5TX/qKFtOoaLUal2LfT+ErW3Dm1l5/P19GgNN1
         cdKRktAku8Z5Szg7f2NnV70JURkt7HruuCu2/33eQGZaCMVaIbnHHmy4fKTY1hgAt+HE
         IguKtXD0u0g/Y23nAhNk9Nksfb9b93wp3shYHYcDAY2eE1hrcWRoZbE5RY+wtAXprue5
         YRKxPwYCVHQFVvdVfVET6jkdN6cQH2eQAQQGur0hfy2aGMbhKzIbqOq4jYrApnkppUX3
         rM4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=KTk/jsxYEOr2RjeIKWnkX+Ltl2is2fgwnpKFsrOk8/8=;
        b=s1VjQcNu87Al2RVTUh2rfTUKiYiJD85vwPXyHdXoldEIsTu+Dv7N/S5c7CceKWZi2B
         Csh7UWYrSAl86P4Wve68COybgINt55ofV5cHbYFhRUAeIUAPgzYp42pD7/DOiS0e9BgU
         7l5YHouf+6qmGVFtpDAwxDQuhrFWUzrCQ2r5cgafW4Fr+EKJHpUF4TsZaU9ZN48CTrU9
         WWRsDGq24a2hiGPRK16o2AIjrH/ZfnS0a2zw0IUTGCjnOL9wFFmDfhJ2xQrAPS2neKum
         vHo1p4A1mKWM7xXEHCf5vg4eGDZclem+TJJmDdx0Ifha+TsyXQ6WsBAeYJwDGJq/PLA7
         NdJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=sRJQtK8f;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id k51si3504622edd.0.2019.08.07.08.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 08:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 463ZSy223gz9vBn3;
	Wed,  7 Aug 2019 17:01:06 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id m0nSBStJOG36; Wed,  7 Aug 2019 17:01:06 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 463ZSy0pcTz9vBn1;
	Wed,  7 Aug 2019 17:01:06 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B64BC8B835;
	Wed,  7 Aug 2019 17:01:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id lLYk9-4xDcJM; Wed,  7 Aug 2019 17:01:07 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 885588B832;
	Wed,  7 Aug 2019 17:01:07 +0200 (CEST)
Subject: Re: [PATCH 3/4] powerpc: support KASAN instrumentation of bitops
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 Nicholas Piggin <npiggin@gmail.com>
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <b96900fd-2b43-f6b9-0d22-2d715370baf0@c-s.fr>
Date: Wed, 7 Aug 2019 17:01:07 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190806233827.16454-4-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=sRJQtK8f;       spf=pass (google.com:
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



Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
> In KASAN development I noticed that the powerpc-specific bitops
> were not being picked up by the KASAN test suite.
>=20
> Instrumentation is done via the bitops-instrumented.h header. It
> requies that arch-specific versions of bitop functions are renamed
> to arch_*. Do this renaming.
>=20
> For clear_bit_unlock_is_negative_byte, the current implementation
> uses the PG_waiter constant. This works because it's a preprocessor
> macro - so it's only actually evaluated in contexts where PG_waiter
> is defined. With instrumentation however, it becomes a static inline
> function, and all of a sudden we need the actual value of PG_waiter.
> Because of the order of header includes, it's not available and we
> fail to compile. Instead, manually specify that we care about bit 7.
> This is still correct: bit 7 is the bit that would mark a negative
> byte, but it does obscure the origin a little bit.
>=20
> Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   arch/powerpc/include/asm/bitops.h | 25 ++++++++++++++-----------
>   1 file changed, 14 insertions(+), 11 deletions(-)
>=20
> diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm=
/bitops.h
> index 603aed229af7..19dc16e62e6a 100644
> --- a/arch/powerpc/include/asm/bitops.h
> +++ b/arch/powerpc/include/asm/bitops.h
> @@ -86,22 +86,22 @@ DEFINE_BITOP(clear_bits, andc, "")
>   DEFINE_BITOP(clear_bits_unlock, andc, PPC_RELEASE_BARRIER)
>   DEFINE_BITOP(change_bits, xor, "")
>  =20
> -static __inline__ void set_bit(int nr, volatile unsigned long *addr)
> +static __inline__ void arch_set_bit(int nr, volatile unsigned long *addr=
)
>   {
>   	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
> +static __inline__ void arch_clear_bit(int nr, volatile unsigned long *ad=
dr)
>   {
>   	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void clear_bit_unlock(int nr, volatile unsigned long *=
addr)
> +static __inline__ void arch_clear_bit_unlock(int nr, volatile unsigned l=
ong *addr)
>   {
>   	clear_bits_unlock(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
>  =20
> -static __inline__ void change_bit(int nr, volatile unsigned long *addr)
> +static __inline__ void arch_change_bit(int nr, volatile unsigned long *a=
ddr)
>   {
>   	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
>   }
> @@ -138,26 +138,26 @@ DEFINE_TESTOP(test_and_clear_bits, andc, PPC_ATOMIC=
_ENTRY_BARRIER,
>   DEFINE_TESTOP(test_and_change_bits, xor, PPC_ATOMIC_ENTRY_BARRIER,
>   	      PPC_ATOMIC_EXIT_BARRIER, 0)
>  =20
> -static __inline__ int test_and_set_bit(unsigned long nr,
> +static __inline__ int arch_test_and_set_bit(unsigned long nr,
>   				       volatile unsigned long *addr)
>   {
>   	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_set_bit_lock(unsigned long nr,
> +static __inline__ int arch_test_and_set_bit_lock(unsigned long nr,
>   				       volatile unsigned long *addr)
>   {
>   	return test_and_set_bits_lock(BIT_MASK(nr),
>   				addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_clear_bit(unsigned long nr,
> +static __inline__ int arch_test_and_clear_bit(unsigned long nr,
>   					 volatile unsigned long *addr)
>   {
>   	return test_and_clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
>   }
>  =20
> -static __inline__ int test_and_change_bit(unsigned long nr,
> +static __inline__ int arch_test_and_change_bit(unsigned long nr,
>   					  volatile unsigned long *addr)
>   {
>   	return test_and_change_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) !=3D 0;
> @@ -186,14 +186,14 @@ static __inline__ unsigned long clear_bit_unlock_re=
turn_word(int nr,
>   }
>  =20
>   /* This is a special function for mm/filemap.c */
> -#define clear_bit_unlock_is_negative_byte(nr, addr)			\
> -	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(PG_waiters))
> +#define arch_clear_bit_unlock_is_negative_byte(nr, addr)		\
> +	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(7))

Maybe add a comment reminding that 7 is PG_waiters ?

Christophe

>  =20
>   #endif /* CONFIG_PPC64 */
>  =20
>   #include <asm-generic/bitops/non-atomic.h>
>  =20
> -static __inline__ void __clear_bit_unlock(int nr, volatile unsigned long=
 *addr)
> +static __inline__ void arch___clear_bit_unlock(int nr, volatile unsigned=
 long *addr)
>   {
>   	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
>   	__clear_bit(nr, addr);
> @@ -239,6 +239,9 @@ unsigned long __arch_hweight64(__u64 w);
>  =20
>   #include <asm-generic/bitops/find.h>
>  =20
> +/* wrappers that deal with KASAN instrumentation */
> +#include <asm-generic/bitops-instrumented.h>
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
kasan-dev/b96900fd-2b43-f6b9-0d22-2d715370baf0%40c-s.fr.
