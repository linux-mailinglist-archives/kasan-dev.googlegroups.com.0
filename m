Return-Path: <kasan-dev+bncBCXLBLOA7IGBB6MT5LVAKGQEHLOE4II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AD43892282
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 13:37:29 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id w17sf511284lff.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566214649; cv=pass;
        d=google.com; s=arc-20160816;
        b=jk8uitgKEJ1YkWDOTCCWra9iPgvbzka/QLMSthiTO7pUlMqLEC0acUnJTlp1F7Q+NS
         YkaeriCRabXjsnKyMp4uVoyM9z35fxAyxeAOICUrNWKlZ9EiObGS7KKkTschtZBvREfz
         9YPeOGgCbmBl16CCRDgeSqQYxNV7NzWYwpY2yAL81w96h6/GMVzGvoxRHPqQEOjcQvCT
         oyNL2Gp/oYOiHcRCN/7QOYzDWeUudkW97hzDGsJ55mFXidW7B43rpC8qq/rOc5Y9M87L
         m5Yo5A13kJnvZaP7VhQA+cXb3tG6JWk4ffeRoUTvUENHHetb5frSOqkUPn+zg2cZb3KV
         WWkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Y/PQ8a9nAzxisRWpHjPBMxgYjPpfYvoQSK8EoAaY6iU=;
        b=wxYoCaEVZMF0WJpKyjVqAR6y3UtlxpP/EqDX6S9N/4jmdN+hmHpG+Bs6kxe5AM2vSj
         ur+96Dl3ewKn3Gzj0YLZCPzhL0B2kzzvWuPu2ISdFT9mQ4EmchwQwDED6yCMhazskoa4
         /CDPcYabNTZ4oTYaCOJqRdbfyaqyBWv3x0dSO9etC79TQWnLG1zbqeIwPFfDN45COw2k
         5i1QpDHA5OTI5kepctQIvxb0H67deQAHLh+U67E6bSzYT6f+4qLFqI80mSVE7kh4mDPi
         LXQFdwhKJ92QWcB7QqhzppKslt5Hlbx1hDUC73t2DbGBgWGvhzicttsFpOPgkjMgIIzP
         2wIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=IHsOl9a7;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y/PQ8a9nAzxisRWpHjPBMxgYjPpfYvoQSK8EoAaY6iU=;
        b=qyNKabi+bhF51/ku5MhRvxJL+FcCVhK0Wxu46Y59KVYfCS4xb/gGJUMd3DtRX03JI/
         tizFLyDtKM5m7xcInI+BzcptDBxhNdPHa4SpecTGgr+BytAIkwiV4/fDtHHm3dDwe5Bf
         bPOK8X1ILWoRj31i7O5yZgDemqiDg54hITJ57hYoL8MfRKtf6eYE3UAiLNsi5kJLGAM/
         Il31gB5dTntCb/g2QIkg+UnJA0ZGFTkMMj3bKbXh/vj0bC4Cgw6e4+MNtuZyzz7Qa3ZR
         qPMz7FnPxqlqyI0Cj5JuSGga5JI6HTP3duxx8fAGO+GPeYg7SgAyR8R+/UK8YuwfSIos
         51Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y/PQ8a9nAzxisRWpHjPBMxgYjPpfYvoQSK8EoAaY6iU=;
        b=U9Xl4XdpuoovoJaYAW3/tFIAPDtQNlBQerU7bzPRcdcWFIA3Y0U3FP7REZyAioQPqA
         p7F0SGSwPQf98peNWJbiJmYCJ4ttzgzEKGNS1ZHxzV7JlTYMTClnQWPkabKy4/MTCAXC
         xZdVY+yV8BloDwmcs8XD/2wc1AukCP+N6c/+7CMqR/t0p9Wzk1DjmBH4DfMS6vZtIkOx
         zdwxtFCD8bmX1zOldGO4Z/ewcX0MEXDyVqa3SykBm/oOEL1wKAfdo1kExX/zOrBHwcdA
         LRyzbhmSB+V8tz/uDDd176VFP3LOnJ1xy92Tjn/7en5qX5la/jEdSEw4iFAbvvQKmZ8E
         mkFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAViVda4iFSSuTI8D22moLYGhfcxYcXDBrOYoOGj7B0NKMHElbir
	aBeSuVlPQKPF/CQFSK79F2A=
X-Google-Smtp-Source: APXvYqxPoUEDGS0BZjyArebtfsaRYZxZk3ZYOoOsg4x7wV/CTi9z3D3Z3Z/ekEw6zrmrRK0QL3gDgg==
X-Received: by 2002:a05:6512:244:: with SMTP id b4mr12760777lfo.114.1566214649261;
        Mon, 19 Aug 2019 04:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:87d5:: with SMTP id v21ls1679482ljj.5.gmail; Mon, 19 Aug
 2019 04:37:28 -0700 (PDT)
X-Received: by 2002:a2e:7c0b:: with SMTP id x11mr12240428ljc.85.1566214648715;
        Mon, 19 Aug 2019 04:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566214648; cv=none;
        d=google.com; s=arc-20160816;
        b=ol2L4O1kXns4dFXVixoI6VWWgFhUXXXCy0gMb1n/XxutSuz/p4eCb6kaXBW8AaGiFx
         FpAqMWpY+ma9yVIkONiMtN0C66iPuDnx5X0wsz+tvt7Y4rgQsHsSwebaXNkMqN7EHvqw
         4kPSt1H9qq7JOU7NJwcjA5g7VqM+edQCj9SY+fvTJKChO5m6Fr9fXJ7bEZyPwwuBImrU
         hjx72oaUz+wJWzlVeKYK+icqBlnxqXk0PwV0HbduT6ZSO0AnYRpIHr4vey8DQX4H+a04
         /NPq+29ZaDU7Tjw/2OcK0A0lSMjxAffv5KtXqugGjDLRooIp9Iejnig8Ns4TC6A/cdAn
         uS9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=DGGXu4mqnMWHUmNbB5+ROy/HiaG54r+RC+Wcdt0Sf00=;
        b=nVCrlaBkAeGzAAVm7lgRC5W/xIakYIyvda9Y7EHMDPlZu/M2/ykHWfmdTqQxW6PaW6
         MIpjk8s/wDQ0nYwxHTTZoKHiEnyRxouBYwmegtSJOGNQmWaBjyOaEtszWTWSlCGA7Pix
         K60NF0FbNaloLqnZo7LzJKlz3B+W+83ptAsXXQnB8Qyon8h+V7GYQNgRxAAVVXKeKmYi
         GGpWkz4B+rwBQKAoV6XGDHn476FVFbSzdtKgkl3bPeKJcdl9GMU2WRzEkMJkqhe1SvOa
         5xKMcKLRcQXwW7TpCPoVG6M0IzGY+9aDPJAexTiFrNG7KD+76jmpI9YEVTBWSkPV5jqm
         WltA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=IHsOl9a7;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id u10si777593lfk.0.2019.08.19.04.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 04:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46BsNL3FQnz9txwK;
	Mon, 19 Aug 2019 13:37:22 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id oFKXEToytF74; Mon, 19 Aug 2019 13:37:22 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46BsNL28mZz9txwM;
	Mon, 19 Aug 2019 13:37:22 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 9E5778B7B3;
	Mon, 19 Aug 2019 13:37:27 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id equtsE-UlxDy; Mon, 19 Aug 2019 13:37:27 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 585EE8B7B1;
	Mon, 19 Aug 2019 13:37:27 +0200 (CEST)
Subject: Re: [PATCH 2/2] powerpc: support KASAN instrumentation of bitops
To: Daniel Axtens <dja@axtens.net>, linux-s390@vger.kernel.org,
 linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, Nicholas Piggin <npiggin@gmail.com>
References: <20190819062814.5315-1-dja@axtens.net>
 <20190819062814.5315-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <a1932e9e-3697-b8a0-c936-098b390b817f@c-s.fr>
Date: Mon, 19 Aug 2019 13:37:11 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190819062814.5315-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=IHsOl9a7;       spf=pass (google.com:
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



Le 19/08/2019 =C3=A0 08:28, Daniel Axtens a =C3=A9crit=C2=A0:
> In KASAN development I noticed that the powerpc-specific bitops
> were not being picked up by the KASAN test suite.

I'm not sure anybody cares about who noticed the problem. This sentence=20
could be rephrased as:

The powerpc-specific bitops are not being picked up by the KASAN test suite=
.

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
> Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

Note that this patch might be an opportunity to replace all the=20
'__inline__' by the standard 'inline' keyword.

Some () alignment to be fixes as well, see checkpatch warnings/checks at=20
https://openpower.xyz/job/snowpatch/job/snowpatch-linux-checkpatch/8601//ar=
tifact/linux/checkpatch.log

> ---
>   arch/powerpc/include/asm/bitops.h | 31 +++++++++++++++++++------------
>   1 file changed, 19 insertions(+), 12 deletions(-)
>=20
> diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm=
/bitops.h
> index 603aed229af7..8615b2bc35fe 100644
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
> +static __inline__ void arch___clear_bit_unlock(int nr, volatile unsigned=
 long *addr)
>   {
>   	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
>   	__clear_bit(nr, addr);
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
kasan-dev/a1932e9e-3697-b8a0-c936-098b390b817f%40c-s.fr.
