Return-Path: <kasan-dev+bncBCXLBLOA7IGBB54I5LVAKGQEEGHMVRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E87B921E1
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 13:14:00 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id k25sf507451lfj.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 04:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566213240; cv=pass;
        d=google.com; s=arc-20160816;
        b=dITMf2W0BXHX1PgAudF8/6RScNwaJzp6N/9O5mtCbN9Mn0/PjGSY1ouWineFiK+7xZ
         Ta7x9xSUPDJQWTRdoszBkfLAB/K4Yc74WXmEDUl+QuXcwjgJm+EZcYQe8w1vmFEZdH3H
         1i13ZIpCpyd33w3UUUX3UIxJ9pEUL0PkiUiAOa+F9UHfstbJkLHUXXtI33lOxOiulAKt
         ca1EBLzIRv3jZ62w6jkiJYlX1B3ALR+SrYJoFv9lClqt8ajECIouhv7S/4wmS9/gG0xw
         dCXYOTNDRVWptL6cr1KvT4HHijtAhIxMjILM15XCJrkXsJ/l3+jPwq7gGpvCQQFDjv5N
         vPYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=UJusFUo9aHigwfuU2QMJt3fw2GzXH4/+OH5q8cHqlZI=;
        b=0CAmuwCK/VJ6BpxKQoD/U7xfdqOwr0jyB0YJ2WfCUOS0KiBS+cLcK8zgDgpEFIzpO4
         cXtIGUs2QLTC7QCjlxzm+du8psbm6tkJDm9bPX+pq0draglEub/rbfrhd/EIAgeNSH3S
         Wk9mo+fPVGTy+KU3SyAx6Rd5/4LvuLm22OsBavRNiVx50mslYZAxGvOUfTqJ7ybJwIYF
         7QZrmCSkARxkhc5Jk1qXemj47kSag2yrLkO8cT4ZFafFMbaQ3+Z0SP9OK3xpz+GAvaLc
         KjqZh5TiEyWaFAIyJNXuIEoOTfiDIDNU7XNJOdwEQufZKb/Bm74Qv3NoIDZPT+cdYL92
         jivA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=ramJ5RU9;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UJusFUo9aHigwfuU2QMJt3fw2GzXH4/+OH5q8cHqlZI=;
        b=QmV3k1hagBFCnlJTpUNPLKbEyjd2EF9tjTuMcvxFHGfnrseG1YAovbOwyS9D90Gz89
         oGUWCbGtgFyTuJnDSl6GgOdaT0nwNQKEW2oMfmlVspOZma+mr1SfiWNqV00plkYiTRn8
         lkM75ZQISc0kTsUTLd48FMu96oWibFWulF/Rww36Zv/+zuUSgPachfPZgqLSS1B2EMHN
         A6O9l2jo1Bc3sRoQeXO6+incxdq4Qt1Q9M3Nir1lPBxkR0Z2jdV60aSy9qLCvC5/ff7P
         satV8SK2YbcifpnZUPo3UgtstPeWMB1WmxiVPmt21j1Bwg7vDPqsIBrM/ARVtDaiXpC7
         uMnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UJusFUo9aHigwfuU2QMJt3fw2GzXH4/+OH5q8cHqlZI=;
        b=Qi6M/bE0zSkF76fu5Nqlt2HuvnsoM7YVfy/znY0K+H9JKosn5p83LS9ZkbsuzxbjEH
         Z1TsD9pF0jwjGFm0eNihkgNuKTiA509EAyL2AqsYFtzTryRO32aDJIPDf94fhZEDtE9N
         IZ/1+PqIsBj8twr0viviSEsLf/SqucCIODAWbxJeZLEzm8sjXdxVwtfRIYO+ukgspySN
         0OlgRseDjmgXbALDoZrHIcQ8W93FnA5drrtRyr2GG1z1sypON3IMF214e6KrV2Lh8GcO
         SIMrT0JfD9VTn3CBt+vxEmz+R1CDwc/FVArolMrdHDCDyOQVyrtw2jrSw5p/uZUYKjIy
         MBzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVQUvt1TdSqdpTTUTx2DbKNzAoge1wmxACCMS497AVVt5FSWz/W
	oSLzW8EIzVJQsuTl11FX0M0=
X-Google-Smtp-Source: APXvYqxmtmVG1c+vsKOj+prW7oXWFeYa4NvnZ8rdyOQdIYd6uLY0Mj+ryJsYSK5/UXJz1mNBU9fCzA==
X-Received: by 2002:a19:2207:: with SMTP id i7mr12562494lfi.78.1566213239834;
        Mon, 19 Aug 2019 04:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860d:: with SMTP id a13ls875756lji.4.gmail; Mon, 19 Aug
 2019 04:13:59 -0700 (PDT)
X-Received: by 2002:a2e:2bc1:: with SMTP id r62mr8681902ljr.215.1566213239310;
        Mon, 19 Aug 2019 04:13:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566213239; cv=none;
        d=google.com; s=arc-20160816;
        b=e5r8LrlEXEnfLk4GsM3DHAqQXoLNFrJqFHpK/ewlYCjv9hLVoRunGgiLvuMvinUsrG
         Sf4S1g5tUJ619UAX68dFGCq/rFWO7xWxD0T5wR2lKaXMOnanPPxMOzZK2ASDEQ4wcJdD
         wnjahc1JGXp9MAY5bV3sI/JjzaMYT5MaewaJ2/hMgcmRZbqm/DM8Fghn85oVkaxi1ye2
         HDhClYNdHvmGSq89k7BKHd0bvsUTdgiD42bdYn9h8LVxa62fnfN62CRQkPYjveGRano6
         YHaxy8EfrWovxM8YjLvGo0XDCy2O8KLWTFmLgm6DJsuQsmxDujdqlPbCbRaxH2dkvXw3
         iV6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Qa36/ZV23YLoxH5dypntYvzfFhXm/LNaj9kJFgYe0Og=;
        b=DO+z2ITsl6d48tUfTdsz9cwRFYXa7Wp/b4u+hK5IWuKWp0FJH9+hnB43Q2XMz20Zpn
         oIE2fen3l3VJZhmPkb8qZdnlSqHigPMSjOGVBMafP74dxDe/Bl38VWEYdP8dvzYauQCq
         ZPYgjivbZGJDPorcY9cw9klPv8wLEiKdrRwaSKiB+bbjFJ7Gq3PgW/hT3aYIw+C8JGZt
         J9YKKRCC3z2I5H5hDGrL8buM0ZlhK0QDq4rH2UHBSgXok2xlDP3uVhH8c6juhzATLYRM
         NRpgC0d09kiQ5FoU59QccYd16xDDqyLCBOY+4SB7dVB922JYzG1O69NZNpoO47+QtBTL
         iuQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=ramJ5RU9;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id c12si227340lji.0.2019.08.19.04.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 04:13:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46BrsD6rhDz9v0Tw;
	Mon, 19 Aug 2019 13:13:52 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id iYxzepr8e_KW; Mon, 19 Aug 2019 13:13:52 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46BrsD5jwmz9v0Tv;
	Mon, 19 Aug 2019 13:13:52 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 218458B7B1;
	Mon, 19 Aug 2019 13:13:58 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id xonJeIpIn123; Mon, 19 Aug 2019 13:13:58 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id DD5F48B778;
	Mon, 19 Aug 2019 13:13:57 +0200 (CEST)
Subject: Re: [PATCH 1/2] kasan: support instrumented bitops combined with
 generic bitops
To: Daniel Axtens <dja@axtens.net>, linux-s390@vger.kernel.org,
 linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com
References: <20190819062814.5315-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <c3231cb1-a705-579e-cb27-183320f708af@c-s.fr>
Date: Mon, 19 Aug 2019 13:13:42 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190819062814.5315-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=ramJ5RU9;       spf=pass (google.com:
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
> Currently bitops-instrumented.h assumes that the architecture provides
> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
> This is true on x86 and s390, but is not always true: there is a
> generic bitops/non-atomic.h header that provides generic non-atomic
> operations, and also a generic bitops/lock.h for locking operations.
>=20
> powerpc uses the generic non-atomic version, so it does not have it's
> own e.g. __set_bit that could be renamed arch___set_bit.
>=20
> Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
> split. This allows arches to only include the headers where they
> have arch-specific versions to rename. Update x86 and s390.
>=20
> (The generic operations are automatically instrumented because they're
> written in C, not asm.)
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

> ---
>   Documentation/core-api/kernel-api.rst         |  17 +-
>   arch/s390/include/asm/bitops.h                |   4 +-
>   arch/x86/include/asm/bitops.h                 |   4 +-
>   include/asm-generic/bitops-instrumented.h     | 263 ------------------
>   .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
>   .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
>   .../bitops/instrumented-non-atomic.h          | 114 ++++++++
>   7 files changed, 317 insertions(+), 266 deletions(-)
>   delete mode 100644 include/asm-generic/bitops-instrumented.h
>   create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
>   create mode 100644 include/asm-generic/bitops/instrumented-lock.h
>   create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h
>=20
> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-a=
pi/kernel-api.rst
> index 08af5caf036d..2e21248277e3 100644
> --- a/Documentation/core-api/kernel-api.rst
> +++ b/Documentation/core-api/kernel-api.rst
> @@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions=
.
>   Bit Operations
>   --------------
>  =20
> -.. kernel-doc:: include/asm-generic/bitops-instrumented.h
> +Atomic Operations
> +~~~~~~~~~~~~~~~~~
> +
> +.. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
> +   :internal:
> +
> +Non-atomic Operations
> +~~~~~~~~~~~~~~~~~~~~~
> +
> +.. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
> +   :internal:
> +
> +Locking Operations
> +~~~~~~~~~~~~~~~~~~
> +
> +.. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
>      :internal:
>  =20
>   Bitmap Operations
> diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitop=
s.h
> index b8833ac983fa..0ceb12593a68 100644
> --- a/arch/s390/include/asm/bitops.h
> +++ b/arch/s390/include/asm/bitops.h
> @@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned l=
ong nr,
>   	arch___clear_bit(nr, ptr);
>   }
>  =20
> -#include <asm-generic/bitops-instrumented.h>
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> +#include <asm-generic/bitops/instrumented-lock.h>
>  =20
>   /*
>    * Functions which use MSB0 bit numbering.
> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.=
h
> index ba15d53c1ca7..4a2e2432238f 100644
> --- a/arch/x86/include/asm/bitops.h
> +++ b/arch/x86/include/asm/bitops.h
> @@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
>  =20
>   #include <asm-generic/bitops/const_hweight.h>
>  =20
> -#include <asm-generic/bitops-instrumented.h>
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> +#include <asm-generic/bitops/instrumented-lock.h>
>  =20
>   #include <asm-generic/bitops/le.h>
>  =20
> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-gene=
ric/bitops-instrumented.h
> deleted file mode 100644
> index ddd1c6d9d8db..000000000000
> --- a/include/asm-generic/bitops-instrumented.h
> +++ /dev/null
> @@ -1,263 +0,0 @@
> -/* SPDX-License-Identifier: GPL-2.0 */
> -
> -/*
> - * This file provides wrappers with sanitizer instrumentation for bit
> - * operations.
> - *
> - * To use this functionality, an arch's bitops.h file needs to define ea=
ch of
> - * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> - * arch___set_bit(), etc.).
> - */
> -#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> -#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> -
> -#include <linux/kasan-checks.h>
> -
> -/**
> - * set_bit - Atomically set a bit in memory
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * This is a relaxed atomic operation (no implied memory barriers).
> - *
> - * Note that @nr may be almost arbitrarily large; this function is not
> - * restricted to acting on a single-word quantity.
> - */
> -static inline void set_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch_set_bit(nr, addr);
> -}
> -
> -/**
> - * __set_bit - Set a bit in memory
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * Unlike set_bit(), this function is non-atomic. If it is called on the=
 same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __set_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___set_bit(nr, addr);
> -}
> -
> -/**
> - * clear_bit - Clears a bit in memory
> - * @nr: Bit to clear
> - * @addr: Address to start counting from
> - *
> - * This is a relaxed atomic operation (no implied memory barriers).
> - */
> -static inline void clear_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch_clear_bit(nr, addr);
> -}
> -
> -/**
> - * __clear_bit - Clears a bit in memory
> - * @nr: the bit to clear
> - * @addr: the address to start counting from
> - *
> - * Unlike clear_bit(), this function is non-atomic. If it is called on t=
he same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __clear_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___clear_bit(nr, addr);
> -}
> -
> -/**
> - * clear_bit_unlock - Clear a bit in memory, for unlock
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * This operation is atomic and provides release barrier semantics.
> - */
> -static inline void clear_bit_unlock(long nr, volatile unsigned long *add=
r)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch_clear_bit_unlock(nr, addr);
> -}
> -
> -/**
> - * __clear_bit_unlock - Clears a bit in memory
> - * @nr: Bit to clear
> - * @addr: Address to start counting from
> - *
> - * This is a non-atomic operation but implies a release barrier before t=
he
> - * memory operation. It can be used for an unlock if no other CPUs can
> - * concurrently modify other bits in the word.
> - */
> -static inline void __clear_bit_unlock(long nr, volatile unsigned long *a=
ddr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___clear_bit_unlock(nr, addr);
> -}
> -
> -/**
> - * change_bit - Toggle a bit in memory
> - * @nr: Bit to change
> - * @addr: Address to start counting from
> - *
> - * This is a relaxed atomic operation (no implied memory barriers).
> - *
> - * Note that @nr may be almost arbitrarily large; this function is not
> - * restricted to acting on a single-word quantity.
> - */
> -static inline void change_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch_change_bit(nr, addr);
> -}
> -
> -/**
> - * __change_bit - Toggle a bit in memory
> - * @nr: the bit to change
> - * @addr: the address to start counting from
> - *
> - * Unlike change_bit(), this function is non-atomic. If it is called on =
the same
> - * region of memory concurrently, the effect may be that only one operat=
ion
> - * succeeds.
> - */
> -static inline void __change_bit(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	arch___change_bit(nr, addr);
> -}
> -
> -/**
> - * test_and_set_bit - Set a bit and return its old value
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> - */
> -static inline bool test_and_set_bit(long nr, volatile unsigned long *add=
r)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_and_set_bit(nr, addr);
> -}
> -
> -/**
> - * __test_and_set_bit - Set a bit and return its old value
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic. If two instances of this operation race=
, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_set_bit(long nr, volatile unsigned long *a=
ddr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch___test_and_set_bit(nr, addr);
> -}
> -
> -/**
> - * test_and_set_bit_lock - Set a bit and return its old value, for lock
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This operation is atomic and provides acquire barrier semantics if
> - * the returned value is 0.
> - * It can be used to implement bit locks.
> - */
> -static inline bool test_and_set_bit_lock(long nr, volatile unsigned long=
 *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_and_set_bit_lock(nr, addr);
> -}
> -
> -/**
> - * test_and_clear_bit - Clear a bit and return its old value
> - * @nr: Bit to clear
> - * @addr: Address to count from
> - *
> - * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> - */
> -static inline bool test_and_clear_bit(long nr, volatile unsigned long *a=
ddr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_and_clear_bit(nr, addr);
> -}
> -
> -/**
> - * __test_and_clear_bit - Clear a bit and return its old value
> - * @nr: Bit to clear
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic. If two instances of this operation race=
, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_clear_bit(long nr, volatile unsigned long =
*addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch___test_and_clear_bit(nr, addr);
> -}
> -
> -/**
> - * test_and_change_bit - Change a bit and return its old value
> - * @nr: Bit to change
> - * @addr: Address to count from
> - *
> - * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> - */
> -static inline bool test_and_change_bit(long nr, volatile unsigned long *=
addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_and_change_bit(nr, addr);
> -}
> -
> -/**
> - * __test_and_change_bit - Change a bit and return its old value
> - * @nr: Bit to change
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic. If two instances of this operation race=
, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_change_bit(long nr, volatile unsigned long=
 *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch___test_and_change_bit(nr, addr);
> -}
> -
> -/**
> - * test_bit - Determine whether a bit is set
> - * @nr: bit number to test
> - * @addr: Address to start counting from
> - */
> -static inline bool test_bit(long nr, const volatile unsigned long *addr)
> -{
> -	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_test_bit(nr, addr);
> -}
> -
> -#if defined(arch_clear_bit_unlock_is_negative_byte)
> -/**
> - * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if=
 bottom
> - *                                     byte is negative, for unlock.
> - * @nr: the bit to clear
> - * @addr: the address to start counting from
> - *
> - * This operation is atomic and provides release barrier semantics.
> - *
> - * This is a bit of a one-trick-pony for the filemap code, which clears
> - * PG_locked and tests PG_waiters,
> - */
> -static inline bool
> -clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
> -{
> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> -	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
> -}
> -/* Let everybody know we have it. */
> -#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_b=
yte
> -#endif
> -
> -#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
> diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/a=
sm-generic/bitops/instrumented-atomic.h
> new file mode 100644
> index 000000000000..18ce3c9e8eec
> --- /dev/null
> +++ b/include/asm-generic/bitops/instrumented-atomic.h
> @@ -0,0 +1,100 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for atomic=
 bit
> + * operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define ea=
ch of
> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> + * arch___set_bit(), etc.).
> + */
> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
> +
> +#include <linux/kasan-checks.h>
> +
> +/**
> + * set_bit - Atomically set a bit in memory
> + * @nr: the bit to set
> + * @addr: the address to start counting from
> + *
> + * This is a relaxed atomic operation (no implied memory barriers).
> + *
> + * Note that @nr may be almost arbitrarily large; this function is not
> + * restricted to acting on a single-word quantity.
> + */
> +static inline void set_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch_set_bit(nr, addr);
> +}
> +
> +/**
> + * clear_bit - Clears a bit in memory
> + * @nr: Bit to clear
> + * @addr: Address to start counting from
> + *
> + * This is a relaxed atomic operation (no implied memory barriers).
> + */
> +static inline void clear_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch_clear_bit(nr, addr);
> +}
> +
> +/**
> + * change_bit - Toggle a bit in memory
> + * @nr: Bit to change
> + * @addr: Address to start counting from
> + *
> + * This is a relaxed atomic operation (no implied memory barriers).
> + *
> + * Note that @nr may be almost arbitrarily large; this function is not
> + * restricted to acting on a single-word quantity.
> + */
> +static inline void change_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch_change_bit(nr, addr);
> +}
> +
> +/**
> + * test_and_set_bit - Set a bit and return its old value
> + * @nr: Bit to set
> + * @addr: Address to count from
> + *
> + * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> + */
> +static inline bool test_and_set_bit(long nr, volatile unsigned long *add=
r)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_set_bit(nr, addr);
> +}
> +
> +/**
> + * test_and_clear_bit - Clear a bit and return its old value
> + * @nr: Bit to clear
> + * @addr: Address to count from
> + *
> + * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> + */
> +static inline bool test_and_clear_bit(long nr, volatile unsigned long *a=
ddr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_clear_bit(nr, addr);
> +}
> +
> +/**
> + * test_and_change_bit - Change a bit and return its old value
> + * @nr: Bit to change
> + * @addr: Address to count from
> + *
> + * This is an atomic fully-ordered operation (implied full memory barrie=
r).
> + */
> +static inline bool test_and_change_bit(long nr, volatile unsigned long *=
addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_change_bit(nr, addr);
> +}
> +
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
> diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm=
-generic/bitops/instrumented-lock.h
> new file mode 100644
> index 000000000000..ec53fdeea9ec
> --- /dev/null
> +++ b/include/asm-generic/bitops/instrumented-lock.h
> @@ -0,0 +1,81 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for bit
> + * locking operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define ea=
ch of
> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> + * arch___set_bit(), etc.).
> + */
> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
> +
> +#include <linux/kasan-checks.h>
> +
> +/**
> + * clear_bit_unlock - Clear a bit in memory, for unlock
> + * @nr: the bit to set
> + * @addr: the address to start counting from
> + *
> + * This operation is atomic and provides release barrier semantics.
> + */
> +static inline void clear_bit_unlock(long nr, volatile unsigned long *add=
r)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch_clear_bit_unlock(nr, addr);
> +}
> +
> +/**
> + * __clear_bit_unlock - Clears a bit in memory
> + * @nr: Bit to clear
> + * @addr: Address to start counting from
> + *
> + * This is a non-atomic operation but implies a release barrier before t=
he
> + * memory operation. It can be used for an unlock if no other CPUs can
> + * concurrently modify other bits in the word.
> + */
> +static inline void __clear_bit_unlock(long nr, volatile unsigned long *a=
ddr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___clear_bit_unlock(nr, addr);
> +}
> +
> +/**
> + * test_and_set_bit_lock - Set a bit and return its old value, for lock
> + * @nr: Bit to set
> + * @addr: Address to count from
> + *
> + * This operation is atomic and provides acquire barrier semantics if
> + * the returned value is 0.
> + * It can be used to implement bit locks.
> + */
> +static inline bool test_and_set_bit_lock(long nr, volatile unsigned long=
 *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_set_bit_lock(nr, addr);
> +}
> +
> +#if defined(arch_clear_bit_unlock_is_negative_byte)
> +/**
> + * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if=
 bottom
> + *                                     byte is negative, for unlock.
> + * @nr: the bit to clear
> + * @addr: the address to start counting from
> + *
> + * This operation is atomic and provides release barrier semantics.
> + *
> + * This is a bit of a one-trick-pony for the filemap code, which clears
> + * PG_locked and tests PG_waiters,
> + */
> +static inline bool
> +clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
> +}
> +/* Let everybody know we have it. */
> +#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_b=
yte
> +#endif
> +
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
> diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/inclu=
de/asm-generic/bitops/instrumented-non-atomic.h
> new file mode 100644
> index 000000000000..95ff28d128a1
> --- /dev/null
> +++ b/include/asm-generic/bitops/instrumented-non-atomic.h
> @@ -0,0 +1,114 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for non-at=
omic
> + * bit operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define ea=
ch of
> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> + * arch___set_bit(), etc.).
> + */
> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
> +
> +#include <linux/kasan-checks.h>
> +
> +/**
> + * __set_bit - Set a bit in memory
> + * @nr: the bit to set
> + * @addr: the address to start counting from
> + *
> + * Unlike set_bit(), this function is non-atomic. If it is called on the=
 same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __set_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___set_bit(nr, addr);
> +}
> +
> +/**
> + * __clear_bit - Clears a bit in memory
> + * @nr: the bit to clear
> + * @addr: the address to start counting from
> + *
> + * Unlike clear_bit(), this function is non-atomic. If it is called on t=
he same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __clear_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___clear_bit(nr, addr);
> +}
> +
> +/**
> + * __change_bit - Toggle a bit in memory
> + * @nr: the bit to change
> + * @addr: the address to start counting from
> + *
> + * Unlike change_bit(), this function is non-atomic. If it is called on =
the same
> + * region of memory concurrently, the effect may be that only one operat=
ion
> + * succeeds.
> + */
> +static inline void __change_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	arch___change_bit(nr, addr);
> +}
> +
> +/**
> + * __test_and_set_bit - Set a bit and return its old value
> + * @nr: Bit to set
> + * @addr: Address to count from
> + *
> + * This operation is non-atomic. If two instances of this operation race=
, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_set_bit(long nr, volatile unsigned long *a=
ddr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch___test_and_set_bit(nr, addr);
> +}
> +
> +/**
> + * __test_and_clear_bit - Clear a bit and return its old value
> + * @nr: Bit to clear
> + * @addr: Address to count from
> + *
> + * This operation is non-atomic. If two instances of this operation race=
, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_clear_bit(long nr, volatile unsigned long =
*addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch___test_and_clear_bit(nr, addr);
> +}
> +
> +/**
> + * __test_and_change_bit - Change a bit and return its old value
> + * @nr: Bit to change
> + * @addr: Address to count from
> + *
> + * This operation is non-atomic. If two instances of this operation race=
, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_change_bit(long nr, volatile unsigned long=
 *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch___test_and_change_bit(nr, addr);
> +}
> +
> +/**
> + * test_bit - Determine whether a bit is set
> + * @nr: bit number to test
> + * @addr: Address to start counting from
> + */
> +static inline bool test_bit(long nr, const volatile unsigned long *addr)
> +{
> +	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_bit(nr, addr);
> +}
> +
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c3231cb1-a705-579e-cb27-183320f708af%40c-s.fr.
