Return-Path: <kasan-dev+bncBDQ27FVWWUFRBA7H3PWQKGQEMN4P35A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C3FD4E72EE
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 14:56:20 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id q187sf5048248vkq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 06:56:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572270979; cv=pass;
        d=google.com; s=arc-20160816;
        b=aMiQSW1n7LaGG/IufBKad1oVcT4dzvr9B0W4PKwu8iphv07aIEFqpErVVtNFfCe1yR
         EY1+QvsEC6s/fC996ajwfii/qXlefhq3H85WQwHCI82gO6Rv5+QZ9xX4kaU+GuX5iRRU
         2JX+yjwtpKl2DocL3+6n0EFnvDXIn5b3UJYMhafV46kPY438TjD5Yp9Uz9zMUOaL/Fud
         lTI0DCiqrxfYbwm5Lb+XefGc3cKnSdBvSowvh+XV5cGLL0mQKQaGmC/WM/Ws6PSE2VRP
         istF+WXNu4RhH5Al0G4J1uznSCDwHjQ816TiY+ULh9RqLqJB0RQmoGyJJm8K2q8MC1yS
         /c+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=iURv45LzCUhfhQow5gIo5K5lYRvTXqDyKXkkAQ5JmbU=;
        b=RKfR7giKdLcRV4BY1SINCHA8tar0hGayusxVnD32yo8cb2lR/g55TDGXN6GOrAJkrP
         2Zlv0jedYBMwR31bT7DQwrLSuKMI2odNqK5RM9GSwphtM8kOh4JZvUcPQf8Waw8suObD
         mqOgTZpeTr1qRXdSSIXSvk7ycaYAKbnsG38yz5Kgn0Fb0iWj237E17mT+7ucYMyw86U9
         u/girihgxVxp/4PvGeJ0bT6QOcsfm8f9OJ40P7o3c1ZYsJauOyIBr23FZLDFsifKJorv
         gFjVftc9fx377eUDJuluhcAar1L2tm2Q6cAPple5GbnfOK0cMbdpW56DZ7KWme2Mk8vr
         ypOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Mvv9arsl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iURv45LzCUhfhQow5gIo5K5lYRvTXqDyKXkkAQ5JmbU=;
        b=JVStbPxWt22X8M9l9WOfEWxmltqTx8w6vVANlqlsduDN8SpcTTKK8H01WbM14qJEqB
         RNdD++Mbubrt2B00TdgGnPwj8hJycykTUxV2VZR6Enzot7hK+DKsx7tyPicSxRhTwW3R
         v6XoDOQpsMtqu3VTqip7nn347UXwiHmbv0ha0WMb0BNen37ywOGDenmFQAgAOZko8fP3
         z94MY75IaGdhFrzrXOx2KYyPNbg+5jMYyfdGc5MmYyjihg5NdjMQBrehCnB2PiQG1GWZ
         Q2SVhaZJ2JQtTRtgTe17Ezv2uCr3tqKSzbkZ/71uAR1icxw1RBakQqwKBKWtWI6GiilG
         GvVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iURv45LzCUhfhQow5gIo5K5lYRvTXqDyKXkkAQ5JmbU=;
        b=VpVzNGptSia+3J+7wxS4oS1F2JSvKmMK8XDE+ZTT8ZEvlTrfSHkOgJXdmS751l49Fw
         X1Gl9s/kNsjufpbo76NjPvT1nZHYUWUKBjjhFw2n7tYra2SyF6AlWDTiLbGPrtHR/p3H
         EpSNf5N0Q+aJAOTBP02FKJN2FQNf1sJhrKuJUlMObjPZN3JZg5U63BHxdOSiKSgpC6sv
         T77JxuR+nPpkQzAzKyiRKqpvao7CpfOyxYR3wU42Xk3MRrD1V6Nls60NbPYmFQ+LOTZ1
         Ctb1A37aN9gUxGmiYr52ZQt/DOkSo0OcjRRrKIzrcHuj+sYiZD8r1DB26C84EP7ER9yx
         GmLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW4LO9uy4ibBrNP7lYQTjaHkMWtXfQDmo1yDL1YH9GuYSQydhTt
	okpNy/63jbUYK2f/Ckg1d/8=
X-Google-Smtp-Source: APXvYqzFrb3QMW3ZkfTEbyuLtqbV8kkbc9OxRAtYof5vMu90c5UkV4iRJ2toGEOfEBE7LpkL+TyE3g==
X-Received: by 2002:a1f:4b05:: with SMTP id y5mr8216943vka.12.1572270979361;
        Mon, 28 Oct 2019 06:56:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:c387:: with SMTP id t129ls605919vkf.12.gmail; Mon, 28
 Oct 2019 06:56:19 -0700 (PDT)
X-Received: by 2002:a1f:8c01:: with SMTP id o1mr469673vkd.69.1572270978980;
        Mon, 28 Oct 2019 06:56:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572270978; cv=none;
        d=google.com; s=arc-20160816;
        b=DzYFLmsir/WphRnjVENXDAP1e8FnBebnYNI98YpLUmrpzahLVoNY/Js6lHJXTx1nUp
         GNaLuYFI2W66dEwDJunqGC/aG43YAwMVD6L6JUJrx2qZpZhIk0OiVwcN4lHAxzn52YwU
         k9qpcA6pLTfnDJNix2v4edbxhQ8Ou5q7ECFGiB3vVaR/Dp9e9idpw6E9XQZmMsNgrLBq
         AlsWrZ9STh6X84hLXwSOf7W2XZKu669zqIsutrfHNnmoPsLZeg5Tq+Xh1ff7IuKHn+Aj
         P9Qw/yYo4ntAc9tRmsnhCJUZbTHIh7q38BWB9cE6B7s2mRhIr2EL6IAMrE3hjQAKMhhG
         65vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=NlNcagJRlCYv67eS/EOooXlXEuL3iiAxaHHrNsMQ/qQ=;
        b=RflHq9U53yTPM45EjzYbpjFH0wdt9iIGP4F07JXbdu3RGFLjsEvClIHPC3LhO6Y3iI
         Hx5jKBaFRvsk5Dxrz1U6Bp9Y1LVelhsMq4cd7FSKOdm3PvPn5ZMDZrQbSFjlXLuWqo6N
         NYotqMVaCXsCJID+m33mcNFaVNSfculgamjiJbE+ng8EW5PCzyVNPA7idFq+9nlIcM8S
         hx1sg6Q3Zcr88NEUGMnDhZbdahK3SafFzHJckGK6JcdTR4vFfzjVxKpOoGmwcydLSvGP
         HpOmYKZJ7wWfaosMwSgoSvUGu2ZUvG4KvfsxcN/3T1DnCqSfX8y4Q7G0h05LFog+1sFJ
         SzUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Mvv9arsl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id p18si455582vsn.1.2019.10.28.06.56.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 06:56:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id p12so6927132pgn.6
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 06:56:18 -0700 (PDT)
X-Received: by 2002:a65:4189:: with SMTP id a9mr20663758pgq.380.1572270977427;
        Mon, 28 Oct 2019 06:56:17 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id q6sm13421896pgn.44.2019.10.28.06.56.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 06:56:16 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <877e6vutiu.fsf@dja-thinkpad.axtens.net>
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net>
Date: Tue, 29 Oct 2019 00:56:11 +1100
Message-ID: <878sp57z44.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Mvv9arsl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi all,

Would it be possible to get an Ack from a KASAN maintainter? mpe is
happy to take this through powerpc but would like an ack first.

Regards,
Daniel

>> Currently bitops-instrumented.h assumes that the architecture provides
>> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
>> This is true on x86 and s390, but is not always true: there is a
>> generic bitops/non-atomic.h header that provides generic non-atomic
>> operations, and also a generic bitops/lock.h for locking operations.
>>
>> powerpc uses the generic non-atomic version, so it does not have it's
>> own e.g. __set_bit that could be renamed arch___set_bit.
>>
>> Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
>> split. This allows arches to only include the headers where they
>> have arch-specific versions to rename. Update x86 and s390.
>
> This patch should not cause any functional change on either arch.
>
> To verify, I have compiled kernels with and without these. With the
> appropriate setting of environment variables and the general assorted
> mucking around required for reproducible builds, I have tested:
>
>  - s390, without kasan - byte-for-byte identical vmlinux before and after
>  - x86,  without kasan - byte-for-byte identical vmlinux before and after
>
>  - s390, inline kasan  - byte-for-byte identical vmlinux before and after
>
>  - x86,  inline kasan  - 3 functions in drivers/rtc/dev.o are reordered,
>                          build-id and __ex_table differ, rest is unchanged
>
> The kernels were based on defconfigs. I disabled debug info (as that
> obviously changes with code being rearranged) and initrd support (as the
> cpio wrapper doesn't seem to take KBUILD_BUILD_TIMESTAMP but the current
> time, and that screws things up).
>
> I wouldn't read too much in to the weird result on x86 with inline
> kasan: the code I moved about is compiled even without KASAN enabled.
>
> Regards,
> Daniel
>
>
>>
>> (The generic operations are automatically instrumented because they're
>> written in C, not asm.)
>>
>> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
>> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> ---
>>  Documentation/core-api/kernel-api.rst         |  17 +-
>>  arch/s390/include/asm/bitops.h                |   4 +-
>>  arch/x86/include/asm/bitops.h                 |   4 +-
>>  include/asm-generic/bitops-instrumented.h     | 263 ------------------
>>  .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
>>  .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
>>  .../bitops/instrumented-non-atomic.h          | 114 ++++++++
>>  7 files changed, 317 insertions(+), 266 deletions(-)
>>  delete mode 100644 include/asm-generic/bitops-instrumented.h
>>  create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
>>  create mode 100644 include/asm-generic/bitops/instrumented-lock.h
>>  create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h
>>
>> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
>> index 08af5caf036d..2e21248277e3 100644
>> --- a/Documentation/core-api/kernel-api.rst
>> +++ b/Documentation/core-api/kernel-api.rst
>> @@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions.
>>  Bit Operations
>>  --------------
>>  
>> -.. kernel-doc:: include/asm-generic/bitops-instrumented.h
>> +Atomic Operations
>> +~~~~~~~~~~~~~~~~~
>> +
>> +.. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
>> +   :internal:
>> +
>> +Non-atomic Operations
>> +~~~~~~~~~~~~~~~~~~~~~
>> +
>> +.. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
>> +   :internal:
>> +
>> +Locking Operations
>> +~~~~~~~~~~~~~~~~~~
>> +
>> +.. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
>>     :internal:
>>  
>>  Bitmap Operations
>> diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitops.h
>> index b8833ac983fa..0ceb12593a68 100644
>> --- a/arch/s390/include/asm/bitops.h
>> +++ b/arch/s390/include/asm/bitops.h
>> @@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned long nr,
>>  	arch___clear_bit(nr, ptr);
>>  }
>>  
>> -#include <asm-generic/bitops-instrumented.h>
>> +#include <asm-generic/bitops/instrumented-atomic.h>
>> +#include <asm-generic/bitops/instrumented-non-atomic.h>
>> +#include <asm-generic/bitops/instrumented-lock.h>
>>  
>>  /*
>>   * Functions which use MSB0 bit numbering.
>> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
>> index ba15d53c1ca7..4a2e2432238f 100644
>> --- a/arch/x86/include/asm/bitops.h
>> +++ b/arch/x86/include/asm/bitops.h
>> @@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
>>  
>>  #include <asm-generic/bitops/const_hweight.h>
>>  
>> -#include <asm-generic/bitops-instrumented.h>
>> +#include <asm-generic/bitops/instrumented-atomic.h>
>> +#include <asm-generic/bitops/instrumented-non-atomic.h>
>> +#include <asm-generic/bitops/instrumented-lock.h>
>>  
>>  #include <asm-generic/bitops/le.h>
>>  
>> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
>> deleted file mode 100644
>> index ddd1c6d9d8db..000000000000
>> --- a/include/asm-generic/bitops-instrumented.h
>> +++ /dev/null
>> @@ -1,263 +0,0 @@
>> -/* SPDX-License-Identifier: GPL-2.0 */
>> -
>> -/*
>> - * This file provides wrappers with sanitizer instrumentation for bit
>> - * operations.
>> - *
>> - * To use this functionality, an arch's bitops.h file needs to define each of
>> - * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
>> - * arch___set_bit(), etc.).
>> - */
>> -#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
>> -#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
>> -
>> -#include <linux/kasan-checks.h>
>> -
>> -/**
>> - * set_bit - Atomically set a bit in memory
>> - * @nr: the bit to set
>> - * @addr: the address to start counting from
>> - *
>> - * This is a relaxed atomic operation (no implied memory barriers).
>> - *
>> - * Note that @nr may be almost arbitrarily large; this function is not
>> - * restricted to acting on a single-word quantity.
>> - */
>> -static inline void set_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch_set_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __set_bit - Set a bit in memory
>> - * @nr: the bit to set
>> - * @addr: the address to start counting from
>> - *
>> - * Unlike set_bit(), this function is non-atomic. If it is called on the same
>> - * region of memory concurrently, the effect may be that only one operation
>> - * succeeds.
>> - */
>> -static inline void __set_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch___set_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * clear_bit - Clears a bit in memory
>> - * @nr: Bit to clear
>> - * @addr: Address to start counting from
>> - *
>> - * This is a relaxed atomic operation (no implied memory barriers).
>> - */
>> -static inline void clear_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch_clear_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __clear_bit - Clears a bit in memory
>> - * @nr: the bit to clear
>> - * @addr: the address to start counting from
>> - *
>> - * Unlike clear_bit(), this function is non-atomic. If it is called on the same
>> - * region of memory concurrently, the effect may be that only one operation
>> - * succeeds.
>> - */
>> -static inline void __clear_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch___clear_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * clear_bit_unlock - Clear a bit in memory, for unlock
>> - * @nr: the bit to set
>> - * @addr: the address to start counting from
>> - *
>> - * This operation is atomic and provides release barrier semantics.
>> - */
>> -static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch_clear_bit_unlock(nr, addr);
>> -}
>> -
>> -/**
>> - * __clear_bit_unlock - Clears a bit in memory
>> - * @nr: Bit to clear
>> - * @addr: Address to start counting from
>> - *
>> - * This is a non-atomic operation but implies a release barrier before the
>> - * memory operation. It can be used for an unlock if no other CPUs can
>> - * concurrently modify other bits in the word.
>> - */
>> -static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch___clear_bit_unlock(nr, addr);
>> -}
>> -
>> -/**
>> - * change_bit - Toggle a bit in memory
>> - * @nr: Bit to change
>> - * @addr: Address to start counting from
>> - *
>> - * This is a relaxed atomic operation (no implied memory barriers).
>> - *
>> - * Note that @nr may be almost arbitrarily large; this function is not
>> - * restricted to acting on a single-word quantity.
>> - */
>> -static inline void change_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch_change_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __change_bit - Toggle a bit in memory
>> - * @nr: the bit to change
>> - * @addr: the address to start counting from
>> - *
>> - * Unlike change_bit(), this function is non-atomic. If it is called on the same
>> - * region of memory concurrently, the effect may be that only one operation
>> - * succeeds.
>> - */
>> -static inline void __change_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	arch___change_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * test_and_set_bit - Set a bit and return its old value
>> - * @nr: Bit to set
>> - * @addr: Address to count from
>> - *
>> - * This is an atomic fully-ordered operation (implied full memory barrier).
>> - */
>> -static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_test_and_set_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __test_and_set_bit - Set a bit and return its old value
>> - * @nr: Bit to set
>> - * @addr: Address to count from
>> - *
>> - * This operation is non-atomic. If two instances of this operation race, one
>> - * can appear to succeed but actually fail.
>> - */
>> -static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch___test_and_set_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * test_and_set_bit_lock - Set a bit and return its old value, for lock
>> - * @nr: Bit to set
>> - * @addr: Address to count from
>> - *
>> - * This operation is atomic and provides acquire barrier semantics if
>> - * the returned value is 0.
>> - * It can be used to implement bit locks.
>> - */
>> -static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_test_and_set_bit_lock(nr, addr);
>> -}
>> -
>> -/**
>> - * test_and_clear_bit - Clear a bit and return its old value
>> - * @nr: Bit to clear
>> - * @addr: Address to count from
>> - *
>> - * This is an atomic fully-ordered operation (implied full memory barrier).
>> - */
>> -static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_test_and_clear_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __test_and_clear_bit - Clear a bit and return its old value
>> - * @nr: Bit to clear
>> - * @addr: Address to count from
>> - *
>> - * This operation is non-atomic. If two instances of this operation race, one
>> - * can appear to succeed but actually fail.
>> - */
>> -static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch___test_and_clear_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * test_and_change_bit - Change a bit and return its old value
>> - * @nr: Bit to change
>> - * @addr: Address to count from
>> - *
>> - * This is an atomic fully-ordered operation (implied full memory barrier).
>> - */
>> -static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_test_and_change_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * __test_and_change_bit - Change a bit and return its old value
>> - * @nr: Bit to change
>> - * @addr: Address to count from
>> - *
>> - * This operation is non-atomic. If two instances of this operation race, one
>> - * can appear to succeed but actually fail.
>> - */
>> -static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch___test_and_change_bit(nr, addr);
>> -}
>> -
>> -/**
>> - * test_bit - Determine whether a bit is set
>> - * @nr: bit number to test
>> - * @addr: Address to start counting from
>> - */
>> -static inline bool test_bit(long nr, const volatile unsigned long *addr)
>> -{
>> -	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_test_bit(nr, addr);
>> -}
>> -
>> -#if defined(arch_clear_bit_unlock_is_negative_byte)
>> -/**
>> - * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
>> - *                                     byte is negative, for unlock.
>> - * @nr: the bit to clear
>> - * @addr: the address to start counting from
>> - *
>> - * This operation is atomic and provides release barrier semantics.
>> - *
>> - * This is a bit of a one-trick-pony for the filemap code, which clears
>> - * PG_locked and tests PG_waiters,
>> - */
>> -static inline bool
>> -clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
>> -{
>> -	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> -	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
>> -}
>> -/* Let everybody know we have it. */
>> -#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
>> -#endif
>> -
>> -#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
>> diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
>> new file mode 100644
>> index 000000000000..18ce3c9e8eec
>> --- /dev/null
>> +++ b/include/asm-generic/bitops/instrumented-atomic.h
>> @@ -0,0 +1,100 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +
>> +/*
>> + * This file provides wrappers with sanitizer instrumentation for atomic bit
>> + * operations.
>> + *
>> + * To use this functionality, an arch's bitops.h file needs to define each of
>> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
>> + * arch___set_bit(), etc.).
>> + */
>> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
>> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
>> +
>> +#include <linux/kasan-checks.h>
>> +
>> +/**
>> + * set_bit - Atomically set a bit in memory
>> + * @nr: the bit to set
>> + * @addr: the address to start counting from
>> + *
>> + * This is a relaxed atomic operation (no implied memory barriers).
>> + *
>> + * Note that @nr may be almost arbitrarily large; this function is not
>> + * restricted to acting on a single-word quantity.
>> + */
>> +static inline void set_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch_set_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * clear_bit - Clears a bit in memory
>> + * @nr: Bit to clear
>> + * @addr: Address to start counting from
>> + *
>> + * This is a relaxed atomic operation (no implied memory barriers).
>> + */
>> +static inline void clear_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch_clear_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * change_bit - Toggle a bit in memory
>> + * @nr: Bit to change
>> + * @addr: Address to start counting from
>> + *
>> + * This is a relaxed atomic operation (no implied memory barriers).
>> + *
>> + * Note that @nr may be almost arbitrarily large; this function is not
>> + * restricted to acting on a single-word quantity.
>> + */
>> +static inline void change_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch_change_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * test_and_set_bit - Set a bit and return its old value
>> + * @nr: Bit to set
>> + * @addr: Address to count from
>> + *
>> + * This is an atomic fully-ordered operation (implied full memory barrier).
>> + */
>> +static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_test_and_set_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * test_and_clear_bit - Clear a bit and return its old value
>> + * @nr: Bit to clear
>> + * @addr: Address to count from
>> + *
>> + * This is an atomic fully-ordered operation (implied full memory barrier).
>> + */
>> +static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_test_and_clear_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * test_and_change_bit - Change a bit and return its old value
>> + * @nr: Bit to change
>> + * @addr: Address to count from
>> + *
>> + * This is an atomic fully-ordered operation (implied full memory barrier).
>> + */
>> +static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_test_and_change_bit(nr, addr);
>> +}
>> +
>> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
>> diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
>> new file mode 100644
>> index 000000000000..ec53fdeea9ec
>> --- /dev/null
>> +++ b/include/asm-generic/bitops/instrumented-lock.h
>> @@ -0,0 +1,81 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +
>> +/*
>> + * This file provides wrappers with sanitizer instrumentation for bit
>> + * locking operations.
>> + *
>> + * To use this functionality, an arch's bitops.h file needs to define each of
>> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
>> + * arch___set_bit(), etc.).
>> + */
>> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
>> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
>> +
>> +#include <linux/kasan-checks.h>
>> +
>> +/**
>> + * clear_bit_unlock - Clear a bit in memory, for unlock
>> + * @nr: the bit to set
>> + * @addr: the address to start counting from
>> + *
>> + * This operation is atomic and provides release barrier semantics.
>> + */
>> +static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch_clear_bit_unlock(nr, addr);
>> +}
>> +
>> +/**
>> + * __clear_bit_unlock - Clears a bit in memory
>> + * @nr: Bit to clear
>> + * @addr: Address to start counting from
>> + *
>> + * This is a non-atomic operation but implies a release barrier before the
>> + * memory operation. It can be used for an unlock if no other CPUs can
>> + * concurrently modify other bits in the word.
>> + */
>> +static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch___clear_bit_unlock(nr, addr);
>> +}
>> +
>> +/**
>> + * test_and_set_bit_lock - Set a bit and return its old value, for lock
>> + * @nr: Bit to set
>> + * @addr: Address to count from
>> + *
>> + * This operation is atomic and provides acquire barrier semantics if
>> + * the returned value is 0.
>> + * It can be used to implement bit locks.
>> + */
>> +static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_test_and_set_bit_lock(nr, addr);
>> +}
>> +
>> +#if defined(arch_clear_bit_unlock_is_negative_byte)
>> +/**
>> + * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
>> + *                                     byte is negative, for unlock.
>> + * @nr: the bit to clear
>> + * @addr: the address to start counting from
>> + *
>> + * This operation is atomic and provides release barrier semantics.
>> + *
>> + * This is a bit of a one-trick-pony for the filemap code, which clears
>> + * PG_locked and tests PG_waiters,
>> + */
>> +static inline bool
>> +clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
>> +}
>> +/* Let everybody know we have it. */
>> +#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
>> +#endif
>> +
>> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
>> diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
>> new file mode 100644
>> index 000000000000..95ff28d128a1
>> --- /dev/null
>> +++ b/include/asm-generic/bitops/instrumented-non-atomic.h
>> @@ -0,0 +1,114 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +
>> +/*
>> + * This file provides wrappers with sanitizer instrumentation for non-atomic
>> + * bit operations.
>> + *
>> + * To use this functionality, an arch's bitops.h file needs to define each of
>> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
>> + * arch___set_bit(), etc.).
>> + */
>> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
>> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
>> +
>> +#include <linux/kasan-checks.h>
>> +
>> +/**
>> + * __set_bit - Set a bit in memory
>> + * @nr: the bit to set
>> + * @addr: the address to start counting from
>> + *
>> + * Unlike set_bit(), this function is non-atomic. If it is called on the same
>> + * region of memory concurrently, the effect may be that only one operation
>> + * succeeds.
>> + */
>> +static inline void __set_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch___set_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * __clear_bit - Clears a bit in memory
>> + * @nr: the bit to clear
>> + * @addr: the address to start counting from
>> + *
>> + * Unlike clear_bit(), this function is non-atomic. If it is called on the same
>> + * region of memory concurrently, the effect may be that only one operation
>> + * succeeds.
>> + */
>> +static inline void __clear_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch___clear_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * __change_bit - Toggle a bit in memory
>> + * @nr: the bit to change
>> + * @addr: the address to start counting from
>> + *
>> + * Unlike change_bit(), this function is non-atomic. If it is called on the same
>> + * region of memory concurrently, the effect may be that only one operation
>> + * succeeds.
>> + */
>> +static inline void __change_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	arch___change_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * __test_and_set_bit - Set a bit and return its old value
>> + * @nr: Bit to set
>> + * @addr: Address to count from
>> + *
>> + * This operation is non-atomic. If two instances of this operation race, one
>> + * can appear to succeed but actually fail.
>> + */
>> +static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch___test_and_set_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * __test_and_clear_bit - Clear a bit and return its old value
>> + * @nr: Bit to clear
>> + * @addr: Address to count from
>> + *
>> + * This operation is non-atomic. If two instances of this operation race, one
>> + * can appear to succeed but actually fail.
>> + */
>> +static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch___test_and_clear_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * __test_and_change_bit - Change a bit and return its old value
>> + * @nr: Bit to change
>> + * @addr: Address to count from
>> + *
>> + * This operation is non-atomic. If two instances of this operation race, one
>> + * can appear to succeed but actually fail.
>> + */
>> +static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
>> +{
>> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch___test_and_change_bit(nr, addr);
>> +}
>> +
>> +/**
>> + * test_bit - Determine whether a bit is set
>> + * @nr: bit number to test
>> + * @addr: Address to start counting from
>> + */
>> +static inline bool test_bit(long nr, const volatile unsigned long *addr)
>> +{
>> +	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
>> +	return arch_test_bit(nr, addr);
>> +}
>> +
>> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
>> -- 
>> 2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878sp57z44.fsf%40dja-thinkpad.axtens.net.
