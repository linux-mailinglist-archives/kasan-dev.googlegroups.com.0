Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHXAULVQKGQE7SEPU4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B986FA2EBD
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 07:11:59 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id o201sf4347239ywo.14
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 22:11:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567141918; cv=pass;
        d=google.com; s=arc-20160816;
        b=bMW2jBBkq1PATIJQm8pm8klVTIrcije+Y788HEM6yA0yNvKhKdPhmejFyVbtMi2dZC
         /3Y7ZfauFXMjpIB+Usdg756BE2qXAgx48bjf1KgnEJVnVUN0aQjnTKdnipogfYdPUjUP
         DnBitoHhzHuQzOvOmseWS3K/1GwqlGRL0Guc8unzLsCl+qDtIohjKn3PusqBtl8KiLSx
         a8/U1/aXqq64ifplbvBA6RmYvrH/SqEWRZDSDvfICLl8KR1YzRRfk98cZM7oXE993wXr
         VbU0Vg5Tmg/ln8741dvqe6BqjQL/02kpoI+ryuIXDZYNhBJ2WrU24PW/IKcwoBoJuZ4G
         Q0AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=tOFlf2NBhBtcDLgcMPrEAfsJDwVNJGcD8RY+NFB3OrQ=;
        b=w06KUJta4FrHoNru5xREDPL+novWCaUrO60b4oydKhx56DJK1VU1+sSLzFDyVG0cij
         VlU3tmI0SbdyGpq2hd0FyEW9M3PxI8AcOlonuIls3zigVEY1FtxgI/YhdzQF6COD6ylQ
         popx/fbG6r6dl7r7vTB7jZT3ePflQcWScCBe9Kv0FBmDrXTjb/KVDA/C4KjvRup6YE+F
         OgCqMGELkLvs/3NUdQLOuGzIjwg7WzDZjju/eMj5Gue0kVls9bj4L/84Gfqz/DGEdrSu
         ZPHqvxK0jkldLoqKNv6WrbnPjz8Mhk+kghepf1odRxWjXUI8tk2YOYc4fB/J7tse0LA4
         T2Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qBsOfnWT;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOFlf2NBhBtcDLgcMPrEAfsJDwVNJGcD8RY+NFB3OrQ=;
        b=ZdsxAdezwhxkj/WUlPTUUdh11ToDVs8mat3JKZjNwRx49ggFvLX1z8QdcGufC32COL
         VAWGMJkOQ1QMAMn+/sgPilcJWnDliDflium9Tbfnf9BjobjL08qVbIk0l1bGgF5XtVKR
         2zIMX8+AZm+y0ZmZ3yZnC4iOT/zeOJVtRVGpr3nX8wFFCCELPC+mXkDMYnYxHAvSq7oK
         1QtzwyJPI/7nD/f4WXy8e0aIfBI2bocjrUV1EdsjFkYu/nq5y8CgitlMih+HEvsdtwXY
         Q/Nu3z9uC9fetEpJzRFywHHkJCC+ReQZ0cd8AKhis1uAnDGn8JNA7IUVlPpxrkSRxErr
         iC/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOFlf2NBhBtcDLgcMPrEAfsJDwVNJGcD8RY+NFB3OrQ=;
        b=fVNbH1lzv9udb4LVatu49As4iOsrETp8YYfBm3UA/oCA4+mp0LD/3oCdu3EFA7/NpD
         mGHuk3IxAx6YbeXSbswLxTyCzaA84C2pvwt6ld8I0iaw/K5RDZ2DGc4jMuiyqhX7Aj4P
         WVxQ79HyEH0ORTCyOB3CfyWUG0eG+deiqDUdiY1kCQAO1Q/1EaC14IxTIqLdVRT/o9ah
         7Wel3PO5fShSggnjr5XWfL3tI53m4Gf6pSilzlCWQnJ66cydk1pE25uEvUOXIull5HmB
         osNTjReaqGSCa2/W6mSQKuafESC+hs9HNa2zUgoAfANQTmUBZ5QZu9Bflhr6+vlv9z3Q
         LC7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWGcjydI+zwUykvmjDm+xQV1r90Hnohw3Z0ilG1NF3XEbhV2GjV
	PqBBJxtiTqT2RGHG++cbiK0=
X-Google-Smtp-Source: APXvYqwdk90u4UqGZbrhSqqDq3Qiw10Mt1jERX5jp8cgZkIx3Aw0xSA+HjIG23Sa9VlA+hMwfHXdSw==
X-Received: by 2002:a81:9b86:: with SMTP id s128mr4866211ywg.212.1567141918478;
        Thu, 29 Aug 2019 22:11:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7105:: with SMTP id m5ls285198ybc.8.gmail; Thu, 29 Aug
 2019 22:11:58 -0700 (PDT)
X-Received: by 2002:a25:3a45:: with SMTP id h66mr9897145yba.359.1567141918194;
        Thu, 29 Aug 2019 22:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567141918; cv=none;
        d=google.com; s=arc-20160816;
        b=SCFum/ZPG7GfZeZziONalbWvt06Btb35Xyc+k9cryFHAUK2yval8HLXAmzlufvuzK6
         ZIxradc+RUfkbauvSEmNKuI3MRfNj9+M1Y066YHZhSJduweumPKh6RiM8q6W6PRcwDYb
         FpknIr0ucOwsupmyHROT38Frv873OH1GOoWOztYPW0VUUMk6BPQZjW7l2JrQMWB7uLC4
         pSPH8MmsvusuiIhdcJ3oie+IVM+2Rg27K2RB7I6e74Si2jMJ3zoWWeAcA6t4/P6Bv12g
         wgZKGXwuYyZE2kfPvcmrNVy9hCSb890xohfm7FASuKJ/Yk8uMPdGtGGfrttNPRASaINm
         nh1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=BDDZU6io9vyxcQuCREoReDDzkBWMD2HQCXWdarYbhKA=;
        b=Zgmpc+rPLlB5lUIeBX0hTxqszSD2wo/q4g2fTeJlOGbW9B8phAJanJVjxpfmJ5TG6m
         sIt8ecZX/r0WyhhyEmwRl0qBuASu8IRTrcw1X+QliSkKVLRd7xfhd9gfqwR7zuZkfKcz
         699QP2H/BwyiozwEeG1yL7VLNasGlh+14nq817wFJCL6eUW5Hh7vnU7YQtfLYY9dYEMW
         4s+TBFFD0loygdeyOyWYbL2fn+JjcynNLYpUXOkX64WAdgPeCydowcsFUDKKfG6wUeCT
         vVK8T2cIhaFNMG0ERK/hBCShRspX1IK+39MQCoGKxgSesHuc3Y93/uLX4gU4xyXH6728
         /4ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qBsOfnWT;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id r6si363407ybb.1.2019.08.29.22.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 22:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id a67so526191pfa.6
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 22:11:58 -0700 (PDT)
X-Received: by 2002:a65:5b09:: with SMTP id y9mr11827288pgq.345.1567141917114;
        Thu, 29 Aug 2019 22:11:57 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id q3sm5353656pfn.4.2019.08.29.22.11.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 22:11:56 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <20190820024941.12640-1-dja@axtens.net>
References: <20190820024941.12640-1-dja@axtens.net>
Date: Fri, 30 Aug 2019 15:11:37 +1000
Message-ID: <877e6vutiu.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qBsOfnWT;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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

Daniel Axtens <dja@axtens.net> writes:

> Currently bitops-instrumented.h assumes that the architecture provides
> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
> This is true on x86 and s390, but is not always true: there is a
> generic bitops/non-atomic.h header that provides generic non-atomic
> operations, and also a generic bitops/lock.h for locking operations.
>
> powerpc uses the generic non-atomic version, so it does not have it's
> own e.g. __set_bit that could be renamed arch___set_bit.
>
> Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
> split. This allows arches to only include the headers where they
> have arch-specific versions to rename. Update x86 and s390.

This patch should not cause any functional change on either arch.

To verify, I have compiled kernels with and without these. With the
appropriate setting of environment variables and the general assorted
mucking around required for reproducible builds, I have tested:

 - s390, without kasan - byte-for-byte identical vmlinux before and after
 - x86,  without kasan - byte-for-byte identical vmlinux before and after

 - s390, inline kasan  - byte-for-byte identical vmlinux before and after

 - x86,  inline kasan  - 3 functions in drivers/rtc/dev.o are reordered,
                         build-id and __ex_table differ, rest is unchanged

The kernels were based on defconfigs. I disabled debug info (as that
obviously changes with code being rearranged) and initrd support (as the
cpio wrapper doesn't seem to take KBUILD_BUILD_TIMESTAMP but the current
time, and that screws things up).

I wouldn't read too much in to the weird result on x86 with inline
kasan: the code I moved about is compiled even without KASAN enabled.

Regards,
Daniel


>
> (The generic operations are automatically instrumented because they're
> written in C, not asm.)
>
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  Documentation/core-api/kernel-api.rst         |  17 +-
>  arch/s390/include/asm/bitops.h                |   4 +-
>  arch/x86/include/asm/bitops.h                 |   4 +-
>  include/asm-generic/bitops-instrumented.h     | 263 ------------------
>  .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
>  .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
>  .../bitops/instrumented-non-atomic.h          | 114 ++++++++
>  7 files changed, 317 insertions(+), 266 deletions(-)
>  delete mode 100644 include/asm-generic/bitops-instrumented.h
>  create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
>  create mode 100644 include/asm-generic/bitops/instrumented-lock.h
>  create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h
>
> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
> index 08af5caf036d..2e21248277e3 100644
> --- a/Documentation/core-api/kernel-api.rst
> +++ b/Documentation/core-api/kernel-api.rst
> @@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions.
>  Bit Operations
>  --------------
>  
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
>     :internal:
>  
>  Bitmap Operations
> diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitops.h
> index b8833ac983fa..0ceb12593a68 100644
> --- a/arch/s390/include/asm/bitops.h
> +++ b/arch/s390/include/asm/bitops.h
> @@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned long nr,
>  	arch___clear_bit(nr, ptr);
>  }
>  
> -#include <asm-generic/bitops-instrumented.h>
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> +#include <asm-generic/bitops/instrumented-lock.h>
>  
>  /*
>   * Functions which use MSB0 bit numbering.
> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
> index ba15d53c1ca7..4a2e2432238f 100644
> --- a/arch/x86/include/asm/bitops.h
> +++ b/arch/x86/include/asm/bitops.h
> @@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
>  
>  #include <asm-generic/bitops/const_hweight.h>
>  
> -#include <asm-generic/bitops-instrumented.h>
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> +#include <asm-generic/bitops/instrumented-lock.h>
>  
>  #include <asm-generic/bitops/le.h>
>  
> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
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
> - * To use this functionality, an arch's bitops.h file needs to define each of
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
> - * Unlike set_bit(), this function is non-atomic. If it is called on the same
> - * region of memory concurrently, the effect may be that only one operation
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
> - * Unlike clear_bit(), this function is non-atomic. If it is called on the same
> - * region of memory concurrently, the effect may be that only one operation
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
> -static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
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
> - * This is a non-atomic operation but implies a release barrier before the
> - * memory operation. It can be used for an unlock if no other CPUs can
> - * concurrently modify other bits in the word.
> - */
> -static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
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
> - * Unlike change_bit(), this function is non-atomic. If it is called on the same
> - * region of memory concurrently, the effect may be that only one operation
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
> - * This is an atomic fully-ordered operation (implied full memory barrier).
> - */
> -static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
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
> - * This operation is non-atomic. If two instances of this operation race, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
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
> -static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
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
> - * This is an atomic fully-ordered operation (implied full memory barrier).
> - */
> -static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
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
> - * This operation is non-atomic. If two instances of this operation race, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
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
> - * This is an atomic fully-ordered operation (implied full memory barrier).
> - */
> -static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
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
> - * This operation is non-atomic. If two instances of this operation race, one
> - * can appear to succeed but actually fail.
> - */
> -static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
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
> - * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
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
> -#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
> -#endif
> -
> -#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
> diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
> new file mode 100644
> index 000000000000..18ce3c9e8eec
> --- /dev/null
> +++ b/include/asm-generic/bitops/instrumented-atomic.h
> @@ -0,0 +1,100 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for atomic bit
> + * operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define each of
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
> + * This is an atomic fully-ordered operation (implied full memory barrier).
> + */
> +static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
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
> + * This is an atomic fully-ordered operation (implied full memory barrier).
> + */
> +static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
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
> + * This is an atomic fully-ordered operation (implied full memory barrier).
> + */
> +static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_change_bit(nr, addr);
> +}
> +
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
> diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
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
> + * To use this functionality, an arch's bitops.h file needs to define each of
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
> +static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
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
> + * This is a non-atomic operation but implies a release barrier before the
> + * memory operation. It can be used for an unlock if no other CPUs can
> + * concurrently modify other bits in the word.
> + */
> +static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
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
> +static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
> +{
> +	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +	return arch_test_and_set_bit_lock(nr, addr);
> +}
> +
> +#if defined(arch_clear_bit_unlock_is_negative_byte)
> +/**
> + * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
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
> +#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
> +#endif
> +
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
> diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
> new file mode 100644
> index 000000000000..95ff28d128a1
> --- /dev/null
> +++ b/include/asm-generic/bitops/instrumented-non-atomic.h
> @@ -0,0 +1,114 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for non-atomic
> + * bit operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define each of
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
> + * Unlike set_bit(), this function is non-atomic. If it is called on the same
> + * region of memory concurrently, the effect may be that only one operation
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
> + * Unlike clear_bit(), this function is non-atomic. If it is called on the same
> + * region of memory concurrently, the effect may be that only one operation
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
> + * Unlike change_bit(), this function is non-atomic. If it is called on the same
> + * region of memory concurrently, the effect may be that only one operation
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
> + * This operation is non-atomic. If two instances of this operation race, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
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
> + * This operation is non-atomic. If two instances of this operation race, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
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
> + * This operation is non-atomic. If two instances of this operation race, one
> + * can appear to succeed but actually fail.
> + */
> +static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
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
> -- 
> 2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877e6vutiu.fsf%40dja-thinkpad.axtens.net.
