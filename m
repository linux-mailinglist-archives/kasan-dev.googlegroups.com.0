Return-Path: <kasan-dev+bncBDV37XP3XYDRBWE7YXTQKGQECIXR2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2277311D9
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 18:01:28 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id x130sf3847991wmg.1
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 09:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559318488; cv=pass;
        d=google.com; s=arc-20160816;
        b=bps82qGizsltTZmOLsnD93fQVyal/HQq/3mbIe40xCCqzmpgsdCSsgWoRZ0PmI7cd7
         gh3x2WynTiZ6JMgrJM8VDMwIqJoOa5dyWeB1CiDB4BT01+2ArO3UApQK8lBHzutmPn3j
         v2wYAQHec5XDH+jFh5DnzZf3mekSYNJva4ah7bmZ9ad++9hesKoBMexOSIK7vzx9oOuP
         OQAtzDnlYMIYnq1IhpX7oRdf1XiNAogNoUgskH1gECHqq98yOV91kRAnR6Nz3ecTjlMG
         FMgKA4lrtT87G76f7JR3fkhfZxYsLFgvHsql9JjL21lPBJKz4I+Vj7vMNAxoOak3+Bef
         7LsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6QngLiBgjbTkJfDRQ0WIXhClkMRTfmq9Q5gVbYZW3+Q=;
        b=X5gliyMlJn6idp4KcHMxA9sdyz/sW/c1+ZHtLLTPQRWcZyQmh+bWhEOuKeQ0dmYRo4
         E9HuQBQUwQHVL/JxEaV/7sGCGnr/mTLlqhfLn5QRVQTZlPFm34oeHkjmdudoVMqSMoC9
         +FRSP2rWpcWisA4jCsrg+7nk0JNvXstaeOGtfBRVOws+2qnH1qiywKYqx4vpd7em+3bH
         Fa1zi7lOFcgVR3RAxgwIbzjEax0SPPgm2wO76XEqFrLqzxQjXVlELul95LZG+fsdKI7M
         Ptut9YtMNq7iRF3kKNJy/09KRpMiRsBEDrMhsJ6PQJ3O5CoK0eKy7mfi1sfIefstyH/A
         E+iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6QngLiBgjbTkJfDRQ0WIXhClkMRTfmq9Q5gVbYZW3+Q=;
        b=INHmIlXEJIXJla5KMXDW9VTGHRXtf4NGDqcrLqla57jMP3L9ZgrZfJdvRQm/UetOuF
         uUUYnynALQyLSGm/QYvgqcxQvIPQOBO8p4zvTbj/WCW/QEsLsQsx7RxNmu0pFTYQmJQS
         hYiTolZ8whpHCpGaDj75vFgzvi5XwnDroEAk9BsMAHnKZ3bcno9i4E3g+n97g4+iRl33
         vrWW2sTuU5x8Aw49/9EHAP5kMyETV4zrBDE4OujysKnsPP78x6PdJbS6tE9Kk/gJcN9p
         1dA4mDbaRPGvhCbkfGAHdJCiq9m+KelReMqvlTBanZ3MO1fvn9D/6/P1YZApUcdYySoB
         ykDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6QngLiBgjbTkJfDRQ0WIXhClkMRTfmq9Q5gVbYZW3+Q=;
        b=azpmWV0tu6gIsrSSIthIVbkISldzmd/j8eBBMV5HZm/O7xxR67yXJ3qL4R/pcZZR+B
         faBThn3xAgRGx3grCkec7x6Rvk7KPL+y+8PLdZxchQYSJrLhQmWN8cVT+Yb2hCdxYojW
         Gj7kz/kQvVWYeF75CO1IAr9mjg/2qLrsm1NI99crX6TGM0RvmWTPuxYuayDUsIuePVAu
         q6nHBCI7A4o2ZsekE9vO/UpMTUaBbuZntDdbqr+9Ebj+cUtfIaQ5HB6v/RLmTI3ikRlW
         H/vVAZrZpQ/HFJB3lj/12szRfbjEyFVzWRAt5AqirsxpdmJUHiNEjHfB51qpnRLKAaqW
         27mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOJ8KMTmBeW3RxgWJs5Fzbvb5ZTipqEyaSSYTWbDiC22oCr82D
	Zv8xnk2SAE93id1ax6BOWFg=
X-Google-Smtp-Source: APXvYqyb3TqyijyE3JfWRziRPx49SIVYO+hx0qUQcfoIyKbof9MasP6K4a2/Xmvx7ZezMupRz825RQ==
X-Received: by 2002:a1c:6242:: with SMTP id w63mr1718250wmb.161.1559318488504;
        Fri, 31 May 2019 09:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:40ce:: with SMTP id b14ls2023167wrq.0.gmail; Fri, 31 May
 2019 09:01:28 -0700 (PDT)
X-Received: by 2002:a5d:5702:: with SMTP id a2mr7336200wrv.89.1559318487981;
        Fri, 31 May 2019 09:01:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559318487; cv=none;
        d=google.com; s=arc-20160816;
        b=TvSjvwjgalC/Bd3OZc7qse17lTQLgxsLn68NNkfHBp32iaZBiikFDGSmvKRuxixlyf
         yFrDmKDIVU+nfAk52ADNtWztAHjr4zZPkJSVx62jXwRB8l/e2SgJsxA13gVehvj1ZdiM
         hh0/kEocvs5zeVfFQtp/98j3pEsrF1cJxfQr3bMSqhk3kSRGx1A7zqnRpqAzgx+RO7ze
         SpzSLZkTIi6dAiaSEWvEbTANrGzlprrilNhFgLRhnh35089Fn4bPbxGgJyE9/n+kbY9m
         z2TtF7/KIMpbUDRUAOyIitwKAfXcyxVeL0SDg3yCLSoWzn0zwm4Orw52u4yGw3DjXBLx
         DGMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=skytbQ/MVhTdetrS2HTyvoSCCCLFsq65KIyTUxPtE+Q=;
        b=TfSLZGC/pjsG0b9pIGJPfr4M73Z+kf5U8Y9x6/cV3RmtStcGVYZmmkeVfmJj6Q96XL
         tkv/DSn+KXejksY4cBuYR3VuA7YSjHqZdRzmu3vvocS9bvkixz847NyRS9MKC+o3svWg
         XpKTrFwBf6yXUgK4Xtcqp+ee2HT0CWHfSKidgRzl2lYLxDLbeGDPHxyP+Dej3DcYKaPn
         kqqMTHtb9lVbqkURv3fAGjesuhSDsAIxGgPozgl1cvRWrKHHYiH9bnLG4RuNqkjGDo02
         tSaccmUPh4cqE2jMXNmQdt8uPzOwnDaNGvXoD6xxEYZBCEexoR6eLbm1OT1UQdWRkiLt
         +bcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (usa-sjc-mx-foss1.foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id f8si280572wre.0.2019.05.31.09.01.27
        for <kasan-dev@googlegroups.com>;
        Fri, 31 May 2019 09:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E7E82341;
	Fri, 31 May 2019 09:01:26 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CF90E3F59C;
	Fri, 31 May 2019 09:01:23 -0700 (PDT)
Date: Fri, 31 May 2019 17:01:21 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com, hpa@zytor.com,
	corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190531160120.GB2646@lakrids.cambridge.arm.com>
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190531150828.157832-4-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, May 31, 2019 at 05:08:31PM +0200, Marco Elver wrote:
> This adds a new header to asm-generic to allow optionally instrumenting
> architecture-specific asm implementations of bitops.
> 
> This change includes the required change for x86 as reference and
> changes the kernel API doc to point to bitops-instrumented.h instead.
> Rationale: the functions in x86's bitops.h are no longer the kernel API
> functions, but instead the arch_ prefixed functions, which are then
> instrumented via bitops-instrumented.h.
> 
> Other architectures can similarly add support for asm implementations of
> bitops.
> 
> The documentation text was derived from x86 and existing bitops
> asm-generic versions: 1) references to x86 have been removed; 2) as a
> result, some of the text had to be reworded for clarity and consistency.
> 
> Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Changes in v3:
> * Remove references to 'x86' in API documentation; as a result, had to
>   reword doc text for clarify and consistency.
> * Remove #ifdef, since it is assumed that if asm-generic bitops
>   implementations are used, bitops-instrumented.h is not needed.

Thanks for sorting this out. FWIW:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> 
> Changes in v2:
> * Instrument word-sized accesses, as specified by the interface.
> ---
>  Documentation/core-api/kernel-api.rst     |   2 +-
>  arch/x86/include/asm/bitops.h             | 189 ++++------------
>  include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
>  3 files changed, 302 insertions(+), 152 deletions(-)
>  create mode 100644 include/asm-generic/bitops-instrumented.h
> 
> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
> index a29c99d13331..65266fa1b706 100644
> --- a/Documentation/core-api/kernel-api.rst
> +++ b/Documentation/core-api/kernel-api.rst
> @@ -51,7 +51,7 @@ The Linux kernel provides more basic utility functions.
>  Bit Operations
>  --------------
>  
> -.. kernel-doc:: arch/x86/include/asm/bitops.h
> +.. kernel-doc:: include/asm-generic/bitops-instrumented.h
>     :internal:
>  
>  Bitmap Operations
> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
> index 8e790ec219a5..ba15d53c1ca7 100644
> --- a/arch/x86/include/asm/bitops.h
> +++ b/arch/x86/include/asm/bitops.h
> @@ -49,23 +49,8 @@
>  #define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((void *)(addr) + ((nr)>>3))
>  #define CONST_MASK(nr)			(1 << ((nr) & 7))
>  
> -/**
> - * set_bit - Atomically set a bit in memory
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * This function is atomic and may not be reordered.  See __set_bit()
> - * if you do not require the atomic guarantees.
> - *
> - * Note: there are no guarantees that this function will not be reordered
> - * on non x86 architectures, so if you are writing portable code,
> - * make sure not to rely on its reordering guarantees.
> - *
> - * Note that @nr may be almost arbitrarily large; this function is not
> - * restricted to acting on a single-word quantity.
> - */
>  static __always_inline void
> -set_bit(long nr, volatile unsigned long *addr)
> +arch_set_bit(long nr, volatile unsigned long *addr)
>  {
>  	if (IS_IMMEDIATE(nr)) {
>  		asm volatile(LOCK_PREFIX "orb %1,%0"
> @@ -78,32 +63,14 @@ set_bit(long nr, volatile unsigned long *addr)
>  	}
>  }
>  
> -/**
> - * __set_bit - Set a bit in memory
> - * @nr: the bit to set
> - * @addr: the address to start counting from
> - *
> - * Unlike set_bit(), this function is non-atomic and may be reordered.
> - * If it's called on the same region of memory simultaneously, the effect
> - * may be that only one operation succeeds.
> - */
> -static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch___set_bit(long nr, volatile unsigned long *addr)
>  {
>  	asm volatile(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
>  }
>  
> -/**
> - * clear_bit - Clears a bit in memory
> - * @nr: Bit to clear
> - * @addr: Address to start counting from
> - *
> - * clear_bit() is atomic and may not be reordered.  However, it does
> - * not contain a memory barrier, so if it is used for locking purposes,
> - * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
> - * in order to ensure changes are visible on other processors.
> - */
>  static __always_inline void
> -clear_bit(long nr, volatile unsigned long *addr)
> +arch_clear_bit(long nr, volatile unsigned long *addr)
>  {
>  	if (IS_IMMEDIATE(nr)) {
>  		asm volatile(LOCK_PREFIX "andb %1,%0"
> @@ -115,26 +82,21 @@ clear_bit(long nr, volatile unsigned long *addr)
>  	}
>  }
>  
> -/*
> - * clear_bit_unlock - Clears a bit in memory
> - * @nr: Bit to clear
> - * @addr: Address to start counting from
> - *
> - * clear_bit() is atomic and implies release semantics before the memory
> - * operation. It can be used for an unlock.
> - */
> -static __always_inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch_clear_bit_unlock(long nr, volatile unsigned long *addr)
>  {
>  	barrier();
> -	clear_bit(nr, addr);
> +	arch_clear_bit(nr, addr);
>  }
>  
> -static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch___clear_bit(long nr, volatile unsigned long *addr)
>  {
>  	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
>  }
>  
> -static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
>  {
>  	bool negative;
>  	asm volatile(LOCK_PREFIX "andb %2,%1"
> @@ -143,48 +105,23 @@ static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile
>  		: "ir" ((char) ~(1 << nr)) : "memory");
>  	return negative;
>  }
> +#define arch_clear_bit_unlock_is_negative_byte                                 \
> +	arch_clear_bit_unlock_is_negative_byte
>  
> -// Let everybody know we have it
> -#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
> -
> -/*
> - * __clear_bit_unlock - Clears a bit in memory
> - * @nr: Bit to clear
> - * @addr: Address to start counting from
> - *
> - * __clear_bit() is non-atomic and implies release semantics before the memory
> - * operation. It can be used for an unlock if no other CPUs can concurrently
> - * modify other bits in the word.
> - */
> -static __always_inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch___clear_bit_unlock(long nr, volatile unsigned long *addr)
>  {
> -	__clear_bit(nr, addr);
> +	arch___clear_bit(nr, addr);
>  }
>  
> -/**
> - * __change_bit - Toggle a bit in memory
> - * @nr: the bit to change
> - * @addr: the address to start counting from
> - *
> - * Unlike change_bit(), this function is non-atomic and may be reordered.
> - * If it's called on the same region of memory simultaneously, the effect
> - * may be that only one operation succeeds.
> - */
> -static __always_inline void __change_bit(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch___change_bit(long nr, volatile unsigned long *addr)
>  {
>  	asm volatile(__ASM_SIZE(btc) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
>  }
>  
> -/**
> - * change_bit - Toggle a bit in memory
> - * @nr: Bit to change
> - * @addr: Address to start counting from
> - *
> - * change_bit() is atomic and may not be reordered.
> - * Note that @nr may be almost arbitrarily large; this function is not
> - * restricted to acting on a single-word quantity.
> - */
> -static __always_inline void change_bit(long nr, volatile unsigned long *addr)
> +static __always_inline void
> +arch_change_bit(long nr, volatile unsigned long *addr)
>  {
>  	if (IS_IMMEDIATE(nr)) {
>  		asm volatile(LOCK_PREFIX "xorb %1,%0"
> @@ -196,42 +133,20 @@ static __always_inline void change_bit(long nr, volatile unsigned long *addr)
>  	}
>  }
>  
> -/**
> - * test_and_set_bit - Set a bit and return its old value
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This operation is atomic and cannot be reordered.
> - * It also implies a memory barrier.
> - */
> -static __always_inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch_test_and_set_bit(long nr, volatile unsigned long *addr)
>  {
>  	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(bts), *addr, c, "Ir", nr);
>  }
>  
> -/**
> - * test_and_set_bit_lock - Set a bit and return its old value for lock
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This is the same as test_and_set_bit on x86.
> - */
>  static __always_inline bool
> -test_and_set_bit_lock(long nr, volatile unsigned long *addr)
> +arch_test_and_set_bit_lock(long nr, volatile unsigned long *addr)
>  {
> -	return test_and_set_bit(nr, addr);
> +	return arch_test_and_set_bit(nr, addr);
>  }
>  
> -/**
> - * __test_and_set_bit - Set a bit and return its old value
> - * @nr: Bit to set
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic and can be reordered.
> - * If two examples of this operation race, one can appear to succeed
> - * but actually fail.  You must protect multiple accesses with a lock.
> - */
> -static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch___test_and_set_bit(long nr, volatile unsigned long *addr)
>  {
>  	bool oldbit;
>  
> @@ -242,28 +157,13 @@ static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *
>  	return oldbit;
>  }
>  
> -/**
> - * test_and_clear_bit - Clear a bit and return its old value
> - * @nr: Bit to clear
> - * @addr: Address to count from
> - *
> - * This operation is atomic and cannot be reordered.
> - * It also implies a memory barrier.
> - */
> -static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch_test_and_clear_bit(long nr, volatile unsigned long *addr)
>  {
>  	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btr), *addr, c, "Ir", nr);
>  }
>  
> -/**
> - * __test_and_clear_bit - Clear a bit and return its old value
> - * @nr: Bit to clear
> - * @addr: Address to count from
> - *
> - * This operation is non-atomic and can be reordered.
> - * If two examples of this operation race, one can appear to succeed
> - * but actually fail.  You must protect multiple accesses with a lock.
> - *
> +/*
>   * Note: the operation is performed atomically with respect to
>   * the local CPU, but not other CPUs. Portable code should not
>   * rely on this behaviour.
> @@ -271,7 +171,8 @@ static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *
>   * accessed from a hypervisor on the same CPU if running in a VM: don't change
>   * this without also updating arch/x86/kernel/kvm.c
>   */
> -static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
>  {
>  	bool oldbit;
>  
> @@ -282,8 +183,8 @@ static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long
>  	return oldbit;
>  }
>  
> -/* WARNING: non atomic and it can be reordered! */
> -static __always_inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch___test_and_change_bit(long nr, volatile unsigned long *addr)
>  {
>  	bool oldbit;
>  
> @@ -295,15 +196,8 @@ static __always_inline bool __test_and_change_bit(long nr, volatile unsigned lon
>  	return oldbit;
>  }
>  
> -/**
> - * test_and_change_bit - Change a bit and return its old value
> - * @nr: Bit to change
> - * @addr: Address to count from
> - *
> - * This operation is atomic and cannot be reordered.
> - * It also implies a memory barrier.
> - */
> -static __always_inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
> +static __always_inline bool
> +arch_test_and_change_bit(long nr, volatile unsigned long *addr)
>  {
>  	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
>  }
> @@ -326,16 +220,7 @@ static __always_inline bool variable_test_bit(long nr, volatile const unsigned l
>  	return oldbit;
>  }
>  
> -#if 0 /* Fool kernel-doc since it doesn't do macros yet */
> -/**
> - * test_bit - Determine whether a bit is set
> - * @nr: bit number to test
> - * @addr: Address to start counting from
> - */
> -static bool test_bit(int nr, const volatile unsigned long *addr);
> -#endif
> -
> -#define test_bit(nr, addr)			\
> +#define arch_test_bit(nr, addr)			\
>  	(__builtin_constant_p((nr))		\
>  	 ? constant_test_bit((nr), (addr))	\
>  	 : variable_test_bit((nr), (addr)))
> @@ -504,6 +389,8 @@ static __always_inline int fls64(__u64 x)
>  
>  #include <asm-generic/bitops/const_hweight.h>
>  
> +#include <asm-generic/bitops-instrumented.h>
> +
>  #include <asm-generic/bitops/le.h>
>  
>  #include <asm-generic/bitops/ext2-atomic-setbit.h>
> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
> new file mode 100644
> index 000000000000..ddd1c6d9d8db
> --- /dev/null
> +++ b/include/asm-generic/bitops-instrumented.h
> @@ -0,0 +1,263 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for bit
> + * operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define each of
> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> + * arch___set_bit(), etc.).
> + */
> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
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
> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
> -- 
> 2.22.0.rc1.257.g3120a18244-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531160120.GB2646%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
