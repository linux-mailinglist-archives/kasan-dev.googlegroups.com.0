Return-Path: <kasan-dev+bncBDV37XP3XYDRB5M24OWQMGQE7CVWH7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4395384210F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 11:20:39 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3638219eb79sf204935ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 02:20:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706610038; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8eilo+XyBdviTdFamIiRjmFnBfON2ByHOkSrSIRe74+N5COUl2fhlQ4c/ZIwMBHXF
         sYgwSIwDJBU/eks1gZO5969It0wnC3a1u8eoucz72jPw2YHTcMPAjbYkiPOxGgI1j9VE
         opTMD9zfprRaVm3xEStFasIYVEmr6lSrQELAwnYTHYN+Z72UM75htqa9Np3hA7fB8jUu
         aWPQJpoka1vdgiOdNH9sDG2oyxaJk6I3tJFyCWhbSOZqUKTiRcgwDJuUgm8gAPhXv6dA
         d4MubIv3uOL2mUlQyX9N/QSYOJdScoZ5c3+pe5u66tvNYO+MMG0hVHq8rq62lja/DrLG
         pCMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KfuNeefOReSJFPRHbusifqVECnipp9iOKawEc2jtlvA=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=FlSlpGNaMI4lRUlJnB+65SvxIyUyayEXXCIeQswC/Nw5kBzGNVYnshsBoEoMUNNd5M
         WfyVPpbVCvv8BwUN2uYVj18k9gBsDdVN47V2VtB5tlotr/D8Z29kdDOKav9KpigPsH6A
         cW5BJJ3rrnuucBnxVhRDJG4S1Y1/7U4EIGS2T96SY2xRZvZHkh5jmxS/uz8y/eWY/Ko2
         qv8C6k0H9PSy8wZuy1+kbj37wdhVdyBenkkJSA5svNXvAwsEiSPVEYfgpDNz0EPD8NGf
         VDlv6BLyWIrkeONCmEzV/gGCI4ryl4FN72EGqJhDKOuGL32GWa25Ul2QoWzZ/cmn9lHW
         Hpog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706610038; x=1707214838; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KfuNeefOReSJFPRHbusifqVECnipp9iOKawEc2jtlvA=;
        b=khy5XvEUANIzfTlNMabBqJRRZ8hN916ovXHD9Cufj7qNgpYrZmNZge3m1VFC3RxIi8
         c19zBA6/PCGvXNagDvwOHPdBxFOHX4R4LuRv/nV3Y26gn+H7FxOep9MDvHQEDKcytrAw
         OsvA4IU78KXv9wBI4PS+VgGzhKgIKrLkGABMa01VLfTwHtwyCRKtzy96sGrdf6Qj6CpC
         rSvtfjDnEpa0uOBcZ/7tnNv4PcVPu+fhz1m6HWaNTMxJJf3TKdCWR6MF67OVWqKl8Mdm
         1Yz7YgrqZYZEfNSbWBT1Zp8VmWK2I6up55LXCK8sgVo5qtWkXD9kY2sHszpLZ44XRxxw
         3ltw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706610038; x=1707214838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KfuNeefOReSJFPRHbusifqVECnipp9iOKawEc2jtlvA=;
        b=FCoR4Q2zGNjU3B62Pt2216pojdQi5kZPP/KKq+TJgTNC6pR8wxUngGUGmQwNqCNp1X
         J9KuSTkYmh+KZ3CqjEz0zHXK2OMWs4ACL98G/JD9CU8RtAZ2DxRnXOgMYYstIhzfSNbB
         sbsNUt9Aai8+XPEz18Kv5O2IMm+zh178Dc1Jte8yuZsV3AT4V84QawHqo9yvYTx7SjuQ
         nBZEKLysId711ERdxfJ6ubP7yCBtY+Fifgv0mdqaPiExfu7+CQHEe+tnliETrPNkLdP4
         lPs3CabBzaZvAzsnAEIwUsPDhj62Q46rgKYi3Tx7q1SP8vAWAKNbZrpk5Kp8F9wgX5a9
         gKsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxf+Z/3F+1bifJLUSVZo8MN+F+C82VkHFsyslx011KPQEXWlTuR
	fsR7HQex45VvP8EoBBNh6ZWfT6lgHQbC8DiBQuQM+aE31NlvpSez
X-Google-Smtp-Source: AGHT+IFbjyAYkcQsmIrWctvDJ8hybT9SliHDBwtPa/BXKH+xg7wr5jT4EzIil6RkJwIw6fEE/j3CQg==
X-Received: by 2002:a92:c083:0:b0:360:8006:1c0c with SMTP id h3-20020a92c083000000b0036080061c0cmr159698ile.23.1706610037821;
        Tue, 30 Jan 2024 02:20:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:970e:b0:217:2d0a:d876 with SMTP id
 n14-20020a056870970e00b002172d0ad876ls141383oaq.0.-pod-prod-05-us; Tue, 30
 Jan 2024 02:20:36 -0800 (PST)
X-Received: by 2002:a05:6870:618a:b0:214:e52c:ae30 with SMTP id a10-20020a056870618a00b00214e52cae30mr7952863oah.54.1706610036009;
        Tue, 30 Jan 2024 02:20:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706610035; cv=none;
        d=google.com; s=arc-20160816;
        b=lPQhAt6FGewR21B3hnbDtnO3XlH2SF6BOHrAc9QolePAog/8DKNbW/799VO7HcByZo
         1iEC5ZX1UwL0d/phaEtS10pSC1q09qKNn5/8sqy9WRG3KXTKy+WakZay/JQkgjAYmf5Q
         IjizRG/mGOGXPa7dm5v8EBl7bCto5aoZgGncBCsg6u8qvOF6rtkLsnen6gwoi97fsfCW
         MTW/BCJqVfiC+Su2XYeImhzZJay3R351dWHrj+LW1wAjCTH057zOWyYucbY1hlkDBMF+
         qGMyFbu0BCXomvYLrzZJGM+a7So2dt2ZvOhvp5tEz/HtTxlbrDOL56hxnHHmGmKHbMn8
         u2Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=X4nX+btmqoT9xRaxOXm66G/mPnZq/Whj1mYSAqn/1Vc=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=uSGj6aP12LtNCxjFxeWuqDts4ZGtmu5gLkR+AshKyS1tUTkkZlBKY/FzRcufhbmsOZ
         HZFzqrX2VH4648PZIN5Dkq1rH4xzvgk4Se6XzEARy2mPH1gG4B5i1lyfwJdmxjQ5N4G2
         O8CrEAHSmUat5jFCeLhNOZhffumDN24a4yUXB9r7yTb/vHH+yIWlbA9dIYCYXcgHi5hN
         a5PYVWfFC6PVli5ClHVrmy3AVLTM7krkh61jO31ssf3exkcYlpBQebChsn2bu4AvjOKH
         FHpMNFh8GcPQ4edCCKXg3YZIOyjrtYs0m7QzpVom/uj7JXnYdCKo0WWj9dCalEnUM4oe
         kqjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id gh22-20020a0568703b1600b0021868acb041si727753oab.4.2024.01.30.02.20.35
        for <kasan-dev@googlegroups.com>;
        Tue, 30 Jan 2024 02:20:35 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D91FADA7;
	Tue, 30 Jan 2024 02:21:18 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 035BD3F5A1;
	Tue, 30 Jan 2024 02:20:30 -0800 (PST)
Date: Tue, 30 Jan 2024 10:20:28 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 6/6] arm64: introduce copy_mc_to_kernel()
 implementation
Message-ID: <ZbjNbA1Onnjd6kyp@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-7-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240129134652.4004931-7-tongtiangen@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 29, 2024 at 09:46:52PM +0800, Tong Tiangen wrote:
> The copy_mc_to_kernel() helper is memory copy implementation that handles
> source exceptions. It can be used in memory copy scenarios that tolerate
> hardware memory errors(e.g: pmem_read/dax_copy_to_iter).
> 
> Currnently, only x86 and ppc suuport this helper, after arm64 support
> machine check safe framework, we introduce copy_mc_to_kernel()
> implementation.
> 
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>  arch/arm64/include/asm/string.h  |   5 +
>  arch/arm64/include/asm/uaccess.h |  21 +++
>  arch/arm64/lib/Makefile          |   2 +-
>  arch/arm64/lib/memcpy_mc.S       | 257 +++++++++++++++++++++++++++++++
>  mm/kasan/shadow.c                |  12 ++
>  5 files changed, 296 insertions(+), 1 deletion(-)
>  create mode 100644 arch/arm64/lib/memcpy_mc.S

Looking at the diffstat and code, this duplicates arch/arm64/lib/memcpy.S with
a few annotations. Duplicating that code is not maintainable, and so we cannot
take this as-is.

If you want a version that can handle faults that *must* be written such that
the code is shared with the regular memcpy. That could be done by using macros
to instantiate two copies (one with fault handling, the other without).

It would also be very helpful to see *any* indication that this has been
tested, which is sorely lacking in the series as-is.

Mark.

> diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
> index 3a3264ff47b9..995b63c26e99 100644
> --- a/arch/arm64/include/asm/string.h
> +++ b/arch/arm64/include/asm/string.h
> @@ -35,6 +35,10 @@ extern void *memchr(const void *, int, __kernel_size_t);
>  extern void *memcpy(void *, const void *, __kernel_size_t);
>  extern void *__memcpy(void *, const void *, __kernel_size_t);
>  
> +#define __HAVE_ARCH_MEMCPY_MC
> +extern int memcpy_mcs(void *, const void *, __kernel_size_t);
> +extern int __memcpy_mcs(void *, const void *, __kernel_size_t);
> +
>  #define __HAVE_ARCH_MEMMOVE
>  extern void *memmove(void *, const void *, __kernel_size_t);
>  extern void *__memmove(void *, const void *, __kernel_size_t);
> @@ -57,6 +61,7 @@ void memcpy_flushcache(void *dst, const void *src, size_t cnt);
>   */
>  
>  #define memcpy(dst, src, len) __memcpy(dst, src, len)
> +#define memcpy_mcs(dst, src, len) __memcpy_mcs(dst, src, len)
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
>  
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 14be5000c5a0..61e28ef2112a 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -425,4 +425,25 @@ static inline size_t probe_subpage_writeable(const char __user *uaddr,
>  
>  #endif /* CONFIG_ARCH_HAS_SUBPAGE_FAULTS */
>  
> +#ifdef CONFIG_ARCH_HAS_COPY_MC
> +/**
> + * copy_mc_to_kernel - memory copy that handles source exceptions
> + *
> + * @dst:	destination address
> + * @src:	source address
> + * @len:	number of bytes to copy
> + *
> + * Return 0 for success, or #size if there was an exception.
> + */
> +static inline unsigned long __must_check
> +copy_mc_to_kernel(void *to, const void *from, unsigned long size)
> +{
> +	int ret;
> +
> +	ret = memcpy_mcs(to, from, size);
> +	return (ret == -EFAULT) ? size : 0;
> +}
> +#define copy_mc_to_kernel copy_mc_to_kernel
> +#endif
> +
>  #endif /* __ASM_UACCESS_H */
> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
> index a2fd865b816d..899d6ae9698c 100644
> --- a/arch/arm64/lib/Makefile
> +++ b/arch/arm64/lib/Makefile
> @@ -3,7 +3,7 @@ lib-y		:= clear_user.o delay.o copy_from_user.o		\
>  		   copy_to_user.o copy_page.o				\
>  		   clear_page.o csum.o insn.o memchr.o memcpy.o		\
>  		   memset.o memcmp.o strcmp.o strncmp.o strlen.o	\
> -		   strnlen.o strchr.o strrchr.o tishift.o
> +		   strnlen.o strchr.o strrchr.o tishift.o memcpy_mc.o
>  
>  ifeq ($(CONFIG_KERNEL_MODE_NEON), y)
>  obj-$(CONFIG_XOR_BLOCKS)	+= xor-neon.o
> diff --git a/arch/arm64/lib/memcpy_mc.S b/arch/arm64/lib/memcpy_mc.S
> new file mode 100644
> index 000000000000..7076b500d154
> --- /dev/null
> +++ b/arch/arm64/lib/memcpy_mc.S
> @@ -0,0 +1,257 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (c) 2012-2021, Arm Limited.
> + *
> + * Adapted from the original at:
> + * https://github.com/ARM-software/optimized-routines/blob/afd6244a1f8d9229/string/aarch64/memcpy.S
> + */
> +
> +#include <linux/linkage.h>
> +#include <asm/assembler.h>
> +
> +/* Assumptions:
> + *
> + * ARMv8-a, AArch64, unaligned accesses.
> + *
> + */
> +
> +#define L(label) .L ## label
> +
> +#define dstin	x0
> +#define src	x1
> +#define count	x2
> +#define dst	x3
> +#define srcend	x4
> +#define dstend	x5
> +#define A_l	x6
> +#define A_lw	w6
> +#define A_h	x7
> +#define B_l	x8
> +#define B_lw	w8
> +#define B_h	x9
> +#define C_l	x10
> +#define C_lw	w10
> +#define C_h	x11
> +#define D_l	x12
> +#define D_h	x13
> +#define E_l	x14
> +#define E_h	x15
> +#define F_l	x16
> +#define F_h	x17
> +#define G_l	count
> +#define G_h	dst
> +#define H_l	src
> +#define H_h	srcend
> +#define tmp1	x14
> +
> +/* This implementation handles overlaps and supports both memcpy and memmove
> +   from a single entry point.  It uses unaligned accesses and branchless
> +   sequences to keep the code small, simple and improve performance.
> +
> +   Copies are split into 3 main cases: small copies of up to 32 bytes, medium
> +   copies of up to 128 bytes, and large copies.  The overhead of the overlap
> +   check is negligible since it is only required for large copies.
> +
> +   Large copies use a software pipelined loop processing 64 bytes per iteration.
> +   The destination pointer is 16-byte aligned to minimize unaligned accesses.
> +   The loop tail is handled by always copying 64 bytes from the end.
> +*/
> +
> +SYM_FUNC_START(__pi_memcpy_mcs)
> +	add	srcend, src, count
> +	add	dstend, dstin, count
> +	cmp	count, 128
> +	b.hi	L(copy_long)
> +	cmp	count, 32
> +	b.hi	L(copy32_128)
> +
> +	/* Small copies: 0..32 bytes.  */
> +	cmp	count, 16
> +	b.lo	L(copy16)
> +	CPY_MC(9998f, ldp	A_l, A_h, [src])
> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
> +	mov x0, #0
> +	ret
> +
> +	/* Copy 8-15 bytes.  */
> +L(copy16):
> +	tbz	count, 3, L(copy8)
> +	CPY_MC(9998f, ldr	A_l, [src])
> +	CPY_MC(9998f, ldr	A_h, [srcend, -8])
> +	CPY_MC(9998f, str	A_l, [dstin])
> +	CPY_MC(9998f, str	A_h, [dstend, -8])
> +	mov x0, #0
> +	ret
> +
> +	.p2align 3
> +	/* Copy 4-7 bytes.  */
> +L(copy8):
> +	tbz	count, 2, L(copy4)
> +	CPY_MC(9998f, ldr	A_lw, [src])
> +	CPY_MC(9998f, ldr	B_lw, [srcend, -4])
> +	CPY_MC(9998f, str	A_lw, [dstin])
> +	CPY_MC(9998f, str	B_lw, [dstend, -4])
> +	mov x0, #0
> +	ret
> +
> +	/* Copy 0..3 bytes using a branchless sequence.  */
> +L(copy4):
> +	cbz	count, L(copy0)
> +	lsr	tmp1, count, 1
> +	CPY_MC(9998f, ldrb	A_lw, [src])
> +	CPY_MC(9998f, ldrb	C_lw, [srcend, -1])
> +	CPY_MC(9998f, ldrb	B_lw, [src, tmp1])
> +	CPY_MC(9998f, strb	A_lw, [dstin])
> +	CPY_MC(9998f, strb	B_lw, [dstin, tmp1])
> +	CPY_MC(9998f, strb	C_lw, [dstend, -1])
> +L(copy0):
> +	mov x0, #0
> +	ret
> +
> +	.p2align 4
> +	/* Medium copies: 33..128 bytes.  */
> +L(copy32_128):
> +	CPY_MC(9998f, ldp	A_l, A_h, [src])
> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -32])
> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
> +	cmp	count, 64
> +	b.hi	L(copy128)
> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
> +	mov x0, #0
> +	ret
> +
> +	.p2align 4
> +	/* Copy 65..128 bytes.  */
> +L(copy128):
> +	CPY_MC(9998f, ldp	E_l, E_h, [src, 32])
> +	CPY_MC(9998f, ldp	F_l, F_h, [src, 48])
> +	cmp	count, 96
> +	b.ls	L(copy96)
> +	CPY_MC(9998f, ldp	G_l, G_h, [srcend, -64])
> +	CPY_MC(9998f, ldp	H_l, H_h, [srcend, -48])
> +	CPY_MC(9998f, stp	G_l, G_h, [dstend, -64])
> +	CPY_MC(9998f, stp	H_l, H_h, [dstend, -48])
> +L(copy96):
> +	CPY_MC(9998f, stp	A_l, A_h, [dstin])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
> +	CPY_MC(9998f, stp	E_l, E_h, [dstin, 32])
> +	CPY_MC(9998f, stp	F_l, F_h, [dstin, 48])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
> +	mov x0, #0
> +	ret
> +
> +	.p2align 4
> +	/* Copy more than 128 bytes.  */
> +L(copy_long):
> +	/* Use backwards copy if there is an overlap.  */
> +	sub	tmp1, dstin, src
> +	cbz	tmp1, L(copy0)
> +	cmp	tmp1, count
> +	b.lo	L(copy_long_backwards)
> +
> +	/* Copy 16 bytes and then align dst to 16-byte alignment.  */
> +
> +	CPY_MC(9998f, ldp	D_l, D_h, [src])
> +	and	tmp1, dstin, 15
> +	bic	dst, dstin, 15
> +	sub	src, src, tmp1
> +	add	count, count, tmp1	/* Count is now 16 too large.  */
> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstin])
> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
> +	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
> +	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
> +	subs	count, count, 128 + 16	/* Test and readjust count.  */
> +	b.ls	L(copy64_from_end)
> +
> +L(loop64):
> +	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
> +	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
> +	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
> +	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
> +	CPY_MC(9998f, stp	D_l, D_h, [dst, 64]!)
> +	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
> +	subs	count, count, 64
> +	b.hi	L(loop64)
> +
> +	/* Write the last iteration and copy 64 bytes from the end.  */
> +L(copy64_from_end):
> +	CPY_MC(9998f, ldp	E_l, E_h, [srcend, -64])
> +	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -48])
> +	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
> +	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -16])
> +	CPY_MC(9998f, stp	D_l, D_h, [dst, 64])
> +	CPY_MC(9998f, stp	E_l, E_h, [dstend, -64])
> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -48])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -16])
> +	mov x0, #0
> +	ret
> +
> +	.p2align 4
> +
> +	/* Large backwards copy for overlapping copies.
> +	   Copy 16 bytes and then align dst to 16-byte alignment.  */
> +L(copy_long_backwards):
> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
> +	and	tmp1, dstend, 15
> +	sub	srcend, srcend, tmp1
> +	sub	count, count, tmp1
> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
> +	sub	dstend, dstend, tmp1
> +	subs	count, count, 128
> +	b.ls	L(copy64_from_start)
> +
> +L(loop64_backwards):
> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
> +	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
> +	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
> +	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64]!)
> +	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
> +	subs	count, count, 64
> +	b.hi	L(loop64_backwards)
> +
> +	/* Write the last iteration and copy 64 bytes from the start.  */
> +L(copy64_from_start):
> +	CPY_MC(9998f, ldp	G_l, G_h, [src, 48])
> +	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
> +	CPY_MC(9998f, ldp	A_l, A_h, [src, 32])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
> +	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
> +	CPY_MC(9998f, ldp	C_l, C_h, [src])
> +	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64])
> +	CPY_MC(9998f, stp	G_l, G_h, [dstin, 48])
> +	CPY_MC(9998f, stp	A_l, A_h, [dstin, 32])
> +	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
> +	CPY_MC(9998f, stp	C_l, C_h, [dstin])
> +	mov x0, #0
> +	ret
> +
> +9998:	mov x0, #-EFAULT
> +	ret
> +SYM_FUNC_END(__pi_memcpy_mcs)
> +
> +SYM_FUNC_ALIAS(__memcpy_mcs, __pi_memcpy_mcs)
> +EXPORT_SYMBOL(__memcpy_mcs)
> +SYM_FUNC_ALIAS_WEAK(memcpy_mcs, __memcpy_mcs)
> +EXPORT_SYMBOL(memcpy_mcs)
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 9ef84f31833f..e6519fd329b2 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -79,6 +79,18 @@ void *memcpy(void *dest, const void *src, size_t len)
>  }
>  #endif
>  
> +#ifdef __HAVE_ARCH_MEMCPY_MC
> +#undef memcpy_mcs
> +int memcpy_mcs(void *dest, const void *src, size_t len)
> +{
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return (unsigned long)len;
> +
> +	return __memcpy_mcs(dest, src, len);
> +}
> +#endif
> +
>  void *__asan_memset(void *addr, int c, ssize_t len)
>  {
>  	if (!kasan_check_range(addr, len, true, _RET_IP_))
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbjNbA1Onnjd6kyp%40FVFF77S0Q05N.
