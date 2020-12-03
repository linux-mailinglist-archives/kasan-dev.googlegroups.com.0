Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXH2UL7AKGQEKTTHYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CDBB2CD362
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 11:26:37 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id y6sf1223888ilu.14
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 02:26:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606991196; cv=pass;
        d=google.com; s=arc-20160816;
        b=qvRio+kCMuXgbtQkEC4WBC0E7qF4U0vY2zkm32+WBGNckLlsovZj1T3iYRkCgyDXxD
         9MmFe9C0j2HsTXLZ4n6boUUFbHuBiWCiEdF65cqUUjhQSFisTR32Kloeosgjy6Q7Qamk
         gafva+rV6Sa5weECStySX883ZkfdSGCwBbyKVOCKMnK8biBMHmTypTljJZyc3z31Zl3p
         /8o434ZkrXQBMA6Z4U8cAh8w7o5IJ9A75b7cgcGhHjv/vGT7Nuj5QNI4FyTgbXlAU3fJ
         D+v6emifyw/pzRqaDM6S4P3t7cRrmnPu34dB4UedNJDt+P2pgsOetlSLXF3z9PIk8TCr
         3Gqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=jviImvuNyh972y3AuGg9Vi20lQtseNYpWRnB7HPWcrs=;
        b=QTIyRtxHAmAnuYpGYRKSL6WdAdKxDvd+gJ2YdfimsIWssBU6aAs01IZ3njvyqaYXpc
         E3GNWaOnGK32NsHeCKTTgwGkdadHDG5du0fmdQP/j46egGeLiqoGvClRkXnZ3PLklJ/b
         noc0y27RWC61oa1nJf1HmZ8MEgWuP63rDNyX2j7W7kAu+7vw5a3EWPX6A4X4af9wSaaQ
         sfu8LP8fbZaFLfSVlzbjhDgh1o16NH1dYlAEcZsFXnSSippSj+TXo8ksG22uSOgraJzv
         TUuS0/OmYMHTvyq2lYeA4GGDrw0ao2hQ8OuxbA2x9d/tW/YG39jKmXd6CdIt4BLDuDPu
         N1VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jviImvuNyh972y3AuGg9Vi20lQtseNYpWRnB7HPWcrs=;
        b=KmYECyr9hkPINrEM7+QRA094GS/zGoUGc+8A4D4+gjDN09oG1LoWuXltRdbQG2OMjz
         dvwCHtfU3GPAlIxAKAzoOR1wcRo6chMquciIKkT0MJs0GyKhgaHN/5nwQCIAicToZ2ev
         TbpSJ2V3aT1ZGtT/+KR6gtdjBuiMGTTMeaC7wO3cV879BAuJ5GJBAbkhdIMofXTeTSOn
         IUB9YdCKxQPOWrZth3Pdan7G5DFbsJN5uAWLURINvSMWwqdShZ2+V5phJ3opyq5+IXD6
         IhCx3jdv/fpduUMsyE/Gv0ZSevZ/y86NWNmKPS0NCA63AUkhhCa7tp8X7DBt6w1w6W2A
         WV6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jviImvuNyh972y3AuGg9Vi20lQtseNYpWRnB7HPWcrs=;
        b=V6UeGK7pwfp+mMO7ZVXFjwkgBqJX4ZyI48TbzLZDpkTr4Ky3R51ecn8U/5Os3sLU4f
         fH5HikdqN8x/ZBNbgYKulk0yX+G1VMOeXL7/3RaPuqkojECvJIb4f6ZZoEsivLouY4cL
         QkMdfpDwHE65QgRx/jo25JFQB4F7GB9YzrSBZk0gq2dnIoE8A/+wvybBjOBsmsJM0LNZ
         JD1FRtiDOtSM2qV+0eu5Tyc2t3UajZ0A6ZtRzkz7LfUHBRbKG0GvxYdQZwWX2Kg81C4L
         iPmo3vLfrroBLsA0URt0Y7R/vVowBrU9uBzvmERCDindB4D00i+C+Brva7RgAtQzNNbu
         6NkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533J2MPlvcdaE3ySFMZcC4UFrjkEA9QZBFZnn7NcM0BEqcunTz6F
	N1ICUJRxFom0N9AsyYwbxMQ=
X-Google-Smtp-Source: ABdhPJwWDAc6wRwHA8gRQDkWNMQhj6mchPHecg/4Oaf1oGOipRGY0d198XV3trsiwQNSlb2bbZnkaA==
X-Received: by 2002:a05:6602:2c8f:: with SMTP id i15mr2666193iow.66.1606991196291;
        Thu, 03 Dec 2020 02:26:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17ca:: with SMTP id z10ls1297561ilu.2.gmail; Thu,
 03 Dec 2020 02:26:36 -0800 (PST)
X-Received: by 2002:a92:d203:: with SMTP id y3mr2290160ily.206.1606991195965;
        Thu, 03 Dec 2020 02:26:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606991195; cv=none;
        d=google.com; s=arc-20160816;
        b=xoZb3pFEG6raN9/GfNGVBw/pHm+JVdNBsFCgiF6WKVYfT1UgwN6XlnO9VLn8GLfXPT
         wnT8bB1jYmeupYaKRI4fjzXNrn1/q1xW9IZOdCpD22oRKL0oAkwkHF4kk+gcl83t1tM5
         JKKLmwD/9SZ51uM/n9xublSX4+iTcd0m09FyOY+X4n6XODzIQy63BIvXr3sb1qTqT5Ho
         RlKoYjYHbf+pgLWAZYmU5B1XoMUouVUSVMOoiv2k+Nz7NnqZANg9PCPCnPbtxK3PEeoz
         UrA3iWhYv1WMO7iyqes/ADQU4/XoSW3yYc8UdcZBZoSbNSAv3lSNzihsk0wrFzQ1s6dv
         jteQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XI9BUuReRic2maLaK1AjdDlYKv31v/cIByeA9Wm0rpo=;
        b=n09Z9NavTsIp/a84dnuHm6V7EscJ6nhqlXWAp+GiMfRQ4IPgzJkiuhDPlyLOxJ6Dfu
         cufDBQ43gtRen5aikG3dvniq/z0vw1C85RDjH6v1BLU4qIis19h9L7vsKuMd4z9NSt7u
         Hn1xHPQOPDQlHAIanaMhgVS+lPQ3ZeLiL3GApqBw/tpQMJD74XHaPAvEPEm1Idh8cHZW
         gK6YQuYxdjp459NzjLIeQNBBTUxu1nxJYBnVK90ce7IhK4i83ZiYs9bWXTPjLwzjhuaP
         42ce75yGxLe2nXCMVjvW65dI6qynnq8A9bdfkBWqAfu2JG6JRJ2Ekisb98pdpVu3hBC1
         Q3/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j1si37513ilk.3.2020.12.03.02.26.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 02:26:35 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 3 Dec 2020 10:26:29 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [PATCH mm v11 27/42] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20201203102628.GB2224@gaia>
References: <cover.1606161801.git.andreyknvl@google.com>
 <ad31529b073e22840b7a2246172c2b67747ed7c4.1606161801.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ad31529b073e22840b7a2246172c2b67747ed7c4.1606161801.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Nov 23, 2020 at 09:07:51PM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 385a189f7d39..d841a560fae7 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -200,13 +200,36 @@ do {									\
>  				CONFIG_ARM64_PAN));			\
>  } while (0)
>  
> +/*
> + * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
> + * affects EL0 and TCF affects EL1 irrespective of which TTBR is
> + * used.
> + * The kernel accesses TTBR0 usually with LDTR/STTR instructions
> + * when UAO is available, so these would act as EL0 accesses using
> + * TCF0.
> + * However futex.h code uses exclusives which would be executed as
> + * EL1, this can potentially cause a tag check fault even if the
> + * user disables TCF0.
> + *
> + * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
> + * and reset it in uaccess_disable().
> + *
> + * The Tag check override (TCO) bit disables temporarily the tag checking
> + * preventing the issue.
> + */
>  static inline void uaccess_disable(void)
>  {
> +	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
> +				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
> +
>  	__uaccess_disable(ARM64_HAS_PAN);
>  }
>  
>  static inline void uaccess_enable(void)
>  {
> +	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
> +				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
> +
>  	__uaccess_enable(ARM64_HAS_PAN);
>  }

I think that's insufficient if CONFIG_ARM64_PAN is disabled. In the !PAN
case, the get/put_user() accessors use standard LDR/STR instructions
which would follow the TCF rather than TCF0 mode checking. However, they
don't use the above uaccess_disable/enable() functions.

The current user space support is affected as well but luckily we just
skip tag checking on the uaccess routines if !PAN since the kernel TCF
is 0. With the in-kernel MTE, TCF may be more strict than TCF0.

My suggestion is to simply make CONFIG_ARM64_MTE depend on (or select)
PAN. Architecturally this should work since PAN is required for ARMv8.1,
so present with any MTE implementation. This patch is on top of -next,
though it has a Fixes tag in 5.10:

--------------------------8<---------------------------
From ecc819804c1fb1ad498d7ced07e01e3b3e055a3f Mon Sep 17 00:00:00 2001
From: Catalin Marinas <catalin.marinas@arm.com>
Date: Thu, 3 Dec 2020 10:15:39 +0000
Subject: [PATCH] arm64: mte: Ensure CONFIG_ARM64_PAN is enabled with MTE

The uaccess routines like get/put_user() rely on the user TCF0 mode
setting for tag checking. However, if CONFIG_ARM64_PAN is disabled,
these routines would use the standard LDR/STR instructions and therefore
the kernel TCF mode. In 5.10, the kernel TCF==0, so no tag checking, but
this will change with the in-kernel MTE support.

Make ARM64_MTE depend on ARM64_PAN.

Fixes: 89b94df9dfb1 ("arm64: mte: Kconfig entry")
Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/Kconfig | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 844d62df776c..f9eed3a5917e 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1673,6 +1673,8 @@ config ARM64_MTE
 	default y
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
 	depends on AS_HAS_ARMV8_5
+	# Required for tag checking in the uaccess routines
+	depends on ARM64_PAN
 	select ARCH_USES_HIGH_VMA_FLAGS
 	help
 	  Memory Tagging (part of the ARMv8.5 Extensions) provides

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203102628.GB2224%40gaia.
