Return-Path: <kasan-dev+bncBAABB37CSSQQMGQEFCXIBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7136CFBED
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 08:51:29 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id e8-20020a17090a118800b0023d35ae431esf5493660pja.8
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 23:51:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680159088; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKnMaYwXsRelj8vq/qbvWib+S7/T9nzObKs94C3ZP1Qp2IxkyQslr4Wkvlq14zPNX+
         nwNnYB43moKg00m8N2futMCxWRw3Pc0ZkpP2p2bFJ5C0iCpfM/RUaovtG6bBxwgpOICR
         km+5lfsO8DyhJU65qExLSdfOyFp6g1AO2wQ/doninUKW6ojEINLSf3meLnrGbkH37VIa
         xb+nidXC3jb9U/RKbwAniy1pk+U2ZFG+nEe2tNukRDLdJnHN7FR4VYpH4ThjrZFz8Xj8
         bbjVnEY77YO4WrpKBfZFl9SDij5Ol+oGUrxdUaDUrWeg1w9T/NZ3zG20yyCCGeshaArh
         KMdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=3I6Z/3rfcPOWyO04hB6s/qLF+UMLkMzqzk6Jh+vbfRo=;
        b=fZc12RaBgeVr9Lx/K+0mi/I8aB0psRGJk/ue4tVxPPNa7+wR56uhEC8M9MZ5oQ10Yo
         SpsOHGTxxXusIFb/qTN6m15pWluBrzmwZ+KgqT1WgL9i2t7+I6OrMVW31tKA9KmWTDOO
         KfQ7ko96M0iMkBJeqDxLxMUBpWE1bqT6sx0dtOzvbsipmSt6mDrVp6/CLAxsMNIHvzMc
         ahXfXmF6TQ7vc3ocOoEXhh6RoPif260jrKq2vTzJO6grqX5Q7rIji3OsyTHWkXfRf0+2
         c7IFU+2+obOjuW0dXVvGmXwFokBJAAdN3fgY71fCveODmcjAEmQdbDEVwhPJbqhfEgH+
         I6JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680159088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3I6Z/3rfcPOWyO04hB6s/qLF+UMLkMzqzk6Jh+vbfRo=;
        b=E2eA4NXnsXSvG4xQXzgLmZrYuESzB/OWvOeTHa5WrRtOJxH9JA2HsWZ/+VXedGTTCR
         WkvrxdQwkgtrVsV3Pnl7/ZcfdISqibajbSFs4xh9kPU8By5YS3uyEzNojhAIWlY0aPMt
         e5YrzlzYuKAweHBrsJHF6JIJbmWgXPrJHHc9VPAHGPt200FURVTB+GSRLYa79cCHrnD7
         pGHW0PLSHL7/7IULWaweyGhyRY88a6PVuE6OF9HVgpvalHKHmL+fljZ1nKnJ7WXs9B3/
         LJhm4iVq8KRiv/SY2T+avNpkNIIKLyLpzDrktK3kzz1cWhGIDEePIH0NbO7LoJq1fUU0
         e0EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680159088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :mime-version:user-agent:date:message-id:from:cc:references:to
         :subject:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3I6Z/3rfcPOWyO04hB6s/qLF+UMLkMzqzk6Jh+vbfRo=;
        b=Y6NGSqHtZDCreNGHdb8Kp05t3uxk2N5CXwYagGrIhcHgCDDjbo86EPVeAsQ3uM5X/8
         3iFeFp5A5PyFZylb1uygt+A/sqNpksMqvoOUi+bNyP+zMKS8igddghldpnFbqs4BfyCo
         y9TEAts/A9J3/+zOSM/2HO4d+Op6v6KGz/6hk4AZr/GToQh1WXlc4IQI449YvpGnlG87
         043GlYYajGmBovyOYOPBNabmtwmN0Fe9FBaDNzWUoZDykdWZtAVA23RzZrVWZUlxW5xC
         ygfp30WN81jJxaLUwlXzilCEE/0ZSboVDzabg7ZZ2FUsSuY+GYswej+j7PpkPnTbO9Jg
         udbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cuiQxe0yfBtU8hNuBCsDOZSq90cjjLVstLPBDiZezBjMGZYcy0
	FNcAaGUXWB/56cyH7ZccEHA=
X-Google-Smtp-Source: AKy350aULCHES58fbNOvYuj2tBkjy2qK0IF7UvSFDRTpoglpDq1U+Bh34g7toAC6K9uqPJW8kXucGg==
X-Received: by 2002:a17:903:22c6:b0:1a0:6000:7fd0 with SMTP id y6-20020a17090322c600b001a060007fd0mr8878894plg.5.1680159087940;
        Wed, 29 Mar 2023 23:51:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1106:b0:19c:b122:6f2d with SMTP id
 n6-20020a170903110600b0019cb1226f2dls1145559plh.2.-pod-prod-gmail; Wed, 29
 Mar 2023 23:51:27 -0700 (PDT)
X-Received: by 2002:a17:903:2303:b0:19a:7f4b:3ef6 with SMTP id d3-20020a170903230300b0019a7f4b3ef6mr27724267plh.3.1680159087276;
        Wed, 29 Mar 2023 23:51:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680159087; cv=none;
        d=google.com; s=arc-20160816;
        b=x6cYpdapu7vBaSPdEITH6KjpyA5yODqbdywy/BKMT+xkLP4O1i6Xi0HAQzS/NvHncw
         4NOTwEVa09jVjWn3zmoOkDMB0XhEITihngjiaPNXdFJK8mPRfkR4t7qcV2XloDtsMFxj
         6QJB1MvZZ+EjQGl1EH/3N9whPLy5F/PYVIeMT6Y4kFrg5vvMbJFWkwO5vneogl1xbqV0
         Jkr5KhGQ34dgxpNst7ze5wnRmIdkdPW5DwjB8+hQn7v56DigRdIdGXHHIZ9egJTddtS/
         l3yuB2LRT8etiveoS2cEJMzoQxB5CqfdpLTZNX5MCvfcwWFVTZQtb+iwccIaO3C6rGOm
         //xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=nY7bVFpyIBEvtvk6GyVvqGdtGyp5kHy1dxcrN8nslJ0=;
        b=G7fRzyVy0CSZJ2KU//A1HwRlZ+Ca4BbtV18ShYAHjYLtyQ0w7DQQ9sdFz3W3kfeN9Q
         5FtG+vDf2gv4GWSaAPeBKPUlfmX3NAHlrhRl5z23Vi+VWiMWJE0UKKKF+kFF4dH/YHm9
         GvPXbP+p6PzJKPYcXl1QEF0WCiuaPAvEGe6Z+iO/EsTVxSW7gGOL3nB+xZUKGkf+fK/6
         c03sVpx6Z9YbEU8XNRmjrgq3Bc5HcuaeAuBQB8CVqI/VyQ3XJLyzlAznRbvTNKjbKmGx
         wQnkejZpsYI2abdDZqKDIJBk7oGYKWTtXv9JlVlZvwcnQ+RrxoSsAdUVkf3/YIS5S/hl
         zSEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bi7-20020a170902bf0700b001a1e6e40fe8si758999plb.3.2023.03.29.23.51.26
        for <kasan-dev@googlegroups.com>;
        Wed, 29 Mar 2023 23:51:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [192.168.200.1])
	by gateway (Coremail) with SMTP id _____8AxlF1OMSVk_kMUAA--.31013S3;
	Thu, 30 Mar 2023 14:50:54 +0800 (CST)
Received: from [0.0.0.0] (unknown [192.168.200.1])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Cx_75LMSVklQcRAA--.48492S3;
	Thu, 30 Mar 2023 14:50:53 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet
 <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
From: Youling Tang <tangyouling@loongson.cn>
Message-ID: <4ad7dfe6-160a-d4a8-e262-1fb13a395510@loongson.cn>
Date: Thu, 30 Mar 2023 14:50:51 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:45.0) Gecko/20100101
 Thunderbird/45.4.0
MIME-Version: 1.0
In-Reply-To: <20230328111714.2056-1-zhangqing@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: AQAAf8Cx_75LMSVklQcRAA--.48492S3
X-CM-SenderInfo: 5wdqw5prxox03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBjvAXoWfJF1xuFWfKF4ftryrKrWUtwb_yoW8Jr47Xo
	WFkF43Kw4rGw47CrZ8Xw4DJ34Utr109r4kA3y7Zr1fuF1xAFWak3yUtw4Sgry3t34kKr13
	W3y2gFZ3J3sYyrn8n29KB7ZKAUJUUUUr529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUkq1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l8cAvFVAK0II2c7xJM28CjxkF64
	kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8IcVCY
	1x0267AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6x
	kF7I0E14v26r4UJVWxJr1ln4kS14v26r1Y6r17M2AIxVAIcxkEcVAq07x20xvEncxIr21l
	57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6x8ErcxFaV
	Av8VWrMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1cAE67vI
	Y487MxAIw28IcxkI7VAKI48JMxAIw28IcVCjz48v1sIEY20_WwCFx2IqxVCFs4IE7xkEbV
	WUJVW8JwCFI7km07C267AKxVWUXVWUAwC20s026c02F40E14v26r1j6r18MI8I3I0E7480
	Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64vIr41lIxAIcVC0I7
	IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF04k2
	6cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxV
	AFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7xRihFxUUUUUU==
X-Original-Sender: tangyouling@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=tangyouling@loongson.cn
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

Hi, Qing

On 03/28/2023 07:17 PM, Qing Zhang wrote:
> 1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
> There are a lot of holes between different segments and valid address
> space(256T available) is insufficient to map all these segments to kasan
> shadow memory with the common formula provided by kasan core, saying
> addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
>
> So Loongarch has a ARCH specific mapping formula,different segments
> are mapped individually, and only limited length of space of that
> specific segment is mapped to shadow.
>
> At early boot stage the whole shadow region populated with just
> one physical page (kasan_early_shadow_page). Later, this page is
> reused as readonly zero shadow for some memory that Kasan currently
> don't track.
> After mapping the physical memory, pages for shadow memory are
> allocated and mapped.
>
> Functions like memset/memmove/memcpy do a lot of memory accesses.
> If bad pointer passed to one of these function it is important
> to catch this. Compiler's instrumentation cannot do this since
> these functions are written in assembly.
> KASan replaces memory functions with manually instrumented variants.
> Original functions declared as weak symbols so strong definitions
> in mm/kasan/kasan.c could replace them. Original functions have aliases
> with '__' prefix in name, so we could call non-instrumented variant
> if needed.
>
> Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
> ---
>  Documentation/dev-tools/kasan.rst             |   4 +-
>  .../features/debug/KASAN/arch-support.txt     |   2 +-
>  arch/loongarch/Kconfig                        |   7 +
>  arch/loongarch/include/asm/kasan.h            | 120 +++++++++
>  arch/loongarch/include/asm/pgtable.h          |   7 +
>  arch/loongarch/include/asm/setup.h            |   2 +-
>  arch/loongarch/include/asm/string.h           |  20 ++
>  arch/loongarch/kernel/Makefile                |   3 +
>  arch/loongarch/kernel/head.S                  |  14 +-
>  arch/loongarch/kernel/relocate.c              |   8 +-
>  arch/loongarch/kernel/setup.c                 |   4 +
>  arch/loongarch/lib/memcpy.S                   |   4 +-
>  arch/loongarch/lib/memmove.S                  |  13 +-
>  arch/loongarch/lib/memset.S                   |   4 +-
>  arch/loongarch/mm/Makefile                    |   2 +
>  arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
>  arch/loongarch/vdso/Makefile                  |   4 +
>  include/linux/kasan.h                         |   2 +
>  mm/kasan/generic.c                            |   5 +
>  mm/kasan/init.c                               |  10 +-
>  mm/kasan/kasan.h                              |   6 +
>  21 files changed, 470 insertions(+), 26 deletions(-)
>  create mode 100644 arch/loongarch/include/asm/kasan.h
>  create mode 100644 arch/loongarch/mm/kasan_init.c
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index e66916a483cd..ee91f2872767 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -41,8 +41,8 @@ Support
>  Architectures
>  ~~~~~~~~~~~~~
>
> -Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, and
> -xtensa, and the tag-based KASAN modes are supported only on arm64.
> +Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, xtensa,
> +and loongarch, and the tag-based KASAN modes are supported only on arm64.
>
>  Compilers
>  ~~~~~~~~~
> diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Documentation/features/debug/KASAN/arch-support.txt
> index bf0124fae643..c4581c2edb28 100644
> --- a/Documentation/features/debug/KASAN/arch-support.txt
> +++ b/Documentation/features/debug/KASAN/arch-support.txt
> @@ -13,7 +13,7 @@
>      |        csky: | TODO |
>      |     hexagon: | TODO |
>      |        ia64: | TODO |
> -    |   loongarch: | TODO |
> +    |   loongarch: |  ok  |
>      |        m68k: | TODO |
>      |  microblaze: | TODO |
>      |        mips: | TODO |
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index 72dd00f48b8c..61f883c51045 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -7,6 +7,7 @@ config LOONGARCH
>  	select ACPI_MCFG if ACPI
>  	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
>  	select ARCH_BINFMT_ELF_STATE
> +	select ARCH_DISABLE_KASAN_INLINE
>  	select ARCH_ENABLE_MEMORY_HOTPLUG
>  	select ARCH_ENABLE_MEMORY_HOTREMOVE
>  	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
> @@ -83,6 +84,7 @@ config LOONGARCH
>  	select HAVE_ARCH_AUDITSYSCALL
>  	select HAVE_ARCH_MMAP_RND_BITS if MMU
>  	select HAVE_ARCH_SECCOMP_FILTER
> +	select HAVE_ARCH_KASAN if 64BIT
>  	select HAVE_ARCH_TRACEHOOK
>  	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
>  	select HAVE_ASM_MODVERSIONS
> @@ -626,6 +628,11 @@ config ARCH_MMAP_RND_BITS_MIN
>  config ARCH_MMAP_RND_BITS_MAX
>  	default 18
>
> +config KASAN_SHADOW_OFFSET
> +	hex
> +	default 0x0
> +	depends on KASAN
> +
>  menu "Power management options"
>
>  config ARCH_SUSPEND_POSSIBLE
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
> new file mode 100644
> index 000000000000..582bcded311e
> --- /dev/null
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -0,0 +1,120 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_H
> +#define __ASM_KASAN_H
> +
> +#ifndef __ASSEMBLY__
> +
> +#include <linux/linkage.h>
> +#include <linux/mmzone.h>
> +#include <asm/addrspace.h>
> +#include <asm/io.h>
> +#include <asm/pgtable.h>
> +
> +#define __HAVE_ARCH_SHADOW_MAP
> +
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +#define XRANGE_SHIFT (48)
> +
> +/* Valid address length */
> +#define XRANGE_SHADOW_SHIFT	(PGDIR_SHIFT + PAGE_SHIFT - 3)
> +/* Used for taking out the valid address */
> +#define XRANGE_SHADOW_MASK	GENMASK_ULL(XRANGE_SHADOW_SHIFT - 1, 0)
> +/* One segment whole address space size */
> +#define	XRANGE_SIZE		(XRANGE_SHADOW_MASK + 1)
> +
> +/* 64-bit segment value. */
> +#define XKPRANGE_UC_SEG		(0x8000)
> +#define XKPRANGE_CC_SEG		(0x9000)
> +#define XKVRANGE_VC_SEG		(0xffff)
> +
> +/* Cached */
> +#define XKPRANGE_CC_START		CACHE_BASE
> +#define XKPRANGE_CC_SIZE		XRANGE_SIZE
> +#define XKPRANGE_CC_KASAN_OFFSET	(0)
> +#define XKPRANGE_CC_SHADOW_SIZE		(XKPRANGE_CC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
> +#define XKPRANGE_CC_SHADOW_END		(XKPRANGE_CC_KASAN_OFFSET + XKPRANGE_CC_SHADOW_SIZE)
> +
> +/* UnCached */
> +#define XKPRANGE_UC_START		UNCACHE_BASE
> +#define XKPRANGE_UC_SIZE		XRANGE_SIZE
> +#define XKPRANGE_UC_KASAN_OFFSET	XKPRANGE_CC_SHADOW_END
> +#define XKPRANGE_UC_SHADOW_SIZE		(XKPRANGE_UC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
> +#define XKPRANGE_UC_SHADOW_END		(XKPRANGE_UC_KASAN_OFFSET + XKPRANGE_UC_SHADOW_SIZE)
> +
> +/* VMALLOC (Cached or UnCached)  */
> +#define XKVRANGE_VC_START		MODULES_VADDR
> +#define XKVRANGE_VC_SIZE		round_up(VMEMMAP_END - MODULES_VADDR + 1, PGDIR_SIZE)
> +#define XKVRANGE_VC_KASAN_OFFSET	XKPRANGE_UC_SHADOW_END
> +#define XKVRANGE_VC_SHADOW_SIZE		(XKVRANGE_VC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
> +#define XKVRANGE_VC_SHADOW_END		(XKVRANGE_VC_KASAN_OFFSET + XKVRANGE_VC_SHADOW_SIZE)
> +
> +/* Kasan shadow memory start right after vmalloc. */
> +#define KASAN_SHADOW_START		round_up(VMEMMAP_END, PGDIR_SIZE)
> +#define KASAN_SHADOW_SIZE		(XKVRANGE_VC_SHADOW_END - XKPRANGE_CC_KASAN_OFFSET)
> +#define KASAN_SHADOW_END		round_up(KASAN_SHADOW_START + KASAN_SHADOW_SIZE, PGDIR_SIZE)
> +
> +#define XKPRANGE_CC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_CC_KASAN_OFFSET)
> +#define XKPRANGE_UC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_UC_KASAN_OFFSET)
> +#define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
> +
> +extern bool kasan_early_stage;
> +extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> +
> +static inline void *kasan_mem_to_shadow(const void *addr)
> +{
> +	if (kasan_early_stage) {
> +		return (void *)(kasan_early_shadow_page);
> +	} else {
> +		unsigned long maddr = (unsigned long)addr;
> +		unsigned long xrange = (maddr >> XRANGE_SHIFT) & 0xffff;
> +		unsigned long offset = 0;
> +
> +		maddr &= XRANGE_SHADOW_MASK;
> +		switch (xrange) {
> +		case XKPRANGE_CC_SEG:
> +			offset = XKPRANGE_CC_SHADOW_OFFSET;
> +			break;
> +		case XKPRANGE_UC_SEG:
> +			offset = XKPRANGE_UC_SHADOW_OFFSET;
> +			break;
> +		case XKVRANGE_VC_SEG:
> +			offset = XKVRANGE_VC_SHADOW_OFFSET;
> +			break;
> +		default:
> +			WARN_ON(1);
> +			return NULL;
> +		}
> +
> +		return (void *)((maddr >> KASAN_SHADOW_SCALE_SHIFT) + offset);
> +	}
> +}
> +
> +static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> +{
> +	unsigned long addr = (unsigned long)shadow_addr;
> +
> +	if (unlikely(addr > KASAN_SHADOW_END) ||
> +		unlikely(addr < KASAN_SHADOW_START)) {
> +		WARN_ON(1);
> +		return NULL;
> +	}
> +
> +	if (addr >= XKVRANGE_VC_SHADOW_OFFSET)
> +		return (void *)(((addr - XKVRANGE_VC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKVRANGE_VC_START);
> +	else if (addr >= XKPRANGE_UC_SHADOW_OFFSET)
> +		return (void *)(((addr - XKPRANGE_UC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_UC_START);
> +	else if (addr >= XKPRANGE_CC_SHADOW_OFFSET)
> +		return (void *)(((addr - XKPRANGE_CC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_CC_START);
> +	else {
> +		WARN_ON(1);
> +		return NULL;
> +	}
> +}
> +
> +void kasan_init(void);
> +asmlinkage void kasan_early_init(void);
> +
> +#endif
> +#endif
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
> index d28fb9dbec59..5cfdf79b287e 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -86,9 +86,16 @@ extern unsigned long zero_page_mask;
>  #define MODULES_END	(MODULES_VADDR + SZ_256M)
>
>  #define VMALLOC_START	MODULES_END
> +
> +#ifndef CONFIG_KASAN
>  #define VMALLOC_END	\
>  	(vm_map_base +	\
>  	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
> +#else
> +#define VMALLOC_END	\
> +	(vm_map_base +	\
> +	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
> +#endif
>
>  #define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
>  #define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
> diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/asm/setup.h
> index be05c0e706a2..2dca0d1dd90a 100644
> --- a/arch/loongarch/include/asm/setup.h
> +++ b/arch/loongarch/include/asm/setup.h
> @@ -33,7 +33,7 @@ extern long __la_abs_end;
>  extern long __rela_dyn_begin;
>  extern long __rela_dyn_end;
>
> -extern void * __init relocate_kernel(void);
> +extern unsigned long __init relocate_kernel(void);
>
>  #endif
>
> diff --git a/arch/loongarch/include/asm/string.h b/arch/loongarch/include/asm/string.h
> index 7b29cc9c70aa..5bb5a90d2681 100644
> --- a/arch/loongarch/include/asm/string.h
> +++ b/arch/loongarch/include/asm/string.h
> @@ -7,11 +7,31 @@
>
>  #define __HAVE_ARCH_MEMSET
>  extern void *memset(void *__s, int __c, size_t __count);
> +extern void *__memset(void *__s, int __c, size_t __count);
>
>  #define __HAVE_ARCH_MEMCPY
>  extern void *memcpy(void *__to, __const__ void *__from, size_t __n);
> +extern void *__memcpy(void *__to, __const__ void *__from, size_t __n);
>
>  #define __HAVE_ARCH_MEMMOVE
>  extern void *memmove(void *__dest, __const__ void *__src, size_t __n);
> +extern void *__memmove(void *__dest, __const__ void *__src, size_t __n);
> +
> +#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> +
> +/*
> + * For files that are not instrumented (e.g. mm/slub.c) we
> + * should use not instrumented version of mem* functions.
> + */
> +
> +#define memset(s, c, n) __memset(s, c, n)
> +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> +#define memmove(dst, src, len) __memmove(dst, src, len)
> +
> +#ifndef __NO_FORTIFY
> +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */

If we need to add __NO_FORTIFY processing, please add
ARCH_HAS_FORTIFY_SOURCE in Kconfig, and submit a separate patch like
9530141455c9 ("riscv: Add ARCH_HAS_FORTIFY_SOURCE").

Youling.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ad7dfe6-160a-d4a8-e262-1fb13a395510%40loongson.cn.
