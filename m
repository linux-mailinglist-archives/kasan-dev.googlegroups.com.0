Return-Path: <kasan-dev+bncBAABBU5LTKQQMGQE7AWOFHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BBC756D197C
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Mar 2023 10:12:04 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id n9-20020a056e02100900b00325c9240af7sf13904602ilj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Mar 2023 01:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680250323; cv=pass;
        d=google.com; s=arc-20160816;
        b=PdaDl32ixEjd4ub2zlnzE9jKePEwEuivcE87S/qqGpJDmgKxfa2e3bB31ZqaqFv1Im
         7Vo90n/0XSUh55eqc4DzZ4XYcb+bPOcNIdmRG5tfCFJQ/GDKcu2y/8JU48VMVCCbQt5V
         HfcHt3eG7y0O49rAKFKl6onCqA6iAJbYJVv0L4Cei0zxV3SLJseKw3EoEoHIw9IKrsts
         Vtdq1aueBKrVxJtiA7l0MFCyFASzquL7aAMuiZvoDJuysjJxFCT1E4mdHA8dNIIiczbb
         k+0chYn78XTlP31CcC04ZMM5SZ0gjO2O06V+Sx/rX48EwHazc4+TxE+TZdFtHspM36mP
         n1jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=N7JV+gB3IM68eiroGk8QvmduQvatoKeq02Px34jOsBM=;
        b=vcHHD1Le423ILFfenmAJO0R1YPUVZy14xrhHgVQVm3K5IraARo9uFlyr+3qLcYofi+
         TrdrAJUv/fh9RQcZQLn1MvGQiaMPqoWss52xw/bcNiR32bhdS6K9GPy4Vcmy2AAzixml
         +ZrlD3GB7f0m1AgGomgEqqstqz05sax8ZbO8Nqz1kxe6d9p5WnD7wpuauWj5+fSwTKYU
         VJAZGISa+IcYAyt/L1crg6SAU93ebGqqactCg1npuUjj0R0O5YuI0NHw0fWRiM0V4vfv
         JavoczgtLhw+7Dh9t1fUqjn4jIr71jI80wVgApiOnRawyyhQVNdkN6mWBJs5OGSakUMA
         yUaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680250323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=N7JV+gB3IM68eiroGk8QvmduQvatoKeq02Px34jOsBM=;
        b=USt5vxgCz9mCzqiuR6WxDwa4Dm6/coYlX4uCfbNAHc373d/bqSx5o9VkCAgVEkx17z
         CAm1ob3hMVkIX2jr2+7UUD9t7llETiwo1gC9u/5mVhIRUJB3zIw15aWZL2F2AMlDgWHd
         ZR+pHZ90KheBElV3YI7bfHZfZ1NGlOjeyhIobyXknnUr3N5REojNahl8rvssTN3J06uT
         pUtwHdEsY6ssFRfC69jITLQNJ/aEs8zm4pg94RR1uL2Z+ckSogH/HstQmBcJH1i+QPWh
         SstcaczhpAyTHJIqdCvk+K5BJU2aCXq8U91XA1VUTKoana4e29HNm5vvAH4FGtofVoQk
         LnVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680250323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :mime-version:user-agent:date:message-id:from:cc:references:to
         :subject:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N7JV+gB3IM68eiroGk8QvmduQvatoKeq02Px34jOsBM=;
        b=zkgpPdNFCqrrYpL+zAH5maRaOjYwR9LTybOxYLiIw8RpR5iuVnHOFD/JtOObg0HL91
         8v2vkU3DHfqplvIcb8NG2fenYACPkQ/86On+fWRQn4bRNAw7kRJ1A6PBhfFejxHCNqfJ
         axve4TKnV4IoK/cnobZHfbmMjbSjHQrYuMOiNuGQuyseJxluhsL9rSysBAzYlX7UVVIS
         kO7/S+Cw6Ql77W6mfBtJeS6UcMMrap4tQi5EpMuwknblBt1eAF72hQxqWNoLotplDplg
         LYQ4rJy3IAnKTGfFznSDqft7qMQHtwR2U16TO4i8jVQ0W+/PNeWDtT/YmKlUXQMeavUm
         lq2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cwa987I8KmwrEL0KDB8eeVC8g3fLJJR9L+Tbqz54P+2nd0Fe8O
	6m0MKGNveLmPBzzfvBSA3Kk7Ew==
X-Google-Smtp-Source: AKy350bbuuvDp5WFN3DWtA6orsdBgFnIPkfyDacSH/mpZ7bOziWMFHYrL4E3FYZYzaYk1CzXi53s5g==
X-Received: by 2002:a05:6e02:219c:b0:326:4201:2d8c with SMTP id j28-20020a056e02219c00b0032642012d8cmr2050582ila.1.1680250323099;
        Fri, 31 Mar 2023 01:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2bed:b0:745:5be5:240d with SMTP id
 d13-20020a0566022bed00b007455be5240dls829931ioy.2.-pod-prod-gmail; Fri, 31
 Mar 2023 01:12:02 -0700 (PDT)
X-Received: by 2002:a5d:9e1a:0:b0:74c:91c2:cb05 with SMTP id h26-20020a5d9e1a000000b0074c91c2cb05mr19328384ioh.9.1680250322642;
        Fri, 31 Mar 2023 01:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680250322; cv=none;
        d=google.com; s=arc-20160816;
        b=MtRKVA4uTQzw83ImVWquBMbLLRXFmfUuCI+jXF7x/Yf1XVwn7M0h5lVJqE/a1aFMwe
         J4Gf8b9blyrVQJgjVVSA548OywDChAYQDs8Jysa2L1s5MWFQ0sa0Dluc+P+P052bwOa4
         pjI+iIWNI/xXCfshAqmqJz/EgrsofhDnKXOKsLU/vEsidKgnUNeyLfBuiKfH/yaCF/eh
         aLc2CPAwmEM4hnwuPUu1LnD3A2FcM4cFGRsDdNRI8xxkHMFnv6ZEqwWF0hhYfu8JB2L8
         WNOktZqquz6clgGVHVRmiuY5WsGSZNgIrKo6jQnMjOBoKQhsoHqd64QCMdj/O2mpbRc4
         T3ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=yKzTwf7vlaoVbUNaFKvoV1i0YPponyKIUFmQvfk8kqo=;
        b=gSPAnMyybKOrdEe4+aDChte0EE+LGMgGCyi0Ztx2KwrB24WvzignlbqBwUHjFhkOAr
         W0/xYlPsZ1xJrltf6H0m1wZVAkI9s7L8BVIPQMjMvDA5Lsnd1FxSPPHfxoGmYo9Y8oR2
         OnSoJyjS5nyJLpSLrSIjNE0daxA3hx2JMlntS8S6ZDUxnllzCTPdkRptLJjzr5LnsNGJ
         jTJLfFg9CSKkvdChCEexUuLsWm25iilL3lVSM8MWkHrA03gRMrfCxGxBATqAscjkDnLd
         l49vhkb5f8TvxTyqNLwgprdUE4FhX20LUmU19kqnbNO6wJhcze1pJf3Nn1+j2EnYyvEp
         8bsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bb15-20020a056602380f00b00758d3de6d0esi67654iob.1.2023.03.31.01.12.01
        for <kasan-dev@googlegroups.com>;
        Fri, 31 Mar 2023 01:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [192.168.200.1])
	by gateway (Coremail) with SMTP id _____8BxEJVJlSZktOAUAA--.32272S3;
	Fri, 31 Mar 2023 16:09:45 +0800 (CST)
Received: from [0.0.0.0] (unknown [192.168.200.1])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxtrzZlCZkDuoRAA--.12556S3;
	Fri, 31 Mar 2023 16:08:09 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>,
 Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
From: Youling Tang <tangyouling@loongson.cn>
Message-ID: <8b472ba9-a39d-b9cc-d515-c1a9d42ae865@loongson.cn>
Date: Fri, 31 Mar 2023 16:07:53 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:45.0) Gecko/20100101
 Thunderbird/45.4.0
MIME-Version: 1.0
In-Reply-To: <20230328111714.2056-1-zhangqing@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: AQAAf8CxtrzZlCZkDuoRAA--.12556S3
X-CM-SenderInfo: 5wdqw5prxox03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBjvJXoW3GF43try5WF4rZF13AryrJFb_yoWDGF47pr
	WkCFyvgrWktF1Ig3yrKr1UJr1DJrs3Ga12gF13JFWfCF4xu3s2gr1DKFWkta4UXw4kJFyF
	gFn5uayjq39rt37anT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bc8Fc2x0x2IEx4CE42xK8VAvwI8IcIk0rVWrJVCq3wA2ocxC64kIII0Yj41l84x0c7CEw4
	AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r4j6ryUM28EF7xvwVC0I7IYx2IY6xkF
	7I0E14v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7
	CjxVAFwI0_Gr1j6F4UJwAaw2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAq
	jxCEc2xF0cIa020Ex4CE44I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E74AGY7Cv6c
	x26rWlOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4CEbIxv
	r21l42xK82IYc2Ij64vIr41l42xK82IY6x8ErcxFaVAv8VWrMxC20s026xCaFVCjc4AY6r
	1j6r4UMxCIbckI1I0E14v26r1Y6r17MI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xv
	wVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwIxGrwCI42IY6xIIjx
	v20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAIw20E
	Y4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267
	AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvj4RKtC7UUUUU
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

Maybe you need to update `Documentation/translations/zh_CN/dev-tools
/kasan.rst` synchronously.

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

When the "earlycon=uart,mmio,0x1fe001e0,115200n8" cmdline parameter is
added under CONFIG_KASAN, the kernel will not start normally and stay
at the following position:
...
[    0.000000] On node 0, zone DMA32: 4 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 8 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 8 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 160 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 256 pages in unavailable ranges


The reason is that when accessing the serial port address `0x1fe001e0`,
kasan will add relevant checks, such as inserting `__asan_load1()`, and
will eventually enter the `default` branch in kasan_mem_to_shadow(),
causing the kernel to fail to start.

Add the following modification to avoid inserting the kasan check in
8250_early.o, and it will be able to start successfully.

diff --git a/drivers/tty/serial/8250/Makefile 
b/drivers/tty/serial/8250/Makefile
index 4fc2fc1f41b6..3c17d0e72c83 100644
--- a/drivers/tty/serial/8250/Makefile
+++ b/drivers/tty/serial/8250/Makefile
@@ -3,6 +3,8 @@
  # Makefile for the 8250 serial device drivers.
  #

+KASAN_SANITIZE_8250_early.o            := n
+
  obj-$(CONFIG_SERIAL_8250)              += 8250.o 8250_base.o
  8250-y                                 := 8250_core.o
  8250-$(CONFIG_ALPHA_GENERIC)           += 8250_alpha.o

Thanks,
Youling

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8b472ba9-a39d-b9cc-d515-c1a9d42ae865%40loongson.cn.
