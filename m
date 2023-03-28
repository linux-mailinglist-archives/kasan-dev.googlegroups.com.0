Return-Path: <kasan-dev+bncBAABB2FMROQQMGQEEOSFQQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 66F9E6CBE42
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 13:58:34 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id pm10-20020a17090b3c4a00b0023ff02aced2sf744020pjb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 04:58:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680004713; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gu3eVEeiljl1gxPCCOJvN45HmN6cZ65fJHYkidoJxxMM4QkR0xhaR9kPx1cuqW3nIy
         Nvrxzco0TQBKClrnBVINc1Ekixh8L5X+onHks2Yf9TZwTND8R38XvrpHsdPE3OZi1vVn
         vQKl9KKNW3E/4GwpHXKY/v+F20c7raxJOg2ICEnBfdxKu1ye7y3PNiOQWUv0Mglq2BP7
         wu0kzw3rWUaNVEAIVYb2PTLmht4rNz3cylv7vg4QHq85zKjsresnucybIanp1FBHbMJU
         uew5rtbhL4489xlJXVH9ywGiTNgsRQejwtrx87akHnBZXsl+Nu+OQqwVHN7xIpn4bG1X
         0HKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=bdC1A+cKFH2ACvrerQy/kGgR2qtund1T85AGxeld6u8=;
        b=LSOEbkC6gbnoHEBKUI8SDf0kfHrn0LGzP0kOfH9g6AoyM+ylLslbZOM4KTGldz4QOo
         wYyN/xS3dVjFvxbAtdevL5bCYSaCatXQvB0i//SBA7iuGXIOxVvE4D2tZsF6sENpRT3r
         iJD8hvi1xTz+Gh97h4nn18S94I4DUT9/6k2iGggQ4o6kmmZ5sBWOUU8CXFAcSZU3QCVI
         HsCt/od3wqHnQYbtsKbYXRTSnGs/Rh6kwHvsD82h/h0LTI1Ppqg83ULX3rtPjgayh+/V
         /kO0huOiZUlORwsRTJCeLIwYGK/WHc+zb1A8J0ehOCyqP5Kb++o2OzL9m2VTsmLx8snC
         iSpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680004713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bdC1A+cKFH2ACvrerQy/kGgR2qtund1T85AGxeld6u8=;
        b=PNrgcumXW/52vX0GyiAyiIvxBJNYpV5DUuLKrk8UzjB+7cV/rQBG1VYTJdhYlGlmdM
         eaGUOdYM8cwLoN/jP3UgP4VogN5StG6IL6vJi2EN4/4jKAojA750LoeGguA/MUl5GTkn
         QyK2FllCb2tzOim5104Ka5DNDTL7KHrumEDt2avORj43vbc/X6a0eMKnmRAaVDkJCTg/
         PSeDGQcXWcJfwa5hoXjVxAsHjs0l0MlzEDcmVxd+A7WE6XlX736bI2IjLsrekWU5vKC5
         IbnL4VV7GD+3r/6pO+pgKmaOlP3QqgVhDQG6wMlrte5kLsZo1w3adJMXoF3GdE6Sn6CK
         BM2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680004713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :mime-version:user-agent:date:message-id:from:cc:references:to
         :subject:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bdC1A+cKFH2ACvrerQy/kGgR2qtund1T85AGxeld6u8=;
        b=PCW88Ig287tzF1Z3KF+73ZYGLGk4jaoEx/tI9HxIh1fttchBrdtodU6ht53bvhE7p8
         cnEO/C0/aW+efuqQ/BMulg89xzfVhA4toIt/gDzSvVGg2r2q8sWjLVgAzlJv59q8XxGT
         AYCQs6QEJlu++bhnl0NczFjidWGO4GPdIKfLAhyNQ4H6AL8Vmu3fVjlXLESPllcRI5Vt
         yDE1ESJKXgP84x9hy3a4jSh/Q0OYOCUTziKpO9WrumCtu6vO4ePVF3blOTDkt1LQxcep
         j1OdAlAjorkrSC6KE/sMrvQEYJnTJWTaQSVENgF798butpJCXfIPOVCfFDJiZ6zNZwmX
         x37Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9c/NKxNeeI3ejA7KSSO+4bpNhO1bH9pV4A8wyug3qGaAW1jB7AR
	VLNfCkvukaE/+Lgms9pWjtc=
X-Google-Smtp-Source: AKy350aCmkTO3k3Pifeipje4mMH8CLi3jNrPri/j7Of8sPzwQGeS5KefAds/fQmTZQJHPx4PjdYcrA==
X-Received: by 2002:a63:455:0:b0:50b:e523:3cd2 with SMTP id 82-20020a630455000000b0050be5233cd2mr4016710pge.11.1680004712862;
        Tue, 28 Mar 2023 04:58:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3e82:b0:234:2ef4:2e9 with SMTP id
 rj2-20020a17090b3e8200b002342ef402e9ls10250441pjb.0.-pod-control-gmail; Tue,
 28 Mar 2023 04:58:32 -0700 (PDT)
X-Received: by 2002:a05:6a20:1221:b0:da:acdf:d241 with SMTP id v33-20020a056a20122100b000daacdfd241mr11522345pzf.45.1680004712247;
        Tue, 28 Mar 2023 04:58:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680004712; cv=none;
        d=google.com; s=arc-20160816;
        b=CYv+BLvENkyrGeQGSHCLCzjIahiwUqPxGncVJzXs6ftb1NiVTbDLpfB16N8w6bDqkG
         4hzmcXBbi7iTOHLaHHp/X1poXQedTz43QB+jJDwdpBa8lNVe9K/rlOMFJY1zt94PCdzC
         7Q9so/RAMGGb38LdQ5MudriHvtBh5gR4eiwguWx42+XipbympTlkJdxHhu/OZeDtyHRN
         ZNBAqVB5N0kk5bwh7awZd/0fn9v2dau2zfkzAcdq7FUt6cZDr1CQEFiMyt2Klst3EweH
         USjiy3cgR6Tzx0Fme1bdtabnM4sW4MgEpnu+e8/Jh8TNoNfEaOmP4pgxH07cEyQBAp8Y
         jN1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=OyW89lDKt+5R+n3r6CjtJycYausiJchA4e8wbSxezJo=;
        b=PmguG+HHg/28wh6t3MLuBr5IXucbPTV7g8Y9rnwONgpQLgbc9VDtkEFE6o5cgcwCCE
         gmeZMFUHD6pcvRTOD6/epSR0mj49bUlA+9Qy8eSqkK/ixWBkNHYXSydzC6k2h+PFl6nA
         fVrT0K3nmsjye24CceAbh0bMOW5snwn0wvGBCDDdqFN8xw9+1IXFVrM+ymbYvN7ekXm1
         GBeBC/QDXmft4eDj5ItLMXVgU+MiOgN4pMZpU1EZ7sr/KlRb+JEDHQtp3WoHmkmL4qrR
         hpnuPoT9LJsahZAv2F6Njs62+r6xnajkOqWOBXEOHAHT9ABP85mmlYCYrSs12dYWed5L
         ECFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=tangyouling@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bh27-20020a056a00309b00b00625965308absi1581109pfb.3.2023.03.28.04.58.31
        for <kasan-dev@googlegroups.com>;
        Tue, 28 Mar 2023 04:58:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of tangyouling@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [192.168.200.1])
	by gateway (Coremail) with SMTP id _____8BxYU9H1iJkIBQTAA--.29267S3;
	Tue, 28 Mar 2023 19:57:59 +0800 (CST)
Received: from [0.0.0.0] (unknown [192.168.200.1])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Cxur1F1iJkSmAPAA--.10783S3;
	Tue, 28 Mar 2023 19:57:58 +0800 (CST)
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
Message-ID: <39af0c57-acff-d36c-a67d-e4a6783b57cd@loongson.cn>
Date: Tue, 28 Mar 2023 19:57:57 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:45.0) Gecko/20100101
 Thunderbird/45.4.0
MIME-Version: 1.0
In-Reply-To: <20230328111714.2056-1-zhangqing@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: AQAAf8Cxur1F1iJkSmAPAA--.10783S3
X-CM-SenderInfo: 5wdqw5prxox03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBjvAXoWfJF1xuFWfKF4ftryrKrWUtwb_yoW8XFW5to
	WFkF17Kw48Gw47CrZ8Ww1DJFyUtr1qkrWkZ39rZr1fWF1xAFW3C3yUtayagry3t34kGr1f
	W3y2gFZay3sYyrn8n29KB7ZKAUJUUUUr529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUkS1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l8cAvFVAK0II2c7xJM28CjxkF64
	kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY
	1x0267AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6x
	kF7I0E14v26F4UJVW0owAaw2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAq
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
`Loongarch` -> `LoongArch`

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
It is not recommended to use a fixed value, it can be as follows,

CACHE_BASE >> DMW_PABITS
UNCACHE_BASE >> DMW_PABITS

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
> +#endif
> +
> +#endif
>
>  #endif /* _ASM_STRING_H */
> diff --git a/arch/loongarch/kernel/Makefile b/arch/loongarch/kernel/Makefile
> index 9a72d91cd104..0055e7582e15 100644
> --- a/arch/loongarch/kernel/Makefile
> +++ b/arch/loongarch/kernel/Makefile
> @@ -30,6 +30,9 @@ ifdef CONFIG_FUNCTION_TRACER
>    CFLAGS_REMOVE_perf_event.o = $(CC_FLAGS_FTRACE)
>  endif
>
> +KASAN_SANITIZE_vdso.o := n
> +KASAN_SANITIZE_efi.o := n
> +
>  obj-$(CONFIG_MODULES)		+= module.o module-sections.o
>  obj-$(CONFIG_STACKTRACE)	+= stacktrace.o
>
> diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
> index aa64b179744f..19d4be5c8381 100644
> --- a/arch/loongarch/kernel/head.S
> +++ b/arch/loongarch/kernel/head.S
> @@ -95,13 +95,17 @@ SYM_CODE_START(kernel_entry)			# kernel entry point
>  	PTR_LI		sp, (_THREAD_SIZE - PT_SIZE)
>  	PTR_ADD		sp, sp, tp
>  	set_saved_sp	sp, t0, t1
> -#endif
> -
> -	/* relocate_kernel() returns the new kernel entry point */
> -	jr		a0
> -	ASM_BUG()
>
> +	/* Jump to new kernel: new_pc = current_pc + random_offset */
> +	pcaddi		t0, 0
> +	add.d		t0, t0, a0
> +	jirl		zero, t0, 0xc
>  #endif
> +#endif
> +
> +	#ifdef CONFIG_KASAN
> +	bl              kasan_early_init
> +	#endif
No tab operation is required before `#ifdef`.

>
>  	bl		start_kernel
>  	ASM_BUG()
> diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/relocate.c
> index 01f94d1e3edf..6c3eff9af9fb 100644
> --- a/arch/loongarch/kernel/relocate.c
> +++ b/arch/loongarch/kernel/relocate.c
> @@ -157,12 +157,11 @@ static inline void __init update_reloc_offset(unsigned long *addr, long random_o
>  	*new_addr = (unsigned long)reloc_offset;
>  }
>
> -void * __init relocate_kernel(void)
> +unsigned long __init relocate_kernel(void)
>  {
>  	unsigned long kernel_length;
>  	unsigned long random_offset = 0;
>  	void *location_new = _text; /* Default to original kernel start */
> -	void *kernel_entry = start_kernel; /* Default to original kernel entry point */
>  	char *cmdline = early_ioremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot command line is passed in fw_arg1 */
>
>  	strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
>
>  		reloc_offset += random_offset;
>
> -		/* Return the new kernel's entry point */
> -		kernel_entry = RELOCATED_KASLR(start_kernel);
> -
>  		/* The current thread is now within the relocated kernel */
>  		__current_thread_info = RELOCATED_KASLR(__current_thread_info);
>
> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
>
>  	relocate_absolute(random_offset);
>
> -	return kernel_entry;
> +	return random_offset;
>  }
>
>  /*
> diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.c
> index 27f71f9531e1..18453f8cb9e8 100644
> --- a/arch/loongarch/kernel/setup.c
> +++ b/arch/loongarch/kernel/setup.c
> @@ -610,4 +610,8 @@ void __init setup_arch(char **cmdline_p)
>  #endif
>
>  	paging_init();
> +
> +#if defined(CONFIG_KASAN)
> +	kasan_init();
> +#endif
Can be added in arch/loongarch/include/asm/kasan.h,
#else
static inline void kasan_init(void) { }
#endif


Youling.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/39af0c57-acff-d36c-a67d-e4a6783b57cd%40loongson.cn.
