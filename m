Return-Path: <kasan-dev+bncBAABBY4VVSSAMGQELTPSNWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2842C731958
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jun 2023 14:58:13 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-3f9ec5ab50dsf44020011cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jun 2023 05:58:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686833892; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMZdNqoTncGmYGORBvpmrJR3i5IUnujjt5e/6RUkPNQ9lG+7FiR8zxRPfvFKZEqOnX
         bBU/GuGpeFRWVfGDuBAlsiFWuAuxrw4BZtqYfwnQimF6Guzh8lwBahUayqWWZZwB6VTT
         3rTLSCM7JJE3YfzCkfVpMJpl+Yh/d9BrnsHe06LjF0O+9374Z32W8Etd5JL4nRTzV83+
         jGq/jwjudjx4ZQ+9bUyg+BFGyrl05YDsWy8XJJLxp7NhkJpCXlRmt1BUWhwDVmu6tB1Y
         Vm8os/SufyLl03CbYOL98WZWRvcZNQEMpqAM0k7uG0g3v9IIDJTwEpHKs7sO6hwTA4A1
         KMQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=08++w1SHzYukOkpLSjGBRPl6Wuce1XkxQg82A3PlH1c=;
        b=OGCY8131B5/jJN0Cc+dQpwZWaZVF2umgAyLf9/m/qy20mGF85SvvICO4d1a/EJ+b+s
         g8GNuvr+GQol8SzYfEsCJOKZYcDNKFynk3Ax4rFgD3WYk7GeD/cwJ7viDJySRZFpeCiJ
         BpQjDL7LYfbh9tdK34p+zxD7zBJNL8ndz1pdDwj1dH4xRe8UP8/bZ9wD2LeaJRr5h3Vx
         J6Bc6jjHhjQy3uDZ0X/vCMYBxgePKHP0lXLH9vjieHom4lY+1o7boAKltZM00xexXnI0
         a1r0e1MD9mhKZ3bDopHV2biA7LvVNrwKOUDWKjsqOsHycRw6NKavISXsB2xy47wG6L4z
         dr3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n5uPgneP;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686833892; x=1689425892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=08++w1SHzYukOkpLSjGBRPl6Wuce1XkxQg82A3PlH1c=;
        b=hVIJqzUDC+cGOXzb7MvmTrKCcv/LLd7acC4EgEnoI3I21h1ptxtC0EpZ66VtdlTHLM
         F8JaeMvr01H6lYXuYVjnw2UZTBNA5d+WopEZ6UZ2Nl9tW5Ye54QJFW8mLaKhlWhB4K7y
         bV7veEfIxWC1BWLRhenb2jQG3v9aWwJIQzWjXdWUStclRnKssVCDqEStUZ0qCBnMiaqz
         dskgjIJTeEJkefIdaJQo7agvX5Sx3vhINspmZ6rL70Y++B8IYfyCvR5dQrqAjmRSzlMl
         VnsVY118B5whhQrVphli0ywnikGwp4KMf7+7u+ss3nJ0BYnYYiNaY7l93t21nCXqfdsS
         uxsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686833892; x=1689425892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=08++w1SHzYukOkpLSjGBRPl6Wuce1XkxQg82A3PlH1c=;
        b=VlMqkJ0i5CmKdPnBuDfgaP4XUKOWP5kY+Q4/qCRlyqRivC2DhFsgI9N7DlxVK233cJ
         UYJJK5S4EkhyuSqClNdZbxpTjIeh+V80Nf9bPO/7MMrMknT0gLtycEuliJVygERRXVqG
         u4L2+SGHIG4rGRsAZoP6qLoXUWMLGQPhzpYWx26Hst/rHa6wOtjoJ+Vw1TGqCg8gQO5F
         GuiEqgJquKEEoHcopEL8j/tGrMgxGJy6s+//UoTuay0wQSy23ri025gwbGnUD0NLXHAT
         K7OccWyayNYn0aq96pZc54oysxPziba6yTRR/UjtB0AvVjEXwa5yj4N5m37CrTmmWKDp
         PHnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwQoFhN+6PnDqNj/JoPrqvKriOivb/XW8XD9k5X5hE6LjKEbtpF
	YDGJWRYuAgwtUUjN11lpEkE=
X-Google-Smtp-Source: ACHHUZ4V4JATFtI5zwHBwoQ3LzU63AUTjb/aeEo1K1vgMJ8YZibwaolatXwEGyiUbyGW2UKCKYLBKA==
X-Received: by 2002:a05:622a:54d:b0:3fd:3a8d:90f3 with SMTP id m13-20020a05622a054d00b003fd3a8d90f3mr6635665qtx.20.1686833891749;
        Thu, 15 Jun 2023 05:58:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4904:0:b0:3f5:3b17:86be with SMTP id e4-20020ac84904000000b003f53b1786bels225478qtq.0.-pod-prod-09-us;
 Thu, 15 Jun 2023 05:58:11 -0700 (PDT)
X-Received: by 2002:a05:622a:155:b0:3f9:3103:cf29 with SMTP id v21-20020a05622a015500b003f93103cf29mr6237258qtw.61.1686833891231;
        Thu, 15 Jun 2023 05:58:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686833891; cv=none;
        d=google.com; s=arc-20160816;
        b=ple6X/Csgw7lVnkEhLvcv+oUKbXK06+UpdU62tNwx1hVlvAdBkj8RrudHEoHJjlf1C
         Q59Yw2H5e01EGn/WER9uhdD6eDuxdz1sJOTeRCU4lCzQ9y2ZcCgZz8kWbyvRP0Ci06G9
         stmJYD0+/xmHvp+qlNFZINWjQhIyTy1H1YAf5pi2dPkqotkGXMEUsl03OXRzx2KjrInp
         4omkyWuluo/psSdSOEUGQhatUDn513sm3jVnJgT+4+BiQf/+mlCxMy6t5KT/ZV2fCdnm
         oNfr3Na3srROZRX3A4igP5xHnjbYJYPUd4oslTQu8BG2qvBWuYC16cHt+kzIsE+uUGWo
         902A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1o418HYMatkuPDe8yyj1LT1+HpTWPlsFFOLbT20Rhss=;
        b=twx7T/TMxo1hMM5ZJJ9SauP4rs61Ivv/PriZ3lUiLOFCYKRsHCPOQsNpH6RV7Xw12u
         W4jmaRLcgnX+OqA7g2/goRVDgFXXCDcZtByYiyClcDlMFfSpXTCU06dy9uD4JAeBL5QV
         XAHgkxRzfirm48bGyMFl8Ihe3vrffrPRbt3janiAIc/8wpL6bDGcVdTgACZGKt80FA2e
         Wv2dHgJeZD4JXXtWR97QIPie3WfA8GKi4eUG7JygphnfDX9+IFG1x1lJndbF/cqjH/XW
         fHDeql4VKGr++kA/Q3lbbA3cUGOvhnRuGYTm3Y68QqgAS2LOFgxxE9Yqw4l+7+dhK/nO
         J0qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n5uPgneP;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bs17-20020ac86f11000000b003ef46e5143dsi1368896qtb.3.2023.06.15.05.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jun 2023 05:58:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C165463111
	for <kasan-dev@googlegroups.com>; Thu, 15 Jun 2023 12:58:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0FC1FC433CA
	for <kasan-dev@googlegroups.com>; Thu, 15 Jun 2023 12:58:10 +0000 (UTC)
Received: by mail-ed1-f54.google.com with SMTP id 4fb4d7f45d1cf-5147e40bbbbso11624237a12.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Jun 2023 05:58:09 -0700 (PDT)
X-Received: by 2002:a05:6402:8:b0:518:79c4:f599 with SMTP id
 d8-20020a056402000800b0051879c4f599mr5159526edu.28.1686833888043; Thu, 15 Jun
 2023 05:58:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230512015839.23862-1-zhangqing@loongson.cn>
In-Reply-To: <20230512015839.23862-1-zhangqing@loongson.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Thu, 15 Jun 2023 20:57:56 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7bVZ5Svg4Y0TUGXy-0fksR4p9ota_HfnW4cCY+Ow4t5Q@mail.gmail.com>
Message-ID: <CAAhV-H7bVZ5Svg4Y0TUGXy-0fksR4p9ota_HfnW4cCY+Ow4t5Q@mail.gmail.com>
Subject: Re: [PATCH v3 4/4] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>, 
	Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n5uPgneP;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Qing,

On Fri, May 12, 2023 at 9:58=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> 1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
> There are a lot of holes between different segments and valid address
> space (256T available) is insufficient to map all these segments to kasan
> shadow memory with the common formula provided by kasan core, saying
> (addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
>
> So LoongArch has a arch-specific mapping formula, different segments are
> mapped individually, and only limited space lengths of these specific
> segments are mapped to shadow.
>
> At early boot stage the whole shadow region populated with just one
> physical page (kasan_early_shadow_page). Later, this page is reused as
> readonly zero shadow for some memory that kasan currently don't track.
> After mapping the physical memory, pages for shadow memory are allocated
> and mapped.
>
> Functions like memset()/memcpy()/memmove() do a lot of memory accesses.
> If bad pointer passed to one of these function it is important to be
> caught. Compiler's instrumentation cannot do this since these functions
> are written in assembly.
>
> KASan replaces memory functions with manually instrumented variants.
> Original functions declared as weak symbols so strong definitions in
> mm/kasan/kasan.c could replace them. Original functions have aliases
> with '__' prefix in names, so we could call non-instrumented variant
> if needed.
>
> Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
> ---
>  Documentation/dev-tools/kasan.rst             |   4 +-
>  .../features/debug/KASAN/arch-support.txt     |   2 +-
>  .../translations/zh_CN/dev-tools/kasan.rst    |   2 +-
>  arch/loongarch/Kconfig                        |   7 +
>  arch/loongarch/include/asm/kasan.h            | 120 +++++++++
>  arch/loongarch/include/asm/pgtable.h          |   7 +
>  arch/loongarch/include/asm/string.h           |  20 ++
>  arch/loongarch/kernel/Makefile                |   6 +
>  arch/loongarch/kernel/head.S                  |   4 +
>  arch/loongarch/kernel/setup.c                 |   4 +
>  arch/loongarch/lib/memcpy.S                   |   4 +-
>  arch/loongarch/lib/memmove.S                  |  16 +-
>  arch/loongarch/lib/memset.S                   |   4 +-
>  arch/loongarch/mm/Makefile                    |   2 +
>  arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
>  arch/loongarch/vdso/Makefile                  |   4 +
>  16 files changed, 448 insertions(+), 13 deletions(-)
>  create mode 100644 arch/loongarch/include/asm/kasan.h
>  create mode 100644 arch/loongarch/mm/kasan_init.c
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index e66916a483cd..ee91f2872767 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -41,8 +41,8 @@ Support
>  Architectures
>  ~~~~~~~~~~~~~
>
> -Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, =
and
> -xtensa, and the tag-based KASAN modes are supported only on arm64.
> +Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, =
xtensa,
> +and loongarch, and the tag-based KASAN modes are supported only on arm64=
.
>
>  Compilers
>  ~~~~~~~~~
> diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Docume=
ntation/features/debug/KASAN/arch-support.txt
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
> diff --git a/Documentation/translations/zh_CN/dev-tools/kasan.rst b/Docum=
entation/translations/zh_CN/dev-tools/kasan.rst
> index 05ef904dbcfb..8fdb20c9665b 100644
> --- a/Documentation/translations/zh_CN/dev-tools/kasan.rst
> +++ b/Documentation/translations/zh_CN/dev-tools/kasan.rst
> @@ -42,7 +42,7 @@ KASAN=E6=9C=89=E4=B8=89=E7=A7=8D=E6=A8=A1=E5=BC=8F:
>  =E4=BD=93=E7=B3=BB=E6=9E=B6=E6=9E=84
>  ~~~~~~~~
>
> -=E5=9C=A8x86_64=E3=80=81arm=E3=80=81arm64=E3=80=81powerpc=E3=80=81riscv=
=E3=80=81s390=E5=92=8Cxtensa=E4=B8=8A=E6=94=AF=E6=8C=81=E9=80=9A=E7=94=A8KA=
SAN=EF=BC=8C
> +=E5=9C=A8x86_64=E3=80=81arm=E3=80=81arm64=E3=80=81powerpc=E3=80=81riscv=
=E3=80=81s390=E3=80=81xtensa=E5=92=8Cloongarch=E4=B8=8A=E6=94=AF=E6=8C=81=
=E9=80=9A=E7=94=A8KASAN=EF=BC=8C
>  =E8=80=8C=E5=9F=BA=E4=BA=8E=E6=A0=87=E7=AD=BE=E7=9A=84KASAN=E6=A8=A1=E5=
=BC=8F=E5=8F=AA=E5=9C=A8arm64=E4=B8=8A=E6=94=AF=E6=8C=81=E3=80=82
>
>  =E7=BC=96=E8=AF=91=E5=99=A8
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index ac3d3d9b5716..a9c879fd037e 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -7,6 +7,7 @@ config LOONGARCH
>         select ACPI_MCFG if ACPI
>         select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
>         select ARCH_BINFMT_ELF_STATE
> +       select ARCH_DISABLE_KASAN_INLINE
>         select ARCH_ENABLE_MEMORY_HOTPLUG
>         select ARCH_ENABLE_MEMORY_HOTREMOVE
>         select ARCH_HAS_ACPI_TABLE_UPGRADE      if ACPI
> @@ -82,6 +83,7 @@ config LOONGARCH
>         select GENERIC_TIME_VSYSCALL
>         select GPIOLIB
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN
>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ARCH_TRACEHOOK
> @@ -595,6 +597,11 @@ config ARCH_MMAP_RND_BITS_MIN
>  config ARCH_MMAP_RND_BITS_MAX
>         default 18
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       default 0x0
> +       depends on KASAN
> +
>  menu "Power management options"
>
>  config ARCH_SUSPEND_POSSIBLE
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/=
asm/kasan.h
> new file mode 100644
> index 000000000000..04fb6c210945
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
> +#define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +#define XRANGE_SHIFT (48)
> +
> +/* Valid address length */
> +#define XRANGE_SHADOW_SHIFT    (PGDIR_SHIFT + PAGE_SHIFT - 3)
> +/* Used for taking out the valid address */
> +#define XRANGE_SHADOW_MASK     GENMASK_ULL(XRANGE_SHADOW_SHIFT - 1, 0)
> +/* One segment whole address space size */
> +#define        XRANGE_SIZE             (XRANGE_SHADOW_MASK + 1)
Use space instead of tab here.

> +
> +/* 64-bit segment value. */
> +#define XKPRANGE_UC_SEG                (UNCACHE_BASE >> DMW_PABITS)
> +#define XKPRANGE_CC_SEG                (CACHE_BASE >> DMW_PABITS)
> +#define XKVRANGE_VC_SEG                (0xffff)
> +
> +/* Cached */
> +#define XKPRANGE_CC_START              CACHE_BASE
> +#define XKPRANGE_CC_SIZE               XRANGE_SIZE
> +#define XKPRANGE_CC_KASAN_OFFSET       (0)
> +#define XKPRANGE_CC_SHADOW_SIZE                (XKPRANGE_CC_SIZE >> KASA=
N_SHADOW_SCALE_SHIFT)
> +#define XKPRANGE_CC_SHADOW_END         (XKPRANGE_CC_KASAN_OFFSET + XKPRA=
NGE_CC_SHADOW_SIZE)
> +
> +/* UnCached */
> +#define XKPRANGE_UC_START              UNCACHE_BASE
> +#define XKPRANGE_UC_SIZE               XRANGE_SIZE
> +#define XKPRANGE_UC_KASAN_OFFSET       XKPRANGE_CC_SHADOW_END
> +#define XKPRANGE_UC_SHADOW_SIZE                (XKPRANGE_UC_SIZE >> KASA=
N_SHADOW_SCALE_SHIFT)
> +#define XKPRANGE_UC_SHADOW_END         (XKPRANGE_UC_KASAN_OFFSET + XKPRA=
NGE_UC_SHADOW_SIZE)
> +
> +/* VMALLOC (Cached or UnCached)  */
> +#define XKVRANGE_VC_START              MODULES_VADDR
> +#define XKVRANGE_VC_SIZE               round_up(VMEMMAP_END - MODULES_VA=
DDR + 1, PGDIR_SIZE)
> +#define XKVRANGE_VC_KASAN_OFFSET       XKPRANGE_UC_SHADOW_END
> +#define XKVRANGE_VC_SHADOW_SIZE                (XKVRANGE_VC_SIZE >> KASA=
N_SHADOW_SCALE_SHIFT)
> +#define XKVRANGE_VC_SHADOW_END         (XKVRANGE_VC_KASAN_OFFSET + XKVRA=
NGE_VC_SHADOW_SIZE)
> +
> +/* Kasan shadow memory start right after vmalloc. */
> +#define KASAN_SHADOW_START             round_up(VMEMMAP_END, PGDIR_SIZE)
> +#define KASAN_SHADOW_SIZE              (XKVRANGE_VC_SHADOW_END - XKPRANG=
E_CC_KASAN_OFFSET)
> +#define KASAN_SHADOW_END               round_up(KASAN_SHADOW_START + KAS=
AN_SHADOW_SIZE, PGDIR_SIZE)
> +
> +#define XKPRANGE_CC_SHADOW_OFFSET      (KASAN_SHADOW_START + XKPRANGE_CC=
_KASAN_OFFSET)
> +#define XKPRANGE_UC_SHADOW_OFFSET      (KASAN_SHADOW_START + XKPRANGE_UC=
_KASAN_OFFSET)
> +#define XKVRANGE_VC_SHADOW_OFFSET      (KASAN_SHADOW_START + XKVRANGE_VC=
_KASAN_OFFSET)
> +
> +extern bool kasan_early_stage;
> +extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> +
> +static inline void *kasan_mem_to_shadow(const void *addr)
> +{
> +       if (kasan_early_stage) {
> +               return (void *)(kasan_early_shadow_page);
> +       } else {
> +               unsigned long maddr =3D (unsigned long)addr;
> +               unsigned long xrange =3D (maddr >> XRANGE_SHIFT) & 0xffff=
;
> +               unsigned long offset =3D 0;
> +
> +               maddr &=3D XRANGE_SHADOW_MASK;
> +               switch (xrange) {
> +               case XKPRANGE_CC_SEG:
> +                       offset =3D XKPRANGE_CC_SHADOW_OFFSET;
> +                       break;
> +               case XKPRANGE_UC_SEG:
> +                       offset =3D XKPRANGE_UC_SHADOW_OFFSET;
> +                       break;
> +               case XKVRANGE_VC_SEG:
> +                       offset =3D XKVRANGE_VC_SHADOW_OFFSET;
> +                       break;
> +               default:
> +                       WARN_ON(1);
> +                       return NULL;
> +               }
> +
> +               return (void *)((maddr >> KASAN_SHADOW_SCALE_SHIFT) + off=
set);
> +       }
> +}
> +
> +static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> +{
> +       unsigned long addr =3D (unsigned long)shadow_addr;
> +
> +       if (unlikely(addr > KASAN_SHADOW_END) ||
> +               unlikely(addr < KASAN_SHADOW_START)) {
> +               WARN_ON(1);
> +               return NULL;
> +       }
> +
> +       if (addr >=3D XKVRANGE_VC_SHADOW_OFFSET)
> +               return (void *)(((addr - XKVRANGE_VC_SHADOW_OFFSET) << KA=
SAN_SHADOW_SCALE_SHIFT) + XKVRANGE_VC_START);
> +       else if (addr >=3D XKPRANGE_UC_SHADOW_OFFSET)
> +               return (void *)(((addr - XKPRANGE_UC_SHADOW_OFFSET) << KA=
SAN_SHADOW_SCALE_SHIFT) + XKPRANGE_UC_START);
> +       else if (addr >=3D XKPRANGE_CC_SHADOW_OFFSET)
> +               return (void *)(((addr - XKPRANGE_CC_SHADOW_OFFSET) << KA=
SAN_SHADOW_SCALE_SHIFT) + XKPRANGE_CC_START);
> +       else {
> +               WARN_ON(1);
> +               return NULL;
> +       }
> +}
> +
> +void kasan_init(void);
> +asmlinkage void kasan_early_init(void);
> +
> +#endif
> +#endif
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index d28fb9dbec59..5cfdf79b287e 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -86,9 +86,16 @@ extern unsigned long zero_page_mask;
>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>
>  #define VMALLOC_START  MODULES_END
> +
> +#ifndef CONFIG_KASAN
>  #define VMALLOC_END    \
>         (vm_map_base +  \
>          min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * =
PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
> +#else
> +#define VMALLOC_END    \
> +       (vm_map_base +  \
> +        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * =
PAGE_SIZE, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
> +#endif
>
>  #define vmemmap                ((struct page *)((VMALLOC_END + PMD_SIZE)=
 & PMD_MASK))
>  #define VMEMMAP_END    ((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
> diff --git a/arch/loongarch/include/asm/string.h b/arch/loongarch/include=
/asm/string.h
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
> diff --git a/arch/loongarch/kernel/Makefile b/arch/loongarch/kernel/Makef=
ile
> index 9a72d91cd104..b45c6932a6cf 100644
> --- a/arch/loongarch/kernel/Makefile
> +++ b/arch/loongarch/kernel/Makefile
> @@ -30,6 +30,12 @@ ifdef CONFIG_FUNCTION_TRACER
>    CFLAGS_REMOVE_perf_event.o =3D $(CC_FLAGS_FTRACE)
>  endif
>
> +KASAN_SANITIZE_efi.o :=3D n
> +KASAN_SANITIZE_vdso.o :=3D n
> +KASAN_SANITIZE_cpu-probe.o :=3D n
> +KASAN_SANITIZE_traps.o :=3D n
> +KASAN_SANITIZE_smp.o :=3D n
> +
>  obj-$(CONFIG_MODULES)          +=3D module.o module-sections.o
>  obj-$(CONFIG_STACKTRACE)       +=3D stacktrace.o
>
> diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
> index aace7a300cd3..0d8180153ec0 100644
> --- a/arch/loongarch/kernel/head.S
> +++ b/arch/loongarch/kernel/head.S
> @@ -104,6 +104,10 @@ SYM_CODE_START(kernel_entry)                       #=
 kernel entry point
>
>  #endif /* CONFIG_RELOCATABLE */
>
> +#ifdef CONFIG_KASAN
> +       bl              kasan_early_init
> +#endif
> +
>         bl              start_kernel
>         ASM_BUG()
>
> diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.=
c
> index 4444b13418f0..9e94bf60c900 100644
> --- a/arch/loongarch/kernel/setup.c
> +++ b/arch/loongarch/kernel/setup.c
> @@ -610,4 +610,8 @@ void __init setup_arch(char **cmdline_p)
>  #endif
>
>         paging_init();
> +
> +#ifdef CONFIG_KASAN
> +       kasan_init();
> +#endif
>  }
> diff --git a/arch/loongarch/lib/memcpy.S b/arch/loongarch/lib/memcpy.S
> index 39ce6621c704..b9eb89e90550 100644
> --- a/arch/loongarch/lib/memcpy.S
> +++ b/arch/loongarch/lib/memcpy.S
> @@ -10,16 +10,18 @@
>  #include <asm/export.h>
>  #include <asm/regdef.h>
>
> -SYM_FUNC_START(memcpy)
> +SYM_FUNC_START_WEAK(memcpy)
>         /*
>          * Some CPUs support hardware unaligned access
>          */
>         ALTERNATIVE     "b __memcpy_generic", \
>                         "b __memcpy_fast", CPU_FEATURE_UAL
>  SYM_FUNC_END(memcpy)
> +SYM_FUNC_ALIAS(__memcpy, memcpy)
>  _ASM_NOKPROBE(memcpy)
>
>  EXPORT_SYMBOL(memcpy)
> +EXPORT_SYMBOL(__memcpy)
>
>  /*
>   * void *__memcpy_generic(void *dst, const void *src, size_t n)
> diff --git a/arch/loongarch/lib/memmove.S b/arch/loongarch/lib/memmove.S
> index 45b725ba7867..df521f8b9c9a 100644
> --- a/arch/loongarch/lib/memmove.S
> +++ b/arch/loongarch/lib/memmove.S
> @@ -10,23 +10,25 @@
>  #include <asm/export.h>
>  #include <asm/regdef.h>
>
> -SYM_FUNC_START(memmove)
> -       blt     a0, a1, memcpy  /* dst < src, memcpy */
> -       blt     a1, a0, rmemcpy /* src < dst, rmemcpy */
> -       jr      ra              /* dst =3D=3D src, return */
> +SYM_FUNC_START_WEAK(memmove)
> +       blt     a0, a1, __memcpy        /* dst < src, memcpy */
> +       blt     a1, a0, __rmemcpy       /* src < dst, rmemcpy */
> +       jr      ra                      /* dst =3D=3D src, return */
>  SYM_FUNC_END(memmove)
> +SYM_FUNC_ALIAS(__memmove, memmove)
>  _ASM_NOKPROBE(memmove)
>
>  EXPORT_SYMBOL(memmove)
> +EXPORT_SYMBOL(__memmove)
>
> -SYM_FUNC_START(rmemcpy)
> +SYM_FUNC_START(__rmemcpy)
>         /*
>          * Some CPUs support hardware unaligned access
>          */
>         ALTERNATIVE     "b __rmemcpy_generic", \
>                         "b __rmemcpy_fast", CPU_FEATURE_UAL
> -SYM_FUNC_END(rmemcpy)
> -_ASM_NOKPROBE(rmemcpy)
> +SYM_FUNC_END(__rmemcpy)
> +_ASM_NOKPROBE(__rmemcpy)
>
>  /*
>   * void *__rmemcpy_generic(void *dst, const void *src, size_t n)
> diff --git a/arch/loongarch/lib/memset.S b/arch/loongarch/lib/memset.S
> index b39c6194e3ae..392901aba970 100644
> --- a/arch/loongarch/lib/memset.S
> +++ b/arch/loongarch/lib/memset.S
> @@ -16,16 +16,18 @@
>         bstrins.d \r0, \r0, 63, 32
>  .endm
>
> -SYM_FUNC_START(memset)
> +SYM_FUNC_START_WEAK(memset)
>         /*
>          * Some CPUs support hardware unaligned access
>          */
>         ALTERNATIVE     "b __memset_generic", \
>                         "b __memset_fast", CPU_FEATURE_UAL
>  SYM_FUNC_END(memset)
> +SYM_FUNC_ALIAS(__memset, memset)
>  _ASM_NOKPROBE(memset)
>
>  EXPORT_SYMBOL(memset)
> +EXPORT_SYMBOL(__memset)
>
>  /*
>   * void *__memset_generic(void *s, int c, size_t n)
> diff --git a/arch/loongarch/mm/Makefile b/arch/loongarch/mm/Makefile
> index 8ffc6383f836..6e50cf6cf733 100644
> --- a/arch/loongarch/mm/Makefile
> +++ b/arch/loongarch/mm/Makefile
> @@ -7,3 +7,5 @@ obj-y                           +=3D init.o cache.o tlb.o=
 tlbex.o extable.o \
>                                    fault.o ioremap.o maccess.o mmap.o pgt=
able.o page.o
>
>  obj-$(CONFIG_HUGETLB_PAGE)     +=3D hugetlbpage.o
> +obj-$(CONFIG_KASAN)            +=3D kasan_init.o
> +KASAN_SANITIZE_kasan_init.o     :=3D n
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_ini=
t.c
> new file mode 100644
> index 000000000000..fb3077f8d508
> --- /dev/null
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -0,0 +1,255 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +/*
> + * Copyright (C) 2023 Loongson Technology Corporation Limited
> + */
> +#define pr_fmt(fmt) "kasan: " fmt
> +#include <linux/kasan.h>
> +#include <linux/memblock.h>
> +#include <linux/sched/task.h>
> +
> +#include <asm/tlbflush.h>
> +#include <asm/pgalloc.h>
> +#include <asm-generic/sections.h>
> +
> +static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
> +
> +static inline int __p4d_none(int early, p4d_t p4d) {return 0; }
> +
> +#ifndef __PAGETABLE_PUD_FOLDED
> +#define __p4d_none(early, p4d) (early ? (p4d_val(p4d) =3D=3D 0) : \
> +(__pa(p4d_val(p4d)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pud)))
> +#endif
__p4d_none() is redefined in some cases here.

> +
> +#define __pud_none(early, pud) (early ? (pud_val(pud) =3D=3D 0) : \
> +(__pa(pud_val(pud)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pmd)))
> +
> +#define __pmd_none(early, pmd) (early ? (pmd_val(pmd) =3D=3D 0) : \
> +(__pa(pmd_val(pmd)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pte)))
> +
> +#define __pte_none(early, pte) (early ? pte_none(pte) : \
> +((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_shado=
w_page)))
> +
> +bool kasan_early_stage =3D true;
> +
> +/*
> + * Alloc memory for shadow memory page table.
> + */
> +static phys_addr_t __init kasan_alloc_zeroed_page(int node)
> +{
> +       void *p =3D memblock_alloc_try_nid(PAGE_SIZE, PAGE_SIZE,
> +                                       __pa(MAX_DMA_ADDRESS),
> +                                       MEMBLOCK_ALLOC_ACCESSIBLE, node);
> +       if (!p)
> +               panic("%s: Failed to allocate %lu bytes align=3D0x%lx nid=
=3D%d from=3D%llx\n",
> +                       __func__, PAGE_SIZE, PAGE_SIZE, node, __pa(MAX_DM=
A_ADDRESS));
> +       return __pa(p);
> +}
> +
> +static pte_t *kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node=
,
> +                                    bool early)
> +{
> +       if (__pmd_none(early, READ_ONCE(*pmdp))) {
> +               phys_addr_t pte_phys =3D early ?
> +                               __pa_symbol(kasan_early_shadow_pte)
> +                                       : kasan_alloc_zeroed_page(node);
> +               if (!early)
> +                       memcpy(__va(pte_phys), kasan_early_shadow_pte,
> +                               sizeof(kasan_early_shadow_pte));
> +               pmd_populate_kernel(NULL, pmdp, (pte_t *)__va(pte_phys));
> +       }
> +
> +       return pte_offset_kernel(pmdp, addr);
> +}
> +
> +static inline void kasan_set_pgd(pgd_t *pgdp, pgd_t pgdval)
> +{
> +       WRITE_ONCE(*pgdp, pgdval);
> +}
> +
> +static pmd_t *kasan_pmd_offset(pud_t *pudp, unsigned long addr, int node=
,
> +                                    bool early)
> +{
> +       if (__pud_none(early, READ_ONCE(*pudp))) {
> +               phys_addr_t pmd_phys =3D early ?
> +                               __pa_symbol(kasan_early_shadow_pmd)
> +                                       : kasan_alloc_zeroed_page(node);
> +               if (!early)
> +                       memcpy(__va(pmd_phys), kasan_early_shadow_pmd,
> +                               sizeof(kasan_early_shadow_pmd));
> +               pud_populate(&init_mm, pudp, (pmd_t *)__va(pmd_phys));
> +       }
> +
> +       return pmd_offset(pudp, addr);
> +}
> +
> +static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, i=
nt node,
> +                                           bool early)
> +{
> +       if (__p4d_none(early, READ_ONCE(*p4dp))) {
> +               phys_addr_t pud_phys =3D early ?
> +                       __pa_symbol(kasan_early_shadow_pud)
> +                               : kasan_alloc_zeroed_page(node);
> +               if (!early)
> +                       memcpy(__va(pud_phys), kasan_early_shadow_pud,
> +                               sizeof(kasan_early_shadow_pud));
> +               p4d_populate(&init_mm, p4dp, (pud_t *)__va(pud_phys));
> +       }
> +
> +       return pud_offset(p4dp, addr);
> +}
> +
> +static void  kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> +                                     unsigned long end, int node, bool e=
arly)
> +{
> +       unsigned long next;
> +       pte_t *ptep =3D kasan_pte_offset(pmdp, addr, node, early);
> +
> +       do {
> +               phys_addr_t page_phys =3D early ?
> +                                       __pa_symbol(kasan_early_shadow_pa=
ge)
> +                                             : kasan_alloc_zeroed_page(n=
ode);
> +               next =3D addr + PAGE_SIZE;
> +               set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERN=
EL));
> +       } while (ptep++, addr =3D next, addr !=3D end && __pte_none(early=
, READ_ONCE(*ptep)));
> +}
> +
> +static void kasan_pmd_populate(pud_t *pudp, unsigned long addr,
> +                                     unsigned long end, int node, bool e=
arly)
> +{
> +       unsigned long next;
> +       pmd_t *pmdp =3D kasan_pmd_offset(pudp, addr, node, early);
> +
> +       do {
> +               next =3D pmd_addr_end(addr, end);
> +               kasan_pte_populate(pmdp, addr, next, node, early);
> +       } while (pmdp++, addr =3D next, addr !=3D end && __pmd_none(early=
, READ_ONCE(*pmdp)));
> +}
> +
> +static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
> +                                           unsigned long end, int node, =
bool early)
> +{
> +       unsigned long next;
> +       pud_t *pudp =3D kasan_pud_offset(p4dp, addr, node, early);
> +
> +       do {
> +               next =3D pud_addr_end(addr, end);
> +               kasan_pmd_populate(pudp, addr, next, node, early);
> +       } while (pudp++, addr =3D next, addr !=3D end);
> +}
> +
> +static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
> +                                           unsigned long end, int node, =
bool early)
> +{
> +       unsigned long next;
> +       p4d_t *p4dp =3D p4d_offset(pgdp, addr);
> +
> +       do {
> +               next =3D p4d_addr_end(addr, end);
> +               kasan_pud_populate(p4dp, addr, next, node, early);
> +       } while (p4dp++, addr =3D next, addr !=3D end);
> +}
> +
> +static void __init kasan_pgd_populate(unsigned long addr, unsigned long =
end,
> +                                     int node, bool early)
> +{
> +       unsigned long next;
> +       pgd_t *pgdp;
> +
> +       pgdp =3D pgd_offset_k(addr);
> +
> +       do {
> +               next =3D pgd_addr_end(addr, end);
> +               kasan_p4d_populate(pgdp, addr, next, node, early);
> +       } while (pgdp++, addr =3D next, addr !=3D end);
> +
> +}
> +
> +asmlinkage void __init kasan_early_init(void)
> +{
> +       BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_SIZE));
> +       BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));
> +}
> +
> +/* Set up full kasan mappings, ensuring that the mapped pages are zeroed=
 */
> +static void __init kasan_map_populate(unsigned long start, unsigned long=
 end,
> +                                     int node)
> +{
> +       kasan_pgd_populate(start & PAGE_MASK, PAGE_ALIGN(end), node, fals=
e);
> +}
> +
> +static void __init clear_pgds(unsigned long start, unsigned long end)
> +{
> +       /*
> +        * Remove references to kasan page tables from
> +        * swapper_pg_dir. pgd_clear() can't be used
> +        * here because it's nop on 2,3-level pagetable setups
> +        */
> +       for (; start < end; start +=3D PGDIR_SIZE)
> +               kasan_set_pgd((pgd_t *)pgd_offset_k(start), __pgd(0));
> +}
> +
> +void __init kasan_init(void)
> +{
> +       u64 i;
> +       phys_addr_t pa_start, pa_end;
> +       /*
> +        * PGD was populated as invalid_pmd_table or invalid_pud_table
> +        * in pagetable_init() which depends on how many levels of page
> +        * table you are using, but we had to clean the gpd of kasan
> +        * shadow memory, as the pgd value is none-zero.
> +        * The assertion pgd_none is going to be false and the formal pop=
ulate
> +        * afterwards is not going to create any new pgd at all.
> +        */
> +       memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
tmp_pg_dir can be a local variable, I think.

> +       __sync();
I don't know why we need __sync(), keep the memory ordering or flush
the write buffer?

Huacai
> +       csr_write64(__pa_symbol(tmp_pg_dir), LOONGARCH_CSR_PGDH);
> +       local_flush_tlb_all();
> +
> +       clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> +
> +       /* Maps everything to a single page of zeroes */
> +       kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END,
> +                       NUMA_NO_NODE, true);
> +
> +       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)MODULES_E=
ND),
> +                       kasan_mem_to_shadow((void *)VMEMMAP_END));
> +
> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +               kasan_populate_early_shadow(kasan_mem_to_shadow((void *)V=
MALLOC_START),
> +                                           kasan_mem_to_shadow((void *)V=
MALLOC_END));
> +
> +       kasan_early_stage =3D false;
> +
> +       /* Populate the linear mapping */
> +       for_each_mem_range(i, &pa_start, &pa_end) {
> +               void *start =3D (void *)phys_to_virt(pa_start);
> +               void *end   =3D (void *)phys_to_virt(pa_end);
> +
> +               if (start >=3D end)
> +                       break;
> +
> +               kasan_map_populate((unsigned long)kasan_mem_to_shadow(sta=
rt),
> +                       (unsigned long)kasan_mem_to_shadow(end), NUMA_NO_=
NODE);
> +       }
> +
> +       /* Populate modules mapping */
> +       kasan_map_populate((unsigned long)kasan_mem_to_shadow((void *)MOD=
ULES_VADDR),
> +               (unsigned long)kasan_mem_to_shadow((void *)MODULES_END), =
NUMA_NO_NODE);
> +       /*
> +        * Kasan may reuse the contents of kasan_early_shadow_pte directl=
y, so we
> +        * should make sure that it maps the zero page read-only.
> +        */
> +       for (i =3D 0; i < PTRS_PER_PTE; i++)
> +               set_pte(&kasan_early_shadow_pte[i],
> +                       pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_sha=
dow_page)),
> +                               PAGE_KERNEL_RO));
> +
> +       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +        __sync();
> +       csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
> +       local_flush_tlb_all();
> +
> +       /* At this point kasan is fully initialized. Enable error message=
s */
> +       init_task.kasan_depth =3D 0;
> +       pr_info("KernelAddressSanitizer initialized.\n");
> +}
> diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
> index d89e2ac75f7b..df328cd92875 100644
> --- a/arch/loongarch/vdso/Makefile
> +++ b/arch/loongarch/vdso/Makefile
> @@ -1,6 +1,10 @@
>  # SPDX-License-Identifier: GPL-2.0
>  # Objects to go into the VDSO.
>
> +ifdef CONFIG_KASAN
> +KASAN_SANITIZE :=3D n
> +endif
> +
>  # Absolute relocation type $(ARCH_REL_TYPE_ABS) needs to be defined befo=
re
>  # the inclusion of generic Makefile.
>  ARCH_REL_TYPE_ABS :=3D R_LARCH_32|R_LARCH_64|R_LARCH_MARK_LA|R_LARCH_JUM=
P_SLOT
> --
> 2.36.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7bVZ5Svg4Y0TUGXy-0fksR4p9ota_HfnW4cCY%2BOw4t5Q%40mail.gmai=
l.com.
