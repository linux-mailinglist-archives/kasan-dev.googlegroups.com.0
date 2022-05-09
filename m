Return-Path: <kasan-dev+bncBD5L3BOATYFRBSU54KJQMGQEEGNOAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8ECC51F304
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 05:47:23 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id b65-20020a509f47000000b00427b34634d3sf7542230edf.20
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 20:47:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652068043; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBjsOfcDz0viyK5Zm4c9DINU5leghe0/9t5qCmQHDFTahTqenah8szczna1wIVeGEo
         LxsWT+vDVvbmCyRy17ln0RKSN5sDN7iYU8sZewvbns/YmZG4L5ncfk3IHkD97gn4bG4D
         uk5Aqhi3A5YAJ4H7kRzoMCFSiJ+dGIQlKOBxDnr0ytCVnQVT6IJH6Vp/tzNkyg9dN7bQ
         SOfRkaum4tFWTFlxXhPiiY/eC20rc+7Nv6tQV9ens7aCmO+VFy8HvsIEdLNbDFCnsXk0
         Oturw1YZfm4/fDaczqXlcx0EaHb2ihkVslHCFiwMk/x3CoAarULeMdDVMh3ns+zAkxJq
         4D7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fjSm1rwcVfMfMxnnL7Pe2VtOQyONadIgKiU3IBaoSeg=;
        b=k0OCdq+yDYtOvRmINA+aU493Q0fXQmLfDOMTitZ6ymmxJrRJe1BRNYpVkWXRCFsuzu
         yZdBRkoaSfM45jT2U8WoqHEuXZceIYiy3tzkZYdCRKSj039XFpk5DijD6SjNfXt7B7Zy
         F4TFZJW7vP7fI/SqEM0un8rNNqMYGGRELeEFs0tmVvO/eH/ERgvZ28WQ2dqwgXAm0Xt9
         vGd7vFAnVK+m4C+VW18rmdTEYPERotAIriK8Bqj2L/OGPViOQ+IOup3ybAEUBSDDD/n0
         n2czBwgVCxyeU3fFobC0Njtpk3oY923OacZY6kEBLFWvsAGNBcslbuq7DdjAnC2G737b
         4fMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=FGQqvl29;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fjSm1rwcVfMfMxnnL7Pe2VtOQyONadIgKiU3IBaoSeg=;
        b=Vd+eO3zIDaNs3bsxNHW9mEPxq616uUmUkcQwmr/jxAwIl/+Bo0oRX7d2gGRHVOs29b
         KFVdiM2Qo6wcWnziNnVH5CFTCdGhdtKcr/9m4P1Rc6AHa89UUj6vZUYiK4X1Mf2FZfvA
         +WNZXbxFOxGRpwhn4POdNVlragvguh53aIvXwXRWGRMNdJYhWevEC5KL6sqtB6lcWy9y
         n7KimVEvN4RzIcD3hwAQZpd2WdWob3MYMAOPHMQCwFH62c/55N6WykaEjPPC0CEW2FA3
         XvdsbDYxo4I54lxDHaEGhZA6xlcq18bhEfzJlxodRiC7HjmhGCr2MIv4mRZoCIKr6JFo
         +R3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fjSm1rwcVfMfMxnnL7Pe2VtOQyONadIgKiU3IBaoSeg=;
        b=eADczJiZpquqRw35/3Cme/fnrq5mSedALaMq4XP5oqbX+ZNnpIdiPi/EvmeUWK/G4n
         9Lil/dc8idAOiN+Bs42msRjAvUXlhp3oki2K31BaR6RpRc7n+Khe2X8/LVvsE8rM9hih
         GAF3cp2nFI7M89QLYV3b4HH2ar3QKy6hJCxO7IbKyU7sidh4XI47QgNlykMhgN+DiwRW
         cJjxmPRcvlrU/z23t4i5KlEw9eeq4BvIaaTCZkHoriJqh8Dm+J3x84ngYVJKp4Q0e19q
         jpTIBLRayg7p3FLk1nkDIAKqf6zuOpJmz6eLkhURcE7UWJWLYzkiZgdvxAKirRuLI/B9
         Vjqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zE/2I9L8zTXRZsYk+O6WHKqYf48+eh1yRUI3urgjDkaj0abQV
	rEPi23Yd/xk/F0PbKyHJv4w=
X-Google-Smtp-Source: ABdhPJxJtp819sQXABp0q+Yc6vwA8K/2Dmnw6jXsCLUy5ps1dEt4yVYWW1JgWfDkt+EZzzXYqeHsSw==
X-Received: by 2002:a17:907:3e8e:b0:6f4:ff62:a399 with SMTP id hs14-20020a1709073e8e00b006f4ff62a399mr13423451ejc.298.1652068043180;
        Sun, 08 May 2022 20:47:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1c9e:b0:6f4:52da:cc01 with SMTP id
 nb30-20020a1709071c9e00b006f452dacc01ls3213096ejc.10.gmail; Sun, 08 May 2022
 20:47:22 -0700 (PDT)
X-Received: by 2002:a17:907:a06f:b0:6f4:d336:6baa with SMTP id ia15-20020a170907a06f00b006f4d3366baamr12810495ejc.638.1652068042238;
        Sun, 08 May 2022 20:47:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652068042; cv=none;
        d=google.com; s=arc-20160816;
        b=HbGr0aRNfJJc8PdYFU376qBGKGZeHlPWNtCZml0C1DKU9rOQfDaKvM5Znurs9CBeAh
         IQZspZ6uQ9AB80rylkuDx9EHQHg3nZhrNqjxMDmdCjrId7VnalbAeDKpOfMcXwH9L01d
         AmkmDJhCBUvefT6B7VYXPEIFTRwB1vE8u0bR22bYUw6xuudOYSdxk1bYKjhSFCm52+Jr
         w6OFVIUm6mGMcVjvMTVR+F/OuWt0ZBd7XKiEBB+xGtcDvero6IOSdNs5uLvyl+YXlK1o
         3C32QRCVf/2XlnIl6plixg2jwMXtALgweSo5hatO2NTal0N2uwuWqkzIBsYLMHMt5Cu9
         iEkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sgeqc5+6lUb+9xfdT4wfaAHvYTUYEwM44Jw+nzAyvBo=;
        b=QhuePrlzaaoMYOUUHxLFcWcKYf/ehfX9VIpDC5lGovhYFUEkcJFSYNl86vp4/kFI49
         sFy7gl7fE1/PT+mRv3oN7uOyXw6hbIL4VM0nyoHbhgupXeqNhVR25hUpujTYw+U1knqg
         2kQ5dl53matUOVzDieUEq/8zGfCt2hoKD+TOpFoThR0r4sHnvA/QKNL86B6+NVdtVsda
         zrVGQarqP9jELd4yIrfZTDP1gPC68wI3SSGus4w+EHW3DbxhpBH/sQeP58edPSWwLFUo
         lK9grNuzqU1MQ2dzVO+XlFzzFpgOd0q/qxvNSo3mIbV03x0EsCoczyWszpL1loIz8CQK
         UKFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=FGQqvl29;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id s3-20020aa7cb03000000b0042888ee8cfdsi188828edt.5.2022.05.08.20.47.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 May 2022 20:47:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id p26so8375390lfh.10
        for <kasan-dev@googlegroups.com>; Sun, 08 May 2022 20:47:22 -0700 (PDT)
X-Received: by 2002:a05:6512:e9e:b0:473:be54:ba7b with SMTP id
 bi30-20020a0565120e9e00b00473be54ba7bmr11177760lfb.419.1652068041785; Sun, 08
 May 2022 20:47:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-3-jszhang@kernel.org>
In-Reply-To: <20220508160749.984-3-jszhang@kernel.org>
From: Anup Patel <apatel@ventanamicro.com>
Date: Mon, 9 May 2022 09:17:10 +0530
Message-ID: <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: apatel@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=FGQqvl29;       spf=pass
 (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
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

On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> Currently, riscv has several features why may not be supported on all
> riscv platforms, for example, FPU, SV48 and so on. To support unified
> kernel Image style, we need to check whether the feature is suportted
> or not. If the check sits at hot code path, then performance will be
> impacted a lot. static key can be used to solve the issue. In the past
> FPU support has been converted to use static key mechanism. I believe
> we will have similar cases in the future.

It's not just FPU and Sv48. There are several others such as Svinval,
Vector, Svnapot, Svpbmt, and many many others.

Overall, I agree with the approach of using static key array but I
disagree with the semantics and the duplicate stuff being added.

Please see more comments below ..

>
> Similar as arm64 does(in fact, some code is borrowed from arm64), this
> patch tries to add an unified mechanism to use static keys for all
> the cpu features by implementing an array of default-false static keys
> and enabling them when detected. The cpus_have_*_cap() check uses the
> static keys if riscv_const_caps_ready is finalized, otherwise the
> compiler generates the bitmap test.

First of all, we should stop calling this a feature (like ARM does). Rather,
we should call these as isa extensions ("isaext") to align with the RISC-V
priv spec and RISC-V profiles spec. For all the ISA optionalities which do
not have distinct extension name, the RISC-V profiles spec is assigning
names to all such optionalities.

Another issue with semantics is that this patch assumes all features are
enabled by default and we selectively disable it. This contrary to the
approach taken by existing arch/riscv/kernel/cpufeature.c which assumes
nothing is enabled by default and we selectively enable it.

>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>  arch/riscv/Makefile                 |  3 +
>  arch/riscv/include/asm/cpufeature.h | 94 +++++++++++++++++++++++++++++
>  arch/riscv/kernel/cpufeature.c      | 23 +++++++
>  arch/riscv/tools/Makefile           | 22 +++++++
>  arch/riscv/tools/cpucaps            |  5 ++
>  arch/riscv/tools/gen-cpucaps.awk    | 40 ++++++++++++
>  6 files changed, 187 insertions(+)
>  create mode 100644 arch/riscv/include/asm/cpufeature.h
>  create mode 100644 arch/riscv/tools/Makefile
>  create mode 100644 arch/riscv/tools/cpucaps
>  create mode 100755 arch/riscv/tools/gen-cpucaps.awk
>
> diff --git a/arch/riscv/Makefile b/arch/riscv/Makefile
> index 7d81102cffd4..f4df67369d84 100644
> --- a/arch/riscv/Makefile
> +++ b/arch/riscv/Makefile
> @@ -154,3 +154,6 @@ PHONY += rv64_randconfig
>  rv64_randconfig:
>         $(Q)$(MAKE) KCONFIG_ALLCONFIG=$(srctree)/arch/riscv/configs/64-bit.config \
>                 -f $(srctree)/Makefile randconfig
> +
> +archprepare:
> +       $(Q)$(MAKE) $(build)=arch/riscv/tools kapi
> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
> new file mode 100644
> index 000000000000..d80ddd2f3b49
> --- /dev/null
> +++ b/arch/riscv/include/asm/cpufeature.h

We don't need a separate header for this.

All this belongs to arch/riscv/include/asm/hwcap.h

> @@ -0,0 +1,94 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
> + * Copyright (C) 2022 Jisheng Zhang <jszhang@kernel.org>
> + */
> +
> +#ifndef __ASM_CPUFEATURE_H
> +#define __ASM_CPUFEATURE_H
> +
> +#include <asm/cpucaps.h>
> +
> +#include <linux/bug.h>
> +#include <linux/jump_label.h>
> +#include <linux/kernel.h>
> +
> +extern DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);

This is a redundant bitmap. Please re-use "riscv_isa" bitmap for this
the ISA extensions.

> +extern struct static_key_false cpu_hwcap_keys[RISCV_NCAPS];

This should be called "riscv_isa_keys"

> +extern struct static_key_false riscv_const_caps_ready;

This should be called "riscv_isa_keys_ready".

> +
> +static __always_inline bool system_capabilities_finalized(void)

Another misaligned name. This should be called
"riscv_isa_keys_finalized()".

> +{
> +       return static_branch_likely(&riscv_const_caps_ready);
> +}
> +
> +/*
> + * Test for a capability with a runtime check.
> + *
> + * Before the capability is detected, this returns false.
> + */
> +static inline bool cpus_have_cap(unsigned int num)
> +{
> +       if (num >= RISCV_NCAPS)
> +               return false;
> +       return test_bit(num, cpu_hwcaps);
> +}

This should be called riscv_isa_have_extension() and it should
internally call "__riscv_isa_extension_available(NULL, num)".

> +
> +/*
> + * Test for a capability without a runtime check.
> + *
> + * Before capabilities are finalized, this returns false.
> + * After capabilities are finalized, this is patched to avoid a runtime check.
> + *
> + * @num must be a compile-time constant.
> + */
> +static __always_inline bool __cpus_have_const_cap(int num)

This should be named "__riscv_isa_have_const_extension()"

> +{
> +       if (num >= RISCV_NCAPS)
> +               return false;
> +       return static_branch_unlikely(&cpu_hwcap_keys[num]);
> +}
> +
> +/*
> + * Test for a capability without a runtime check.
> + *
> + * Before capabilities are finalized, this will BUG().
> + * After capabilities are finalized, this is patched to avoid a runtime check.
> + *
> + * @num must be a compile-time constant.
> + */
> +static __always_inline bool cpus_have_final_cap(int num)

This should be called "riscv_isa_have_final_extension()"

> +{
> +       if (system_capabilities_finalized())
> +               return __cpus_have_const_cap(num);
> +       else
> +               BUG();
> +}
> +
> +/*
> + * Test for a capability, possibly with a runtime check.
> + *
> + * Before capabilities are finalized, this behaves as cpus_have_cap().
> + * After capabilities are finalized, this is patched to avoid a runtime check.
> + *
> + * @num must be a compile-time constant.
> + */
> +static __always_inline bool cpus_have_const_cap(int num)

Same comment as above.

> +{
> +       if (system_capabilities_finalized())
> +               return __cpus_have_const_cap(num);
> +       else
> +               return cpus_have_cap(num);
> +}
> +
> +static inline void cpus_set_cap(unsigned int num)

Same comment as above.

> +{
> +       if (num >= RISCV_NCAPS) {
> +               pr_warn("Attempt to set an illegal CPU capability (%d >= %d)\n",
> +                       num, RISCV_NCAPS);
> +       } else {
> +               __set_bit(num, cpu_hwcaps);
> +       }
> +}
> +
> +#endif
> diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
> index 1b2d42d7f589..e6c72cad0c1c 100644
> --- a/arch/riscv/kernel/cpufeature.c
> +++ b/arch/riscv/kernel/cpufeature.c
> @@ -9,6 +9,7 @@
>  #include <linux/bitmap.h>
>  #include <linux/ctype.h>
>  #include <linux/of.h>
> +#include <asm/cpufeature.h>
>  #include <asm/processor.h>
>  #include <asm/hwcap.h>
>  #include <asm/smp.h>
> @@ -25,6 +26,15 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
>  __ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
>  #endif
>
> +DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
> +EXPORT_SYMBOL(cpu_hwcaps);

Just like the previous comment. This is a redundant bitmap.
Please use "riscv_isa" bitmap for this purpose.

> +
> +DEFINE_STATIC_KEY_ARRAY_FALSE(cpu_hwcap_keys, RISCV_NCAPS);
> +EXPORT_SYMBOL(cpu_hwcap_keys);
> +
> +DEFINE_STATIC_KEY_FALSE(riscv_const_caps_ready);
> +EXPORT_SYMBOL(riscv_const_caps_ready);

Please see comments above.

> +
>  /**
>   * riscv_isa_extension_base() - Get base extension word
>   *
> @@ -62,6 +72,17 @@ bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
>  }
>  EXPORT_SYMBOL_GPL(__riscv_isa_extension_available);
>
> +static void __init enable_cpu_capabilities(void)
> +{
> +       int i;
> +
> +       for (i = 0; i < RISCV_NCAPS; i++) {
> +               if (!cpus_have_cap(i))
> +                       continue;
> +               static_branch_enable(&cpu_hwcap_keys[i]);
> +       }
> +}
> +
>  void __init riscv_fill_hwcap(void)
>  {
>         struct device_node *node;
> @@ -236,4 +257,6 @@ void __init riscv_fill_hwcap(void)
>         if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
>                 static_branch_enable(&cpu_hwcap_fpu);
>  #endif
> +       enable_cpu_capabilities();
> +       static_branch_enable(&riscv_const_caps_ready);
>  }
> diff --git a/arch/riscv/tools/Makefile b/arch/riscv/tools/Makefile
> new file mode 100644
> index 000000000000..932b4fe5c768
> --- /dev/null
> +++ b/arch/riscv/tools/Makefile
> @@ -0,0 +1,22 @@
> +# SPDX-License-Identifier: GPL-2.0
> +
> +gen := arch/$(ARCH)/include/generated
> +kapi := $(gen)/asm
> +
> +kapi-hdrs-y := $(kapi)/cpucaps.h
> +
> +targets += $(addprefix ../../../,$(gen-y) $(kapi-hdrs-y))
> +
> +PHONY += kapi
> +
> +kapi:   $(kapi-hdrs-y) $(gen-y)
> +
> +# Create output directory if not already present
> +_dummy := $(shell [ -d '$(kapi)' ] || mkdir -p '$(kapi)')
> +
> +quiet_cmd_gen_cpucaps = GEN     $@
> +      cmd_gen_cpucaps = mkdir -p $(dir $@) && \
> +                     $(AWK) -f $(filter-out $(PHONY),$^) > $@
> +
> +$(kapi)/cpucaps.h: $(src)/gen-cpucaps.awk $(src)/cpucaps FORCE
> +       $(call if_changed,gen_cpucaps)
> diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
> new file mode 100644
> index 000000000000..cb1ff2747859
> --- /dev/null
> +++ b/arch/riscv/tools/cpucaps
> @@ -0,0 +1,5 @@
> +# SPDX-License-Identifier: GPL-2.0
> +#
> +# Internal CPU capabilities constants, keep this list sorted
> +
> +HAS_NO_FPU

How can "No FPU" be a CPU capability ?

We have ISA extensions 'F' and 'D' which tells us whether an FPU is available
or not.

I think this file should be a table with two columns
"<lower_case_extension_name> <parsed_from_isa_string_yes_no>"
I this this file should look like this:

i yes
m yes
a yes
c yes
f yes
d yes
h yes
sv48 no
sv57 no
sstc yes
svinval yes
svpbmt yes
svnapot yes
sscofpmf yes
...

> diff --git a/arch/riscv/tools/gen-cpucaps.awk b/arch/riscv/tools/gen-cpucaps.awk
> new file mode 100755
> index 000000000000..52a1e1b064ad
> --- /dev/null
> +++ b/arch/riscv/tools/gen-cpucaps.awk
> @@ -0,0 +1,40 @@
> +#!/bin/awk -f
> +# SPDX-License-Identifier: GPL-2.0
> +# gen-cpucaps.awk: riscv cpucaps header generator
> +#
> +# Usage: awk -f gen-cpucaps.awk cpucaps.txt
> +
> +# Log an error and terminate
> +function fatal(msg) {
> +       print "Error at line " NR ": " msg > "/dev/stderr"
> +       exit 1
> +}
> +
> +# skip blank lines and comment lines
> +/^$/ { next }
> +/^#/ { next }
> +
> +BEGIN {
> +       print "#ifndef __ASM_CPUCAPS_H"
> +       print "#define __ASM_CPUCAPS_H"
> +       print ""
> +       print "/* Generated file - do not edit */"
> +       cap_num = 0
> +       print ""
> +}
> +
> +/^[vA-Z0-9_]+$/ {
> +       printf("#define RISCV_%-30s\t%d\n", $0, cap_num++)
> +       next
> +}
> +
> +END {
> +       printf("#define RISCV_NCAPS\t\t\t\t%d\n", cap_num)
> +       print ""
> +       print "#endif /* __ASM_CPUCAPS_H */"
> +}

This script need to change refer capabilities as extensions.

For every extension, there should be two defines.
For e.g. "sstc" extension should have following defines
#define RISCV_ISA_EXT_sstc <#num>
#define RISCV_ISA_EXT_FROMSTR_sstc <1|0>

> +
> +# Any lines not handled by previous rules are unexpected
> +{
> +       fatal("unhandled statement")
> +}
> --
> 2.34.1
>

Regards,
Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK9%3DC2Xinc6Y9ue%2B3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w%40mail.gmail.com.
