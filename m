Return-Path: <kasan-dev+bncBD7YVUUI5IMBBS4M5HBQMGQES3VHF4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 2626DB0A4B7
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 15:04:13 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ab3b89760bsf39260151cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 06:04:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752843852; cv=pass;
        d=google.com; s=arc-20240605;
        b=ReO1JRwlrQEPGE67ctU6aoUHHGPE9IEhIW+46+XHOM8ljwppG79kCTjQQ9Z5Af6OFN
         5pG1z7+Za5vwZxbDC4IolgvNutRTZGHz3hd2Z1yfUd+e7dFFvuhpFDyejtPoJRemMffP
         ZO3xRWQj9oXtAMkrY4KLhP9+Hmw0GfXDpk9zlnDKgafNpRhR1cqn0gUutHVu82BXoz0V
         yBaP/9310P/+7cfY7+QEwD6bCbqIcJint32k63iwfJOXHT2XcthAygyPzAHxsNEmTt3k
         DXNnBYaKiGFzKI3i64wDbJK2AY0Ofmb5K7GUOMFnQ4yPntncCi27P1n4ZlITGt6egaqc
         a7Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Uj8a1gEdcPgZTfAcc/PshXLvj+9xAfSUcDeufAbUAAM=;
        fh=DqPERWpmf+tAWdYh4pu2xm9aRw1bZgBKsVZoj0KcJ3w=;
        b=AkTgvDC7pEdOJoBNokAZ5IK4H6qv8Ek0YMCXZTfM3VU42H7/SahJtRQBqYGfwrbTuV
         E55VOiEHFLSznrxKmI8emFPA5K/fvj9/LAITWa80anzZI0+j4skJSXvj7VqAvOvs8jE+
         J51VyqRYO+fSuqTKVkCgpGKrPMcKkTX+LL2kOEt3f7soGghZkHpUZ/OE8pZgSxw244bb
         Y2FEDFnieduoj/Us23nL8Q4dCYIqX3yx38NhPLmIaJy6zgKLIkw2bIxytNGOsBmGvKR4
         m9sOM+pmAXZB7ETVffKVQCz/8aW332c0hkn1eYaVD/2axSnimKUqgZgLzZikVp7fzD4w
         IfaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dSHIa+Mr;
       spf=pass (google.com: domain of lee@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=lee@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752843852; x=1753448652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Uj8a1gEdcPgZTfAcc/PshXLvj+9xAfSUcDeufAbUAAM=;
        b=QNKPgpEGRDfBRf/W007fFZW0r3QPM8EMHvWC8vgUoLUM+OGUwctOD5gvdU/JfLxwxO
         gzBPedVYR4oEQm/Oi5ja4tdfL69RebVELjPXtcfKfls/vciqS36HnsQJixCnUSWFn5ce
         F2QqFGKVqEa15Cv6MDgvi3N5NduZXtaded9SLYbyrX42639DK5cQPr3P7HBDSQL/ZGWL
         8UTC4QgjEiCuiXnUZuisqDQERdNpLntSmGrsk3fenc/1rZL67bmhlf+1BUS7dwFFbnV3
         wgg1mHKiaU/dwQimnEMef5KjEKLdUC2vD8uZ3XO8b5ZUys8o4Mas8Nwj0PqMN29vN8cy
         gwnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752843852; x=1753448652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Uj8a1gEdcPgZTfAcc/PshXLvj+9xAfSUcDeufAbUAAM=;
        b=lH7c2wal0AjAJE7vQE2etRC/yDw/Gh81esiEo3Gy0XrHMg733DYGQYEYcdvyFYif9K
         dwZUlyQezsoiEtT80AGqCK4/H0CKKmURTm7l1U/AeMG565BQPoWI4zIG0s7bbSMhh/vX
         24NCGx/nWxWGtoM03V+qQ5r/LEGod4Ps5xYZxgBTkJRFB29nHU3BUQYUpMoZdAsZp4Gp
         sk2GqqqKIyh0bVeJfVUJvacmcPqkYtBzJIh2e/sTI49PunKBkgI688FR5CatpF368OAB
         k5hO0Yrr0pMLLBqM1kJtA1VFNhFOac6AYvz9A3m7wzoe8ZwYBS/qcCrSRxUaAYTt6jHQ
         NuIw==
X-Forwarded-Encrypted: i=2; AJvYcCXibgyNNaucAWfCUWHcgqSJIDFhsAfbvvt1sSYiKZmSlsU7muRR7ht9I9IBt4MC7AsDDqDAfQ==@lfdr.de
X-Gm-Message-State: AOJu0YzkLIge18987C08ICSq5IMGwUPpeqopmkJsJCTCIDuAXuYGo9ZT
	jVQA7yI8+i3hRQ43CnX+yGJspq6/kMHcKL9HMVAFFiUgeCCiBLu3oqZZ
X-Google-Smtp-Source: AGHT+IG1CiL8m/UT8NVzWn28b549Lc2Br3/LowWzsQypJa8415Y0/ThXP41dbhVj0rtijwUj72AREg==
X-Received: by 2002:a05:622a:4d4a:b0:4ab:77a3:2f64 with SMTP id d75a77b69052e-4ab939d91dcmr139510461cf.0.1752843851422;
        Fri, 18 Jul 2025 06:04:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfcpyVp0h1LFyrZjSW3l93+Bj5FDaCJHKaMgK1rh2ImYw==
Received: by 2002:ac8:7f08:0:b0:4ab:40fc:abd with SMTP id d75a77b69052e-4aba19faf2fls32057841cf.1.-pod-prod-06-us;
 Fri, 18 Jul 2025 06:04:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJ98MydwN1EBTdlZuRMNMJn1T2c6sb2RvetVTU5jTu4nVY4hjcvNAwjzYGHJRk1SRf9XQFGPOr/fU=@googlegroups.com
X-Received: by 2002:a05:620a:28c4:b0:7e0:6012:f18f with SMTP id af79cd13be357-7e343613062mr1329004985a.49.1752843850547;
        Fri, 18 Jul 2025 06:04:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752843850; cv=none;
        d=google.com; s=arc-20240605;
        b=DE8+aIDUKtatnXZxH7zLT3SSdg0InCgTs4Y7IMwMYpblPvCcL1g0JSB/d3uGwzUnxu
         QpTzTFl6bN6sntcmb/dppdtvalUZVK1INm8JPytuOZPHAeWEPeNLZcZIC4xZ8HmSf446
         YIxKzwMiVNZUEHBmp1BHFAuLjraZMVAwDd3Yv1cMySY320hHpNiiyTMbFJ8vMA+q8Uzb
         HwzB+S0cFfldg169MR74rkUrpISqkLL/in/on9HzmrsB83K7hF6rlWetjEaP8IW++B/a
         hXLDfnU1eaMHnsHo1lIIqjeNrJNuRnhIdqxZBaMY2+T4JjleTaqtyA9daFYvWcVijiYf
         92hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1QyuKp1ne6S0Nw91olTOl1i1He12QQQlzxYlMWsDPf4=;
        fh=VMQnWOci/Wvv50ewaSJF22wO62IJaQRMTnBhzs+Z8HM=;
        b=L/rORMO6Vx0wygS/tbnSS0f0s51Z+NEq+25sJs0+AAwoWVN23CWY1dbKPYzSHiBXll
         QB+A8+Qf2jEysMa1ccjY8qDte+phx8PkYfrgHlSxqt+uRaQMjjc7Y1QUTS8ftP2snlVV
         XUckkx6qpE1e/TU10icxBY1Ask90/jyd7LEt4iy6yWnncQ7+AzArG6JvVMaE+hmXIrJP
         noP7LfDTKFepFfWqBbC6tgzaIfSnGbkCxBeDB5KMxZMX1qYZlUcHrRemPRJyoZUg8jlS
         3Bf6eoKU5ZYzxFHRedWrLEhipciXB0Cjqwi0JA2yoEjCMzP2zkzd9PxdCAhIB1Fm+KMP
         fPyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dSHIa+Mr;
       spf=pass (google.com: domain of lee@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=lee@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7051ba7b65csi903616d6.7.2025.07.18.06.04.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jul 2025 06:04:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of lee@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E3DEC601D9;
	Fri, 18 Jul 2025 13:04:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 76E41C4CEEB;
	Fri, 18 Jul 2025 13:04:03 +0000 (UTC)
Date: Fri, 18 Jul 2025 14:04:00 +0100
From: "'Lee Jones' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Nishanth Menon <nm@ti.com>,
	Russell King <linux@armlinux.org.uk>,
	Daniel Lezcano <daniel.lezcano@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Santosh Shilimkar <ssantosh@kernel.org>,
	Allison Randal <allison@lohutok.net>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 05/13] arm: Handle KCOV __init vs inline mismatches
Message-ID: <20250718130400.GB11056@google.com>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-5-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250717232519.2984886-5-kees@kernel.org>
X-Original-Sender: lee@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dSHIa+Mr;       spf=pass
 (google.com: domain of lee@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=lee@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Lee Jones <lee@kernel.org>
Reply-To: Lee Jones <lee@kernel.org>
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

On Thu, 17 Jul 2025, Kees Cook wrote:

> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> arm this exposed several places where __init annotations were missing
> but ended up being "accidentally correct". Fix these cases and force
> several functions to be inline with __always_inline.
>=20
> Acked-by: Nishanth Menon <nm@ti.com>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Russell King <linux@armlinux.org.uk>
> Cc: Daniel Lezcano <daniel.lezcano@linaro.org>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Nishanth Menon <nm@ti.com>
> Cc: Santosh Shilimkar <ssantosh@kernel.org>
> Cc: Lee Jones <lee@kernel.org>
> Cc: Allison Randal <allison@lohutok.net>
> Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Cc: <linux-arm-kernel@lists.infradead.org>
> ---
>  include/linux/mfd/dbx500-prcmu.h  | 2 +-

Acked-by: Lee Jones <lee@kernel.org>

>  arch/arm/mm/cache-feroceon-l2.c   | 2 +-
>  arch/arm/mm/cache-tauros2.c       | 2 +-
>  drivers/clocksource/timer-orion.c | 2 +-
>  drivers/soc/ti/pm33xx.c           | 2 +-
>  5 files changed, 5 insertions(+), 5 deletions(-)
>=20
> diff --git a/include/linux/mfd/dbx500-prcmu.h b/include/linux/mfd/dbx500-=
prcmu.h
> index 98567623c9df..828362b7860c 100644
> --- a/include/linux/mfd/dbx500-prcmu.h
> +++ b/include/linux/mfd/dbx500-prcmu.h
> @@ -213,7 +213,7 @@ struct prcmu_fw_version {
> =20
>  #if defined(CONFIG_UX500_SOC_DB8500)
> =20
> -static inline void prcmu_early_init(void)
> +static inline void __init prcmu_early_init(void)
>  {
>  	db8500_prcmu_early_init();
>  }
> diff --git a/arch/arm/mm/cache-feroceon-l2.c b/arch/arm/mm/cache-feroceon=
-l2.c
> index 25dbd84a1aaf..2bfefb252ffd 100644
> --- a/arch/arm/mm/cache-feroceon-l2.c
> +++ b/arch/arm/mm/cache-feroceon-l2.c
> @@ -295,7 +295,7 @@ static inline u32 read_extra_features(void)
>  	return u;
>  }
> =20
> -static inline void write_extra_features(u32 u)
> +static inline void __init write_extra_features(u32 u)
>  {
>  	__asm__("mcr p15, 1, %0, c15, c1, 0" : : "r" (u));
>  }
> diff --git a/arch/arm/mm/cache-tauros2.c b/arch/arm/mm/cache-tauros2.c
> index b1e1aba602f7..bfe166ccace0 100644
> --- a/arch/arm/mm/cache-tauros2.c
> +++ b/arch/arm/mm/cache-tauros2.c
> @@ -177,7 +177,7 @@ static inline void __init write_actlr(u32 actlr)
>  	__asm__("mcr p15, 0, %0, c1, c0, 1\n" : : "r" (actlr));
>  }
> =20
> -static void enable_extra_feature(unsigned int features)
> +static void __init enable_extra_feature(unsigned int features)
>  {
>  	u32 u;
> =20
> diff --git a/drivers/clocksource/timer-orion.c b/drivers/clocksource/time=
r-orion.c
> index 49e86cb70a7a..61f1e27fc41e 100644
> --- a/drivers/clocksource/timer-orion.c
> +++ b/drivers/clocksource/timer-orion.c
> @@ -43,7 +43,7 @@ static struct delay_timer orion_delay_timer =3D {
>  	.read_current_timer =3D orion_read_timer,
>  };
> =20
> -static void orion_delay_timer_init(unsigned long rate)
> +static void __init orion_delay_timer_init(unsigned long rate)
>  {
>  	orion_delay_timer.freq =3D rate;
>  	register_current_timer_delay(&orion_delay_timer);
> diff --git a/drivers/soc/ti/pm33xx.c b/drivers/soc/ti/pm33xx.c
> index dfdff186c805..dc52a2197d24 100644
> --- a/drivers/soc/ti/pm33xx.c
> +++ b/drivers/soc/ti/pm33xx.c
> @@ -145,7 +145,7 @@ static int am33xx_do_sram_idle(u32 wfi_flags)
>  	return pm_ops->cpu_suspend(am33xx_do_wfi_sram, wfi_flags);
>  }
> =20
> -static int __init am43xx_map_gic(void)
> +static int am43xx_map_gic(void)
>  {
>  	gic_dist_base =3D ioremap(AM43XX_GIC_DIST_BASE, SZ_4K);
> =20
> --=20
> 2.34.1
>=20

--=20
Lee Jones [=E6=9D=8E=E7=90=BC=E6=96=AF]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250718130400.GB11056%40google.com.
