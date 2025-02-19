Return-Path: <kasan-dev+bncBDW2JDUY5AORBXGT3G6QMGQEG5LZTNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CDA40A3CD9D
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:31:41 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-30a3a0d1bd7sf1511751fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:31:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007901; cv=pass;
        d=google.com; s=arc-20240605;
        b=EDo4ZijrR0HZktcOSHOxhkZI5li7aWWgsyrkQguQoMP5m2bv+0AC5aRDo/d0a4TCVQ
         NzFYFKuG+qlwXOWy2KDVS+ETkgblqwmoVEBL+wqfI6PGHFKCk74fpLIO1+q5Ivk/poku
         qyyKk1x+6wWOuqwkMr33plfpfqjV4NoQEI+WAgPEsDTh64up06VFO7sIDxvwsA9bQNzZ
         P1t0tjW/1cS75A9lDggmBgCqnoazKU16NW7YbrIfPj+cPbq8wT2QoLKKCeoEJcE9ljCH
         3QEW1O0ffek8zTaJCuOOgY/KbnMZlHfRM56l8E3M+g1bfBPsErDD3VCbNWocNN0CZZU6
         SNcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aVX85dH2D+vmkEXybUT23kAjU1PbqV5ntbE4oaytPao=;
        fh=gqPPkY8fW8nGcXxnDjAfAVx5u/6QK1x69vZTuRMX6iY=;
        b=kvytDEjFt7QZEvA8eaqlEWUdFQxcHwDp/iEIIcSzM4HiDflTVFgg9jr0U02lUuaY+N
         kYo2Z4Gj0Pw4Br7PNLOG76NJ54TW01vBvoB/LdHZ6kgMh4OeHeotdOdyOatA/qApSpg6
         PMpasmFGjKQxRnAOXBs6HyvCGBiG7xXcCEHBmp2mzulzRAIchOaxAJQppSLH4QDTaGbf
         SF4wlt9IgimZHnSYKdnKhveRAMdOhirAByk+ToWfErQvF/DZsvQYSbU5I9CbrgqfkWAg
         S4xWK9hbRVK0tjA232lIQk0L6OYRBevZltzOoW4BvCf+bTb7St2wTpDI9nK/uB/nSaKD
         ROnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LCkXyacW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007901; x=1740612701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aVX85dH2D+vmkEXybUT23kAjU1PbqV5ntbE4oaytPao=;
        b=oSrsl7kODsilv0X5LJe4rEVZLQ0WvKzYb2v286JDnTLuo9dC9wvx8pWP4KJr89HT3Y
         XeyefkSmz68GKiK2TVkhh8Lv9LlN2zeCtjiVioZmb3fPG9rrRpccVNWLYk//qAE87qRf
         HDbG57o+hoXyttX4AW9KDZmV1M9zIs1qxRZ676kAsS7fX7kKymQX3c7GoJUXliH74W6R
         ebbBEM64JaG+LDZqy7xDJqHQoRnhpoREKLRd0gUlAqh+U7Tkn6mLy/9AeH2v05oEElUX
         GNvQ+6RTlKwM7/YsdpVU1+hh5OXar4tZlMbUFoVreMXnoBtEWzFxiZNmdUuv4a15hmPK
         5QQA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007901; x=1740612701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aVX85dH2D+vmkEXybUT23kAjU1PbqV5ntbE4oaytPao=;
        b=nDUEqHsxStop6vHLAe4WnZBenygi9ZEWxLGtV8WNyInQrdRnsiMlEJZp1rgPkABgjA
         703/67XJ3ynKVTBiorw9IJrCCRPp/z2/BaQFnKeINoYEC1fQjvzoz6sO75GwUJZb1e7K
         4+5WKwggKkAlUYO12w4BNGKRczZ962Z0bAH/szz/n4JJ4bD9qkvS3YXRJ6FyY08M6n5v
         uvjap1PlHA9AArxEJO+/OeQAZ88fHm9/eHq/2BPir7ilBIy4mZv0K3dKvJhqGnCEjSvZ
         IY5HcDQZgMrFb8OEZqmQnBnfnHqJ7Fm76ApK6J6Nt2A9l0d1ETquwcWet17/j7UCGjBn
         h+KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007901; x=1740612701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aVX85dH2D+vmkEXybUT23kAjU1PbqV5ntbE4oaytPao=;
        b=f1+D7Td/eOwnc0m3RZKJiVb1kVApwtfkg1j7Rq6vidw4WK0oX5SI9VGXmaxjOPaTbi
         HPyujbXt7ApgehS/z9A1+MUy+lSvZA2KZyj7BG9bBxUfmhIwQp6MwxaWuZkwzWZf4lkI
         bVlxdexWmCcq1ARkRFTJDNS3xS5H6ap1P//s/YeRAuJO8As01cjyBaYoHuCZOBFrdoWV
         LREM7kB+hu8sp7YyEfJJ/qISgnn8+TzE2BwgDjhrZEFe6BsIRanIh8q6kX5q+EsKrvK9
         R7n9NnVEp1Ua9iK0t1iqSRk3J8+OMDUO9raFHFK0VIl5L09BbSX47V1PqGG4t7GwPYkH
         aEdw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9w4EUNy4gGCIVOkNVi3gJE1mNjjj4872k5qAtGe9JKS4cw2JwT8YpSFShPY7v/LDKazIryw==@lfdr.de
X-Gm-Message-State: AOJu0YwjUCnSFFMDvioWcUhv2AdX0vVKL3x6CNAgEEVFvc7kcR/SoYIx
	Oif4Gw5XlbS6CKOSq9KTMsrJ8vd1hYRFSDiDlfTZRDzKXP5kIGOe
X-Google-Smtp-Source: AGHT+IGCF83niqsgIDD22RZMMIqvJ3vWemQVgjcGBO2KslPFon+LzU2lVBHN2PT74a13a0Z8Pl6QnQ==
X-Received: by 2002:a2e:9645:0:b0:307:ce2b:ed82 with SMTP id 38308e7fff4ca-30927a63269mr59797341fa.22.1740007900434;
        Wed, 19 Feb 2025 15:31:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG0j25iL7tycEaNlmSWw2DjUSmotmd7zfzjMem8iX3RuQ==
Received: by 2002:a2e:bc13:0:b0:30a:2c11:125f with SMTP id 38308e7fff4ca-30a4fe7c9b1ls1055761fa.0.-pod-prod-06-eu;
 Wed, 19 Feb 2025 15:31:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2l33IeQilJMhZxwR42hyxBHvj1TBEq3dlLF+ZG+i1pwwgnIFg7ciNfjsIKrckk+NZ2PdSJZKTEX8=@googlegroups.com
X-Received: by 2002:a05:6512:3992:b0:542:98bb:5674 with SMTP id 2adb3069b0e04-5452fe6b1damr7116108e87.33.1740007898018;
        Wed, 19 Feb 2025 15:31:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007898; cv=none;
        d=google.com; s=arc-20240605;
        b=C8Nhmyefzbei3x/hrhK6M2uKkVzHFsAEBsfChwZvpp9MPyViz7R+F9eUapQ9HaVv3b
         PQSNIHlqjyWdLm7/1zjciuzd5E04EyTvqV+uMXpbMcmGhRc+ygHGxmPoNnWxKtpBggLH
         h41v+o3PvTm1OcsVEiPENVeeljqRgVo+nv41ecuL4RwhW+cceq7eQLwlKCXExPjudwVJ
         kdlOGz7xuIxZ6jAoo5qguQ9enDEHX8yMdbeaPO8cQjV/GHwzAGJo9XbdzqOU7fHYVDTd
         XeHNYsjn/P4LA/EmS0uOMXTEfP/UDudswqy4zP7Iw59W3tVNjuPO3DAFRn5LbaKbecIU
         Tibg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HmA3kpoVqZacttI/kLsBWuEw55LbtbyDIck2OB1DMsE=;
        fh=BrKps6eZ3SqFsYLkOGBhBPIXQe5NeNLuTXkeemsfEKw=;
        b=Aso1goUayMH1aBVLG4vTl+jwhj3GJzE84jC3xOn7qzX3B55QlCbZ0UcJoW9vl/gWUM
         2cJi3FNLDFAIV0YyD2VxQsLAniqFtQ93jP/93/+kpThMQTkOqS7S9txUHDkoigllGX39
         z8igA/S8CxzK4KY4QsVWjuXHfhZfFLUp2lbelqa5IPh+ECJC8U+/THWwfPF/XtrfmqF+
         JX9JpqqgEP0BhjNeHqDMOuJnjGy6HzmCl9KUsE29JDAWcI7Y+RUU3OAfaKlwpG4wthLA
         oEl12NVdxnFZer61wR9owe6DsntCuEuc/lbnCjvxmavWPuwYziV4xJI8j4Yvk4SqCDdS
         NbdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LCkXyacW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5452f5cfb34si386098e87.7.2025.02.19.15.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:31:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-38f26a82d1dso169110f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:31:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVpWQ51HYS6p8vEORb2OV+vDxIn6d1kJBAnDjNw5hEKcvtTI/2vu5cJ/DlT1EIwVLScW6+SXZk/RPI=@googlegroups.com
X-Gm-Gg: ASbGncvD6+G1kP5BO0o+xZV2sXdSoL3KSLwj5dqW1BqgJ8LldAuj1GOf/wHznqKIl7A
	/tLyFAxViE8eTncTpHN0oo1w6Brpcw12iZpr046LAw3WLVPkwj8fSiBI7Q8YoGkl535P2gdOeVG
	8=
X-Received: by 2002:a05:6000:1fa7:b0:38f:4cb4:b822 with SMTP id
 ffacd0b85a97d-38f4cb4ce41mr9832739f8f.26.1740007897194; Wed, 19 Feb 2025
 15:31:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:31:26 +0100
X-Gm-Features: AWEUYZnqbVnkwo7RUnRvKpv13p7_X9As-mP0O1dDctMW1ycjuPipkHqXbxnM_MQ
Message-ID: <CA+fCnZezPtE+xaZpsf3B5MwhpfdQV+5b4EgAa9PX0FR1+iawfA@mail.gmail.com>
Subject: Re: [PATCH v2 14/14] x86: Make software tag-based kasan available
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LCkXyacW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
> ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
> (TBI) that allows the software tag-based mode on arm64 platform.
>
> Set scale macro based on KASAN mode: in software tag-based mode 32 bytes
> of memory map to one shadow byte and 16 in generic mode.

These should be 16 and 8.

>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2:
> - Remove KASAN dense code.
>
>  arch/x86/Kconfig                | 6 ++++++
>  arch/x86/boot/compressed/misc.h | 1 +
>  arch/x86/include/asm/kasan.h    | 2 +-
>  arch/x86/kernel/setup.c         | 2 ++
>  4 files changed, 10 insertions(+), 1 deletion(-)
>
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index f4ef64bf824a..dc48eb5b664f 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -195,6 +195,7 @@ config X86
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN                  if X86_64
>         select HAVE_ARCH_KASAN_VMALLOC          if X86_64
> +       select HAVE_ARCH_KASAN_SW_TAGS          if ADDRESS_MASKING
>         select HAVE_ARCH_KFENCE
>         select HAVE_ARCH_KMSAN                  if X86_64
>         select HAVE_ARCH_KGDB
> @@ -402,6 +403,11 @@ config KASAN_SHADOW_OFFSET
>         hex
>         default 0xdffffc0000000000 if KASAN_GENERIC
>
> +config KASAN_SHADOW_SCALE_SHIFT
> +       int
> +       default 4 if KASAN_SW_TAGS
> +       default 3

What's the purpose of this config option? I think we can just change
the value of the KASAN_SHADOW_SCALE_SHIFT define when KASAN_SW_TAGS is
enabled.


> +
>  config HAVE_INTEL_TXT
>         def_bool y
>         depends on INTEL_IOMMU && ACPI
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/m=
isc.h
> index dd8d1a85f671..f6a87e9ad200 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -13,6 +13,7 @@
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
>  #undef CONFIG_KASAN_GENERIC
> +#undef CONFIG_KASAN_SW_TAGS
>
>  #define __NO_FORTIFY
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 4bfd3641af84..cfc31e4a2f70 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -6,7 +6,7 @@
>  #include <linux/kasan-tags.h>
>  #include <linux/types.h>
>
> -#define KASAN_SHADOW_SCALE_SHIFT 3
> +#define KASAN_SHADOW_SCALE_SHIFT CONFIG_KASAN_SHADOW_SCALE_SHIFT
>
>  /*
>   * Compiler uses shadow offset assuming that addresses start
> diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> index cebee310e200..768990c573ea 100644
> --- a/arch/x86/kernel/setup.c
> +++ b/arch/x86/kernel/setup.c
> @@ -1124,6 +1124,8 @@ void __init setup_arch(char **cmdline_p)
>
>         kasan_init();
>
> +       kasan_init_sw_tags();
> +
>         /*
>          * Sync back kernel address range.
>          *
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZezPtE%2BxaZpsf3B5MwhpfdQV%2B5b4EgAa9PX0FR1%2BiawfA%40mail.gmail.com=
.
