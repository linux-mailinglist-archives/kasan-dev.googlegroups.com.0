Return-Path: <kasan-dev+bncBAABBIVBZ7BAMGQEIVBNWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FF90AE0094
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 10:56:04 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6fad8b4c92csf13903286d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 01:56:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750323363; cv=pass;
        d=google.com; s=arc-20240605;
        b=gAsTFjGlI2HBLkh7xPInczNRAcisWyKJ6XOzQenI/FXCcTGSXcDMEEEDM7j2+eJ0ps
         luTp/s7920vmtyWuWZAiScOf2UrYpuMeQsnHnIyYTnNeN1RpwV5mT1t10anJGfk14Ghq
         LU0tZ36QIwONfeWinQqxmvvgkao5YYLjWVMpFSlHTx69cOLxFQ4rVjNLaImZrg1nhPk5
         ngiMT3eFwUIKpg4vi4wqGLNU2tBZWP/woIk0d43BE7w9Ad0mas3KEDBPFjHr+j6WEe3K
         V6R9CTB+5iBkBoDGRtx7FDQClIBqVlVIE2As19cN7cHWrgXcqF8y7cmHg+HcgvJafhpc
         WsNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fc3r+3uZ1OUxeGdgu8yok0MS9fDPPSVX+vNy3X8/uQ0=;
        fh=jXd2+PrdOg4jvYn64QxMLIf89vrr1mQil0lzd+5I0gw=;
        b=C65YSo6bGek5n5l8+yno/bTM4tCx1r+J6kvrb5/X0tC77hed4Ybs5mNvGVwaaM6QZw
         f8SJuDSKAhdLjHs+YfV98SzbRa/WhYPhjUZXhF4qZwcqOjiiJ/AWVr4M23BHK+Bpw0S9
         jbffqOqJigpH5YZMH5N4PUlsOoi80F3UntiBaRDVHgknHGY0xr3YV/++V9fGEvMNrUzY
         VaRr9NMNBEtMTBdlvukeiGd/LmYHc5Tzjuque/Z8eBJC4HQ7E7AV3S+AmOAhy0k8rHPp
         NZIFNF2p4rj2a09VoX+Em6ogRSTB6UUeSJe4YXRhdEB0/+4CQi/HXqhqvBypxH6wXAIg
         M/ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BiG8+DpI;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750323363; x=1750928163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fc3r+3uZ1OUxeGdgu8yok0MS9fDPPSVX+vNy3X8/uQ0=;
        b=cbnnVQDJa6/p81UJE4ZvwJkYiH1BTbq4zRdVdBsY8iJEvhj6TX1RPOUW/Oz/JL7T+r
         KE6pedxzEMh+DysTPgUGSKKr2excQev4Q/EbBRY/o4q0MAvJF2XCmijeUMzK4kmNRjAq
         pnXW/DU/r4sTcAFelV3qYfLAPLPe8uM6t5qVOnLwmBoC/0UgilWIUJBmGpcqEbSwE4Ov
         3aPbfOMIONNEaOjH/F0FcKIaS7RNcDunCMOYlQAOWl1xW8WR6bD0C3wFBFWkMKz/DNVY
         Cp1D1Xj4cIwB4+hOBEGNbmbgHL5Y8sUi1WpryJ97viEhosjL5ILkOj7LN2LYkF/gAqcf
         +g7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750323363; x=1750928163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fc3r+3uZ1OUxeGdgu8yok0MS9fDPPSVX+vNy3X8/uQ0=;
        b=rA8ohBVk2kk/QTVECuKB28mzJrfOgDXHNaNTDIErw/17mV4aftrpbaWfjueOVGjpO2
         Mp1+6kbEciYANd57l5xeOVTcesJ8lRnpD+vzEAA0q9Rt5aGq6OSMTVmdEJy0/WOhPhMk
         vmOzbanpxwoDqfs7OEp1qEuZZt2eO9NTUZwj9L+K3v4GLBoj2lWV8b8eJpRmSJ6OOIgR
         IgoOZ4K+XOniMtzMgx6USkhLi2N7SQiddP/wm/apHtq0fa9HUSmfFJ/7co2TvlO3Auru
         TniT4bLAGYCZ8UFpIZd8kYuo0dEyE8g8f/kS4qJDDRje6gIZEUwIGsqI//Ow38kN4aHR
         hDfA==
X-Forwarded-Encrypted: i=2; AJvYcCWytU2sguVKH9tfB7PJTkizYVzAvvEN4XwhXmos2rLgjG1N6zF3IyZiGORgWi9QZhuYETlvtA==@lfdr.de
X-Gm-Message-State: AOJu0YwM4eaEG0h/97qtQv98+iBGJVv5/RzrzYK6jorx1NREKWHJ3lIp
	1QyU089kcNA+hMyjoduXwjjei/g6Uhf8soMJNsyzyWO3Z1TwuMoKE9Ac
X-Google-Smtp-Source: AGHT+IGZrsZbIDdWxdbLHt4qmvvXJd0PmjXjCq0gblW838/fTbRSoREvNNUVqN2scA4JUFtW0d8TYw==
X-Received: by 2002:a05:6214:224d:b0:6fa:9a6a:7cfc with SMTP id 6a1803df08f44-6fb477d9afbmr286394926d6.26.1750323362906;
        Thu, 19 Jun 2025 01:56:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfE8n7108H/8YsHrJxaHck87wAwaUKtI4qa/pyCSxk4pw==
Received: by 2002:a05:6214:d0d:b0:6fa:bcf6:6723 with SMTP id
 6a1803df08f44-6fd008123dbls9631466d6.1.-pod-prod-04-us; Thu, 19 Jun 2025
 01:56:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuf/UJZ3PEzCp7qXwlHBrKJgHUfCl3/GG+4R/Sh8VeLhha0m7WLLDpd7VX3dwbnU5/xx91A33wLhk=@googlegroups.com
X-Received: by 2002:a05:6214:f67:b0:6e8:fa72:be4c with SMTP id 6a1803df08f44-6fb47773489mr326788316d6.1.1750323362089;
        Thu, 19 Jun 2025 01:56:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750323362; cv=none;
        d=google.com; s=arc-20240605;
        b=bIPNrEjWMHMLT44wwg7AJjWfiWaJJgUiCfCKmkt50deBa32h4+nG3hcyPcxpGPLyDm
         xxOUvkvqvuAyoxFprXd2UFgWdmDtLYVt0ujWQJZAubYUv9WNoimAh+9XdZ5OXWVPxVFJ
         jYGbUMHuZxIDs6FtqBC56a1BhtVdkOxRuDInoXTimls5NCubEo5B+nu3I21yrGQWynMD
         6mxvaMY5PAdnZFdM05cRONc50hhN9jirKHqu3z9/izcU9/9rhPumQahFiRNH4wth/kAM
         ebTE7XlnrC4q1rzxOM8l3pgVA86FJGzbwfBekKL/3jIRgd/m/7Hndnmq6Sbt2dT5u4en
         9FCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OinlicTUqCKuG9MTHGgEFzHpHXn4e/TbFQka2FRD/MQ=;
        fh=o87X94tX/di0fVQdEWlOz10ONMqcpAmtX97C9aJGKu0=;
        b=fFFL6HeqBvU5CBVioSQArXA5Qly0b7a69ckz+qFggEU+30wVGpspsBOJtPSHp11r3a
         Tsxhxtai6aPeDmfJtUlbor6725OLrt6WwUYHYcDIMKht4QTkSiUVWgYTyp2UgG4UVFCU
         uUaNqZ+GBhTLrpO6WCp9P8W0bXve+BgNmrtwRtLxQaYBC4USVW9dvwhLzzZx1g2ywd5v
         Uhss4JNk+QLCultO76LAhwD0yyUn8mReEV8XGKSDBTgt3kbZ3rGpURmlAqEnn3AdAQfm
         ISC3Z32enQV8XL+RToRZJwFkdzQ8ljeWUcFbZQ7ifCAGAFUKSYKJTAUG6J6IXFMFkyx9
         kHZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BiG8+DpI;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd014fa7a9si532386d6.2.2025.06.19.01.56.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jun 2025 01:56:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 186EC5C6572
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 08:53:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40FFBC4CEF2
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 08:56:01 +0000 (UTC)
Received: by mail-ed1-f51.google.com with SMTP id 4fb4d7f45d1cf-6077d0b9bbeso863562a12.3
        for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 01:56:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU14i8BAggqHlUYpQvKIP0gp0iLVkeUCdQ7qPPe3tUSUvIZSt+ArZK0XdSI2ODLaUlpH5bQz01t+vU=@googlegroups.com
X-Received: by 2002:a05:6402:26cc:b0:607:16b1:7489 with SMTP id
 4fb4d7f45d1cf-608d094801bmr19223662a12.20.1750323359751; Thu, 19 Jun 2025
 01:55:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-10-kees@kernel.org>
In-Reply-To: <20250523043935.2009972-10-kees@kernel.org>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Jun 2025 16:55:48 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ@mail.gmail.com>
X-Gm-Features: AX0GCFvInY5DbmRkbwxLo6Cb2clGLakUsQ51xQCaa7Coc4b_DkkyTMX5tkJkYVA
Message-ID: <CAAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ@mail.gmail.com>
Subject: Re: [PATCH v2 10/14] loongarch: Handle KCOV __init vs inline mismatches
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, WANG Xuerui <kernel@xen0n.name>, 
	Thomas Gleixner <tglx@linutronix.de>, Tianyang Zhang <zhangtianyang@loongson.cn>, 
	Bibo Mao <maobibo@loongson.cn>, Jiaxun Yang <jiaxun.yang@flygoat.com>, loongarch@lists.linux.dev, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, x86@kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BiG8+DpI;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Kees,

On Fri, May 23, 2025 at 12:39=E2=80=AFPM Kees Cook <kees@kernel.org> wrote:
>
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> loongarch this exposed several places where __init annotations were
> missing but ended up being "accidentally correct". Fix these cases and
> force one function to be inline with __always_inline.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Tianyang Zhang <zhangtianyang@loongson.cn>
> Cc: Bibo Mao <maobibo@loongson.cn>
> Cc: Jiaxun Yang <jiaxun.yang@flygoat.com>
> Cc: <loongarch@lists.linux.dev>
> ---
>  arch/loongarch/include/asm/smp.h | 2 +-
>  arch/loongarch/kernel/time.c     | 2 +-
>  arch/loongarch/mm/ioremap.c      | 4 ++--
>  3 files changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/smp.h b/arch/loongarch/include/as=
m/smp.h
> index ad0bd234a0f1..88e19d8a11f4 100644
> --- a/arch/loongarch/include/asm/smp.h
> +++ b/arch/loongarch/include/asm/smp.h
> @@ -39,7 +39,7 @@ int loongson_cpu_disable(void);
>  void loongson_cpu_die(unsigned int cpu);
>  #endif
>
> -static inline void plat_smp_setup(void)
> +static __always_inline void plat_smp_setup(void)
Similar to x86 and arm, I prefer to mark it as __init rather than
__always_inline.

Huacai

>  {
>         loongson_smp_setup();
>  }
> diff --git a/arch/loongarch/kernel/time.c b/arch/loongarch/kernel/time.c
> index bc75a3a69fc8..367906b10f81 100644
> --- a/arch/loongarch/kernel/time.c
> +++ b/arch/loongarch/kernel/time.c
> @@ -102,7 +102,7 @@ static int constant_timer_next_event(unsigned long de=
lta, struct clock_event_dev
>         return 0;
>  }
>
> -static unsigned long __init get_loops_per_jiffy(void)
> +static unsigned long get_loops_per_jiffy(void)
>  {
>         unsigned long lpj =3D (unsigned long)const_clock_freq;
>
> diff --git a/arch/loongarch/mm/ioremap.c b/arch/loongarch/mm/ioremap.c
> index 70ca73019811..df949a3d0f34 100644
> --- a/arch/loongarch/mm/ioremap.c
> +++ b/arch/loongarch/mm/ioremap.c
> @@ -16,12 +16,12 @@ void __init early_iounmap(void __iomem *addr, unsigne=
d long size)
>
>  }
>
> -void *early_memremap_ro(resource_size_t phys_addr, unsigned long size)
> +void * __init early_memremap_ro(resource_size_t phys_addr, unsigned long=
 size)
>  {
>         return early_memremap(phys_addr, size);
>  }
>
> -void *early_memremap_prot(resource_size_t phys_addr, unsigned long size,
> +void * __init early_memremap_prot(resource_size_t phys_addr, unsigned lo=
ng size,
>                     unsigned long prot_val)
>  {
>         return early_memremap(phys_addr, size);
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ%40mail.gmail.com.
