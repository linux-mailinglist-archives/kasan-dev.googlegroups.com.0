Return-Path: <kasan-dev+bncBD63HSEZTUIBBXM4YH2AKGQEFYE4SBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 43C411A4556
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 12:45:52 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id c139sf779649vke.5
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 03:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586515551; cv=pass;
        d=google.com; s=arc-20160816;
        b=yxkNpiToYLmRdHcKrRXGmCbfVZXtcVK37ri8NM1r7yBbmG37j1noFvFMJ/+sG6MdBM
         weteCLN1F2sM5VJEGVs2qRLskphxkce7W9TwKwoDRv8htjwEXCNyo79YnWWvKkNRtm46
         A0N74uEX13jotKV1QhoacYQoZyy4FIKzg8MtVYPHZsLAutaKH9OOzqYJIPALG01J+mSS
         dNgjcVSraEDvaIJHMGMbivj60s1GdBabwQMR0AzlVf+MgKbEMPULWQKTytlaauwxhOBM
         4AEAg7SKwTLgyonZua7D8I9AggToW1//abEjRVbli++fs2O8frscS2tY64RCKAVJQzmE
         4NTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=f67k6s/TDy7K9ZEktUZAQOlril2QmHAGxx6+3NA6Moc=;
        b=dHRPG3Kj/xETag9WSDJ2OfiWKiswO6nBfdXRAgF871JUZv5qc0CM5O8UFWWREf8Qlz
         gJVGAAY6Xuc6vi/+5fw83n1MJOMmX4K50kvSKQWVPkWZdqioHeGc2xZkatJtEXeIljHF
         tt5dGJRuGQSqU1X//GyX56aqi8cX4qRkaXhnFR9H/fOYbz0YYZwkWzyxxoLKVcV1kvsT
         L470tZIsttBpTdWxi1Dw+bCaLvd0fTIpX4yCgWveBUXLQu/P/bjaQLH7T3Grd758Ilu1
         3sA4KW7/kqlMAiee4+6zVwXQImycuDhxGNxHlI6+LVkjrnvLc1swvYKfzNiGvLZtNIjw
         hSGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=OTKASfAN;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f67k6s/TDy7K9ZEktUZAQOlril2QmHAGxx6+3NA6Moc=;
        b=EVyIKEI9/5TMLGFXr3BjeE/FTwFFSqJ0mxxJUdO2I8Jx8TOAAgdF0o/84bteVMiJIl
         O4Os4DfcI8UNI+UGKrOlag/2s4W0H5Bpzvock109WMVwLJ3OdAWvae0xGHy8DZs6O6jL
         RmNWAYH+e65D0EgnwAviaG8TrLH0Z14vE7ZE8sqU5fmPEtg+SZFKCCWUMcqygAvAT5Az
         7YjTgm7f0V3QpSBXB4zhYEyhNIfCF3EPYJdRm45KZvtkImflJie2CL/Xe9yZtr3Kxndn
         EFPXl9YugYii/jqnrZdnH1fmJGJbH966ZIDimKjSBTFqdRqbECtAYjy62uy7trSVckYa
         7f6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f67k6s/TDy7K9ZEktUZAQOlril2QmHAGxx6+3NA6Moc=;
        b=tl25gUgdTzQvatBLDPYjkpR0bW7PgLd8JS471fEqtdCF3WLFJrh1MWcGRc1Vlv0niP
         U2jKo7htRSpwbCmBTyQSMNfnkdcCX6dRLCseGSYtpSElED35j3lZjV6/fwt+pmGgOypE
         PjZSXvPgD4QBjLKdqqRvjBt+f1ZiKUpO1zXJYK7lIwxEWi5QeJRaG0zp7nZeCvj4Wcsn
         V8Y0xeMeOtMbeXCew2H0wer7je3KrlA9ICAPSx5CtgI+J47H8/fYlWV9AQVq4ZwXSVJJ
         KxzCrUt1BlXyLZT9ZTzWe112kkL/FO8W5ToWlPgPKbW+dQT4tDZ0deEP29QItHqwPMyf
         j0RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZQpf/seQVWe9N/jQuXhrxOoYjNL/CikidImvx8/QBRpwYtG+k7
	mxAdBW0C8XmcYn2vN/g573k=
X-Google-Smtp-Source: APiQypJkH6SUj4uRujb2Bfr6+7YJuH4jxk7UiuieQG0lq+kzB+u5IvLQLnLNSvw7TdAhKW8W2h/fWg==
X-Received: by 2002:ab0:e5:: with SMTP id 92mr2455953uaj.83.1586515549967;
        Fri, 10 Apr 2020 03:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:684c:: with SMTP id d73ls2012690vsc.7.gmail; Fri, 10 Apr
 2020 03:45:49 -0700 (PDT)
X-Received: by 2002:a67:ffd0:: with SMTP id w16mr3123501vsq.151.1586515549613;
        Fri, 10 Apr 2020 03:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586515549; cv=none;
        d=google.com; s=arc-20160816;
        b=cCKcTQMAm6EqJivwBGJxVWkPs0U+D1/MY0oImpoof6aFVfaG0HfhRbrbYMmQPf+ntS
         5y9jHjbbHUXxRTeHbqKTQi7IdJdGBqIcBvkR9kl5M9mv0+1hKZKWAI8uPrXpG1x/hPaq
         g9b+4D3kBncDbNauGfAGX6UNS44Dw+HMInZrvL6o6bv1vp93oMJ6qyQ1BwntGhnjxipy
         cPUYr9tIgPGq/sPk0S0heJ3ccPlrTfn9o3C1qL96Z8fHsLSucIkqknXH03kwee2mf/Jm
         Uiz1w8Tn4Lg0w62uOvaXHvtKqoC6Q6YfLvg9pZwK6RjmbY9K7EPJEEuMpauskdgIOWx6
         6vWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CHUJPFhZEyL5mo+dQ09kAoRf6CevD7UJ8I2mFvajqes=;
        b=Gcc91MI2lw4nQaFmKe64ozQ/PuixODMmv6Jpn9ZPpAYPVOjmaiLWtvQcs4cxGy6Ovi
         oD6oa1rVqqEF6NAlfnYXjGI3x3MmNDS7+yk2avygDe8cRUka+Eg0f4Y9BPOaZ1+CY9ko
         dLpwM7ojZ131juMRVbqTZTuHry8WOIKC7UwLs4BbbRUTxCj+Ss5qBPHSF4dysoVWePbt
         L4vJawMmDzoyn+QyRMTKl4TZ7UKVlpRk6EFPnrpDi5W1RWI0XP6MKrFDsjQHCI5jo4VZ
         0jpYRfJj1rre/wWW/sq71xgrzYdDu/8bfH5zkYAav7iQCK7gWIdfVrEtZ7/LGjY2F+PC
         aGAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=OTKASfAN;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p7si132251vsf.1.2020.04.10.03.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 03:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wm1-f49.google.com (mail-wm1-f49.google.com [209.85.128.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1A24521D7D
	for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 10:45:48 +0000 (UTC)
Received: by mail-wm1-f49.google.com with SMTP id a201so1965104wme.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 03:45:48 -0700 (PDT)
X-Received: by 2002:a7b:c050:: with SMTP id u16mr4992457wmc.68.1586515545554;
 Fri, 10 Apr 2020 03:45:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200117224839.23531-1-f.fainelli@gmail.com> <20200117224839.23531-8-f.fainelli@gmail.com>
In-Reply-To: <20200117224839.23531-8-f.fainelli@gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 10 Apr 2020 12:45:34 +0200
X-Gmail-Original-Message-ID: <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
Message-ID: <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
Subject: Re: [PATCH v7 7/7] ARM: Enable KASan for ARM
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <ryabinin@virtuozzo.com>, Abbott Liu <liuwenliang@huawei.com>, 
	bcm-kernel-feedback-list@broadcom.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Russell King <linux@armlinux.org.uk>, Christoffer Dall <christoffer.dall@arm.com>, 
	Marc Zyngier <marc.zyngier@arm.com>, Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Jinbum Park <jinb.park7@gmail.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Rob Landley <rob@landley.net>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Masahiro Yamada <yamada.masahiro@socionext.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Thomas Garnier <thgarnie@google.com>, 
	David Howells <dhowells@redhat.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Andre Przywara <andre.przywara@arm.com>, Julien Thierry <julien.thierry@arm.com>, 
	Andrew Jones <drjones@redhat.com>, Philip Derrin <philip@cog.systems>, Michal Hocko <mhocko@suse.com>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kvmarm <kvmarm@lists.cs.columbia.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=OTKASfAN;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, 17 Jan 2020 at 23:52, Florian Fainelli <f.fainelli@gmail.com> wrote:
>
> From: Andrey Ryabinin <ryabinin@virtuozzo.com>
>
> This patch enables the kernel address sanitizer for ARM. XIP_KERNEL has
> not been tested and is therefore not allowed.
>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> Tested-by: Linus Walleij <linus.walleij@linaro.org>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> ---
>  Documentation/dev-tools/kasan.rst     | 4 ++--
>  arch/arm/Kconfig                      | 9 +++++++++
>  arch/arm/boot/compressed/Makefile     | 1 +
>  drivers/firmware/efi/libstub/Makefile | 3 ++-
>  4 files changed, 14 insertions(+), 3 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index e4d66e7c50de..6acd949989c3 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -21,8 +21,8 @@ global variables yet.
>
>  Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
>
> -Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
> -architectures, and tag-based KASAN is supported only for arm64.
> +Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa and
> +s390 architectures, and tag-based KASAN is supported only for arm64.
>
>  Usage
>  -----
> diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> index 96dab76da3b3..70a7eb50984e 100644
> --- a/arch/arm/Kconfig
> +++ b/arch/arm/Kconfig
> @@ -65,6 +65,7 @@ config ARM
>         select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
>         select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
>         select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
> +       select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>         select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
>         select HAVE_ARCH_THREAD_STRUCT_WHITELIST
> @@ -212,6 +213,14 @@ config ARCH_MAY_HAVE_PC_FDC
>  config ZONE_DMA
>         bool
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x1f000000 if PAGE_OFFSET=0x40000000
> +       default 0x5f000000 if PAGE_OFFSET=0x80000000
> +       default 0x9f000000 if PAGE_OFFSET=0xC0000000
> +       default 0xffffffff
> +
>  config ARCH_SUPPORTS_UPROBES
>         def_bool y
>
> diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
> index 83991a0447fa..efda24b00a44 100644
> --- a/arch/arm/boot/compressed/Makefile
> +++ b/arch/arm/boot/compressed/Makefile
> @@ -25,6 +25,7 @@ endif
>
>  GCOV_PROFILE           := n
>  KASAN_SANITIZE         := n
> +CFLAGS_KERNEL          += -D__SANITIZE_ADDRESS__
>
>  # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
>  KCOV_INSTRUMENT                := n
> diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> index c35f893897e1..c8b36824189b 100644
> --- a/drivers/firmware/efi/libstub/Makefile
> +++ b/drivers/firmware/efi/libstub/Makefile
> @@ -20,7 +20,8 @@ cflags-$(CONFIG_ARM64)                := $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
>                                    -fpie $(DISABLE_STACKLEAK_PLUGIN)
>  cflags-$(CONFIG_ARM)           := $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
>                                    -fno-builtin -fpic \
> -                                  $(call cc-option,-mno-single-pic-base)
> +                                  $(call cc-option,-mno-single-pic-base) \
> +                                  -D__SANITIZE_ADDRESS__
>

I am not too crazy about this need to unconditionally 'enable' KASAN
on the command line like this, in order to be able to disable it again
when CONFIG_KASAN=y.

Could we instead add something like this at the top of
arch/arm/boot/compressed/string.c?

#ifdef CONFIG_KASAN
#undef memcpy
#undef memmove
#undef memset
void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
void *__memmove(void *__dest, __const void *__src, size_t count)
__alias(memmove);
void *__memset(void *s, int c, size_t count) __alias(memset);
#endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu_6wWhi418%3DGpMjfMpE2E%2BXHbL-DYKT8MJ1jE3%2BVybrAg%40mail.gmail.com.
