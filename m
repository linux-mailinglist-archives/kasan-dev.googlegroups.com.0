Return-Path: <kasan-dev+bncBD63HSEZTUIBBSM5YH2AKGQEVEK63EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A7AD1A455D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 12:47:38 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id k140sf2316587ybf.5
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 03:47:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586515657; cv=pass;
        d=google.com; s=arc-20160816;
        b=m+SqI1KmGBksjSvzVPL8JRGP8u7f4v30CWN3cY3Y4vVulhs/SyPc/1cR4MrNREOTFL
         6T68bWY9pagLbpeRr/emjaXt4Ftlq2lFS3jzpHi5BFBMGBMYwlzMrWRR26IVtOvwzW1K
         I1sDQ1MFKp9MUZmbd+7P+kxLBe9XY/lrTFafsUMuI0FFHFiVR9Lv0M55o9hfU4FjlxUP
         eEFqR8uV0Ul4X6iAJS9CjZGQDUqXjBcdk9ZJxFqfmdq65L5qFdBLsM4mEt1wb6NfwnnV
         ypQ1t6NodlJg1SOSD1+xU0Adn14J7bRMZpEAknVfFbuTTZTmPu0NqyVx09UGU05nGoO4
         iSGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=nzlU43ZxxNt20UHqWGq7wsdPBB4HK1yA1INWXL7YDdE=;
        b=CWVC/tBYkL0beLursorId6OwO2YYunipsmqEEMFwG00DE3LDliOdcpCEiBQ8fI5hZG
         7T7SXReaLoFiuYuZwF4hau7Nj0/KHgkC9+Y90iiL0qFmlMScpXoW4wSkR2ws9CGe2gSi
         Cfcd4QK0vknjjI8463UXtBt776MevcwKt8KPwoDxB0yOx8ksYzLxFPmegwFRC2u7JM06
         tX342wSEWh3CGIW18YKQOzvhxSPfKcRprWGQ5ghtzsWE1G4z1J+BRtUJcj+7uyP+ByVc
         5hvKrANxwPxzg0TUWxA5DNih/fWZDh1WtF2bJkv11NN5C5PrO79a1QYjfWl1kukJ9pLV
         lO7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Kp997bcL;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nzlU43ZxxNt20UHqWGq7wsdPBB4HK1yA1INWXL7YDdE=;
        b=iV89QplWXQNm85YoTek+L6IT6La8TpJPapWBQveNp2AsglQmE7Dd1zWwT6Nr9anAZ/
         4SpcDbr3iUsdt6uR8e75CSyJ3aocgmi3ypKq6sKJBi8FnxS/m1S9y0pQLWxm/9a2D/Nt
         qRQonEeRF3rx7+KvPCHf+tCSGbvzmfDNZEaJQiuDYVLwiX8T/hMZGV93eAjq29VlZ2tX
         i2maX7xcnRnEdWu1x+k1XY8Yg4hWfUTpIJdZ8XMWTIo19pPvBZ5a2g1u9sJ4858S+B3/
         sRyPgynTnD0jmZNA3aHoTVAuDjn5ZMqKlXCdlm0JX5cb4UOoR8GlUtyXNeWGEbP4BeYD
         42Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nzlU43ZxxNt20UHqWGq7wsdPBB4HK1yA1INWXL7YDdE=;
        b=mYoIfaIFFQZsOObSFI3QjVs3bKXHqW9TBOyPfHbGR9dM8qPm5+jtLWzitXyq2b1JIY
         YlZD1p1MuwsU4MfxRxW1scZVjnICdo/oiFf7O+b/JzlVydeQoerW75/V2s1iqshY2kU9
         Xn7NvyR9RLs34Jz29lirdRR1BPYmMj2/jWiCL6d1JwlYXOTX1xtMbVTsdHZjeONwRgKR
         bF/RSnwa6Or2YZPm1ZKnUW6tTSlgXlBXK90hiAcUBkaUqs+H2ArrLLvzUdb+iGi7UHsT
         QfV8g2Z/TDbN1fh9yXrUG54GKtmSwh11Gq6CgUXwUaspPuPwpJ34Hj5L/DJR3d0tox60
         ov2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubIK366GRUNxHLPVfPBuh0ENV8aGk7TYB/ImGQ9i4BuBTSwaUvE
	W7O2GkxQmE3wR92NdFbIGC4=
X-Google-Smtp-Source: APiQypIhgMX03ioVneMjBHmJs5NsxWvJBW6vFImTcyswlWHYjX1szaOdZE+2bvVGUDuEmq3MfwldNA==
X-Received: by 2002:a25:ba03:: with SMTP id t3mr6611986ybg.438.1586515657451;
        Fri, 10 Apr 2020 03:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dcf:: with SMTP id 198ls5401268ybn.8.gmail; Fri, 10 Apr
 2020 03:47:37 -0700 (PDT)
X-Received: by 2002:a5b:64a:: with SMTP id o10mr6678834ybq.434.1586515657055;
        Fri, 10 Apr 2020 03:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586515657; cv=none;
        d=google.com; s=arc-20160816;
        b=JxsYJABaqNhhi3ammNBmIsUgSQ9he/WoeI6l6oZJKDsRy8pUMxaXTmerLJXtDpSQK9
         PxTKfjV3+BVIvCECBlWKNZJm+2HNmhnEu+DfE2yo+PDD6VRwWQeRD5ueYfCoc1cRzAqF
         YTXjbPc9g8Oa6bOq0TuQl78yQ40JQ0DfFrCO0bQ+cvsOdX7XYwClBRdfmO1IQlngQ/xh
         CoyHdXZkydbjb7DLEwOEwUpL3czPFD5hiLzgv0hl9lffnc3sNyx4g2JMmkGNTcE+/Pi7
         cYX/k0GQZHOwnY/AGgx13jwBfTFLXXtTVvUm1VWKzOiFn+8pICFZiN6O5kHCe+NKpyhj
         0XjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Xm030+2305XYpgut9WlO6qdD7ILKjDQxrvkOFpf+8h0=;
        b=W+SM1rC+NDaFvF6VYvtx8RstdoxKwWOeMA0pUNa4ahwb7j/EqmXdErmlGrr82Dn4rH
         btlt3dc3WpGKquyT9bxIKk0a+zZM74/qoZqnuLiUCZqRe1/NHLAVWU/8WbcfuHrx6ZGK
         f6OGJPRbzFwpwEErcKJ7IgdnLUujZF98RnN8O+rDTfDsNLI+3405hHRIgKOQcAaDCV/r
         PXyqdtw42T0sgK8nFaJeGRhw6R0tRAkOU5Ro9iDUD2Yqz/3Iy6d+PVL6IjAHQ3JW3Y2a
         UfSpvBliUEcLVSNvDiAZCGa3b4AP84aFnPshiUiEpdNcYWYrU/F850ahACEMlSWSmvIj
         Pdhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Kp997bcL;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s10si112391ybk.0.2020.04.10.03.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 03:47:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-io1-f43.google.com (mail-io1-f43.google.com [209.85.166.43])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 11F6820787
	for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 10:47:35 +0000 (UTC)
Received: by mail-io1-f43.google.com with SMTP id w20so1388936iob.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 03:47:35 -0700 (PDT)
X-Received: by 2002:a5d:8b57:: with SMTP id c23mr3679119iot.161.1586515654446;
 Fri, 10 Apr 2020 03:47:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200117224839.23531-1-f.fainelli@gmail.com> <20200117224839.23531-8-f.fainelli@gmail.com>
 <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
In-Reply-To: <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 10 Apr 2020 12:47:23 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEmSk6Sq+WPAMc=x=HyP2EzVYbNYjB-4YSLByUurbXa0A@mail.gmail.com>
Message-ID: <CAMj1kXEmSk6Sq+WPAMc=x=HyP2EzVYbNYjB-4YSLByUurbXa0A@mail.gmail.com>
Subject: Re: [PATCH v7 7/7] ARM: Enable KASan for ARM
To: Florian Fainelli <f.fainelli@gmail.com>, Linus Walleij <linus.walleij@linaro.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Michal Hocko <mhocko@suse.com>, Julien Thierry <julien.thierry@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm <kvmarm@lists.cs.columbia.edu>, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, bcm-kernel-feedback-list@broadcom.com, 
	Dmitry Vyukov <dvyukov@google.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Andrew Jones <drjones@redhat.com>, Vladimir Murzin <vladimir.murzin@arm.com>, 
	Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>, 
	Marc Zyngier <marc.zyngier@arm.com>, Andre Przywara <andre.przywara@arm.com>, 
	Philip Derrin <philip@cog.systems>, Jinbum Park <jinb.park7@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, Nicolas Pitre <nico@fluxnic.net>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, Christoffer Dall <christoffer.dall@arm.com>, 
	Thomas Garnier <thgarnie@google.com>, Rob Landley <rob@landley.net>, 
	Philippe Ombredanne <pombredanne@nexb.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin@virtuozzo.com>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Kp997bcL;       spf=pass
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

(+ Linus)

On Fri, 10 Apr 2020 at 12:45, Ard Biesheuvel <ardb@kernel.org> wrote:
>
> On Fri, 17 Jan 2020 at 23:52, Florian Fainelli <f.fainelli@gmail.com> wrote:
> >
> > From: Andrey Ryabinin <ryabinin@virtuozzo.com>
> >
> > This patch enables the kernel address sanitizer for ARM. XIP_KERNEL has
> > not been tested and is therefore not allowed.
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > Tested-by: Linus Walleij <linus.walleij@linaro.org>
> > Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> > Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> > ---
> >  Documentation/dev-tools/kasan.rst     | 4 ++--
> >  arch/arm/Kconfig                      | 9 +++++++++
> >  arch/arm/boot/compressed/Makefile     | 1 +
> >  drivers/firmware/efi/libstub/Makefile | 3 ++-
> >  4 files changed, 14 insertions(+), 3 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index e4d66e7c50de..6acd949989c3 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -21,8 +21,8 @@ global variables yet.
> >
> >  Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
> >
> > -Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
> > -architectures, and tag-based KASAN is supported only for arm64.
> > +Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa and
> > +s390 architectures, and tag-based KASAN is supported only for arm64.
> >
> >  Usage
> >  -----
> > diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> > index 96dab76da3b3..70a7eb50984e 100644
> > --- a/arch/arm/Kconfig
> > +++ b/arch/arm/Kconfig
> > @@ -65,6 +65,7 @@ config ARM
> >         select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
> >         select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
> >         select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
> > +       select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
> >         select HAVE_ARCH_MMAP_RND_BITS if MMU
> >         select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
> >         select HAVE_ARCH_THREAD_STRUCT_WHITELIST
> > @@ -212,6 +213,14 @@ config ARCH_MAY_HAVE_PC_FDC
> >  config ZONE_DMA
> >         bool
> >
> > +config KASAN_SHADOW_OFFSET
> > +       hex
> > +       depends on KASAN
> > +       default 0x1f000000 if PAGE_OFFSET=0x40000000
> > +       default 0x5f000000 if PAGE_OFFSET=0x80000000
> > +       default 0x9f000000 if PAGE_OFFSET=0xC0000000
> > +       default 0xffffffff
> > +
> >  config ARCH_SUPPORTS_UPROBES
> >         def_bool y
> >
> > diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
> > index 83991a0447fa..efda24b00a44 100644
> > --- a/arch/arm/boot/compressed/Makefile
> > +++ b/arch/arm/boot/compressed/Makefile
> > @@ -25,6 +25,7 @@ endif
> >
> >  GCOV_PROFILE           := n
> >  KASAN_SANITIZE         := n
> > +CFLAGS_KERNEL          += -D__SANITIZE_ADDRESS__
> >
> >  # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
> >  KCOV_INSTRUMENT                := n
> > diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> > index c35f893897e1..c8b36824189b 100644
> > --- a/drivers/firmware/efi/libstub/Makefile
> > +++ b/drivers/firmware/efi/libstub/Makefile
> > @@ -20,7 +20,8 @@ cflags-$(CONFIG_ARM64)                := $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
> >                                    -fpie $(DISABLE_STACKLEAK_PLUGIN)
> >  cflags-$(CONFIG_ARM)           := $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) \
> >                                    -fno-builtin -fpic \
> > -                                  $(call cc-option,-mno-single-pic-base)
> > +                                  $(call cc-option,-mno-single-pic-base) \
> > +                                  -D__SANITIZE_ADDRESS__
> >
>
> I am not too crazy about this need to unconditionally 'enable' KASAN
> on the command line like this, in order to be able to disable it again
> when CONFIG_KASAN=y.
>
> Could we instead add something like this at the top of
> arch/arm/boot/compressed/string.c?
>
> #ifdef CONFIG_KASAN
> #undef memcpy
> #undef memmove
> #undef memset
> void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> void *__memmove(void *__dest, __const void *__src, size_t count)
> __alias(memmove);
> void *__memset(void *s, int c, size_t count) __alias(memset);
> #endif
>
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEmSk6Sq%2BWPAMc%3Dx%3DHyP2EzVYbNYjB-4YSLByUurbXa0A%40mail.gmail.com.
