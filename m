Return-Path: <kasan-dev+bncBDAOJ6534YNBBY5Z23CAMGQEJ6M37EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E3AB1E269
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 08:44:53 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-55b872fdb2esf428135e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 23:44:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754635492; cv=pass;
        d=google.com; s=arc-20240605;
        b=OGtQeSPhDwXiPlfMBpG0v7yxvur2oOd8Eks5ZQeGJ8so0O4ZjdYKHWyX0OXFOcaKFe
         dD5K1wD0g4a4yXZN2tFPvlCscBZd/b5nkiXbpcrCEXkv50rWpHKJvZhg9+5S2mFCHz9a
         wxSpNBKMNFnCy6aClfSkyYqDnlhmjApy4mVUFOUSkwt8Us8BPHJLf96X9iQqf4mqw8Ar
         k6hxXN82yne/A+n2vvB7LenK4XRdYPKRuUgP/QM+vAxICbvRLRoICOH1NC0cjXAIVVWV
         qBeg4bqGOGb83wyP4cGddqDTm8lFvDXvDB0HASVgWJF6XNoGh9QPiJndlfqJ1gxB3tn/
         sSdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=kphnKW+UkHaRweSUQ5P2O6lodLH6zKale3kUA1bJrTQ=;
        fh=uU4mMfJh6I7XVLhE7b187ZTNVqVKYB6p0QRvF0VE6B8=;
        b=JI4niKlZzrizdyE4ojr7ZSSwp8pTzEaV48SyxFESXPO/HLM7O291TDGUOXjtpBJqqn
         zt9flTA9olvfjFAJHDg+GLsWtZNOrgVmPOgntlnaV8nhPu2eXuBDoWKHJOLah8MXgVwX
         vFzk7Xm4+GpInjvCu6uP8UkmEhp9kERJwaxdzAiYaxhoWdKNvDvDuPS6FafPIz+Jw0UJ
         7Mji6eXC3LnjiO0GmL7UrK/jyJ3zAq6gMeYUmy8WuwIKInnBC8+QYF3zPfDIEleDH6ar
         UvKz+zX9bFc/pyYRtYI7ofmqFMI++9q/mbRa0/XDwYJH7qAzRqHXI1tT0EFlUPUJ2QaO
         hM7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3IqRt2T;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754635492; x=1755240292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kphnKW+UkHaRweSUQ5P2O6lodLH6zKale3kUA1bJrTQ=;
        b=CZg3C/oGVVdzQ/8MwUGh6OnE4dWYgKzbIxsd6ltovNy8J2vzfEdNHHBtZJSlxQbPds
         Fpj+EfcQdPDGB7BaKOEyyklFxHjH1Yi6kwj+LXYbdu+u2b/R1D2muexAi9CUmaBnEWKO
         cvRlgONVbrCRPxZMYLp5zlFCi76pa58en+w5bRdKZXCSDUJ0ETEgTLAdWDtz7Gpl9g9P
         iJOvuUZab1Bvjd76JrHA6iU3VYcMLuXwitKF/hafEmgTYCbVw34ApLq4Z2820Va3cnlW
         vgxr0ke5MJ0lax7NPvk+b4rCJthdpNaNw1m/sXq7z/ZX2LIjTbgOm5BpZ9WswhXXBF09
         MRAQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754635492; x=1755240292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kphnKW+UkHaRweSUQ5P2O6lodLH6zKale3kUA1bJrTQ=;
        b=kULP5UItG+MJRMPv6lGX8bYPEiCwnS1I7ENjPKVrRrW6XxnHG3ViRp6wSFeuewyPqC
         a+oMumgGsDgDojA8avKngDxjNgO6UyGEY6IspW6TdldMF7fYD5IBt+AtSRPN3jaZjf6s
         Tzt5IS3VgfqivToaewaIJtNjNqbapPuL5QRcbUB1F+ct1Eev+aOwAY46FiUsr1SqY6I2
         QgvusWeQWZjf6l3/Pi86S+yOj1VdFVmyPrruy1XaZGr5BDIltamjsIClfwUilMJlU0It
         zgd2dykBKvQI1tbqnFqHWL3pj5gjM7LRUWyZmYco60nEXT3mFGOqN+6UD53ktAy4Ik0M
         /eVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754635492; x=1755240292;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kphnKW+UkHaRweSUQ5P2O6lodLH6zKale3kUA1bJrTQ=;
        b=sFHY8+TdpLcqHNq0rZLFvpM6YRer9TkKukUkxmJoXoFB5I483CSE/uTJN51N1vFUCB
         HKg/9doRb0UCtmR2T9Huzf7XSWpIVyZ7m9yH2+W5jkreo4duw7mC5zZMtBds70jf3rKd
         3QuD7NJ5X3Dx3fehNGBVd3by3/3WZ8JDphLX/VvXMNO+HIS69B22dxpkdi3QggemdDFV
         1gC/S3dL5j1JfbqE/SYMGOSVc3bi7czj4+6EqTSX/bns89n4HRT2P5X38Rp23CgdLUFK
         V20vE73hHvppN7sh2YGbD3R3a1VnMFY2+fLv4Mqt5Vbs/X2CFGm+BGuasv0m3XWHu2Vp
         l3SA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXoovKolXhfOVoWcfbd2FSRt8lVw+DMeYirKjdse+uNnY+FVNil4ZBspqRDY8BKa1pzU5ewuA==@lfdr.de
X-Gm-Message-State: AOJu0YzqrA7l+Lv2am6jqzmqdBe+D+WaEEfAXzlXLnDsCbeURNvD0RKy
	0H3JKRucxHxSCr5Yyaj3VMSyfJ+i6BKXRidId+dG14IMuHZ49Rq3oYGk
X-Google-Smtp-Source: AGHT+IF+KwgemGl6W3jAAcVWmR1urHEPPtZ2q9EKNURQbWba+O5FVi0ETwnJZiUh9VVBstrKf57v0g==
X-Received: by 2002:a05:6512:1094:b0:553:2d93:d31 with SMTP id 2adb3069b0e04-55cc00d0857mr476342e87.22.1754635491895;
        Thu, 07 Aug 2025 23:44:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcIbcUzhq+doCWe8TtWJoB7m2C4IcnE8uFiYftc8NClMQ==
Received: by 2002:a05:6512:10c9:b0:553:24ed:d64f with SMTP id
 2adb3069b0e04-55cb6260c55ls700948e87.2.-pod-prod-04-eu; Thu, 07 Aug 2025
 23:44:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmMQmDsQJkHT+H6++ThV8xYEfM1tvvUNgBdjfGFtodOWxdrPmC2RORaxK0QewokiEmfuk5pp/e4tc=@googlegroups.com
X-Received: by 2002:a05:6512:3e11:b0:55b:920c:33eb with SMTP id 2adb3069b0e04-55cc01345camr376542e87.42.1754635488770;
        Thu, 07 Aug 2025 23:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754635488; cv=none;
        d=google.com; s=arc-20240605;
        b=P8/XzD6tR3mtWpvebLZW/3vRIxTlSHRpBakX+0PvtZIskbzhfhwdJ81AzsM/Dw604u
         OmGLY21rugaxLQIu1foc4Z9OcDTr//rbehcwmVbi849Z4uZaWGcCySxtUEaSgvEPWtsi
         6ccVor8bEtEMrVNCSMitWGMnXtf/dTG2HxpCQUO/QODGOLT5mxbc9XwMAD0B3sC8V5pV
         xi6Y+aXrjwOcA45s5kO/Rh3VkyiciQ4SETmROmZiHOwj8bskaQyk+dFYJZToKMZ9PdJH
         iiVv40lRn6iGl+J9kTfFGRIVdkKk9/Utl73cTs/m+Qq/w5pA2QHICBn9+aiOIAAiIc32
         Nn8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/bygktD0fqAfBcULD1cv//efBpJOrdPBFdY6zXSYR1E=;
        fh=SJd52TjwXSNK/lPbx3OS3gqkIwdznd/3cHjn+k6HvnY=;
        b=Okw6SPT477Q7WHFrvByCF2YUNIliyjIvnBp5oJnIAoCaT7X99ekfYFJe69BCr8Padh
         ADfadpPa5PMznBtkUYQzFU93lt32R01lspVoQylLwvQTCtwyXNt2v3W500POlQfmyASC
         mFiGHNvDBHVVSN6zN9BGqF86k7pbAnKg9jdsh68ygM+Y3oHiqytEpi8Xw4dX05YjvFLr
         Tq2XIan1/00CKZ1USR/hNall7o44lp+2YDEBf3olf3UYiyBUseNg3KzpliPpo+QqpO+X
         DObYox5dnQ9qZoiYNVhppfiIcvPBr1nkPN6aJVBy1R576oSnAvcQRcZJ9+GZVGj7Glih
         QX0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3IqRt2T;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9a222e4asi394472e87.5.2025.08.07.23.44.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 23:44:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-32f1df5b089so16471521fa.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 23:44:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC4zn/y/sGVQ1WhDWH8isfEag++IwQuIkDJEGLtotKFLb0Zbw5suALjnuVnkVm/aWeQUH4X9Qbj48=@googlegroups.com
X-Gm-Gg: ASbGncuabZD63kwZZfy6gas8BQTJBcDu+dRSjpFbE8cdsBFK7ajWiIQOugZeLPtdM04
	piq3CMdN3/CBNFHdnZLN8F5OWVBLATHY+iDYKnDFqL8idGnhGK1kChu9sbfAsLf/MvgrJayNHWI
	tXtZffgj7TnS0KT07KLUMffXLWFVEWfci/XcVbGIbAD0rTmX8X3Y8HAlRTTvYk83d2QwdPFUavo
	cF0B+HtUTBaUw==
X-Received: by 2002:a05:651c:4010:b0:332:2df3:f8ac with SMTP id
 38308e7fff4ca-333a222c31amr3330341fa.32.1754635487960; Thu, 07 Aug 2025
 23:44:47 -0700 (PDT)
MIME-Version: 1.0
References: <20250807194012.631367-1-snovitoll@gmail.com> <20250807194012.631367-3-snovitoll@gmail.com>
 <07ffb27c-3416-43c9-a50a-164a76e5ab60@csgroup.eu>
In-Reply-To: <07ffb27c-3416-43c9-a50a-164a76e5ab60@csgroup.eu>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 8 Aug 2025 11:44:30 +0500
X-Gm-Features: Ac12FXy3j3jcHWv5quQse7L5XRgGZZuU0Dnwj-G3jWlUZ0ijDblLaDUsIz_V-Q8
Message-ID: <CACzwLxhahYWfRc5xKshayniV6SuFFnMT0NfHttippcASzZgtRw@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] kasan: call kasan_init_generic in kasan_init
To: Christophe Leroy <christophe.leroy@csgroup.eu>, alex@ghiti.fr
Cc: ryabinin.a.a@gmail.com, bhe@redhat.com, hca@linux.ibm.com, 
	andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, davidgow@google.co, glider@google.com, 
	dvyukov@google.com, agordeev@linux.ibm.com, vincenzo.frascino@arm.com, 
	elver@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org, 
	Alexandre Ghiti <alexghiti@rivosinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S3IqRt2T;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Fri, Aug 8, 2025 at 10:07=E2=80=AFAM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
> > Call kasan_init_generic() which handles Generic KASAN initialization.
> > For architectures that do not select ARCH_DEFER_KASAN,
> > this will be a no-op for the runtime flag but will
> > print the initialization banner.
> >
> > For SW_TAGS and HW_TAGS modes, their respective init functions will
> > handle the flag enabling, if they are enabled/implemented.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
> > Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390
> > ---
> > Changes in v5:
> > - Unified arch patches into a single one, where we just call
> >       kasan_init_generic()
> > - Added Tested-by tag for riscv (tested the same change in v4)
> > - Added Acked-by tag for s390 (tested the same change in v4)
> > ---
> >   arch/arm/mm/kasan_init.c    | 2 +-
> >   arch/arm64/mm/kasan_init.c  | 4 +---
> >   arch/riscv/mm/kasan_init.c  | 1 +
> >   arch/s390/kernel/early.c    | 3 ++-
> >   arch/x86/mm/kasan_init_64.c | 2 +-
> >   arch/xtensa/mm/kasan_init.c | 2 +-
> >   6 files changed, 7 insertions(+), 7 deletions(-)
> >
> > diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> > index 111d4f70313..c6625e808bf 100644
> > --- a/arch/arm/mm/kasan_init.c
> > +++ b/arch/arm/mm/kasan_init.c
> > @@ -300,6 +300,6 @@ void __init kasan_init(void)
> >       local_flush_tlb_all();
> >
> >       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> > -     pr_info("Kernel address sanitizer initialized\n");
> >       init_task.kasan_depth =3D 0;
> > +     kasan_init_generic();
> >   }
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index d541ce45dae..abeb81bf6eb 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -399,14 +399,12 @@ void __init kasan_init(void)
> >   {
> >       kasan_init_shadow();
> >       kasan_init_depth();
> > -#if defined(CONFIG_KASAN_GENERIC)
> > +     kasan_init_generic();
> >       /*
> >        * Generic KASAN is now fully initialized.
> >        * Software and Hardware Tag-Based modes still require
> >        * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
> >        */
> > -     pr_info("KernelAddressSanitizer initialized (generic)\n");
> > -#endif
> >   }
> >
> >   #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > index 41c635d6aca..ba2709b1eec 100644
> > --- a/arch/riscv/mm/kasan_init.c
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -530,6 +530,7 @@ void __init kasan_init(void)
> >
> >       memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
> >       init_task.kasan_depth =3D 0;
> > +     kasan_init_generic();
>
> I understood KASAN is really ready to function only once the csr_write()
> and local_flush_tlb_all() below are done. Shouldn't kasan_init_generic()
> be called after it ?

I will try to test this in v6:

        csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
        local_flush_tlb_all();
        kasan_init_generic();

Alexandre Ghiti said [1] it was not a problem, but I will check.

[1] https://lore.kernel.org/all/20c1e656-512e-4424-9d4e-176af18bb7d6@ghiti.=
fr/

>
> >
> >       csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
> >       local_flush_tlb_all();
> > diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
> > index 9adfbdd377d..544e5403dd9 100644
> > --- a/arch/s390/kernel/early.c
> > +++ b/arch/s390/kernel/early.c
> > @@ -21,6 +21,7 @@
> >   #include <linux/kernel.h>
> >   #include <asm/asm-extable.h>
> >   #include <linux/memblock.h>
> > +#include <linux/kasan.h>
> >   #include <asm/access-regs.h>
> >   #include <asm/asm-offsets.h>
> >   #include <asm/machine.h>
> > @@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
> >   {
> >   #ifdef CONFIG_KASAN
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized\n");
> > +     kasan_init_generic();
> >   #endif
> >   }
> >
> > diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> > index 0539efd0d21..998b6010d6d 100644
> > --- a/arch/x86/mm/kasan_init_64.c
> > +++ b/arch/x86/mm/kasan_init_64.c
> > @@ -451,5 +451,5 @@ void __init kasan_init(void)
> >       __flush_tlb_all();
> >
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized\n");
> > +     kasan_init_generic();
> >   }
> > diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
> > index f39c4d83173..0524b9ed5e6 100644
> > --- a/arch/xtensa/mm/kasan_init.c
> > +++ b/arch/xtensa/mm/kasan_init.c
> > @@ -94,5 +94,5 @@ void __init kasan_init(void)
> >
> >       /* At this point kasan is fully initialized. Enable error message=
s. */
> >       current->kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized\n");
> > +     kasan_init_generic();
> >   }
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxhahYWfRc5xKshayniV6SuFFnMT0NfHttippcASzZgtRw%40mail.gmail.com.
