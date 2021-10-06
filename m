Return-Path: <kasan-dev+bncBD4NDKWHQYDRBRE26SFAMGQEMM7XFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F3D242360C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 04:43:18 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id g10-20020a17090a578a00b0019f1277a815sf2773737pji.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 19:43:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633488197; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFsUAkJ5E3zUEIY25fTgtSsm/RSUvYDk+b7GDlZINu9TAH5yZ8Jei+pSUnDDbIepT1
         U+nVb8otF8tjzR51u3YkIqYjfe2Ol/6phn0dVmMiPU19fEtvj3RmivSm8FqQDZg44N3/
         sMVikOHqpuESNpbe/MVoKEa6Wt7nYwDc+b7TQ4Zwjez26ourrZyg5qEkmhp0EBH8Zd0c
         SCtsfe6GtqewFh0NciOiIVwIdlMBueOj5ekjzYnzqhFKmaIrbbtXNIaAAFqO6Ja3Tyih
         xwPtZoWlPm7MeWOEcmSa+o8TRiUVXCZtG3ngIV9sVnBqMb2/dd8Hv0VZ6v6UbWErozRr
         PDVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VWBtu7JbZqSquV4v2HQcpSU2Kk3ZwETORP2K1f58WRw=;
        b=RD2wzKp5iOaai5iWtK0LqBij0xynIEC7PWuMb/v2gjA6+5JxZB10h4wk+EMNZyf6kY
         CIpRuKVqHASkIMdCHz9Re80zcLupz51zmOHx/bOC+oFHdwsZcn6djPDnjkRhGU2/qB7w
         LVhtRmkr7NHHWFuHlLMAFe4rRJaBEyJeoeX6udOManPIOkSBaKoLQmdP8d15KPB+a8FJ
         x3kun2Hq+d949X8V0Uc8lEcSosLYLKDINHLFEWxVvStTt8GR7zAgzxhpje/W5TppPnsp
         U3v5JYgRnuF2FR7RXd9VQedjAD/j6qe6c9P2vh1OGyL9IAxwOaaNCREcN90h6/mHafMn
         MUOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kTn8n8T6;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VWBtu7JbZqSquV4v2HQcpSU2Kk3ZwETORP2K1f58WRw=;
        b=axDmpQTRcTNmehETZf1bnqcAcQROGapgt/2CPqfPuzivqQ9ZWwg0e91vziyJYHeW5h
         SVEK7FO2fRY+Os5TOOIbUqjB9t1YX4+Ez6yItvE21zLLCWMgcb2malLkr2Tw87rYWzif
         S/BnRZxEKbMwj7+NfkiJ1lZWByUAMOZyHFMYG1DKvnO6EPIIKdflWm/8Odzm3PGoB97S
         Nk244fYxGtaYEw62sY0YF9SfYwpSX1RGmS3OFF9+Dab19oJyJPzMZEz2e3pmNi5zbs3b
         WgqZOIEtBx6bxo5HxNTQY9ouZfgVRtjt1rDJ4YxLDtKbwevq2KtL7vPWYPigCl3t0bD0
         kbuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VWBtu7JbZqSquV4v2HQcpSU2Kk3ZwETORP2K1f58WRw=;
        b=i9NhHfGqEezUurVCiBt2CPiYZrJ7tNd412kZvy+gnlxqusHpXx5aC5pNjdbWzL1nHe
         jMhZFCaGgMCOIUHlmSxdMkC6hXV1M1x7kz6NT+68cGr7hYB6qquSJp0GAcIJTP+uWi37
         JXUJznd/ubytO0sjfs7ZWUdt595RXAurPA2R0kt2SHKjtSmKDdADmY7IQBAjufXFzjqy
         pVjxHlgqqJFVYHV2RnSdN5jKuuFib0ZGb2wiNaq/991CL+F22BUT/n6DQrCSYyGDY7yN
         zsWYM+MvAEUUdbDFphSy0dzk43b0RUxMyk4K+MQllcmNPyiYSDlMQIP4uvwuD9ZSFLAv
         TVWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322P7jBuqstxsVWdSXydMM4QIuHBTFJPOU+AZ+nRXNAVJCsQTYD
	rw4LDyqjA2IpmrOr0QXRL7E=
X-Google-Smtp-Source: ABdhPJw0hKOr7FKz3Z6BM7Mus//LcmrKRMNGbuX1NgE8WFNjbFPeKnyQHzV0XXpzvzP/mQDq7ESPnw==
X-Received: by 2002:a17:90a:d195:: with SMTP id fu21mr7665507pjb.67.1633488196850;
        Tue, 05 Oct 2021 19:43:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:20cc:: with SMTP id i12ls12797046plb.8.gmail; Tue,
 05 Oct 2021 19:43:15 -0700 (PDT)
X-Received: by 2002:a17:90a:1d0:: with SMTP id 16mr8009159pjd.60.1633488195765;
        Tue, 05 Oct 2021 19:43:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633488195; cv=none;
        d=google.com; s=arc-20160816;
        b=jw6zcqkd1T0qzqibO/KxXRixiX13qjwFlhMvLet7ZVUIVyINXs0bE3aJNcb1KkCmAW
         vf/TDqoGPSQbX5GS+OBbA/OR2ZGyieV+W3TSUy8ytvNrmo4kxJv7w/omp7qG5nsWyx+J
         d7DRS52A1mv4FAIV1DBrYyMRZ6vIcHqYykwbzP5lBLehZOxyyK3g7HBsC2Zul2sfgeQQ
         tnvEqxO5L70RAwXZ2VLnXI0g1aqH2b3vIy9IoKNrVYUh5lD2QGFScJ+DuTRNq3ipFuL9
         gJUzr5z1t+8udl0aHW9lcqFRxOFHzNqL0FgwVInOvewg+KETj9MzdJnNLUE2duEvhdmf
         AiDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=olCmEXEctA8d+ob0pE1gf/u2OIVZKLJNKJvaXIHzVsQ=;
        b=vEm2HJmfboe2UTpNvMwADr7l/VZapjS5WUCXKkGk6q4ICQWlx0llFpcj4jJ4dBogPc
         +cGOBfRxWWxeYoNtWlliPyYrNvPDLsZoNS0xhuPSUnaQdGmgky/2O3LtGXqPddSbizf2
         sfjfuheRe8A5p0Q4F/fOo1GoXVPQrtnDdq22pYqkff4dYFk88qkcp5TdOh6wONdwV+og
         q81BY5q7bwTwNyto5g1gaZ5VftNKJu7kC9YqzoQMdEiVHLzh2Cr/XQI7Tp3kLQAw5QPj
         85TMtV0GmY3/4maFQ7cLGIIWraCep1W4cNOrTVmMBmG/Qr9B9ULfKWr1SbyWGbROU0Lk
         opRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kTn8n8T6;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a69si1103334pfd.1.2021.10.05.19.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Oct 2021 19:43:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9AA8C611AE;
	Wed,  6 Oct 2021 02:43:13 +0000 (UTC)
Date: Tue, 5 Oct 2021 19:43:10 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
Message-ID: <YV0NPnUbElw7cTRH@archlinux-ax161>
References: <20210922205525.570068-1-nathan@kernel.org>
 <CA+fCnZdfMYvQ1o8n41dDzgJUArsUyhnb9Y_azgCVuzj6_KBifA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdfMYvQ1o8n41dDzgJUArsUyhnb9Y_azgCVuzj6_KBifA@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kTn8n8T6;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, Oct 03, 2021 at 08:04:53PM +0200, Andrey Konovalov wrote:
> On Wed, Sep 22, 2021 at 10:55 PM Nathan Chancellor <nathan@kernel.org> wrote:
> >
> > Currently, the asan-stack parameter is only passed along if
> > CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
> > be defined in Kconfig so that the value can be checked. In RISC-V's
> > case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
> > asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
> > is disabled, resulting in large stack warnings with allmodconfig:
> >
> > drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12:
> > error: stack frame size (14400) exceeds limit (2048) in function
> > 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> > static int lb035q02_connect(struct omap_dss_device *dssdev)
> >            ^
> > 1 error generated.
> >
> > Ensure that the value of CONFIG_KASAN_STACK is always passed along to
> > the compiler so that these warnings do not happen when
> > CONFIG_KASAN_STACK is disabled.
> >
> > Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> > References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
> > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > ---
> >  scripts/Makefile.kasan | 3 ++-
> >  1 file changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index 801c415bac59..b9e94c5e7097 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -33,10 +33,11 @@ else
> >         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
> >          $(call cc-param,asan-globals=1) \
> >          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> > -        $(call cc-param,asan-stack=$(stack_enable)) \
> >          $(call cc-param,asan-instrument-allocas=1)
> >  endif
> 
> This part of code always looked weird to me.
> 
> Shouldn't we be able to pull all these options out of the else section?
> 
> Then, the code structure would make sense: first, try applying
> KASAN_SHADOW_OFFSET; if failed, use CFLAGS_KASAN_MINIMAL; and then try
> applying all these options one by one.

Prior to commit 1a69e7ce8391 ("kasan/Makefile: support LLVM style asan
parameters"), all the flags were run under one cc-option, meaning that
if $(KASAN_SHADOW_OFFSET) was not set, the whole call would fail.
However, after that commit, it is possible to do this but I was not sure
if that was intentional so I went for the minimal fix.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV0NPnUbElw7cTRH%40archlinux-ax161.
