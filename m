Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5OOZH6QKGQES6GVH4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD582B4322
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 12:50:14 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id c19sf1256935pgj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 03:50:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605527413; cv=pass;
        d=google.com; s=arc-20160816;
        b=GwmsLNvrMF6qv76OB2i6X0gTe/94hmKbbUH1vTM2uKhHHkIkNTuo5j1nlaawEze02h
         dFVUYhx9iVFyixFFYKV9cHbyv+sMQOX1i7vWbif8pl4+1PJxJkzVrWcDIgESW8AEvAEF
         /eosduxbvqVSDY5pww2xgC1nFN9iJzL+hLjnveggcRQaNFo2z3/LzZPr/1eI7Tvdtpd2
         LcBioFzLFtcg+/2zubKqupvCRXtft1VXzde9g96BdaNuBzzfb0N1WxODOamBLueZPqtV
         aFqJgUoIROzlVbcSUbuUJwImM5fvQlJLEc3kLY2czH9yKu3jWpXuS57Zxhec58w/SQrR
         HsoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ykjT8hHTDFuf8BAJ+B67JGGcE+YhZkr79c1QUSa7ooE=;
        b=0XpWdt8ZAC7LJFRdA+svU6pvX8elO7NSLEHxRY+wPWzrHPyGRQRK36cv0nJIYk3RpX
         JYihEvens4h0FUYLWqxqw6SiwdkdJL7eXdvNOSSDCNrn8cnDB9+4n+9qYHOo/e8YdUIB
         td+QRYC317GOVAD/fwgAQmPRbVVZzmmkjzczaJgaYjF4u3kAZ9KAouI0smWkY979Gn5+
         tQoA5EAoGGiz1XCftS/uZiw0b0hkj2jyV3sFRXs7WAv4zq8hW2ueJFfHEKbZrLlz66Pp
         LxD3+3FYZ9kIV4FxgDG9e4wN662Gb6oIeAWy2tNiUwWx4TXrTJ0QHZynEhRxYVQEBfxl
         2pPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pt6jcPm5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ykjT8hHTDFuf8BAJ+B67JGGcE+YhZkr79c1QUSa7ooE=;
        b=iuYqxIal3FGNNLL87HsT6v6ld+pmEIOUU4EV3g3uQ8lgSr6bFx+5cQ8vV6Y+2U3UYr
         FvK9qWAGryOPOhcVWuChcKZE1SH4QWALFTWSc9GgkAk7v6aDlZFDEPhnPK1Hs45WQ7qe
         f1aqOySTlXkZF87xRq0ZbwrLlJItiCaYhFHS0bDGDohgC9H03y9FidX80eRYNCDQcCjS
         BNXzjCasvo6PcMdldLXHXz7NC+k7JiLTbxtrId1ofbq1chqwCDAjSGrM44EyOsUrkiCf
         CVByoxyicGx4dzeiUbpGOTSr7KJ5L0PH/ehkeMrtviGkFOlBX0H199GyDbyXlaqB4H7+
         UsRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ykjT8hHTDFuf8BAJ+B67JGGcE+YhZkr79c1QUSa7ooE=;
        b=ultlUdEPA9qsLJvaacHsLYSG9YuvgWMUD/qVVl+MIAdjTWj/b+zm6rEyGneb7QSv72
         ufxuSkMtlQ+pVR1oZXmuRltIc5Ci7kmK5iRDDd36EYj0XO/tLQiICZnmjZLkRHjpj3qg
         7IwIfGUHL23TPn+fdDPbXGHNMzUCjlG5qdzngmod1WXdeYbQmB3P7HM2o8siyAnlOdWt
         gfxb5TWaVaoGPH0tvY8/dTjELW3UxSPG87p8wuusJU4v1OrU4RRRNgTPOWsyQncGE3uH
         7bZSQhHRCJrb7o+YikH9kclwPyqekGmhW34qDxe7E/n6T43yHtmvfiweNs5EoFg0aHhK
         gxMA==
X-Gm-Message-State: AOAM530aZzuZ2dOq9/XSwBN7HuL18moyyMP71wOcY8L38TSanWSY5B+5
	DQQvTI2KJhEGnxrU1Xwvx00=
X-Google-Smtp-Source: ABdhPJwgCFP8UnDB3BcFRPnwn48mpeczD1oY/aIpLmEllGeUn2KSJ4eMvusNOA+/VpM26qXsCg9ANg==
X-Received: by 2002:a63:f944:: with SMTP id q4mr12263461pgk.98.1605527413293;
        Mon, 16 Nov 2020 03:50:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e905:: with SMTP id k5ls126090pld.4.gmail; Mon, 16
 Nov 2020 03:50:12 -0800 (PST)
X-Received: by 2002:a17:90a:cc0b:: with SMTP id b11mr15384015pju.97.1605527412597;
        Mon, 16 Nov 2020 03:50:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605527412; cv=none;
        d=google.com; s=arc-20160816;
        b=Np2HlegLli/fIOtjghvAErKvnYeFm5DW3Q9t2cCN7a19D2o32Kk6vTBUCFYdviN6AQ
         Mz564nWgEOgD/63uhCbRTN8XvlxJsUkby2LtH9tgKJ1fMpavfJJm1IJPIF2T738yVJx0
         RSf8+ZZYbrvZxXyw3hXXSvGHaskdXZEAj0SooxGsNsrjAtWlhZLeIaRDMT9elh9groDR
         S7jyuZiVoMI9gbSBAJ07CDXrb+Z03ItdPItEx6oiGZw+IJyNJTcaVbF1dESn8xrAT2uS
         L4dd8cTnUe6P/n+TPLzXCtDGFApGUrDRLMJdvtfcmxNicxdGJIyDmMTeDb70uRrz50GS
         ulXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fu3D6i8J61m+Cc7UW0OMX7Lqixc5Ynk1q+2LnV9wne0=;
        b=O/XRXolE0vxwOIX/D7Gw/M9eeYD6ydik4uaY/izjtkVfPBMentdHSLj0iRYVf1xOoC
         yBcVnNgg1b1O7BHSG12zLhmLrIn5ET6o/HvUOZC0RIw/zD7YeE3fnVVl/fCVE+jwTMCb
         8gMYgfem7KTzartuitHoICUQyHn1+RAHC9ySFIQsBKEtsQB6H3p7nSB7anjeLavK8cYU
         a1JUcC1MGmBPQXWuabrlCIwC5hujHP2NymZCBD5dQ+CUoGssu3zLwA2TFccVD7vjthjg
         dLY81lM0m8O3gLvNBqnRQ2TbHMManOzLWdcUAd3HLbW4WKbK5W9kmaGhwv5kynjm0VQ3
         ym6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pt6jcPm5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id lw12si1056763pjb.1.2020.11.16.03.50.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 03:50:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id 79so15672869otc.7
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 03:50:12 -0800 (PST)
X-Received: by 2002:a9d:69:: with SMTP id 96mr6596676ota.233.1605527411731;
 Mon, 16 Nov 2020 03:50:11 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com> <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
In-Reply-To: <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 12:50:00 +0100
Message-ID: <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pt6jcPm5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 16 Nov 2020 at 11:59, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 29, 2020 at 8:57 PM 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > > >
> > > > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > > > KASAN to use stack instrumentation and perform validity checks for
> > > > stack variables.
> > > >
> > > > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > > > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > > > enabled.
> > > >
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > > > ---
> > > >  arch/arm64/kernel/sleep.S        |  2 +-
> > > >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> > > >  include/linux/kasan.h            | 10 ++++++----
> > > >  mm/kasan/common.c                |  2 ++
> > > >  4 files changed, 10 insertions(+), 6 deletions(-)
> > > >
> > > > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > > > index ba40d57757d6..bdadfa56b40e 100644
> > > > --- a/arch/arm64/kernel/sleep.S
> > > > +++ b/arch/arm64/kernel/sleep.S
> > > > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> > > >          */
> > > >         bl      cpu_do_resume
> > > >
> > > > -#ifdef CONFIG_KASAN
> > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > >         mov     x0, sp
> > > >         bl      kasan_unpoison_task_stack_below
> > > >  #endif
> > > > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > > > index c8daa92f38dc..5d3a0b8fd379 100644
> > > > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > > > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > > > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> > > >         movq    pt_regs_r14(%rax), %r14
> > > >         movq    pt_regs_r15(%rax), %r15
> > > >
> > > > -#ifdef CONFIG_KASAN
> > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > >         /*
> > > >          * The suspend path may have poisoned some areas deeper in the stack,
> > > >          * which we now need to unpoison.
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index 3f3f541e5d5f..7be9fb9146ac 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
> > > >
> > > >  void kasan_unpoison_memory(const void *address, size_t size);
> > > >
> > > > -void kasan_unpoison_task_stack(struct task_struct *task);
> > > > -
> > > >  void kasan_alloc_pages(struct page *page, unsigned int order);
> > > >  void kasan_free_pages(struct page *page, unsigned int order);
> > > >
> > > > @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
> > > >
> > > >  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> > > >
> > > > -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > > > -
> > > >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> > > >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > > >
> > > > @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > > >
> > > >  #endif /* CONFIG_KASAN */
> > > >
> > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > >
> > > && defined(CONFIG_KASAN_STACK) for consistency
> >
> > CONFIG_KASAN_STACK is different from other KASAN configs. It's always
> > defined, and its value is what controls whether stack instrumentation
> > is enabled.
>
> Not sure why we did this instead of the following, but okay.
>
>  config KASAN_STACK
> -       int
> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> -       default 0
> +       bool
> +       default y if KASAN_STACK_ENABLE || CC_IS_GCC
> +       default n

I wondered the same, but then looking at scripts/Makefile.kasan I
think it's because we directly pass it to the compiler:
    ...
    $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
    ...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPNqHsOfcw7Wh%2BXQ_pPT1610-%2BB9By171t7KMS3aB2sBg%40mail.gmail.com.
