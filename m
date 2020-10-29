Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ555T6AKGQEMMJL6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7722D29F5A8
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:57:56 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id b25sf3925691ybj.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:57:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604001475; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnD7o3FiUGYcudaEshOhuu/PHvGoj2HcefAD4eBjA8ldvYPgN1IDDm4EH+HMPo1wzv
         bE6qDH7RaBGyZZwhdLEgjxET80WYTKARd7CIww1BDsDkq34+y/eckcm0Tt3Tva1lDCvl
         gATzREkEF0VDCzOyHEiDphaWYJGXOga4t4a+8I4Zg+G25WI/Y+nHsJajlWSMUoksCxP0
         OolkdkZUr4kK29Wlo2Ft9tryaeARgZqN+punPlU/IGRah4pBhxJe5UyIFzAchEHwlFsq
         cjbkssRwZIFrc59YEeI6TFM4/UxVy+1bBnfrMQzsPhFXk6LPyk/ZOGjYeBO2AgHQXd9V
         HWdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TLoJHzQQgMMWn6gBMktz95EazKUndSsibqPH13M92cE=;
        b=hRcxOzIPs6KKIM4dLzipje3KEdEf/bCK1fX6p9nRtW5b6/527jL2cGOLW7mDWZ+WUk
         y/ScheP9abo4zXaeWe2C1q9kQwd+sn15DFl8GrrFB80eUuO8UyZwOJiq9f6S3FaFFqoI
         Ep2hri4GLGy5MmmmJJsD3R+QSVnTrNb3YDphm11yrj5Jw6Yh7KRa6LwxUtCaJ/+a2eYj
         fkJlTvBbn7moJEgUToD9CH19pnwtjdW4Bwr9nwVH92D1p+JAyXnjrh8m7Jm5N4iwFOXb
         jE5GcGnRn5B3kv8KpnqvOu00OYtOL97KtSbrHL4ziOopcG98W+IYkFX7OwbrvKiKIDbh
         npkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CkPH+9fR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TLoJHzQQgMMWn6gBMktz95EazKUndSsibqPH13M92cE=;
        b=nD+ID7qALMhk7v1ZfGNKBGsUVxjM4XNOGAYdg12gnSBgu+00TnZ5sgdaeSFf27Unln
         2Ed6qEzFe2s+zO4mo9dMXuIuEIoKuDNpMGTF96KahTKYLK2cknogzpShyj2mvpgHUW+7
         Win6ZbNCgI0d26apX1ZBS4sFgoNO5giH52HCq3YcbtlzsmXOjHzW6kge1ZQuxeFC9J4G
         i8Gg5N6CRtLcAFNPUxNx8S4MDeZegYK2jq1kNpYqNv3TH4RIcny8zg5BB8/FPW9LJEjd
         mwkPb97h0jKYk39q2BYCZfNEJXOUBrW4wVQVmz2UrOPx72KDf1vGrCJiJQI8a2it5PFj
         2BRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TLoJHzQQgMMWn6gBMktz95EazKUndSsibqPH13M92cE=;
        b=YCgZc+xTooadfSk6rcxE77mNMEfi7om7HIsN+5nctxMLMzEO0sJ+n7na0YT1pHWujM
         8YlzsXfaI8nN8CBqmlMPo8Af3YcP+Aei9Da2rORYwObRF0sbmWQqzYDfZt+0Cd+amYkh
         uHudsRCLk4wMOkdCddNEgK4Dt7CBMZMG1p5oG+2g+PqZh79jha+y3iayGpXOzzG7hClj
         GFAow+gkYYBroZfV3DjrtF6sePkZFkx6ijc5RzzaXvPzz3cOIABB3UZI4qNMrSrPi7UM
         GH01QiNjrMLs5mdMGS9ZUvA2FLPfQs8qSh8We0mvte/ZILXjXKVXCc/vpdwETtpOzfl8
         5q5g==
X-Gm-Message-State: AOAM530ObqyKoe40DwEnMFSLO/atbEc4jF1SkGSVXVV8ftTWn0K8FEDN
	QsUfhb39ra85XqTDj76Ujtk=
X-Google-Smtp-Source: ABdhPJxoy8keGBemIFtXIPpRmIYaBwerS4f1YwtUPQNBCBgYZTt7rkKUMV/OpGYJuCv9K9Ak1A+Ihg==
X-Received: by 2002:a25:4654:: with SMTP id t81mr8842340yba.475.1604001475537;
        Thu, 29 Oct 2020 12:57:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cf07:: with SMTP id f7ls1855790ybg.4.gmail; Thu, 29 Oct
 2020 12:57:55 -0700 (PDT)
X-Received: by 2002:a25:d451:: with SMTP id m78mr8956354ybf.293.1604001475070;
        Thu, 29 Oct 2020 12:57:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604001475; cv=none;
        d=google.com; s=arc-20160816;
        b=iK2MQ1JuHTp3aeUl48uQlJdfxEAbFdGqzIEIBu+FP+TNzqnnZhYctxmBogOQ1IwmxX
         OTvvEc5gMZJPqEQMDyxjSeV698z0uOP5DL7DWbFzxonn5BrvXq3NPHmFWatLf1hBLTzB
         ikyn0NAjMHBWoOPMHedFnik+TQBMMSw6U2lViitF3BuQXOOKwHMNctUSmcrmBMVVpJkO
         Av8qZh8wlaMmkR+ESMb3D07+W773/2ZWWBriJLqvlRc4nvtSwM6YP5jD63+E3V3f23wP
         U2C71Q8TrMsUlsLRe6WrLhpuUkqxiLVqcCOEYMsRZewBm8h/niz67lGuygocX209g/N+
         feFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hG781gazXbY/D36WgQVMDGpuA2RWLeNpJCXac5ZQkg8=;
        b=KIcx2OBWcwux9M7JX/8eqvCJ7Yod5bqmOiQkhmeL5WbgsN/sqWs0Lkr/3oCWZG2Asl
         KYw1jICwZ5aU7CmlvcGjobpRq2+nb0d+dWvv753axtx9H9/xlE/4jada3qtwbDa1NcL0
         oOtSRklZX/2D2M2lqEsyspTGjSTxE8XjmubbvYOWGjuq6yblaonsfRh7iQq4s9vQWeCG
         50TtQXJtFf33fV+INHv7XK6QKywZhQiVXLN3OmZ7DqA94ZuzyBgcRnaLwBp3EuZf6o7r
         ORwjDg6DMsQt+Fm+6/iCNCi9QXmE483+dMwcP/kaTxYPSz6b1xVV9HE9zlolZ2GbBb+i
         QUGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CkPH+9fR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id q4si272952ybk.3.2020.10.29.12.57.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:57:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r186so3258713pgr.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:57:55 -0700 (PDT)
X-Received: by 2002:a62:7695:0:b029:152:3ddd:24a3 with SMTP id
 r143-20020a6276950000b02901523ddd24a3mr5622801pfc.2.1604001474526; Thu, 29
 Oct 2020 12:57:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 20:57:43 +0100
Message-ID: <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CkPH+9fR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > KASAN to use stack instrumentation and perform validity checks for
> > stack variables.
> >
> > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > enabled.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > ---
> >  arch/arm64/kernel/sleep.S        |  2 +-
> >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> >  include/linux/kasan.h            | 10 ++++++----
> >  mm/kasan/common.c                |  2 ++
> >  4 files changed, 10 insertions(+), 6 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > index ba40d57757d6..bdadfa56b40e 100644
> > --- a/arch/arm64/kernel/sleep.S
> > +++ b/arch/arm64/kernel/sleep.S
> > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> >          */
> >         bl      cpu_do_resume
> >
> > -#ifdef CONFIG_KASAN
> > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> >         mov     x0, sp
> >         bl      kasan_unpoison_task_stack_below
> >  #endif
> > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > index c8daa92f38dc..5d3a0b8fd379 100644
> > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> >         movq    pt_regs_r14(%rax), %r14
> >         movq    pt_regs_r15(%rax), %r15
> >
> > -#ifdef CONFIG_KASAN
> > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> >         /*
> >          * The suspend path may have poisoned some areas deeper in the stack,
> >          * which we now need to unpoison.
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 3f3f541e5d5f..7be9fb9146ac 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
> >
> >  void kasan_unpoison_memory(const void *address, size_t size);
> >
> > -void kasan_unpoison_task_stack(struct task_struct *task);
> > -
> >  void kasan_alloc_pages(struct page *page, unsigned int order);
> >  void kasan_free_pages(struct page *page, unsigned int order);
> >
> > @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
> >
> >  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> >
> > -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > -
> >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> >
> > @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> >
> >  #endif /* CONFIG_KASAN */
> >
> > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>
> && defined(CONFIG_KASAN_STACK) for consistency

CONFIG_KASAN_STACK is different from other KASAN configs. It's always
defined, and its value is what controls whether stack instrumentation
is enabled.

>
> > +void kasan_unpoison_task_stack(struct task_struct *task);
> > +#else
> > +static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > +#endif
> > +
> >  #ifdef CONFIG_KASAN_GENERIC
> >
> >  void kasan_cache_shrink(struct kmem_cache *cache);
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index a880e5a547ed..a3e67d49b893 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -58,6 +58,7 @@ void kasan_disable_current(void)
> >  }
> >  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> >
> > +#if CONFIG_KASAN_STACK
>
> #ifdef CONFIG_ is the form used toughout the kernel code
>
> >  static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
> >  {
> >         void *base = task_stack_page(task);
> > @@ -84,6 +85,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
> >
> >         kasan_unpoison_memory(base, watermark - base);
> >  }
> > +#endif /* CONFIG_KASAN_STACK */
> >
> >  void kasan_alloc_pages(struct page *page, unsigned int order)
> >  {
> > --
> > 2.29.0.rc1.297.gfa9743e501-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ%40mail.gmail.com.
