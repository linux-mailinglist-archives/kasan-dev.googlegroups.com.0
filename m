Return-Path: <kasan-dev+bncBCMIZB7QWENRB5FM4D6AKGQE37MOTXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4162829AC6B
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:45:41 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id v17sf552428vke.10
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:45:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802740; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzOri6QzsV+rNGWMOZVIOUN9QTnmstqBULQ380LLY2RtFD1bCraaoMFLjeHsKbR4rX
         d/9yHIOUFuKGS3tKnkgwA33h1PKRpJ9S0nNqDkuF+498o7PpTqvi2ZdNU9S5y83DCkMU
         nCTjTG5bIetA5b3+EBIN+SNoTReHPLHW+j5ctCj6yoyR3NYym1LIS9e1NSWiXgtWzEqQ
         H3Cttp2AQxZcRnDu1KAEjxIsu7/6DADYv0dzGHpjug7HYII+LIRFwLWarftG4Aeb327E
         zh4/PV9/BGsY7/lPuQZs7cuAivNpQFg/jQJfct+Kwy/yLdIHc0j6wTzUeAz+5drrImo5
         lYOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jqWMpYF6o8FIDo4lohtz4GZvx9VfdLGAGb2LhaZdg94=;
        b=vIDGIqklZosxiiAb1mrt3p1WA1KuArM3R9eFMFciniZe6oFU55srFImt9mL19Xav8X
         6ZJQ7xpTbQq+qv4A6uh5diJe2WmSTDpXm/L8KCsSfy/f1uB87kdoeTyCckhLf6C/Gusk
         tcEy4WGiBN8KDaIhK2zUMv/f7ECFyQeJ0M/cxLm/1UcVDWpuHByxBe4U2CinKbcFsbni
         ya16Coa3Vy3XqtnVs/lZr9WbU2qDPNSIgYtBZ305eLM9dqgIiPaJ8UhfQ3tzm1Fl/Ugp
         y4kMyiSnBKWC8C41auKtAAxgaAFRZfZOkC9lyI9YWCHoIX6EgDSGLS5rVw3YxG8tX+5+
         P6+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QuhHjliQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jqWMpYF6o8FIDo4lohtz4GZvx9VfdLGAGb2LhaZdg94=;
        b=AzaBKoAygNymzWC8Pc4NM9qc4m2WfjPfXPoFlHe0QYxrOdYqyED8WnNUuGC28R+bDd
         EWUvfr9RDlATD69Cy4Y44u6ODo/XaBmObzJo7wL3m5EKVCdfEFVMWijkxuRHeZPAUa1+
         DPC+7Wt94Ws4nEIlAk6U1bP0C/Lg6fWlfjoKiFO+Lf3n2uzDKpkO3cTqc9YrUUk5ltT+
         pAdI949AJDNt3fRv2Kf4Ihx9WhnDP/TNnPTeqb6+R1Jk+/5kD0GtU/mL6645CQeJFlET
         qSROy7OCO/3EwrBb4AF+bWL3b+EPHhIRFUXOWB5AFFrHdarv7Tvyg67zqJ5gl/P0ugFR
         jYMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jqWMpYF6o8FIDo4lohtz4GZvx9VfdLGAGb2LhaZdg94=;
        b=khRHams4r+dYez2gplZPS7i/gJ+mjr7cglWUUlGGyMHSBcS0tot0ESJ1ygF8EGMT3T
         GaaLf4vs9M4P/Z0wiTm9dVGD0oAeOqq0HMd9S/52Betau6ZjR46YcIA+s+YnkWGVGiJM
         BzooLnB0LkeKyeLY8epfBth4OUwR+lZE1fzxiRhbV+H3aSr9fe9r64DFFGnXexHb6tkN
         6HVBwZJDa2UlHw1TjItu2fG+3cTZig/qfYZW96wiUaV4kO/dPVD9asFuoKAJQRzkzZlL
         hEVhbECcjXTMAqDzmx6nwjSqirdd6TmROkFSYMmPPlftaCeVhNlcV8lsjFp5SHpwA4Se
         5W1w==
X-Gm-Message-State: AOAM531O82wn9ryepnLCMm2HjOCYs8mGFRDi6mWMPt+AMmx2WyE+pX+A
	K4H6TV9XwCvPDfhGNujVUOY=
X-Google-Smtp-Source: ABdhPJxF3z/2feFKoWgxs+Y4UiYSWpFHnVP4JMmAqttDvnqpbhQXO1rIYG9ECZFlGENDpjXxPuM+OA==
X-Received: by 2002:a67:ef5a:: with SMTP id k26mr1019430vsr.27.1603802740347;
        Tue, 27 Oct 2020 05:45:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e29a:: with SMTP id g26ls145677vsf.6.gmail; Tue, 27 Oct
 2020 05:45:39 -0700 (PDT)
X-Received: by 2002:a67:cb17:: with SMTP id b23mr1211558vsl.22.1603802737864;
        Tue, 27 Oct 2020 05:45:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802737; cv=none;
        d=google.com; s=arc-20160816;
        b=Rqd1NBzwjTWUCzyAlGyR/r5TLktIjm1tyTTB/slwF8EfwsOjQ5X4fAdFIldpNRLoGg
         i6clOOseNITpF4cvg0/qIAcnNBNnH+RwE1V38pyMA9xkS0fpYAdlyksl04kpDtxjtNmy
         52ByfcJsHki9Jg5fatnyT6im5xGvtcriHIAokYJkcQicGXHIvEC35EoU46TBqLrhvY4E
         03el79CPXbsxMTYVNHBW+Zw2I4s46pOkD1177yaNTIad6CqokGCntXEYhjbWrZtSmYmm
         o2hFj31Kx/+B4MkYIoq7kEQq/kEF0/ufhQ1fn6pgb5Ybm1eKRJYtkY+haotWmvNteI/h
         yOvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KC5kbhX2B/WcBTAKVbARUxq55uts8rGyp+acLwUDFR4=;
        b=JkkSHQy7zFtD+f0aIwMnMR6eEReXKFuiO09+y8AvHZLK79Tf0JrT5u5NnlrpJ2DJzr
         w3x/j7+cNUZH9ZmD7qs+CjH3Tqn4TwfU9AQ4TDZqgCx4OVMPruB/A4kQMt6/XFMGqT2h
         FtlH1KW/ZGggmpBHEPT0bAJqkQKydFysVAoGQG9057ficD9LTq8vWpjElayhsZnMfSEp
         VywtPAJsJTWUePBowDEkFsoI1ka+4pD3F1dsVzNPwpfbjsZiHHAe6r248YTOt8YLRCN5
         1nNgHPwsxTtxSnQv4QvFdlAKxdAP8ZCb1//gdCiwOaxsS1lbQSXpfY+AppFgK8OimC1y
         Q+dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QuhHjliQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id e7si91326vko.4.2020.10.27.05.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:45:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id p45so649826qtb.5
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:45:37 -0700 (PDT)
X-Received: by 2002:ac8:44b1:: with SMTP id a17mr1901995qto.43.1603802737168;
 Tue, 27 Oct 2020 05:45:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:45:25 +0100
Message-ID: <CACT4Y+avTTkH-y4gVd=X0KqhugzTqrGVx9+Z06cYA2kF+HvffA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Andrey Konovalov <andreyknvl@google.com>
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QuhHjliQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

And similarly here

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

and here

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BavTTkH-y4gVd%3DX0KqhugzTqrGVx9%2BZ06cYA2kF%2BHvffA%40mail.gmail.com.
