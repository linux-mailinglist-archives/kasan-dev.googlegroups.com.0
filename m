Return-Path: <kasan-dev+bncBDDL3KWR4EBRBC63ZH6QKGQEPZWNUOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3552E2B436B
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 13:16:13 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id v2sf5978700pfi.11
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 04:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605528972; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUi53k9ojg7Vd3P7MiV+ntzoIzQmaqZqoQQjCh8DT8SPgBNbt72H0RJTSRYRBw+Rxx
         QowEEhnHrVj3HQIKCIAm4Meo4jBlEdpzLP0Jy2ARk8MBSdtIYgZz63xGwJw4P/zxUu0H
         ZZ19dzeiu5kxJjU6wteu6DL1dPcpqtUZBAF3lwJFQavzamB4UdhuHaUgjWwrEj/dOb0c
         gXu/ZxqxdD+MgMSB8KVxGJg0GShelZZPMSmcRJfI986uQo3Y1q2D4V79PzJvgXypEx9u
         FjOZGz4t/+Irf/z4uRkja3QxUCYixf/5zDFgqBi9+j5pWUckjku+9UAxjINh+JRMwfSA
         N9cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VWLCrJpivXPHvv2PMxptGm+qh8MevJwr8T7Ye381ob0=;
        b=uJK7QXkPMFoia0d+vNkEgHGDIjiFI/dFCmRR+/6v8i2/AA/aqfscaGAn4gV3pmswS6
         e/16jMD5jQ5HeXvN1xTmVH7XLsk4P+yTBsng3ssfQW9+MQQ3MfolQIkU6MJnVpbpuek5
         9IUZnAdHEHGaWjd12X7NZDjmdcHta5NTMO10jk9vym7GG79YZUZ7uZjmxA9KTuXmhMI/
         K0vMq38SRYIzr+MzbdpvoPW9k8ZdaJVthuG/JFInhEBqpBljUdrqsJJqaNq95BAATLFf
         +B5WvIp/R/jJWfpRpDhR7exCM/lihH74dVGUMECBTd24LrRZVod6FXLe7gcS0c2FZM4w
         bkjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VWLCrJpivXPHvv2PMxptGm+qh8MevJwr8T7Ye381ob0=;
        b=TnVparyqB+0BEmyDVSFKQIayKhCO1EfA4g3Fye9o48MLkEeLRqGSGVleD0i1F2+YPM
         CiBbwp+yKr50JGMuDKraqanY0YxfgBRy5bXUtjDnB+EEExLUFjFzApBBwkYzDbF3/q81
         yR7+pqsaOGoMxwCOCGC/LQ6PRIjZxWofuZOi+nqJuQ87zbFD9iLjHt1qHfyXKvW0ODSi
         a+a+lpQrF9iX3vjFsduH6XX7qbItRR9JBfYpzeQ6ob8nUFjYw1dB6mPnBfGx41Sxwc+i
         thZdkRYxigcxOuOnwRmEeyjRcBE9rvhC/HYjZb+f9wgC3dHL7U+soavZeTsdfJTuGoUf
         3iUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VWLCrJpivXPHvv2PMxptGm+qh8MevJwr8T7Ye381ob0=;
        b=c05J0VRl+M871GUIkLrJnSHERN9+xUhRZT4fLd91Cu61V1frLI2e0EVEuOvQIkhrKv
         1Dpa7WV0Fc7RwzIu1H3JvfotY4TUmC07F84vpVZ1UFVc1rQ2KREfQS1rW59cNSHorRxM
         wY2vtBtw8cOIp5uY3drMRr7Oi10I0t2ZD6EuzrWdjvkd/zK1XyPkAqtfnWaGBDZz3Rb2
         I6e6FZLWFOg6T2/P7YGZKhgnhMPhonwtgRyCxkAW328rbeY8aYmBk3Q5+Z9lF1gBjIXP
         zN/3AHrumPQL3D8yOzFQ+amdKCs40dBTN0Cef+uBmpE1hbANj4dM3ThQHmsnCpRPcoyj
         lFiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YJFvxR5kEJTVIvSy58QR5U/Yho1sE+XK5G7mz4d3sa96z2Igo
	WTNqEPPJYJhfLr+pDWldnaQ=
X-Google-Smtp-Source: ABdhPJxlgWPbTsbnFsEv4d25Jfkg1mriuiXchnkpf0yEs5atXX+o5GOXkp30MZeb6de23QY+xv3e1g==
X-Received: by 2002:a17:90a:9dc2:: with SMTP id x2mr15849472pjv.98.1605528971945;
        Mon, 16 Nov 2020 04:16:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a0e:: with SMTP id o14ls7521619pjo.1.canary-gmail;
 Mon, 16 Nov 2020 04:16:11 -0800 (PST)
X-Received: by 2002:a17:90a:7d18:: with SMTP id g24mr9650013pjl.154.1605528971342;
        Mon, 16 Nov 2020 04:16:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605528971; cv=none;
        d=google.com; s=arc-20160816;
        b=PZxG3yQgqbgkRasrWDpYgKNfRhCkk+VmKKixJr6qadvYaFa6QPy5Nvp23lnjYrQjGk
         uzfJYbc5fGGl2gpA6pN0l9QzSOr6sjyoEHvL76Ugk+QOlOFgr/5+SLZl+m4xLTLwz/rK
         pQpoC7jvg8fwqOkfkU1uO5Fi9OtB55zmwGYYB0MCVhrxYEzRjh+xjgpgyYb/dLnF+xXO
         8famouHiDGZBAcpx5tLt9IeFeZ5HF7YHMY2Sw159wS2k0SocuHxHTqvuzJCOj3VL8XAe
         ZZKsGC+K+fq6TbroPMtOc7TAHnKFlZOulqzlVDnEjTwhnWzBJ+beLypJmS6A911evGxU
         F2LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=a8P04R/p5P5moo+j9fZbYy/m1eKpS78ksvd1pNF8fOs=;
        b=ocpfgapJ1z4PY9l0XoOsEiYsJdzZlfPVBSemeADd+RtJQ6KT8AR9tGraiMcVCoCITG
         05vdewk+eo6rD6cS4dfSAB1pgFApLr4KBQZNOLFfqyIr0PQVWUBuhX2e/W/3QoSaiIAx
         Z4ryBxk8Qu8kXd+Zs2Z+h7sj0O/UM5StyhfLd/3HM343hM5mwmviy+aZ2GMgNJnhacJW
         HtkOThlHHA4vQLcmBMgPQSDFf47AQTH+ODyNvhIn5+yux3HkanMYpUrBP6dhKoQdz4aL
         3uLVxxF+hLSQn16RZ679h0hyeiSSvpIhkOAjgkOOVT6ixthkrAPwNIUFQRqvbb6Bd+d9
         0YBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bi5si947280plb.2.2020.11.16.04.16.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 04:16:11 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from trantor (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A17A622263;
	Mon, 16 Nov 2020 12:16:07 +0000 (UTC)
Date: Mon, 16 Nov 2020 12:16:05 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Kostya Serebryany <kcc@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Serban Constantinescu <serbanc@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with
 CONFIG_KASAN_STACK
Message-ID: <X7Jthb9D5Ekq93sS@trantor>
References: <cover.1603372719.git.andreyknvl@google.com>
 <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
 <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
 <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Nov 16, 2020 at 12:50:00PM +0100, Marco Elver wrote:
> On Mon, 16 Nov 2020 at 11:59, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Thu, Oct 29, 2020 at 8:57 PM 'Andrey Konovalov' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > > On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > > > >
> > > > > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > > > > KASAN to use stack instrumentation and perform validity checks for
> > > > > stack variables.
> > > > >
> > > > > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > > > > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > > > > enabled.
> > > > >
> > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > > > > ---
> > > > >  arch/arm64/kernel/sleep.S        |  2 +-
> > > > >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> > > > >  include/linux/kasan.h            | 10 ++++++----
> > > > >  mm/kasan/common.c                |  2 ++
> > > > >  4 files changed, 10 insertions(+), 6 deletions(-)
> > > > >
> > > > > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > > > > index ba40d57757d6..bdadfa56b40e 100644
> > > > > --- a/arch/arm64/kernel/sleep.S
> > > > > +++ b/arch/arm64/kernel/sleep.S
> > > > > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> > > > >          */
> > > > >         bl      cpu_do_resume
> > > > >
> > > > > -#ifdef CONFIG_KASAN
> > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > >         mov     x0, sp
> > > > >         bl      kasan_unpoison_task_stack_below
> > > > >  #endif
> > > > > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > > > > index c8daa92f38dc..5d3a0b8fd379 100644
> > > > > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > > > > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > > > > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> > > > >         movq    pt_regs_r14(%rax), %r14
> > > > >         movq    pt_regs_r15(%rax), %r15
> > > > >
> > > > > -#ifdef CONFIG_KASAN
> > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > >         /*
> > > > >          * The suspend path may have poisoned some areas deeper in the stack,
> > > > >          * which we now need to unpoison.
> > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > index 3f3f541e5d5f..7be9fb9146ac 100644
> > > > > --- a/include/linux/kasan.h
> > > > > +++ b/include/linux/kasan.h
> > > > > @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
> > > > >
> > > > >  void kasan_unpoison_memory(const void *address, size_t size);
> > > > >
> > > > > -void kasan_unpoison_task_stack(struct task_struct *task);
> > > > > -
> > > > >  void kasan_alloc_pages(struct page *page, unsigned int order);
> > > > >  void kasan_free_pages(struct page *page, unsigned int order);
> > > > >
> > > > > @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
> > > > >
> > > > >  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> > > > >
> > > > > -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > > > > -
> > > > >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> > > > >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > > > >
> > > > > @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > > > >
> > > > >  #endif /* CONFIG_KASAN */
> > > > >
> > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > >
> > > > && defined(CONFIG_KASAN_STACK) for consistency
> > >
> > > CONFIG_KASAN_STACK is different from other KASAN configs. It's always
> > > defined, and its value is what controls whether stack instrumentation
> > > is enabled.
> >
> > Not sure why we did this instead of the following, but okay.
> >
> >  config KASAN_STACK
> > -       int
> > -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > -       default 0
> > +       bool
> > +       default y if KASAN_STACK_ENABLE || CC_IS_GCC
> > +       default n
> 
> I wondered the same, but then looking at scripts/Makefile.kasan I
> think it's because we directly pass it to the compiler:
>     ...
>     $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
>     ...

Try this instead:

      $(call cc-param,asan-stack=$(if $(CONFIG_KASAN_STACK),1,0)) \

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X7Jthb9D5Ekq93sS%40trantor.
