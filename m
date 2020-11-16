Return-Path: <kasan-dev+bncBCMIZB7QWENRBHNXZH6QKGQEMH34FAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B82F2B41C7
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 11:59:42 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id u3sf10570829pfm.22
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 02:59:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605524381; cv=pass;
        d=google.com; s=arc-20160816;
        b=vg1lI87Nboaq6dzWP69BmrJzGIrJVNVujEPtz4N6Qoy5M2cg750Haky59iyw4S66CD
         FeLHIW0rDCtb3rTnqBB3E5PaAfsZ8PpOV0KDJeyGq2qF+SWzqR6KWVAnUu4s1Y9MCWqD
         oqEQMPOSsgxPQgTOaCXYzPWrJVUnH/4/sYSO3NM4Qpvf2F5+DZHaRvOra4nMXAol+Ggc
         tyVh1nNyDJhz4B9/WG9et08c+mKCxThe2SZDZjGLz9yg/U9kipyrzTj4GbeQLNeDwCH3
         OIWchJ3p0tBJO1OaksF+OCSBkd9t10mSzq4WtVhi1u6B7fsS+17ozFU50CqAnKVW+iZ0
         Erfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sJHNzeBw17TengO0tZBR2IY3wMDCzHREGj1dRVw67hA=;
        b=waUym0S727wTy1v8u2QGRKt+8hBWjR8YeweqrpjS1NhfXHa9Lid7fP9ddS55pSaZK5
         FRVKfjImFkCTxUHFUWOtxmm4vyHimCU6eJ9JLTGPydq6vTam+/+hIj5cHAH0G51yZnTp
         RuVApmeCxlZTppZNIncZrGnXsPXwcOxcqJkCa+AjFfanFZIWn/9aEkg8XntGvFvVE5FW
         TrCjrnISuH54yKXqwHM7K4y4mm8kS+r8D0BRGXSt0gCk3M2fe9d5fpjaiE3wumm00YDa
         AfJy/H1Rt3p4Evx67jJlnY0fch0BeCepl2FqbpTZq4LlsPFKI9Y/WjfuNYob2I3t+YMg
         awQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gZ4lBG2f;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJHNzeBw17TengO0tZBR2IY3wMDCzHREGj1dRVw67hA=;
        b=owOQo/zTkyIYbj5gaOoAGGxB6AzVVCGJMFxLcATry3L66lvkZSi/Tc+rexaztwmK7l
         v2JwY6VlBb/fUiR8zLO5wSKBrnB7xg/BfZE+mzIzmqlQrWjjuXiA/oL7tXKrUzwPHXJb
         +yrONat9J9lt6h55+RVofhEgw47SEqstmRiHdhf/kqfX5ThDSZxQurPayx1BR1h0PIPE
         0AldouheWpIReT8RA0snGakeV/e/upjuVnbggT/CE9toeCpSjH6S5nSpsMnsB1nvSu/6
         cnxlhZORvYe4GFptpUNlXzRcblXxnv+twukaalbfG7DAH5f4DGHz3zQ2wPn3TfwyqjFI
         QK9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJHNzeBw17TengO0tZBR2IY3wMDCzHREGj1dRVw67hA=;
        b=pNewdw1zcZUpUBmjz+nEkXI0VClNnWOOG6K+rQDeqPPqKWGQM9JUgF/SinjLJFVKPP
         XoiHOfGckx3I03U/aKQ9mzsPQc5z7PK80JToYM5+sxFU0WV97Ir2/KB98ou2+mxcp22O
         ulRVT1NJbZk3+xSj7yMgyGfGdIOvk3FPu13ji7wcTPpyCll6vfyStJqm6Zo1VCx1HWE7
         PSd/EuOtMIbrl4WxESBibwC9DRQftRckSOjHQeWJWplTCEMvaT2SAhb4YLepmPX9M2jP
         vE2bqo3cs5uUqrYNCBllmTaRRhVgwZwpVKQpySbJ+DQkZcQtXsTGQcp8DzIgKl+qXEAp
         VRYg==
X-Gm-Message-State: AOAM532AKCsdyPM5FMp9400d1SUiiQR3ZJg4BzSUKniE8qFqeM6HlrMF
	qwpSmOJuTGazV1mvGgg571U=
X-Google-Smtp-Source: ABdhPJxJXg4E1gXUJAeeV4QVygW1/9fX801Snu6yw1zKIoVu0fAXYf3dUmOrVqqIc4VQimuPfO09ng==
X-Received: by 2002:a17:90a:4281:: with SMTP id p1mr15963189pjg.87.1605524381289;
        Mon, 16 Nov 2020 02:59:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls7414650pjx.2.canary-gmail;
 Mon, 16 Nov 2020 02:59:40 -0800 (PST)
X-Received: by 2002:a17:902:74c2:b029:d7:cce5:1813 with SMTP id f2-20020a17090274c2b02900d7cce51813mr12226665plt.50.1605524380762;
        Mon, 16 Nov 2020 02:59:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605524380; cv=none;
        d=google.com; s=arc-20160816;
        b=ETgGvberRA8xf0es0i1ofXQEynKsBflLCvv+luuYXo+EBPZ49rChrz9AH+hZ9jWs/f
         SVNwES5YymNIbVdL70rPhvRuxh28TuZsqUQ3LNP/shnHmjybbwJP7heFgH7UMHmLPgVX
         /IBftN5HMNuePR92Qfb/LicRKktwmDs/RYbDUq4u9/ZtVV8fqAdSfUiSNhy6IHSfiJAP
         fH436Uc4AKXOwNnjR+RWLQ0B5hkRS4t3gPvvawV6hGRV7KndlYJAPrCCOSgaBRx+blD8
         udOU5ZT7psrifmqKCMGWxfjxFJ4GozZJm3BhDL0tjKvv808CiobANYUaVJ9oq/g8rlcC
         Mq7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w2fKHHmUBTp3QBPbH39v+ua/WX4NZLnRZytlRMmRIjc=;
        b=bdMJw4+IrViQBlNH1Ux5DK6+4hpcL+HE4Z/ltspw3a5rq/ybrN/cWsawutEV/fdAjA
         GBtnpw/8x6sb4aGs5TJv9nLxSPrw6NlBUUF8KS6jmbmh2r8ArVyDUX1abGfmYeWfntXC
         iqepIN7/cvXLn537ZOfNPKiaoKUPOaSF8I74tqwrhh8zcQ42tCSl308LLajqvzEw1AUv
         zqxLH8OipNF4oCSIwOE+L6H08mYlZJvTj6VCKYPnW2PIS7d5EkifB+3Qqf+e2/WqVm1M
         vK5cpXGZ9BGfMh4AhWrctaGbrFMqUpc4Tti+kUR7gA64xH/GlODDbiMXGqNcwckLrhK/
         tYcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gZ4lBG2f;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id d12si179803pgq.2.2020.11.16.02.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 02:59:40 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id p12so12517969qtp.7
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 02:59:40 -0800 (PST)
X-Received: by 2002:ac8:c04:: with SMTP id k4mr14023201qti.66.1605524379709;
 Mon, 16 Nov 2020 02:59:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com> <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
In-Reply-To: <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 11:59:28 +0100
Message-ID: <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=gZ4lBG2f;       spf=pass
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

On Thu, Oct 29, 2020 at 8:57 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > > KASAN to use stack instrumentation and perform validity checks for
> > > stack variables.
> > >
> > > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > > enabled.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > > ---
> > >  arch/arm64/kernel/sleep.S        |  2 +-
> > >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> > >  include/linux/kasan.h            | 10 ++++++----
> > >  mm/kasan/common.c                |  2 ++
> > >  4 files changed, 10 insertions(+), 6 deletions(-)
> > >
> > > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > > index ba40d57757d6..bdadfa56b40e 100644
> > > --- a/arch/arm64/kernel/sleep.S
> > > +++ b/arch/arm64/kernel/sleep.S
> > > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> > >          */
> > >         bl      cpu_do_resume
> > >
> > > -#ifdef CONFIG_KASAN
> > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > >         mov     x0, sp
> > >         bl      kasan_unpoison_task_stack_below
> > >  #endif
> > > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > > index c8daa92f38dc..5d3a0b8fd379 100644
> > > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> > >         movq    pt_regs_r14(%rax), %r14
> > >         movq    pt_regs_r15(%rax), %r15
> > >
> > > -#ifdef CONFIG_KASAN
> > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > >         /*
> > >          * The suspend path may have poisoned some areas deeper in the stack,
> > >          * which we now need to unpoison.
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index 3f3f541e5d5f..7be9fb9146ac 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
> > >
> > >  void kasan_unpoison_memory(const void *address, size_t size);
> > >
> > > -void kasan_unpoison_task_stack(struct task_struct *task);
> > > -
> > >  void kasan_alloc_pages(struct page *page, unsigned int order);
> > >  void kasan_free_pages(struct page *page, unsigned int order);
> > >
> > > @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
> > >
> > >  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> > >
> > > -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > > -
> > >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> > >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > >
> > > @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > >
> > >  #endif /* CONFIG_KASAN */
> > >
> > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> >
> > && defined(CONFIG_KASAN_STACK) for consistency
>
> CONFIG_KASAN_STACK is different from other KASAN configs. It's always
> defined, and its value is what controls whether stack instrumentation
> is enabled.

Not sure why we did this instead of the following, but okay.

 config KASAN_STACK
-       int
-       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
-       default 0
+       bool
+       default y if KASAN_STACK_ENABLE || CC_IS_GCC
+       default n

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g%40mail.gmail.com.
