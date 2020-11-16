Return-Path: <kasan-dev+bncBCMIZB7QWENRBR64ZH6QKGQE5DH7DDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A55D2B437A
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 13:19:21 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id c2sf10530106ioq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 04:19:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605529160; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0JLFW9PXwhJSxJDUeEezt7KEvD71a9UjJSUJiqwqUofKhNC/eB/lv5oUSP2qXbPTN
         vH6XCE8RQwAkXHexO3SEeoxdMzt0mlJ0VsBO1weAKolQ5/DTibwokzxN0ggoVizhIv/8
         FPP1G+sIWTAo5bXxCi5AVdUplVTYlqMa6y9Dva7dIWWvijBce4Vb/JzFC7F9IJp/3GwQ
         9/OWo2Nq6ULmwcD676iqr2tMwbafIoOHsnaTR7GiDa5JfQG4NDOLRr692ewoFYwbvBtA
         nIPTZop84CpVoIniKJLUXb6c0rbrXWi+ShSc7dSVuJkCb9JSSc/SGy8+Ucw9yFgcsQJX
         ff2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Rsp24pPd4CN92Lp5bRcqRHexNU7/zkctcsf+ZX0XxLc=;
        b=wiMuZIGVwQ2XqmRvApQUzhxDcvgZzwV1U98tsW29hihXx4Ki81msWqW4QpEfvQ+WNx
         4vRqho+rU9ortUS2hvGQtMJvKI1jYDDCv1OTgAaqED+Fb/vxATLrl/xjKJRuMvq0Su/W
         kdWkpE0VU6kW6CPa36gWILLbdqzUpvUjTGzFuJLg8u5PcKjRCu0cfd/Q8zsJmHs6Pnou
         9A9hmuT26xjQvWMmc2eVT/MUzGl1LUKPOrKvhRMT3yx3KWMi2G4ZHvu2WUQcPaq+XbY8
         5nIGEM8vr9oIIIDyj4hZQOkS5UTC0R/4Gwys+9DvbT/xnhXGi7DEhYZtUAtWHW8fvsEt
         rZ+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dwCtwSG1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rsp24pPd4CN92Lp5bRcqRHexNU7/zkctcsf+ZX0XxLc=;
        b=oFVkd/CJN5QaL5/V1pLarUeHwpv/ZoCx6LfzEY0lTpKhV/QTyy7znOXskSB41nBebl
         5mM6IDYURF+HizLuvWlSRGClSRMKFfku6dyzz5p9+I962W3zsQMC0tjHh01qbwPbeed1
         B7BNTGVztskGJwACAuYNdmO1pfcbtDcgfNLxkZCy4PD/yxZ+Z5pMrn5et3evD6/mIqwg
         P1ZA+k+pB1j8IlTEP1pnF/4XfL+pQn3DGJoL52AeTJ/xAHIwz0bxVuOmbx9xcwZGPAA8
         tgCFyteptKCF1fBjkUKAxisa/j6jUCjF8GO3lZIBHOKYvhI2WYwuIXk/jz663LOAZCnu
         PSdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rsp24pPd4CN92Lp5bRcqRHexNU7/zkctcsf+ZX0XxLc=;
        b=nIiI7dgNHvMC9CgNr/6Nikw0+u9IaHJLldg8EzQiqyrf5Gxb+zZ+V9a1px8pSeXB2T
         y+nhaMlL3RuTdA4HHsdrITp1rLHdD6B7bVhPO0WLX5NddBrRO3/dJ4IEc3y03Ibp1XvU
         1MtsvqH1FbYu7Q4GrzbW2nAOwHgi8V1WgbSIAf5weWOZt/9Uf7zpV5fbFw8A+/0GnBAS
         35/0kp5gSpxkNmGfZ+srh3pRLlD+BdQfm/j5Ixz1nIT3fNW9Htzq9dlD13UBTGbXwizE
         skLuHMGrIvoFQ4Ecfzk0hX0A1NIXpgh2hZ1sDNGv2XMYLsQ57pvdALj7GSPmib6ApeJ0
         Sykw==
X-Gm-Message-State: AOAM532vYD7l/uN9PUIDRyJCYyrAQIIJIH2YmwYo02y1Nyw/1I+MRspG
	IwKU3eLXw2E9eyk2M4X3OZU=
X-Google-Smtp-Source: ABdhPJx5ASojoTYhuIdqLUUICiWot+7h/pzkfLX9rADQzG4+87D4c1b7kqrCmb32r/Lcl1VjmMW8aQ==
X-Received: by 2002:a05:6638:44c:: with SMTP id r12mr10339872jap.122.1605529160067;
        Mon, 16 Nov 2020 04:19:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d247:: with SMTP id v7ls2990429ilg.0.gmail; Mon, 16 Nov
 2020 04:19:19 -0800 (PST)
X-Received: by 2002:a92:dc07:: with SMTP id t7mr7676485iln.189.1605529159731;
        Mon, 16 Nov 2020 04:19:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605529159; cv=none;
        d=google.com; s=arc-20160816;
        b=VxT14M5/OfPJGZ3N8fO3ZkdcH2agMnwzBIjbisH13qZN2v6IKv71gUaJ8BtAeZ2P8I
         OaHg7wDcPcyz7tUWLm4D+13vcm7XLRHIypQ11OBfwBWqm2LK9PCUA8wbhohfswVNImid
         xKkD7S1vD2f65Kjq9g6h/CBZOR/0vuuAGjKrhEwQFMn3/wZJQklEn2vafzBPRGEwMpdV
         xzhMQ5uH3tYwKAFFH2E8f6fr1hz09iBhJ8W+kK7VtI1sQm0l/68EkX6ti7yrOMO4Kix/
         T226GLKhbaihCzZjNjsQfN2KqiE1llcp3L98ZOgEy8bHRg+cKK1dBem7ZjfJ2qRPPcpG
         U/Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/kYjKHOYdbRkTjeegvgMiUR7lrALhGYE7BaLrgneuEo=;
        b=cm939xSm30E/ceZs+Ui6d5eoguhmsWJliqGqB0CraM7tULpTFA2NmicMKidQv+SPpX
         FlX4GbCYenJWe/KBj2QYH5Eay30mg4HIDfo5DBAHItG/dkYHHw24HCNTvoxe0jiIA0Xa
         y9k+aAFIe7QCWR8Vgk4Z2I7phN4+vWaLS7YiLDaUI38j+5E49Ah2s2X3DeESFvVg1aNP
         i4SbTgjYgGXSJO/870F1CL82UxL3wX+HtnNisCDdTCxny6ZXbEV54MuM38hf/Uohv+bl
         a9akLK/oloUDwaqBK1QK0T3bWGxynh6q+TQKYUAZaSvcxu32Wu+88hHpwdnCcBzr+lp9
         AjQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dwCtwSG1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id j1si1083864ilk.3.2020.11.16.04.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 04:19:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id g17so12637906qts.5
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 04:19:19 -0800 (PST)
X-Received: by 2002:aed:2744:: with SMTP id n62mr14165891qtd.67.1605529158914;
 Mon, 16 Nov 2020 04:19:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
 <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
 <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com> <X7Jthb9D5Ekq93sS@trantor>
In-Reply-To: <X7Jthb9D5Ekq93sS@trantor>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 13:19:07 +0100
Message-ID: <CACT4Y+ZubLBEiGZOVyptB4RPf=3Qr570GN+JBpSmaeEvHWQB5g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dwCtwSG1;       spf=pass
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

On Mon, Nov 16, 2020 at 1:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Nov 16, 2020 at 12:50:00PM +0100, Marco Elver wrote:
> > On Mon, 16 Nov 2020 at 11:59, Dmitry Vyukov <dvyukov@google.com> wrote:
> > > On Thu, Oct 29, 2020 at 8:57 PM 'Andrey Konovalov' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > > On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > >
> > > > > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > > > > >
> > > > > > There's a config option CONFIG_KASAN_STACK that has to be enabled for
> > > > > > KASAN to use stack instrumentation and perform validity checks for
> > > > > > stack variables.
> > > > > >
> > > > > > There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> > > > > > Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> > > > > > enabled.
> > > > > >
> > > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > > > Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> > > > > > ---
> > > > > >  arch/arm64/kernel/sleep.S        |  2 +-
> > > > > >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> > > > > >  include/linux/kasan.h            | 10 ++++++----
> > > > > >  mm/kasan/common.c                |  2 ++
> > > > > >  4 files changed, 10 insertions(+), 6 deletions(-)
> > > > > >
> > > > > > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > > > > > index ba40d57757d6..bdadfa56b40e 100644
> > > > > > --- a/arch/arm64/kernel/sleep.S
> > > > > > +++ b/arch/arm64/kernel/sleep.S
> > > > > > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> > > > > >          */
> > > > > >         bl      cpu_do_resume
> > > > > >
> > > > > > -#ifdef CONFIG_KASAN
> > > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > > >         mov     x0, sp
> > > > > >         bl      kasan_unpoison_task_stack_below
> > > > > >  #endif
> > > > > > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > > > > > index c8daa92f38dc..5d3a0b8fd379 100644
> > > > > > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > > > > > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > > > > > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> > > > > >         movq    pt_regs_r14(%rax), %r14
> > > > > >         movq    pt_regs_r15(%rax), %r15
> > > > > >
> > > > > > -#ifdef CONFIG_KASAN
> > > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > > >         /*
> > > > > >          * The suspend path may have poisoned some areas deeper in the stack,
> > > > > >          * which we now need to unpoison.
> > > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > > index 3f3f541e5d5f..7be9fb9146ac 100644
> > > > > > --- a/include/linux/kasan.h
> > > > > > +++ b/include/linux/kasan.h
> > > > > > @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
> > > > > >
> > > > > >  void kasan_unpoison_memory(const void *address, size_t size);
> > > > > >
> > > > > > -void kasan_unpoison_task_stack(struct task_struct *task);
> > > > > > -
> > > > > >  void kasan_alloc_pages(struct page *page, unsigned int order);
> > > > > >  void kasan_free_pages(struct page *page, unsigned int order);
> > > > > >
> > > > > > @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
> > > > > >
> > > > > >  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> > > > > >
> > > > > > -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > > > > > -
> > > > > >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> > > > > >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> > > > > >
> > > > > > @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > > > > >
> > > > > >  #endif /* CONFIG_KASAN */
> > > > > >
> > > > > > +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > >
> > > > > && defined(CONFIG_KASAN_STACK) for consistency
> > > >
> > > > CONFIG_KASAN_STACK is different from other KASAN configs. It's always
> > > > defined, and its value is what controls whether stack instrumentation
> > > > is enabled.
> > >
> > > Not sure why we did this instead of the following, but okay.
> > >
> > >  config KASAN_STACK
> > > -       int
> > > -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > > -       default 0
> > > +       bool
> > > +       default y if KASAN_STACK_ENABLE || CC_IS_GCC
> > > +       default n
> >
> > I wondered the same, but then looking at scripts/Makefile.kasan I
> > think it's because we directly pass it to the compiler:
> >     ...
> >     $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> >     ...
>
> Try this instead:
>
>       $(call cc-param,asan-stack=$(if $(CONFIG_KASAN_STACK),1,0)) \


We could have just 1 config instead of 2 as well.
For gcc we could do no prompt and default value y, and for clang --
prompt and default value n. I think it should do what we need.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZubLBEiGZOVyptB4RPf%3D3Qr570GN%2BJBpSmaeEvHWQB5g%40mail.gmail.com.
