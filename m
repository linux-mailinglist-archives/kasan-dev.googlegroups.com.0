Return-Path: <kasan-dev+bncBD4NDKWHQYDRB6F76L7QKGQEATK37NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ACE02F1E62
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 19:59:06 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id c72sf208532ila.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 10:59:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610391545; cv=pass;
        d=google.com; s=arc-20160816;
        b=g6sVc9iScKCDg/hbn59ENg2+lkF5HwNjDYZycwKbOaC+Z2g937/jHbZxtBiNWHLE7Y
         lgFiaLYsqk5hAk1nOshwnyce69vJRjnvQCh942AixfV60URLQ53EYYXMzRseNa/L3JQl
         egtg1sAT6jUh/JGijJmEcIj8iD1x4IAj1K56tiiKaMiZAVPHF69GUsKfZhQokW9d2+ve
         3tMnpQfCB6obEENbTK7p1FZbvNUBlxrgalVMYw8lq0WeoeTWaNN2eawqO0ZmKtOiAVQP
         zUn2iApfy8ixENCZNPKoNmYqgbcvvNE8pwwQHdJccr/ukFlK4vc1SuNmTYFlpeC9gypQ
         Pfag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=tldZgKabMkBGO0bqmpbcdRQpHjZ+051e3grCGhruzqg=;
        b=oBd40k/XPSCG5iaxLTJ84be5nFb7t6QiFbG9YVEmjP/CdGi4pP494UPQPVWuxMSLxR
         tA6xbiQ5g55U3PDyYAgOtOuZxmeeEA0skRsZuxTCv9Couy9wHhxBb8paK7S//vqGwu0Z
         fRWLEPRk13ku/gaGcRYltm4vd2dqJuUHxg8fLybPX8OLi2jCOaI5cMi0mirZ5mwzfzf/
         UA4lxykyQA3xtciC5BM/ZzwspkPlBmvisaMFIK8EX2NG8wF96ZNYI7mWgB9dmshzLuFA
         TueikMQ3IilORn/TFYbon3eHQ0b5a05L4pjW0f5c1cbEMc+qZarxxSTnVbqJfzGSvkOj
         RP1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="QTv/dYc0";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tldZgKabMkBGO0bqmpbcdRQpHjZ+051e3grCGhruzqg=;
        b=tWynbHDXWC6SW61tbt/Du+trPjeC1J/uTfu3sEIG62/PpWWwZQ5R3Mv21emD8kKmj2
         sCNBM6anklKNdOGcSeo3syyA8lBk5DoL9P/i7bzhbnGoNwNnaT/fqSgHrpfVeFxtAB8r
         1ews1UT7I2X654trbeNP/rlj9ABb3ioDAAgfnJhMkNM+rhWpBbPGPvCUyN3KD9MJgVbW
         6mTxMTjN63HLWhSi5THRVZ0QGddhQdAMV1nDAkJZpehBwDMwX3un9/Us+tp9QSwJzQB4
         uDZY1HT8NhE5Z8r5eFJc7TS9KPUv3vM0snXjRmNqYuhZqjt9nGU0dvN2wZFMHF1/eVnM
         UjIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tldZgKabMkBGO0bqmpbcdRQpHjZ+051e3grCGhruzqg=;
        b=kCZpvLqbFDVUxl6/q9CcC3Rq8/KYbfh4vJd6GkqiA2LCP6Wed6fUjfz52ETnzUAjdk
         AuSxeV4lX66uU1/nWQdvq48Dy2Z6c6HpC6mwGw5K4/z0yYj9UBoy4GLaKN5kF2bZitQ0
         gn2hyqwUhR/DQB0iMn1hWVBxQUA9sQ5FTEiBgz2nRbatIjF5KYv/n6yBWjxPxyY2h+j+
         BibcBgA1hCjXLxD9TYvcyCXxmpOPz9EzGmeGl+QFtO5mrvrxZWyBptlAg8Lwdut7o1VI
         DmSBUsmcUgHzd2AOfe3SBXsVwL0xUuCg+e6g6a3mO9ZFfqEaVXB0Lo9jKK+KFB+EblWE
         o3Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tldZgKabMkBGO0bqmpbcdRQpHjZ+051e3grCGhruzqg=;
        b=qZmGV7dGdWiBcCqBXCQE+hcpy1k1b3Gl3Xjmt+wfccNBWsx1ZvvkMGV1OE0b3qUvf1
         Pk/iV/si0wE4lN7H6K/oS+1z8v/HF0iWMbPQJ4+FjnkBr0n8xcI/6Tkbs4/Pnk1HosF4
         M3GcoLjGKR8P2D0j/QonVgOq0OuoFyXxaYRa6HBZKo6FtAOYrrBPO/BjEinsHTxDeif5
         hhB1XFNEMAdJL5UjO8iR6wrXciSKvBWOrS+ruziBrpTHw9W4Ou6VtzEaKLLCV1HNnluA
         ciIxzPhWsSkzva2cq+Vkn1rdAp6dUJZ9kx/r3twZfrn95VuE4OAiyzb8V7yj8YgX5Z+P
         8P4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mVGPXNBAgk4/aPpa9Bot4UkO+GYqWiwHMEWmDMsgSiEeFqvSi
	qaXhP3CwrQi8nqCj5Nae9G4=
X-Google-Smtp-Source: ABdhPJwm4qgSxR9VA+30Lyyf3DHV4BB1hIb+NPnZkawmoOP7fwTNvA1DUbgam6qAkmYMj8XSfJQtDA==
X-Received: by 2002:a92:d201:: with SMTP id y1mr497651ily.239.1610391545014;
        Mon, 11 Jan 2021 10:59:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:25c6:: with SMTP id d6ls150728iop.8.gmail; Mon, 11
 Jan 2021 10:59:04 -0800 (PST)
X-Received: by 2002:a6b:8b88:: with SMTP id n130mr557555iod.122.1610391544572;
        Mon, 11 Jan 2021 10:59:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610391544; cv=none;
        d=google.com; s=arc-20160816;
        b=H1IWC2VTbF/iv/1aPumcE/EKA4emO2UcNAJAY7sJZGyl3rTaVdefxJq9bcBlyFJ+P+
         GXfZxhMj5571Jl/yCdjAl244x6zzEy+1VRlGQIOkFClww45vP+0iHXHurzxm2zoKNd7/
         UD7JrM2fF7shvMuHjbygJCvj6z+2gMd2KLOP4NSTRobdgXoAHTu4WC/scgTrWAq4qwgM
         EyJKSA3PmOZcvbODD9gyE6Ns8fjPL0SBjfn1i4TWFNgmZbtJz7IfN7l0REKvrIttM/Nm
         Okk91HxyS4aRZ9RBPOxGXYaBk1PyRO2pJmiIvv11Y9j0fzgXWPAUmjybN5shJR0XX5Sm
         Av4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NHAKhb75s2fP4VkAw0VIGRYTr0gRRezE8oxv1qzuvrE=;
        b=QL08Bgze0seNXmI37Rm75ktV/Oqw3lyoQn92azg5whxGZ1fTLn9xTyvbA1PL24yhb5
         tOhzZg8LzNE0LpbodUl5KQnb5X4+mNRfeJot9kFJfPlYLinbLC+GCudXkx6UsjDzLyYG
         4WdR952NR32w0Dkt+9RqkWH0daIlIsBfeuKvXleXaKvCzk0rWBdLnjtRU5gnUymBjJBq
         gBF1BRl/a1Vck0iKHTrR2S95Gleh3bcO8M/PgW5aL65JEoh2SEMS1WO0J/g7cJhWBk7r
         62GlzkyeQj9gOmbJCA9xCqu54sza1iTTH42gzo866O2GEI2Cl8Kx3NccSGi+FpumICif
         6fYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="QTv/dYc0";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id p16si55543iln.2.2021.01.11.10.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 10:59:04 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id 22so455033qkf.9
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 10:59:04 -0800 (PST)
X-Received: by 2002:a37:9d84:: with SMTP id g126mr794137qke.262.1610391544127;
        Mon, 11 Jan 2021 10:59:04 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id a21sm385628qkb.124.2021.01.11.10.59.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Jan 2021 10:59:03 -0800 (PST)
Date: Mon, 11 Jan 2021 11:59:02 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v3] kasan: remove redundant config option
Message-ID: <20210111185902.GA2112090@ubuntu-m3-large-x86>
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
 <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="QTv/dYc0";       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jan 11, 2021 at 06:49:37PM +0100, Andrey Konovalov wrote:
> On Fri, Jan 8, 2021 at 5:09 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN stack
> > instrumentation, but we should only need one config, so that we remove
> > CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable. see [1].
> >
> > When enable KASAN stack instrumentation, then for gcc we could do
> > no prompt and default value y, and for clang prompt and default
> > value n.
> >
> > [1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Nathan Chancellor <natechancellor@gmail.com>
> > ---
> >
> > v2: make commit log to be more readable.
> > v3: remain CONFIG_KASAN_STACK_ENABLE setting
> >     fix the pre-processors syntax
> >
> > ---
> >  arch/arm64/kernel/sleep.S        |  2 +-
> >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> >  include/linux/kasan.h            |  2 +-
> >  lib/Kconfig.kasan                |  8 ++------
> >  mm/kasan/common.c                |  2 +-
> >  mm/kasan/kasan.h                 |  2 +-
> >  mm/kasan/report_generic.c        |  2 +-
> >  scripts/Makefile.kasan           | 10 ++++++++--
> >  8 files changed, 16 insertions(+), 14 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > index 6bdef7362c0e..7c44ede122a9 100644
> > --- a/arch/arm64/kernel/sleep.S
> > +++ b/arch/arm64/kernel/sleep.S
> > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> >          */
> >         bl      cpu_do_resume
> >
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >         mov     x0, sp
> >         bl      kasan_unpoison_task_stack_below
> >  #endif
> > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > index 5d3a0b8fd379..c7f412f4e07d 100644
> > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> >         movq    pt_regs_r14(%rax), %r14
> >         movq    pt_regs_r15(%rax), %r15
> >
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >         /*
> >          * The suspend path may have poisoned some areas deeper in the stack,
> >          * which we now need to unpoison.
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 5e0655fb2a6f..35d1e9b2cbfa 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -302,7 +302,7 @@ static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >
> >  #endif /* CONFIG_KASAN */
> >
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  void kasan_unpoison_task_stack(struct task_struct *task);
> >  #else
> >  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index f5fa4ba126bf..fde82ec85f8f 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -138,9 +138,10 @@ config KASAN_INLINE
> >
> >  endchoice
> >
> > -config KASAN_STACK_ENABLE
> > +config KASAN_STACK
> >         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> 
> Does this syntax mean that KASAN_STACK is only present for
> CC_IS_CLANG? Or that it can only be disabled for CC_IS_CLANG?

It means that the option can only be disabled for clang.

> Anyway, I think it's better to 1. allow to control KASAN_STACK
> regardless of the compiler (as it was possible before), and 2. avoid

It has never been possible to control KASAN_STACK for GCC because of the
bool ... if ... syntax. This patch does not change that logic. Making it
possible to control KASAN_STACK with GCC seems fine but that is going to
be a new change that would probably be suited for a new patch on top of
this one.

> this "bool ... if ..." syntax as it's confusing.
> 
> >         depends on KASAN_GENERIC || KASAN_SW_TAGS
> > +       default y if CC_IS_GCC
> >         help
> >           The LLVM stack address sanitizer has a know problem that
> >           causes excessive stack usage in a lot of functions, see
> > @@ -154,11 +155,6 @@ config KASAN_STACK_ENABLE
> >           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
> >           to use and enabled by default.
> >
> > -config KASAN_STACK
> > -       int
> > -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > -       default 0
> > -
> >  config KASAN_SW_TAGS_IDENTIFY
> >         bool "Enable memory corruption identification"
> >         depends on KASAN_SW_TAGS
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 38ba2aecd8f4..bf8b073eed62 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
> >         unpoison_range(address, size);
> >  }
> >
> > -#if CONFIG_KASAN_STACK
> > +#ifdef CONFIG_KASAN_STACK
> >  /* Unpoison the entire stack for a task. */
> >  void kasan_unpoison_task_stack(struct task_struct *task)
> >  {
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index cc4d9e1d49b1..bdfdb1cff653 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -224,7 +224,7 @@ void *find_first_bad_addr(void *addr, size_t size);
> >  const char *get_bug_type(struct kasan_access_info *info);
> >  void metadata_fetch_row(char *buffer, void *row);
> >
> > -#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
> >  void print_address_stack_frame(const void *addr);
> >  #else
> >  static inline void print_address_stack_frame(const void *addr) { }
> > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > index 8a9c889872da..4e16518d9877 100644
> > --- a/mm/kasan/report_generic.c
> > +++ b/mm/kasan/report_generic.c
> > @@ -128,7 +128,7 @@ void metadata_fetch_row(char *buffer, void *row)
> >         memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> >  }
> >
> > -#if CONFIG_KASAN_STACK
> > +#ifdef CONFIG_KASAN_STACK
> >  static bool __must_check tokenize_frame_descr(const char **frame_descr,
> >                                               char *token, size_t max_tok_len,
> >                                               unsigned long *value)
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index 1e000cc2e7b4..abf231d209b1 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -2,6 +2,12 @@
> >  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> >  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> >
> > +ifdef CONFIG_KASAN_STACK
> > +       stack_enable := 1
> > +else
> > +       stack_enable := 0
> > +endif
> > +
> >  ifdef CONFIG_KASAN_GENERIC
> >
> >  ifdef CONFIG_KASAN_INLINE
> > @@ -27,7 +33,7 @@ else
> >         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
> >          $(call cc-param,asan-globals=1) \
> >          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> > -        $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> > +        $(call cc-param,asan-stack=$(stack_enable)) \
> >          $(call cc-param,asan-instrument-allocas=1)
> >  endif
> >
> > @@ -42,7 +48,7 @@ else
> >  endif
> >
> >  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> > -               -mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> > +               -mllvm -hwasan-instrument-stack=$(stack_enable) \
> >                 -mllvm -hwasan-use-short-granules=0 \
> >                 $(instrumentation_flags)
> >
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210108040940.1138-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210111185902.GA2112090%40ubuntu-m3-large-x86.
