Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCWZWOGAMGQEEH2WXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id EC41C44D4D1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 11:12:27 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id r15-20020a6b600f000000b005dde03edc0csf3783224iog.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 02:12:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636625546; cv=pass;
        d=google.com; s=arc-20160816;
        b=IcCLFmkjQl4slZ/WmTZYKKag6InV59aPtFYrr2yqrwjvwX97CKwXFWYhXE4dI4Wa1i
         zoVJeRUxsbyNFU7+bo1sRDwCLonXP4o9dS/tF8cR00T8QyFMsRne7ZM/hsDxeTE/Q1GA
         g6bK85JmpDHLLZYVo7bovHPiyB5u7HnkfQglKoPK68gaAeiYF5KUJ5kkcXH6/40CwBLr
         W5OxbqNJgqa2HE+iSzVdYRlERcjKasaKZ3pyb+aZTsSWSmKzLnWSmuL56eYSAdH24js2
         38Qqw6UUisH/yzs/eyphgPo1A3ol0kE3FuVqS+mlPQkgGpTQRxZYtE1CeQaX7NUCaAJq
         ba2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ut59vK31vL4Irkn1TQRHpJ/COndUJNCxvY64H3DpCcs=;
        b=mgT76xQ+wgQlEgZtxU40Rx3wBGOx8GMs1PRGgp6gbjKpjNRQYuvC7rU/8nwDni9YWS
         I0kvNTi96A7MPr8ZPxbt5ooaJPgL1kBkFF9ciF28l/CxbI6RG1JE0JYDoU1RutsEWX5I
         HGdnR2dmRb7QYpQzG6sGHu9FAgffWxmSuJs8XsDYFsRlO42T4xoHDmzCWGS5RPgEOMCt
         Ik5icqJOEaui8g15UbY4ptpLDw0KLL2mK94KKL+sSEcVfROTGyj6+TVq7yafSeMlO9I9
         6CMApddxWv88kLqPjkY8JNiWXCwCcVQne9uXtWHIB9Mw9KcaVSBhwUWDUakstfrMWse/
         n+tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CkvxSK1E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ut59vK31vL4Irkn1TQRHpJ/COndUJNCxvY64H3DpCcs=;
        b=cR84X9jrZJkjZt1uWQNi8sRmvpWrqfaBMFGedcbJx5MuS5xG3ImOsKGcBV3mHlYtEV
         1P5ybLfF2PnFgyA1B/5+pmAczf6/8rxnhdABZZhRMMcrfmmmemVAimcLMjBY8eLO2ipJ
         +6PnBfXeBPCX6ulbHfAieLeR6t875FqIXsJ9KkOaut7HFffaYeQLxdK2OoyK7z024co9
         Nv6BfsxF+a8sFu7stljCJXUYkLdBlYaIO5sZprknzR+Rk+v62sYr9eXuVPe1QUJMwQSx
         WDC5ggzEtGsDeEY6AT33v+8wwoomzLD6bAhbmx1auA0wkXOlwLBe42cTRmQfRSsnfiH7
         j9UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ut59vK31vL4Irkn1TQRHpJ/COndUJNCxvY64H3DpCcs=;
        b=lROKA4UE1bV9sQSM3jopJiHh48zWSmzea+oU7sq+z80oap76um6W6p+C0LCCwhuEfy
         JpCT2esV07dG35GOLpij/malp7hxdn6jFBtr9eFB6TftZnzYJdaICj+Z27oYedW2AM4g
         dlp51OafN5CanI3eappuoT3TtpsU0fSAYpWGLAr7s+rql7V9h+gNASnWKycxAQUCdLE0
         /SNO2AifGNEYLQJl6EEVY81I9RZoMW8928f2nwkGjiev4hu9e/Daqm255rc/B+cn7Cn4
         55rcsOCzp9w0ELBITDbPts3nXaq3pbteclF05aLpbAVdAf9yOFIAoe7dHjgTTZKv6FTZ
         nyNA==
X-Gm-Message-State: AOAM532sLmtVK61X2PksfX9hl/fj/bli1P9VyXGLvL3jRfWN1o+gukn6
	AXuN+RY4zEisbt5FK8Ty8Ao=
X-Google-Smtp-Source: ABdhPJx1jhagWuX3WizYIf45KIwIbO2lvt+/Y1b2YrkJUqtxfps+np9Los9ImfqDyAkWkhkiM2DgFA==
X-Received: by 2002:a05:6638:2601:: with SMTP id m1mr4487516jat.106.1636625546556;
        Thu, 11 Nov 2021 02:12:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:219a:: with SMTP id j26ls537619ila.11.gmail; Thu,
 11 Nov 2021 02:12:26 -0800 (PST)
X-Received: by 2002:a05:6e02:174d:: with SMTP id y13mr3394167ill.183.1636625546196;
        Thu, 11 Nov 2021 02:12:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636625546; cv=none;
        d=google.com; s=arc-20160816;
        b=UqGCvZew37iQl0W0r9C4DbhpA+UafH4GWFwKjs2JiHJvoXo4oPw7RH2D59j74Q7p9A
         VuADN5n1eem6Tj1C90DH43W8z5DX2aNcjYF9QuNdzac1KyIwHW4jiqt1UfBu6RJB6G72
         1y37z5XP0BJnu4nomZN0xr7zYM0S5l1ZyUJUsp1wa3ypEd9gYFotw0VbIxN60ZcJyePT
         xXEpCrTiLpDHkTBsO3OzBo5aHol8fpjm/Enl9r8EEwWS4N6PLR09VWLAQeumygUPse67
         SMNmUW1N6eg7J/y9Jt7YkEDzAoHOsge+8DhPlTntJMmuHGPyk9GNURHRCWYz0e0OjSs8
         lVkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x2JqhGMyfJOncOO31VPKGQJKmpqXdotolWXJ0Sscp8s=;
        b=L2YFrmq8Q8M54Ybg7ILvSCitxofWHTgfCjd7ue6wienJvN9eHPBrPjJ+Yhd5OhW1c9
         +CTl7g9cNtSq+/Jvq59VhkMMxHFRY9yPtQynbqquMr5PKTGO3wbVz0GuVBcRzfPYdhcZ
         bif6Fbn6GSWlQx1VXyA9DPimxapx7QOKS6KS+YWF3sx9869S3B6QHJ6DSs2GisHqsSej
         akrnr3iNiy7uVbx0ZzfEwRjnXGkJF2Xt9Ym1s2LEz8XuLG61vxB/WxamugEy2gZLhYar
         WWW4h8JvPovTrzmH2wN7f668rbB2c6A03kWwfU/Fo26pgbWD8cks03WjjFx91abADrA7
         w4YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CkvxSK1E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id o6si191052ill.3.2021.11.11.02.12.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 02:12:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id m6so10766924oim.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 02:12:26 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr5116357oil.65.1636625545648;
 Thu, 11 Nov 2021 02:12:25 -0800 (PST)
MIME-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com> <20211005105905.1994700-24-elver@google.com>
 <YVxjH2AtjvB8BDMD@hirez.programming.kicks-ass.net> <YVxrn2658Xdf0Asf@elver.google.com>
In-Reply-To: <YVxrn2658Xdf0Asf@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Nov 2021 11:11:00 +0100
Message-ID: <CANpmjNPk9i9Ap6LRuS32dRRCOrs4YwDP-EhfX-niCXu7zH2JOg@mail.gmail.com>
Subject: Re: [PATCH -rcu/kcsan 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E . McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@kernel.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CkvxSK1E;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Tue, 5 Oct 2021 at 17:13, Marco Elver <elver@google.com> wrote:
> On Tue, Oct 05, 2021 at 04:37PM +0200, Peter Zijlstra wrote:
> > On Tue, Oct 05, 2021 at 12:59:05PM +0200, Marco Elver wrote:
> > > Teach objtool to turn instrumentation required for memory barrier
> > > modeling into nops in noinstr text.
> > >
> > > The __tsan_func_entry/exit calls are still emitted by compilers even
> > > with the __no_sanitize_thread attribute. The memory barrier
> > > instrumentation will be inserted explicitly (without compiler help), and
> > > thus needs to also explicitly be removed.
> >
> > How is arm64 and others using kernel/entry + noinstr going to fix this?
> >
> > ISTR they fully rely on the compilers not emitting instrumentation,
> > since they don't have objtool to fix up stray issues like this.
>
> So this is where I'd like to hear if the approach of:
>
>  | #if !defined(CONFIG_ARCH_WANTS_NO_INSTR) || defined(CONFIG_STACK_VALIDATION)
>  | ...
>  | #else
>  | #define kcsan_noinstr noinstr
>  | static __always_inline bool within_noinstr(unsigned long ip)
>  | {
>  |      return (unsigned long)__noinstr_text_start <= ip &&
>  |             ip < (unsigned long)__noinstr_text_end;
>  | }
>  | #endif
>
> and then (using the !STACK_VALIDATION definitions)
>
>  | kcsan_noinstr void instrumentation_may_appear_in_noinstr(void)
>  | {
>  |      if (within_noinstr(_RET_IP_))
>  |              return;
>
> works for the non-x86 arches that select ARCH_WANTS_NO_INSTR.
>
> If it doesn't I can easily just remove kcsan_noinstr/within_noinstr, and
> add a "depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION" to the
> KCSAN_WEAK_MEMORY option.
>
> Looking at a previous discussion [1], however, I was under the
> impression that this would work.
>
> [1] https://lkml.kernel.org/r/CANpmjNMAZiW-Er=2QDgGP+_3hg1LOvPYcbfGSPMv=aR6MVTB-g@mail.gmail.com

I'll send v2 of this series after 5.16-rc1. So far I think we haven't
been able to say the above doesn't work, which means I'll assume it
works on non-x86 architectures with ARCH_WANTS_NO_INSTR until we get
evidence of the opposite.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPk9i9Ap6LRuS32dRRCOrs4YwDP-EhfX-niCXu7zH2JOg%40mail.gmail.com.
