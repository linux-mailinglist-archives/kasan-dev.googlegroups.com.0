Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAM76GFAMGQECRJFODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CBB1422782
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 15:13:39 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id m14-20020a63fd4e000000b00287791fb324sf12435939pgj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 06:13:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633439617; cv=pass;
        d=google.com; s=arc-20160816;
        b=SNDJYsTu8KYioxbJiEmdTRI/g4QIbro5MBc14WrFC7qroQdNpU1Ge1oy6vVCVhT5n4
         4y+XRsR5XNiiVZQOiBO+AchGbHChCc4Kp7oSsscwz9VhbAbmATbZVaWuFK2tAU2VMjjB
         qrLkPtG44zwexK82aiePWEtkYZhh0p04QmVebBu/6vQpdjOfHXpRzvw5fxYETD0f/ZmV
         ZdmIDYZNwOxPO4OMTkL2gPvU9uPFKV6h4E43uQYbd+FFQJdlzMSjNULx4HQtCHljQgZ4
         XLhWCVZwFSQ9mzwNXQR/HzoKAp7O0W2u2zi3nneS8GncncXOFf8nUuWXV/3A6+iwWML+
         W5eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/0F3vHMxDbLhpsA6STTAxKVwi0oKzzuhxi5GbSbKm/s=;
        b=h0ojvfgspxhn7Habd6nwXABTYXso40zovNQn5n0FL5+QDM2bO5qylF+4udabVwx8x5
         GQoZvHVPsmW66vsGCa4ZhSjrpJyM8m4iKk+b32wKl5GDgmJHn8TBPPYtAzbd+dJsgZtj
         dmnrH8dyFVRWYDoq9McUf2MgItTnfZ52lHp97qoUOHDtX+MmZvvPlpdOxYgkl0NZ7gJV
         wtU5A6/JI+LWFa8eU3ZhCD+F98Qv6rnzM0vDu0l1VK4Nfgfd79AyRv6AthpMKSbIxcAZ
         p7BhAK++i9iQyQ9TdJuCM+t6tPeGQQ/O2fkco4ewcpsE4s4dysxv7RbuKlEwDk93R9jU
         jNcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Uo5Dxx/8";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/0F3vHMxDbLhpsA6STTAxKVwi0oKzzuhxi5GbSbKm/s=;
        b=bVwYD3OaMNrsey52b0tWPOj8kDvUDvnDf0x4kh+BZVI3M479jEO/jSOfRyqGMStsrs
         5Yk/lvfRiPBjMmnB8r94QMfSx1IWfuPzRmt8J0qBSJ9vZymuzaQ974cixd7jQmGMuNOc
         JguuRgWyEtiOd5LkggkOmmMHygOVb8WEhGeQn/mzrOCmSOGL+dUnenAq5GgeGEuHpbv5
         8zvph5MW96dtNELLJCTpO2Z+aFmHQMArA1BiO7L3kkBDJwaGU4pb/covjp5QLmdVWNMD
         yaq065ng6obnlkK11XlSvpXaVmaZRVonJUwZA80KQ7o5yv33xhUGBv6t3hoisLLcpiSb
         HEKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/0F3vHMxDbLhpsA6STTAxKVwi0oKzzuhxi5GbSbKm/s=;
        b=TEL6GaAchTy8qTf6rKC2QniXU28NpYbGwsT9FCX/dU2howeNrMaDjtwExPpgMdgjtu
         4fXuEGNoC8lkkAgZnghSwTjEyofeF6EtahAvqdSWWNN3Fl1YL6AmctwXdh9vfAoKNkGj
         WRjZ3DvmLzkQJy6Z4AwGJVnzRm0x8vC7KSiXkZ/P0PTeVsyjXae+TMad9SKry7tb1B/5
         OXE87GM5LVYU5xgVlKHcNtquQQVEXNHYKzCDyzLQK8UHWVsUgDcsGOv3oEZ3mEemBxoG
         cNQ0f+8R60Qi+tSqUiSUl16l6U1utsbWEMECNK6ztaTOY++q7viu+kA3FkkZVe75G2uJ
         1Deg==
X-Gm-Message-State: AOAM533mxRF0sP4xr/CXYdnl0uMOrfYVj25sfdU5m8BwvpAtU1FJoKZ+
	Z8DYfkPgMTVeRXS+dlSYKSk=
X-Google-Smtp-Source: ABdhPJzCXTSsmxClh5UK4j+qQR7UbkJaw5QpIkDBDDMZueGlFGhhAbI6lcCRxuPUNwAvkXHNUAGm5g==
X-Received: by 2002:a17:90a:9912:: with SMTP id b18mr3863814pjp.46.1633439617773;
        Tue, 05 Oct 2021 06:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac9:: with SMTP id r9ls1206267pje.1.gmail; Tue, 05
 Oct 2021 06:13:37 -0700 (PDT)
X-Received: by 2002:a17:90b:1806:: with SMTP id lw6mr3747949pjb.222.1633439617173;
        Tue, 05 Oct 2021 06:13:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633439617; cv=none;
        d=google.com; s=arc-20160816;
        b=nhZT/rfRUR6nbkUQXhHbqGdug6BG8MowOoMqUKx+PbXBrGhbrdCg+glBoVT/ztGrWI
         cqMdd6gY2aiLBnCSVy3zOhYedWdY1CT6bQ2EdYYb+myKZ5ud1/pDbJoIdFEzDkgQCg0Z
         8vUMYOYImN8IqJJcc/Ojz9D+rSqcEpIWgsXBi7tmRG6KN4YhzKfi4+UFK+Zn1zAoWQb5
         3PfgZvb+1h2JFkQhxLa3Kf4ujbRiFuSr5tpPVgyqaHwLZlV2JhHOmDq0/5k9sOrC03pw
         MxHfWkJ3CA9mlzCzv7erw49Ejng8q7k1yN5fLuxXaAUvS29KqAKFmvtuv4xf+lJa9vtt
         W9gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6G7malU1QffNFlLHyGnF0GE1rVke+5aiG8YVR53mxq8=;
        b=GUU2Qht29/+uQkGYNBijdLqhvVX0EBhHFx8rSlOqIly4BC/Ldi3E57ep4wQZdzLJqO
         uIqZbIes7peWNX0Rc6tS3OENnVnYtD1CE/HKy/YjPEtbYfsCH/aSrgYd5B6NpDINiXxD
         hKanpFjfrOMq52O85Gwd79iqbhycYwJB3xGs8jvegBGwCB0+C8Scewawen+nhZUFTv05
         /ensFn08EpyvBhggLn4iaXf00aYKJgMLGI1Jnh5d8YfMBCZTLNAhvBgFkTDjZn6esFKJ
         bgqWQAGu9a/j7BwX0Fk1UdJ7+vOwRBm4t3zmwEM5F4RMJMin7I/62Wl81CacUiRRTAMn
         Hqhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Uo5Dxx/8";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id q75si272006pfc.5.2021.10.05.06.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 06:13:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id k11-20020a4abd8b000000b002b5c622a4ddso6379595oop.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 06:13:37 -0700 (PDT)
X-Received: by 2002:a4a:de57:: with SMTP id z23mr13364623oot.70.1633439616620;
 Tue, 05 Oct 2021 06:13:36 -0700 (PDT)
MIME-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com> <20211005105905.1994700-5-elver@google.com>
 <YVxKplLAMJJUlg/w@hirez.programming.kicks-ass.net>
In-Reply-To: <YVxKplLAMJJUlg/w@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Oct 2021 15:13:25 +0200
Message-ID: <CANpmjNMk0ubjYEVjdx=gg-S=zy7h=PSjZDXZRVfj_BsNzd6zkg@mail.gmail.com>
Subject: Re: [PATCH -rcu/kcsan 04/23] kcsan: Add core support for a subset of
 weak memory modeling
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
 header.i=@google.com header.s=20210112 header.b="Uo5Dxx/8";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as
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

On Tue, 5 Oct 2021 at 14:53, Peter Zijlstra <peterz@infradead.org> wrote:
> On Tue, Oct 05, 2021 at 12:58:46PM +0200, Marco Elver wrote:
> > +#if !defined(CONFIG_ARCH_WANTS_NO_INSTR) || defined(CONFIG_STACK_VALIDATION)
> > +/*
> > + * Arch does not rely on noinstr, or objtool will remove memory barrier
> > + * instrumentation, and no instrumentation of noinstr code is expected.
> > + */
> > +#define kcsan_noinstr
>
> I think this still wants to be at the very least:
>
> #define kcsan_noinstr noinline notrace
>
> without noinline it is possible LTO (or similarly daft things) will end
> up inlining the calls, and since we rely on objtool to NOP out CALLs
> this must not happen.

Good point about noinline, will add.

> And since you want to mark these functions as uaccess_safe, there must
> not be any tracing on, hence notrace.

In the Makefile we've relied on:

  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)

just to disable it for all code here. That should be enough, right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMk0ubjYEVjdx%3Dgg-S%3Dzy7h%3DPSjZDXZRVfj_BsNzd6zkg%40mail.gmail.com.
