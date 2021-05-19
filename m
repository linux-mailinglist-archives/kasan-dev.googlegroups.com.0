Return-Path: <kasan-dev+bncBCMIZB7QWENRBEHYSKCQMGQE6EVBRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 585CC388807
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 09:19:46 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id g144-20020a6252960000b029023d959faca6sf7554663pfb.9
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 00:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621408785; cv=pass;
        d=google.com; s=arc-20160816;
        b=kKgj8qbRmbrHDw3iU+YOGXyqEWhcu6Qw0YBCMODrLrzpNeqXLiH70L/0/sAc5iWQAl
         kgYTaeDPmMvjtLh3fBn2NV5FZPYVgYPYYuR/Nr51VLxE8FOeeDqWdnVqNOw5Joelhrtb
         ndcIEANEK/sK4N9mmsPGz3JYpf+HhumadxiO2rX1vG3K/gp4l4J8FB0FT9Sbe/UpZVYH
         54nQ2JkQ2uDXH5VyRCkzQBoDpmV9h1eZmpyCPN7aMBbMqcDt9FrjGfaM8AO2dKvdNlN4
         0nRVRaZLT8/KEijWfOwhdhtcb0Bj0GCTAmTizxqBxI42ftSk4b3StM4UuOXVbT4OVo58
         e0jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UvEy7VdexosuAfdwnR23j2RvVAYKVIb2nUXiq3VuO8Y=;
        b=kqdIch2yqA4tLXTQnfnmn8aKRKy2FniwEDeAiPf/qq5o5V2M0DtD1CobW8Inq9/dL9
         qKNlYaJEAre7zLkruEE+6ti8QghVvVPajX0suerIh1gERRgB7nzAGXq6O+ojPmy9BI4j
         yE/4Z+3OdUD/6QPIaHwazMsw2KFkGAhHL9pw9P30z44M9Xvqa+E8s+yJXMmziBcYiL9S
         kMW4Po2FsV2tDnm6C/aHomdd0JwpSkDlQpppIKmKUBc/PFBVnuZvj61fbfAtiPoOZYeL
         sJMhQALKGJlJdj/FJ3YXjUy4O7LPtMB2S09nKZ2u5I02odTThwJbyXfRgg0SCTNdCuNf
         9LuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C/Vba2D/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UvEy7VdexosuAfdwnR23j2RvVAYKVIb2nUXiq3VuO8Y=;
        b=drv8YPVP0abiS1LnS7L0sB9yy8g66t8247okaXn1+nqLpuWBubk/rBR6/fzjYoYvo5
         Wm1VS4YlxDb2zNsC5LpyCnB19YnkPvRsOEfZs6Cy/nz53fGP3W2kHV89npkF4rXdoRZ3
         LT4t9yDWwWsUtqUpxj4j7fyDTT8DsreMLKVUvHuKDuye+682IWNdclwc4fb+Dtg+zywx
         wnkhNNpJ+Nfrs9XcpdN0PLYwDVTc+840ZMCVKOEa0sVWpXViBJ8XtioxtWx1cvtYQ3Qu
         H8HmPtjNfHdnDmEPcCO/FzRlWxqHiE6TyP+r+D+O5ay4B5x4l4W4BSe1oKC+gorvBL55
         Q6uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UvEy7VdexosuAfdwnR23j2RvVAYKVIb2nUXiq3VuO8Y=;
        b=WeyS2uG6+aotEhEmUqTZUUEndaR5wM0Lb0l6J3V7fv5B3+7Gywz9mWb06xFmMOezt0
         I5LTxCJSqaCylrg45+3i+7CCHIKWweNENho7jyDWLpkLvGBoFz9sgXm3InMvq5hbHlVw
         ooyxMtZWlZyNtVpy3SVO3iZG2x5svub6t9uvXqQxYU/5WBq+ScIV9oif58btSPEILmP6
         e3+lcYzxnH386WMyjKBQ0T7u95CeUeOQYkcLgkolP3Gwem7FPL3Rn79F0P1OVb0l1GiU
         Pbsy9wCDv1VN8Ohhm4LWszn3A986emUaY1rYLuk5jSnWZgcVvl5q7uIqmEnF44geilwl
         Sntg==
X-Gm-Message-State: AOAM532Clm2uj5JAQ/Q3CUWZZJThfKvQlvbepYjiXei3920remWmKG1F
	6mJEp7Vd/sm7meLx8hn6dI0=
X-Google-Smtp-Source: ABdhPJxkfOCLjijv+HU7FJQS8WwTJ4bGZlr5HTzoZ1x+1JLzE673TJlK5qxciJ5wNF0Acz+6naStLw==
X-Received: by 2002:a65:654e:: with SMTP id a14mr9361046pgw.332.1621408784961;
        Wed, 19 May 2021 00:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7e1c:: with SMTP id z28ls10500000pgc.3.gmail; Wed, 19
 May 2021 00:19:44 -0700 (PDT)
X-Received: by 2002:a63:1443:: with SMTP id 3mr9513934pgu.69.1621408784318;
        Wed, 19 May 2021 00:19:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621408784; cv=none;
        d=google.com; s=arc-20160816;
        b=D542gFerQHcpE117O69AJHKuTOuQpLDzaT7nJ6bSNMv+OsVpJyd35UZtByn2lKUoxw
         TR55Nzs0Gsv5cG8P3/c9pawde0C1srYdb6xUsODSL28+X8WMNMDdnoS22AL2M8VjoiC2
         4YP8XfIPvEoGMCtE/MGymFY0CdR3oMaBtHpgpQL67EgXPyZvWYrgbsrIwVj6fFWuQiPe
         2GDa7+vMjuhxS/70brkyirj1Vxrd6gCZ1ZASwlXVg5KTJRhr+NlOyI9wVKmQMG9XBeMn
         cOjdoFCzulQ+ott0XDoM8vbL0GZ4J+lTe4RUST4YHneEWia/Y28thBSZjjMPfP3BD5zb
         aDTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C7yqoysFdDxhj/4jPmX9l4ofOno+LhygLU/CFOq5vnU=;
        b=C+H4zDZFN+5RodlRwDgln3pi8NTxYAsHQE2YnyUW8INUDWAiKjvE1RniQmk8uqNhwi
         Cbm8a1z0Go74c8SE80x8SgFlAZws/OcSfMl9XUa6NkPtr/8jotPJPOAR5mvQe9B3DTvq
         fqP4uoChseziWBl1CVmbAWo8omoVU/+GHesHwsuZe4pqCkUUdBXaP3V9MD2zU10VqD1S
         31LMOxlyl5tTG6BN2F7iIW2LJOxlKeleCof80rIa/lcTN3N+o24bBZdKVYq+jJfXDsqR
         zu+u+UY3PP91ra5sIsClkwLrLAlaKZHl/5ZvJd2T9MmS+zenBeCWG4TLrX++yGNjDeFC
         9Kgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C/Vba2D/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id 131si1250848pfa.2.2021.05.19.00.19.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 00:19:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id k127so11839688qkc.6
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 00:19:44 -0700 (PDT)
X-Received: by 2002:a05:620a:150c:: with SMTP id i12mr10882391qkk.231.1621408783511;
 Wed, 19 May 2021 00:19:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
In-Reply-To: <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 May 2021 09:19:32 +0200
Message-ID: <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com>
Subject: Re: Re: "Learning-based Controlled Concurrency Testing"
To: Vegard Nossum <vegard.nossum@oracle.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mathias Payer <mathias.payer@nebelwelt.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="C/Vba2D/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c
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

On Mon, May 17, 2021 at 8:15 PM Vegard Nossum <vegard.nossum@oracle.com> wrote:
> On 2021-05-17 18:44, Paul E. McKenney wrote:
> > My hope is that some very clever notion of "state" would allow
> > coverage-guided fuzzing techniques to be applied across the full kernel.
> > Here are a few not-so-clever notions I have thought of, in the hope that
> > they inspire some notion that is within the realm of sanity:
> >
> > 1.    The current coverage state plus the number of locks held by the
> >       current CPU/task.  This is not so clever because the PC value
> >       normally implies the number of locks.
> >
> >       It might be possible to do a little bit better by using the
> >       lockdep hash instead of the number of locks, which could help
> >       with code that is protected by a lock selected by the caller.
> >
> > 2.    #1 above, but the number of locks held globally, not just by
> >       the current CPU/task.  This is not so clever because maintaining
> >       the global number of locks held is quite expensive.
> >
> > 3.    #2 above, but approximate the number of locks held.  The
> >       question is whether there is an approximation that is
> >       both efficient and useful to fuzzing.
> >
> > 4.    Run lockdep and periodically stop all the CPUs to gather the
> >       hashes of their current lock state plus PC.  The result is a set
> >       of states, one for each pair of CPUs, consisting of the first
> >       CPU's PC and both CPU's lockdep hash.  Combine this with the
> >       usual PC-only state.
> >
> >       I could probably talk myself into believing that this one is
> >       clever, but who knows?  One not-so-clever aspect is the size of
> >       the state space, but perhaps bloom-filter techniques can help.
> >
> > 5.    KCSAN-like techniques, but where marking accesses forgives
> >       nothing.  No splats, but instead hash the "conflicting" accesses,
> >       preferably abstracting with type information, and add this hash
> >       to the notion of state.  This might not be so clever given how
> >       huge the state space would be, but again, perhaps bloom-filter
> >       techniques can help.
> >
> > 6.    Your more-clever ideas here!
>
> Somewhat tangential in the context of the paper posted (and probably
> less clever), and not based on state... but how about a new gcc plugin
> that records which struct members are being accessed? You could for
> example hash struct name + member name into a single number that can be
> recorded AFL-style in a fixed-size bitmap or kcov-style...
>
> The fundamental idea is to just ignore everything about locking and
> concurrent accesses -- if you have the data above you'll know which
> independent test cases are likely to *try* accessing the same data (but
> from different code paths), so if there's a race somewhere it might be
> triggered more easily if they're run concurrently.

Hi Vegard,

Interesting idea.
Also +Mathias who was interested in dependency analysis between syscalls.

A similar analysis can be done statically as well... I can't make up
my mind which one would be better... both have pros and cons...

However, again, I think we are missing some lower hanging fruit here.
The current collide mode is super dumb and simple, I added it very
early to trigger at least some races. It turned out to be efficient
enough for now to never get back to it. The tracking issues for better
collider with some ideas is:
https://github.com/google/syzkaller/issues/612
I think we need to implement it before we do anything more fancy. Just
because we need an engine that could accept and act on the signal you
describe. That engine is indepent of the actual signal we use to
determine related syscalls, and it's useful on its own. And we have
some easy to extract dependency information already in syscall
descriptions in the form of /resources/. Namely, if we have 2 syscalls
operating on, say, SCTP sockets, that's a pretty good signal that they
are related and may operate on the same data.
Once we have it, we could plug in more elaborate dynamic analysis info
that will give a much higher quality signal regarding the relation of
2 exact syscall invocations in the exact program.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ%40mail.gmail.com.
