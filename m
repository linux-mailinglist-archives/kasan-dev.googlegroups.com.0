Return-Path: <kasan-dev+bncBCMIZB7QWENRBH4BULWAKGQEY2KUWAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 918B9BAF42
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 10:21:53 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 194sf9672340pfu.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 01:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569226912; cv=pass;
        d=google.com; s=arc-20160816;
        b=LM7smBWXV+xe8Zr/yopZ3QR/HUn6LBnm2S5awTvqleRozhGidaYRc9NJMP/7Rk7OzA
         HwIN9QNzYNNGwLx5M34EwAXCjiEVzRlk/f+tJtZV641ot2dCQ7Id5uYg6/ULBmyBBB2z
         XULCeq7bnQNsxGrby/Fa2JOrpkx0uZVzIor01Zw5JIPLDVnMxMCH3L5UAhAtrdQNY4D3
         Te/ma9Y5syCOQ7BhawqS+fWgjC0ZacvI2ye/jWPozkSy3+BHur2fOkp9ojv8XzQMSCZR
         PiiZijHbjtr1vyNGFsuxJGzCRh7N560T4IfRZva72CgXxPTFuDYV2bzU3RZesqc7OYJG
         uHKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VlSvX49qzQE7ocazzNDNXh08zMoBOlkqPwM6QcOwYuc=;
        b=lNkOzEsQ9WGNFVC70Q39+dXlkERstX1Wtjpkx8yXmQQzHIjcEi1BDFqG94HCsUoXbg
         GkSWabSgscu/42AhvqPRQOwjYRCha5kywLaUerO7yn8PxXhLy4+zdLiTAXDhlyKu6Q9D
         JQX3HKXgbwjYIENS5gBD9zjcq80APy9r2cs8cp3FBdIy0AYXb9kMu5g18/endL/WDtSv
         iN3lKJuT9L9hFHJzB1k7IgBLeNl4GUymNqdzkvV9aTIACradYduV5qP/J1euBMjGMmLM
         J4W4h3H+IJ0nrcNBAayij/XdSd9fjeVG/iSWeoQ3xGYsN1dsSYjWA0nR08lE6E+fu0Fp
         njYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y1zLA0E6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VlSvX49qzQE7ocazzNDNXh08zMoBOlkqPwM6QcOwYuc=;
        b=DPTdGXJp9JCH2vsTHcj3cbpQpebTfTwZvOOBjGAtjir5OdjMXICvyk0F+wh3F6h+3F
         /lSwJ3nSgBcgeR9aJmbs/KWBZiagUNFNbvbA6j5gN3qOqu1hTFlu3AnaomDBlR47zBrT
         JdpvkjQElhZLMbIwdzQFX5QMx4CXSO0o4dnsf7WrrpvBIAbOl4QV1eHh/IaOADebOyNV
         pDmN0oIUBZAQu7vbwdMgb7NV9VQmlELfnLEfI0MgLx5SYzO0lCjOd48D8fIRezG9cRwy
         qTf8pzmPZZODmIk8Um12sxxwsEi9DQwBPHCE0lSo/OKVJ2icQWclU2zKDsRWQ14YRjEm
         4l5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VlSvX49qzQE7ocazzNDNXh08zMoBOlkqPwM6QcOwYuc=;
        b=RfJ1OseSkJK3xoE9EoysXVm2sCCd0cCqPbr8fc9peMahU4fThNB9mikCnPs4kmvDg0
         +4c+iPBeDHjfff7S3o6zRXyEL1YUTZx/nSawjwwuZ0eyAkFB9/3AdHl64aA/N4d5ZIAa
         BNid6CiKd+vbbguLjA5rD6ZehpAlZY/ZlJnf9ltkEcuzibiYR5NRbR4cH6ifvmUzJrk8
         +enuIolDBzuyc/SFmpNjNvHuoUC2M5L7vO7Bv4A7QLQTQ2POtuPWHnq4yXOXmD7JjWSD
         ArliCDb9481fmQydFBPNZYIOUd6I0yOhkryQhDuO/0a3BMea4EuQnG8+0DgCvETutRpQ
         uGbw==
X-Gm-Message-State: APjAAAXnzWE+6FAQHdx2jfzhmNdPhFW9dqKTM05mcTZriz7zsGKNYpha
	VLLbA3dcTuEygea47P+exbg=
X-Google-Smtp-Source: APXvYqzCB1sqe075RUkdunDmy07jh863WbaKjO3QIqm3L5pKuPEWyrGGuQVWPRRFNZXdqgaTOecrlQ==
X-Received: by 2002:a63:d46:: with SMTP id 6mr710083pgn.364.1569226911912;
        Mon, 23 Sep 2019 01:21:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6307:: with SMTP id x7ls3790972pfb.0.gmail; Mon, 23 Sep
 2019 01:21:51 -0700 (PDT)
X-Received: by 2002:a63:1d02:: with SMTP id d2mr1965641pgd.190.1569226911513;
        Mon, 23 Sep 2019 01:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569226911; cv=none;
        d=google.com; s=arc-20160816;
        b=zWdaP6QRgWZHfIWnhbeZhamRJoIRMXBRqh8fZuJxN9gctw1NgbZkP5RI0s7EjI+7v+
         llK0rcZFbZZ+WSPVS1AodUk4C2BVV1whNYW9P+EdnuNMMUf6ir5l0TVEb0VP+c3CMUDG
         EdK9DBS9sDfL4c4ZGW4bMziMvT6rXquqjdSqRNB35CVseP7h8zRr1NI7Gd4dh3VDKpeP
         tZSL/kaWO09gbUWAhGeYUfHlOO5vJidwcJsj9lRGrDmPKY8rC7TyI553Ei8HSw25JSmu
         irn8vqwqmcFGAccky+B0OcAs8YKXM5aKmuKPB01a9c6jldkgUs7zTylzlbgAYb/c8OYF
         SfkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dG+IUBD3k3NqJ3XZ6q5TzuUzXf08ps14N7Cnt35pHj4=;
        b=oDCExE/Fs0ELF/kUc1ZL5ajQKGfVs9drtq9bLdSja0HMwK2nsGdN27lGqpEnkJzJHb
         4VYGjk40LsImiGFL4gMCzhvMQSjmkyQ3hxtiOLwy5Q3F6awgUnMwsJXVp730KqPPbyDA
         X5Tic7dBkNGbLsslnpJGGJsqubBLv9FBYUkw6Ra41fcDwmaaZcx9VF0qc+EiVoWndD0z
         ktdezdCPrJ3mgBd9bR0jDGAmKHEKI3QCONLg4i7QYI0vMwWntl0Z7GezdVsJzNtX6bvL
         SroKs4B7z3XpSo3KQOm8UqSiwYwS2/4S2GjFb+roogq7LjZxomZFS4R8bTpYY9PQFHVc
         jSGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y1zLA0E6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id h1si795021pju.1.2019.09.23.01.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Sep 2019 01:21:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id y144so14426301qkb.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2019 01:21:51 -0700 (PDT)
X-Received: by 2002:a37:9202:: with SMTP id u2mr16131182qkd.8.1569226910085;
 Mon, 23 Sep 2019 01:21:50 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck> <20190923043113.GA1080@tardis>
In-Reply-To: <20190923043113.GA1080@tardis>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Sep 2019 10:21:38 +0200
Message-ID: <CACT4Y+a8qwBA_cHfZXFyO=E8qt2dFwy-ahy=cd66KcvFbpcyZQ@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>, 
	Anatol Pomazau <anatol@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Daniel Lustig <dlustig@nvidia.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y1zLA0E6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Mon, Sep 23, 2019 at 6:31 AM Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Fri, Sep 20, 2019 at 04:54:21PM +0100, Will Deacon wrote:
> > Hi Marco,
> >
> > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > We would like to share a new data-race detector for the Linux kernel:
> > > Kernel Concurrency Sanitizer (KCSAN) --
> > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > >
> > > To those of you who we mentioned at LPC that we're working on a
> > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> >
> > Oh, spiffy!
> >
> > > In the coming weeks we're planning to:
> > > * Set up a syzkaller instance.
> > > * Share the dashboard so that you can see the races that are found.
> > > * Attempt to send fixes for some races upstream (if you find that the
> > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > point it out and we'll prioritize that).
> >
> > Curious: do you take into account things like alignment and/or access size
> > when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> > naturally aligned accesses for which __native_word() is true?
> >
> > > There are a few open questions:
> > > * The big one: most of the reported races are due to unmarked
> > > accesses; prioritization or pruning of races to focus initial efforts
> > > to fix races might be required. Comments on how best to proceed are
> > > welcome. We're aware that these are issues that have recently received
> > > attention in the context of the LKMM
> > > (https://lwn.net/Articles/793253/).
> >
> > This one is tricky. What I think we need to avoid is an onslaught of
> > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > code being modified. My worry is that Joe Developer is eager to get their
> > first patch into the kernel, so runs this tool and starts spamming
> > maintainers with these things to the point that they start ignoring KCSAN
> > reports altogether because of the time they take up.
> >
> > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > to have a comment describing the racy access, a bit like we do for memory
> > barriers. Another possibility would be to use atomic_t more widely if
> > there is genuine concurrency involved.
> >
>
> Instead of commenting READ_ONCE/WRITE_ONCE()s, how about adding
> anotations for data fields/variables that might be accessed without
> holding a lock? Because if all accesses to a variable are protected by
> proper locks, we mostly don't need to worry about data races caused by
> not using READ_ONCE/WRITE_ONCE(). Bad things happen when we write to a
> variable using locks but read it outside a lock critical section for
> better performance, for example, rcu_node::qsmask. I'm thinking so maybe
> we can introduce a new annotation similar to __rcu, maybe call it
> __lockfree ;-) as follow:
>
>         struct rcu_node {
>                 ...
>                 unsigned long __lockfree qsmask;
>                 ...
>         }
>
> , and __lockfree indicates that by design the maintainer of this data
> structure or variable believe there will be accesses outside lock
> critical sections. Note that not all accesses to __lockfree field, need
> to be READ_ONCE/WRITE_ONCE(), if the developer manages to build a
> complex but working wake/wait state machine so that it could not be
> accessed in the same time, READ_ONCE()/WRITE_ONCE() is not needed.
>
> If we have such an annotation, I think it won't be hard for configuring
> KCSAN to only examine accesses to variables with this annotation. Also
> this annotation could help other checkers in the future.
>
> If KCSAN (at the least the upstream version) only check accesses with
> such an anotation, "spamming with KCSAN warnings/fixes" will be the
> choice of each maintainer ;-)
>
> Thoughts?

But doesn't this defeat the main goal of any race detector -- finding
concurrent accesses to complex data structures, e.g. forgotten
spinlock around rbtree manipulation? Since rbtree is not meant to
concurrent accesses, it won't have __lockfree annotation, and thus we
will ignore races on it...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba8qwBA_cHfZXFyO%3DE8qt2dFwy-ahy%3Dcd66KcvFbpcyZQ%40mail.gmail.com.
