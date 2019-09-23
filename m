Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFWMULWAKGQE6ECRSZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 18056BB292
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 13:01:44 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id r7sf9847563pfg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 04:01:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569236502; cv=pass;
        d=google.com; s=arc-20160816;
        b=reJOain6G9fv9PZlIFTGrV+MSJct/pABB1MRTxliNBN3KPn4EFFoKeSpjQPLaYLOlG
         PXxYYlKeCF8GHcCm93atmetMvucgO9tPHBbd5m2om3gMNz98Lb8nVYI1ymT7rCraaCyd
         q0LRIh0V42bD6hQ+vh1u3VdUGneNIAaeofvfNuVHSXBGqGdHXqa5JRKMk+viec7paQ/B
         2WMP61MF9EjJJEWvOM6BHBJ6yNebK5Xh8B99q+LAzquHkL5s1Vc6bJxDh1/mCi/GwgAt
         NbDjGcc+z/kBAFBqfN+RdBGBo5xJ1RMT8JGuUpIpab6fP6ab4d5DmeMncZPGuANjoZDa
         uYvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DaXSJ0fO4tvO5d15Kjev5MoJ3oQFROBW+xkLLfkf+iU=;
        b=Wav8888cvpuoyxxI8mj33Og5mjJYyuN2Z7I6Q6gSGgSb63NGGwAMr+Mf1zzLZn8tH1
         WG2Dq8LnMjXZEbTklwSNR50bbjlqotGe5YupQid1LNLgwH+gZ+l1yPux2XxWWy/x9IMG
         6jIapjeOGvYYxiwgeKKSaFYNhKJgY2r7ibaPDhFluJgmoPpMQwHj/A9AgZh7bXjue0m+
         XipZWwwMJ9Kxnny4uDX5l8Rf3Dmik4ndZbOhgwjT/ylRXqoUpk5E/a41jU7RYp8A9UtA
         YdyUNJVSrp7I0hWKpy5gpNPyFC+r570WJQx4Xh9Qkqft/NseUKtVi/0Bj8SyBiXkBCGg
         xDrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FjdT/Mrj";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DaXSJ0fO4tvO5d15Kjev5MoJ3oQFROBW+xkLLfkf+iU=;
        b=dgZqhhmzyKD8jCGny9MgENTas6dNbdp4RARtG6s9mMhj/gXb8k+y8cBS7IGPj1jfXa
         uDuynZMXzgOtO66G1IRxfe0WUHAGwMv8d6opobX4mGBYmQ+84B1XIGwt3ejZ+qxgQBVF
         fBnWPwU6A/MdXiZykAiSeXehlqB8nJZLGloTfKsK+km1fyfwAItOLDgYtj0FInh46Ujs
         e+wS9WqRsSxacOKOfToA4vs4JuwD1fDXZdAAcvoXUWBO5eTQeGYBb7jetD0DQLea+p+q
         bYHdnbYX9I7tHRVmHkm+S04H/XcdjmMvyZDS1372JQfPre5jDBA3tiSZb8hiK+zAvUKx
         L3bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DaXSJ0fO4tvO5d15Kjev5MoJ3oQFROBW+xkLLfkf+iU=;
        b=c+gGK6v/tnCuOdbkY4lFMSofPYP4xPUhe5op4OgEKlNGOsktMNKn4aFkVUO9HCnnZ+
         2TjKXFyILDGfT+SVLfPDoAOf++qQyvkfTbeihPAuvjmV0onwIKyAsMdlwU1aM1yO022G
         3NVYO00TnYkdFKj7WYNludipDLZPBJc/vgYI7kYRyPKL8aaVZW/Gxk2DUs0q9f69yERg
         BHTrEqB4nzY1XnUnoXmw7rErUnDDFvo0DF1giTFLZcxRvy7eBRyL/EC9jAdHc0inGX5Z
         dIaW/0UGL9LE0IsVs0DSOjTgNBMuAV6fvdNFC2qvWjCar045Ud1F0gYq2U1A0i7a1c5c
         9P3A==
X-Gm-Message-State: APjAAAXVQFFhvLKS2ZB+fzuHO8xqQvvyRn7AIFsvv5GIIsilvzOMhaLh
	G5Z3PWWtlvpVO7uEgG50lAY=
X-Google-Smtp-Source: APXvYqzui4A5+ajdlAiaFYp34RPxCNqMUWzTFlYr+b7VqlQc6bJMSj3z0vWOoM5Lgi+LMln3UM1SeQ==
X-Received: by 2002:a17:902:a586:: with SMTP id az6mr32042419plb.12.1569236502327;
        Mon, 23 Sep 2019 04:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d705:: with SMTP id w5ls3831964ply.12.gmail; Mon, 23
 Sep 2019 04:01:41 -0700 (PDT)
X-Received: by 2002:a17:90a:ec04:: with SMTP id l4mr19903332pjy.21.1569236501924;
        Mon, 23 Sep 2019 04:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569236501; cv=none;
        d=google.com; s=arc-20160816;
        b=kKe4+yHpTcJNbCAa0+BxdUeUuOi2tNxVDFKq6FFKfvPuEY+ps2z2BgM00UzGUqyn69
         yZKyu+7wB4cMghgyJxQVr25QYj9AMjO1ZkFzpHe6MYAjYGlu6eLwkkOIM6Ge2Z7ME37y
         o8fBrlVLALVZ1X8d3ILFXnJ2DS4LPto2cVy5a8Derh50YN1tkbzrU8DVvcYRYBDB3v+0
         6nzKdcAyRb3MpA3pVeMrsSgjWNiZd3S5yWY4QvWfGPK5Zcr5875CgPqY1AVMIA16+jfU
         x5cFQpV7It8FUDx3IbrJHXLK4oSSGfi/61FMWqOHx1Ya0AMK/kdEwd1ochqnGbX2sliY
         /7+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tD1gFIlIhno2JODhrG4T/Y3CfRBXx+18zcgSXO7UpGs=;
        b=tJQqhU2TjzLuCbdn//fNyoMJkFo5Wmd7Whes/pYpg3uhSfRf1B8oEMv/HoSOm8qgKZ
         YzH4PFja8RRxg3pD6+joNd+5Kat9sLf5/6ZnBf+cJUzo5whNbanmH/uHTiOZIs8r8eb1
         bic6zQcX+xcO+V8fwimGAu+UgM06r/6rFb+b/tKewhgzAjNBOtvs8KWOyxWOKqaTQSdl
         qasu3ehszmfjchcvs0cR+XOhOA3zMAACmc48b+2BoUj1BaB15yRrchddb2oCGqgbpsqs
         rAdQVUT02aVgkZ2BvLcjsJucIR0YotfMmhJWApRtkHA4zmqCkM86ENy0g7+alYfpiI58
         LFQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FjdT/Mrj";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id d15si628478pjr.2.2019.09.23.04.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Sep 2019 04:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id k9so7160294oib.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2019 04:01:41 -0700 (PDT)
X-Received: by 2002:aca:56ca:: with SMTP id k193mr12068915oib.155.1569236500660;
 Mon, 23 Sep 2019 04:01:40 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck> <20190923043113.GA1080@tardis>
 <CACT4Y+a8qwBA_cHfZXFyO=E8qt2dFwy-ahy=cd66KcvFbpcyZQ@mail.gmail.com>
 <20190923085409.GB1080@tardis> <CACT4Y+YfkV80QF2qxjfHnBghM8Am8m_YHzCtPRfSmOrF-y3bbg@mail.gmail.com>
In-Reply-To: <CACT4Y+YfkV80QF2qxjfHnBghM8Am8m_YHzCtPRfSmOrF-y3bbg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Sep 2019 13:01:27 +0200
Message-ID: <CANpmjNNX5gJ-CRZ-zg3vNzTcBh6+_zEFQzEGTVFKX-z_KwweVw@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>, 
	Anatol Pomazau <anatol@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Daniel Lustig <dlustig@nvidia.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="FjdT/Mrj";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Mon, 23 Sep 2019 at 10:59, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Sep 23, 2019 at 10:54 AM Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > On Mon, Sep 23, 2019 at 10:21:38AM +0200, Dmitry Vyukov wrote:
> > > On Mon, Sep 23, 2019 at 6:31 AM Boqun Feng <boqun.feng@gmail.com> wrote:
> > > >
> > > > On Fri, Sep 20, 2019 at 04:54:21PM +0100, Will Deacon wrote:
> > > > > Hi Marco,
> > > > >
> > > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > > >
> > > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > >
> > > > > Oh, spiffy!
> > > > >
> > > > > > In the coming weeks we're planning to:
> > > > > > * Set up a syzkaller instance.
> > > > > > * Share the dashboard so that you can see the races that are found.
> > > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > > point it out and we'll prioritize that).
> > > > >
> > > > > Curious: do you take into account things like alignment and/or access size
> > > > > when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> > > > > naturally aligned accesses for which __native_word() is true?
> > > > >
> > > > > > There are a few open questions:
> > > > > > * The big one: most of the reported races are due to unmarked
> > > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > > to fix races might be required. Comments on how best to proceed are
> > > > > > welcome. We're aware that these are issues that have recently received
> > > > > > attention in the context of the LKMM
> > > > > > (https://lwn.net/Articles/793253/).
> > > > >
> > > > > This one is tricky. What I think we need to avoid is an onslaught of
> > > > > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > > > > code being modified. My worry is that Joe Developer is eager to get their
> > > > > first patch into the kernel, so runs this tool and starts spamming
> > > > > maintainers with these things to the point that they start ignoring KCSAN
> > > > > reports altogether because of the time they take up.
> > > > >
> > > > > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > > > > to have a comment describing the racy access, a bit like we do for memory
> > > > > barriers. Another possibility would be to use atomic_t more widely if
> > > > > there is genuine concurrency involved.
> > > > >
> > > >
> > > > Instead of commenting READ_ONCE/WRITE_ONCE()s, how about adding
> > > > anotations for data fields/variables that might be accessed without
> > > > holding a lock? Because if all accesses to a variable are protected by
> > > > proper locks, we mostly don't need to worry about data races caused by
> > > > not using READ_ONCE/WRITE_ONCE(). Bad things happen when we write to a
> > > > variable using locks but read it outside a lock critical section for
> > > > better performance, for example, rcu_node::qsmask. I'm thinking so maybe
> > > > we can introduce a new annotation similar to __rcu, maybe call it
> > > > __lockfree ;-) as follow:
> > > >
> > > >         struct rcu_node {
> > > >                 ...
> > > >                 unsigned long __lockfree qsmask;
> > > >                 ...
> > > >         }
> > > >
> > > > , and __lockfree indicates that by design the maintainer of this data
> > > > structure or variable believe there will be accesses outside lock
> > > > critical sections. Note that not all accesses to __lockfree field, need
> > > > to be READ_ONCE/WRITE_ONCE(), if the developer manages to build a
> > > > complex but working wake/wait state machine so that it could not be
> > > > accessed in the same time, READ_ONCE()/WRITE_ONCE() is not needed.
> > > >
> > > > If we have such an annotation, I think it won't be hard for configuring
> > > > KCSAN to only examine accesses to variables with this annotation. Also
> > > > this annotation could help other checkers in the future.
> > > >
> > > > If KCSAN (at the least the upstream version) only check accesses with
> > > > such an anotation, "spamming with KCSAN warnings/fixes" will be the
> > > > choice of each maintainer ;-)
> > > >
> > > > Thoughts?
> > >
> > > But doesn't this defeat the main goal of any race detector -- finding
> > > concurrent accesses to complex data structures, e.g. forgotten
> > > spinlock around rbtree manipulation? Since rbtree is not meant to
> > > concurrent accesses, it won't have __lockfree annotation, and thus we
> > > will ignore races on it...
> >
> > Maybe, but for forgotten locks detection, we already have lockdep and
> > also sparse can help a little.
>
> They don't do this at all, or to the necessary degree.
>
> > Having a __lockfree annotation could be
> > benefical for KCSAN to focus on checking the accesses whose race
> > conditions could only be detected by KCSAN at this time. I think this
> > could help KCSAN find problem more easily (and fast).

Just to confirm, the annotation is supposed to mean "this variable
should not be accessed concurrently". '__lockfree' may be confusing,
as "lock-free" has a very specific meaning ("lock-free algorithm"),
and I initially thought the annotation means the opposite. Maybe more
intuitive would be '__nonatomic'.

My view, however, is that this will not scale. 1) Our goal is to
*avoid* more annotations if possible. 2) Furthermore, any such
annotation assumes the developer already has understanding of all
concurrently accessed variables; however, this may not be the case for
the next person touching the code, resulting in an error. By
"whitelisting" variables, we would likely miss almost every serious
bug.

To enable/disable KCSAN for entire subsystems, it's already possible
to use 'KCSAN_SANITIZE :=n' in the Makefile, or 'KCSAN_SANITIZE_file.o
:= n' for individual files.

> > Out of curiosity, does KCSAN ever find a problem with forgotten locks
> > involved? I didn't see any in the -with-fixes branch (that's
> > understandable, given the seriousness, the fixes of this kind of
> > problems could already be submitted to upstream once KCSAN found it.)

The sheer volume of 'benign' data-races makes it difficult to filter
through and get to these, but it certainly detects such issues.

Thanks,
-- Marco

> This one comes to mind:
> https://www.spinics.net/lists/linux-mm/msg92677.html
>
> Maybe some others here, but I don't remember which ones now:
> https://github.com/google/ktsan/wiki/KTSAN-Found-Bugs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNX5gJ-CRZ-zg3vNzTcBh6%2B_zEFQzEGTVFKX-z_KwweVw%40mail.gmail.com.
