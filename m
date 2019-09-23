Return-Path: <kasan-dev+bncBCMIZB7QWENRBZMSULWAKGQELU2CXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A293BB016
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 10:59:18 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id l84sf10892905ybc.14
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 01:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569229157; cv=pass;
        d=google.com; s=arc-20160816;
        b=uFRhsfU1OoDoIccHbhPPL1SNy/nzfwKVPqi4JvSH0LY5FXsRaQ3SSS/iZqwaXlp/aK
         ebdhVbYrA4AdbEWBzLXxziNUQR/yCLO6JEH7nO7uXtfitlC6Nql7X6n3hyODpRlX9K9f
         tZ9Li6DoKSu1do54NSIt92BT63GXUuZgjrbULxNL7CPVfFyAtqeaTSMJF76XiEXe4bgc
         2afxfCxLFUnOAmZVRzMX0zmcsYHAeKI5/R+FLlHBonJngkpVGcpkeuv/YZOqA2NZjtxF
         ZrB+CpKczkftkuEEW5BdWeX3b7oeK1jSGf2kkuZtJUTmoqUhLLFSyXU5NhyvU6QKN63N
         Vejg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=N0xWkGes0rRgp+dNKYj4bNgrPCOUR4c7WdAkW61TLng=;
        b=oxr0x2jkA3vO0LNhdMARhjXbhar8Tn04BM9ztveA/jn0WZmpNF2Gj0GNAe9aQKcMH4
         40YrSXeSWW3c/w4cZzmnTUX5oqiwQVcTCkENr+ybAQaK0KMBde7q5x09zWREIW5tS8de
         KlylyWaGyxP0D+4kuWPzYcqSRSrnktXdqeL1a07ZywoovVIT0Rh87AaXa89rzcmZlg+9
         VTnN592JzqWUc5QjLizcq/y74aO+y+vCAay87cbNrAdoEGWVF/nXAz77E4IutLfldLpI
         +CEwu3ejCqNEYY8s3IdqsS+oAAKEjEVjMcxxCnZ4S2b2bcEMWC36TAnbp64I1QHgTroZ
         QYeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oKV8sdMm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N0xWkGes0rRgp+dNKYj4bNgrPCOUR4c7WdAkW61TLng=;
        b=Dan/GUGRcB50EnqWmOwu1URMNNvX1Y7+3v2aoH0ke8BuARr+BpljDPf/yHxh5682W/
         8KrNsXY6p5qQQU6ChlDDIAdNbeKDGIdf4QjM1sLIPo14ZrACmFvKS8nUJBENSrNpo72q
         4aTXRoeZshttTj5V9E79T02374G+XzG4/G2zZh4BbXM/T0LizsTCs/MRltZFZkKyJ8vC
         nLh7CcliyyPhRKItJeKNk+tgw3AHj8LdppDSQehRUIIuJn0YsUQ2iodFZ+jacWx1W/uj
         3PXp5S9plT1Zbs/Xf653N6Ej4p9aDmZZPSzQjyxgzD/rkx/ZVoqXbT1rVmvAMWUftmmw
         eWOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N0xWkGes0rRgp+dNKYj4bNgrPCOUR4c7WdAkW61TLng=;
        b=hH+CTvyJ2Q+Wk/nB41NSpBVxFqHaVI0paxAh4+rtj9ua8EGvXI5Efc6Z8TeylRjW+q
         UjNu2bSULxkEHoOdG/VNH/QBW2kWVwnlWh9wac2tczoo9pkIyHqgfvAusg0v9vTjy95F
         9qqfkBdFU085nTQobjoSOPaVuKThkRIa0avIX9HLxphIHzh3o0jsDBmufyMrEwXzFLKt
         bsc3gsvLPpibzjKy42Boj6xtaqZ4RDSXoahzArVx0nuUOxj7owQlW6JkCV0Wip7DF+1l
         XmW5LS1WF2hpcjBKrwGtjf4Tyhu2Xb05SpSu2aDiFs4LRwlrTmvMrtvEzfdl8nS0V7TU
         v6Xg==
X-Gm-Message-State: APjAAAWwI721I+BZOGknsViM4oLqkTzrtsP3z1gECZ6EaA6pTArdoA+M
	aaBoP/k9z7JVpIDx3Wksgm0=
X-Google-Smtp-Source: APXvYqz/A0X6n1+t13ip6GTOHhtmLpouq17du0irLwAY16++CwF/k1TWEg2DoZixSyfj/iv++qrLJg==
X-Received: by 2002:a81:98cb:: with SMTP id p194mr21449940ywg.0.1569229157261;
        Mon, 23 Sep 2019 01:59:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d611:: with SMTP id y17ls2464529ywd.13.gmail; Mon, 23
 Sep 2019 01:59:16 -0700 (PDT)
X-Received: by 2002:a81:108f:: with SMTP id 137mr23161837ywq.324.1569229156945;
        Mon, 23 Sep 2019 01:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569229156; cv=none;
        d=google.com; s=arc-20160816;
        b=zOSzuliYyJJhHf3Dzsqj7NYkV+QbCUWUiHAk9nJnplrrEEV4V5NNzoCDvLsheT1mA+
         ql6xDkQRnA50FlFI7cqZsY4GhgE7Oa4CHGqTcNRRm+7syJ2tWPt8Lp3Q5dqbSjFokA6M
         gboAdOIxsfgnq9++e76IOR4ody5upDz9hHcPFAp06qF2FiTKcOSBt9u1OvogN9RkYAKI
         oEokg9cI48QUrHP2FZgUUhQuGWaNjhG8KPAzva3FTLn8Go7h9Njn3IGF4hPId1nomQ/C
         cw11Gz0tZiQb8TQyLZ2r5UZKTJkY0/XrUGzeHhHS3pKciPOib3sGV1dxRpaq6GExbWed
         9v8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1wmLHWhdWEkcWYQfJJdjt2kpx2xUUhXVzrZUl6Mqcvk=;
        b=PHMBZav29o3Zf8GhWh7eAtEB1ucqjo9b2Cse9+82hIA4lb6MfBotWru6RpfRxhNh78
         cTCwbuqfplyURFwBts/8l2PHrFny467MACBuCv6Z5urYCL2PQ0G4rpviOvUGP85TutuW
         2DCV3HsSDsmQBFr/fGYRbuXuCn1F9ZB+ZRXpdK+bofyvRni/AQi0jwlIhxeQ8ffDD+GG
         uy9k6OGhEKwtFIhYJqfKxDZ6H872/gbQVjOuRexkw0dpK8FwAPPC6xZ7uoHb8ZWBkRTZ
         pqtIBa6gIoOGyb62WRRtlY9lEFgQZZ9HDn2dZw0+z/xv/g7Eemj7BR/IvknBylQqzKUR
         P8IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oKV8sdMm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id g203si896740ywc.5.2019.09.23.01.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Sep 2019 01:59:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id c3so16169667qtv.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2019 01:59:16 -0700 (PDT)
X-Received: by 2002:a05:6214:801:: with SMTP id df1mr16880596qvb.54.1569229156108;
 Mon, 23 Sep 2019 01:59:16 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck> <20190923043113.GA1080@tardis>
 <CACT4Y+a8qwBA_cHfZXFyO=E8qt2dFwy-ahy=cd66KcvFbpcyZQ@mail.gmail.com> <20190923085409.GB1080@tardis>
In-Reply-To: <20190923085409.GB1080@tardis>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Sep 2019 10:59:04 +0200
Message-ID: <CACT4Y+YfkV80QF2qxjfHnBghM8Am8m_YHzCtPRfSmOrF-y3bbg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=oKV8sdMm;       spf=pass
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

On Mon, Sep 23, 2019 at 10:54 AM Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Mon, Sep 23, 2019 at 10:21:38AM +0200, Dmitry Vyukov wrote:
> > On Mon, Sep 23, 2019 at 6:31 AM Boqun Feng <boqun.feng@gmail.com> wrote:
> > >
> > > On Fri, Sep 20, 2019 at 04:54:21PM +0100, Will Deacon wrote:
> > > > Hi Marco,
> > > >
> > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > >
> > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > >
> > > > Oh, spiffy!
> > > >
> > > > > In the coming weeks we're planning to:
> > > > > * Set up a syzkaller instance.
> > > > > * Share the dashboard so that you can see the races that are found.
> > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > point it out and we'll prioritize that).
> > > >
> > > > Curious: do you take into account things like alignment and/or access size
> > > > when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> > > > naturally aligned accesses for which __native_word() is true?
> > > >
> > > > > There are a few open questions:
> > > > > * The big one: most of the reported races are due to unmarked
> > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > to fix races might be required. Comments on how best to proceed are
> > > > > welcome. We're aware that these are issues that have recently received
> > > > > attention in the context of the LKMM
> > > > > (https://lwn.net/Articles/793253/).
> > > >
> > > > This one is tricky. What I think we need to avoid is an onslaught of
> > > > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > > > code being modified. My worry is that Joe Developer is eager to get their
> > > > first patch into the kernel, so runs this tool and starts spamming
> > > > maintainers with these things to the point that they start ignoring KCSAN
> > > > reports altogether because of the time they take up.
> > > >
> > > > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > > > to have a comment describing the racy access, a bit like we do for memory
> > > > barriers. Another possibility would be to use atomic_t more widely if
> > > > there is genuine concurrency involved.
> > > >
> > >
> > > Instead of commenting READ_ONCE/WRITE_ONCE()s, how about adding
> > > anotations for data fields/variables that might be accessed without
> > > holding a lock? Because if all accesses to a variable are protected by
> > > proper locks, we mostly don't need to worry about data races caused by
> > > not using READ_ONCE/WRITE_ONCE(). Bad things happen when we write to a
> > > variable using locks but read it outside a lock critical section for
> > > better performance, for example, rcu_node::qsmask. I'm thinking so maybe
> > > we can introduce a new annotation similar to __rcu, maybe call it
> > > __lockfree ;-) as follow:
> > >
> > >         struct rcu_node {
> > >                 ...
> > >                 unsigned long __lockfree qsmask;
> > >                 ...
> > >         }
> > >
> > > , and __lockfree indicates that by design the maintainer of this data
> > > structure or variable believe there will be accesses outside lock
> > > critical sections. Note that not all accesses to __lockfree field, need
> > > to be READ_ONCE/WRITE_ONCE(), if the developer manages to build a
> > > complex but working wake/wait state machine so that it could not be
> > > accessed in the same time, READ_ONCE()/WRITE_ONCE() is not needed.
> > >
> > > If we have such an annotation, I think it won't be hard for configuring
> > > KCSAN to only examine accesses to variables with this annotation. Also
> > > this annotation could help other checkers in the future.
> > >
> > > If KCSAN (at the least the upstream version) only check accesses with
> > > such an anotation, "spamming with KCSAN warnings/fixes" will be the
> > > choice of each maintainer ;-)
> > >
> > > Thoughts?
> >
> > But doesn't this defeat the main goal of any race detector -- finding
> > concurrent accesses to complex data structures, e.g. forgotten
> > spinlock around rbtree manipulation? Since rbtree is not meant to
> > concurrent accesses, it won't have __lockfree annotation, and thus we
> > will ignore races on it...
>
> Maybe, but for forgotten locks detection, we already have lockdep and
> also sparse can help a little.

They don't do this at all, or to the necessary degree.

> Having a __lockfree annotation could be
> benefical for KCSAN to focus on checking the accesses whose race
> conditions could only be detected by KCSAN at this time. I think this
> could help KCSAN find problem more easily (and fast).
>
> Out of curiosity, does KCSAN ever find a problem with forgotten locks
> involved? I didn't see any in the -with-fixes branch (that's
> understandable, given the seriousness, the fixes of this kind of
> problems could already be submitted to upstream once KCSAN found it.)

This one comes to mind:
https://www.spinics.net/lists/linux-mm/msg92677.html

Maybe some others here, but I don't remember which ones now:
https://github.com/google/ktsan/wiki/KTSAN-Found-Bugs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYfkV80QF2qxjfHnBghM8Am8m_YHzCtPRfSmOrF-y3bbg%40mail.gmail.com.
