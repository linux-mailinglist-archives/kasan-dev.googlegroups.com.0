Return-Path: <kasan-dev+bncBDMODYUV7YCRB7PP3XWAKGQE3NKNL4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5363ACC10A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 18:49:03 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id y13sf4255163plr.17
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 09:49:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570207741; cv=pass;
        d=google.com; s=arc-20160816;
        b=gerJ82tSuLZH8MLnATrTqdbrSqzXjSwL3rZeOiPD1s54w5W7SA0Him/lY1/iT7Cn6y
         /9oLRvnfQWTKE3sVYzRDnuXwj7Murs+xWJExWbBis1oB0inZgRrlRMrA+1hTyCSGOljH
         MHSbWfVLE03R5Er7EK5RrR5qTrH2J7ex05kCpzw+LtQLzvBzKReI47ZhhocWcXIH7ASx
         4PN1074DrRSieYlKL6rsngUq430oIhdQ/+YZl847lPOiyJqDXKdR6anJcx4SD8qxstfW
         J3jVPlPwY3wxhLBBQ7hQWDuSg66nnS8FIYvDAKt8YlkyRmGuKdk9meltJc5CA2caeFMM
         sdCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=TBCQMQ5haRB92CilUU5GzzUDhxwK7BSL9wyjq307ebg=;
        b=HR7Whx6UX6PDs8EzvYGYAqfWRYprx4oaiFzc7c2zMzFiKML8CjOWu8SBInNyGXJmSr
         p2UmeO74+pASJHFDlPIEy/g9muzvC1yFqt4/ofkigdaSIwevuev+ZKMinDcChtFJsyhi
         NXYWMHVjCPht9saGgftbTVnD17l9K9TVBFYihrUNJqtQ8myT9AZAhhCQUHiVzAcR+qcD
         AZspxNshNgPKOUQg7ekOysKKfNqUU7a70CAaNEInUpUadHpktrVJ3n/deqazZP2J3u8v
         nIV8FGF0t207/o31vAAn2vvIWau3F5MmImOI+MRTIznZ/tN+EhdJq5Ex0Kj2vjytH+mM
         i7KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=tPpec2Wn;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TBCQMQ5haRB92CilUU5GzzUDhxwK7BSL9wyjq307ebg=;
        b=XgY84TSd9FMkADkaLf4F6M3SZQpZNoBSYY8nSVnJ6y2S5i2yUpaTpGIKAnNg9DTjeo
         w08baFabpXTpmMOYIgPPGuUeos8E/+lMbf9sDO0CW0EYpOwJXhjA8ucHPHpcMlwNhXnU
         /X5xVQ7z4Ay95yGn0qELUMsmymo5Ge1RnXwJjrqkJAFylJY5/7Z2p53xPJZZyQ8PSYR5
         dUhGZNvWx155gAZd7Z8YdmZVm/6X6dURbU3Y2oEbKILeFjcgSE8wLUlDz1vMr3wwkNkI
         37munJO4u1FyG0REGcRYCyBIccVnuVi8XcZTfpCRnCONcJYLA/c9HjJfgtDvuQnyDwa2
         juZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TBCQMQ5haRB92CilUU5GzzUDhxwK7BSL9wyjq307ebg=;
        b=jIzeyMV8y9iZJUY0PfJ1jc60AMWpRHhdogytqSLIsQEiql3BGxPnR37AeGnWDXXpDi
         5cUtARQpYfD4uL6qQAagCD78n1wA++5TZHUNTMadi4pV905X5gnCyDy1uz1dp+V4spvn
         I1NWJ+JlAPq+AtBAt0vGlHb96IxKBiwkwKjzoigocJ1VAdN21xTEpLMhzfR1WUnysRIH
         UWJAulpKxfciaWF4eXa1+NSpfE0g44cpM9P36MS+4ZD175brEVmyxPxjb2kL8+8K4JHx
         1BDyHTJ+dz9ckE3IWO9B32bS8Ojfv/aNYxzYioDVjW+cZJ8msbIEY/KyRm3YECtvr73O
         PfPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVP9Gbw3w+DS98szIGIlxYAui4UMdIyPrCkjVVOzfQpUI2aXDFr
	K/ij60CVJ5I9v6J1jW19ltU=
X-Google-Smtp-Source: APXvYqxDh5MLUxEnVG+9PyEIOTOalqQS2Ym3YWe8U5MZ91VO7h39KJ4HG1ACMt7JZGXkLxhrX9ARxg==
X-Received: by 2002:a17:902:202:: with SMTP id 2mr15534736plc.96.1570207741734;
        Fri, 04 Oct 2019 09:49:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:644a:: with SMTP id y71ls2559558pfb.9.gmail; Fri, 04 Oct
 2019 09:49:01 -0700 (PDT)
X-Received: by 2002:a63:61d5:: with SMTP id v204mr16478507pgb.311.1570207740948;
        Fri, 04 Oct 2019 09:49:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570207740; cv=none;
        d=google.com; s=arc-20160816;
        b=t1hN/nXIgpVJOQbqZ1K1AzEW02Km4uHe7wxIvML0wJ5ISfftWTXx1zgRLic8bUZfoV
         rmRgJjDnqgirDs8vVpuR6g4PiUE+UnUSaxLK+ErhPtDbExd/vcj61axMHQaWyGCMbGxq
         DMbrObP2APxjqZ2HcUny9zMfA3ez2AA2KAcekSL2NxoMZwFjFHo8DG4ynbkNjQ1N5gLA
         oSTrv5cZTRzoiQ3No6i/5ACoubo2ZtXYLO6S9Ee8EcvSoYxrRyvRUEhVjv6/NvFCHqNy
         qW5I2XKb7uSFBcnWfGFBnz1riIfrW4AqFSsYtPFUT9xhi3Tyn0s8/B+Nn06/Okf28cDw
         +oWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XdTgxouoyqXx/Y++6hFEOOkFgjmwtjxo2BV5ysqNRLk=;
        b=LRQt1R7s4S73Ja9RfPNFE38kHjGJ2MsGJDajf6yG9T6IJLsObpmcbsB0YJbFJXgdma
         AHWqEzHSuNK6b0N13K1DxtCowZlF3nxJQPNIoSNukkpqBD3L8I15FH1kJqXAGVUNTxG5
         Q3dLYp1N4gSfjsA6+XreH02SqnQ9sOKpOvJOttFmfCYkAG+gTNEb6J4HgghjYnEcsoOR
         X74bb2HaUsnjti+mBhIzkR/w3DBDpl4HFZcC4jz6b5oK/Waw8OLth82r4urmd741SuIa
         B5pqPghN+FYsMPN3DyRm8JWXGRAgBUSR7nLW+/fupxZJ4cWAQoTcA78JWEm6o0OVGnId
         z55w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=tPpec2Wn;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id l1si441568pjr.2.2019.10.04.09.49.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 09:49:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id b128so4262766pfa.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 09:49:00 -0700 (PDT)
X-Received: by 2002:a17:90a:33a2:: with SMTP id n31mr18569367pjb.28.1570207740561;
        Fri, 04 Oct 2019 09:49:00 -0700 (PDT)
Received: from localhost ([2620:15c:6:12:9c46:e0da:efbf:69cc])
        by smtp.gmail.com with ESMTPSA id h2sm11564666pfq.108.2019.10.04.09.48.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Oct 2019 09:48:59 -0700 (PDT)
Date: Fri, 4 Oct 2019 12:48:59 -0400
From: Joel Fernandes <joel@joelfernandes.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191004164859.GD253167@google.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com>
 <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: joel@joelfernandes.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@joelfernandes.org header.s=google header.b=tPpec2Wn;       spf=pass
 (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
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

On Wed, Oct 02, 2019 at 09:51:58PM +0200, Marco Elver wrote:
> Hi Joel,
> 
> On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> >
> > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > Hi all,
> > >
> > > We would like to share a new data-race detector for the Linux kernel:
> > > Kernel Concurrency Sanitizer (KCSAN) --
> > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > >
> > > To those of you who we mentioned at LPC that we're working on a
> > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > >
> > > In the coming weeks we're planning to:
> > > * Set up a syzkaller instance.
> > > * Share the dashboard so that you can see the races that are found.
> > > * Attempt to send fixes for some races upstream (if you find that the
> > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > point it out and we'll prioritize that).
> > >
> > > There are a few open questions:
> > > * The big one: most of the reported races are due to unmarked
> > > accesses; prioritization or pruning of races to focus initial efforts
> > > to fix races might be required. Comments on how best to proceed are
> > > welcome. We're aware that these are issues that have recently received
> > > attention in the context of the LKMM
> > > (https://lwn.net/Articles/793253/).
> > > * How/when to upstream KCSAN?
> >
> > Looks exciting. I think based on our discussion at LPC, you mentioned
> > one way of pruning is if the compiler generated different code with _ONCE
> > annotations than what would have otherwise been generated. Is that still on
> > the table, for the purposing of pruning the reports?
> 
> This might be interesting at first, but it's not entirely clear how
> feasible it is. It's also dangerous, because the real issue would be
> ignored. It may be that one compiler version on a particular
> architecture generates the same code, but any change in compiler or
> architecture and this would no longer be true. Let me know if you have
> any more ideas.

My thought was this technique of looking at compiler generated code can be
used for prioritization of the reports.  Have you tested it though? I think
without testing such technique, we could not know how much of benefit (or
lack thereof) there is to the issue.

In fact, IIRC, the compiler generating different code with _ONCE annotation
can be given as justification for patches doing such conversions.

thanks,

 - Joel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191004164859.GD253167%40google.com.
