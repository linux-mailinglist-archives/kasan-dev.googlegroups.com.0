Return-Path: <kasan-dev+bncBDMODYUV7YCRBAXU3XWAKGQEJCPTSPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E2614CC124
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 18:57:39 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 74sf3468203oie.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 09:57:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570208258; cv=pass;
        d=google.com; s=arc-20160816;
        b=XXBcREvLogmT4R9XPlBiE4rFxfRupBSgKRwlRNscDsl1gVBsFWIuCSFgQJCpSpdgBD
         OYBN/EbG23SXvZ19/6+XoEI5COsvorqK5qN1JXFH6BOHoHU2RRSvvXJHwc74qznP5ZiI
         4xtWO54D3gz8/YV56MxLjhXyIbDweGvMj1vb5XSRCoIfjuL3EwuCVAvRPr4TUf7AxYRN
         /vXmc/u2QvOQhLHBmtpjLnIvBtwtH3UCT59ilm1TL9Xvr1xsC2nmmioKgAwJVZ07gIXy
         YD2QuBM0yvHzFE1yQkqx/fuKDcf1wlteiskBCoNhxNd+buB5w1x029H2XmRhfjucj6j/
         mUCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XYwdYSABduW9SoW4h5PI1vSeTXqA6yXhrx2ZtPuRjhU=;
        b=G275Whu3kO+zrjXOIa2vUBV34y+V8sGagNy11aKZBG8FEki6FYYqr7OSz0tQX4Py7s
         jL+eM+s/dOokuI0J6qWri+2QVB2s5IUe4uJu6D2Eu7OntPEmb1kTXgVg7Mu6wnJKfKGJ
         qnzCFOLhXdMD+Wje6A8Ar2x2d/JBBviEI173IeLxS98VceAxp+hLVmB9IfyRD9nkmedo
         I2ZSCZwKAQC/bpE3JxtD0cPMM0nL8WPkvqm1kbFTmhtyS5QAvyOHecgEKjqvuZc/8AoE
         uQ0xpDWZXeK3PVWfn8jZNRHOk/DV8+GbVZ+wsM6kLVYoIhBJHoZQxH5V59enqsoatKUl
         Mg4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=A0o11SDO;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XYwdYSABduW9SoW4h5PI1vSeTXqA6yXhrx2ZtPuRjhU=;
        b=e2rSsdvDBgg23qNHwXr1kMLEoqU7KGz6MhihBD0Le/+ZUzUcQp7ZMjygKNMW92KHuu
         7OdOg9ykRQkw5tK0YfDjDJWcMyLG165o0BUC9hJPc7X6DNxFidVaQgNqRy3SLV48YL6s
         u9VH33Uzj5JS+vrQBwLREi+vd2QWEawogsOX9qy9mSK1kojWXN5LJjGpgZF+3x5epTia
         s37EmwK1zgpkU7Gxl7PqbWlQ/z8kFJD6JcjcAat/ge47cKcjwaaDLrehAHbpQTNgA13m
         zMSl+w3cagjUZPsE1uIATP0C/P8rcNxs1z49KqygQtuuX1efaHxrHUuMnHx9Vy01tf92
         kjHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XYwdYSABduW9SoW4h5PI1vSeTXqA6yXhrx2ZtPuRjhU=;
        b=dVBsa0wnLZTHoeaPvkd13CdgTTLOXLG6oWJLcP9OG1d2QtTNz8TkQotoe6Ye7dQ3Kb
         8gUQZYWg+oeu6X0uGmfLkd5H4cfqFjQ6Ke58TSSXM5kNxSNVo72Z+fartpWcUu6cPDX8
         lkqw39a5dRJkCukdt7x2cL2uAbk+2OBgeo9xARDOVcMoaaivEq6glu0z4sBaClDrmO8t
         S6ue7eUGkzJLzUGErJ02GSQCic2kApcUe2CyzS/xZsAgTh0Qqp6FKWLAd10sXdpjcQkC
         nT/Yiyc4wbOgYeBD6eoRq4o+s/fpQQk44KAvLi7kB9zWZHYLq0Z3sUxmh/n4jBCzwl9g
         vGPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSEPdF8irFKfYVzxKS4i/3TJSjssazKwNGggMMghKQVBXbjz8Z
	mkIpLPcf57RZ5VeoZLQodHs=
X-Google-Smtp-Source: APXvYqzCL/mEhR4qEiA3Mlp8AgQzZTi5bLvcQwSiMmWm+JF5WBvD9px/Wwrsoyqz3z69e1p+q8xQRg==
X-Received: by 2002:a9d:734b:: with SMTP id l11mr11784413otk.33.1570208258465;
        Fri, 04 Oct 2019 09:57:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:de9:: with SMTP id 96ls1823724ots.6.gmail; Fri, 04 Oct
 2019 09:57:38 -0700 (PDT)
X-Received: by 2002:a05:6830:1414:: with SMTP id v20mr11652230otp.40.1570208258166;
        Fri, 04 Oct 2019 09:57:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570208258; cv=none;
        d=google.com; s=arc-20160816;
        b=uQAQLfynYLAoJ4xXxwOCRlbX2A/Y2BguOLFSjvMQ30l8SZVPQMpp8Q3CqmQ2YoQ7bG
         FB5osN4Sn5ADQ+K64E5uNZ8fknlVE31Y9yfa4RbcH04peVX+d9MbwBGCgyCgV4i6no4C
         8kajIl7CnS1aVKC30pXMjnXhCPPMx24GCA6MwDeRYPxRv2lmTC3/wBVRKB4ALlx/aKdZ
         yaaVDWG87Sd8kgOIQQSxB+8AqmYxOIbL1JFrqZHVJ8K+vduNpW0yIoVWTeyciFZQG0XT
         3QSDv4osrdqIn6dogg5lkAGrJ2zDbv6hsUgAm/m89aADZed5kgSivR8dKbBf5K/lRrCn
         Zx0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ab3tBPQ6Pcp75EMdc8QMkmhS5pFStOh5Ri4sl4H0v0g=;
        b=KEhl80WngIh0zRCSkFtGqD1ymELVxUAROmU1DRLxNE0APfXdE4NnEAGklVHMqtFbiP
         HReCb2CrM0Ry/grsXBvppQg2X6LJ5LOoYLzdJGiKUCLd5Fbv6gkX23Z0X1YRmZj2Gx7L
         ZrmQskYsgJIDbaJ6FzHlWFZnGndPHpfmGIBaGDDOQFVQ2uVOOVVu0FT3W3v0WB5Eu5F9
         1m7dQY3L4yOB2aBxESeM0QP9VMbTijvuiiukeLzOWwajxJyHF8T4z/gnuko7NcG5kckB
         PIjWIswuq94uDwt5E5gorkJM0w1i74sss0QGEOD9fRj/t1whwMiXtfPr3j97FGx2XXSK
         N7cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=A0o11SDO;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id n63si354586oib.3.2019.10.04.09.57.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 09:57:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id z12so4061004pgp.9
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 09:57:38 -0700 (PDT)
X-Received: by 2002:aa7:8813:: with SMTP id c19mr18135534pfo.101.1570208257358;
        Fri, 04 Oct 2019 09:57:37 -0700 (PDT)
Received: from localhost ([2620:15c:6:12:9c46:e0da:efbf:69cc])
        by smtp.gmail.com with ESMTPSA id t125sm8906818pfc.80.2019.10.04.09.57.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Oct 2019 09:57:36 -0700 (PDT)
Date: Fri, 4 Oct 2019 12:57:36 -0400
From: Joel Fernandes <joel@joelfernandes.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
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
Message-ID: <20191004165736.GF253167@google.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com>
 <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <20191004164859.GD253167@google.com>
 <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: joel@joelfernandes.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@joelfernandes.org header.s=google header.b=A0o11SDO;       spf=pass
 (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::542
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

On Fri, Oct 04, 2019 at 06:52:49PM +0200, Dmitry Vyukov wrote:
> On Fri, Oct 4, 2019 at 6:49 PM Joel Fernandes <joel@joelfernandes.org> wrote:
> >
> > On Wed, Oct 02, 2019 at 09:51:58PM +0200, Marco Elver wrote:
> > > Hi Joel,
> > >
> > > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > > >
> > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > Hi all,
> > > > >
> > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > >
> > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > >
> > > > > In the coming weeks we're planning to:
> > > > > * Set up a syzkaller instance.
> > > > > * Share the dashboard so that you can see the races that are found.
> > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > point it out and we'll prioritize that).
> > > > >
> > > > > There are a few open questions:
> > > > > * The big one: most of the reported races are due to unmarked
> > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > to fix races might be required. Comments on how best to proceed are
> > > > > welcome. We're aware that these are issues that have recently received
> > > > > attention in the context of the LKMM
> > > > > (https://lwn.net/Articles/793253/).
> > > > > * How/when to upstream KCSAN?
> > > >
> > > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > > one way of pruning is if the compiler generated different code with _ONCE
> > > > annotations than what would have otherwise been generated. Is that still on
> > > > the table, for the purposing of pruning the reports?
> > >
> > > This might be interesting at first, but it's not entirely clear how
> > > feasible it is. It's also dangerous, because the real issue would be
> > > ignored. It may be that one compiler version on a particular
> > > architecture generates the same code, but any change in compiler or
> > > architecture and this would no longer be true. Let me know if you have
> > > any more ideas.
> >
> > My thought was this technique of looking at compiler generated code can be
> > used for prioritization of the reports.  Have you tested it though? I think
> > without testing such technique, we could not know how much of benefit (or
> > lack thereof) there is to the issue.
> >
> > In fact, IIRC, the compiler generating different code with _ONCE annotation
> > can be given as justification for patches doing such conversions.
> 
> 
> We also should not forget about "missed mutex" races (e.g. unprotected
> radix tree), which are much worse and higher priority than a missed
> atomic annotation. If we look at codegen we may discard most of them
> as non important.

Sure. I was not asking to look at codegen as the only signal. But to use the
signal for whatever it is worth.

thanks,

 - Joel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191004165736.GF253167%40google.com.
