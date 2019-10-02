Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2772PWAKGQE7WMM2WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 578CFC92A3
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 21:52:12 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id w14sf123190oih.19
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 12:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570045931; cv=pass;
        d=google.com; s=arc-20160816;
        b=CEGV5dbZPjh+1gBsNh9MXPFd7wsaD7GqiC+g69NgHuSXOQviV4k3whoJ1GtrYLVnzm
         UMTChpPYx3l822XcasGCRopm/DhwUI/tjjVGoVUw5P8yUxa/e85pdD0LsPpZv7tp3aNP
         QZnS6IvFNuU9xM25Grs1KQRV3ntt9OlwUV3t/Pl1U0gDy5wRr7RkaZX9rnN/F+hdiODw
         xHOF9YephywgsWxXTwlArg1ppk+DaODQeLuOBxErO7d+X90R5NVriSCI7aR6v1ErVoNa
         Z4hGogVeSf5oZKbFO9lGnRhTNUZODdDvvyp+mS/kqXtaoj9v9uViRwUr6IoMihHqMw1x
         9W7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sA3dNsAGaIYfKZ5U7Xpht+qTI97x7S8znwcIGJnkMXE=;
        b=RYMK/nFMn7jTHj3CKRsRGylan/JJLqxnInBa+dk6iQrQvZ7OXM/7hOl49rY8AyCDtn
         y2S5/i/+CAp/qLcySvQUpQ/U7EYvJ00gygUpyTCW+d7msGSvrlbGx/2HA/FppUfXRYJ5
         qJrNoMTP2mk9YWedJ1C2ReE9YyvWrLUAB3AvBgn/FXgXpcqEED46A0EvE6oN0W5wCzFT
         VNjJW+Bdv0XCqvwp5rRdo8KL/NHjPevcoBsfZYI9Y65nkbn0G6QyEi8NIVKeo4sAV1jJ
         1mngcgzw2nlVn9w2YOQmhNJic7VS9+wKuud6qSsZyoUZfYg71yeFhUa+s0AfINtnrno4
         DUQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DbBnVOau;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sA3dNsAGaIYfKZ5U7Xpht+qTI97x7S8znwcIGJnkMXE=;
        b=ah7lg7K5pJ/aRWr89czvDWFsE5WNHqBpGnviHF/q5XhxdA8+Lj307ek7USOUEIM3vk
         4gXT1DsRh1TeTVhDHYpXLbHHpZ3lwVnwZWrDPn6yZwA2/NrfEBNPhMgmuFteDe3Do2Yv
         nAxlDrbxmIoBgCwok+SC4bQ/Njh69n3PVsy/iRCxF1K5Gq1Y7ICrzT+i6hPuzkqX3lc7
         FV9MNiOAG9NDdYX4+tbmAwAzOnBi6SA5zOMmWGjC+hKWDcJeQoUy0zIrpe3sxQIKlwQv
         v5x5WI8YnAmE0xRJuJwA/IMhu+RB5SFFyze7Tm5O4NrVNJpRsVIT6XB7XaxbCdqJT968
         36Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sA3dNsAGaIYfKZ5U7Xpht+qTI97x7S8znwcIGJnkMXE=;
        b=F57uzdWEJuFIR7ALbVCxuLCz+g8d9ZR3Z0VsiXqLVUMxwkGcndwIy/qx3ABS9tC0FA
         BBYGyWPS0Tbs2tVKzLDHcotzDQvwYdgbItkUwkovk0E883jtexc7gZ1UIrMFSnCYk2t9
         6yysWgIJtkXUp18qvaeA1mVOG2v4ku7ra2KvO9BG93OKFvOoEbQaowUD2o1XCPc/rnIR
         cOOA2WPVoMHlT0aJzsuo73PN817Wg8sKkfxYEo874lCp8HHypBXo/NTd2U0KwSumkRjF
         xZ6NUH3NN9JNpiL70IPBomTsCWCo1+3RtM0hXkDNfHHxbs+0WXinL5Eh/hF+4lNqYDcm
         ce9Q==
X-Gm-Message-State: APjAAAXADrwH7yivDxwmIGQU3Mzj1P1kaf+exO5c9nXzaQF5kP1fQkyK
	SWOSsOOUrbChZcE9vxmUe9o=
X-Google-Smtp-Source: APXvYqx48e6E8uzShsNkSsGrIPX0O9oZux9HcZ8Yu8L9S7+cAacnuJ7WtKampuhjovVDqc547adkxA==
X-Received: by 2002:a9d:7498:: with SMTP id t24mr4221057otk.0.1570045931045;
        Wed, 02 Oct 2019 12:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cc88:: with SMTP id c130ls735513oig.4.gmail; Wed, 02 Oct
 2019 12:52:10 -0700 (PDT)
X-Received: by 2002:aca:3c55:: with SMTP id j82mr4265200oia.135.1570045930736;
        Wed, 02 Oct 2019 12:52:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570045930; cv=none;
        d=google.com; s=arc-20160816;
        b=xy5YofqSQxq4YWibRhtEjs+gIXhCO4Ji3hwInf3UBQk2yuqw/WFbLF3dymiIs+TxJo
         6y+FC3Z35blKw+z2WhW+cR20o4nvC1Hx8vMY+0AXIGkH4pFSKEj4yx0bY76pjEvF97hO
         /4O7hC9fkJc67PvmnrOrRYCckkW2s2Zqq164SpE97HjXKAFeQywED8pNoXFBtEp+kQGX
         6V9We9kWqn6XQX6191FBykE18PxYApoScqG2rL+MtxCcOXAnAYxtD1XzT//GalWu4n81
         IegNcJ/w7yknePEkiBFZD0ctNu126lGAHAibFHbAjNHx4RrfA2vhk99vwdNLA0AnZfSo
         JNvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8UdMjUT2pdLGE8ndpyA/9BXAvjXXhiUaO/cTeSeGp6c=;
        b=pExpswYwfltnurm0jo4PV4dNKJB6r2Mp3MLxftJSyZj29JSkuspdA86/omTuj9aq0I
         a3Ql7mFr+hhltsAt5Ex9yiNg+rt/zE+lsyg4GpzcKAbAu0EtikrPcCejWUH6el3lVJfu
         vU8tsM/fWS+CiZKqHQJEBOC+AzeVTViNPXAwryP6fufvAYkcUY1PrEun/z/fyA/4Z5sm
         uOG4WL7SDfuEF+Lu7mDWFQbj2FiKiuntFteA89ZeQhEh+1WrOt4rgL151z161PRZA4L4
         gKOY4njqAwL+owwB+CpRm16/69DGJ9e/V/L9PKxI6/dvPNdLfx+LohfXjw+VqBgfeZFY
         nuvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DbBnVOau;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id v3si19130oth.4.2019.10.02.12.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 12:52:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id k9so456782oib.7
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 12:52:10 -0700 (PDT)
X-Received: by 2002:a05:6808:13:: with SMTP id u19mr4279200oic.83.1570045929963;
 Wed, 02 Oct 2019 12:52:09 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com>
In-Reply-To: <20191001211948.GA42035@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Oct 2019 21:51:58 +0200
Message-ID: <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Joel Fernandes <joel@joelfernandes.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DbBnVOau;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

Hi Joel,

On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
>
> On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > Hi all,
> >
> > We would like to share a new data-race detector for the Linux kernel:
> > Kernel Concurrency Sanitizer (KCSAN) --
> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> >
> > To those of you who we mentioned at LPC that we're working on a
> > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > renamed it to KCSAN to avoid confusion with KTSAN).
> > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> >
> > In the coming weeks we're planning to:
> > * Set up a syzkaller instance.
> > * Share the dashboard so that you can see the races that are found.
> > * Attempt to send fixes for some races upstream (if you find that the
> > kcsan-with-fixes branch contains an important fix, please feel free to
> > point it out and we'll prioritize that).
> >
> > There are a few open questions:
> > * The big one: most of the reported races are due to unmarked
> > accesses; prioritization or pruning of races to focus initial efforts
> > to fix races might be required. Comments on how best to proceed are
> > welcome. We're aware that these are issues that have recently received
> > attention in the context of the LKMM
> > (https://lwn.net/Articles/793253/).
> > * How/when to upstream KCSAN?
>
> Looks exciting. I think based on our discussion at LPC, you mentioned
> one way of pruning is if the compiler generated different code with _ONCE
> annotations than what would have otherwise been generated. Is that still on
> the table, for the purposing of pruning the reports?

This might be interesting at first, but it's not entirely clear how
feasible it is. It's also dangerous, because the real issue would be
ignored. It may be that one compiler version on a particular
architecture generates the same code, but any change in compiler or
architecture and this would no longer be true. Let me know if you have
any more ideas.

Best,
-- Marco

> Also appreciate a CC on future patches as well.
>
> thanks,
>
>  - Joel
>
>
> >
> > Feel free to test and send feedback.
> >
> > Thanks,
> > -- Marco
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001211948.GA42035%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNp%3DzVzM2iGcQwVYxzNHYjBo%3D%3D_2nito4Dw%3DkHopy%3D0Sg%40mail.gmail.com.
