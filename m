Return-Path: <kasan-dev+bncBCMIZB7QWENRB7PV3XWAKGQEW54D3TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id BCAC2CC131
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 19:01:50 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id g65sf6900532qkf.19
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 10:01:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570208509; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pfb5LYJms24hmf4HekG+pOmT4RDOsSb10zr0A5bOsxE5FhgU5wNFtPrLZHLFYX2Cwr
         tOBmGqQja5vnUCP38yQcPS3dB1zcNccU81uPbQDzmE4qsa7lA8bGRNpA9XpB7baeV5Im
         izWGTmLNgL++7QSM1yEcGxa1HnIu1iMFeSY8w6Ob8y2fuX8EWlKZB/nGNnwhARL2x/tO
         3CKJVsFAHgOlm6P3L4kXla9Xs8WbjnFU6CiqSaXnP0vbhDtFx86F4gtbWU76JwWRLbsR
         lk6w/Ihyks8x+mvBCCzIiAp/M87pRSluXCpAf5lDeDYjaPfyjE/rGoHZbOANdROQvttk
         tEIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nZev9IXUgIP3CMysene36NfZH/42N4IGXaIJJhSrUcM=;
        b=XNcrROCCQHLJvXoupixGapVZdzT9wYACEkh33QzfFxMNDCNcO9aDpMBaSRSEwemoFA
         0hXJLRzj1JeVQ8jnf8chP2wRWyR9EdqSobNi9x95XEOPpArWCdVEyJ7mxHUEsZ8ADFKa
         HgJ9czMnoACSsNg3u806c1XQT2oT41yIcZZ86h3BNevLZd1nf8825xtLNZu0wMo8P0Gs
         JKe5p6jjTle6AWVYlH8oDmjLQN0aK8iIUoXLcgz10drM12Tt+XI6ChP+1grrZpIlRUPj
         htVaOv0U+Q0yXMTROZOM/NH6pHLQDIsWF56ospl4T5uT2+IuzB86QhMjFfpTRDrMFJvo
         p1tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fwAJsXkn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZev9IXUgIP3CMysene36NfZH/42N4IGXaIJJhSrUcM=;
        b=lDHWl4fnXIhZWu2fy8FtPrcHyMpySa6wfQkwmpvj+/wdR6z1boX26Ff7XRj24RBBnE
         MWyS4UW8A6t1jUHEG4/m91pCtHvJ9ckCO3u5BqLYp7Pglx/BxB4soe8DMVwTPyLS4/yy
         zjES4FWtaFOwZPc0Gyc4XJrDNik0Koyw4Q9J6OTufNc7amcqNZtKQPM3W+mxqRbtcwdo
         nnN4XTnO+NSmd5cFottDa6Mrg2oYHnvgSE00PXIsloSH0Ga21XDPTciSS9Wi2JRvMhCQ
         C577IgjVMuBCmSaEmRAXZ2DAF1DnAvzn5/ZbI7/5W0nfqn0Fs7aacTxO8g2D2mnbtHq9
         GFAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZev9IXUgIP3CMysene36NfZH/42N4IGXaIJJhSrUcM=;
        b=ASaoNC1kZFwvNgdD3M8yj5g80dIxS/6AtQO9q5EiWTUbGfB27AQ8g7y1P1y37mNOhO
         L7BwCBgp/UiiRLIEfuw+DFTFgijb1Gfz05CkAxGk+GIig/UFNbV3HTBGQlwaocmxuO5B
         oepjhKGjGmcWqmVhYUeMfey1PJV0ty1zIJaFmgkUbkWBrMMEZtM4B0+R1qwvOHUsIg3j
         FY4TBDFv3L//dtJq/WmF2h6dbTKOIrLOZxROJd+g899PPyyP1ExTlVti5Xetmf38Zjvu
         fOkS1TGsP1zWQpn7HYIYpZX+nN+uK0gv0FVk438b/27HfWnXBd7eCu4RLLfbKVdOwUlk
         vf4A==
X-Gm-Message-State: APjAAAVZiSysw8XV6/Ag78eleqQbbAGIVBCiOGMEn5JrV9Ti8dBwfsDW
	F2OwhnUStSiFYGCaGK5oe4g=
X-Google-Smtp-Source: APXvYqxY4pA22Vok5yZoVqTWEtyzx34BlpcLZgzgt5xZwtXqU8tWJuGWdwVkFtgJBDDftTusj75y/w==
X-Received: by 2002:a05:6214:1231:: with SMTP id p17mr14760308qvv.170.1570208509533;
        Fri, 04 Oct 2019 10:01:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:102:: with SMTP id e2ls1673531qtg.2.gmail; Fri, 04 Oct
 2019 10:01:49 -0700 (PDT)
X-Received: by 2002:ac8:6982:: with SMTP id o2mr16976020qtq.143.1570208509262;
        Fri, 04 Oct 2019 10:01:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570208509; cv=none;
        d=google.com; s=arc-20160816;
        b=Jov8p9iiCf7rBB9dtDS8NCWA4xr0QWAe9Jv1x6Fb2+rqQiq31TWicB+ZNQjHK+o4uh
         prOeBqwwjFp9CBGmu0dVTMB4RpjNmR7zb0CULcO8tXuilk1fY7rNXkixv+2DGawx2coN
         vO97jDUg2vHL8NxobUEukM8Fvbgg1SOtguFMpx+gdlcJW1g4MlGBUfdbKJ/hs0VwJv8l
         c8QY7HBnhHq01rVOTzwgKvYI8sE2tEa2LwEMa0h/1gFUiRrlc6A2YDiX4f+94/+3vGrO
         SmOLhIduaUBdZHjDb8moapjdSCX9hNju21ixpFofixHbZHaSs5+PmrY8YGvXPQz1S7Po
         XDOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7/+diOvmD2cdT3EOqXHZRXZjOjtDcKS88F8U+M4R9pI=;
        b=WiBfiVNVx2VBC+e4vsR5r0hHeipJBIBz59E+DibF/QBpE/sq4cQ0OkIgnlRPCivFIH
         Hejj+pauBqEYAaAfxd0+FonGOK0iuQrqxJ7giVMrzckmGnWW+iwERYjLqDm8XHHKfKPc
         V1lqQknAMQv3Mqq4dNjD4gvDFj0S/zTynm+rm9May6IDs9yH7V7BXk0hbtb1fVobkAFW
         dPnixf3aGlBnVCsB6Z4DmL3wGS94tt8k5qZIhVRnJc6rnWyZRN1G/asDJiFTaUX03CyJ
         ISiii8+RP/t9P6K/HprHO209vQcycO0hkAkyDrG7e4Al1BSwFA0IXQbs7dpp8GXmCWIc
         TrDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fwAJsXkn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id l4si378845qtl.1.2019.10.04.10.01.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 10:01:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id u40so9455439qth.11
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 10:01:49 -0700 (PDT)
X-Received: by 2002:ac8:76c6:: with SMTP id q6mr16725217qtr.158.1570208508546;
 Fri, 04 Oct 2019 10:01:48 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com> <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <20191004164859.GD253167@google.com> <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
 <20191004165736.GF253167@google.com>
In-Reply-To: <20191004165736.GF253167@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2019 19:01:37 +0200
Message-ID: <CACT4Y+aEHmbLin_5Od++WVqgiFX7hkjARGgVK0QUj7eUpFLVeg@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Joel Fernandes <joel@joelfernandes.org>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fwAJsXkn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Fri, Oct 4, 2019 at 6:57 PM Joel Fernandes <joel@joelfernandes.org> wrote:
>
> On Fri, Oct 04, 2019 at 06:52:49PM +0200, Dmitry Vyukov wrote:
> > On Fri, Oct 4, 2019 at 6:49 PM Joel Fernandes <joel@joelfernandes.org> wrote:
> > >
> > > On Wed, Oct 02, 2019 at 09:51:58PM +0200, Marco Elver wrote:
> > > > Hi Joel,
> > > >
> > > > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > > > >
> > > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > > Hi all,
> > > > > >
> > > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > > >
> > > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > > >
> > > > > > In the coming weeks we're planning to:
> > > > > > * Set up a syzkaller instance.
> > > > > > * Share the dashboard so that you can see the races that are found.
> > > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > > point it out and we'll prioritize that).
> > > > > >
> > > > > > There are a few open questions:
> > > > > > * The big one: most of the reported races are due to unmarked
> > > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > > to fix races might be required. Comments on how best to proceed are
> > > > > > welcome. We're aware that these are issues that have recently received
> > > > > > attention in the context of the LKMM
> > > > > > (https://lwn.net/Articles/793253/).
> > > > > > * How/when to upstream KCSAN?
> > > > >
> > > > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > > > one way of pruning is if the compiler generated different code with _ONCE
> > > > > annotations than what would have otherwise been generated. Is that still on
> > > > > the table, for the purposing of pruning the reports?
> > > >
> > > > This might be interesting at first, but it's not entirely clear how
> > > > feasible it is. It's also dangerous, because the real issue would be
> > > > ignored. It may be that one compiler version on a particular
> > > > architecture generates the same code, but any change in compiler or
> > > > architecture and this would no longer be true. Let me know if you have
> > > > any more ideas.
> > >
> > > My thought was this technique of looking at compiler generated code can be
> > > used for prioritization of the reports.  Have you tested it though? I think
> > > without testing such technique, we could not know how much of benefit (or
> > > lack thereof) there is to the issue.
> > >
> > > In fact, IIRC, the compiler generating different code with _ONCE annotation
> > > can be given as justification for patches doing such conversions.
> >
> >
> > We also should not forget about "missed mutex" races (e.g. unprotected
> > radix tree), which are much worse and higher priority than a missed
> > atomic annotation. If we look at codegen we may discard most of them
> > as non important.
>
> Sure. I was not asking to look at codegen as the only signal. But to use the
> signal for whatever it is worth.

But then we need other, stronger signals. We don't have any.
So if the codegen is the only one and it says "this is not important",
then we conclude "this is not important".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaEHmbLin_5Od%2B%2BWVqgiFX7hkjARGgVK0QUj7eUpFLVeg%40mail.gmail.com.
