Return-Path: <kasan-dev+bncBCMIZB7QWENRBJHI27WAKGQE2U3KDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1565C9F22
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 15:14:13 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id g15sf5198456ioc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 06:14:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570108452; cv=pass;
        d=google.com; s=arc-20160816;
        b=qpw6yDG7f3pRFs5yl3l/aZJ0I+WifNNWYyAgeYW98i2DcIVlySXLNW5R+tHW6o1nBa
         qLQrzwzBv3KhiXfq/z8HGiqfMiiIfiTxhYVeUCpeE6sN0wBTylZcgCvPMibNz6w2zitK
         ANylDpIGY9b2VP4X0fHO2ESt5vBqK4MyzK6KBTMfZxXPjQdrgltTWgsCSvjm0xtQpbfw
         KGVcps30ez9BfiqiZ7+XXdEoSKquSLEfS+rndom5Vch9QCYRTtokrEZiEf/5ZfKNojz/
         n5oNe4xyU4oyxWydej0tUxQ8OkLRrPJJL5wbw8dusn7q55SPM9RPi92LyS9VNlVR+5nO
         oZYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IByR1QI4gznOh/GnY1fDnCrD5J3VwMXHmaurTu2dgn4=;
        b=CE6COLw682fNSVf8lTi2Ib0uOTdpq4+Xu8mXzFWAn9S+lmDDwPh/BntXHTSukhfmQ9
         F+8x4ko+TE42WYXQ+ZYV8hqTrynfX4L/p0ge3Esa+q2QhOaTlpTWgvIxP3HMa1GcwUbB
         Wb8w+dRUqC/KWyMESt0OE0z9PS0K1TIEhviCYngDoJC+43fsH5/r3SmmqQSzPNzd+1m7
         gpfJffOLdXYrxp+uIQCv4oxkRDY6vTsOoEADdGCxdfUB5F1HH/QLEG0Zsamkg7UkAw8z
         vm+OHQgcB5UepSvdHJ2aFaD8PP5DyNMDrQyJwmXgK3Ggh03MjTFevQcdysTZP9P0cVcf
         vJ5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ux5nAYlQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IByR1QI4gznOh/GnY1fDnCrD5J3VwMXHmaurTu2dgn4=;
        b=L4yLtqp3FbaNyn6w+Y9G69JnuSKV/sqhPCUrepj04jpr6f/AhUEqwu+bYyz+G4GMFk
         MIMxHXQhCRxRaEzZcWjXgzUiInOhNzUHttPqFHArF6o5vdwdinaLAcvq3InkniltX8hl
         0lG4Yh21UB9nkJKGIziKuk39QvW8DQBJ+Aay+v/SEuuKluIbmh+Oj/tCBzxENadA8vV7
         ImCpVZz4cU/4Cwkg7tVyCwczyTslOhUA2ZE65E77/aJq9NoP9Ql9Smb0frZqvcb55FxG
         0HbGWWfAOY8gma1j2gNxLz0QsMa2eRDFTbrSMuhFdSxCuOSKZeFkCX7Pcj9nBHNNp6JK
         ezAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IByR1QI4gznOh/GnY1fDnCrD5J3VwMXHmaurTu2dgn4=;
        b=lmiK9tFtrLW/d4cxwuotb3DmxRkF87rp1D4TsfWBU9uTpRwpQ8wH1ojEvBEjfQHzAS
         LBEAcNA0d332ro2WlrHm4xI02XQKDlPEbxz45PYtiyTY6imcls0YGGUCL7KIDsZBUD+C
         GNHgpQh2aNGTr8svRHCt5S+ob2eWQdXd89jwiZUUZYYcRYl4Yxsj4tl3thTT1CHXgX5e
         Cf9bj3TKz3wDBUbzLM3gSXZ4KDT2X+YXzGxOIUyZeG3G0eFTweF5sA/BSS49ZyWmEd3b
         6S+saWLIZnMqUQkfOA/rbtlnjVQ2zsQdmYnDpfwdCnugvnrG5R5D+8Oz/QThxmuQHBxZ
         10tQ==
X-Gm-Message-State: APjAAAUE8b4eVhiypJfWivzgcD5rwOYRlTGfJ7NuvfKVUEN5J6hIoCst
	zGMSA+chxpjEZkfbnaWCaBI=
X-Google-Smtp-Source: APXvYqwhzLIcAVp1wO0d7lE0FlzXS+GybsMKjT8agTUIFvixa45b5g3r0uRnHfHlGPzIgQXRavzQ6Q==
X-Received: by 2002:a92:c989:: with SMTP id y9mr9658669iln.283.1570108452499;
        Thu, 03 Oct 2019 06:14:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c98a:: with SMTP id z132ls1205030iof.4.gmail; Thu, 03
 Oct 2019 06:14:12 -0700 (PDT)
X-Received: by 2002:a5e:aa09:: with SMTP id s9mr8322820ioe.22.1570108452082;
        Thu, 03 Oct 2019 06:14:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570108452; cv=none;
        d=google.com; s=arc-20160816;
        b=ShkBbnbQ0rJjhGP5Vs+gUawKq3VOQLVQnkyI/m+/G+Om+TRQVSGhUuticUoyG4KBEe
         FcYHw1DJiCTHAOQQ1OigOsIbIjlb611DSxMRA08hs6ZN0HQPVY/bw9jmU//TPzpGjizK
         kS3OR5DPNKrrGpA1mPcSZmVpNLBzLZQVuyP/MS7ja9V02rNx1KbJpfHb7fPlB2G/T4Gu
         RSmfX7VacQXJ6wzknq+Uigqrg1dBbCDxFtYdmCRGpc2b1kqrfu24pfxZAhohmbQD7IkU
         nesee1PS9UIwKpwkyXCdPMhEoNwoeu63vTj41gBQf4x6fiS0t6zNFU+q+H0CIom+t/20
         xcjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hjQvtW5KCBAhxkXZKBpTw3Thc1AXYBDLoKRUiQoeyvg=;
        b=nd0eFEpXuis4dcv1WwDIrVmydKK4QRrs6yn4y2wgCg3iftsQBVUYIFs4pjyvGleVA7
         lS4yFTsrdUkHspcfV3pzXbfjXz6qSNOyl8lPVePjnMVeoZC4L7lIiqlMjsf6JLSAi+jm
         mD4S6NJGmqks+JkxYtGJO9+Ni6wEtKFEiLPPfj792+0u6MkGrosMxDMQDS2y4ByaI2hf
         Z75j7gWdSoi3+uirqo4m/YvcVRp/XzokXoewLV9rZFPLYlpV+FqSLzdx9XoWyy4WqXQ8
         CJW3dEWlpf+7pz6+mh1r8yaf5mcjT3toFr+ndeE8kQDFXgnD0HNYAF3AVIJsAqU36UPx
         Iglw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ux5nAYlQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id b12si171746ile.2.2019.10.03.06.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2019 06:14:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id u22so3420300qtq.13
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2019 06:14:12 -0700 (PDT)
X-Received: by 2002:ac8:7642:: with SMTP id i2mr9488940qtr.57.1570108450446;
 Thu, 03 Oct 2019 06:14:10 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com> <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
In-Reply-To: <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Oct 2019 15:13:57 +0200
Message-ID: <CACT4Y+bNun9zAcUEAm9TC6C_e9W9dd3+Eq9GwPWun1zzQOtHAg@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Marco Elver <elver@google.com>
Cc: Joel Fernandes <joel@joelfernandes.org>, kasan-dev <kasan-dev@googlegroups.com>, 
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
 header.i=@google.com header.s=20161025 header.b=Ux5nAYlQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Wed, Oct 2, 2019 at 9:52 PM Marco Elver <elver@google.com> wrote:
>
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
>
> Best,
> -- Marco
>
> > Also appreciate a CC on future patches as well.
> >
> > thanks,
> >
> >  - Joel
> >
> >
> > >
> > > Feel free to test and send feedback.

FYI https://twitter.com/grsecurity/status/1179736828880048128 :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbNun9zAcUEAm9TC6C_e9W9dd3%2BEq9GwPWun1zzQOtHAg%40mail.gmail.com.
