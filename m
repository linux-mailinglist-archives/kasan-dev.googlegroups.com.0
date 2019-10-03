Return-Path: <kasan-dev+bncBCMIZB7QWENRBNFW3DWAKGQEKIEA7HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 210B2CA1EA
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 18:00:54 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id x31sf2259228pgl.12
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 09:00:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570118452; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIj2FnBwo6i1G/+/ozQruFOExl/pkUdUL8pGLuJoBNTrPJmoZrgxku0HjSvfzO87d7
         yvPOas3AzYJ1bIjx/vPUvIdOCXbgE4tHxaK894/gVxa/oNTUD4ittmMMLc+qlvoTxWvP
         1uOQKl8R/JzMUbo31Xw53hnDQQXmXd6TxTcs3WhEE5EZsmUozWPQ+ni5YHJeenpNYbe5
         q+84ke7AQyKE93BW6iH3Va0ja28ZAy7jn7KFtNliZCBz8si4RicAe8UAMUqO/jlZ+PKK
         Iu1mD6COqJlJQTICeXOCXcn8XL5keN/7aoUL42uLXhLBGCwyuDRsuDRb2TZPglSwhZbP
         KShw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HO6Jpdl/RmkH5IxJf2CSbziFgbBXSfZWo3a27srKL0w=;
        b=SBuG/X7biT0DLM7kXVVZ7AlEDV4jrDl2pK8sUEyV4cX7kwPAOmaWTSRFhkPrsOCdkf
         0vhrTp9hdUWzLiUXKQjwp8Ke8SIpTsThVKUaz/L44KHB51zeqMoquOPml7WWYDUFSsjX
         jD5CcZN8l3IEG8h8OsdLF8rHW9g3cZhWGRrRfbRP1MG4QPAUEfPwE/8FOnGME8+cbEn8
         w1ybwlmPYK7DHdoTXwKob4DzHnk+2+Dm3GhsIxPLz574VqVlnu47TU4dTxjokt69wm97
         oRk+I015GtMIa5B5SDm+hXb47z/pzftGfcRXrxxrNttw/GZhA7DFB7qoarmLfZXcU6El
         W0EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n69rlZo+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HO6Jpdl/RmkH5IxJf2CSbziFgbBXSfZWo3a27srKL0w=;
        b=jzG2+RPFz8crPDvxBpQIJyCRd7zdJWfz1OnQxMSSGMXniIRrfapaq/YaesvSq+jXSi
         eDeb+3UNvphHzcvpkivfNrUcZEukHWcCRcalKd9fqugPeG9DiWAIRaDBSemwI/hqshBl
         it6cCvYk52HxfDthDpKYTIFm0j7T/Ie+HAq7QR5YaROFFCmnGZS0uRwPAv1G7opzcNkM
         vZvE20gmp0aIpsIGybyXj/SLEb5gfQPZSQ7qo9GsfvmKzuI8rY0HXqO6hnPLJ5YVhT2T
         486j5YJgjNma+PUxZoQVy1Jxtjd6KmjPfhOUVJCFNbDXYMhUWJJ1zIz02PLcI6z7gLPb
         5atQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HO6Jpdl/RmkH5IxJf2CSbziFgbBXSfZWo3a27srKL0w=;
        b=T02fQkxxKw4vRA8LlTY7v+Nl7cmcek+7rZZUn8rLGAfMD1tZ15Vn2HKQZtnQZpvxLz
         sa3whXmHJ81hnGrSOhBAfWEzQyY3/Yv8hXqN5sU8wwW6za6oCzzvSVJio/Ev2g4v9LWi
         L9s0MpJLqgfZRgjG4K/J/0ZmQ2uUierf07tFke88rl9X5px6U1sabjkDZlfmOr1JAqvp
         qcM9tgwiVjlZPVO2rqXKIpOVtwMBiP4uzXwyoThFmwAnrl4j+N3Swu8CMvCzP9L4EGyS
         /SmUQCas1anF4ziw2pStdu+R6KrXlGDIZLgEbLNAnSyVuD/81CoTQFirALttgYoPoHN1
         sYCg==
X-Gm-Message-State: APjAAAVe+vfDaftjdk10coMSJfdD2aZ+Jdkoz8D3Efd1xExctU7xpmAf
	ZJSg6a/O2TS/FnB+u9cMbHc=
X-Google-Smtp-Source: APXvYqxpXeqmAEFCIFwkjZddPSRufXmVw4NWCkHwVVsi703DVfS91WjOZPAAhHCAiOadq0AaEooYMQ==
X-Received: by 2002:aa7:9210:: with SMTP id 16mr11733495pfo.19.1570118452567;
        Thu, 03 Oct 2019 09:00:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls1622216pfb.2.gmail; Thu, 03 Oct
 2019 09:00:52 -0700 (PDT)
X-Received: by 2002:a63:5552:: with SMTP id f18mr223370pgm.437.1570118451977;
        Thu, 03 Oct 2019 09:00:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570118451; cv=none;
        d=google.com; s=arc-20160816;
        b=lG4dUY21DSJA+XdqbC/UL5GmBGIgh9kxvb82Rh5zQ794O4r1B2W4Cmrpr3it+WVSYG
         6pwmdJD/eCfeVf4nKKaGXkTAteg4Bj9hpTQAVtnVGcn5AkqITOZrknaGaQ0X6fHGqdmw
         a1aOF+/RwizCeotoyIvZfOjYRFIxCpEWfB1NuNYqNrP4475kYu/5oCSXPMsoIAHj9ZAS
         p+Sapg3QdhdwhdN8rOA+KXifXKh2BEOZW9ImTP6/6UQ4GY/+W/S/QTmXjbbDGgo69vw0
         BlONOI2GN52j7kBbRnnDXiOb5e2iL/XKRlEseyfIYVmAEsdSRclqpFJy4jvbMKiXKCk0
         zmTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WHlhVUvFqch680wlgcRKCc65z2j3hwVlcjsPrmD0yPY=;
        b=cET+cL42cpiKzybaruIvqW2kSsUrrHD5CLKnhBP/5hXiBzQvUdFiTT2bEYKcUxJvVc
         IIR78hD/5uNw48FFjHDj3NWcHxlAhyVw1ud4P8mlVfWdMYjxKFRM8bPC1sw5vwnxf1Ra
         X0fguTnLWtt9cHECUqV4g1XEEByTu505BJLlvDg3h8esRQxC2NntJcvHa/4oiOcK9ul8
         y5w4xOYo8sj05EH2jqDh4zF3GERkERHSchazX/M093B9/8m1Ar5hQTLD/BoK1urM43Vu
         cDr+zxcLwt5XxMY4x7JMykGZ9/DhecIw498hWwEX1bNtQHqg2ly1W9hpjrE15T/fubfE
         3p6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n69rlZo+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id e6si140853pjp.2.2019.10.03.09.00.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2019 09:00:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id c21so4249189qtj.12
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2019 09:00:51 -0700 (PDT)
X-Received: by 2002:ac8:7642:: with SMTP id i2mr10304461qtr.57.1570118450459;
 Thu, 03 Oct 2019 09:00:50 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com> <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <CACT4Y+bNun9zAcUEAm9TC6C_e9W9dd3+Eq9GwPWun1zzQOtHAg@mail.gmail.com>
In-Reply-To: <CACT4Y+bNun9zAcUEAm9TC6C_e9W9dd3+Eq9GwPWun1zzQOtHAg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Oct 2019 18:00:38 +0200
Message-ID: <CACT4Y+Zaz9+t6LDW5csyezeHQ+whM-wPcta+REa0ESDj4JXPGQ@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Marco Elver <elver@google.com>, Christian Brauner <christian@brauner.io>
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
 header.i=@google.com header.s=20161025 header.b=n69rlZo+;       spf=pass
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

On Thu, Oct 3, 2019 at 3:13 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Oct 2, 2019 at 9:52 PM Marco Elver <elver@google.com> wrote:
> >
> > Hi Joel,
> >
> > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > >
> > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > Hi all,
> > > >
> > > > We would like to share a new data-race detector for the Linux kernel:
> > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > >
> > > > To those of you who we mentioned at LPC that we're working on a
> > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > >
> > > > In the coming weeks we're planning to:
> > > > * Set up a syzkaller instance.
> > > > * Share the dashboard so that you can see the races that are found.
> > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > point it out and we'll prioritize that).
> > > >
> > > > There are a few open questions:
> > > > * The big one: most of the reported races are due to unmarked
> > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > to fix races might be required. Comments on how best to proceed are
> > > > welcome. We're aware that these are issues that have recently received
> > > > attention in the context of the LKMM
> > > > (https://lwn.net/Articles/793253/).
> > > > * How/when to upstream KCSAN?
> > >
> > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > one way of pruning is if the compiler generated different code with _ONCE
> > > annotations than what would have otherwise been generated. Is that still on
> > > the table, for the purposing of pruning the reports?
> >
> > This might be interesting at first, but it's not entirely clear how
> > feasible it is. It's also dangerous, because the real issue would be
> > ignored. It may be that one compiler version on a particular
> > architecture generates the same code, but any change in compiler or
> > architecture and this would no longer be true. Let me know if you have
> > any more ideas.
> >
> > Best,
> > -- Marco
> >
> > > Also appreciate a CC on future patches as well.
> > >
> > > thanks,
> > >
> > >  - Joel
> > >
> > >
> > > >
> > > > Feel free to test and send feedback.
>
> FYI https://twitter.com/grsecurity/status/1179736828880048128 :)

+Christian opts in for _all_ reports for
kernel/{fork,exit,pid,signal}.c and friends.
Just wanted it to be written down for future reference :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZaz9%2Bt6LDW5csyezeHQ%2BwhM-wPcta%2BREa0ESDj4JXPGQ%40mail.gmail.com.
