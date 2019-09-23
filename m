Return-Path: <kasan-dev+bncBC6LHPWNU4DBBOMQULWAKGQE3SC2PJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C749CBB008
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 10:54:18 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id f6sf6908581oti.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 01:54:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569228857; cv=pass;
        d=google.com; s=arc-20160816;
        b=bxcI6Rtk+x8d9637bpHz3auvwgrmEUCrvogPdkeSs2kRSHETRK5cHbU9XuBE30Faz2
         7bySvWapDu13Iy8l0EBH8mNqVzskgvwanfqidAv7pM3+1hBRNawFxOqW52YO3J01QGBT
         lIrPVsfS2U90PTE+xoTpnGFN1m/UN1T+tmmg43Qqejl8P7orfx1dlUouQamdIKCSA8Rj
         lx71RzQz7ZsVLMTjM50oCtscO7tfKgr1bFsJsPoKUzVz0R6H2kVCXg2qGr4FjBoAYFDb
         ZHf/Yn2qhgYblC85im1Tb3jjYuQjtui+7Ie9HJbIRmDTup6CDQwTzrOGO8ChGcb2HiBR
         ZhJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=vLWm0GG095ah5c6L2NwGlhIGCrMjs35vO7XMFXhMsT8=;
        b=LP5Zf1l8eONr1uWcqW9eoFcabJOZWMXRx9kuwkPBsbvOgP6uAuba1n/bqgLBB/D5rC
         EwkgT5muz5Q7o3tYB5B7DXLC3PRl1ZSeP1AUDcUBw7HNnt/065+t5tXHzgvrix+XWLtR
         0fWZXVM8TUADuf5hl3gH6GuqeZ0mPNCaGgjbUiUqRaxX0HQkrW7vLDPfwB2d4r3xKZ74
         vD+2mXbMnRKZeI+8lVBMO+rN3q7JF7QEqwne0Bv+S0pzMiFhInFADoCklJ43poor2hLy
         V6oZIFTmEYpc9EHrZZpKbFOTLyUhRfZ5lfDHIP2CiZ8yAu2jp21PR4/dlHJylfmF5EjQ
         2afw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=CjgRm9zM;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vLWm0GG095ah5c6L2NwGlhIGCrMjs35vO7XMFXhMsT8=;
        b=YfZufX2ukdeYC4uQEJq0ZWNkFJQwt8C1vcCdHInhxrNAB8AwqwLVSxGruiOCQwa18Z
         huYyDXNmnkb7ZWrmzpRXZz9cl3W88PcnhEADZD+QMvxzoSe8u9cANZ9X9BCIhkmtyafG
         nsi2CGahVixa/rqSkD63EjzNDZRP4n92rUC90JzIGP0qVFEJVkBao5R47nA7hmxAwOBx
         z5AzNQpds8hqdiQWwzL35wW0YYG5IQ1E3RHRuUj0L+/Ux2ZfdTjIZlcbyF54A9zTLj/y
         RZPQjjXwuvbyDPpC8lybqXnNO0xxbmp8y3MZ+CZ7i+DrnL2WPcbJ7VvIgga+4JbGQubK
         nWsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vLWm0GG095ah5c6L2NwGlhIGCrMjs35vO7XMFXhMsT8=;
        b=hbrFsQiZhjTXA9r5lKCdQ+hf7yOg5XN8BtxHcpEKuvLTEgCMiBOl6qzauhHOsLN+yv
         fdDQkORroMw0N/SesCJljBWMwOtN3v60soC6BdnEeifzXGxaERp9AvUMzLw+AuMMFD+x
         C5LmO3YYeDgldw4+9SV8oM4HwAP8V+RsbVjRzdg7N9jJdPeeEhrV3EBPiv8Bgt17pGhZ
         c0pRquRNuLorMcuNFpEM016EeJdGYKEPdej2e1xxDQuJO0OPLL6EkSWjYLMXzz1Amlrt
         wSwp04BXDD9jjkDElA0xv6xN7/MtHj12r2m5ihrKFczcmM76EQhdS7zJ2EXmKCa9/rKI
         sbGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vLWm0GG095ah5c6L2NwGlhIGCrMjs35vO7XMFXhMsT8=;
        b=qkM21wzYF8+CkmOTUcYc+OTnBwmFfNB7//Kg1XyAiicc4NwjG50MZPYIonRID8r3fS
         vQI7/djne1VU7UYTZYNsJlKotUZhqGLW+G0W+Tq0KGstNs6VNf4gfsbGPE3i6zSDdf3e
         Ji1TkTT3KlykAgHXPCSvX2t+3RLCTquygjqio02nKy3CeaCHVHAiX9dxt64aYSlwQ7NY
         TrQRsYUqnSAP35Tx7WrWvJJDYFPR9zao5EBun7h6WG+3Q/M1A4V/V7ADmt8p5vLx+xjK
         Smxq2pq3Ey2TePvN8b00DHuU91ypS2ibtofGy/BELpvHZyMJmKc5I/rULLn9/InM1E8+
         E16Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOFo8Ww1ukRpMyICCHpDkuTaMZFMK7Wws7YLo2MXYo1VKdiUnY
	TdR0YoGqVxZVBmVGkiO0qCU=
X-Google-Smtp-Source: APXvYqzfAOTHxWj3lnWxp2+N43kMY1LWR6zXabgyh92c5ukBcNMxZczEHK4LALS8ARs3ycGfamJicw==
X-Received: by 2002:a9d:7450:: with SMTP id p16mr2165392otk.141.1569228857449;
        Mon, 23 Sep 2019 01:54:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c42:: with SMTP id f60ls2827353otb.8.gmail; Mon, 23 Sep
 2019 01:54:17 -0700 (PDT)
X-Received: by 2002:a9d:3424:: with SMTP id v33mr21407959otb.162.1569228857207;
        Mon, 23 Sep 2019 01:54:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569228857; cv=none;
        d=google.com; s=arc-20160816;
        b=BYgsUSz6hWkO6kCyD6OGdE/H0sBzeSL6PlqXcljdd3VpKMVC2lX5whQ6J8j3CkDMCN
         d+WNpz7s69D2rlxJoGq72jpMiXAUX9vSK3Rw6ezzhbxMRmSf/Tf0VuggvT7nLosQ8U/L
         18ux5yAN4Z5md9pCg1diL4G1nlieNDpMajYiiVquaicXuQ7NLIwtzGLpqsHrDTdyWWag
         YWcLxTUPsPDTfkFg5f2TNwcjtD9cG/2/XdHeH9UGBOlD6XmYFgeiYlegrXtJCc2obAGO
         3RPqMYR/mG8ITNDhXU4uNtRR3Zx6V5Ts0rjdn5Y2v4XtxhTab58MZ7sId4TjIcbAOpuc
         5IJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2HTTegD4xnUb2DPrlY/Y5rzaeP5y5DbCzcsegVnbQgA=;
        b=iQ4XR87kQGWZA39eDMOWpJF/f8HNZEtoiD0qCWNDv9etvWz/0rvkqpXi5AWGgAOfDA
         heScgk+9sbq6si4ongEoDNwdRRK1R4DqtRF+RakAh59VWuugM5GyZ95MbKR2b5hHDk5X
         XjCOYcMQk7NpjFt1PjxU71zDyhUPBPjxki/ooD0SeHdvX1IQl4wnHjl6JtuA/PvhH6cB
         oiPcTtGk3fHXaAqspkMMdx9iY4KIJO3e9ipEvHTCNz+9KbIGfrZ8vQwFxLrUcgRpNkAa
         TGUdgH3qsx6jvdxixAgAlG5I0e3pUduJx2L+X/fE3fYJYsuZ29Bvs15LChjMNz/AOh0W
         C/Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=CjgRm9zM;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id k198si512920oib.4.2019.09.23.01.54.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Sep 2019 01:54:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w14so11743646qto.9
        for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2019 01:54:17 -0700 (PDT)
X-Received: by 2002:a0c:aadb:: with SMTP id g27mr23296635qvb.149.1569228856661;
        Mon, 23 Sep 2019 01:54:16 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id h184sm4929661qkf.89.2019.09.23.01.54.15
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Sep 2019 01:54:15 -0700 (PDT)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id CAE6E22340;
	Mon, 23 Sep 2019 04:54:14 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute6.internal (MEProxy); Mon, 23 Sep 2019 04:54:14 -0400
X-ME-Sender: <xms:NYiIXdiVLRkTw8ju_fEG5N8fv9Qrl9XuEcc_aQEmoir3gE_bBntPZg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedufedrvdekgddtkecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujggfsehgtderredtredvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuffhomhgrih
    hnpehgihhthhhusgdrtghomhdpuhhsvghnihigrdhorhhgpdhlfihnrdhnvghtnecukfhp
    peeghedrfedvrdduvdekrddutdelnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquh
    hnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudej
    jeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrd
    hnrghmvgenucevlhhushhtvghrufhiiigvpedt
X-ME-Proxy: <xmx:NYiIXcoMqaEGdCLyukkqIKZpbt29sNk6G2aDvhssACUWH0YwD7nukg>
    <xmx:NYiIXTGkUb752-vBAJansb_FJ5igS68D5xVuMs5p30XWG8Ble7lagg>
    <xmx:NYiIXR7reQauwbMGobl7NgODOxX1_K3PNh-YEAVRIs10v2ZoF8270w>
    <xmx:NoiIXQPqQ6waDEnuc3cd-wTtT6odV9HIJt0aUQ29thVCrMlpDMVkvJo2JIs>
Received: from localhost (unknown [45.32.128.109])
	by mail.messagingengine.com (Postfix) with ESMTPA id 36FD680065;
	Mon, 23 Sep 2019 04:54:13 -0400 (EDT)
Date: Mon, 23 Sep 2019 16:54:09 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20190923085409.GB1080@tardis>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
 <20190923043113.GA1080@tardis>
 <CACT4Y+a8qwBA_cHfZXFyO=E8qt2dFwy-ahy=cd66KcvFbpcyZQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="mojUlQ0s9EVzWg2t"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a8qwBA_cHfZXFyO=E8qt2dFwy-ahy=cd66KcvFbpcyZQ@mail.gmail.com>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=CjgRm9zM;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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


--mojUlQ0s9EVzWg2t
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Mon, Sep 23, 2019 at 10:21:38AM +0200, Dmitry Vyukov wrote:
> On Mon, Sep 23, 2019 at 6:31 AM Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > On Fri, Sep 20, 2019 at 04:54:21PM +0100, Will Deacon wrote:
> > > Hi Marco,
> > >
> > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > We would like to share a new data-race detector for the Linux kernel:
> > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > >
> > > > To those of you who we mentioned at LPC that we're working on a
> > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > >
> > > Oh, spiffy!
> > >
> > > > In the coming weeks we're planning to:
> > > > * Set up a syzkaller instance.
> > > > * Share the dashboard so that you can see the races that are found.
> > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > point it out and we'll prioritize that).
> > >
> > > Curious: do you take into account things like alignment and/or access size
> > > when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> > > naturally aligned accesses for which __native_word() is true?
> > >
> > > > There are a few open questions:
> > > > * The big one: most of the reported races are due to unmarked
> > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > to fix races might be required. Comments on how best to proceed are
> > > > welcome. We're aware that these are issues that have recently received
> > > > attention in the context of the LKMM
> > > > (https://lwn.net/Articles/793253/).
> > >
> > > This one is tricky. What I think we need to avoid is an onslaught of
> > > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > > code being modified. My worry is that Joe Developer is eager to get their
> > > first patch into the kernel, so runs this tool and starts spamming
> > > maintainers with these things to the point that they start ignoring KCSAN
> > > reports altogether because of the time they take up.
> > >
> > > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > > to have a comment describing the racy access, a bit like we do for memory
> > > barriers. Another possibility would be to use atomic_t more widely if
> > > there is genuine concurrency involved.
> > >
> >
> > Instead of commenting READ_ONCE/WRITE_ONCE()s, how about adding
> > anotations for data fields/variables that might be accessed without
> > holding a lock? Because if all accesses to a variable are protected by
> > proper locks, we mostly don't need to worry about data races caused by
> > not using READ_ONCE/WRITE_ONCE(). Bad things happen when we write to a
> > variable using locks but read it outside a lock critical section for
> > better performance, for example, rcu_node::qsmask. I'm thinking so maybe
> > we can introduce a new annotation similar to __rcu, maybe call it
> > __lockfree ;-) as follow:
> >
> >         struct rcu_node {
> >                 ...
> >                 unsigned long __lockfree qsmask;
> >                 ...
> >         }
> >
> > , and __lockfree indicates that by design the maintainer of this data
> > structure or variable believe there will be accesses outside lock
> > critical sections. Note that not all accesses to __lockfree field, need
> > to be READ_ONCE/WRITE_ONCE(), if the developer manages to build a
> > complex but working wake/wait state machine so that it could not be
> > accessed in the same time, READ_ONCE()/WRITE_ONCE() is not needed.
> >
> > If we have such an annotation, I think it won't be hard for configuring
> > KCSAN to only examine accesses to variables with this annotation. Also
> > this annotation could help other checkers in the future.
> >
> > If KCSAN (at the least the upstream version) only check accesses with
> > such an anotation, "spamming with KCSAN warnings/fixes" will be the
> > choice of each maintainer ;-)
> >
> > Thoughts?
> 
> But doesn't this defeat the main goal of any race detector -- finding
> concurrent accesses to complex data structures, e.g. forgotten
> spinlock around rbtree manipulation? Since rbtree is not meant to
> concurrent accesses, it won't have __lockfree annotation, and thus we
> will ignore races on it...

Maybe, but for forgotten locks detection, we already have lockdep and
also sparse can help a little. Having a __lockfree annotation could be
benefical for KCSAN to focus on checking the accesses whose race
conditions could only be detected by KCSAN at this time. I think this
could help KCSAN find problem more easily (and fast).

Out of curiosity, does KCSAN ever find a problem with forgotten locks
involved? I didn't see any in the -with-fixes branch (that's
understandable, given the seriousness, the fixes of this kind of
problems could already be submitted to upstream once KCSAN found it.)

Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190923085409.GB1080%40tardis.

--mojUlQ0s9EVzWg2t
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEj5IosQTPz8XU1wRHSXnow7UH+rgFAl2IiCkACgkQSXnow7UH
+rhPFgf/TJZhR+De2cHda5tb/9QSVnk0DgSAkdDkEBpDiafGVUPPv02aDRzknBML
60CgOciTh/CBR83TpFvZvc/WWLp42pQHxySeO+ATFAaH9ayaH7CeNE4ZjpRZPoUG
1+i2B1/cO6e4XPEig9Dq6CuObYEdNRZyLmIk4VZUf9/bvIAHjC9A6qNQ+52vY7mj
jnf3N2bR/ni2aTI+meIybbaKpW7tCLsRmD9ZgWIAu9q+KEUuien0Zfa6CK6Qt8yF
ZGVw/P4fRQgivOj7+7j1kFnx0SiRgZYNjdmsjmdbCbT/Dtgu6SZUR2RO8u/p4meI
V6OeAnxTbYGrf5CKGSQwceqhxpiXyA==
=F7nQ
-----END PGP SIGNATURE-----

--mojUlQ0s9EVzWg2t--
