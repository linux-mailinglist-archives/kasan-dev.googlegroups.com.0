Return-Path: <kasan-dev+bncBC6LHPWNU4DBBLMC7SFAMGQEM7XTYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BA6C425522
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 16:16:14 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id w26-20020a056808091a00b0027630e0f24asf3578236oih.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 07:16:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633616173; cv=pass;
        d=google.com; s=arc-20160816;
        b=oBmyLhIGUNoHD8uK4P/PQhfjD9mmhaErvHQLrpRMyx1TgAm25wE9+8CkDxryGfMS+c
         JMUck6MGnSF9+lPwTJ6Wz+ymwowCgnc81SwXEcCV9N7LBol4E0EcqZxrBUTmYhU24bu0
         8jpwG92KcM+mKlrlu+/jvGq//ACrDGX/BrWA9cIZX6OVDPhQn12+OdIuG8aZxWril94J
         fX7BMIvDqkZV9wa9/1ivSurUCbGPMiqPyy6+IV34yixxD9C71hp1m8sMr98w3uMi2azV
         R+hutj63gIXXsxlAktGJ0lxkubLWaLcfdpHLcWUcP0b6RVQgFNjQ/Ln6kIsiicn2EfgH
         mOfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=e606QGg+/iRn2qelNOmZk5+QAHOLQnhXfoHe+9bjr9w=;
        b=xi6ffjJVAfn/Q6wGBiFNzWyZOw2/s8Jg3rlEkpmTcb39HLtlIP8cIrs2eL3b6CIf/y
         w3yLtVNzBrVLYFj/zaTWdJB9X+vLDxZBbKPGCsbzNwdoifwQFYbX323aVA8/702aLgBU
         lXUri7e2Ou9/dXYnj7I91i4DqvnrDA99wgN+5ABg/uCdPHx5ES6K6YFRFn0TsgzQmrvB
         P6Mf4n/ZygEIbfgA6/IUhL5IuomBcPzingNK98XykFtWUdGn7nISGtXAhO/cTJmJxP6y
         8yV48HzXy+Wc6tY2zB6uQzFTPqFU8xqKQjXAs1rO5K+fpEcSceahbE7RXom6PjNehWI1
         +Xeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EkiY7tK+;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e606QGg+/iRn2qelNOmZk5+QAHOLQnhXfoHe+9bjr9w=;
        b=Fib6Jbpa8k7tydEG3mYbAc2iYe3DhEoh/WUVkM1C7slcgTOU7jBjpgnk9ntnx62JeM
         H2QrSum9p9SAAUxO4qxxOqlMqYr7U3tMu6vGIxQmgZjuooPVoOWq42vh0wj4ZoHNllKg
         sLQ4Huitvxz+rcnpcTdIvuuzBJS349RCnOoUGLzsOz85lQ2bd7hMvzku6cP/+OFOxsDH
         tOFzjpmg16bqPr2v7ocvRnWmpWV4QM0RmYe2WHMksG5mPo4RRKQbglEFQB7pcG2Dls1H
         EzXaqNC6pXDx2H3FnFnzTrFpIc5VM+29hsHuU6zCcrHD/qecHgQ++zhQwkPQ/i72T2Th
         3A6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e606QGg+/iRn2qelNOmZk5+QAHOLQnhXfoHe+9bjr9w=;
        b=lTY7GvsiJZGKvsAQJPSSrTgJEQM59rzV/KR6VyWhS1egpeT6FyqREvLf6ABRLocGgi
         tCmSWJwgcIb9uzsAqA6u6FnK8a1uxA50D78Xg1eT9xcls7uTBP1OwPW/krrssKcPRzq9
         irHXg1STSnaXxZbw6qi83jZUlSNl7jujA4aLX4lRuezDjOpTGmXXdeqJ4Mx1c+f0JD54
         eNaxhFMT6uOhUyHePIhD7kQVGOlCleygqOnzpO/GvFRYgWSR1JwipF6Uxcv56UABOGvY
         bi//NIuHBVIEkwSNrOf3Iurl/YsdJqHngX+lJwLDAwhz65Ae+/hJahUdCN4h/TF+T37m
         rsXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e606QGg+/iRn2qelNOmZk5+QAHOLQnhXfoHe+9bjr9w=;
        b=KoZpooDBkwLtFSADREjTvNgy4OPvuC9LWY0vOXywXk7Gs4gS7htwSQC9FI3T3rEbho
         yBcuVs/4H/oVfqXYaVitmOLHFjnuxpe2mqq3Jlk9ovyJYRcEcXBmfq7VJSv1V0a6PuHC
         Y6MJUeGaEdCpvvsytuLTGgHBUjuEhuODpmW1O3D3k+447XpsDTJOKlOEo2L968QKEwvL
         7FMUG4jiIoV7t/YOC4yB50QARFuX5eRJq2bdG/dLblcAJHSTbCB7JIFDrioEedKGxHvV
         PyxELZfoLOQW1J5MTi3xuP5Vt5QQF58qbLLwcN3Fb9xDian5Dpx1b07nKHUV80Wj+TjX
         Pskg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pCxlgPZu95TQ8U/e+hchMJvs9tZTNxpF6XZNk4TyJshfXAVRN
	m9zauxhD4rgq1Ih5IYBdBDY=
X-Google-Smtp-Source: ABdhPJx0IwoJtHhU7DMsmZxzhu6U1kNMURRc+SoNdlWtplPg5JnVv8UnSFb1sHK+55kCfpgLr7aEGg==
X-Received: by 2002:a9d:4618:: with SMTP id y24mr3731401ote.326.1633616173049;
        Thu, 07 Oct 2021 07:16:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2f5:: with SMTP id r21ls9733ote.3.gmail; Thu, 07
 Oct 2021 07:16:12 -0700 (PDT)
X-Received: by 2002:a05:6830:4095:: with SMTP id x21mr3784582ott.352.1633616172632;
        Thu, 07 Oct 2021 07:16:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633616172; cv=none;
        d=google.com; s=arc-20160816;
        b=qdAhg1Z62AMA8Pj+Dswr/55Zs4JSjwmGfsE/EpOvYu1YAnqcOABumNUfCMmo+V0KfX
         WE9BwEcbH3U1trPGLvyzFniMgY0KhLG2tapYNfqxoH8z3pw3Yj78kGk4ZgyEIiLwhoYE
         MmPvtwbWdkpERTFT5l9zbdDQcr8PKntlbnP6GEBNK2BtkXHBkHHHXIm/rL642DzKY+mr
         x85QsrXDDzKWWaOx+mKyLzFYU/aZahdOq5uLXoNuxkdx9JBWEZZD2/nczUI+EKsp6iZr
         k31Lh1I8dAuYEW77M3roA6symAKWWfQ0WeX/M73qTxJVC8LDqS7Rb5WntlkAEN4rv9mr
         hELA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CqmpeBKXPeCWG5yhm1g9in1p1BGDIrI8z6UPDnu3A0M=;
        b=U2CzN9pEEZu816jEobmIv4DmetR8fO/G6QIOmS8dmr0Ik3VWFdvPGtRZOZ1zZa6Wqb
         L8rnfRnvzj9eU+hyga/HJ70pUSlcP6LJhk7X9UF9OgFgEe/ddvz8DIeQfSiNW8rtXJMc
         kZx3znf7Df4T/oyoG0qBKcyw7ptx18N8zXB6OXGid9jp/NlJF8r7Fyf6lwbTrNqLJjg0
         2kWcRkqW7Ed49IxLWZTPs4crMEeMfrbZ2cjYkWGwfLApkcUt7pLpjkdcuT9qdldYBkvo
         BQVhZQm2mLeo+pN5WN+aoZD6MfJu06YSu+EPCZnLjM1zicQmpgE7fqNsQBttOs/0NfF7
         MFEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EkiY7tK+;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id bj8si3076270oib.1.2021.10.07.07.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 07:16:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id 77so4866656qkh.6
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 07:16:12 -0700 (PDT)
X-Received: by 2002:a37:9cd0:: with SMTP id f199mr3502256qke.499.1633616171690;
        Thu, 07 Oct 2021 07:16:11 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id m27sm13466456qkm.57.2021.10.07.07.16.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Oct 2021 07:16:10 -0700 (PDT)
Received: from compute3.internal (compute3.nyi.internal [10.202.2.43])
	by mailauth.nyi.internal (Postfix) with ESMTP id C7DBC27C005B;
	Thu,  7 Oct 2021 10:16:08 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute3.internal (MEProxy); Thu, 07 Oct 2021 10:16:09 -0400
X-ME-Sender: <xms:KAFfYQv85wA3-KUbu1G4osk3h2ahqRVu3egJBfBEWZAqpqyRNbQllA>
    <xme:KAFfYddOUvt9KDvC68QQK9RdZxLWi2TMVwiAUbjcwTRZ6NcHtU0AUj4eGaFGOdkM9
    ZF0omy59oTvXaFP9A>
X-ME-Received: <xmr:KAFfYbwTdQzQQkyoNLjNH89CsLytcMlyOr4dp6WivKoUekHy5CvNkR5brVY>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvtddrudelkedgjeefucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    goufhushhpvggtthffohhmrghinhculdegledmnecujfgurhepfffhvffukfhfgggtuggj
    sehttdertddttddvnecuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvg
    hnghesghhmrghilhdrtghomheqnecuggftrfgrthhtvghrnhepudfhlefgvdfhieejheev
    heeghfdtjeekfeehgfegheeitdefveevtdevveeghfevnecuffhomhgrihhnpehlihhvvg
    hjohhurhhnrghlrdgtohhmpdhruhhsthdqlhgrnhhgrdhorhhgpdhllhhvmhdrohhrghen
    ucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquh
    hnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudej
    jeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrd
    hnrghmvg
X-ME-Proxy: <xmx:KAFfYTO7x_u78xpMjaGJN1S7mj_mkX77GWyc338kA1krO5RiMbiyBg>
    <xmx:KAFfYQ9Lgq-9WBCdX7n2VpkcABckbNXoCIG6InQDgV_rSnXudMxZvw>
    <xmx:KAFfYbULpH41YRMC3fOb2itpJiLnfKDcOGvWYz1Ta-tx8-6ht4tG0g>
    <xmx:KAFfYfZSPDjtqbPPz-RyfxO3DxqnGuFulZ_gSu9Lfpix8S8HKmgREg>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Thu,
 7 Oct 2021 10:16:08 -0400 (EDT)
Date: Thu, 7 Oct 2021 22:15:02 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux@vger.kernel.org
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <YV8A5iQczHApZlD6@boqun-archlinux>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EkiY7tK+;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::731
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

Hi Marco,

On Thu, Oct 07, 2021 at 03:01:07PM +0200, Marco Elver wrote:
> Hi Paul,
> 
> Thanks for writing up https://paulmck.livejournal.com/64970.html --
> these were also my thoughts. Similarly for KASAN.
> 
> Sanitizer integration will also, over time, provide quantitative data
> on the rate of bugs in C code, unsafe-Rust, and of course safe-Rust
> code as well as any number of interactions between them once the
> fuzzers are let loose on Rust code.
> 
> Re integrating KCSAN with Rust, this should be doable since rustc does
> support ThreadSanitizer instrumentation:
> https://rustc-dev-guide.rust-lang.org/sanitizers.html
> 
> Just need to pass all the rest of the -mllvm options to rustc as well,
> and ensure it's not attempting to link against compiler-rt. I haven't
> tried, so wouldn't know how it currently behaves.
> 

Thanks for looking into this, and I think you're right: if rustc
supports ThreadSanitizer, then basic features os KCSAN should work.

> Also of importance will be the __tsan_atomic*() instrumentation, which
> KCSAN already provides: my guess is that whatever subset of the LKMM
> Rust initially provides (looking at the current version it certainly
> is the case), the backend will lower them to LLVM atomic intrinsics
> [1], which ThreadSanitizer instrumentation turns into __tsan_atomic*()
> calls.
> [1] https://llvm.org/docs/Atomics.html
> 

Besides atomics, the counterpart of READ_ONCE() and WRITE_ONCE() should
also be looked into, IOW the core::ptr::{read,write}_volatile()
(although I don't think their semantics is completely defined since the
memory model of Rust is incomplete). There could easily be cases where
Rust-side do writes with lock critical sections while C-side do reads
out of the lock critical sections, so Rust-side need to play the
volatile game.

I'm not sure whether rustc will generate special instrumentation for
{read,write}_volatile(), if not, we need to provide something similar to
KCSAN does for READ_ONCE() and WRITE_ONCE().

Regards,
Boqun

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV8A5iQczHApZlD6%40boqun-archlinux.
