Return-Path: <kasan-dev+bncBC6LHPWNU4DBBXMP7SFAMGQEWWMQBTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BA374255BA
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 16:44:47 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 41-20020a17090a0fac00b00195a5a61ab8sf3821732pjz.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 07:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633617886; cv=pass;
        d=google.com; s=arc-20160816;
        b=enKs0JYMXQXefXTiLKAXxi6+/QwyacEl22SxNNH+h0PA4bee90mPb/1CY9W87E0Yro
         Meuk6piT+hmaVTono3RxoIXRHQZLuQhmvmePiJxZYJR54vG95J1XjgnRN3Wqi7ty28Lk
         NoqU5tE/xLtVBeiXHiC1aTgnKLDbnAy46covHQnZbRdCWkwDdJuMbgTUscPEkI7CRphz
         A6t3pIklQySGn2c5Ftl7p6jsj0qy2sOZOTqLb+3ZVl9M17Vh5YRWQJmrW0fN8Ex5J3lx
         KfUe4NrNMv5JaMtkUtyJTCgwntRX1gXKpiDn+JQxpI/dBDhMbNQS1drtVwnHUJjKbFrG
         bHaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Gs+MmGxpqm7rVlvSrhb1ZgWjJVophahU5ZAzAJuY3qg=;
        b=EHJ4G8+EEbdJElMhiaWrr2ugUdUt60Xz8DkLtuMyTGB049ESVlNti4oEcrtnf9G4WO
         r9mlUUc58rQLo6Q+Nuo/lEtU0Eu4CvA2q9oJ8EcMuloVQyvy/QE9nNTPnO7EEZS2fU0d
         D/+vZ1mTpdMvElrjUVA6YL0MG1okq5U/zthaueQYLIeSvGhX8hh1Wv5+e4MAKfQ3YUU+
         GzuxencD/MbNajGpEQ874rp1LZzmTgovgvIu5KeVqGD2I8skLciVzpOSpC1eYplKTZaO
         n1D8SrujFoTRoJhOKGWfJimoCPAP+vsakQXEFE8/HYNkPUw6hPMTCqVHriPyE7AN0I+/
         pbDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="dYJRX/2T";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gs+MmGxpqm7rVlvSrhb1ZgWjJVophahU5ZAzAJuY3qg=;
        b=IP2OXP4wtbfphHVxqCdYNQSKx+dK/TwHgQsj2xl8Ypxz2PY2ZHnCHr3LZyAOgiCSRi
         TtjKzFKC6P2QQv0zcy4GgeGaGXEhMBP+lErXUI7WkJqIztcs8tukpjXw9WHwpfD4SysC
         Fi7CdZRqzhk/DIDjhfSHcmpYOA5A9MU+O2aoq4xAODBowxgJv33+VEomGRCDKHVGI68T
         Y45tL8JIUj9VODrFvM6wvkn5x97z9y1qqRVU+HA5WEELJRM9PhT8rC/kptVVNxqu/qRf
         4v2TV/5oZj8H45eEhPf3aht0D8o1XAhm7CDYaMwYKpDMNhPjOldL50bKZxA5+HyovXnh
         MerA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gs+MmGxpqm7rVlvSrhb1ZgWjJVophahU5ZAzAJuY3qg=;
        b=f3FANQxB1UzBC8VzDrE1dL4IopeKnk7PReBubnWaH3ZAggHAunbwRkvqTHxKJ3VzUW
         dg2y+E77DmzEaWJCD1eSDePM6JLYCB8uwFAsrqs6OiYUY6ZmB7vQlH/dWVd0oXijNkwU
         Yt4algDGhD2FOHxCNfD+QJlk+/0f3CVFNjYde6McjRbpH0MMIJQeP0f1AoyfN9eHJ4I/
         sYXGM0I+Vv/RauyIXJddrPo5ziy6taIciQ126jaVBBrKIXh9ycrbdzC5ANrgC+WioiLA
         nTa2LEyOZSX27XcL3tsd72gK3fRWN1dbVCx/HKd0JCap5EC+4Dwf5sTHKsGhDcwKQ/w+
         L3qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Gs+MmGxpqm7rVlvSrhb1ZgWjJVophahU5ZAzAJuY3qg=;
        b=AVVnXNYee728nzu2M0rxy7TGOAAAmkVL1hwwq+7sJjyv9NuspaeFbPgi63AtpxEhs+
         PVCto8NfdRa30nVoWmuT67FgKxKwbLBOUKz3CqNTreO3vBFapqeWM7Wmg83378HmRjSz
         rKaDFUprGPQPVQrNkZI0RrBb/5uT6oiFhfi4150RcgJiW4VRo9oPRcnIzFcUUypAl+tx
         OzViulaBMt4d9w2bBLfzvxFIChUxNIvGWJzcIx1Akb9qScwff7d7NqvegXJF59sBk6ke
         oCF5go7GOkS7VkKBHeRiHfe8HMZ67/Jgif0d4KA/0FXLrf5az+SowEIsQPks/AggqIiu
         2XHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530W+UK0y9mmqeLmaf5veL5lgnSb53CwcyWTLJs2TGWwvhf41CI6
	8KHBXYaT5J4IkOjQmQuaaIk=
X-Google-Smtp-Source: ABdhPJyGglMCKHEXgCPQwh1209cl65VZgVpeXSQkZ3lqJMtoxzX0OqDugPyQ5HSnYfz6/0m6VJlGHw==
X-Received: by 2002:aa7:811a:0:b0:44c:b9ef:f618 with SMTP id b26-20020aa7811a000000b0044cb9eff618mr4435206pfi.9.1633617885969;
        Thu, 07 Oct 2021 07:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80a:: with SMTP id u10ls43339plg.5.gmail; Thu, 07
 Oct 2021 07:44:45 -0700 (PDT)
X-Received: by 2002:a17:90a:8b8d:: with SMTP id z13mr5983624pjn.214.1633617885301;
        Thu, 07 Oct 2021 07:44:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633617885; cv=none;
        d=google.com; s=arc-20160816;
        b=MOJinpMi1b5otaS8Y4+i/r/4n8A2ZbLH6dWj1HzWlWjm/bzxORw3xBEETzvoMq/4Qy
         qDz2OZNgV+pn+E7q2eQW7z67E8X7+i+dCvcEY7yp9bEGjnBY8AOASCVQ2QRDdds/ggj0
         0bBONkPkz3/9dC1KYiNdAwLkiE9iMO1QeccpGm/yXag7QJ7P9PchJ9g7oacjRE0Hdw6d
         goA5z1Bs8wIdOs3zN7ryTkquI2tL8sihoIK9hRvY+CG0evUJRLJ90Uxtph1YNa5zfLga
         SItoVQDW666RpLz7qLjPltitQopUgykbvKWisA8TGDhxURtv4YSMpurL3cVofH7Nx7DU
         uRaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=h2WMqBtwnFLyTqXqeBzucsF1CbmEs9P3PKcX4LkuraI=;
        b=XDxoseMuVFUNKM/jYSAoUClRYSyX2T7L+3o/MkKx1PdFMmYlF9Dt8wQUh7eZvSxxty
         HCXWlJSGkoBUOYfLw433SMM14zunT4n8hIB6G6wn7Ndd59roPyVRLvL4LQTVAVNdIBMd
         pkH6JaXfXvfpYrcAOSOCvGAEQGdzbAmr0f0r3WIhua9u2sZpF1N5g8XfArPEate8fV0M
         Y8cBW8vPs5moNX5zbKBv782mPfdCqW8apfKtl9rTWpGO+NsQeQfNxzyTrIyTMniKIBuL
         4TOlrHSRb9TAZIumtSfR6+XX4o96WJxIL85N4VxYK9wjpsRUgJZv2JDclMFWYhjJvu48
         4wAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="dYJRX/2T";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id q75si756001pfc.5.2021.10.07.07.44.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 07:44:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id e16so6370571qts.4
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 07:44:45 -0700 (PDT)
X-Received: by 2002:ac8:6147:: with SMTP id d7mr5274254qtm.38.1633617884561;
        Thu, 07 Oct 2021 07:44:44 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id l28sm15588797qtn.1.2021.10.07.07.44.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Oct 2021 07:44:43 -0700 (PDT)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id D201A27C0061;
	Thu,  7 Oct 2021 10:44:42 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute6.internal (MEProxy); Thu, 07 Oct 2021 10:44:42 -0400
X-ME-Sender: <xms:2gdfYey3TpmV4klGvLTy6Y8crUuTiHLUqH6mMadV5hL7r61RKXhIkg>
    <xme:2gdfYaRzSH10363no8lxl4roJJLAKgCuPf9FkTSr4n2r-7fZoGNGMmEykkChjCpCX
    8GS5mZiql_1fdPdnw>
X-ME-Received: <xmr:2gdfYQXtTjpyFZ-BXrNZb_fgJkpm2Fvg4szDnHzQPx6mWWeumm5v0r8ndGJGIw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvtddrudelkedgjeelucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepleetgeffteekkeehkeeiffekfeeffedujeetteeileetudduffduffdutddt
    feevnecuffhomhgrihhnpehllhhvmhdrohhrghenucevlhhushhtvghrufhiiigvpedtne
    curfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquhhnodhmvghsmhhtphgruhhthhhpvghr
    shhonhgrlhhithihqdeiledvgeehtdeigedqudejjeekheehhedvqdgsohhquhhnrdhfvg
    hngheppehgmhgrihhlrdgtohhmsehfihigmhgvrdhnrghmvg
X-ME-Proxy: <xmx:2gdfYUjVDNjg9mas7qyubCiMXcKh0D0PKU9f1tw8x4eV0cLh7nSIMw>
    <xmx:2gdfYQBEuc89KjyUXZ4icuuKx8gAFRE9TIA1CXiDtFUCr5hLjn92yA>
    <xmx:2gdfYVKQ4BU290nxtrP_Lc1hwM0uVePm5CyLA68VLJEXRylF999cAA>
    <xmx:2gdfYTPuF_uyfgmwi2yjo8VNSSxCQ_VycMcuw2MO8kHQbVdNvszR3A>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Thu,
 7 Oct 2021 10:44:42 -0400 (EDT)
Date: Thu, 7 Oct 2021 22:43:36 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux@vger.kernel.org
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <YV8HmFZ6RqPMVmSY@boqun-archlinux>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="dYJRX/2T";       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::836
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

On Thu, Oct 07, 2021 at 04:22:41PM +0200, Marco Elver wrote:
> On Thu, 7 Oct 2021 at 16:16, Boqun Feng <boqun.feng@gmail.com> wrote:
> [...]
> > > Also of importance will be the __tsan_atomic*() instrumentation, which
> > > KCSAN already provides: my guess is that whatever subset of the LKMM
> > > Rust initially provides (looking at the current version it certainly
> > > is the case), the backend will lower them to LLVM atomic intrinsics
> > > [1], which ThreadSanitizer instrumentation turns into __tsan_atomic*()
> > > calls.
> > > [1] https://llvm.org/docs/Atomics.html
> > >
> >
> > Besides atomics, the counterpart of READ_ONCE() and WRITE_ONCE() should
> > also be looked into, IOW the core::ptr::{read,write}_volatile()
> > (although I don't think their semantics is completely defined since the
> > memory model of Rust is incomplete). There could easily be cases where
> > Rust-side do writes with lock critical sections while C-side do reads
> > out of the lock critical sections, so Rust-side need to play the
> > volatile game.
> >
> > I'm not sure whether rustc will generate special instrumentation for
> > {read,write}_volatile(), if not, we need to provide something similar to
> > KCSAN does for READ_ONCE() and WRITE_ONCE().
> 
> For volatile (i.e. *ONCE()) KCSAN no longer does anything special.
> This was one of the major compiler changes (-mllvm
> -tsan-distinguish-volatile=1, and similarly for GCC) to get KCSAN
> merged in the end.
> 

Ah, I should have remembered this ;-) Thanks!

Regards,
Boqun

> So if rustc lowers core::ptr::{read,write}_volatile() to volatile in
> LLVM IR (which I assume it does), then everything works as intended,
> and no extra explicit instrumentation is required.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV8HmFZ6RqPMVmSY%40boqun-archlinux.
