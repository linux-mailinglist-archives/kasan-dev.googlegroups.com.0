Return-Path: <kasan-dev+bncBCJZRXGY5YJBBB53QOFQMGQE7WZ6NGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id F1CB1427482
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Oct 2021 02:08:40 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id p7-20020a056830318700b0054749cce9bcsf6327172ots.18
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 17:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633738119; cv=pass;
        d=google.com; s=arc-20160816;
        b=vhDfRslB0t+erdVNen0xqtA7qzRSWfrpAKavV2pBQnFzF3X00YPqzrW9W11CftUGFg
         foUblSgJps+8BwYl5WRKzP90OmKAH1+n4Jpe+vKb/ac2TZ4Od8xRqnyL72lvYdfsJG5O
         UnuK1DjmyHp/8H/AKel8YdmYXUWinwLlh8Up0JS8lPhd2zILXg6uZx8pNwZVozd6zGIz
         u1BF86+l4pwD243hVfSxpaNHCYGEt6w7wjvwAK76DAahbnB98jZkIlmdKYfZMMknRnQt
         rLIYtq57Yg34NqJbws5tkDMb2WvYfXtIpNxsVal9lQa0L7W4DtbrCy5zkPgLcAUPzAqZ
         hAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=x17rjWRLaJ4xn3Vu72Kpo2CVur4FaagtaroeqWjKdfw=;
        b=THh/WPJaeyr7WvfYbn1zArMzdixsxrGgJEc0ExLAUylbORbTzfuyO6VGT1esaQoV+L
         OUvzHpyrHlo6hbZT1s7pIYhCmeHYhjnDnbl1s4ofXg2/NvN4WfvLHcm8sNEyuqR+rQrf
         pvv8R1soOGiUw8WHW93pLlP1HB4mVcV5HtO9J90+aXWxU0h0FJP0DaBMdrgh+IzV2yhT
         jggILZKsdVJPvw6dSMX2sdLRi1pbTN1XSVthlLhbjKOA+yIBD2gXygkMOnMl5ngQusOf
         CMffTTdFHsL7Pc1FUPhQT16YGTokfkXzFAgRaAAIwTsYMlybStYnfp5JYSxKHtoQeizS
         Ev+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Oo8nsj0F;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x17rjWRLaJ4xn3Vu72Kpo2CVur4FaagtaroeqWjKdfw=;
        b=XeTriWaX6rLunFyFUTU5VmZAvaeb/sayWlTitX1ZiDjVZhvpDt6tpyeiRaDuLQtTuQ
         lyuoUQaDHyLWvBKelAS4VtmYMFWwbeejbftbzxEWnyGn5IMXBPZk10m/Sbbgr7H66p+d
         Qh8W3k6eUhu9uFR8UlzWS0lw4gOlDFcfGAoT6srL7Hxnw4uEnwlaSB2+pYEudDGppfQX
         8mdlBVpe0rXO55gAUQtpg4DZGKrpsQdz8znnkBVRvhnUSvu4mNQQEdN7j+HoBPkJaMSo
         GDWaUxBixI6JKexXWxrqazryu95Uzx9DRw1z1zHOybcbeEVNFJEz3W/K+2FLf++WIARV
         4KjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x17rjWRLaJ4xn3Vu72Kpo2CVur4FaagtaroeqWjKdfw=;
        b=5A7/CnVxyba9byxVvPlGu6vEq3WUuIvP0WLkWR6caR9IfeJVJWlmTYP+0fKGCCMY0X
         bpCCCIolL+Zl/hJdM4l5IJoCC4+1cdKX1FaPE/KHNAdNCHyl2DQrKdtKCDkWjkuufXAQ
         GAJjADuHpmezp5hmZ/1QSRO2pAjIC79aosaYkwTq05j/an3GXxfi+Y5cQVvp0sJG1sPL
         vJOeO6WWgY/YMxQtLqJtHGe15mc+GlnGQY6/USFBwxW+YFdT+011SEVtQquMh0bKLIRi
         eM4XdpQM0tjBG9ul8ttGKtc7hr8FYpW3PrU67b3xFQK6HbRdTU/cOyWTvZb2gpkjmiXh
         Y1ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314iH9ZHYqr9rsarV4dUbCBgyXHXq0V8fl7mF5fnP9VX3yR2edS
	fZertE3kei0cAcWbM17ZbYg=
X-Google-Smtp-Source: ABdhPJwO88P2Z7mih1gAlHkha4zCQqEJw5/zbj9BGsQPsFl1z421GWzp9rLONikiwWVGUmdkpLJJmw==
X-Received: by 2002:a05:6808:56b:: with SMTP id j11mr10109491oig.79.1633738119687;
        Fri, 08 Oct 2021 17:08:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e298:: with SMTP id k24ls351411oot.3.gmail; Fri, 08 Oct
 2021 17:08:39 -0700 (PDT)
X-Received: by 2002:a4a:ac47:: with SMTP id q7mr10100100oon.90.1633738119351;
        Fri, 08 Oct 2021 17:08:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633738119; cv=none;
        d=google.com; s=arc-20160816;
        b=nvCRmHgzAlzQm492TheekEy7pHnhvq6U/zJodpi/lKrnqft8gD3FMetys+WCxUYoNE
         5nFo4vKDKx25j7YviInoIMufLfNuLgBQ/B/FbDrd36f2E+XvGIfuV387ACD4ENJvABj2
         29FMf0wOSntRMGT8w5q0sNNuZP6Bo+pOUqIiEmgEPcwkvlPKlZatMrnkqJAnVuRjWX2A
         i9S/94QOx321C5aFeTIak0Q2+vtQpncKXpir0r1VSUT9lOLZ4MAO6Ro0yyUi63VkuTho
         OPPcq9yw39grrNBY4I6BkFELy17GXhHUfz/gLS46V3gsLYLs4/TwEpvuZ5YP+FLGPpG4
         iJWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LFJBZKhPG97x54iS3dEkSS9CYrazS326dXDelzBhmnw=;
        b=aOGLqikX9MPzvd3c6zfSGTvK+nfyhMRfZGoXBq3csx0mgaTV5gwWrFFWDuQKJ+Gohj
         Fa9YQSJOfhtltAzMdRB7XAcdkKZ6OTlh7njKmashV5Ph5Y1V6RqTqQM4JU+0SHx6q+Ux
         /bbNki1DSm/TRFMZwzOwgmKpHF9EZV3MpW3eP1TjX0wRBfNRyxJjFvRV4HRMGkPM6ibI
         wjFQOP2wYTpa30w9NBymRHNZ2vhegPqxoUw7QfEuODD3cVATZz0Fg/lLZQMfSXZovZgN
         PAcHP8fd7wZzhbJb/UVsBvMHAqziZptuJIgDm4X+ZRlGJSXHBLZezFb7d1DN75EwSDnv
         lOgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Oo8nsj0F;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v12si43437otq.4.2021.10.08.17.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Oct 2021 17:08:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8762860FC2;
	Sat,  9 Oct 2021 00:08:38 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 51FD35C1E85; Fri,  8 Oct 2021 17:08:38 -0700 (PDT)
Date: Fri, 8 Oct 2021 17:08:38 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Oo8nsj0F;       spf=pass
 (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Oct 08, 2021 at 11:32:34PM +0200, Miguel Ojeda wrote:
> On Fri, Oct 8, 2021 at 7:40 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Just in case there is lingering confusion, my purpose in providing an
> > example from the field of safety-critical systems was nothing more or
> > less than to derive an extreme lower bound for the expected bug rate in
> 
> Yes, safety-critical systems usually have lower rate of bugs, but they
> can actually be very buggy as long as they comply with requirements...
> :P

If it complies with requirements, is it really a bug?  And while we are
at it, I need to make an insignificant change to those requirements.  ;-)

> > production software.  Believe me, there is no way that I am advocating
> > use of Rust as it currently exists for use in safety-critical systems!
> > Not that this will necessarily prevent such use, mind you!  ;-)
> 
> Well, people are already working on bringing Rust to safety-critical domains! :)

Hey, they have been using C for quite some time!  In at least some cases,
with the assistance of formal verification tooling that takes the C code
as input (cbmc, for example).

> In any case, for example, DO-178 describes the software development
> process, but does not require a particular language to be used even if
> a particular project following that standard may do so.

And how many of those boxes are ticked by the usual open-source processes?
Nicholas Mc Guire talks about this from time to time.

One challenge for use of Rust in my previous work with similar standards
would be repeatability.  It would be necessary to carefully identify and
archive the Rust compiler.

> > From what I have seen, people prevent unsafe Rust code from introducing
> > UB by adding things, for example assertions and proofs of correctness.
> > Each and every one of those added things have a non-zero probability
> > of themselves containing bugs or mistakes.  Therefore, a Rust program
> > containing a sufficiently large quantity of unsafe code will with high
> > probability invoke UB.
> >
> > Hopefully, a much lower UB-invocation probability than a similar quantity
> > of C code, but nevertheless, a decidedly non-zero probability.
> >
> > So what am I missing here?
> 
> Rust does not guarantee UB-freedom in an absolute way -- after all,
> there is unsafe code in the standard library, we have unsafe code in
> the kernel abstractions, the compiler may have bugs, the hardware may
> misbehave, there may be a single-event upset, etc.
> 
> However, the key is to understand Rust as a way to minimize unsafe
> code, and therefore minimize the chances of UB happening.
> 
> Let's take an example: we need to dereference a pointer 10 times in a
> driver. And 10 more times in another driver. We may do it writing
> `unsafe` many times in every driver, and checking that every single
> usage does not trigger UB. This is fine, and we can write Rust code
> like that, but is not buying us much. And, as you say, if we keep
> accumulating those dereferences, the probability of a mistake grows
> and grows.

The real fun in device drivers is the MMIO references, along with the
IOMMU, the occasional cache-incoherent device, and so on.

> Instead, we could write an abstraction that provides a safe way to do
> the same thing. Then we can focus our efforts in checking the
> abstraction, and reuse it everywhere, in all drivers.
> 
> That abstraction does not guarantee there is no UB -- after all, it
> may have a bug, or someone else may corrupt our memory, or the
> hardware may have a bug, etc. However, that abstraction is promising
> that, as long as there is no other UB subverting it, then it will not
> allow safe code to create UB.
> 
> Therefore, as a driver writer, as long as I keep writing only safe
> code, I do not have to care about introducing UB. As a reviewer, if
> the driver does not contain unsafe code, I don't need to worry about
> any UB either. If UB is actually introduced, then the bug is in the
> abstractions, not the safe driver.
> 
> Thus we are reducing the amount of places where we risk using a
> potentially-UB operation.

So Rust is an attempt to let the compiler writers have their UB while
inflicting at least somewhat less inconvenience on those of us poor
fools using the resulting compilers?  If so, I predict that the compiler
writers will work hard to exploit additional UB until such time as Rust
is at least as unsound as the C language currently is.

Sorry, but you did leave yourself wide open for that one!!!  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211009000838.GV880162%40paulmck-ThinkPad-P17-Gen-1.
