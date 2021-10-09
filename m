Return-Path: <kasan-dev+bncBCJZRXGY5YJBBTGZRCFQMGQEX6G7S2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DF6B427E1F
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 01:59:09 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id f8-20020a2585480000b02905937897e3dasf18144497ybn.2
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Oct 2021 16:59:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633823948; cv=pass;
        d=google.com; s=arc-20160816;
        b=G/Sh4LoTSwyO1B/9gs2QVwcMdKEdnUz8q6xR0L33fv6hIftiwddqwPk+9Pci+08IXD
         JnWyDvrPUJegkHxkBOnI3wMdfJ9GavRphsI8keIctmZAZROB0EXU56lJsBzoEvvVoItp
         basIXklea1OzddGzZDkThHsHwT5eK4p6G9M7OZJS7oi40QYxWd/f932DE8tHVs/zgLQN
         8cWGzx3OYAgnZuVtN6MkvZGDTWjRujVqBJc67d6j4x8EC+3y9pmUXd0eOeBv8THmFFT6
         takAXVIZ+AGZOAoFWAoKpjj5486ngaLJPMJ7U26jHlYrwMjjdmEDRAIMQS4KgplHsFul
         VPrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=yQaEGdfAgCbhJR+7DM4bN+rMox2bm7w37/Oscx6SgLw=;
        b=j4zE6VJabMz7mTeF6zAGojwxj1y7K5z5E1gHsgD7rb27hfkbE5KBpebsPuLWG+0neI
         TAbit/NztZbdOXqj65yHdFhTWuM/fRWCO26iwyfp8PUKFTbwHCMTItjeY1H40LzaeczT
         80CPkEFiC6PyFiSs46Fnjf3S4YXT+6DTH/9F3qSE+l3Bm/z87U607vhtfHwykKkKIgno
         mvFwgcK/wJepzv0Nx1wnuLaHO3G1pSTrvavbbc7pW8ZQMGmW4kWUNmwd+rrzRmaZlQE7
         TfmSWENR4Kf6u8aRHSLlL5QopqUrbzNsl+KZ0KruXLYEitsstIztjg+E7YXS4RH6Pyfm
         79mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=strx8NBT;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yQaEGdfAgCbhJR+7DM4bN+rMox2bm7w37/Oscx6SgLw=;
        b=Oe2OJKeghkfdGlgzfRoOZImhpR+y6JW8bEM5l3Uad/6ola5iPyTJ9TT3yiyB/LFNXX
         QUSTKqQe2r3yVzwqKN69H01EfuJvi/l67Qbf21G9iW2nRKyBQ6eE42rGZNho/+sxqsCS
         c+pEMBX3ovxqVF425qQK/LvjE5jVtWOUBUqxAx8aMqsFPDr0xvWPC54r09LlnOzP+syb
         L+NzbZT4L3g4OVpTXwkR1DnE133AIqvToyMnV5ZOdf0IreyCEsHATz/RKnFAUglzFGmQ
         DfYE8z10X/3yTOUqC9yKCF5hHk6nTmhcRr9hQvQdGCXiFQlI859L8Q/ufg2M6HclsTpJ
         5EVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yQaEGdfAgCbhJR+7DM4bN+rMox2bm7w37/Oscx6SgLw=;
        b=Dbsky9DikNe8IkGt/l0fGiNeaapzMW4LtJn9GnqLzwjl4t+e9reDNlPuw1wXm7c1SL
         C8TjoQdbwcOcYsDspKWaWlh+XtUbnQM0YgcFaa+ugBcHT7GTzpExb8hWEQTo0XhSqQum
         aUBvIuSlx7feJ7Ki5JGySfUqyMpPexXwC1ktLsONllmWv6d9mpkO0FNXBTYfK/XEYk58
         UxbaZNm5nyA3dt83GVsQ7MnLVZRtUafF5tKw+MWXg47IvndsNbMseqeRLVRu6nO4hPbs
         vRwccZSJ58ldi/VGz176bVkhBFeoz4CgVANPkgoDyF9wKnWi8b6gM5M0Mn1sFnqhjX13
         BW0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Z2jtGQY+N2e1TuB3TcKwAtWZ27RkgwuSstxwVITgjHj8cInyq
	EgayOJQNLXWWu+Bp/rR0efU=
X-Google-Smtp-Source: ABdhPJxmOHZZsCXFmha5H/fdutaYFHiF4sfC4+qXya21RzpZsKEDIzb4qX4EQjGBMrLFNiUaocwOng==
X-Received: by 2002:a25:2a89:: with SMTP id q131mr13211384ybq.404.1633823948463;
        Sat, 09 Oct 2021 16:59:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:800e:: with SMTP id m14ls899946ybk.7.gmail; Sat, 09 Oct
 2021 16:59:08 -0700 (PDT)
X-Received: by 2002:a25:9782:: with SMTP id i2mr11479536ybo.119.1633823947930;
        Sat, 09 Oct 2021 16:59:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633823947; cv=none;
        d=google.com; s=arc-20160816;
        b=QPohcqeGtv/0rbY0/H9OOVPdI3/eYz+vYDVbSP6Qp7Ugii0ZIwDLC6QazfUaohRFVv
         g1/AipXp3u9L624xxLcm96nRTIQ0c3IkXaDek/j3J/IUQ5lsahX1gMOM32k9Iou3YGzA
         gnkl86L/YQgeDZ5goPE14v+3cD1+beYZz4gs1XDehnajJYZWTulBiFqPtL2UiI337RIv
         usewIZiInt0jJvXT4Zllg59wo1q3S5T+5Zddo6icvxrvZs++vXV8GdLH4D0qmAgzgYv0
         lBA+/8e0KpPWkp1Zbv14r0AZ4ibPq3meNcrBBRDzzsmdcwVrM2jVV0+PLxch1HzYIhK8
         v0gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yt8CVMi6TzBhEKSbuVDfat4f1TwzAuNbxY7Hg6S5/YE=;
        b=bX1OLwBtXbrs5StFZsPZ/rarx49VE2I5ae8OsEdBc+DjKzJe34kHo0ZfvlFaQRivsg
         gK9Rgw/+78vK5ckqQUE+Bb1v694KPLt3U9+SQlITyKqHk1SvZ7tvEkSXXMm29NINseIl
         zEtcBLDCO63d8XAaR8+JtS69cxDy8/I1O9s00fnbz9fYovJDDu8/ZFrXIMpY63txkwv2
         hdTL84C50+oBRdmgIqdpJ/m0PLwY6bPVqHqCRS9hKOEOiU3owShlRnase9d7V/1/ExK2
         YiRGxS/fkbm7z11QtZoQ0LndzhA3D8RicsT1KBHKrHQqjLIGVYw7HMnAstSmStgu4gQd
         qWsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=strx8NBT;
       spf=pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=pPAm=O5=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l4si318024ybk.0.2021.10.09.16.59.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Oct 2021 16:59:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ppam=o5=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DC55E60F57;
	Sat,  9 Oct 2021 23:59:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A7A785C0887; Sat,  9 Oct 2021 16:59:06 -0700 (PDT)
Date: Sat, 9 Oct 2021 16:59:06 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=strx8NBT;       spf=pass
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

On Sat, Oct 09, 2021 at 06:31:06PM +0200, Miguel Ojeda wrote:
> On Sat, Oct 9, 2021 at 2:08 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > If it complies with requirements, is it really a bug?  And while we are
> > at it, I need to make an insignificant change to those requirements.  ;-)
> >
> > Hey, they have been using C for quite some time!  In at least some cases,
> > with the assistance of formal verification tooling that takes the C code
> > as input (cbmc, for example).
> 
> Indeed, for assurance levels that require that kind of verification,
> there is a need for that kind of tooling for Rust.
> 
> > And how many of those boxes are ticked by the usual open-source processes?
> > Nicholas Mc Guire talks about this from time to time.
> >
> > One challenge for use of Rust in my previous work with similar standards
> > would be repeatability.  It would be necessary to carefully identify and
> > archive the Rust compiler.
> 
> This may be open for interpretation, but I am aware of safety-critical
> projects having used open-source compilers (e.g. GCC) and passing
> certification (in at least some assurance levels).
> 
> Of course, in any case, companies looking to certify a system will not
> jump right away into Rust because there are many other things to
> consider: previous experience certifying, existence of tools, etc. and
> all their implications in cost.

The advantage that GCC and Clang/LLVM have is that you can simply say
"CentOS vx.yy" and define the full distro in an organized manner, for
a reasonably old and trusted distro version.  Perhaps Rust is already
there, but some have led me to believe that the safety-critical project
would need to take on some of the job of a Linux distribution.

Which they most definitely can do, if they so choose and properly document
with proper approvals.  Which should not be that much of a problem to
make happen.

> > So Rust is an attempt to let the compiler writers have their UB while
> > inflicting at least somewhat less inconvenience on those of us poor
> > fools using the resulting compilers?  If so, I predict that the compiler
> 
> You can see Rust as a way to "tame" C and C++, yes ;D

How about instead taming the people writing insane optimizations?  ;-)

> More seriously, users of Rust also take advantage of it, not just
> compiler writers. For instance, unsafe code is used all the time to
> implement all sorts of data structures in a performant way, while
> still giving callers a safe interface.
> 
> There is also the angle about using `unsafe` even in "normal code" as
> an escape hatch when you really need the performance (e.g. to avoid a
> runtime check you can show it always holds).
> 
> The key idea is to encapsulate and minimize all that, and keep most of
> the code (e.g. drivers) within the safe subset while still taking
> advantage of the performance potentially-UB operations give us.

Nice spin.  ;-)

> > writers will work hard to exploit additional UB until such time as Rust
> > is at least as unsound as the C language currently is.
> 
> Rust has defined both the language and the compiler frontend so far,
> thus it is also its own compiler writer here (ignoring here
> alternative compilers which are very welcome). So it is in a good
> position to argue with itself about what should be UB ;)
> 
> Now, of course, the Rust compiler writers have to ensure to abide by
> LLVM's UB semantics when they lower code (and similarly for
> alternative backends). But this is a different layer of UB, one that
> frontend writers are responsible for, not the Rust one, which is the
> one we care about for writing unsafe code.
> 
> Nevertheless, in the layer we care about, it would be nice to see the
> unsafe Rust semantics defined as precisely as possible -- and there is
> work to do there (as well as an opportunity).
> 
> (In any case, to be clear, this all is about unsafe Rust -- for safe
> Rust, it has to show no UB modulo bugs in optimizers, libraries,
> hardware, etc. -- see my other email about this. Furthermore, even if
> there comes a time Rust has an standard, the safe Rust subset should
> still not allow any UB).

In the near term, you are constrained by the existing compiler backends,
which contain a bunch of optimizations that are and will continue to limit
what you can do.  Longer term, you could write your own backend, or rework
the existing backends, but are all of you really interested in doing that?

The current ownership model is also an interesting constraint, witness
the comments on the sequence locking post.  That said, I completely
understand how the ownership model is a powerful tool that can do an
extremely good job of keeping concurrency novices out of trouble.

> > Sorry, but you did leave yourself wide open for that one!!!  ;-)
> 
> No worries :) I appreciate that you raise all these points, and I hope
> it clarifies things for others with the same questions.

Here is hoping!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211009235906.GY880162%40paulmck-ThinkPad-P17-Gen-1.
