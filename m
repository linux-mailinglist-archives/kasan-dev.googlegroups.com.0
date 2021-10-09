Return-Path: <kasan-dev+bncBDRZHGH43YJRBVUHQ6FQMGQEAUDLO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 947B3427C05
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Oct 2021 18:31:19 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id b9-20020a5b07890000b0290558245b7eabsf16905686ybq.10
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Oct 2021 09:31:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633797078; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKwiewrvrLVlVYFe79Xo/FAtQKAyt03Ss57OkvEWcILBePLZnqCJ86qVGJKXAWj31O
         A1f12zr1D4hNKulbHxvzYQs9T0SR0VuERCYEgbZI8D/wV623vci/VEQmd1I4O3lWrQ6K
         w+EDmN19Kg5aDw5PlWWBnBEvElhWTZR0GFx3gzAuXA1/rR6gBlVsRVszMvyLC4QpG4BL
         hhhbCLdivzL7JH8QFDRgEcmqPPwybG+sOYs/6XNWpTPogyK83eeM8ia6d9b9ZXddtsVL
         3wylVoFRKVnMo3qZjyJsbNSVywXoDlZOqQ8EiD91qJl9FRQ/ucc5Xg19a9+YyzXVUjLY
         Xq5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=fgx7qyPVO0PNgsXfgUZsCEfnc/iVFwG9l32aQrZI3SY=;
        b=lbXKLieCqnwCRVYoAWzGf5+uBojzPA0IvropWOSomTLJPunSukBPjgsWJxB/YjCQHJ
         j2WjjKWNROF2x18bsfuVDGwz70bDQ5NoIkM5hGhBNicOHmXFQWJmbA7yc1PQiON/ipy0
         TWi3klWw7lkn3c3GCEFInwqpA+/b9TEkwBNk7sWoIcgJZnpwkO4CVZ38BDcGwUqCLe/8
         cNaq27RFFHSUGzu4fWKOuaVpiaEOApX+bKKTAx7VKNsWcRvSI4Y/6ZCOOfevEUSEW+hN
         pLQ7iz/o7EIsi6jaxKO+dncdyv1Jrf/KdqRFw1qebEvrChqtFRBB+nWY8bOFAsogpqsy
         w7dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oNVFlHLi;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgx7qyPVO0PNgsXfgUZsCEfnc/iVFwG9l32aQrZI3SY=;
        b=V4aVs09gJlqy72cYzIe0bem+PQCSwr+hQe7o2HR6obt5Y9U4jhCfvX3vl5vc/2jWml
         wkKp2dIzMXEsKmXFFxw2tMEmEiyfPlDmxQJtl8sOJuj5oMU45+I2XAhCTqjWhQ/HR6XW
         p7uprYW9aG+VsNSr77utfJzSrr9CARvW/pf0Wb9dicXVUjy9/2Nh6xkhbFQ9cQgDOcHJ
         lvEi9AP3cv4QU3YN2OWjwqxLVBbvI+8DnU5QFXBM8idqJbKs14B3+53OSgDUmn+t3JxP
         cQm55q70vRWt3mHCwGxDYO3pshlkpQmn/ZX8hwZ76rWsYFa8VGAC7du27NuU5YJrir/C
         VjKw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgx7qyPVO0PNgsXfgUZsCEfnc/iVFwG9l32aQrZI3SY=;
        b=auKBtDS1BybvWLKLF1rmPj/Y1Zh+u1cBQc1HMJokndX+2McMzZIo6dGlA6tFTDiBVI
         XlEA5Sn3FPmDmApAqDL/aS8qeUEebXUwoPYnLzVp25hFYGfYZRvbathnXir29SscUJEy
         XWNAWiRNi3sV8kGpm/SferI3n5GATxz9c8vRzvitP108A+A6bNO8ObBdUyYtX54YlIov
         FWWlOnQFOQNJdSP7gBXnmQLMZ0NCN7245gI/KB4r4OFQpIdWolvaQmIbwN0ZECvjmIYo
         JWizemX2P0743zW9YEObdY1x/uYEAQ8ju+6pwZtZXCwyfl9VA5oNAGyEtxLPSBjQXmIW
         eeTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgx7qyPVO0PNgsXfgUZsCEfnc/iVFwG9l32aQrZI3SY=;
        b=qzLtbyaKp02Lfi4k1PByg7fUIN8MGVdMtuPM5vhpO1islkGhV2odsulydlD69x36lQ
         +zA+9TA6MU2ZM+0/vpyKxGWWCHxsAgSLI8GFvbP7wHmC5b61QtGbm7NscALmz0SNTTGq
         oIXBUO6UaSVasoYL3QztXOGaIIyJ9LxapMv/Xw3/iggWDC4/3opOs1hNgctRP4S96s1x
         QU122CNcLpGcHtB+6hI31pB/rllvP7DylzegyIgO8QQBzgJY0G2bKatm1N/NMGUPyP2d
         7L46OT9ICyC4/7j1nEtF69Bu/QMjJqQhDozyisuZTHp8hlYjSVYTbkFFDDLdA24nAFpl
         Tf3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Rko1tr28mKoFLT/uJ0jumF6ZnexPwugxXhADAG/Oq1R6/lsVo
	7F7Bw8fccdXIBRW4Cx2NEdU=
X-Google-Smtp-Source: ABdhPJwVq5Ivw61CoqziNOiCgpkP+i5luNDaKv2WIvehPhVqWhAOtxbnn87KtpsDaZoHnoTiW60pGw==
X-Received: by 2002:a05:6902:150d:: with SMTP id q13mr10710650ybu.489.1633797078516;
        Sat, 09 Oct 2021 09:31:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cb8f:: with SMTP id b137ls315388ybg.0.gmail; Sat, 09 Oct
 2021 09:31:18 -0700 (PDT)
X-Received: by 2002:a25:1845:: with SMTP id 66mr10211055yby.396.1633797078031;
        Sat, 09 Oct 2021 09:31:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633797078; cv=none;
        d=google.com; s=arc-20160816;
        b=uoJs4/MPM3kmnq3HLz7DRIWGpUExr0itciuwA0r+lo77tbf2c+h3BcwdcNGTsiKdFL
         ivWBGA5dMTBhx5HpCiUVcPT4e62q2RglbL5GSDuwx/ytkfUwtk9bjMAE+Emge7Re7Eym
         DngdYlfM+Zrw6zIE4JWj1vPHitWW8ChH0D3MGjlX0ZRheNwzpN+U0ZC8X4W8YsvRPrtz
         bNYgoJDOCw7inQjsfIF07CNS8RomqlNam6f3mlJEkOY3uOWfXTnKpj6UQX/xFzDa4moQ
         WbSL4CwPEk2b8hdvoBxSjHG8T8D92sQ73U4gYgNDvV29lo0D6U5nlPD9kH3JwoKYVsRV
         xCqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yVEm896Yx01LPVLuAIaN3xFYGrEW8NhuMbgTTKjWCI8=;
        b=xSlUaQozV+0R4V5Em+amyId4HVeSfO2bl1/AaNhlX9IHdzRvsI05K76IU10b4+TCHf
         pkK4eZLOaBaVcOTiF7Lvj3PhBWP6a/uDJb/tj0dzdcB7tPu/bg/FjLipMYn5LSyiLvsB
         U9p2vpm96jsyWbQDLuv6iniYjlREiA900T5lTH6RdzLWHYp5SPWmwIZIVu6UGHzpDOdq
         uxXWMPvta6Nyo0+1z01v0GrT/SmeuiuygWdWHNJJ6/FWKyxKsuiJoRh1PKzD3hr5dek5
         sf/A+RgfNevVUSpEyrl1Bjp9NN396cJalzwklvuR/Hqtbhq0em+vDqEA1/5/FlHNTLXm
         AaYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oNVFlHLi;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id v16si180430ybq.5.2021.10.09.09.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Oct 2021 09:31:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id i189so6716688ioa.1
        for <kasan-dev@googlegroups.com>; Sat, 09 Oct 2021 09:31:18 -0700 (PDT)
X-Received: by 2002:a05:6602:160c:: with SMTP id x12mr12100046iow.44.1633797077563;
 Sat, 09 Oct 2021 09:31:17 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1> <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1> <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1> <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sat, 9 Oct 2021 18:31:06 +0200
Message-ID: <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oNVFlHLi;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Oct 9, 2021 at 2:08 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> If it complies with requirements, is it really a bug?  And while we are
> at it, I need to make an insignificant change to those requirements.  ;-)
>
> Hey, they have been using C for quite some time!  In at least some cases,
> with the assistance of formal verification tooling that takes the C code
> as input (cbmc, for example).

Indeed, for assurance levels that require that kind of verification,
there is a need for that kind of tooling for Rust.

> And how many of those boxes are ticked by the usual open-source processes?
> Nicholas Mc Guire talks about this from time to time.
>
> One challenge for use of Rust in my previous work with similar standards
> would be repeatability.  It would be necessary to carefully identify and
> archive the Rust compiler.

This may be open for interpretation, but I am aware of safety-critical
projects having used open-source compilers (e.g. GCC) and passing
certification (in at least some assurance levels).

Of course, in any case, companies looking to certify a system will not
jump right away into Rust because there are many other things to
consider: previous experience certifying, existence of tools, etc. and
all their implications in cost.

> So Rust is an attempt to let the compiler writers have their UB while
> inflicting at least somewhat less inconvenience on those of us poor
> fools using the resulting compilers?  If so, I predict that the compiler

You can see Rust as a way to "tame" C and C++, yes ;D

More seriously, users of Rust also take advantage of it, not just
compiler writers. For instance, unsafe code is used all the time to
implement all sorts of data structures in a performant way, while
still giving callers a safe interface.

There is also the angle about using `unsafe` even in "normal code" as
an escape hatch when you really need the performance (e.g. to avoid a
runtime check you can show it always holds).

The key idea is to encapsulate and minimize all that, and keep most of
the code (e.g. drivers) within the safe subset while still taking
advantage of the performance potentially-UB operations give us.

> writers will work hard to exploit additional UB until such time as Rust
> is at least as unsound as the C language currently is.

Rust has defined both the language and the compiler frontend so far,
thus it is also its own compiler writer here (ignoring here
alternative compilers which are very welcome). So it is in a good
position to argue with itself about what should be UB ;)

Now, of course, the Rust compiler writers have to ensure to abide by
LLVM's UB semantics when they lower code (and similarly for
alternative backends). But this is a different layer of UB, one that
frontend writers are responsible for, not the Rust one, which is the
one we care about for writing unsafe code.

Nevertheless, in the layer we care about, it would be nice to see the
unsafe Rust semantics defined as precisely as possible -- and there is
work to do there (as well as an opportunity).

(In any case, to be clear, this all is about unsafe Rust -- for safe
Rust, it has to show no UB modulo bugs in optimizers, libraries,
hardware, etc. -- see my other email about this. Furthermore, even if
there comes a time Rust has an standard, the safe Rust subset should
still not allow any UB).

> Sorry, but you did leave yourself wide open for that one!!!  ;-)

No worries :) I appreciate that you raise all these points, and I hope
it clarifies things for others with the same questions.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w%40mail.gmail.com.
