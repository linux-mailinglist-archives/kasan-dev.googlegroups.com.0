Return-Path: <kasan-dev+bncBCJZRXGY5YJBB2OAZSFQMGQEUXFIOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 14F88437F62
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 22:34:51 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id n15-20020a170902e54f00b0013ed08c1bacsf2175679plf.20
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 13:34:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634934889; cv=pass;
        d=google.com; s=arc-20160816;
        b=zcdXizlWm7MMJ+pLzekVaQ8wfP9jeumGTTEi09QAdcCqJnAclmAOhWO5ggLMFd3XUk
         o9izReCWRAisCcd+nyQ8NAb/bokEE+lpTHT79QtnyiwW6zhpPJhV3BVuNc92ws0/FtgW
         woYX3nKyF7UwoDiYvZxsabc7hEUj91xSP5m17qtw2jKMlHlyblmoxIzAdsR4+4cVkvNO
         /R5D6piFiXrgXZyQWIAZnnTbz4eLf2ydFkExfHvXage46sZ4KGgT7INh+l35F9JLH8tb
         9oxG29An6F5NeaBDza9MPCxZlR9BGajNLIXWgkGz9UPUJH2lrMws3PGK6+tDuEJV1uR4
         Fdtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=vClQRphdiKvW2HLMsFXQTMYRHoLfA8W1FVxnPs7dP08=;
        b=aMX3CuP5ucrVxgYLxvboeCxPYUG1DWy/u/7JOcx4UhIhRjZSn5Tj9j0TBoFp4HlisT
         x7m2VH1tCZvFlrA0HkDK+xD92rRUQ9W3M+wP0kMs3Vr0983aYgw2Fr4rh+IMibBasES2
         TGntiMbPr9b+40O7ls65jWnWAWw50NA54OkJsi6Vqd3sxrdCgQ5K+bJ4F8US+JUYMakL
         M1znoVyDZmm1rBRMqNb/bz0e4vkdvfVpLItL1zCNpj9dRfpgxdqIOF1kZ83zKMyKYKiL
         j4Vz8zTBy96JDFrt+OQwimaoVAD5KHbLj9lPKUVXstehm2pEo71fKaR6fR2HaMXpLvEM
         lAgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hOcAlJzS;
       spf=pass (google.com: domain of srs0=cjuh=pk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CjuH=PK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vClQRphdiKvW2HLMsFXQTMYRHoLfA8W1FVxnPs7dP08=;
        b=JRzjeNbUFisiBh6PEkCOFHYyTCSGVL7YcmMhz8eO0NrhZfJwfidIclJNbLS3EdKYYH
         65yO5BsYJFIzABZo411IrGfphfxl395Iu63W4SDFKERlp378xjR7yzH7sbdQ32ggFjwb
         rp+Lhh+Us8naJeJPWQ7twp7KIBh+2C5/WlIiYzIbsnqGbbOid8KMQhLIj/ZrJd65BVuW
         esSSaGWBBVJxBg7NBAgQK9L+HCcpWAr07LQ3zL19I25I0bYRLC8g9sARSMbhePqHd24j
         GONLiU8npQ3cMbxsUym/tXDQtpFLtxTPSLyUMU284O86cPjTQ+aiIf65JPcIQuW5pch1
         wLJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vClQRphdiKvW2HLMsFXQTMYRHoLfA8W1FVxnPs7dP08=;
        b=4BqaCrFoCyBJ54rcQXEENFC0NwTXAknrtfsEPr/fprv/p83d5uoLP+F+JQRXGrtCA8
         nNnofdTjP2jPmwUHKn4A7bMx6dizWNZ9E5tLOHC7y3TkEsbVY1D6cTTtYcOyJt1YkVfi
         k5/FNNO0Dm9JWpjEvKZStR4amgsRI81QvDfSmXoCEWd4U8ULNJk1heOz7bad+vQhJO9u
         cF/d2i2AkJ3I3bEULxtJWbUWXplTKdW3Tbn5DvS+LdXMVH2F9JtjRtChKEbVJFLBp7/8
         CdlDF++gZauQCNw6m0BhlC023JgiRJfHaA6aVmvoh+djcyJkkwxBO7CRJTJrOdDlWW18
         8sJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/5VCkz619/RLcGG0gGHxmudOfp1Wa/kDjwMRGCLuze+sQlH7Z
	PUA2vDXasGy6N/9dJqFgmH4=
X-Google-Smtp-Source: ABdhPJylsbEVCiC5AUFyQye/G7xQnpUfz3VDQcVQLXcMdo3nG+xwzYxfi3NyFjzUM3DTiE4NLVV8VQ==
X-Received: by 2002:a62:1887:0:b0:44c:872e:27ed with SMTP id 129-20020a621887000000b0044c872e27edmr2015659pfy.71.1634934889537;
        Fri, 22 Oct 2021 13:34:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5c1:: with SMTP id u1ls6298993plf.0.gmail; Fri, 22
 Oct 2021 13:34:49 -0700 (PDT)
X-Received: by 2002:a17:902:9882:b0:13e:1749:daae with SMTP id s2-20020a170902988200b0013e1749daaemr2191522plp.60.1634934888836;
        Fri, 22 Oct 2021 13:34:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634934888; cv=none;
        d=google.com; s=arc-20160816;
        b=W+LsY931RNpbtn9PM6De/Y7nCLui29A8kG6RRbVEsQ+MrG1B/SYz4meK5HPro2xG+D
         qZl1UrfDa34QwF6p9doocE6MSUFmbQO648UOebbd5rwXkpiCPMHmZg6gNyrpLQZ23JdX
         KDEOxsDDZlgHXz/IM8xmH0BiA+2GXV4tzh/SaXcn4tnmxzEUsSusakAA32+ER/4O6+W6
         HdTDxEBLBwnJgXdvCXcKuXk/OoV5wGAfCJncxm91NuMnpYGWm275fciiD4ZhDaR72vpf
         iXx86a/JLzfFXq5QxOh4FcytPAfhpD8arOeADBOqCrknkWNVnpjxG/+3HWvD8fVqIzj5
         1Avw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YK6plP3YVtpRTatGguH2lYXlGYfJlicz4elazx9XJKM=;
        b=PVwnd3wKoZg+RAtNAjBM2HUX8+aiWmVMZeJ4kvQVfJV/VUqb3JP6bR4NGGG4y9K4vc
         IjMOAVU4a7+iQKAuY6g/B6Vu34DYa/mXOPWOp3yNBkEjIRivft3bKQaFyMPgirazImMt
         n1E4A5rmxxxOZ3kiXuraT4AmHMvzURdlw/axjUUvLJbg4GgQDn6XEMzJyxXh4COfF6sz
         6j2BHndmDvs6x2l0qZkrTmmJCoo8M3Mk9mp0j4bfwzAYB4GwVe19bp1SzvzOQdOcJy9u
         uzc2Y9k8zVraNWJVjHN8nFsOCoVlSHzJJ7zX2PNQ2Uy/j+AFs3A63ZQpzai8aKXqPBlA
         PIEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hOcAlJzS;
       spf=pass (google.com: domain of srs0=cjuh=pk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CjuH=PK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w9si768628plq.0.2021.10.22.13.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Oct 2021 13:34:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=cjuh=pk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7B69A61059;
	Fri, 22 Oct 2021 20:34:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 47C635C0BF4; Fri, 22 Oct 2021 13:34:48 -0700 (PDT)
Date: Fri, 22 Oct 2021 13:34:48 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211022203448.GC880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
 <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
 <20211011185234.GH880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72k+wa8bkxzcaRUSAee2btOy04uqLLnwY_AsBfd2RBhOxw@mail.gmail.com>
 <20211013232939.GW880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72m=MV2rF=SHKfrAi+E0vwEpKemeO_48h10=tvejJ_mAPw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72m=MV2rF=SHKfrAi+E0vwEpKemeO_48h10=tvejJ_mAPw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hOcAlJzS;       spf=pass
 (google.com: domain of srs0=cjuh=pk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CjuH=PK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, Oct 22, 2021 at 09:17:34PM +0200, Miguel Ojeda wrote:
> On Thu, Oct 14, 2021 at 1:29 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > So Rust could support zombie pointers without changes to LLVM?
> 
> I don't know what you mean "without changes". LLVM is not fixed, it
> changes every version, and Rust sometimes has to patch it on top. If
> Rust decides to support (or not) zombie pointers, then they will have
> to look for a way to lower code in the given version/instance of LLVM
> they are using in a way that does not break the zap-susceptible
> algorithms. That may require new features for the IR, or disabling
> certain optimizations, or fixing bugs, etc.

And we do have some people working on these fixes in the LLVM backend,
but it may take some time.

> > The standard is for the most part not a mathematical document.  So many
> > parts of it can only be "understood in a personal capacity".
> 
> Sure, but there is a middle-ground between a formal model and
> completely unstated semantics where nobody can even guess the
> intention. My point was that we should not rely on semantics that are
> not precise yet -- if possible. And if the same problem happens in C,
> but we have a workaround for it, we should not be rewriting those
> algorithms in Rust.

Me, I don't have a choice.  To get my job done, I am required to use
things that the standards do not define very well, if at all.

And this is true of any large project.  And also part of the reason that
Rust has unsafe mode.

But yes, in many cases, informal definitions are better than no
definitions.  And I agree that it is possible to reason informally.
After all, the formal definitions of RCU didn't show up until RCU had
some decades of use in production.  ;-)

> > To be proven in the context of the Linux kernel.  And I am happy to
> > provide at least a little help with the experiment.
> 
> I was talking about classes of errors that are avoided "just" by using
> the language. For instance, using `Result` instead of hoping users to
> get the error encoding right even across maintenance rounds.

OK, I have to ask and I apologize in advance, but...

...have you taken courses in statistics and in experiment design?

> > Working on it in the case of C/C++, though quite a bit more slowly
> > than I would like.
> 
> In my case I am trying to see if WG14 would be interested in adding
> Rust-like features to C, but even if everyone agreed, it would take a
> very long time, indeed.

I know that feeling.

And to be fair, everyone would have been better off had C and C++ been
slower to adopt memory_order_consume.  (Another thing being worked on.)

> > However...
> >
> > Just to get you an idea of the timeframe, the C++ committee requested
> > an RCU proposal from me in 2014.  It took about four years to exchange
> > sufficient C++ and RCU knowledge to come to agreement on what a C++
> > RCU API would even look like.  The subsequent three years of delay were
> > due to bottlenecks in the standardization process.  Only this year were
> > hazard pointers and RCU voted into a Technical Specification, which has
> > since been drafted by Michael Wong, Maged Michael (who of course did the
> > hazard pointers section), and myself.  The earliest possible International
> > Standard release date is 2026, with 2029 perhaps being more likely.
> >
> > Let's be optimistic and assume 2026.  That would be 12 years elapsed time.
> >
> > Now, the USA Social Security actuarial tables [1] give me about a 77%
> > chance of living another 12 years, never mind the small matter of
> > remaining vigorous enough to participate in the standards process.
> > Therefore, there is only so much more that I will doing in this space.
> >
> > Apologies for bringing up what might seem to be a rather morbid point,
> > but there really are sharp limits here.  ;-)
> 
> I feel you, I have also experienced it (to a much lesser degree, though).
> 
> I could even see similar work for Rust going in faster than in C++
> even if you started today ;-)

For RCU in Rust, there would first be much need for the Rust community
to learn more about RCU and for me to learn more about Rust.  As noted
earlier, my next step is to better document RCU's wide range of use cases.

And I know (and appreciate) that some in the Rust community have read
my open-source book on concurrency, but I suspect that quite a few more
could benefit from doing so.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211022203448.GC880162%40paulmck-ThinkPad-P17-Gen-1.
