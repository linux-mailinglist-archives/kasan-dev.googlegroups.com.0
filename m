Return-Path: <kasan-dev+bncBCJZRXGY5YJBB4UTSKFQMGQEFOKZZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 852E7429731
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 21:01:07 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id u66-20020acaab45000000b0029850ee48b8sf3106411oie.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 12:01:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633978866; cv=pass;
        d=google.com; s=arc-20160816;
        b=i2t+tYg/Y0QY8viKmAFMAicMoFjxOdg11qRm55eM/YluM6SdpK9Ze6j2mouI/r9gRY
         VOgYgFSdVxu16yBWZanuxmWx+XvLCGpsiPWR2NAPMfwL2rOSXvrJ500TiPRxJo9D5Iqp
         kPWFzdexF67m3hT7h8p1M4W17m2KE4h/Z5ifTkdFfJ4vUzJv8oySSoPKgaF2/GvgLJ5M
         nDuD6urS4AqoSpTNCzi7UJJgnUdP3omMfx0V5wFwHEbrruw3jdYLf5TDVQ1ZsvPiY3sW
         1tDCHCi3EiSXR35wO2y0t4t0rmBCuntmFMb+f5VZhz0PxFjIaY/LVbhbuo5GAcznECT3
         SGFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=sRZZ7asbRe89AUx8ifCQ/9r1eE/31VsPRh501LocUfA=;
        b=gIz8UqBamqHlgUWNb/wh/bmdwGEI8KVvwmPDgIjGv8qbcAChAGGO+qJ9ZUKNZHaFc7
         eEBuotdlhKkCmTDRqnWap8yBU6101qHiH8e/Wr/6hwi8mM7u9PoF7BWMVaQjYTaGbP20
         ZSvrbc4zTihiifK4BsPMlORbRyoS+pzFcrlYjd4LtUPbnCIzpgTtscuA44X/+sNbhosU
         s8QJiy17Kl2N8U7Hz3fzsl60htOjif2FI6mwRPpKDDtFXacWKM55UuYmTYRJ3SP2mqbI
         DmEwnUWIlPZ3x9vDmz/DrXKO+oPN9hWJ2MavQJEZNJObrMcEVPwDp9lNYFKAsWYb+tJm
         5gPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kvfkEXIX;
       spf=pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sRZZ7asbRe89AUx8ifCQ/9r1eE/31VsPRh501LocUfA=;
        b=ZW328Jk30V/TIuudwnDkfXZK5SYHVtOxkjGFGEIgyYTIOH3b8IxkmDMIstqm3Q3j35
         cROweb+9Ii76jaxS2weHGwCrFxl/NVJfwjrYfSfIU41pyk9rdikEG6Jsjng1K+8udgbn
         2fAHUAO5/EtrRf0hrMYdRpQi8vZUNT7wPcbHroKDtxWrHBbKPoxjmh2gHo+JI2jVsBNX
         NYf6OkUSdoCA3QDnx1puj4mm3Zdi7Z/BoUsmvVZJs5XI6Vk5BAvzND2ORE51rg/OQ1UI
         S3r4ohkC3USALh+gfBTsFWITDJB0omDTHH54KxypR4zi/pF/KQs8X1DFzvN5w+BFJrBE
         n46Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sRZZ7asbRe89AUx8ifCQ/9r1eE/31VsPRh501LocUfA=;
        b=II6LzWBk6CIiM7+XWPu8A920ld6IuB0xbcFPZWXNVkkO/gFgjfx/QKTLeTaA/ZrK35
         DbIP+qT5yz4L0OXm8Vs7uM+tnE/damP9QKeQLhHqrJIe4Xvgys6ZZZK66HewDQki6f9p
         3CFMpOWt0p3XBvzHfATzeS8eGPfdI7T5O/DM9Dn9OPtww9fYpLd6GLASpmgv2MKuA9cA
         31kVd0MQzXcQTAfwR3OOzd14ADX3HyT2Ki8dHz7Fk7Qi0uTED+lWt0FGcF/Y0TQhS+lr
         CQPWaE6r7wGagjCkhDL4LZvNik84WMLkiwztUQs7k2C5G+ltgKMFHxbWHgez+RzEGwC6
         aYOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53161UQytzjxG+9mGgx1ECk0j5pDGLt1fKa9BLJveuqmOHfHs3vr
	eQDX/374qp1PcPpCHCykk5E=
X-Google-Smtp-Source: ABdhPJy7Yp3PIGSmoImXbmEZ6KUWIn2NWMrZVyBBDVmzWmqj2hWalACBbB4HfdNAKZ5xFm3uVTeGuQ==
X-Received: by 2002:a9d:60da:: with SMTP id b26mr23646107otk.369.1633978866425;
        Mon, 11 Oct 2021 12:01:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1219:: with SMTP id 25ls3065210ois.4.gmail; Mon, 11 Oct
 2021 12:01:06 -0700 (PDT)
X-Received: by 2002:aca:4b15:: with SMTP id y21mr506382oia.89.1633978866036;
        Mon, 11 Oct 2021 12:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633978866; cv=none;
        d=google.com; s=arc-20160816;
        b=rqTEgcJ3spqx3kGapd3P0QusWYd2vyTEJ7+YUb51G+YUNzd3ZSeAkRJbHW6e3iaP3+
         CBOQLO7mNaUiQBgTZUPL/uzl/Q284AMDfMgCTezafMH3ahBLIkEApywgxnhgoSfupsml
         dMCWa/YA60yj1fa+sxXmqsZB6yGTBki2vGQs6psm4vtJNpFWazsZa3YE/xaR4iAQHTgu
         sSycX6P6r640Co9ArpEeD78RDweKIygZol9CXs12ikJzE6vfqt1FyM6EFn0c3jmm89wE
         XuGdT2Whjb0DBg/gmkDE5YwrmAtLp5Wv3lDQpmxGHUBlSxYwk0yQJ48cEwFAq+7P4gdU
         oTkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8GNKI9GaU9IfAYyeZ8Nkdju+auiKFH/oY7hN1n3duWU=;
        b=hFzRuW5bj76B5X1Zg7eHcSJfgvL/5myur+Dw4vnidfZCLnmHulyKq19Td/t3cLPjCk
         mcExe2jJsW1WHKMc0C90B/6E43RE7L0dX727znQigJq7lZKShYO4tesnw+A+cfxgBqNP
         xLVau2PSRTx82jcpNMGQtFiKl1d5NvD3lDUOKZ8i6lZid7iESUrjQlQgrIzQN59uTwLj
         5Azz9JxYmG/U7LRx8sqKkYNM9eK2EwyZkZvzkrz3/Bv9GGexbGo8b1EEx3pqtSHFZRDb
         /bQo/4kXES8kh84RtqDR7uPDIzeIL3xei3wFBWIW+3vurnuOfSBnG4tqGLn7oWfxUNw1
         JoHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kvfkEXIX;
       spf=pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bg28si1374717oib.0.2021.10.11.12.01.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 12:01:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 34B6F60F23;
	Mon, 11 Oct 2021 19:01:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 02D665C0687; Mon, 11 Oct 2021 12:01:04 -0700 (PDT)
Date: Mon, 11 Oct 2021 12:01:04 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kvfkEXIX;       spf=pass
 (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Oct 11, 2021 at 03:24:53AM +0200, Miguel Ojeda wrote:
> On Sun, Oct 10, 2021 at 1:59 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > The advantage that GCC and Clang/LLVM have is that you can simply say
> > "CentOS vx.yy" and define the full distro in an organized manner, for
> > a reasonably old and trusted distro version.  Perhaps Rust is already
> > there, but some have led me to believe that the safety-critical project
> > would need to take on some of the job of a Linux distribution.
> >
> > Which they most definitely can do, if they so choose and properly document
> > with proper approvals.  Which should not be that much of a problem to
> > make happen.
> 
> Exactly, it is doable, and the language is really just one more tool
> in the process. For instance, if I had to take on such a project right
> now, I might be more afraid (in terms of cost) of having to adapt
> internal testing-related tooling (so that it works with Rust) than
> about justifying the open-source compiler.

The main issue I was calling out was not justifying Rust, but rather
making sure that the exact same build could be reproduced a decade later.

> > In the near term, you are constrained by the existing compiler backends,
> > which contain a bunch of optimizations that are and will continue to limit
> > what you can do.  Longer term, you could write your own backend, or rework
> > the existing backends, but are all of you really interested in doing that?
> 
> I am not sure I understand what you mean, nor why you think we would
> need to rewrite any backend (I think your point here is the same as in
> the other email -- see the answer there).
> 
> Regardless of what UB instances a backend defines, Rust is still a
> layer above. It is the responsibility of the lowering code to not give
> e.g. LLVM enough freedom in its own UB terms to do unsound
> optimizations in terms of Rust UB.

There are things that concurrent software would like to do that are
made quite inconvenient due to large numbers of existing optimizations
in the various compiler backends.  Yes, we have workarounds.  But I
do not see how Rust is going to help with these inconveniences.

> > The current ownership model is also an interesting constraint, witness
> > the comments on the sequence locking post.  That said, I completely
> > understand how the ownership model is a powerful tool that can do an
> > extremely good job of keeping concurrency novices out of trouble.
> 
> I think it also does a good job of keeping concurrency experts out of trouble ;)

You mean like how I am not coding while I am producing blog posts and
responding to emails?  ;-)

Other than that, from some of the replies I am seeing to some of the
posts in this series, it looks like there are some things that concurrency
experts need to do that Rust makes quite hard.

But maybe others in the Rust community know easy solutions to the issues
raised in this series.  If so, perhaps they should speak up.  ;-)

But to be fair, much again depends on exactly where Rust is to be applied
in the kernel.  If a given Linux-kernel feature is not used where Rust
needs to be applied, then there is no need to solve the corresponding
issues.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211011190104.GI880162%40paulmck-ThinkPad-P17-Gen-1.
