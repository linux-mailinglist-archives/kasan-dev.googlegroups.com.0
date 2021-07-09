Return-Path: <kasan-dev+bncBC7OBJGL2MHBBON5UCDQMGQEHOCYVDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id BEF2E3C2208
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Jul 2021 12:02:33 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id u7-20020a5d46870000b029012786ba1bc9sf2686459wrq.21
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jul 2021 03:02:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625824953; cv=pass;
        d=google.com; s=arc-20160816;
        b=eJe2G2ljT2LEdCVYeg6xpIs0Z6kiJ52U5OCXrZnLPMX67ETPDLjdqR5ov0Lsg77ZMF
         VVk7R3QgrfOul5xifgT0rFVPwEn7o3VmNXUSofJ+vgn3Ry5GqRiCniCoOrGSt1AqE8tL
         jZzzIOpL1rU4jOpp15NesZT4SESp+lnJor0/iUW7FZWY8UAIcYgchJ57wzKzbvGgL/0n
         dUQ1jEtyHAvcoq1mVkp4AHD64BdPDM2+WMOr6hNu9pBsvl9y0dpqGb85ZtSCGSHDN1LB
         twAeVjskwRvzyDG7oBs8oP6RhRbTncVfPflPDQ0hGQusbtda2pn+K8b0aCA+Diju4NI6
         BULw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mpjcjbmecmISL+t7Y+BfzsmHI7EEN9Gkr7Ol/zqaxbM=;
        b=ZWV5LdVRBM8UI/gCpJ+I1rZSWiTdMR80+TdKtnoMo6R0X29CpQOZjbboivPzWd4c7Z
         9y/9dd3uAzQ+B1vNz2UUGShHdVkFLsrz2bRzcq9t876DH9fc69h0qmRI9AhGLDwsBn/0
         THAXG3jLhNCyo1+0xb60L9pOUFiPnHKg+7ZoUoiUbKTzHuXOZHYf7T8dC4QyFhuVxlvn
         s7VMoVWtCOOUuAO83ibeBhKKpYDfmDXApQT0MqAoiKjqRbyiXflCp0UjXeT7DKy4nJdi
         j78MJ52jenHGrmUe6XNcI2ss+FNwIIdoY8R1E6MsMacUDvpTTIqjsYi19rcDgQtwdIhy
         DOXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aADWTyMA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mpjcjbmecmISL+t7Y+BfzsmHI7EEN9Gkr7Ol/zqaxbM=;
        b=WrAdyozdITh23bGuXp3UhharrNNSC7BDh/IubpV/JjCCfhjb12cWMdBqxomhHkll/w
         ZW1sei5LNnUfeqY+L/T678ykGASPCzi1l/Vixrq80BQ10SDLjZnHO4ROuGMTLKe5uJsm
         PaiMDPsYeRjqloQsrZ0EyTj2dCTFCFwed7VHR3UVFgwTCouQnpCQ89OfKfSCPVI0L5Mk
         zEuyd3YQRtDZjPcmu4TmT7ejGzLbnoyzmnQCFzI6GYiQblvQ+u0xNWSDTdtC6u+GMgvB
         Kj+z/hJuUgVTVWHT2FYOL8xPccivgnkoddzi48eBM6sJqf1XAf6FTp6ZegAiUnYDoHH6
         mfSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mpjcjbmecmISL+t7Y+BfzsmHI7EEN9Gkr7Ol/zqaxbM=;
        b=YCs3Ojrm0sAW7/w/9cN/Nl7xQ31yPcNfnkV3SV0rFDXQobA7zZ1FwHMV9BTobN3Fxb
         T66Jgv/GkV0YBUoCcHRS06kJ1N4GJ85bLpoYTPe4Ojl9Y178EgZaJqgaElnE55Fnfkvc
         fBnbIx00eFXVtCKtmpJMJRfD+iRXEyrucgTlZ5SXxHNV07VI/iM8B9GZxH8275euDsl7
         RrxrJbnPKZVLN97NcX2uJYTXmRNHtmZKmEOWHSYQjz4Mb8ivDEZMDIcmtoRzjBTu9rH2
         wv4pi2xE3A4JYd+iiAjKiJyz6wlNesy8H9LPOESB3trtDanEtAW6A06R5YUWUNkJgUv4
         pBnw==
X-Gm-Message-State: AOAM533ZMIykbvCMvSf+gl7RmZIvH4S+T6x4iVTNCB3yKDAEKQCgNc2N
	LF+7pPZ9Z0UWrzK53W0sRSE=
X-Google-Smtp-Source: ABdhPJwMM3ZwVfiJjCPLbCmWrO37n8cATzpdtNlYR4HCwn+/e0h8HZlkrO0gfuX67PpxWBZ0EyUyDA==
X-Received: by 2002:adf:a1c4:: with SMTP id v4mr7700419wrv.217.1625824953496;
        Fri, 09 Jul 2021 03:02:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd86:: with SMTP id x6ls650855wrl.1.gmail; Fri, 09 Jul
 2021 03:02:32 -0700 (PDT)
X-Received: by 2002:adf:e4c3:: with SMTP id v3mr15470757wrm.362.1625824952498;
        Fri, 09 Jul 2021 03:02:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625824952; cv=none;
        d=google.com; s=arc-20160816;
        b=oW/OzIlsBRohhNOQKx/vyTXdeFV3tkLkCQKcw1g/T8j+kHZoK6Bqr8Ub1yTRQswxO2
         XBgg1OzYDh8JWbEcT2FjiBiMlqC9PF/6gKPpcZhhCC7iDWc+fHUGqzXKgJKC/Xx3qxcP
         ARsPZrZYXp1MZAZ0DfCLwSjGZ2hVIIz8+JrRDzb0ZpfQjnLbJSctv6gVNwwjQRlS8QAL
         QxHw70VV1SidWcemPsj8a7XXq6dPNGK6vliFPWv+mE7qq2e5PAbKWyDz4hMX2x7eSP/S
         AiaqbrvIJZznGuFAUfuP905OPi2fCzlxahcxdeq8mxX8LNNLnhI0QTNm2GrwM9YMitQL
         p/ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pMpdjHLOcFTwAYrNYMAV3UZbyINNRc9Ym5LX3jQiX7o=;
        b=BtrpoiIHE4MVw06K0TUqQSFqY2TIRAg1Hw5SlXK7nHdbxMfabKwiFQ35hQhRHdUvtl
         kins1SpFwcPuvbrcCxMv+XW6rPNgSeoy+2cZtJ8PP+18/Ddh25wZcw4+Mh+Kbw/Jtg1d
         JjUImpkTILOm5dJMtmz8f/R3rchmGxHWtwh60CFRq1aff0mWeVBNwtBvcnOr4k3jqmE9
         X6syzTNE2IxrwAatCngA36nmeL5C8l93t/aSFIMB6mVmgbCU0mrhZXO3Sg2JxWPtd+2B
         7v6zeiEWeOBYUVXof6wK85MyzrENwYyckkLWEnyyWDg+Ij4Nx4iwmOjVUMrDA7u3HeJm
         dxZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aADWTyMA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id k18si713423wmj.0.2021.07.09.03.02.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jul 2021 03:02:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id d2so11443561wrn.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Jul 2021 03:02:32 -0700 (PDT)
X-Received: by 2002:a05:6000:551:: with SMTP id b17mr39732334wrf.32.1625824952017;
        Fri, 09 Jul 2021 03:02:32 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:8f0a:b44a:3744:8a04])
        by smtp.gmail.com with ESMTPSA id x4sm11724356wmi.22.2021.07.09.03.02.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jul 2021 03:02:31 -0700 (PDT)
Date: Fri, 9 Jul 2021 12:02:26 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>,
	Leon Romanovsky <leon@kernel.org>,
	Linus Walleij <linus.walleij@linaro.org>, ksummit@lists.linux.dev,
	kasan-dev@googlegroups.com
Subject: Re: [TECH TOPIC] Rust for Linux
Message-ID: <YOgesjNqpsZNK5Gf@elver.google.com>
References: <CANiq72kF7AbiJCTHca4A0CxDDJU90j89uh80S3pDqDt7-jthOg@mail.gmail.com>
 <CACRpkdbbPEnNTLYSP-YP+hTnqhUGQ8FjJLNY_fpSNWWd8tCFTQ@mail.gmail.com>
 <YOPcZE+WjlwNueTa@unreal>
 <19e0f737a3e58ed32758fb4758393c197437e8de.camel@HansenPartnership.com>
 <CANiq72mPMa9CwprrkL7QsEChQPMNtC61kJgaM4Rx0EyuQmvs2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72mPMa9CwprrkL7QsEChQPMNtC61kJgaM4Rx0EyuQmvs2g@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aADWTyMA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Jul 06, 2021 at 04:55PM +0200, Miguel Ojeda wrote:
> On Tue, Jul 6, 2021 at 12:20 PM James Bottomley
> <James.Bottomley@hansenpartnership.com> wrote:
> >
> > The main advantage is supposed to be "memory safety":
> >
> > https://en.wikipedia.org/wiki/Memory_safety
[...]
> > The other thing that makes comparison with C hard is the fact that
> > compilers and fuzzers are pretty good at detecting memory problems in
> > the existing code, so it's unclear what memory safety ab initio
> > actually buys for the kernel.
> 
> Compilers definitely do not detect all memory safety issues -- not
> even close. They cannot anyway, in the general case. Not even in C++
> with `std::unique_ptr`, `std::vector`, etc. Rust can do so because it
> places extra restrictions in the modeling capabilities (in the safe
> subset only).

I think the main point was about the combination of sanitizers paired
with fuzzers like syzkaller.

> Runtime detection of UB in C is, of course, possible, but the idea is
> to have static guarantees vs. runtime-checked ones. There is also
> runtime detection of UB in Rust for unsafe code with tooling like
> Miri. plus all the language-independent tooling, of course.

I sincerely hope that not too much trust will be put into Rust-only
dynamic analysis via something like Miri (for the unsafe parts). For the
kernel, first and foremost, the Rust integration will require proper
integration with existing sanitizers (with `rustc -Zsanitizer=`??):
KASAN, KCSAN (possibly KMSAN which is still out-of-tree).

We have years of experience with kernel dynamic analysis, and discover
over and over that bugs are missed due to uninstrumented code paths
(including inline asm and such), and put in a lot of effort to
instrument as much as possible.

It is very likely that if the Rust portion is analyzed alone, be it
statically or dynamically, that there will remain undiscovered bugs due
to improper abstractions between C and Rust. While I fully see that
Rust's static guarantees are strong for safe code, I'm pragmatic and
just do not believe those building the safe abstractions from unsafe
code will not make mistakes nor will those abstractions shield from
changed behaviour on the C side that directly affects safety of the Rust
abstraction.

Not only will Rust integration with K*SANs be required to catch early
bugs in the abstractions, but also be necessary to catch e.g.
use-after-frees in Rust code where C code freed the memory erroneously,
or data races between Rust and C code.

But it will ultimately also prove that the main proposition of Rust in
the kernel holds: less bugs in the Rust parts over time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YOgesjNqpsZNK5Gf%40elver.google.com.
