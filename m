Return-Path: <kasan-dev+bncBCJZRXGY5YJBB6VVQOFQMGQEULKCPUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71A9A427471
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Oct 2021 01:57:47 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id g10-20020a17090a578a00b0019f1277a815sf8397162pji.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 16:57:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633737466; cv=pass;
        d=google.com; s=arc-20160816;
        b=bzYeTSw8k7UwTKRX65Xmp1EuNdmTB/fJ7Hn5N+bpvaYIvS55xtprwbPY4XLvwAAfE4
         BsIn5v5vQr3Yb7GeLac1yKrwYD9GbaBaV15FcDq8KWNRsUZ2GoOI6yHQx1vXiSrkN8Ij
         Fub++chyE9tEHG7f9IUvEmyCDZqTJC8hXSjypGAC7uO2oHes9y3M5dspb8VAdlPBYdsO
         MX3LqxUT3K+uvCeYBlLmB4ZlWrdnqZEP8ObV8+Om1rnaA07gQx+D98ceDc66xxdcwgo5
         RU+Izqpab1GbxBtBY/kemxNaXmaDa62UaijGW+dGkgiV1Kl5g4aHuI2435lcYzSh/lic
         BQWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=oC3QUOwV+rr2US2jmHaLebU2CIX6R8QEInv0rund2+U=;
        b=PHJbUCfvsejhZ3KuzYbiKubgt5eoQWtO7irPj/rcGHqvOiM/gEEjsP34FTG80atxUf
         lkIwfMxXm3Eh2RqOx4pYOXOVQQfBg3EAKLhBxBNHHUpf39OUYPxcZqD//Eml7cWcAhij
         grbRQV6H5S7FPVC7d2i26WN8iCbCRElVgd1qnfUEflW3z+VLaBVFs/B/KvIc63UDwuUP
         fIL0lo+r6Bj4rgQSR28LKC6jTq8Z6gWTIH1Uawid30/ucGlpWE/r1gT4/3uD5dEfOR6h
         RxP1WthofT1dpWoUWEKqGY/Ckx/Ik8sRnQ6qkeKpHeAJyLsZn33CzdPQaeLOb9esRYpX
         7lDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pYnxhcbD;
       spf=pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oC3QUOwV+rr2US2jmHaLebU2CIX6R8QEInv0rund2+U=;
        b=leheqM2AFgHE7+lGJz74tfoBgSIEDeYUMV2AXynZ/LxqZKI0kSEdgpeU/R615l03Eu
         RXfQ9pdihQWbhj+d6BZCblyScm4rYZSRjhf6d8dAGpN3UrGSNhUiCtY/ttf7HBmBEsIs
         GsTgIsyj4YZVQUY11jgQ7JVDdYcPGEszQzmuv4gS0+noi8D/6Vyhi6OE5a591Ye5AXfF
         CCUE/T/YbIjTdt+2ROoUI5I8oZ67TSOhBhTp5K7GwQJax+lXIr9lVp/3FxthUO0OgBoE
         akbTBBQCWj4EtQgsoEZwnou2gjT/5zzCMuLyLYjhBDtivA7PgLiJgmXoXus92S48yoS+
         wRYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oC3QUOwV+rr2US2jmHaLebU2CIX6R8QEInv0rund2+U=;
        b=Vc/96uRtuppldSgqpj2atblWnS2UUcW4Kzb41cgj85SEU4M4sijhYWv+JhNaBx2okh
         pnnvtJ1WE1eRDdI9ho8U7K3bcY6kOI/Q2nD3eTHEfzhWhNlY9RA/SkPzpkpaG20eSgwh
         UiCIj3uUYvGDwCz8fbIT/ica3qV2aY14/g9iAN9EY00e235KcmmvQiAnKGL5NfibjwxV
         5gRREHOpz5j8/gkvc+OfUAcPOmHs7HFjK7/FPAaPKunPf3XjLaZ3HHbBBIZgDj++oKqC
         oCFuBUL0rEt4PbOqlDAfgf+yzOFqxwCgTTQMGRU1JkPp/1FPX7v0PWtX20UhMIYo26kQ
         MFhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Y+25HiZoQGlYT3gZvDQoa+EAd0TSveq7RUlSa3ghk0pNp8GEg
	mlc5p2HSbBxo6NG+U1iVOGg=
X-Google-Smtp-Source: ABdhPJy9iWI9jo96TM57M3nZ2l9TCJDDpk9vLSwgDQb6cmJpLvZ/KaawGaQogoX1fXzV9YBm6v6IAg==
X-Received: by 2002:a17:90a:a41:: with SMTP id o59mr13343852pjo.243.1633737466080;
        Fri, 08 Oct 2021 16:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:188b:: with SMTP id mn11ls2325533pjb.2.gmail; Fri,
 08 Oct 2021 16:57:45 -0700 (PDT)
X-Received: by 2002:a17:90a:7d0a:: with SMTP id g10mr15605572pjl.73.1633737465081;
        Fri, 08 Oct 2021 16:57:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633737465; cv=none;
        d=google.com; s=arc-20160816;
        b=iFyOOPq3Hs4nlv+Oqj7KpeQrFMKiwgFPnp7pFVFxgUFj/eGK4+0/bcGD7Jmo52b9pf
         KRfxsmtMWDd31xrXyeUkjca16rgbTEtJ9FMV/ItYXhvDbFGhu3/h37tjy5YM2dzNAfxa
         Ykzdkkh1p4//8K7I8xmAOjh7dPwPCk1WDQpXvxgsgnCtHtOpsIJc+5Z13hmbVDSSUxTx
         4/LF6A2gRQcPFw5jLQfNaKP4BrhdglLCxBiO0paJiZIrD+rPitORATnq2HFK1h1y2LBw
         4XPUvxYx0xrlImYcztocmsqv2kOFCK4SvE7EY7wsWReh7Zqp5g82sITIHYeVASucUCKZ
         BfIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FJLlK0fMQem4P8z1gz1UVo/SlogfsyhviNoENNYzSjA=;
        b=Xg0ZidKKjxH5dLKcn+vLgsdkW7dmjTIfwp+h7YyYwiMbIkpC8beULNV9yF/ggOVQs3
         UQPYHLcMpzIAnbQJPdVaAlEtongDtMXQ9zVKlCVsQuH2XvQrO1yF+ERzr4zYJ7zRM3W+
         k449W83PtfdUW2Kxfb3eHTGYLzGDnbA2uOuVlcRXknN5SfS33emM8yC9Qa4Y1rkado6T
         VMY6btugw1rCksDKFgsmywQswpx9Pzc51ass0bQdmz1fyc3TUhKUh0YpbFi6lTqv4m26
         afydFVa9HfBovFlJ9i1J77GUZGmL49u6ggMozVIN3+IFwbJZ0GerI+faqNQRl4bi+yu1
         i4VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pYnxhcbD;
       spf=pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v7si868569pjk.2.2021.10.08.16.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Oct 2021 16:57:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C7DBB60F9E;
	Fri,  8 Oct 2021 23:57:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9AEA35C1E85; Fri,  8 Oct 2021 16:57:44 -0700 (PDT)
Date: Fri, 8 Oct 2021 16:57:44 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pYnxhcbD;       spf=pass
 (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, Oct 08, 2021 at 09:53:34PM +0200, Miguel Ojeda wrote:
> On Fri, Oct 8, 2021 at 1:42 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > OK, I now have this:
> >
> >         Both the unsafe Rust code and the C code can interfere with Rust
> >         non-unsafe code, and furthermore safe code can violate unsafe
> >         code's assumptions as long as it is in the same module. However,
> >         please note that a Rust module is a syntactic construct vaguely
> >         resembling a C++ namespace, and has nothing to do with a kernel
> >         module or a translation unit.
> >
> > Is that better?
> 
> For someone new to Rust, I think the paragraph may be hard to make
> sense of, and there are several ways to read it.
> 
> For instance, safe code "can" violate unsafe code's assumptions in the
> same module, but then it just means the module is buggy/unsound.
> 
> But if we are talking about buggy/unsound modules, then even safe code
> outside the module may be able to violate the module's assumptions
> too.
> 
> Instead, it is easier to talk about what Rust aims to guarantee: that
> if libraries containing unsafe code are sound, then outside safe code
> cannot subvert them to introduce UB.
> 
> Thus it is a conditional promise. But it is a powerful one. The point
> is not that libraries may be subverted if there is a bug in them, but
> that they cannot be subverted if they are correct.

But some other library could have a wild-pointer bug in unsafe Rust code
or in C code, correct?  And such a bug could subvert a rather wide range
of code, including that of correct libraries, right?  If I am wrong,
please tell me what Rust is doing to provide the additional protection.

> As an example, take `std::vector` from C++. Correct usage of
> `std::vector` will not trigger UB (as long as `std::vector` is
> non-buggy). Rust aims to guarantee something extra: that even
> *incorrect* safe code using `Vec` will not be able to trigger UB (as
> long as `Vec` and other abstractions are non-buggy).
> 
> As you see, the condition "as long as X is non-buggy" remains. But
> that is OK -- it does not mean encapsulation is useless: it still
> allows to effectively contain UB.

I would like to believe that, but I have seen too many cases where
UB propagates far and wide.  :-(

> Put another way, C and C++ APIs are the trivial / reduced case for
> what Rust aims to guarantee. For instance, we can think of C++
> `std::vector` as a Rust type where every method is marked as `unsafe`.
> As such, Rust would be able to provide its guarantee vacuously --
> there are no safe APIs to call to begin with.

Believe me, I am not arguing that C code is safer than Rust code,
not even than Rust unsafe code.

> To be clear, this "incorrect" usage includes maliciously-written safe
> code. So it even has some merits as an "extra layer of protection"
> against Minnesota-style or "Underhanded C Contest"-style code (at
> least regarding vulnerabilities that exploit UB).

Except that all too many compiler writers are actively looking for more
UB to exploit.  So this would be a difficult moving target.

Let me see if I can summarize with a bit of interpretation...

1.	Rust modules are a pointless distraction here.	Unless you object,
	I will remove all mention of them from this blog series.

2.	Safe Rust code might have bugs, as might any other code.

	For example, even if Linux-kernel RCU were to somehow be rewritten
	into Rust with no unsafe code whatsoever, there is not a verifier
	alive today that is going to realize that changing the value of
	RCU_JIFFIES_FQS_DIV from 256 to (say) 16 is a really bad idea.
	Nevertheless, RCU's users would not likely suffer in silence
	after seeing the greatly extended RCU grace periods, which in
	some cases could result in OOMing the system.

3.	Correctly written unsafe Rust code defends itself (and the safe
	code invoking it) from misuse.  And presumably the same applies
	for wrappers written for C code, given that there is probably
	an "unsafe" lurking somewhere in such wrappers.

4.	Rust's safety properties are focused more on UB in particular
	than on bugs in general.

And one final thing to keep in mind...  If I turn this blog series into
a rosy hymn to Rust, nobody is going to believe it.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211008235744.GU880162%40paulmck-ThinkPad-P17-Gen-1.
