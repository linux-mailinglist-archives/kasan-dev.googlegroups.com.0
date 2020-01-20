Return-Path: <kasan-dev+bncBAABBYEYTDYQKGQEH3EU7UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E10C11432DF
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 21:24:01 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id q1sf218546pge.12
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 12:24:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579551840; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlpjqB+2BakoILEvXDXMJcY2WFrMDdF1CSJOhYACB3qbio/ApyWmBP0VsKdDY6wFqk
         zlyA7JYKRjXrGNWJJYMdsd7ZSxutzNLtPOiA9Vsl5HuMgT1Vc0caxVF1P6NZRQLXDfZf
         Pgqkku48M48XH1OlmjxjWqLt4Qx7I2hupIXAUDwKNxTVLy/iBVN0XE6JXIhuIRgzfKey
         o2Fvx4oRgkPK6RYd6IHrF3Q1/BFIL6P9Py0pX97cn/9SZ0DYbC3oiLe/HFpY3iuXsKO8
         3J2gdFXIMEP8sVM/USQ+tm1T3PgXwCIKLiStg5yzxQ7/yp+EOLGUdyxYXTXfC+Lz6JGG
         U8Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=ZTR6GTVubkBrx2OCGikk7OJ5zxMvATZ8bSBquLySiE0=;
        b=UDJdKPz/FRBS7ATDwg2VjoV9MF241cJMLbaHdCJUjEL7ul17vpFGsWm4OHLoFN013+
         BCM5s3rWrjyylme0xGyt4bxasnWYiyyIzFwBn6Pl5xyeFVS4yna1ljDoOpTAewa6vGuD
         DVlHiBr6xB8P0DEiHrRCeYyGGyeGKfqTvxkn6dow9jVhAxPwfO98n/2IceB+nwud1cNb
         RnXCKVgfth6ZHvaDBeTczl8fJJOPSssSGgl1jnCfFvAF0YEgNI4cy343vUy19DE1MPzK
         OaVUvfOjOlal+r/NWg9mi2nxccd31LETwNAt0/sNiUWDRCX+UdmqWF5EOlmEGcBvm3ir
         cBBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Trz8Uogv;
       spf=pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZTR6GTVubkBrx2OCGikk7OJ5zxMvATZ8bSBquLySiE0=;
        b=mqqNZlJ6HZcTEqDkdgVD0T0yHyoaY4xRqsqceY9IMFlS4+oJwiQW3Y/ebJH0ine/r2
         3BTYBwFsIJK+YYbr2gsOae7765/YldXnwBAt5eZA39gpAaCFSpOuMbT7q5ZuTPIGaI1W
         pkm+Z4XGReKQlasQSL+jmhXMc6jUcRsD4EbbRwvTxh4KVz2QlttUdtSp8EiHz/kUWjFB
         0S0K4nk1y/M+XOEDlFGmvCpeCvqccZy981SovZEHsMrinu3C8Xa3PRqGa/l5wVYQsrxs
         UIqB5BStSg+0ffi2v0rPCuQMTnYiOxtCWS96R8Jl0YjPuPvLVjFzaxbB0Ia7yOEQ1yy8
         bAcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZTR6GTVubkBrx2OCGikk7OJ5zxMvATZ8bSBquLySiE0=;
        b=pyAbJMp9TcRZv3zayPPlrhDYk4PYBUC9xaDnD3k4qpz/3OV0g5n2DHnazIe8sqcAMd
         LwNfm1SPZQo38zz/svrR4E9frMEtgT/oFDboIQ6LSXqIVJn057C6MhvkXUQ/4tVuwmEk
         DoU6cKTAKxlhnNMJldeziwdzdZBv8/Zw1n2BgShIbsGC4zmasYXcWhVKC7vl5jmIlZ+k
         biA8HpzVDFyM3CxoKj3WPeWYy4dlVQyiv4EvKIVI+T4CgJopY/DAJw8DCsQNMmJzdj1/
         CmS77i7zt6IScc9vzdC654g2PF5GKmeZV9vBKTJvh/zmx89vHyYTC8VPWqC04n/aETJ1
         8biQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWf98awXEXdsPLSXnHl6iHzQsqu77u90OduCruXtG5IneqqcmoF
	/nYFbukNfVPGdp4N7ZgRCT4=
X-Google-Smtp-Source: APXvYqzRGh1QLQWx0uca8k/7KCYxrdMsO2TynfnRWiIhl1XYMIE/eQO3IOkBXBaFcBhISsO7YKefXA==
X-Received: by 2002:a17:90a:c301:: with SMTP id g1mr863442pjt.88.1579551840198;
        Mon, 20 Jan 2020 12:24:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8686:: with SMTP id g6ls10176351plo.12.gmail; Mon,
 20 Jan 2020 12:23:59 -0800 (PST)
X-Received: by 2002:a17:902:7b86:: with SMTP id w6mr1438405pll.317.1579551839808;
        Mon, 20 Jan 2020 12:23:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579551839; cv=none;
        d=google.com; s=arc-20160816;
        b=HwzadLX/4vtgkuQnbSwgXmtc1+RSoA3zErFH7dl/sEaCRprEK1lXOn8dNIfCw27XMj
         sWdEr4/TRNACKOzQwPKEmUoA3TrbYQRJ1LGW5g/FkXgXpaJnAj1t6YYtXkT38LG8vi27
         +jyZeA1IRkWg3vQ2nkddFkuR+n/pny6B/eVZCdqOsAug8lfrHdeH35cKsKumvsWQFlHu
         3Y7GB0euyZn5Mu9dromrEyPCyo/hllNfLPW6xyGv9ideWvsG8/5K0p8C8Nl9H2Bjsf6B
         9Bu4yYb7AR9JSrlMv6usH2bAgF6YNugaUbv2fzozt33PFLr8/oe04xE4HzPWQbfL/fos
         NzMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wEGTHLrigkXKi4scRVgiXZcVEUOKm1jYWbV6RrGGpLE=;
        b=om1B0o+DITENROs/gR2qrVrdSm/lv4HIOTrohvXDEkvYgZZ28DLkUtie9aPfTxB9pA
         7uNeNcYC+O4uzVPozX5ekmF0ORxIzOBwjzPiG6JDzIbVXfLKsSg6ynPZ7C9lveqxrvHo
         xkBgwV/YQfyF188BOJltcX4H4EcXzZnpy2c1C3smcaitwpKfRqCP0O70KKh6tAazdVT/
         ohAgz/cIUFI9mL/r3Sk9DFIUR7oEegEUkTkvtZz9RmkOrr6BMFTaX0Sivw13wfTXKLKd
         VU9zAkYvfC3rSW2v1oRGsGl7Eh2QcDYaD42L3w1nFVcqGvTswR810P1e1Wx5JPW1LW+c
         OkKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Trz8Uogv;
       spf=pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d14si1646804pfo.4.2020.01.20.12.23.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Jan 2020 12:23:59 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 602D1217F4;
	Mon, 20 Jan 2020 20:23:59 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3A1093522745; Mon, 20 Jan 2020 12:23:59 -0800 (PST)
Date: Mon, 20 Jan 2020 12:23:59 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200120202359.GF2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200120165223.GC14914@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Trz8Uogv;       spf=pass
 (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Jan 20, 2020 at 05:52:23PM +0100, Peter Zijlstra wrote:
> On Mon, Jan 20, 2020 at 08:27:25AM -0800, Paul E. McKenney wrote:
> > On Mon, Jan 20, 2020 at 03:40:48PM +0100, Peter Zijlstra wrote:
> > > On Mon, Jan 20, 2020 at 03:19:25PM +0100, Marco Elver wrote:
> > > > Add explicit KCSAN checks for bitops.
> > > > 
> > > > Note that test_bit() is an atomic bitop, and we instrument it as such,
> > > 
> > > Well, it is 'atomic' in the same way that atomic_read() is. Both are
> > > very much not atomic ops, but are part of an interface that facilitates
> > > atomic operations.
> > 
> > True, but they all are either inline assembly or have either an
> > implicit or explicit cast to volatile, so they could be treated
> > the same as atomic_read(), correct?  If not, what am I missing?
> 
> Sure, but that is due to instrumentation requirements, not anything
> else.
> 
> Also note the distinct lack of __test_bit(), to mirror the non-atomic
> __set_bit() and __clear_bit().

OK, I will bite.  ;-)

We also don't have __atomic_read() and __atomic_set(), yet atomic_read()
and atomic_set() are considered to be non-racy, right?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120202359.GF2935%40paulmck-ThinkPad-P72.
