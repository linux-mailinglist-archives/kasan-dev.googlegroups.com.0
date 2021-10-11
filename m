Return-Path: <kasan-dev+bncBDRZHGH43YJRB4NER2FQMGQELNAF6MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id BA249428497
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 03:25:06 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id m19-20020a6bea13000000b005d751644a6esf12483970ioc.15
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 18:25:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633915505; cv=pass;
        d=google.com; s=arc-20160816;
        b=ismpvzwLhDWazEZcqbf1BQAIAFseCZJNThs9q3x29bjLA4qdedn03yjaFttcmQf6FA
         aRosaUyXVvGFrpyHSeAj6Gq3udIPFD10veH3Bjvcuh1oL8lwWAojjZ1wrRPx8HJw06EP
         iRoHlUEGSwuN74YjAY1Axvvi+Vi8M5v3gZgR3PC1jaiEOWhEwmKXXhVZUzv+uvgS3CPs
         +asB6ByXpZuRUWtd4klZpFxD1ND6FeQ6PkIw7s92TmGtaJRN2N00ZSQZFOb0HdVWjYmu
         u7+qt/jEhu/ZMMYfI8JyoKkigryteY031s1a/oz0wVuAT2f4fTd6zKpy9VCtU43GTjLi
         hKxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=eYHK6RyJs/Ab0MMCWptw99JmP2cXwnN4STnffsF5oCU=;
        b=DCIloS0o9cEzmpVleX3hPzx712tYzyNvt55CaEtBFAg4UnbI2I7EYblQnKPJZ+z+A0
         rnt1sVXeEby84dylySpqstVe11TqWP17+AgrUTUWh8A3RDSMUJmbuSFbDdMsbYDvhA+b
         HQVkKQ5mhS21QdQ0aeTUC8vExwbCfbpexjBaGCZNnNN3LLehT8yNhdf4i5ocOXhPwxM5
         e6/7XJD7eEf3kjV2YPTFzUD3Pry/M/tj1Gw68tcblfG5zuQYYeYfbTjYAkcpQ8e+tg53
         Mluupg5Zb8WB+lb5jWR8XjiKHZFTtUIfwUchlZUMwWrN48hVsMhTWeNVFSSDrOJGw9qg
         CtKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QE3+hhEJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eYHK6RyJs/Ab0MMCWptw99JmP2cXwnN4STnffsF5oCU=;
        b=p3sLs/xNU1PWcFEJNCugazZXKLG6+UepwY5xLNxgxC7Oju7vq5E7FJ9fgasz2n4muT
         qs2vaiNgRf6SXktETmrYuC1mYq+V2j6AV3IPHRc9q+a6Vsy3owlCzjgs/pxKz8rkB9vI
         ENG23w1sY4zi977XJ5O2uWKblYJou4Boc+DZ2OtH/ZAhA2zzCBVlEu2tgq20gRp7W3we
         xo0jZKsQnxxx+LhBzklie/d0W5AysznAlI4YILnwjpGceQdq9jjEFnHHcYVycdPEDXHD
         /hXhG6HzjzYyxSooFgvEEZ1lnlxrVM1yGVFNcF6lAml5SBaeavDCRWhPDvCLTP7S9Shi
         7a6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eYHK6RyJs/Ab0MMCWptw99JmP2cXwnN4STnffsF5oCU=;
        b=PNsiObOuwVpNp97OAhgPF/khjSkmvBk+lyAbvCBJ8wKDR2IR1YpSw1FEP6/rIt7LYR
         nuSEvTJJgTgoggyegp+ocubccHFlboEECj2OdtcQWVONMBsHzZxyAy3Quk/Lup+Hvt/t
         hM6Zk41yPSPJhvor1YyZPhFIVlb8KzeGYWslwIrqt9+5AiW9pQsr7JdnE2GtXvE5bqBw
         AMa4Jk84m0bZLzHQNUY4iLxa1zIQgboeXifjLgEYwpNmgJAy0sw9Evke7NyXqlb+CoLY
         2bgx+Pp9wq+l1cBWX1WgAz0pJ4cDI0OJX7/HCp9QpzTAaNTznB340yVGrQecf0JEHT3d
         T20g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eYHK6RyJs/Ab0MMCWptw99JmP2cXwnN4STnffsF5oCU=;
        b=nHvFMAb7s7FYTigNo9ORQ+vZck6D6QeWZSZ4mDEvPH7epuAUYwoNuU4vYnOOTnQIQZ
         zcQvU46yWC6tYTGa2Ve7oh2lqY2WnbfIlc/Ok8Aay8agKCUJ/noOF2ItG6BQjWUxBAfF
         qszlqcaLiM5hACT9URRIF0XL3/HAxmuxDBaWw3UADDLzy9CG4Gc1p8rfKYwf8QYvu1zB
         Pdiak2Z0z4+VIYS3WE5mrdkRealtGyrqn0SoFfUuOqQFynJH0fbFu1zMDQxH+tSB5XPP
         KPM2aQGb94N3vH3u1YmiAjMSHUPRlT1Jjk1aENY301nCH4Se9WP6DntYUuXenn4L6fTV
         kU3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tK9tki4bNDaTFSYgAPoFJwLYQ8IQu0+BpvMvtBLAepsoUUPfo
	550pFYCT+i6PlSipPdWwyto=
X-Google-Smtp-Source: ABdhPJzsZ7TetcEZRrTsBsl5RH2dJ/s+Z9cmFR8de0F3AhFxQo5asfud/6tVE72pbHbyrfk3xXNk/A==
X-Received: by 2002:a05:6e02:1887:: with SMTP id o7mr17225939ilu.144.1633915505417;
        Sun, 10 Oct 2021 18:25:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6a0f:: with SMTP id l15ls1205355jac.8.gmail; Sun, 10 Oct
 2021 18:25:05 -0700 (PDT)
X-Received: by 2002:a02:25ca:: with SMTP id g193mr13191284jag.125.1633915505064;
        Sun, 10 Oct 2021 18:25:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633915505; cv=none;
        d=google.com; s=arc-20160816;
        b=JQ6YuboxGekA9CIzqWoj337Y+cX/mNvvli3mr94VtRqHmx5e3MXBbemAteVfgqWlF3
         2WLzpg5aSrIYquFW062Gq8KsNbhmW5LVMPkoxhjQWllnFBoGevIsYugOg8ga7fvdCL7r
         ftU5FdNaSQaQmH9XgNLEOAEdUlgMmhz/gtpYyjhxDeGykgzpfPcDwn4NPIm1f9xbHxwe
         y3gLap3d0Wdql24QBgdj0T1cCb4jhnSHhGehT0l3pTuUOkFjSmwJcZ+RppfgA03Ov2Xm
         KyP4Q2xYibbdePxy5um876PprB67mXQsQsnphKsBmau+KWokCRjLL1wW5yg1xbJf7TIp
         wnwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qg/lw2b089jKrvjooAfpKe59rWCsGtQNpRbIh39OG8Y=;
        b=t0RFq3ctQ1ZYouMWcMikDTNEemfQeJeqij0PSLDG/Y3f30bmrj30Xnok7DlOtmTU3h
         kze97QlVIR6PHK0yb7Pyk3JZ+kaFln1ToAykuJgvDdTetWHJTevVpruBButOz/icdR1k
         SAXbmva5SOX8nfwEsD1NzLShN4PX8NG62FUEk4xCsoYUt8wM3WR3f/ZyqCk6odMZ+KWH
         VlnkH1gcZrb/NPsK25kepN2KmMjv12QZhoeq9ATPIV+N67lYJF2q3X3RD8bZTW24sc56
         AEdu98z9lx+B9ANu6ljw23KbGMU31+/GOGe0I/9KRugf2Oii0Ve43NxU8g94Rhs+sLRG
         Qo2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QE3+hhEJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id j14si343835ils.5.2021.10.10.18.25.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Oct 2021 18:25:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id w10so16382601ilc.13
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 18:25:05 -0700 (PDT)
X-Received: by 2002:a05:6e02:1688:: with SMTP id f8mr17511226ila.72.1633915504805;
 Sun, 10 Oct 2021 18:25:04 -0700 (PDT)
MIME-Version: 1.0
References: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net> <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net> <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net> <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 11 Oct 2021 03:24:53 +0200
Message-ID: <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QE3+hhEJ;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Sun, Oct 10, 2021 at 1:59 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> The advantage that GCC and Clang/LLVM have is that you can simply say
> "CentOS vx.yy" and define the full distro in an organized manner, for
> a reasonably old and trusted distro version.  Perhaps Rust is already
> there, but some have led me to believe that the safety-critical project
> would need to take on some of the job of a Linux distribution.
>
> Which they most definitely can do, if they so choose and properly document
> with proper approvals.  Which should not be that much of a problem to
> make happen.

Exactly, it is doable, and the language is really just one more tool
in the process. For instance, if I had to take on such a project right
now, I might be more afraid (in terms of cost) of having to adapt
internal testing-related tooling (so that it works with Rust) than
about justifying the open-source compiler.

> In the near term, you are constrained by the existing compiler backends,
> which contain a bunch of optimizations that are and will continue to limit
> what you can do.  Longer term, you could write your own backend, or rework
> the existing backends, but are all of you really interested in doing that?

I am not sure I understand what you mean, nor why you think we would
need to rewrite any backend (I think your point here is the same as in
the other email -- see the answer there).

Regardless of what UB instances a backend defines, Rust is still a
layer above. It is the responsibility of the lowering code to not give
e.g. LLVM enough freedom in its own UB terms to do unsound
optimizations in terms of Rust UB.

> The current ownership model is also an interesting constraint, witness
> the comments on the sequence locking post.  That said, I completely
> understand how the ownership model is a powerful tool that can do an
> extremely good job of keeping concurrency novices out of trouble.

I think it also does a good job of keeping concurrency experts out of trouble ;)

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72mj9x7a4mfzJo%2BpY8HOXAshqfhyEJMjs7F%2BqS-rJaaCeA%40mail.gmail.com.
