Return-Path: <kasan-dev+bncBDRZHGH43YJRBLHGUGDQMGQEBR3OFPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 432673C273E
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Jul 2021 18:02:54 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id w38-20020a6347660000b029022342ce1f8bsf7580411pgk.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jul 2021 09:02:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625846573; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0Zf0WyF/dK5m/msN5gd3JFu0LBDDpIOvQ6aV0m7fG9X9Ufhod+sRtF5oZZRTeSeZf
         S/EwWP//00FiV9Qr4dT6pXkLnvmuijrAEY8R64i3xD3z7ZRJMB/YZof4qK+w5PiISWit
         KvTRdnwer/6bcjqP25SblU9hljDBxmuc3soUA21JvoFU7VAGzgG7qZ6L1bQjg2sdmKZq
         E5OCLam2aes5aQ+a2l+qVytpk7uBF8cL2tBwejsVExQyY6lYjWmc9e+VgwudVvJXfSjN
         c9Trx2uaT7p0e83CWL9ZJdVdLmoVnIo/Yqf56hsmLrKQbHNrzAPXnmyH6kKnxb497iV2
         DmNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=hwl47LymavSJ93xuEuN4TPZeSXo9XkeDn9pKcQv2FhU=;
        b=gU2+6qnqoeIAIZTSppDIeVpMqBDz72iFLyuIKvoGaXfQ+ZYT9ntha3Jnp6pUDXg2fC
         PWV10EV5irUS2lGjTKGTOAwGYaW6zYYy52ZVKZ3ECIp3poVJbm6j7bSmY9QydCG0fWNk
         GK2r7rAYfkjv6jBlhj2iwOmOcspGB+85udxcEp1Q+52sZY4ESrnaAA4uYGrH6rt8hlCa
         goXNd+KTMUITFcVZLqZjrpAL+YcYlsiMbMzSw0KIkyB/50zenruHlekLFXmD/kd5IcsZ
         WOv6UxHzhZDNeSs5oTOGzVwxGhdolZK7/Prbi+HDo2nXFJnv7LQapWBe7lZ6Z6ikvuhv
         b/+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qgCxE7Ww;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hwl47LymavSJ93xuEuN4TPZeSXo9XkeDn9pKcQv2FhU=;
        b=GDSFnFXd9lmNjTq0lGhzq/ZIyr0z6kkbp5NvCSJyNv7AokLwSCT8KTuq2QKbml8XAx
         B59j4v6zYfk1fDmd3nG5noLGqRHfaoVWu3f2aOyH+MZqu1Dih1vwDybQ/vWunn5GfsR+
         vtlLnaIFM0oztCthLEOx+pIjRYXxbY3C+fZWyjcJ0878E5mgZI3OcU6qyC09lR8WaDEO
         qvRH51xqP8gCRqY13v8iLWrW7NbpZ8tllIK8L6eJs9qEXQTHMBX69yws4CQSCAI3DNs9
         t1EcjvTmkvEixz7yKTzUEAVCdQlh36XipLxZYqVx0VQiAGCkFJxY4BmG3J1Z+lRw/5P1
         KdJA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hwl47LymavSJ93xuEuN4TPZeSXo9XkeDn9pKcQv2FhU=;
        b=vftX3/bO8O44VSqMXfdVTUsi2aFpMuAr/qO90gCy5B3HaVrYbdjMllUllJW1RRXYnI
         iOAsEpEEWKu5nOnH7IogpeaDcNMNbV5Gh80OZ1M72PH2FldTOr/gw+ZBYjhCmVtvpEKd
         ftHzo3TdGrBYTcF3DnVHAgPCB+fmsAvWupM5cFCS2frSimJ9+BdVwfKtsp7saI7zaUwj
         RX961Edetvcl8eQ+1pu/7oWKZtgkr5uwuKriufZ1d/H4T0gQWsDFnrVztE8QOWvL4QnX
         B0baxvCXPuAgW0SpbGcuasbyMwXmjqSsNvdCq0k8PE55VUvi0BukopryT3AcapslBMyH
         stLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hwl47LymavSJ93xuEuN4TPZeSXo9XkeDn9pKcQv2FhU=;
        b=Vy2RUSpy7WxYXk09xPtNyhqu0+VVO/PO8CjkBIQD895CMiFUZNSaS3sp385GO5KeS6
         ltZ9knTz+wQpCPcDjZAuStmLn7Lp4Kfo+ipel0EPYYAz6snRSQp5i9ovFHysQqLR7g81
         y9A42Q5d5Iht1dWNJdh2XGsA1HE7deym61zoQ2KEsI5+exULNIS2xqPUpw4WnUGH1o+k
         B9pmfRMVw0gSH63PKXkGxscMRtnoCjjaUK6sY8A9riUZk1ypxQ+gmgbc6X/MRUuG4tPj
         vbKKW5pev4K4ctRhP2NQvt0p9R6KI5pSMvuw60nDpLntMAZZB9Fr3PtDBAvjvsQlFQf4
         715A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vvut0lhupe/P976Yapdtd5aHtgoMif2iRl9PWMDL7ZDh1J+Vq
	xV9gga2876ql372WWUUMb1Y=
X-Google-Smtp-Source: ABdhPJy823alS6ya6/GbOdSnqAcley0aqGSN9e7T2MsmSUVhoUdTGqWX995sKBwz11GCyJnAZdVMGA==
X-Received: by 2002:a17:90a:b906:: with SMTP id p6mr5461932pjr.143.1625846572750;
        Fri, 09 Jul 2021 09:02:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8410:: with SMTP id j16ls8205570pjn.2.canary-gmail;
 Fri, 09 Jul 2021 09:02:52 -0700 (PDT)
X-Received: by 2002:a17:903:18c:b029:125:b183:798f with SMTP id z12-20020a170903018cb0290125b183798fmr31422838plg.24.1625846572114;
        Fri, 09 Jul 2021 09:02:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625846572; cv=none;
        d=google.com; s=arc-20160816;
        b=oQ/wBp4f1rPZFzMCBYnMDFhBESn+SFD3pNv1iULdHWkO1SSHU80JckfFmLERII4tS8
         88knQTLc+K+MqKJHOVtkpAYzmNsp+V+xYEDVQ+qlFo/v6ekcz0NCjXaVLiZgkT45+J2A
         0FNmm4TDtRErTbghy6SWAJl/gifk8GWMhl7wiDmGvRo6Zlbmsqlu1hcHc1FF0ZlHNsu8
         z06JW9dg4WHa86DlYAq+F9PmJubRJZ0heLGzRyEldfSf0aMWQbONkDCCFlLqLz28MA1q
         HJo6+glh1HaBf5m4XdxKrgMm/EXQlDwl8FSEUCnJqxtAOckkhX8lEUfATHmKK5/UN+Xv
         OGTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sej+T/bePMdoiBqNeQkF4QPgZxgyOdE8cD4ihrSSbfI=;
        b=s1bbUkuXgi6GHW4krJEw5k/VnC6VFjwjl9Az30VeGfDDfnukSiWe+8VC934WIKcN+s
         f+9Gt86JMBSy9hcmHd7+veq3oektEL4mOdveCgMVNBmOZh2VDusLOODgQhZm6VtRp0np
         9cSsl3ijRZdYNrz86cUH3m4wXmgFwANrQCqG3ZFIBsfLuifTyyBWMZGouJFt6oqz45t7
         TGHeyJ7U8mi+O3qTerwT8n/K7+/1za6thkwPTQucDkUu9A9J4VzXWctkqvLuu0qwxdQS
         UydofHr10++QGPremhjT4XlhG9+P73dVsqtUZgnIYb3AieeA/VZyf/UMlKz/m2JK3fY9
         UE3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qgCxE7Ww;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id u38si687672pfg.4.2021.07.09.09.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jul 2021 09:02:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id y6so9762925ilj.13
        for <kasan-dev@googlegroups.com>; Fri, 09 Jul 2021 09:02:52 -0700 (PDT)
X-Received: by 2002:a05:6e02:1d04:: with SMTP id i4mr27150441ila.149.1625846571843;
 Fri, 09 Jul 2021 09:02:51 -0700 (PDT)
MIME-Version: 1.0
References: <CANiq72kF7AbiJCTHca4A0CxDDJU90j89uh80S3pDqDt7-jthOg@mail.gmail.com>
 <CACRpkdbbPEnNTLYSP-YP+hTnqhUGQ8FjJLNY_fpSNWWd8tCFTQ@mail.gmail.com>
 <YOPcZE+WjlwNueTa@unreal> <19e0f737a3e58ed32758fb4758393c197437e8de.camel@HansenPartnership.com>
 <CANiq72mPMa9CwprrkL7QsEChQPMNtC61kJgaM4Rx0EyuQmvs2g@mail.gmail.com> <YOgesjNqpsZNK5Gf@elver.google.com>
In-Reply-To: <YOgesjNqpsZNK5Gf@elver.google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 9 Jul 2021 18:02:40 +0200
Message-ID: <CANiq72n8fJ8S5R4YKZBDuNFMCN3cDOUmk+6Rtp-ikNVwceX-Ng@mail.gmail.com>
Subject: Re: [TECH TOPIC] Rust for Linux
To: Marco Elver <elver@google.com>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>, 
	Leon Romanovsky <leon@kernel.org>, Linus Walleij <linus.walleij@linaro.org>, ksummit@lists.linux.dev, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qgCxE7Ww;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Fri, Jul 9, 2021 at 12:02 PM Marco Elver <elver@google.com> wrote:
>
> I think the main point was about the combination of sanitizers paired
> with fuzzers like syzkaller.

Yes, and my reply was that compile-time detection of bugs is way, way
better than runtime detection + relying on being lucky enough to hit
the bug via testing and/or fuzzing.

> I sincerely hope that not too much trust will be put into Rust-only
> dynamic analysis via something like Miri (for the unsafe parts). For the
> (...)

I never claimed that we should blindly trust unsafe code written in
Rust, nor that we should only perform Rust-only dynamic analysis.
Quite the opposite: I mentioned there is already tooling around it
precisely because we need as much of it as possible.

Put another way: the topic is "what Rust buys us", not "what unsafe
Rust buys us". That is, the goal is writing abstractions in a way that
we maximize the amount of safe Rust code for modules etc. But,
obviously, the Rust abstractions that deal with unsafe code (e.g.
calling C) need to be as carefully reviewed and analyzed as C code is
-- nobody claimed otherwise.

> It is very likely that if the Rust portion is analyzed alone, be it
> statically or dynamically, that there will remain undiscovered bugs due
> to improper abstractions between C and Rust. While I fully see that

Definitely, but there are some things that are amenable to be analyzed
on their own. For instance, for data structures written in pure Rust,
Miri is a powerful tool we should be using right away.

> Rust's static guarantees are strong for safe code, I'm pragmatic and

Note that even within the unsafe subset there are some benefits over
C, such as the borrow checker (it is still enabled in unsafe code),
pattern matching and type system in general (e.g. like the
`Option`/`Result` example a few emails above about being unable to
mistakenly use its contents if there are none; that you can create
types that enforce invariants, that it is stronger overall than
C's...), etc.

It also has some downsides, though: the rules one needs to abide by in
unsafe code are different than C's (e.g. due to new concepts like
references), and thus one should be careful about conflating
assumptions.

Side-note: our coding guidelines enforce that every `unsafe` block
must be documented with a proof of why such block is sound. Same for
invariants that a type holds. Moreover, we require all public APIs to
be documented, etc. This is a way of saying that, even for unsafe
code, we are trying to be stricter than the C side.

> just do not believe those building the safe abstractions from unsafe
> code will not make mistakes nor will those abstractions shield from
> changed behaviour on the C side that directly affects safety of the Rust
> abstraction.

Again, please note we never claimed anything like that.

It is the opposite: we want to use Rust precisely because we want to
be able to statically enforce as much as we can -- that is, maximizing
the amount of safe code.

> Not only will Rust integration with K*SANs be required to catch early
> bugs in the abstractions, but also be necessary to catch e.g.
> use-after-frees in Rust code where C code freed the memory erroneously,
> or data races between Rust and C code.

It might be possible to eliminate some classes of bugs if we avoid
mixing C and Rust too much.

For instance, if we have a model where we allow the Rust side to
manage ownership of some objects (instead of being forced to always go
through the C APIs), then we may be able to statically guarantee more
things and further maximize the amount of safe code, in particular in
modules -- which is why I raised the question earlier.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72n8fJ8S5R4YKZBDuNFMCN3cDOUmk%2B6Rtp-ikNVwceX-Ng%40mail.gmail.com.
