Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVYSP3AKGQEGSHVHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7879D1DAC05
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 09:28:36 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id q5sf1801036pgt.16
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 00:28:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589959715; cv=pass;
        d=google.com; s=arc-20160816;
        b=bXymkx6pzwZJT8BkoxTLdr1CwQQwtIaXYU0oZrY0EpB0jwCQxFVUlmlIM+DxQannSH
         jgfyP211lj+hkQCZ2GgdVJj/Dr+ZvXdHDkNzh+L7133d0mKI1Vm9TWt8sWO5zAMVI2Ku
         TjXrldPN7Y01m8+yHaIyMSpoDRIRUxo58eTRavwFVn0oMYpqO8VrZ1pDwQUwTFqk9lTI
         ZWSim6marvH0uLRErz6yh6mhT+/Y95bANC0fQ5GrO1qVXjcd+kCsz13mYt0T3pi4qIY0
         2TyqlWyTbwjm9TOZHx/B4d/PNPNGXeOTzEiiQbWny8XuXu/aXLprA+858EfNU+S5kDt/
         xTvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=79mxp48HjCLTLOpNJGkAfU+xF474OZhpzJVOk70Fldg=;
        b=pJUobz5kgi1L7zpt9rEMhbjs0gLxG/HDNOoFyIaqzkEVqzXcRkc4znUj6U43pcP+r+
         MxOb9Hts/SaAJlos7vrB7S4A4dMqacJyUbn2vkUNGgdkUPwpXZYAh0WqGDMmeXfnrVsD
         ai/HVjfepJT163fIPjxlVSMkyaV9fZp4JYO2iA743ILs3VFYX+qUrG8TWyU0Lfs1esob
         fsy7AIQwBzdFiu0IHpk9NR3xEa59sfvnIdYRCU2ZRsabqVEW1AX02ZdueFx4Gi/LwW31
         Kec7cgZEfTNJNVKfHf2lUzg3Dmw1jsPVlIS3zJrRPA9FoCGHStHlTKDXt99SiqgWPPnc
         c1cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pEvWD2Pb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=79mxp48HjCLTLOpNJGkAfU+xF474OZhpzJVOk70Fldg=;
        b=dhATSmYvsfGTk0oU97LtZrqwzpQcS2q6YHWBO2vd3tnN5dYKCfjWVoAuKv8foPtvql
         eYvN27vvSIamyNIwGYEV9jiFo68reMMx7W6YKW4U2yDk14CK2KqJTSU0O2xymsJcCKyt
         5XgJq6qiGVYBZPw1Y5ImZaE6RD88904b3Nr13wFRuLaopTOmzfkxedk4lWD7ZvGUqN74
         n2z1NBls8t2bJPlTU5lve2FGj7QvMl4VLkAI19wQNYoGKTBxcPvhJZXENqrULVcNhBkq
         c/+/RZvxE5vA1JXdCJbV0THoHSDLrdX3a9ApAveXwnJ9iY7MrmfApb2EJ7/V/Ogxx/F/
         /e3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=79mxp48HjCLTLOpNJGkAfU+xF474OZhpzJVOk70Fldg=;
        b=drvEydiGXxfAJE/z7Glgru3/etYvSE26INgkEvoCuMpgBQI9U6RtzhRjnDFvb0PbN2
         Cgwo/6FOj2CRwwdfKrG0Oki7WXwEGtjXI2QX1aHeTs6Xr+8nvWnf3mAxFoCMUfhWecKC
         5y8Mi9w/GXgcrFMZK9VbEJWWw03M0ZQWorAfAcVoYAPoeUt1HsBEPez/sNgKSsHNXLVz
         5kJwAEOgHrVCZGhIfJAF2IN2579/rq9yqMkj0F5WDF1PaIjafXxnyw1QDuPDsKrklTqL
         /Eh8to7zrSn5FHn2Nn9lHUxhLa8A+JIZ6cnDp+5biMoV8B7j8K4Jnf2KaJghLlDnVn9Y
         qYOw==
X-Gm-Message-State: AOAM5312/onjJDgGCZYrdNUJXOAskVdjrYWkD1H8tVo8Qmf+7INuUV2B
	EpQzRSR3CvSngYJz1Nq7LV0=
X-Google-Smtp-Source: ABdhPJwPNWTHonrKUrxAUJM1+PchMLTijcNRaeb9SzLjHMwWfUd3uzfxvotYWTMhhXVArphKplEe9A==
X-Received: by 2002:a17:90a:7787:: with SMTP id v7mr3897914pjk.199.1589959714927;
        Wed, 20 May 2020 00:28:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2068:: with SMTP id n95ls833298pjc.3.gmail; Wed, 20
 May 2020 00:28:34 -0700 (PDT)
X-Received: by 2002:a17:902:dc86:: with SMTP id n6mr3236733pld.340.1589959714410;
        Wed, 20 May 2020 00:28:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589959714; cv=none;
        d=google.com; s=arc-20160816;
        b=Sg/exwY/GzssasFEJYjJ/+z+3aBKF2T2fUWdlhE8B5ReLxH5ufTUBRVEqNJKn8qj4v
         nLvs7UKhnLzsCeLU/V8SzhC2mgel2xrsUeanQP2G+11CJJauT76seWah1RpsTJJGcyeZ
         xrLN1SOVjaETFZX+7ov9ujHE+Qb9CoH6Uk3Z8DgleYrtjpe1uqvb4T90vW8mbnEpvIbv
         g81bwCRkwSznpt5CTGGQAnByhHWf9t0wxSPIb5y3tFLa4ULvo5YoOsTapGYR4XY24pbj
         PjLLjUgb2iCcR8Y/E+todS4DE8QLUxlFFQeWqSNVQF4Qbd+PPvzFfY4h/PX3WALSHDRi
         fDzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xkPHVoXP68BKS5mey7jq2q721wyLayczstvvUEvUVF8=;
        b=CqPDj5cDjM7tUktRZUR2gVcZyM4GZtyov9djnNcGPe3QGzVB9lT4UeMc9wW+O5KcmJ
         MTSw89vuCKTf8qM9wKPSau05TCOhDk3a1i5m0/UmKUn3QRARTbehPkzdwSKuiGzYYMl9
         Cyb5vlW0PL+1+JROoKi+08lPJRbJd130tFDjlmMxqmTMhfc7zGtfg7BFqIbfSOV1oRqc
         8rGt1jDsoTifNKbA0nMgwfLXa1fgzJIGVaOK777q1C+v3ADzb4vhJbFUCOZcPDuhRPQo
         O9+3cvDB4GzRraNe9BpPvJra+CBpbBtK4wqtt40N0XZRsWz6M5Yt8lqfn9JCvRGJY5Oe
         3zbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pEvWD2Pb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id i4si78559pgl.0.2020.05.20.00.28.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 May 2020 00:28:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id c3so1670261otr.12
        for <kasan-dev@googlegroups.com>; Wed, 20 May 2020 00:28:34 -0700 (PDT)
X-Received: by 2002:a05:6830:18ce:: with SMTP id v14mr2045756ote.251.1589959713491;
 Wed, 20 May 2020 00:28:33 -0700 (PDT)
MIME-Version: 1.0
References: <87y2pn60ob.fsf@nanos.tec.linutronix.de> <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
 <20200520024736.GA854786@ubuntu-s3-xlarge-x86> <CAG=TAF4M5s1kQ98ys_YCgRS9WqjV_9KEbPCFiS71MA_QK8epdA@mail.gmail.com>
 <20200520034426.GA1027673@ubuntu-s3-xlarge-x86>
In-Reply-To: <20200520034426.GA1027673@ubuntu-s3-xlarge-x86>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 09:28:20 +0200
Message-ID: <CANpmjNMiiDN0AueijLbkbhEX0vLc3xfPyA7kec5_T3Qku7wkMw@mail.gmail.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Zijlstra <peterz@infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, "Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pEvWD2Pb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Wed, 20 May 2020 at 05:44, Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> On Tue, May 19, 2020 at 11:16:24PM -0400, Qian Cai wrote:
> > On Tue, May 19, 2020 at 10:47 PM Nathan Chancellor
> > <natechancellor@gmail.com> wrote:
> > >
> > > On Tue, May 19, 2020 at 10:28:41PM -0400, Qian Cai wrote:
> > > >
> > > >
> > > > > On May 19, 2020, at 6:05 PM, Thomas Gleixner <tglx@linutronix.de>=
 wrote:
> > > > >
> > > > > Yes, it's unfortunate, but we have to stop making major concessio=
ns just
> > > > > because tools are not up to the task.
> > > > >
> > > > > We've done that way too much in the past and this particular prob=
lem
> > > > > clearly demonstrates that there are limits.
> > > > >
> > > > > Making brand new technology depend on sane tools is not asked too
> > > > > much. And yes, it's inconvenient, but all of us have to build too=
ls
> > > > > every now and then to get our job done. It's not the end of the w=
orld.
> > > > >
> > > > > Building clang is trivial enough and pointing the make to the rig=
ht
> > > > > compiler is not rocket science either.
> > > >
> > > > Yes, it all make sense from that angle. On the other hand, I want t=
o be focus on kernel rather than compilers by using a stable and rocket-sol=
id version. Not mentioned the time lost by compiling and properly manage my=
 own toolchain in an automated environment, using such new version of compi=
lers means that I have to inevitably deal with compiler bugs occasionally. =
Anyway, it is just some other more bugs I have to deal with, and I don=E2=
=80=99t have a better solution to offer right now.
> > >
> > > Hi Qian,
> > >
> > > Shameless plug but I have made a Python script to efficiently configu=
re
> > > then build clang specifically for building the kernel (turn off a lot=
 of
> > > different things that the kernel does not need).
> > >
> > > https://github.com/ClangBuiltLinux/tc-build
> > >
> > > I added an option '--use-good-revision', which uses an older master
> > > version (basically somewhere between clang-10 and current master) tha=
t
> > > has been qualified against the kernel. I currently update it every
> > > Linux release but I am probably going to start doing it every month a=
s
> > > I have written a pretty decent framework to ensure that nothing is
> > > breaking on either the LLVM or kernel side.
> > >
> > > $ ./build-llvm.py --use-good-revision
> > >
> > > should be all you need to get off the ground and running if you wante=
d
> > > to give it a shot. The script is completely self contained by default=
 so
> > > it won't mess with the rest of your system. Additionally, leaving off
> > > '--use-good-revision' will just use the master branch, which can
> > > definitely be broken but not as often as you would think (although I
> > > totally understand wanting to focus on kernel regressions only).
> >
> > Great, thanks. I'll try it in a bit.
>
> Please let me know if there are any issues!
>
> Do note that in order to get support for Marco's series, you will need
> to have a version of LLVM that includes [1], which the current
> --use-good-revision does not. You can checkout that revision exactly
> through the '-b' ('--branch') parameter:
>
> $ ./build-llvm.py -b 5a2c31116f412c3b6888be361137efd705e05814
>
> I also see another patch in LLVM that concerns KCSAN [2] but that does
> not appear used in Marco's series. Still might be worth having available
> in your version of clang.
>
> I'll try to bump the hash that '--use-good-revision' uses soon. I might
> wait until 5.7 final so that I can do both at the same time like I
> usually do but we'll see how much time I have.
>
> [1]: https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be36=
1137efd705e05814
> [2]: https://github.com/llvm/llvm-project/commit/151ed6aa38a3ec6c01973b35=
f684586b6e1c0f7e

Thanks for sharing the script, this is very useful!

Note that [2] above is used, but optional:
https://lore.kernel.org/lkml/20200515150338.190344-5-elver@google.com/
It's not required for KCSAN to function correctly, but if it's
available it'll help find more data races with the default config.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMiiDN0AueijLbkbhEX0vLc3xfPyA7kec5_T3Qku7wkMw%40mail.gmail.=
com.
