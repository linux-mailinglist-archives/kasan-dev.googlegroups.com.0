Return-Path: <kasan-dev+bncBD4NDKWHQYDRBHWPSL3AKGQEAUFATYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04CFA1DA8B2
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:44:32 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id v1sf1468276pgl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 20:44:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589946270; cv=pass;
        d=google.com; s=arc-20160816;
        b=cff1hW7Ga6x8im64nZ1/lGYso5hLFa2NsGVKI89WWbjERYycQ7kWxzw2SD1TCGOgel
         5i7S52J4VOhrK1M1dtQMl25Z44w/fs4u3h9xaABANApiCE9+pZplMQBTpecnKr92jQWR
         gRvWqF8ThBb+72SnL/EGtgoME1rCdDc/xRVgxhke5ZjjDppTRbDLdyuGqgKOMwNDl3Is
         jjcspSpe/BHfScj0tBmvZQMM/uhPHDQmPADO0G/QDjF3VwCthiTF++SrVMfshc39DfN+
         tLWbZJWWoLNJJT51gc4XEakk6CokTxCxxFueLjia29y+UFylcLwVzrSMP/v/0rbHdE3g
         64bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=jaHNsE3T1m1EPBi4C+/+oJXZiGFVaUhz7EimUmxjw5c=;
        b=G9PZQEwdK4/lypcm00tDmWojQ2lm1FAaNX/wE9j81l3eqIo6AfhnrL7NZFBj5kgYeJ
         1LNFEFw3UaAW6fi2gYdeQ3ff256BNbbfe1LLBhEO2VpHeURriXAL16Kt3rhgnu37ZRLd
         ltt3fTYjZG570R70fQ1wpXSygjDMb3AmzCBJWn5fDls8XlgZnlzBkFKzGEtVGG248aCx
         YLIO9P0vfhd2BzWpin6hgHTLeXzmI9omirR44SeuIkSUkNcM7sQg6NwJE0+A+7fKK2gS
         CYNR0cRibUT57EisotiIYdaLZkYwESIg+EOxeGfoohZDUBvMbAJDulN/nPyV3khJYssd
         qb0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kt9bXylY;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jaHNsE3T1m1EPBi4C+/+oJXZiGFVaUhz7EimUmxjw5c=;
        b=fo+OJ6k5c/bUdCN40AIVlktjXZXqH/XxORUfcrDXDpUf2i8OkjR+L2rwm0qluGhyuz
         4Hz84Hmq5mk4+OjckKBpVo4AXFM+wipmqWH739qm2O8OypK/KRQYIBR85YGkzvuK+DN7
         qBY4wrTsfKn6p5fGZqEAlY68D9fY5MZWE1PsMV8okEiqkZUMvlNRDE8YBBfql2o0DsTs
         dBsr6s5Ui6sUrizSn6E/9P5skKP7bQRhAaYRl73ze10NvjQisW+uVm8DCHSGwxWk1pHu
         lweMKQZNTiFrKVQOZtNlvjZeXiFPPFOZQoMRhemM5tFlqUyOr/OumbmtA26CXRCKu4po
         AR8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jaHNsE3T1m1EPBi4C+/+oJXZiGFVaUhz7EimUmxjw5c=;
        b=P6kNUQt5XHb17MqsHiwJ3K8iwzffmEVWGFmbZdAwXuPG/wRl49E5CBdEERcckOVaC2
         xdi018GAw+cnw9p/McaWtLCfA8w9T+hEPV0OH7cdWe1pywpq5GV2YkgsWdJkddZ5aPAg
         LNDgENZp8JHhZGORrw3sJ3dQV9VL09gipbCPLgLa9hWaucPkKbOLHnYCAgAsult01XHP
         dQ/ble5aZENcjMVcA95cDquUsKW3SqMguLgTL5KEpFudu+Qs1vsDUXNf6hZnW6nWKbFo
         fagH5T92Uz+snwbYg+p6IOg2M0OQkwF9/n9uTUMol8lVA2c+23rSMwXghz0ho9+jKt1y
         ZSxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jaHNsE3T1m1EPBi4C+/+oJXZiGFVaUhz7EimUmxjw5c=;
        b=Cqj4VDRlsp54QVcFL1Z3W3W/OLA/HUCrf+gJxV+HQHZHXWMZ+UN2M35KmKaIkhI4Bh
         Q85wdQa018mcMFKIfSSMJ3XtMEde7FJXde2KGYPS7rIYTx5uXKJAIno+FvsXbTJiA4Jx
         T++8tf9/YIE9bYyiEJyTtLtvXgPT4dlKHhAyqDVJRp0xj+q844FlxyYmMzpqozNZa68e
         FGVC5nar156fq5Z08ZKld6o3O6UWfIOmzdH4+VJA48/stwHOyQZeE/5wOMi403Uq5bel
         QPIts1xDYy6LSCrXB6KWGlsKiyZ2iyGSjFHfu4MXZZIDPkMFZTJ5lTm97ceywQebIvMa
         zOWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Q/BTKcr4hhi3L0ZIrD4B41TNezZ8LyCw6KjzIYPXwJxr3CbSl
	HYqNqgU2u2LMJJF9IpydYQc=
X-Google-Smtp-Source: ABdhPJwUKbJqUpmqkeRNJm/hlIrurYkvNxoOi2+e2yUe7qhIIJslkvTnyYUJB/CKmmuci/eAvnObHw==
X-Received: by 2002:a63:e256:: with SMTP id y22mr2168537pgj.441.1589946270621;
        Tue, 19 May 2020 20:44:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1acc:: with SMTP id a195ls489203pfa.11.gmail; Tue, 19
 May 2020 20:44:30 -0700 (PDT)
X-Received: by 2002:aa7:8691:: with SMTP id d17mr2329695pfo.308.1589946270154;
        Tue, 19 May 2020 20:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589946270; cv=none;
        d=google.com; s=arc-20160816;
        b=BUJyCd3YvyP917+7Cigtdk7cxMmk+xAGwb+fWqriVXhq+LVLpniF8CIq1+bjBVWb4q
         ceeYfYovdlNFhLB2akLtdvXyMWlcu4MOZuXCd8Kf7pzE2htBg/hVRd+VKzqD9ym8bWbE
         HFHItcgDP3+UZFjsSj37dhRIJZLRQ6QDYHzbZ5ISH1Y6NdYgNfPuR4W0V4wVZbELnakq
         KB0HwLBXJvKyjgRXlb5nO51u2k8FuC/W7GaWTKS/jAz0cBbUcFXczCDOn3btUjJ8FD2X
         +MCyH9BYzMG12SROVWSLA/3UUobj5ZPsw5p/nubNEVbj/8a0ykib/Feal2UbDlZGqI5a
         +Zrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ONyQEflSz6Imoxq9sQgBsPIATKu6ZPvvMsByuX0h1+8=;
        b=NT87NkdARoU6oReHY0Kj7yO62Xhx14i9z7H7Kkj+6ZWm4p2Rqu7TqDf+z47Vz+pMYP
         8CUZ5J3N/t4+eioVFF3qQ1bbBVBzrHUMrGQlPxke1teQqFmDknnTz0XJ3NkmAXRzYDy8
         XKv7x0JXORfaI9JN5hmpDmhB7wc6YLfE/Yim5974STA+SFjkVrDzigmy8X1vPKQi8xvA
         Gk8f9fqe9By6/3iGwcS2IqfCVCPj2jPrEueMU7Bd5lD0HLDx6u9dirCz24X9M9h1xYoY
         27jWRYLNPSgxtizfhWoIwdYUrMS1KBxQJY4UWCaw/lKrPXUZx04UqlW2uHSQGK/E/P2q
         5TzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kt9bXylY;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id s12si157398pfh.5.2020.05.19.20.44.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 20:44:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id w19so762298ply.11;
        Tue, 19 May 2020 20:44:30 -0700 (PDT)
X-Received: by 2002:a17:902:ea8a:: with SMTP id x10mr2625015plb.255.1589946269662;
        Tue, 19 May 2020 20:44:29 -0700 (PDT)
Received: from ubuntu-s3-xlarge-x86 ([2604:1380:4111:8b00::1])
        by smtp.gmail.com with ESMTPSA id h3sm745528pjk.10.2020.05.19.20.44.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 May 2020 20:44:28 -0700 (PDT)
Date: Tue, 19 May 2020 20:44:26 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Qian Cai <cai@lca.pw>
Cc: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE
 variants
Message-ID: <20200520034426.GA1027673@ubuntu-s3-xlarge-x86>
References: <87y2pn60ob.fsf@nanos.tec.linutronix.de>
 <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
 <20200520024736.GA854786@ubuntu-s3-xlarge-x86>
 <CAG=TAF4M5s1kQ98ys_YCgRS9WqjV_9KEbPCFiS71MA_QK8epdA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG=TAF4M5s1kQ98ys_YCgRS9WqjV_9KEbPCFiS71MA_QK8epdA@mail.gmail.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kt9bXylY;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
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

On Tue, May 19, 2020 at 11:16:24PM -0400, Qian Cai wrote:
> On Tue, May 19, 2020 at 10:47 PM Nathan Chancellor
> <natechancellor@gmail.com> wrote:
> >
> > On Tue, May 19, 2020 at 10:28:41PM -0400, Qian Cai wrote:
> > >
> > >
> > > > On May 19, 2020, at 6:05 PM, Thomas Gleixner <tglx@linutronix.de> w=
rote:
> > > >
> > > > Yes, it's unfortunate, but we have to stop making major concessions=
 just
> > > > because tools are not up to the task.
> > > >
> > > > We've done that way too much in the past and this particular proble=
m
> > > > clearly demonstrates that there are limits.
> > > >
> > > > Making brand new technology depend on sane tools is not asked too
> > > > much. And yes, it's inconvenient, but all of us have to build tools
> > > > every now and then to get our job done. It's not the end of the wor=
ld.
> > > >
> > > > Building clang is trivial enough and pointing the make to the right
> > > > compiler is not rocket science either.
> > >
> > > Yes, it all make sense from that angle. On the other hand, I want to =
be focus on kernel rather than compilers by using a stable and rocket-solid=
 version. Not mentioned the time lost by compiling and properly manage my o=
wn toolchain in an automated environment, using such new version of compile=
rs means that I have to inevitably deal with compiler bugs occasionally. An=
yway, it is just some other more bugs I have to deal with, and I don=E2=80=
=99t have a better solution to offer right now.
> >
> > Hi Qian,
> >
> > Shameless plug but I have made a Python script to efficiently configure
> > then build clang specifically for building the kernel (turn off a lot o=
f
> > different things that the kernel does not need).
> >
> > https://github.com/ClangBuiltLinux/tc-build
> >
> > I added an option '--use-good-revision', which uses an older master
> > version (basically somewhere between clang-10 and current master) that
> > has been qualified against the kernel. I currently update it every
> > Linux release but I am probably going to start doing it every month as
> > I have written a pretty decent framework to ensure that nothing is
> > breaking on either the LLVM or kernel side.
> >
> > $ ./build-llvm.py --use-good-revision
> >
> > should be all you need to get off the ground and running if you wanted
> > to give it a shot. The script is completely self contained by default s=
o
> > it won't mess with the rest of your system. Additionally, leaving off
> > '--use-good-revision' will just use the master branch, which can
> > definitely be broken but not as often as you would think (although I
> > totally understand wanting to focus on kernel regressions only).
>=20
> Great, thanks. I'll try it in a bit.

Please let me know if there are any issues!

Do note that in order to get support for Marco's series, you will need
to have a version of LLVM that includes [1], which the current
--use-good-revision does not. You can checkout that revision exactly
through the '-b' ('--branch') parameter:

$ ./build-llvm.py -b 5a2c31116f412c3b6888be361137efd705e05814

I also see another patch in LLVM that concerns KCSAN [2] but that does
not appear used in Marco's series. Still might be worth having available
in your version of clang.

I'll try to bump the hash that '--use-good-revision' uses soon. I might
wait until 5.7 final so that I can do both at the same time like I
usually do but we'll see how much time I have.

[1]: https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be3611=
37efd705e05814
[2]: https://github.com/llvm/llvm-project/commit/151ed6aa38a3ec6c01973b35f6=
84586b6e1c0f7e

Cheers,
Nathan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200520034426.GA1027673%40ubuntu-s3-xlarge-x86.
