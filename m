Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVH3XT2AKGQEQJXSPJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 476FC1A36EB
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 17:23:02 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id w10sf172047iod.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 08:23:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586445781; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfDkWXvsCTy+uSrjmW37pEVudL3ZXCnRPjYWcRHQiY1YO7l2E3C/Yqgirge+7AuaXa
         jxGyltsnC8R/1pG7DgUTiBbxh4vnYwxK4TZI1zIfPy5BDf4aakJeYpi395+cEVgkVm1o
         zW1M6UshmHE/jE6or+AKK/ZCPpRRs604tfvktTpnyevPyQN6BYuv7n5hXRDR9pkacYrh
         TTwVCX6HR6Xitlp9UsWZqhh5jBHyAn3E7KJXeljWzhQXLClJc2zFOOA6YVaUEDo1/6sU
         VcZGvcrmiibopwGAEmBOqgXJWAirHi+bdDUD34RgjTtfHMTBL1TCa6RBSW4qnA0x7rlQ
         i8Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LWY2oWta8iB0bqjrNmaPss5GEYw8sFEl4izS3+PK9Pk=;
        b=OnQjyn7YDqor15hOumgFY+QPeuJ8frj/W7nzCdmg5/N+hCGE5Z3ilONm3aDkEzgf8e
         KhcoUVf5LYwDFQMiLVqvpKLfxp2KthrdgE/vwDCbKE8nKtNj04XljBbV9TyFUPTzCakW
         dw66XQ/ET2KhWyqwWWYyhh4V/qfVR+vuwYNYiw9VE4+haH1u0jjUerY/e8TXNgeIR2/1
         MF8NaUgOpGWmQM5PuY/Wo2zW7Eq/o3726EV5ArhG5cQ5WOLY/GnE+y66baVWj2BHbfx7
         jbLrRwd5DgCjFCQ00ChHwSXWzjvgamLps5zNfcFMq55GJTSl+R5TcH+w+WPJKdB6/gBO
         j2fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CSr6492W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LWY2oWta8iB0bqjrNmaPss5GEYw8sFEl4izS3+PK9Pk=;
        b=MFjWp713jdowVCkK0jKP4M9usSGryYvFCzowDOkjjacVpxZZDLStSTHxH4EFvPZ2iX
         Gk/bVWh9WhtTlaYbPT5RWEkxGY0xoV54trbVn0BFk9QcdMfUQNfeoW862gS9urIjMQES
         EudyKsAhN8x0XfFHy6u/6bBdzo6qCKqXfAa7dImpOzIJ5+d498a+Fx96K1Z5lD4ixqt+
         RCzpznKfUE99cy8zeLqBgiBG5Le2EeKKuJ2ij0sM2Uo/6aQCkerzD7mJIGhAc2wJgevU
         IyPz77AQn0myL+S/3AHqYnGHvBB07HDU8MjxYm5o+GWePN8z3uVM5VEnWoIkYjIKqnOt
         NYqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LWY2oWta8iB0bqjrNmaPss5GEYw8sFEl4izS3+PK9Pk=;
        b=iK4GxEkrbLgw1uUAISfk0x2uHNOW+9u5ItstuCOaHyTjEVR1voWDKyDCIQZ3MNRbgP
         HMA7XXAaUMxtLKvOkyWC6maaEN1tDWcbasKYpevv32u+N64a1KIxXOd+qaqVit4G6NiM
         ARbv9+SD1ZW7E8LNaFw7lggZKPhSp1zj2PiLztaIEyzxOG9lA6MGarZqhaHo4vRdfCyU
         /8ZCmPMISJ41wkD9hxQLhzvKYtb/TtxSHHJTBUGUhKoBiSEgkIPVOfEY9GO1XtkyLTtS
         WO/EtHbGjtH+YZuFmNzqt9/qRdO04OpMbxe4k7MmvJ8dCuXCVLNTYOLiqoVaELy0dl1C
         TiYQ==
X-Gm-Message-State: AGi0PuYiT2gooEDbuC2fvd8dFwdycqxIs2f/60TTpQQ6QSvcScGGBubF
	nr4SptOL9CfWy+2sWtrdW3A=
X-Google-Smtp-Source: APiQypIXiuvdVgaAs8/MvhkYVi3utrHlrIkWV4tJj2lNjhhekPaZIWZX6tZWa7AGeBaGzxIzD0vx9A==
X-Received: by 2002:a92:bbc4:: with SMTP id x65mr253576ilk.82.1586445781115;
        Thu, 09 Apr 2020 08:23:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:608:: with SMTP id t8ls5223388ils.11.gmail; Thu, 09
 Apr 2020 08:23:00 -0700 (PDT)
X-Received: by 2002:a92:394d:: with SMTP id g74mr210460ila.250.1586445780576;
        Thu, 09 Apr 2020 08:23:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586445780; cv=none;
        d=google.com; s=arc-20160816;
        b=Jiv7C4BPUDadTn/wx+ZUr/MgJK2Z3HDul2HsDsuRper5E5eIqup6kb4BVy61mHmCY8
         7hvCZp7Vh3Q8iq+ZKsoLsIzH4vqjaQ3/LV6ol1kBbFMBhdRmMpr9E65OkW5bp1uIjKtT
         eFp9foaeQpR5YC6IkNXogwrFp7rx15OxK+hhiBe7xdln+3srScLss8c1BBDxUXCaYTFX
         ee8D4NOhYyrRRZ+IztUUdVgPKuKh7C31lFrk41cfJJSa5aYIKiSxQ/PU7N4YQlRyL/Ar
         CWWUJdoj4aBKMAQSUIOV3GdJTEmFvQtkt+NY+N5vZJzcRyLKdD7erkwhjzDYG8cTcTwN
         oFTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vgEQvvnJoquOGzGtJREDN5USMlXV+4P/x5EsAI2d6zc=;
        b=FVV7IdrD2ODkfzRue3a8pt052dMxSJcvrBIrpg77EY0SfGwDhN9OUWyMYkoOAPAJha
         WcfFL2H3yUOYuU+5AgPqEsdwIbRwu6OgbbPAawClt5icht6W170vu9o+L+YCu/bmA6mq
         /bT3xAaPCPoqN8vCfV3bjGI6Az2w9kXL+YwDEl4Pnc9jrIGTLdY2wpqOOSNt5ozdW+kB
         dNZZfAc27nxUxpGabAQUOqudoK7yvAId/A4WrMDRNWXNQR5FTNfK3SSfSBhQMZ/VilXc
         47DYIsyEu+5iqqxwgMlQpbMIZaNGdDudEdtEzz7cso+5F+3Ap1jOkSV4IevF2tkMAdqD
         roTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CSr6492W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id s201si718233ilc.0.2020.04.09.08.23.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:23:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id t28so10860252ott.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 08:23:00 -0700 (PDT)
X-Received: by 2002:a4a:d516:: with SMTP id m22mr355695oos.72.1586445779925;
 Thu, 09 Apr 2020 08:22:59 -0700 (PDT)
MIME-Version: 1.0
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw> <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw> <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
In-Reply-To: <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Apr 2020 17:22:48 +0200
Message-ID: <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CSr6492W;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
> >>
> >>
> >>
> >>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wrote=
:
> >>>
> >>> On 08/04/20 22:59, Qian Cai wrote:
> >>>> Running a simple thing on this AMD host would trigger a reset right =
away.
> >>>> Unselect KCSAN kconfig makes everything work fine (the host would al=
so
> >>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before ru=
nning qemu-kvm).
> >>>
> >>> Is this a regression or something you've just started to play with?  =
(If
> >>> anything, the assembly language conversion of the AMD world switch th=
at
> >>> is in linux-next could have reduced the likelihood of such a failure,
> >>> not increased it).
> >>
> >> I don=E2=80=99t remember I had tried this combination before, so don=
=E2=80=99t know if it is a
> >> regression or not.
> >
> > What happens with KASAN? My guess is that, since it also happens with
> > "off", something that should not be instrumented is being
> > instrumented.
>
> No, KASAN + KVM works fine.
>
> >
> > What happens if you put a 'KCSAN_SANITIZE :=3D n' into
> > arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
>
> Yes, that works, but this below alone does not work,
>
> KCSAN_SANITIZE_kvm-amd.o :=3D n

There are some other files as well, that you could try until you hit
the right one.

But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too bad
for now. If you can't narrow it down further, do you want to send a
patch?

Thanks,
-- Marco

> I have been able to reproduce this on a few AMD hosts.
>
> > exact system, I'd ask you to narrow it down by placing 'KCSAN_SANITIZE
> > :=3D n' into suspect subsystems' Makefiles. Once you get it to work wit=
h
> > that, we can refine the solution.
> >
> > Thanks,
> > -- Marco
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMEgc%3D%2BbLU472jy37hYPYo5_c%2BKbyti8-mubPsEGBrm3A%40mail.=
gmail.com.
