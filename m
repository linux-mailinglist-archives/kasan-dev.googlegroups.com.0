Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBCX7XT2AKGQEO5BQJJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFB11A3732
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 17:30:20 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id e3sf12486873ybq.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 08:30:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586446219; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5vqK0AJHM0o73ix0XkEJY/KsJLux/cVC3Nuf0JedxDJHFaRR6RZByid0ztn3NtB+a
         rcE8v+aZemgQqZfl7uUHbcaXCBkGhLzmHuwDI4utai8V6eIugjeZQV5B9UzwoPMXEo3L
         yYRlyT2lthU8ytymEhez2k7MD9bLHFJNaLbuBok9W26zMkXeHfvvjxMSbsDPkEvdDLha
         cU85d7pHVEo/qinJlzl3oTDugbDiPFaiD4qjJ3+jvmWQFYk47Z4GctMSn4FMlFAtlbZJ
         1j8tCzuwqVCcbGRzTiM4skSici9Zb7rp4tOwSXL0knGNHoPiVOgkcKx70qc/uSFBsSvh
         ByoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=fHME9u/+PQ1ZvGu9bFp/JilUhA+b7jkiFHTzMAN7ho4=;
        b=kWeORLwZhlIFO9FD9v2S0gYKu4ShM0t4XgQuv3jCC8/f0+iQOXMeAWa7f/OmZbSLHv
         xZLNy8BDdyOhK+laOdE6swovqE/vdTO2CQMFQdeSZ3CtHkREsBSjAlwUQOWiwut/nQj4
         9DH6PdIlPl5fjRC5JqHu3XaE25sSBCNaoTQ+DgUNwt47LG5cPRjPWvRtgCJ45U0zAA4Y
         6VNjoDAjCAwvQRSLxtsc9MtfpgF4zhbprobj94YOKPSNRphj05oOFlzNHa8oAqBxQhjP
         QMP0WvOfTupPpCJBhX1jVcVIVXNxBwX0deCEN4nx+ic1Kc7Vv+qW3X0P1bIfTCEg5KMS
         fn8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=d5ONUE0g;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fHME9u/+PQ1ZvGu9bFp/JilUhA+b7jkiFHTzMAN7ho4=;
        b=r42CVwJIRhWU2VvhZlaRPuMX++33SDpdzrOU1ubKVWghnV6/3VDxbb1FLioyClQ702
         R33VPIyGBM5qa4vAHfaxNI6RygdkUZ+zTioixfzwNYIz+sjEHfQftAzFUdZDeUQG3Aak
         /CtUiMc0rHi4W+og3ls1v67VRKDc7g9LOiLsIyX6wa6ac5LIOFPkRk7k/DRE7QT087ZO
         5Xje0P67tVyYZlhWj0oxhekVDxe1z+wqa3KrksCvflrIFyMG8v/0WirSyZZ5b42Ni7+w
         5nk5jxPXn3moP0aGzKEpTSPbOqkdp8isrTge+qVll3yVQbA+G3c/SSC4f2RnqbmMxWbF
         ASZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fHME9u/+PQ1ZvGu9bFp/JilUhA+b7jkiFHTzMAN7ho4=;
        b=ZTMAVv7LQ5GyXnKUC1DAYx4/trRCJza73iGf4RC6AvGIKBgjdXErUEBAbz4q7OGaZE
         KDrU377ga2cHoBX2NQtAUdpq1OY8QQsLEnyjfwL6PEyw0mEj3fiFTwTjMTrBNhDBq7jF
         m8Egw2MqI31Ud+tY0UDiNnee8ol1HfYRkHKdNPoGAUebu2SwlBfv8v2ro7cnxHj6iwUD
         ssm9DtlBwN9GBrWddl07rzCYb1dVJ5aHKxTCNqFOD8UP0YwKNfFWAgN0sjvb6xHchiFp
         2CP0xY0UsFHpSX35TU9oJx2bYrbRN4gqt5kMugSCRUa29Uwb9K9ygKJMf1V6R9l962k5
         V6ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY8EiBLinwCG5ddn5h8qFCi6Ds9xhYhmfMHm1IITVqIUhJaKts6
	1YVDDQyYzwuUg2oQ1166a4I=
X-Google-Smtp-Source: APiQypIjMU5i9omf5IM5EMp8W5RuFa69SR+WQgWoFNq5nPCETll/nCTkbEgnZFJDbW+slZ/9KgLLog==
X-Received: by 2002:a25:dc8e:: with SMTP id y136mr472821ybe.294.1586446218928;
        Thu, 09 Apr 2020 08:30:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2ace:: with SMTP id q197ls4080761ybq.1.gmail; Thu, 09
 Apr 2020 08:30:18 -0700 (PDT)
X-Received: by 2002:a25:3c9:: with SMTP id 192mr454131ybd.418.1586446218542;
        Thu, 09 Apr 2020 08:30:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586446218; cv=none;
        d=google.com; s=arc-20160816;
        b=vxveyjR64ls3SL51b1OvnJKKgaMsezDN4CCFV4qbBUbMAPFCRu6Hd2d50epiWZ6G6k
         PxdyzzF3iw+grev9QxChwNNGB/B8+devRiiTdwV1dXO06Iu+76ygCzoy0UojU0vMnuae
         EYe08Z23Nv4mZMZTFirI/GZC1QF5KLYwKafdtqAb84yGz2DnLulqfVc9+Qm2Rf5CIdAw
         bjF5PWuU2m5VsU5NAbg+Ni8X8le8TwPbXP4GDnShcQJP0iLl+j+8tCNnx28BrGiyTseZ
         5uCY/QCBcfwyZekoY3zpj3oWEfh4do3Fq28UWJuJIpPSy7n4jHz64aU2o/IX8ZE9MF3t
         mo0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=KqSuwj1Lnw+46mOu5HvLLZOQhrSTpPUDCk9ASXa3iQI=;
        b=lx3x02AZYlqEEToIdHYkx/D+QzAzJkAfyDGk8jLBm4vYfnKx6o9cs5SHtmBhyqh0p8
         W0tXePtBwbZu2hPooMyPoTtgunGIC0CmxuFuq2NmgZg0fOWsNtczKTaBSxCMjvNW918w
         gzxFiP6EWonv71ICyn2yuuwLEZBm+U37sJZ8UjmWDP3MJ/VD9AClDlLfGHNqlZhoM11u
         35oRBpECPHVs+lKzWzH/Mok2h9BrhkaWizSXaJ9CfMG/Q86KywtrpET/igKp46E7rfZt
         ccG0uSvz6EOTTxV3jeSt4NuiiIhu4zkbxmY8lhcfr9ZaqL7V8HeVwpaVIIFSVZASuQNh
         mbjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=d5ONUE0g;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id f195si544455ybg.4.2020.04.09.08.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:30:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id 13so4300247qko.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 08:30:18 -0700 (PDT)
X-Received: by 2002:ae9:e80f:: with SMTP id a15mr352621qkg.367.1586446218111;
        Thu, 09 Apr 2020 08:30:18 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id q5sm11214109qkn.59.2020.04.09.08.30.16
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:30:17 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
Date: Thu, 9 Apr 2020 11:30:14 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw>
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
 <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
 <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
 <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=d5ONUE0g;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 9, 2020, at 11:22 AM, Marco Elver <elver@google.com> wrote:
>=20
> On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
>>>>=20
>>>>=20
>>>>=20
>>>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wrote=
:
>>>>>=20
>>>>> On 08/04/20 22:59, Qian Cai wrote:
>>>>>> Running a simple thing on this AMD host would trigger a reset right =
away.
>>>>>> Unselect KCSAN kconfig makes everything work fine (the host would al=
so
>>>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before ru=
nning qemu-kvm).
>>>>>=20
>>>>> Is this a regression or something you've just started to play with?  =
(If
>>>>> anything, the assembly language conversion of the AMD world switch th=
at
>>>>> is in linux-next could have reduced the likelihood of such a failure,
>>>>> not increased it).
>>>>=20
>>>> I don=E2=80=99t remember I had tried this combination before, so don=
=E2=80=99t know if it is a
>>>> regression or not.
>>>=20
>>> What happens with KASAN? My guess is that, since it also happens with
>>> "off", something that should not be instrumented is being
>>> instrumented.
>>=20
>> No, KASAN + KVM works fine.
>>=20
>>>=20
>>> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
>>> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
>>=20
>> Yes, that works, but this below alone does not work,
>>=20
>> KCSAN_SANITIZE_kvm-amd.o :=3D n
>=20
> There are some other files as well, that you could try until you hit
> the right one.
>=20
> But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too bad
> for now. If you can't narrow it down further, do you want to send a
> patch?

No, that would be pretty bad because it will disable KCSAN for Intel
KVM as well which is working perfectly fine right now. It is only AMD
is broken.

>=20
> Thanks,
> -- Marco
>=20
>> I have been able to reproduce this on a few AMD hosts.
>>=20
>>> exact system, I'd ask you to narrow it down by placing 'KCSAN_SANITIZE
>>> :=3D n' into suspect subsystems' Makefiles. Once you get it to work wit=
h
>>> that, we can refine the solution.
>>>=20
>>> Thanks,
>>> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6%40lca.pw.
