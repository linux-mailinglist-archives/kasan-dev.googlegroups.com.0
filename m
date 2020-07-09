Return-Path: <kasan-dev+bncBCMIZB7QWENRBKN6TP4AKGQECKA2G4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B848B219BC4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jul 2020 11:11:06 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id 71sf1128319qte.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jul 2020 02:11:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594285865; cv=pass;
        d=google.com; s=arc-20160816;
        b=TeY5iO6no/JqoEzKi/cHm0hIbYksciMKkmLzx4DbP7azeLQh6HKA+m7bAsUQkFTtt9
         LidQPYfEMepyMzo7ncMN7ab7hnx6skUC9caw+SoDWFqaic43kES/ymwa+VcoZBsGMib8
         RLAarjtbhKtfGMlOgL8ab3Ef4LTdYuLYMCrDERL/Phf25vVsVBgTyhEbNHQbWLwJRAUk
         TWrBnf4PGLLD2P20UCVDGCr1UZ++blWNxKzRBPEJ84R1qsuTtJo8ntD1SXilnd6NV+VE
         CD+x+yEBixcXBJm57wGQ9YnZQtQdyv8KlVK1uOkV+5x4jxNSUHxtDGgnEgTL1ga66jHM
         WiHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fd7d7VDsVxsZr/T4dbiWvKMAd1CnJOVRYad9wNQ8MxQ=;
        b=S63JqEhE+NmtdLMv0ZNWAq9N73fbh0elsEKq2VQwEEmstVSGh2cHz2uu7xSxHJm7nq
         +WXkvNidG3iiLJKWU74k571PRj1dFshNjXGb4jp7qEI39RsFxfjMwnSAEuxHIGeekeCj
         GVhU9vWyYDB63VTY1HcfX4Yy6c6UWSxY0eYEL5BrYXUPAxoCtIi+Nl8u5id0oPsJgvXY
         hXQTFMscFSp+4U2ZeuVMMuQN5r4ou8Z4ajGeUdEoxWGbVkh045oSlK4FOH+rsowfOeOA
         2w003dlpo5qJC3BDLshVVLfZsE9esQwCguxPWcLHN/TXsjNQm1wj9xTigREujfIuUYyo
         IMOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gpu8cbG4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fd7d7VDsVxsZr/T4dbiWvKMAd1CnJOVRYad9wNQ8MxQ=;
        b=Y0WrXfj9aXkrgCBKS2raRpMik6AB6/ZZ+O6hb18PVFxGGrn10liAabANw33Wzxfqkb
         o/dAE5jus8WfqG4+LI8cgF06Am1chq2+/0izDrD7xTW4UBzWQYEDyb0DMeY2p9JaEb2Y
         RExFYBHnTnzt7khnOGwXJFfT5WkdqrBaxjsQqIIZobbwGwccX69GUHQ58YhlKlfAAnOI
         PduqK9wW7wQTMWRT0oWsQGAKqZefBO/kd9IEP6BOfjXOYEkGWySKoX8amBjcW9K8cW20
         43+0ZgM0KGtXzqkUYI26qBd6YzdnoGlBP70iIrNsOX4I7CDOuFlQFWu1kBDbe/3M3KNQ
         JsmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fd7d7VDsVxsZr/T4dbiWvKMAd1CnJOVRYad9wNQ8MxQ=;
        b=hcyoVK6weDo5CI2zALziRfBiYVWSF71S6O4nZHA894bjlUHCQk/s7PbttHTDatl3Yd
         OGMA3QkJ3g4TvFLalBncMAahnRuVTfFtz0pkXZrxC3yBU4IBl7bgE8iYhGd20+Y+305f
         jisZk+rUh+GI0n2F5FhXrNgVh0IJmiJiOaoMND6Sa1pn7xXuxEKXkMR4csUEhVy0o5yh
         F7rS9BMRb5tzTrRXh+TapQQkFGsKNplND9Lk1AhSM8pzKrzyiYFnwsKIhNih044NMH5X
         VBrjz2yXQqLu4xUzUFTqzRTvsTpHjGTrFvf48MZ990+VOjkGncZxZSs6tBeHqUtdlDJV
         FZ2g==
X-Gm-Message-State: AOAM533btqXi0ivDF0HyYM+gY+IuoaE+YIDz1M2yuLFM3b6+M/zpbUb3
	g7h8u+Y+X1ogSOFawToCj5E=
X-Google-Smtp-Source: ABdhPJzgg7SXpODeKUzC3vDb+qxjTYjP8k940xUYeECwhNCNDlgnC024kW62IJERpbVFoURExmTlmQ==
X-Received: by 2002:ac8:1762:: with SMTP id u31mr12587943qtk.185.1594285865799;
        Thu, 09 Jul 2020 02:11:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9ece:: with SMTP id h197ls2408025qke.7.gmail; Thu, 09
 Jul 2020 02:11:05 -0700 (PDT)
X-Received: by 2002:a05:620a:12ad:: with SMTP id x13mr21086091qki.202.1594285865510;
        Thu, 09 Jul 2020 02:11:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594285865; cv=none;
        d=google.com; s=arc-20160816;
        b=szD6xN7QjLYZKbw+oMmfVgzBWIRDO91Py2hJh5949GAer05uOl5ty7bNvsJKaaLRtO
         yfpBFzf/FnE0kuyHue8mnb2G0NYorl6Zh3i8cejIdM35BBnEAJlUrN54KzI5Fu9PqzSy
         3bChktOeWYoSWhb+II+ImY6RIH+R2Cofi46RAOsg0SYE8ssCkQ67hlEXtH1eI4E3OSjO
         qR9//YD9m9vAa1fRa4KLJ5AeJEAbubTnO18mMmHekldXQz+exGe/NONoiwrLwIrp3tKJ
         iU1dFGMwZBBB/FzD9mvaR9ZnIq+MNOnTcy136SBywP7Us1FuTJL+J8UWw5pzXLzuk94K
         bg1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BcQjlyTaAwPUA+WSdEp+qmyf+OuAYP1Xdns3kDYUsCc=;
        b=auHBJEmngBTotleUkNKbmYtB9yR6QFEVBYApT/vV+Y3Yk28Zn+wZYTvoDpWyy6zeNF
         ZsN/3EFqJkkrgTyz/X4G3cOPTNYlwZGs6Eia2bUPuk8xX9l1txRNNjRUm5gijY72Nq0c
         j6nGOdQ2CW66Bxr1eCGWjLf6d44X3oSjNtwS49P3r7Lzdz3BeXDES2rqR3YfdK1BpVeC
         IueX+BmJjn7S4hYHi76AzA/q2ArdNHSCFubalNp7QEQconAai9SM2hmr1tKtvBnUSuWW
         Ul2FqHPtGIbYJLwyNEM+g2pMa0FkBZRB6/e0QhLVID9gbPxln52TFvb1D4nlqZGFGljL
         i3BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gpu8cbG4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id f2si171399qkk.3.2020.07.09.02.11.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jul 2020 02:11:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id e12so1098697qtr.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Jul 2020 02:11:05 -0700 (PDT)
X-Received: by 2002:ac8:260b:: with SMTP id u11mr64965179qtu.380.1594285865006;
 Thu, 09 Jul 2020 02:11:05 -0700 (PDT)
MIME-Version: 1.0
References: <3b2f7ad0-ce14-48c7-80bd-59ae261697ddo@googlegroups.com>
In-Reply-To: <3b2f7ad0-ce14-48c7-80bd-59ae261697ddo@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jul 2020 11:10:53 +0200
Message-ID: <CACT4Y+a7H03pRzWL6cisxJSdaT0TVvZmuYgQ5Q1-ORd_H=8O6Q@mail.gmail.com>
Subject: Re: Using Kcov during startup
To: Kamran Rezaei <kamraN.746@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gpu8cbG4;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jul 9, 2020 at 11:02 AM Kamran Rezaei <kamraN.746@gmail.com> wrote:
>
> Hi all,
>
>
> I am new to syzkaller and kernel fuzzing , I wanted to know if it is possible to use Kcov during the early phases of starting up the kernel and collect Kcov information and  if not, at what point it would be possible to collect Kcov information?

Hi Kamran,

KCOV has user-space interface. So it should be possible to collect
coverage in the init process.
If you want to collect coverage earlier (kernel bootstrap before
init), there is nothing available for this in KCOV at the moment. It
may be possible to hack KCOV to collect coverage from bootstrap and
put into some global buffer and then dump that buffer somewhere.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba7H03pRzWL6cisxJSdaT0TVvZmuYgQ5Q1-ORd_H%3D8O6Q%40mail.gmail.com.
