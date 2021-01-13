Return-Path: <kasan-dev+bncBCH2XPOBSAERBSVR7P7QKGQEJT56CZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 385AB2F49ED
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 12:26:04 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id 98sf1035776pla.12
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 03:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610537163; cv=pass;
        d=google.com; s=arc-20160816;
        b=FE5um0IJQGorxh/kvq4fQvnv+kOLbpk7Z4drjVsyH5GiGvCmPHFNpIYZzX704ra3RF
         LTg1adEoDaYS3X06/3N6LJvw9bVlD9iFo2/yOmqvUoN7DgbTzp8H+xtmm3DH43zrsgvz
         FyJz8dvxCdzmtkU4BePoUN2tRz4Ome5mLQIW2Qr6noSf6nV57eICqUMOxCgsRFSVZILb
         MFmP6QaDb/eKJ+x0k/lFCozSMYMDKmhxjv1bZeW/vfIneyJeK2zFvwEXD5nKb/0hfELI
         FF5J1v54X8X+4ACn9Dnr8V6B4Ki4lPMRkQWOP+OvP/fxHmPYLfESCHwx/8GQGwDzj9eg
         zlvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=eGzgphuww1WrdTAvGm6K1g5RxLMbEjKEloDwetwYKvE=;
        b=bZTAkIPpqy/0jFdZbiNJ03zDK7slaWxVqvnhMyRDXUCLmgqDXGptcW2o6l9vCjndr8
         cLhZQkh1LUBjiBtOqqFIlpIGALN0nX44yUAtzgzm4OGWZv3hWFgYdKjUOODxqlMm1DJ8
         TpshFnXpbI8zeptx1YvExOP//Qgrwcpf+acK6K5tJuALMGiFP/3tE/y3hUj5sehPyaT0
         CrY55UqVbgrzZZ1Mj5fPz2gRM3tY5qOMFAYBsPOFAewha/zlDVI5WmC1Xd8DMX7jDyTA
         nkuw9FwIvRROoq0U1l38xH0B/Vcd4bpyGGJKrIVpgomuQry7yQSkyDvboSf3wda8KAGq
         nifw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QveSVUPL;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eGzgphuww1WrdTAvGm6K1g5RxLMbEjKEloDwetwYKvE=;
        b=hUA3nAQBIorA004Je/k1+3nule4URx1b9AswPerrkLaPdxUdQvtaWNVH6xD/zAWI5+
         Hh5UFA0LSchgnqLEcqz6U7shNxXnStpYuVBFeS+6UkU2LdNymbl2ZCRjch7GIasGd60z
         yhg8C7hv4ah0cClECmuyBoH2u9w9g1VVIi/mVHo6g8GgUD5Dj6AkS1x/+LFHMJpxf/7I
         RvJ6OEU9ynf9EU9zlC4QMoGfqEnprevXp68xa3btzCDHLHhbsP32M6iksrJ7sKeuKY9A
         iGos80M2w0+HwhAIZCPY/dd/tM4w6/EJDDn1ATpl5twAHEf22PzPIjdpCWZ+aropPhRy
         XRLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eGzgphuww1WrdTAvGm6K1g5RxLMbEjKEloDwetwYKvE=;
        b=VetRTdmdv5pAp9d9t7zxlH2wzmiCjQCRJqNRsdTCv1fxysR5Sei7zPqIrMBlW8cWqH
         7+VDtF5geFUZuhHCydrncbNqsG+FQ542nWLDN1JH+I3dzBKUigjqvxRcPDumpd+z86db
         1dJNEb7DEg2QMfRmOgPsfBnKIGeSvSehZCgmf9rsEmoy97nfY8hIb9rV/r1VXUfzs7f1
         C1LTzPWB4jZKgy7HxHGotlqH0t/pZdobrPcv5k+5ijRUeZKlpFvpT1NB8WMbvAkvaTWi
         zckQaeURebAfnqXlLHBBaAgt72sq8Q1GLQf7D1tE0NDmRPI4x4Wy5hbTj1nJh7ZNyXnp
         lgAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eGzgphuww1WrdTAvGm6K1g5RxLMbEjKEloDwetwYKvE=;
        b=UyB4q7UnM048xirmbqqV0rR5H6PH5SrAIdmcUEnWOgDZi0eK9J5LJ8qy2U9PePNdF4
         E3j9o15dvmp+EVjzC/SgDcZH1Mj3pEcVis1alATwIQMQnA8vnYkqzDh1h3d6SB9aHgE4
         0AEZQX6cCmLiBk/JdmHhjWks2SXCCWWNCAA/Bjc/lGzXoTm/XwuMvLtm4UWbpWIoKqP0
         zxyJulX8GCTl9l7GyMTpwbXCXL1fy6tpUV8HlbpPbI9tv85Dt7WIsrfQPtq0aHNMW+nz
         IqDMA36gs87Sinvg1GbAI/ZGw1xXO7Hnf/vcwexyi7sv04zfkBSCsuAhFlqAWjDtISFc
         hUKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ARWTenarnBTuVO3d14Z+3BzOiLjLhihD4gQCkADjqqrFT0MLk
	ojp9CQtCqCGLrwm71EslJjk=
X-Google-Smtp-Source: ABdhPJxT8gHvVUJuS7pETgNXwIjoBDpFv97gEyQo63xTJR1UjVuWQ6cEYcByrZlm4gPwvcR/qp8yhA==
X-Received: by 2002:a17:902:76c8:b029:dc:183d:60cf with SMTP id j8-20020a17090276c8b02900dc183d60cfmr1843642plt.15.1610537162985;
        Wed, 13 Jan 2021 03:26:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9286:: with SMTP id j6ls810699pfa.7.gmail; Wed, 13 Jan
 2021 03:26:02 -0800 (PST)
X-Received: by 2002:a63:1401:: with SMTP id u1mr1636029pgl.229.1610537162406;
        Wed, 13 Jan 2021 03:26:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610537162; cv=none;
        d=google.com; s=arc-20160816;
        b=tFUlWHfffX6fggFUN6BYIkq8IIFeh6QuitHyG/Hym01I3wUi/TxeiGK/Ca25ZPLH81
         BW5Ih/vgySSo7OVtj3noPYs17kJ3t9oDa95brwOBaTT4a7JZkKXOhDR7dkAU57I1iRM8
         jmiZPUOqDPRHdIuutuen66pqKAL6SpzhoeIE9x6uudrSKrh5myFizd1GNXBPrqlIBa9e
         9TF2/mySZK4K0MYTUKICfRDZfw2e79kiHux8y2rBQIB1rJ1fU/A+owqifMMUJwD6/HSr
         NV3Yp/UjJ8jDtLGMlGKScZq4Ek0a0Vafp6kqzIomPtKop3eAToq6GorFJBCo/MBOD98i
         9aqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BRZ1cE5zYUbqGX5dQSTvGzhIsYL45cGcrI9mULm1MMQ=;
        b=IwjbDR4TSPO+H6paTttb8jyRmv/FisnQ/b1L4dw1NnbHofLG5uWRjUlSG3CU4pNCf3
         ze+tFbwJGTwPH8RhELgD+ly/Vq429lrOhBY8vZAOV9zJZGu0Q9f2Zj6Gv39VMw2IjymS
         YVpR4z/Cl++npCnr5aEkmuvy2BEmuVWwiwxzrIefGCLu455DU0RpgZ0CCOrzZwR3wp1V
         lz+2iyn8dDaX3foQceLY9eHhIzFmlyaMqbYGxygO3Ulxu2aVl0TY+s94ADcdhKSlgPtA
         V7knJ1eZXunZncvdrL5qGcWVuqb5N6sgEFkYOgLbYJqLzPPH7aHuNAwl9GedScr41nPi
         DTuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QveSVUPL;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id j22si88896pgn.5.2021.01.13.03.26.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 03:26:02 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id g4so1795442ybo.11;
        Wed, 13 Jan 2021 03:26:02 -0800 (PST)
X-Received: by 2002:a25:141:: with SMTP id 62mr2593722ybb.426.1610537161692;
 Wed, 13 Jan 2021 03:26:01 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
 <CACT4Y+Yh=qjm4Ov8XbTXFWeTbgnreab+3QBm5mLZ6vm7+JLQiw@mail.gmail.com>
 <CAD-N9QWQVg1nRhHQi1+e_FmF4nyxQAANktbsjmiGWMkXCPN0RQ@mail.gmail.com> <CACT4Y+Y-Lu=UMsapj8Z4WR6_Qh-dwAcgXFuShso72Fd-gzQNtA@mail.gmail.com>
In-Reply-To: <CACT4Y+Y-Lu=UMsapj8Z4WR6_Qh-dwAcgXFuShso72Fd-gzQNtA@mail.gmail.com>
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 13 Jan 2021 19:25:35 +0800
Message-ID: <CAD-N9QU_auOz9XWq7AUAKjRGhdfn03h+QWHggKXVAjuMp7HtMA@mail.gmail.com>
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=QveSVUPL;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
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

On Wed, Jan 13, 2021 at 7:16 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jan 13, 2021 at 11:44 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliang=
abcd@gmail.com> wrote:
> > > >
> > > > Hi Dmitry:
> > > >
> > > > I would like to verify if "KASAN: use-after-free Read in ath9k_hif_=
usb_rx_cb (2)" shares the same root cause with "KASAN: slab-out-of-bounds R=
ead in ath9k_hif_usb_rx_cb (2)".
> > > >
> > > > However, I cannot reproduce these two cases since the firmware for =
htc_9271.fw is no available. Do I need to take some special steps to get th=
e firmware working? Thanks in advance.
> > > >
> > > >
> > > > --
> > > > My best regards to you.
> > > >
> > > >      No System Is Safe!
> > > >      Dongliang Mu
> > >
> > > Hi Dongliang,
> > >
> > > I don't see these errors in syzbot logs:
> > > https://syzkaller.appspot.com/bug?id=3D6ead44e37afb6866ac0c7dd121b4ce=
07cb665f60
> > > However, we don't do anything special to add that firmware.
> > > syzbot uses the provided kernel config and the Stretch image:
> >
> > It seems like the problem of image. I change the image to Stretch. The
> > driver for ath9k_htc works well.
> >
> > > https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-=
does-not-reproduce
> > > Where is the firmware searched for?
> >
> > I don't know. However, it seems that Stretch installs this driver by de=
fault.
>
> FTR,  I see in the Debian Stretch image these blobs are located in
> /lib/firmware:
>
> # ls -1 /lib/firmware/
> ar3k
> ar5523.bin
> ar7010.fw
> ar7010_1_1.fw
> ar9271.fw
> ath10k
> ath3k-1.fw
> ath6k
> ath9k_htc
> htc_7010.fw
> htc_9271.fw

That's what we want. Thanks for your help.

> qca

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QU_auOz9XWq7AUAKjRGhdfn03h%2BQWHggKXVAjuMp7HtMA%40mail.gmai=
l.com.
