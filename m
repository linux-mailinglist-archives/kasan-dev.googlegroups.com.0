Return-Path: <kasan-dev+bncBCH2XPOBSAERB6U57P7QKGQETPBV5CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 457082F48D9
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 11:44:12 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id a204sf751939vka.21
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 02:44:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610534651; cv=pass;
        d=google.com; s=arc-20160816;
        b=s9TQTITXylrMmivCvQ5eYYp+D8Z2XWU+UXSZPPFT1zk6xcoIZIZ56/agrRRAXbDZOV
         CpYP6eAbpjWffGlTMM25NAT0Db5RjLTyYB1eqH1GIL1YUbUOWgC3lXofMZjV8iggEtau
         eiIArWyiwr7z7+OfboXooSHZRJeZZwwQft3Dpepx/z89o1kgw8wk5gQ+zrhkaCZyapqV
         iqOnGvDvMTINGZmxuG3BSUvt+0m4P+broVczH5f+Kutfi24k684wkUSXZIF938xDHZQN
         MADUdTYo+ilqo7G4/I8nQ2nREIfcc+yn2Y0zJ+/0v3IQReaNdQgXSs3EANY/WByXFGEJ
         lSUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=YCNRj3frrufJPg10APPu5K9ddDV8+4ZEeepvvmJFTeU=;
        b=A2lhfFGJHMLPk78ZHxyk6lz+cuiUiEZJmE7VDu4mboFKufDvOU0v4WTlQNZ/SnP9xJ
         NJxFUcRW/RxbH0y/j1v5C7etUUuCle+HHOKvy6l6bavsn0iuzL0YMihyZZuCMEHxpBQh
         DPZqNIhtZDgSn2SeBKGi0/tl0O5kbf4LJ5up6NWkYYpafxnGJ74CAQa6ORzAjpgW7Ols
         G1tN7Z+bnNy2aYp3a2B7gNgXlOggAE+fNMraOGC++9UbIddj60PqRBnuePMo2BG9qlya
         taIN8nV12WoD0i/lQIt02BlXo025EsQ0j0n10MtgXA70MRgRBhDkx62avwC0u5wg/Fug
         r5gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BQw7u1tL;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YCNRj3frrufJPg10APPu5K9ddDV8+4ZEeepvvmJFTeU=;
        b=GLwy5ZntEUUw8F5E3EkeA+cvbmlWhsOvKnKP5hjKHRQbZdvFYQmnPAWqRwUkPD6Qja
         wVjyzRvzyMLE5qCHx1zIGv2e6zsBhiI18z8YMOfcd9fWXbxlLrgIj2GYOlkc5biGznna
         728fU+eMVJsSXIwSi0SiDA0pXNzj4NeeMwNCP/tt1U54aqMCpgg+TwQb4i6VJAR38Iy6
         SN6PpQyvGfoPos8l4rdjCzkwQO87HcleOK/c941Do+WB0edIL9Noo4vpUAbrwaj47bEP
         nyuJm1y0SQf6GAbg7+pxA1z/5QTIZbl5YWeY9QiNG/e2qOcM7DMyOK3pbcf7PRU4bFLY
         SD6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YCNRj3frrufJPg10APPu5K9ddDV8+4ZEeepvvmJFTeU=;
        b=Oou5RKzslxbjphqNWvwKK9sYcVPeFyAE5KN/EejswrB8IDGTp61VN1pop/VsElH+fu
         LVSg/dl/ivHge0HdnB0TGx3ft07614RkiSIgdgMR/YQFjq80m++j2iw9IOq+9dejs3he
         OLO2mbGUMbznuEJjhgyRp/t2UiOAE3FMS3jtTVdIE94QH+befYJxo14AlBre3DL1ZG8D
         sgIWuu5Ltkmgx2HNO/bdwFNjul9Vu5BKKEwD9D1M9KHQm8XnbnefO5Px9BT07MmOaHgE
         J3DApzS7n73Ih7z/bm/Jv3wdMW2lkWV89fV9T44NB/uRQKj02p0vOEK/JgHrGcPYVlPv
         tZ8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YCNRj3frrufJPg10APPu5K9ddDV8+4ZEeepvvmJFTeU=;
        b=L77MOX70J46HagPtN9A9+o68hxKDD4t53qzd5klhyu7YIeLhQFkqo5+7mIq7j0m4wX
         TyOAIoZCJ9jouf7vzjcqXOVrSGucyUuPmS+kDoHguZlNU2qnVZqFrk7awDGZ5dT2oUsc
         39n1vbwtUBSDjrSrIvPgUv8yxeNzzQsHDpdcoYWg9c+wE3HRAnIYQgZmC/JiiOGpYRon
         hjw1JKvmvOAx0zKrcYY/Jauu2OMOmvq7aIRSDNiWCdFAv5GNw+6zRmVcvRjC0vZNOx/Q
         py7X3rus9ya8nP4ln8aKi6wG/YxI64eIbqxFhRiAxGzbVAs4KlhYR8oMjHTOyTjpfYkk
         a2EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pM2pDeC9GGSpZ/Q+wTWs0E2+vsgjJlOULH4BVGMQchR/hl3Nh
	reGk5EK6pizBm7L88npcNNQ=
X-Google-Smtp-Source: ABdhPJyGoSJhIYDQ00Q2L54Ld/yozd1SRfygqh1biEC7O++o4B9V3q0i6HwLMWxKQf+AnCgERAiQUw==
X-Received: by 2002:a67:cb1a:: with SMTP id b26mr1453023vsl.22.1610534651155;
        Wed, 13 Jan 2021 02:44:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6c44:: with SMTP id q4ls100706uas.7.gmail; Wed, 13 Jan
 2021 02:44:10 -0800 (PST)
X-Received: by 2002:ab0:39c8:: with SMTP id g8mr1231861uaw.120.1610534650399;
        Wed, 13 Jan 2021 02:44:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610534650; cv=none;
        d=google.com; s=arc-20160816;
        b=Fuy3V+G5Omszflp8KF2KETPHcpKsmbUtO7XZw9XwEqfKCZSSg5NLMXKSe+FLAxZZSf
         cn6J+8UrcT7pu3aMj4Ls03sJnqlZMIlYy7yhJEviR4jz1Q1i6w2rH9AzeOCTuQGSK25A
         +7atc6hA2GKV1ATT62+iGzS/wZB4iMBSdbtCgbw32gKq4TanYaVWrX1xnyJmbzy+R0yu
         poSIB4QGJU8CZ+nIAoRf23JfDQFDurvzx7ZXlMuGB+KThlEr+RC5psbpI/0PDG5j0oYF
         Lit5BgtT7Yp5xxDy4LY1x7uugsv5RHsFRzb4DqY5u46Skex90oxScepXQj9y8g/vVA4s
         QVuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZtWBMjKXQ3fzEO+v+jdi7jEFVh2wSZsrjdqBj33zMUI=;
        b=f7eNikZiaR7qCQ47M9Y+RCgeSfvMDgVHIZhnLbJUhaUIbYurjspnax0GUjKPfwDDxT
         hTx6mnA4J6etGXOcAdKrwOvAuMdgLDE8/D57rvmk9x4UINhmxmkSeIm2npoV7gb+FNvU
         RQlX4nyyNm0rOua0oL8MX8k/4SRiLgPhes0VIPTaAbrqLxjGMVYj2aXt+NSZXb/xDpex
         7cNFfm0n5fmjPBEV3DBrvfwzRptfHTzvakJ97OKFEx9ZTMIs/HrRIYgJXtc/9Z1tim8G
         r5sxlNUQg5NTkEMNiJULQnMwNF4QJSfaI+33I4LhubOVxV2lSFu6a91YvO6QiGc3Pa1M
         FxhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BQw7u1tL;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id y127si90802vsc.0.2021.01.13.02.44.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 02:44:10 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 18so1746796ybx.2;
        Wed, 13 Jan 2021 02:44:10 -0800 (PST)
X-Received: by 2002:a25:880a:: with SMTP id c10mr2323147ybl.456.1610534649902;
 Wed, 13 Jan 2021 02:44:09 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
 <CACT4Y+Yh=qjm4Ov8XbTXFWeTbgnreab+3QBm5mLZ6vm7+JLQiw@mail.gmail.com>
In-Reply-To: <CACT4Y+Yh=qjm4Ov8XbTXFWeTbgnreab+3QBm5mLZ6vm7+JLQiw@mail.gmail.com>
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 13 Jan 2021 18:43:43 +0800
Message-ID: <CAD-N9QWQVg1nRhHQi1+e_FmF4nyxQAANktbsjmiGWMkXCPN0RQ@mail.gmail.com>
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=BQw7u1tL;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
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

On Wed, Jan 13, 2021 at 6:27 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jan 13, 2021 at 9:37 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudonglianga=
bcd@gmail.com> wrote:
> >
> > Hi Dmitry:
> >
> > I would like to verify if "KASAN: use-after-free Read in ath9k_hif_usb_=
rx_cb (2)" shares the same root cause with "KASAN: slab-out-of-bounds Read =
in ath9k_hif_usb_rx_cb (2)".
> >
> > However, I cannot reproduce these two cases since the firmware for htc_=
9271.fw is no available. Do I need to take some special steps to get the fi=
rmware working? Thanks in advance.
> >
> >
> > --
> > My best regards to you.
> >
> >      No System Is Safe!
> >      Dongliang Mu
>
> Hi Dongliang,
>
> I don't see these errors in syzbot logs:
> https://syzkaller.appspot.com/bug?id=3D6ead44e37afb6866ac0c7dd121b4ce07cb=
665f60
> However, we don't do anything special to add that firmware.
> syzbot uses the provided kernel config and the Stretch image:

It seems like the problem of image. I change the image to Stretch. The
driver for ath9k_htc works well.

> https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does=
-not-reproduce
> Where is the firmware searched for?

I don't know. However, it seems that Stretch installs this driver by defaul=
t.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QWQVg1nRhHQi1%2Be_FmF4nyxQAANktbsjmiGWMkXCPN0RQ%40mail.gmai=
l.com.
