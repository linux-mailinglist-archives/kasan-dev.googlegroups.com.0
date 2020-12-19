Return-Path: <kasan-dev+bncBCMIZB7QWENRBC7V677AKGQEEMGMQSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F3372DEF80
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Dec 2020 14:05:17 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id f6sf3486803pgh.3
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Dec 2020 05:05:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608383116; cv=pass;
        d=google.com; s=arc-20160816;
        b=LZDP0Gi2zo/5rUK/cvNbrBLl8a2iSWVxuqhtwsBzxofLggHSaSSTdduIldzlGl7UZx
         8o2HMkCITZNCYl+Vv6UmyZ7e23Q6Wm8iRIVcXyNlJia5kfB7WvT1F9072FQy1LKGfi/i
         8UrQRBPhN//o+ffN2BmncsulbrKzPqpBUmWR/hi++5TvLs4MMwxwY0j6QCWcFoQyZrrm
         NaidUfCQSUXZcsCMyC2LNTakbDKGCte655FPP3mrvUQBhpi2vqarplrftZsFU/VulPcZ
         TJf/vx+pYiMZZ1AsQJ4cMt4vndYYzKAA1lvsxSQxqx0jk7/0MzkFkQBCW3tpyRIJcTww
         okXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Paxq0lLPUG+VztL2Wwb6x959qeXJquDE8ABgiaL4Qu0=;
        b=iCOfYIDg8mDYNfBKPkRUIj2R14Vj5I2eO/Q616p3NBHdyBZ7sl4GpsLZIazlSMU1r2
         bqK8oHTT2naVtFTL/l50ON6vEKerTxi+gEKp5pmcYlYOj1oI3T9kFR+d2VGpLTAWZ9H9
         dJzfq5fquObqykCnPZccD1+E5BxoAK3YR/YAKOnddtWCtMLr6LfFmrkRVqtjdjuGKoQU
         VTQ+GwB5AAoIR5iKN4k9sgn26UMJa7+xSE2quiZ+M+8EWu9qogUVOv8sH016GG88sR8G
         GfAizfcNj07D7LgNVTBg9wcjqpCekObksqRLqt6mvfy6L07dih6EUnVHielKPWPjTBC3
         HKng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RovqRVsX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Paxq0lLPUG+VztL2Wwb6x959qeXJquDE8ABgiaL4Qu0=;
        b=MuMhPrRxGFD9DpUeZecqa6p+r8KrB+gk2zjeiDys0YR2Syd7V9OSsDXwRaCH3g0f2/
         KONOPGa4rQWmc4Im65mVEz0aVEhseyPo0ijrzFAS1CvnevkdwWqtoL67BnvyiKdlXyJu
         xt0lQaT5f8sU5A7wpTNiy8Hx5pt7DSxSsy64j4ciDTKlMqmszN1ghFDs3ap/km9NesYz
         a6BoEfA2cig51Et6d5HDijy+24E9PM0b4JGElHQRr1EvPcX0FqY9Kk6l6N1GNLs989Qi
         kwbxI8FoSr86dedRDS+yJCtKuYmuBI3J5xmFlrEGxq+Ua9dvAdVe8SfJoN9MENK8PstM
         Ku+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Paxq0lLPUG+VztL2Wwb6x959qeXJquDE8ABgiaL4Qu0=;
        b=UbQNZhzorzQzqO0o2HtH2NeU/9UuInqfaHLdz8osjzkZr2vOVsNd71WWtLgu2Tto+r
         FFm83P1PBWuEkkguQjW2AyQD6Dcyq6PxbcGMyQCGFvy8kHurBaHpcF0W+kSO2uejo293
         w9k/TgDTe39eFEMM1ICN2T0F7RGUgEKQewTheYvt+FkSl90jPV+Gx2Db7VPZp+e2uIIT
         RYYkZcAXVqD6aLTbthd6f0fYmqEJKQebWIgHvI1Tae0NwH39kOJZrDf8zFoxahnsz250
         UZfHmQA6IAqPcxLndJ8P52BtZpzEZzis7flFMukf5aU7UvW1ty5T7kqq72We2otvJINw
         Q8dg==
X-Gm-Message-State: AOAM530YYhGqPSkSKVLrkL1vrbTIo6/cw2EvmjD/tK+VOhdKQAK+z/r+
	KAi2At/UbIc7e+tsHvkMz5M=
X-Google-Smtp-Source: ABdhPJwm2kNm+yAg191pm4O/NV/3RCgraZFYhJO85LLwAfJ4oQS5/Q2EWGKRSlAa/wnhEOg+wes7+g==
X-Received: by 2002:a17:902:8b8c:b029:d8:de6f:ed35 with SMTP id ay12-20020a1709028b8cb02900d8de6fed35mr8520794plb.36.1608383116007;
        Sat, 19 Dec 2020 05:05:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls16028436pll.0.gmail; Sat, 19
 Dec 2020 05:05:15 -0800 (PST)
X-Received: by 2002:a17:90a:4209:: with SMTP id o9mr9090848pjg.75.1608383115512;
        Sat, 19 Dec 2020 05:05:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608383115; cv=none;
        d=google.com; s=arc-20160816;
        b=iGA8FEyjv5dZ9Ol8J0ZMQokOvy3D7gUZW7GDwPz9v5DZIxrPw0Z95tamI+vlFbxdVL
         EzDlXjJuIV3QydH9A/NrhOdhYcE4pqeImdjxrE8mFIe/hOFcb5EFsd34tStnSEuZcjfY
         s2qAGoQztDfipDZDBjjiKeYmfQWKtChaKkpIwXJYAucZRK19220Bs/2VwwoHwjHQOv4H
         scHbSslfJ5D2wXKOqrr9rnblxcpVMN01cPHHNlZylSt6DGviNYEPkVhFDPWcSo6vbwXP
         BxhNrLuoD5Uz+2/9Asy76R69vtCK3FklmYFFgc0VXX78Cbo/dR4Vy0DzugLQYB2dO++E
         a2ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dW5xvLVAUafYilsBuZXHi7nhHMHKCk0CWT5CToDLRIU=;
        b=vUw+XZDdfCAnfwTJykVgMYrmf3Gs/Bx8SZUi3ggrkSgZFWDnFOj9bsNU5pTS24dFSp
         YKUDdfSJAaFBhdavczTCkCqrrTd2aDrtrYBs7W1Tv7U0N/AEeHXXs5ugmjG4aYAnpsWz
         zDOVFnwYNnXlrcIwb8Kq2DLqScD4FkqFdbJXFjSdYWLb5DNUQ5+fAmHQXD846Vt2LGRX
         oLHTdeePCuffMTHJt2WAJBcL4z5gcKhdkrenDK7e1pPg8d6IwWdS0nWR52V4nn5SkPJo
         4zJN54HcIVOsJKoy6NJJNRXOWBs26EtKvb0QOuuvYDBfv7y8iuDFQrOsxwlHaKCJ9lgQ
         qFlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RovqRVsX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id r2si833475pls.2.2020.12.19.05.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 19 Dec 2020 05:05:15 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id p12so2278141qvj.13
        for <kasan-dev@googlegroups.com>; Sat, 19 Dec 2020 05:05:15 -0800 (PST)
X-Received: by 2002:a0c:b20d:: with SMTP id x13mr9699876qvd.18.1608383114439;
 Sat, 19 Dec 2020 05:05:14 -0800 (PST)
MIME-Version: 1.0
References: <10b4ec66-1552-4224-810a-81ac2cb8d097n@googlegroups.com>
In-Reply-To: <10b4ec66-1552-4224-810a-81ac2cb8d097n@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 19 Dec 2020 14:05:02 +0100
Message-ID: <CACT4Y+Yr_yLbHT8tMy1yE5Z+fVJK+_Bv946c9KZTsWEcwtSECA@mail.gmail.com>
Subject: Re: it's unclear how to activate kasan
To: =?UTF-8?B?16LXqNefINec15XXmdef?= <exx8eran@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RovqRVsX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f34
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

On Thu, Dec 17, 2020 at 9:56 PM =E2=80=AB=D7=A2=D7=A8=D7=9F =D7=9C=D7=95=D7=
=99=D7=9F=E2=80=AC=E2=80=8E <exx8eran@gmail.com> wrote:=E2=80=AC
>
> Hello,
> I would like to start using kasan.
> In the guide which is attached to the project, it says the one should
> CONFIG_KASAN=3Dy
> I don't understand where and how to set it.
> If anyone can help, I will be grateful.

Hi,

Here is some tutorials on configuring the kernel (first matches for
"linux kernel configuration" search, probably can find more):
https://www.linuxtopia.org/online_books/linux_kernel/kernel_configuration/c=
h05.html
https://www.linuxtopia.org/online_books/linux_kernel/kernel_configuration/c=
h08.html
https://www.novell.com/documentation/suse91/suselinux-adminguide/html/ch11s=
03.html

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYr_yLbHT8tMy1yE5Z%2BfVJK%2B_Bv946c9KZTsWEcwtSECA%40mail.=
gmail.com.
