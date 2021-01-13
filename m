Return-Path: <kasan-dev+bncBCMIZB7QWENRBHMW7P7QKGQER4FYFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 48E132F48A7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 11:27:43 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id l11sf967893plt.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 02:27:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610533662; cv=pass;
        d=google.com; s=arc-20160816;
        b=HBmB2VKJl6i6Nf0pCIbYv8S57zeOkpXhsQcnkZ3hBnfOHoMsLGVqg7tQXWXvtrRJax
         ebOgskL+lml/B8rrtTDmDrZUOpoTjdcayfeNpcwUof+pVAwWa1r6SPKvKYdKMQIu9as8
         /fziAEOnze9rZSvwZZrz9ltC5YWDRrwNRxA96T4FxAujZ8nAZ0aJOV6BO/jl8eoL5Snu
         jYbuDNuHV4lX+9GZSCJD69a74lZ2XHrSm9LK98Wq42jDqDndZ73PtZMnIqeRFhM7KDr6
         RCp/HaTB8jWyG4pkMWF5gvCO6ROXUTV21v3t+tV+sHdLKo3oXrkZyqXSQWzWyOqrfq08
         gdjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OzsbqwU3X+v5E1oVR5uLZRiFAOn3qsOL/i6l1qZYlYA=;
        b=gVWmdSVCd7ToUCc3Ioue4q5nEUVdND3zD7eo1guJ6n2vjig/umohM1XoCi8Z/vDEFz
         PL5AkxH2cU4iqXjFsxXCpE9TkpwRwkPqmBwgB2kH1UmndY4UJC0hSYQuU95fjwcHu9vr
         T0VO/K3kUfQ7USHpo6FMQYX4+WEYtmxNTJYnuwRXMPNdN/wzphHq3YU+X0Rae3koPpiL
         n7UnLbgrkdQvT9uewg8qPdTSbtGw41zBH6eB0k+7MeP3M3mTvJdByjTkoTKsIF1E8tny
         M5LxgG3rS3ruMHxkOdOKkwyckDhb9Dau20GzERtVAygz1ZNElK0xBx6wDSyp1q7Jy+Rn
         CQOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A6Vppaj9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OzsbqwU3X+v5E1oVR5uLZRiFAOn3qsOL/i6l1qZYlYA=;
        b=Xg+CFEIWduwp4pys3wOoBmaH9fT0IIZdkhO1ZjjBUCqBD7NfX0DaAA2sxnj/KWd+IE
         asZHI/aET206PXa3mEpd7Xvd73auvr++En33YRfRsXbKGOd4YvULlsc64C/244ZusXSL
         vtqKnTyP7Mop5gFNnLePsXHj0eCI5gl2j2GkQn99IgQVBD8bRoTACwjuHWrr1NfvUx5B
         s0jHcWVRRgIpF0QWmmrpJN51Ey96RTIGRdoEHOMM3yeA5iCEwoGSHWAoX35+lVR4Wg1T
         3nSJpBzCZ2T50tmhwWkRwmh0LeyCNFVcBzBYzYIm9h+dnO5lS/IhDEVRwSbMUZJjsTo7
         77rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OzsbqwU3X+v5E1oVR5uLZRiFAOn3qsOL/i6l1qZYlYA=;
        b=IUlMjWA44bC/Pd2kd7s4BfAIZpcVt30m9mJ9j9kGK9tWD9KDl4F0AhvDeoIqJ0BCpt
         Y95ibaCzl5EnshSKH9eFP3bUStXrna+9QNabWH0g5teFSV3Z31+IFk9dBCb7ugOFdZBV
         AJbz3oNZMfyVMJHQC5GhDfNOJ9jI576dzxEWV2PifFFmShT1uyZ3VOy+21zKphFBbFnI
         y/uYZLQdKus0UCOV338vE6uhJKhhMxdfyF9MSs/zTuGyjZFmNKIiUR6Obh23GQdQq1Or
         3pjvfjM3OmMklVHqAHOVcziKVu9zqRuBK2AMXKj3HcUPhY2RdUY+lE4VUuattUbA6S6j
         VNXA==
X-Gm-Message-State: AOAM533rK/9JQnLNeV5oHDGCSKE4y3VyKzrK8AH7FX6TKcNV9LRjrDbd
	Ov9f0jnN9pNcorxajypwF5w=
X-Google-Smtp-Source: ABdhPJyaIvRhAg0QkBn5AKIQbczCAHf/uw+wgdBZi8EOFQYmfSodrJASRp3J67rM9gexbLzBl09R/g==
X-Received: by 2002:a17:90a:5782:: with SMTP id g2mr1688209pji.124.1610533661829;
        Wed, 13 Jan 2021 02:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls856925pjz.1.canary-gmail;
 Wed, 13 Jan 2021 02:27:41 -0800 (PST)
X-Received: by 2002:a17:902:be02:b029:da:c6c9:c9db with SMTP id r2-20020a170902be02b02900dac6c9c9dbmr1569603pls.69.1610533661311;
        Wed, 13 Jan 2021 02:27:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610533661; cv=none;
        d=google.com; s=arc-20160816;
        b=YHpQwMhu5dZcf3VxgmYTBOZyCNJXSzBtDdw4/vwSok2abZGAS0SlxGf3Px5KKZkico
         cxvT5M3N+sWz1kOqWILPk1TypNVHD6Nj2Glm6FupynyJKuf/Kp0BFpnB6lwL7PFPR1gI
         jX4fijYlbCzrTPJaVxI8gIFp9tJIbgu3rdOKSyKtqN0xujkgcrmOddgjvPMig2woCG5m
         4tMgXD/pVto1sj+DTP7Ed9r5tsGyclUEmyZ3M+kIqDMNyWbBUD0sWb5HWOrgpLSyWOES
         SznN1JeuJVqYKNyir1uirNN1L06fYam6HnQdOteUXhaVvWdr+RFZGv+RChQG2u2/gja2
         Q0qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RHEKQlqIs9KuXL2pPy64NobGH030aVJ2RGYH3B588ZM=;
        b=HYQMVgpyp9wTyRwKRzN7DB8szuhS3c+gZw+FSheEdiursTaa/MgugYL+a5iBt3rlWj
         ss7d17Y0qIaAISdbUmvOob+3WO3HGAjpmWkJopGmV5iOolEw3ZRs1QqJalsfnc1mKrPq
         y1eCc9d0ZqqJ6pj0emRhU1tKhLpxnTpfLqDcloWUdVrjJ6GKawt+WDODuTX7cMRak/lB
         d0EUp2LegaHnbgWYVH9+HbWspqlJlXYYeGHapYrlIE5wUkfADau38pxPQru2UyM/qmp1
         /UMEXr4RpliJ4u4NDm6mwZTM43I+IN2ZJsnEi+hY9GnjBk5oDZw+MtKLGlX/pjoRz8C9
         TUUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A6Vppaj9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id ne6si106375pjb.1.2021.01.13.02.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 02:27:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id bd6so524700qvb.9
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 02:27:41 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr1618146qva.18.1610533660220;
 Wed, 13 Jan 2021 02:27:40 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
In-Reply-To: <CAD-N9QV0UVFxZQyvghMaWRC9U9LhqraFr9cx9DvKia1ErymsZQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 11:27:29 +0100
Message-ID: <CACT4Y+Yh=qjm4Ov8XbTXFWeTbgnreab+3QBm5mLZ6vm7+JLQiw@mail.gmail.com>
Subject: Re: Direct firmware load for htc_9271.fw failed with error -2
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A6Vppaj9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36
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

On Wed, Jan 13, 2021 at 9:37 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangabc=
d@gmail.com> wrote:
>
> Hi Dmitry:
>
> I would like to verify if "KASAN: use-after-free Read in ath9k_hif_usb_rx=
_cb (2)" shares the same root cause with "KASAN: slab-out-of-bounds Read in=
 ath9k_hif_usb_rx_cb (2)".
>
> However, I cannot reproduce these two cases since the firmware for htc_92=
71.fw is no available. Do I need to take some special steps to get the firm=
ware working? Thanks in advance.
>
>
> --
> My best regards to you.
>
>      No System Is Safe!
>      Dongliang Mu

Hi Dongliang,

I don't see these errors in syzbot logs:
https://syzkaller.appspot.com/bug?id=3D6ead44e37afb6866ac0c7dd121b4ce07cb66=
5f60
However, we don't do anything special to add that firmware.
syzbot uses the provided kernel config and the Stretch image:
https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does-n=
ot-reproduce
Where is the firmware searched for?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYh%3Dqjm4Ov8XbTXFWeTbgnreab%2B3QBm5mLZ6vm7%2BJLQiw%40mai=
l.gmail.com.
