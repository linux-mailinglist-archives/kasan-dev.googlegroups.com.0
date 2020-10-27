Return-Path: <kasan-dev+bncBCMIZB7QWENRB3UD376AKGQE6CSO5DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id E491229A4D4
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:45:04 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id f20sf273511pjq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 23:45:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603781103; cv=pass;
        d=google.com; s=arc-20160816;
        b=E/K9MK3D34OFQgEnU95IN6TBBiRl5q/RkKSC8eiPYJJcVEon/yH8jDzM8bvM4b520g
         ubKWy+/Icu+IUSYKlwuW1Y+UmKPbRHCtl8DToh56CptVmfvRyTStMyJLjJELTT4QMZsv
         kCf7AO0RZLHclQSUELxv9O+uixXMLHKZ+O93gyaKKzsGT9kcfiT4e3sj6DTOATF3Urww
         ynKnXDVnFZxa1kPz/gT3lBp7dnasV1OqsKLgataos3NaoTuo9Ry3aaUsgXa/aErnC3R+
         QJ6O28fDJERT78rJnRuirY+IK7hqFuWUOEgbnxU9y5KJn2FkbpOfvHL+IfHDp3C2Mu0j
         mP7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=s7+driY176JkJPCb5nccmBIMJ6EN3xkAbDXRECvjHNg=;
        b=tEUAzEJ8cbr22OPtts2oGUwQHRQB3bXaLocNy2ymx+yL2yEyF3VPsFQiTQuGowN7Hq
         4qP8Zu8qgyWkVlgLG3V1THxNnTbxNqzmA9hJ2UtZ6LCp0LzQLuq1LWyzMsF1KeDwGBoA
         3y3pykWsaA694x9ivTjH33RsFPrmOsrd5Ad3xt0iheTjqwWhmrt/D20/B+W8MGSb9B2R
         FL9A0IPmrPkW87eaTfPb88iE8HNP8F0//jh9XY6Sb0FAwrAj/GFx35LNUiAOnhFfvAUL
         JrvJhgGK6DLUuD/HKXvqxByVIE7ua04dtOSNqDVip8QqOvWlKPj2zUCk5UJcD3kvntqv
         qeag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YZW4Lcqx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s7+driY176JkJPCb5nccmBIMJ6EN3xkAbDXRECvjHNg=;
        b=iNEM9p19ZHOL+nBjniIiqERV4xF0QBLZAJCKj0kgQN/hB6lCNTIjkmsuuZBBndRTWE
         wZFwep9D0AG8vVvHXzw/C7iX5ua7KbOamgDB5kKsSuKrhJGkkNz2Sn8HX/eaocYfemJe
         ZHo5JJQJYSCxSenJrb4akE4zTfjNBUoccPrCFz+93seZFSupDW0wH1xak9CFoxPejkHA
         hGNaEUB7ee324Ok5EhcYk/BU4tXjSMe1X+kQYElydr+bWd1dN95o3KFwHK0YVCGsST3k
         xa9Lz1E2EXmoyPCEnCDJYJuzFVt4o5SZHlISx3aBMsy4igV+TaT2WFhb9iUXm1dTJE12
         KszA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s7+driY176JkJPCb5nccmBIMJ6EN3xkAbDXRECvjHNg=;
        b=CplthhH8FmxFxK+wT9F4lRYvr58AMyiE1w848UeUm8QTCrXjfORv09JTG8pDUY3nxB
         EkW5CCFlnOQMvLyP64yGNh4BigXV3SzYOx62B6iCt/b8A6mJ8JE2LuoQaTPUcsr9QLOa
         eXmWsHUcbFXP/yH6uTB+fQMxPGRXsTPKKJhwvObra9zWceu9/yjS0Y6JowzygU5jwz3U
         vb9CDnepsJzqK3IWEgxU5F6TOACWiTzmRYecBAFFs7cXweKt8w/wvA2qwhN3y2F9lhvG
         RDYIaLYxy/0gSWmp+Ky9ODWOMMBgugp3l7J9+g+UgqAFkYCF9eHXtyAZBA1sSwnGZ22U
         lACw==
X-Gm-Message-State: AOAM532bh+LJwjdQNgBjd4i35vSxGWJ2PzLDb7BAUIBDPHmwFCgotzOs
	Ai9Opj0EUc7u75B0o6j4FDQ=
X-Google-Smtp-Source: ABdhPJzUr8m5vyDpQKfF3Y8otkxXvWFx54UGOcEQHIhWHKnpqRmvH74/IKOnWpxRLTgEhHTmc9zDrw==
X-Received: by 2002:a17:902:7c8c:b029:d4:e5b2:fba4 with SMTP id y12-20020a1709027c8cb02900d4e5b2fba4mr1104509pll.82.1603781103064;
        Mon, 26 Oct 2020 23:45:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d88:: with SMTP id t8ls373719pji.2.canary-gmail;
 Mon, 26 Oct 2020 23:45:02 -0700 (PDT)
X-Received: by 2002:a17:902:c391:b029:d6:32b5:1066 with SMTP id g17-20020a170902c391b02900d632b51066mr826738plg.79.1603781102552;
        Mon, 26 Oct 2020 23:45:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603781102; cv=none;
        d=google.com; s=arc-20160816;
        b=EXmXKOCsGqx/l4kNyfhv2GYQ41XaWI8Wdo/QcVFRsBlBj1m2cx+KhmaiWLchy6zSAz
         iHsniX+iKC31Bm1RG5nyHMe9XjP4iRyC19ClGz0SoVIz34kQ8s3dja8HfzffZkDdnUIU
         80uf8xevBUBUpgvDpjCgFuxic01o7mSzP4xkBI6suj9QllTUtqPj2nt62zKwXq5vUQq2
         zRKF8j0XK6lGaSbJmvNh4ytU8WBoE1hQdMhYzdtjzoBkMnIJu5rAGvDsCWhPwF6S/r3k
         agg3ZpaneK2EHdbr0SOGJ74RNyReRzdVwupgXpIEbW0YkIAaC6gWSLG1Uz04XgZfL/jH
         cs1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=PCsdOVk9MIUWDBFV77riEY+y8w6fIGfy1/7b1RuMtno=;
        b=gRIK3wKrK8dZJI2mbYEEkWV8lK4/hmtR4mms3KaBChbwGVAieMeaRVurLjFuwVLrh0
         tDwZtLknPT1kbSo5S2imQKcyEYrHCD1GQbw/Cw8o6OVsliyazXNW+S+nCXdZwpjRZjI6
         o4Yj+8M6bAB/rLRrwOTgPeyySfLJfgvXYtPWaRhzXkxfbRCkyxfKgifH0YXGTRcp72dt
         fqyvMWjWxOo3n5QTRdEPOFsYc6QJXcogsK/d10le8vtmr0NPj2BdOpdWTfldYC2CQzGb
         PDDqUVS5/QHiWovvCgQ0yYUo/ayI4/Ke/YmnPe0q0r3qhqhb54jUOdZTi5rvPXrBJSWW
         1aWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YZW4Lcqx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id v1si37418pfi.2.2020.10.26.23.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 23:45:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id p45so129853qtb.5
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 23:45:02 -0700 (PDT)
X-Received: by 2002:ac8:44b1:: with SMTP id a17mr738535qto.43.1603781101450;
 Mon, 26 Oct 2020 23:45:01 -0700 (PDT)
MIME-Version: 1.0
References: <CALZ+MD2orvStubdgL4zEH8L6ADSvqmgvsEjLWdfak13N6vaKww@mail.gmail.com>
In-Reply-To: <CALZ+MD2orvStubdgL4zEH8L6ADSvqmgvsEjLWdfak13N6vaKww@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 07:44:49 +0100
Message-ID: <CACT4Y+YCZTOmxbE6qHobsbQ5mj6rqH5ZGrRxOL_yWQ=_wRLchw@mail.gmail.com>
Subject: Re: Questions on KASAN quarantize zone
To: Zeyu Chen <zeyuchen@udel.edu>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YZW4Lcqx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d
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

On Mon, Oct 26, 2020 at 10:47 PM Zeyu Chen <zeyuchen@udel.edu> wrote:
>
> Hello Dmitry,
>
> I just start to use KASAN for my research on kernel use-after-free bugs. One of the key factors is the quarantine size. In ASAN, you can set up the value via a flag quarantine_size_mb. Basically, you can run the code like this:
> ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
>
> I am not so sure how to do that in KASAN. I have been noticing in quarantine.c, its implementation seems a little trickier with a global queue and per-cpu queues. There are two static parameters:
>
>  #define QUARANTINE_FRACTION 32
>  #define QUARANTINE_PERCPU_SIZE (1 << 20)
>
> Can I understand that QUARANTINE_FRACTION is the quarantine size 32 Mb for each cpu and QUARANTINE_PERCPU_SIZE 1 Mb is a local cache optimized for concurrent implementation of per_cpu queue?
>
> In addition, I am wondering if I could change the quarantine size by changing the parameter QUARANTINE_FRACTION.

+kasan-dev mailing list for KASAN questions

Hi Zeyu,

QUARANTINE_FRACTION is fraction of RAM for quarantine. There is a
comment on top of the define that explains it.

Yes, you should be able to change QUARANTINE_FRACTION to change quarantine size.
Try it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYCZTOmxbE6qHobsbQ5mj6rqH5ZGrRxOL_yWQ%3D_wRLchw%40mail.gmail.com.
