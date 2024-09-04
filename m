Return-Path: <kasan-dev+bncBDW2JDUY5AORBFPS323AMGQEWUPZE5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B944296ADF1
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 03:34:15 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-535681e6f8esf65982e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 18:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725413655; cv=pass;
        d=google.com; s=arc-20240605;
        b=KJKBr0E/cmzJLTh5ygqC0JI0dbafDc/+DTt1SJ5LgVeCXC36duChvAFMqINyw3vSUV
         pfvf8eszDp5FBfrY6TxiBZZIT3fvqXkvZdgvkNKOLNzLkHI8WHt6+uMtzPPPCHSrwj6H
         cQgYf9tG7TzMxi5LjFSELqLGBYlQrZZkgc6gk17Oel588b6dUPJohMsAN/py66iq6Rr2
         SRG+4LRk3mr35dR66goSF6bw2mfr2cDLWgrBw1I1s3zy56UffhtrKofbb/kTDMbsOOJX
         nHWlem0FR5Pb2k5sE5MYK2+eDme1HbaDHiviBJfbZ6h6OjqNNpjCDN47niJ6wMbiYsdy
         bDLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gjsfr9iRbm+j5VmdDskNzCrhMARSlfrDK8deWoKb1ck=;
        fh=Uzbq+uof/I4+jXSz600jJ+tNzdIXmgPjFLeaypDiWas=;
        b=awwEE5MbYfWuEdLHSA3JFAtFJZrrju8vw3scZ31zuW1o0fLxTrxRAcBEXIOufTfYSs
         Uqz5Ltvya/A7PO0lR5vDbQyYw+2o5yptdVcUKl3hlKnls0n0QZZ0dp9IqJGf9yy1x9ra
         boyB/t7g9nTMLRlXla6TD71bhvdZtGFiA36eqLHOExky0xEQ7C+oykN1BIET2W1BgxkR
         4YqMrRRV/yQC352MNUl+33JTAqczrO/lkyLyN9xd3fSuIFmsn9/PiEYrt4JWlXwUQF3H
         Iaj+BbyHLw1AISGhJpg/s2+AavItuO/Cbra6TeBp6H+0/WHAwzqB9JqHyizoOKzCzNJQ
         /maQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NKPsnpb+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725413655; x=1726018455; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gjsfr9iRbm+j5VmdDskNzCrhMARSlfrDK8deWoKb1ck=;
        b=UFDLsAN2vMOjhE7AamsCwubkqztfelMS4Bkv5SDF+rmkIoBw9dK0QbM9WeFq72EwNd
         PowdseAWRBMxWeKa4XMTICRaRSQuzuXEBYX9/JbOiGo1wkGoRqi+U//u+ko2MC7cG11c
         foPrDk9ffcZzhsmQJoQRPqLIgCTQnwvEBQ7BAnXNLkYdlG1BTdLi9R8b7D4Cl0rUx8Cc
         6MYP3V8lRGG8JDOoYF0c2Lt3KztNQn/9KUox1iTVf11Ui/iabokXHoQgP1GdWa5v+UuD
         vvA4MIC93XyuRL2bhKho3T9MIBzYFc80HtYh+Pu1XuiP/kJVYEwCxozNbc5JxvUajICP
         dKJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1725413655; x=1726018455; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gjsfr9iRbm+j5VmdDskNzCrhMARSlfrDK8deWoKb1ck=;
        b=KPYGILO/XHZcYEmP2pmP3wdngBPL1Ls3kWn8y4b2CYI8G/ylhuchrCgblHwDyCp0sB
         +HxpytfOZJjhQcZnShUFN7Kx5V86UJYg7FsmYBbNNjng09GCoZkRuTgF8MEpkQdnpIrN
         7L0g9YBPlmJ5uNWBr1tGIQGlTuYs2gWMFkrgiJCNWXOnN4SbraQALerj9c8xyiFryIAL
         mEPxioWADjwLu6usSrlhXrKFDhkszxF5JHIaGbzYiQFEZP2oVuSgizyX8r1T1BSmg90M
         PClfwIeN/kM4l46srtR9WdMONejJukBzWszy9bWAT3jEI8NwbH1dXDqFbYkD4PWE7NRO
         HD2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725413655; x=1726018455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gjsfr9iRbm+j5VmdDskNzCrhMARSlfrDK8deWoKb1ck=;
        b=R7RyG6Q61yz0qc17BfESq1YmQuwogihMHqFJzm8igLwXeJdMzZ2bXUsms3qDG0KAKR
         OnuP4efHShOO3jSOLp52kcvTjssbLiRDm3SweoGpbIgDRWDzmb4jtv1MAPdex2RPXMke
         3dPdocp2Za4AZwAodHKlX0KSpQMw1xuOBQadNRXK+VOhzoyTd/OjIGlJB4NXRmNN7vj0
         TcQIw04BXz7dIa8+9hGvw9+R/7x/P6DdD0qTIrMQ45wCVKBxj3pc9BCJ7V7/pii4dj9+
         JdXHvY5+l6I0VXBPgTLlSOOmZGoosrHFc4HFtovbHs6g+XTYBvqklZbwIvxKR85Uq+Gk
         Od7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvwRhLbPjkxpM3mk4pOu924IVDNSuB32K+sWti9gxGpicMkY8gj3DgpGMhU66kmdROW9GNZA==@lfdr.de
X-Gm-Message-State: AOJu0YwCn4V/dEG5fH0eHJ27LfS3vm1EVix4uPT2u9FonsvyIpX6gW5X
	QvytTkXWDOXAdNEQSUtTGfhoeL8cXWA0CjeaLCQbB/lsxKDpVBUU
X-Google-Smtp-Source: AGHT+IEUOWEWP0Xpr2b8lZ7h/3nayLC3b2finU5isoAt0UfqPwmb5NMu1kSTR7IX3SWTm+jZ2nxP5g==
X-Received: by 2002:a05:6512:3e02:b0:533:483f:957f with SMTP id 2adb3069b0e04-53546b2c0c9mr10667594e87.32.1725413654176;
        Tue, 03 Sep 2024 18:34:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2351:b0:533:48c9:754e with SMTP id
 2adb3069b0e04-5353d814aa2ls387118e87.2.-pod-prod-06-eu; Tue, 03 Sep 2024
 18:34:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD27Owzumhm+uWzF/xb9uT7sIew6zKaLp6+59spFxF2NtAdQDnTCD8XzpfzNzJtDmFIYEpSlymAOM=@googlegroups.com
X-Received: by 2002:a2e:619:0:b0:2f3:f49a:c6df with SMTP id 38308e7fff4ca-2f6104f2547mr100542971fa.32.1725413652147;
        Tue, 03 Sep 2024 18:34:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725413652; cv=none;
        d=google.com; s=arc-20240605;
        b=ji9P85lqNAIenFm+sh3XvN5n8tn5R84M7jtjNqXML2lf84hTvvITg6wOWuzJlVlmBj
         KKMZIR+DQulpEl8jR127LYGWoE/LcoeTJ0nmOhiFG5Tapwa0KweaaTznxEMQxRarGaI6
         ztnAp0ax9w4XH2TbsqO9TJrVANj85mzF+jKyHEtsQ6crT3kBJtgd4AM9v30l82A0Hu79
         DqdTVy56lehtEM/wynjj22X6KgYDe5TFXJ3kfE36MbY8a+9192IV1cMyCDcP3ec3RLd3
         98lOCMrkon5CG5Ky+MRQSGeuCiuktkt4vR21CvQ/N+hRo/n/OLpda+Jjd5oKAYEQdiH1
         YomA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=93FgyLKkVo2N1tBHkMC3aUUtyplqFSBZGLIS2ASQJQE=;
        fh=LnZW7ThkucQSNmlGUmqSd+E7017VCBchSqlhCGmaa4Y=;
        b=gFue3AixYsJrmZitQSeXJ/5SQzEYQ8aY53npf3RBAEpFcXN1WANaCf6D3ARrHUKVCf
         GEwT3790u+O1PBzF244XXBGmz4l+hTIozH88Kn8GJq2tYP60CNBiJzAz+mTGfpSkwd9b
         W0A+lAwgUZcmlsfIqKwsxQ+KKKpeLlhahQM1bKne2Rm7qWa+fsFAzPi1eCcKOw3rAPhE
         X14xDwnE9PBpHh/6fxcUoBs2D+vfyu38cIB/6uOzbPGeGneUO2cPR2OartEpdsNr5X93
         De0WytVqFKsmYOMYx82uhTB0NfFvKyRY9nyXh0cQKaDrLfe/UVRtDo7eq5l3QsSv64MJ
         cniA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NKPsnpb+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f614de8911si2521221fa.0.2024.09.03.18.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 18:34:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-374b25263a3so2583982f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2024 18:34:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmcpmKU1MNJcQ0uSi2umbfvG/2GOE6Jk9p/AnDyHukokRRHQl5bb8G4zgCTj+kX49Z4tn+q9Wu9f4=@googlegroups.com
X-Received: by 2002:a05:6000:1886:b0:376:65fc:6cbf with SMTP id
 ffacd0b85a97d-37665fc6d98mr3028566f8f.23.1725413651088; Tue, 03 Sep 2024
 18:34:11 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
 <CA+fCnZc7qVTmH2neiCn3T44+C-CCyxfCKNc0FP3F9Cu0oKtBRQ@mail.gmail.com> <2024090332-whomever-careless-5b7d@gregkh>
In-Reply-To: <2024090332-whomever-careless-5b7d@gregkh>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 4 Sep 2024 03:34:00 +0200
Message-ID: <CA+fCnZdCwpxc4gL7FeUEJ0cbMESe3d2tRe-NTCyDH9uZTR_tZQ@mail.gmail.com>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marcello Sylvester Bauer <sylv@sylv.io>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, linux-usb@vger.kernel.org, 
	linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com, stable@vger.kernel.org, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NKPsnpb+;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Sep 3, 2024 at 9:09=E2=80=AFAM Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
>
> > Hi Greg,
> >
> > Could you pick up either this or Marcello's patch
> > (https://lkml.org/lkml/2024/6/26/969)? In case they got lost.
>
> Both are lost now, (and please use lore.kernel.org, not lkml.org), can
> you resend the one that you wish to see accepted?

Done: https://lore.kernel.org/linux-usb/20240904013051.4409-1-andrey.konova=
lov@linux.dev/T/#u

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdCwpxc4gL7FeUEJ0cbMESe3d2tRe-NTCyDH9uZTR_tZQ%40mail.gmai=
l.com.
