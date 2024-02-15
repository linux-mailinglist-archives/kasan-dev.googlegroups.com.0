Return-Path: <kasan-dev+bncBDW2JDUY5AORB46AXKXAMGQEZGMPYII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A41C08571AD
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:38:28 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-511a142ed1bsf1630e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708040308; cv=pass;
        d=google.com; s=arc-20160816;
        b=C1Z1edlJIJqIxwNmA/LgUo1oPJpJ7Ga8C6ZbeZhHyQTXXkQjdmguSrKDIcS5GgbI+p
         BAiEcaE92TGK6bQYTBf7UvRG8T5ctSpJ6HdaHLOTOkuhedO8jyRU15NKA/TJHMpMwRU5
         QqqsIGzokmnIg/3ghua8ME977OwwvJzj4FazwpB9X9sq/6iYDsIdIjcC4cQdtBSbH55N
         24COmO1wDh8d0LAyvmCefvXk4GBn7/GhvpVLN5WcYiK9tp0FQKZOTxn6DFPGaynWOfp7
         XZYxHTteYIRRgG33b+O06+Zu7/H/CpX/nXfTHoFd3MBUMiMkoJ0L2EilK1g29EUhFuW6
         xLGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=XC9R0OhEzcXO28ni/SyCCgujNVumT6Y3cmR3yYXRGiA=;
        fh=9eAu7JZ8ncMhWu4jIGJCd9sRtyd/og5F97JK2UnnM70=;
        b=Xcdm6R5TTz9KcKWaKyMzKxSLqKHIOziInv0Y/W65Q07Pr9wfR3Wr5An94fWc6S0KWA
         +WzU/vIxbgsQDEfP3SPdAa+sESzs8yHKNuxz+cHsUsdLWbqud0QpDI7O9x9TjI2L3HiI
         mVhGc+62i0R0uJ8rTdJyZz3rzSIFk56yMxwpSe451PAsWApzRz+aQVoZtQGJs35WoT0V
         3PoqIbXAdf0+f3x7BeUQVb5y/I/9/TbojkiMBLLCMjAd6vR0BX/aDtUPnNYkB1Mufnh6
         y6+HfKgbIsg0x+y37gNz+rILbU8+fJHLZzXpafORLu8YCH7kpZULuciwB0dC5+dqwXsY
         ZcEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UDse4dNi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708040308; x=1708645108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XC9R0OhEzcXO28ni/SyCCgujNVumT6Y3cmR3yYXRGiA=;
        b=jPbHfRTqlS+psgSDGUCL5yPQ+rDz1H8F/jPCjbndjCq9F3jIrErZGxN667YUaIJy8Y
         /5aD+DNhDRgwi6SRDXaMa/NQr1lAyMcpjVQuiHxUyMdcbr50bAV2ibdlEoV2w5CQyUa+
         ekxCxUxMvuNVr8DNGDK1vcYLTg8wyRBkKvoGIwBpkt1xqCsbEUgBc1aCXvDieEj2UmV9
         asIRzZpgAdpklaL2/dyjWGChkbiHYWo4HXzVDTONEQDLzoQpAIwIxnHihPJO0JPMyYAF
         iSlsMYVJUA1EKI+drzykrFSL6yb3ZFBLmvFVQ7897Fb7+jGxXY6Hirky58Dz9qdoGc/H
         1i1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708040308; x=1708645108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XC9R0OhEzcXO28ni/SyCCgujNVumT6Y3cmR3yYXRGiA=;
        b=LzRQGoV8DtgViCUXYAT+INYEriQFXsrVGwFTBQkpWibqCBk56hmXsPNcJfKtQS5BPO
         WLbq7F+D04HEIcXiu+sP0sxlEeKwKyW1oEBfdtRdtojyHC++VfhcE8Vb9C1VWwvslyp2
         nXDOceIgAPfDejoU7av/YgJwzF1HVHnxs9SFfVwJk0xIzx52lASZxzVMf/HylF02Bctk
         0Kvop29/ujBjEpUUc2stq9R49oeuGv/Mcgmv0JyOFeDWBkNUjtTkvN84+TK68UzHOsf0
         nzmwiSdi6TcthiaqJmYL2r+VjBySmuX1iKdY67x8C78N+dwKBx2BcXN4eNw5aZ28mbM9
         32+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708040308; x=1708645108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XC9R0OhEzcXO28ni/SyCCgujNVumT6Y3cmR3yYXRGiA=;
        b=cb1tHCJT5ENazkvGDTME5IesP9v5XeDQXaH+s25mpXPs26AhLhA/yAt52X7iJtxczB
         RVjkH+xUNTM8mkmuqAjfTQLa7u/SpmtMWQgEmAPPUondfC5x5xc9Dwv84UtLYsuiWKxp
         CfSilMwI8mNJSTtuzzOLN1AeXPc/tFq0vCIbMXM8CbOmaOMSHwigcImwi177Fw909ORJ
         utubJeaF6DoulTahLijwoPN9SityilkFsA6ugucBvFs1dF60y6r00Kb50fMXTqlbJk9O
         0CidpMR8aatD0CgV1wFT1CYyzrVzDm0FcFJryzdvm7e5Te+LdzdXD3p9v+ibGOJ5GmNK
         zzPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJRhJgav+DE/6kt6kkLKh7JOm9Y8zdMW41Imec8YMbN15qOK3aMBf4oLWk6SJ6wfzWrvP3/JjmKcx4jp2mKEDb3TBWy3Dpng==
X-Gm-Message-State: AOJu0YwpTq960eejPm+9qqJAhwZ6uoSuB0/3qO4OJZ0PlPIV6hM2XGvj
	hMQXHZcTLvhnCpjgeilEoYxoh/Eav9O1ksameCCND2i4JH1e0w1n
X-Google-Smtp-Source: AGHT+IHeyCeDBMiBoDgV82O7gEJYvhVc/JAtsR/svAd2qHmGArH4sWNH2N46wzVrWCM/HRKlyAEesg==
X-Received: by 2002:ac2:4189:0:b0:511:9165:9e13 with SMTP id z9-20020ac24189000000b0051191659e13mr55070lfh.5.1708040307770;
        Thu, 15 Feb 2024 15:38:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c8c:b0:511:5035:8a41 with SMTP id
 h12-20020a0565123c8c00b0051150358a41ls117060lfv.2.-pod-prod-05-eu; Thu, 15
 Feb 2024 15:38:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYELyfbFbhIMOhC62EyU7AeavHQ8n9AF2rrPbryUY4lO9LDOrBC7UcfJCX0M2uoishNcvi3v2NemAmVlPA1cewmnxOF2CfaeJuFw==
X-Received: by 2002:ac2:5478:0:b0:511:6f43:b5d with SMTP id e24-20020ac25478000000b005116f430b5dmr2289811lfn.17.1708040305923;
        Thu, 15 Feb 2024 15:38:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708040305; cv=none;
        d=google.com; s=arc-20160816;
        b=AzjekWZftg3Ey+/hyK5tiOmryjf1rKtRfAEBSkBzxctlvwuzIYuT/NWlFEJZRXT0k/
         Ch2O9vUzcH/TX7QS6VB3rc1i8gO9zYMGT1X4kSQyCKHppBq2idlIgCnicfjm4SolJD5u
         SzGORbMrH0/b6ZrlMVJ2ppBQ4nTDA9LKeYP3yOdi6nJ5sabdW8a/evD9luYoXHv4aFW6
         G3ESe13nGw/94Gpp/ubDZzzPyJZ388h+jEcwuAzni3nmJcBm+crNhNPC0Q1pwl21LiUE
         4/hs4DTJHUr1V/lYjj6pyIcb4EbnAGs0F7HNKIoK1d97/iShz8YHNjhG0AA26MK4Of09
         NQbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sn0sQTAwhEvIBiXDzaG6iULDQCmeFqcNJO1N7EmRs4g=;
        fh=gwsoeEdJi2RHEWbsBrvPQ7pqmKnX3wlRgmZeevk++1A=;
        b=Jpnb5C9LQ4XR+D1XC63kMzX1Ivj77cGkqT4WdLRqKB2SIJax0jikC2vWVgybHR5iUJ
         JDk46BhtCEcHb9/nFqKZbj7eXdL81vZ4qW/YC/sFH+Hgy5P2lhlR/hU5k/9eBHcp05Nb
         94ybUwxr97CIjC6iZ7cFyOlg4gyc6PgkdjqnjZyWaPD4EPG5ujqqzJOlPcdVnJVynEpm
         j/crkPOvZIESbHhwNgFmEYJF7VJncLTwCXf2SvNQzKC3mKfJqcQkQZNgSXa/idP8r/xm
         3+UPwAjyevjLoWKQZPtTfUsSaOCEI8uuIk6UykNwPmgsg8q0bTqSa2z2FMyUp6N6CgUE
         +wwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UDse4dNi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id h5-20020a056512350500b0050ec7483a0bsi82189lfs.3.2024.02.15.15.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 15:38:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-337d05b8942so905714f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 15:38:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXQJBQyUudDrq/Y1YkuhHvEEw4o2BlksjASxHlk/sEBlyfR0qLAI8nvXmkEU/zmjvw48wzuD75w4L/9lXLjbIxIg56dS6Vlnha4AQ==
X-Received: by 2002:adf:f0d0:0:b0:33d:174e:4813 with SMTP id
 x16-20020adff0d0000000b0033d174e4813mr453648wro.23.1708040305196; Thu, 15 Feb
 2024 15:38:25 -0800 (PST)
MIME-Version: 1.0
References: <AM6PR03MB58481629F2F28CE007412139994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
In-Reply-To: <AM6PR03MB58481629F2F28CE007412139994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 16 Feb 2024 00:38:14 +0100
Message-ID: <CA+fCnZc4huzB4e1vdmxYa-3fFQadO6j7ZTCAvcRV52LPNWbYow@mail.gmail.com>
Subject: Re: [PATCH] kasan: Increase the number of bits to shift when
 recording extra timestamps
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UDse4dNi;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Feb 15, 2024 at 7:41=E2=80=AFPM Juntong Deng <juntong.deng@outlook.=
com> wrote:
>
> Fix the mistake before, I thought printk only display 99999 seconds
> at max, but actually printk can display larger number of seconds.
>
> So increase the number of bits to shift when recording the extra
> timestamp (44 bits), without affecting the precision, shift it right by
> 9 bits, discarding all bits that do not affect the microsecond part
> (nanoseconds will not be shown).
>
> Currently the maximum time that can be displayed is 9007199.254740s,
> because
>
> 11111111111111111111111111111111111111111111 (44 bits) << 9
> =3D 11111111111111111111111111111111111111111111000000000
> =3D 9007199.254740
>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
>  mm/kasan/common.c | 2 +-
>  mm/kasan/report.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6ca63e8dda74..e7c9a4dc89f8 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -55,7 +55,7 @@ void kasan_set_track(struct kasan_track *track, depot_s=
tack_handle_t stack)
>         u64 ts_nsec =3D local_clock();
>
>         track->cpu =3D cpu;
> -       track->timestamp =3D ts_nsec >> 3;
> +       track->timestamp =3D ts_nsec >> 9;
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
>         track->pid =3D current->pid;
>         track->stack =3D stack;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 7afa4feb03e1..b48c768acc84 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -267,7 +267,7 @@ static void print_track(struct kasan_track *track, co=
nst char *prefix)
>         u64 ts_nsec =3D track->timestamp;
>         unsigned long rem_usec;
>
> -       ts_nsec <<=3D 3;
> +       ts_nsec <<=3D 9;
>         rem_usec =3D do_div(ts_nsec, NSEC_PER_SEC) / 1000;
>
>         pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
> --
> 2.39.2
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc4huzB4e1vdmxYa-3fFQadO6j7ZTCAvcRV52LPNWbYow%40mail.gmai=
l.com.
