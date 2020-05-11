Return-Path: <kasan-dev+bncBCMIZB7QWENRB3644T2QKGQE63NT2OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B91471CD6DF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 12:52:32 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 5sf7478572pgb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 03:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589194351; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hkbi16zo6xZ2jwmUO/S7EDti8a11aKRiB3tLrcQEiIoR57xWnnjTZb6yzX2/x9vfCc
         Zn8etHuvaVlDQ6mgHT1fjPfqFrT4dqbmP3u+DUKUP7t3aPCZHs7Uu2FXHzdKvgCHTcIU
         evbfZSNmb0wRTPoXZVQrXRDgb/A8OtQ92m0/qo5LLlYy/7a73bc6/qRF8R5fdldMOAUh
         MLDnqyJwWw0YEv8dhSh2JLAastPedViHMGCeBrdiLNjqOJ4k8iTwdxdI/YGaSf5etJdd
         QOb6x2RH+eGisHGmj4otnMfsZaynyASpoqyrLoFNoWmdF2vazo8yGDwZ8Va/hpD2UVjY
         G0dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RtT9GSp43GUvbpag9LfCZ4XKEozPo/Dcl21cV6oNS9M=;
        b=PdWPj/zgyZuJ3d/pSq2kmpyDtR3TSV3JYIL/2LOgRGXvGe7/1EuEO8PUEYfgLulZVi
         izNCl60w01keuEO4ylJRz2j4yfeNPLTN4dVnSJlOyjvaGc0o1iAAZAozmh5SlBzQFtMM
         lhiovJT+PbqKz76ck3cK2ATzGQ+giBP+vvCkaKQhW7aBN3SlfB6cAu1SaeCSmyVh8PUT
         pJvGelr/28NRdU+1gJHY4Lo4uaC7mzDeQWBgdvFggsRn54TIlZfSLS+MbeMeCsDMJr+8
         O0MVCiDf5XN470sgb2Cl65/P7nHFia59EFIiA4/sHqXN4RcTIUOB9X8uOufezSEQb07o
         pCQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ILnkM6H1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RtT9GSp43GUvbpag9LfCZ4XKEozPo/Dcl21cV6oNS9M=;
        b=te6yKcrzuMauDySh/T5OrkuKNeniTGjn2IjRJz/j7AKDUVLc+fSWfbunOUY02D6ONl
         0TuwaRllkQWUqFhCljIDk5VgN0lYNfAkBaDmWhyYzYuLdooAcPvzyEh7tk5mo7TtK2Vo
         qThh5enj57/a0r1aIM8e6PP6IwJA21t+XC2DVgmA3/sQM2bN/Gi/JBbKxfnYleEkcwGY
         AJ/OIh8uj8J0lnZVwz5n1wv7dv5SNY6W/W5JDRbcKFlgidxcaWPGlGNUPR8ya2ZwzoKm
         3C3yBFpceDKaFEz4Aa6SxqxfnYQPXexd5guB+FfhmxXX82+k1hHSQI3ZgJfLeR1aarCI
         Q+Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RtT9GSp43GUvbpag9LfCZ4XKEozPo/Dcl21cV6oNS9M=;
        b=OFrS7wYnVmH68UidAH+78NH0oDagNkOvN6kXSmWjpxSEfNX18RpK6VPm7YSUrH9RPD
         XV9t/XDtIFyf29dgawHn/yB2uZlFXPVxufsb+veAld/L/MO2ss6C0uhoU9/jYAH2VNTl
         cbJggz4f7ODUey2n3Rm3ID3gm0BGgXyimob4RHwOT2AndM7TQR55PJLG6aJfaS4h7BUM
         spANUrycjLiv6SV9p64Ny7JMQEgwAzCGz4xSNf8bbrDuX0HftH989ms39EHvxpN/gc71
         MzW5H2wnkHKOq1qAamvQNvVUTFkcuA8vjHlMdw2S4jeo3ME3ev2yD+8UOixFP1j98zi5
         tTaQ==
X-Gm-Message-State: AGi0PuYmcxFBRO4kkstakHzn94AuP+dXA/XO2SQ9BCkMrjYL1vFGyeSY
	0R9QR/O/6D2LspcbHyqINHc=
X-Google-Smtp-Source: APiQypIrE0pZBNXu5xEs9JFVL3lX6zQa86KSZgQDWycrvvRyuOh/+qhr6HYvPmKZaPPXenXAeJxvXA==
X-Received: by 2002:a17:902:a586:: with SMTP id az6mr14437529plb.201.1589194351365;
        Mon, 11 May 2020 03:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b702:: with SMTP id d2ls4815954pls.6.gmail; Mon, 11
 May 2020 03:52:31 -0700 (PDT)
X-Received: by 2002:a17:90a:362f:: with SMTP id s44mr23436909pjb.156.1589194350994;
        Mon, 11 May 2020 03:52:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589194350; cv=none;
        d=google.com; s=arc-20160816;
        b=ExueQWEYQ83/nZ8/G+XPHPkmlwH/KC0gea7ncnfkgTOrODSGkc+afP8Kg8GKcfT647
         6NlBi4peKRYQN8OZsy3kz5mMKYg69ksKLFqgJf7pj4oFItEg9muDWpa1hiohu4InF214
         x4iz3AUaW23zfOBh1D4tYj9e2cG4p/NdSPl1rD+X2Doi6tPOCn7PhXEPJC4khQDO80hg
         PZ3tIylHGbM5QzdA/FtJlVQrtde5T4SqBR+F9K11dICC3uFGPDK+FO9hXcDkiGhBsQEf
         imdZnkeM1c3mT0q58XyR63+XUprwjPoUB/EpsvXx6iS1MjG+u0irFeKrYs3p4MhMnz2m
         BM/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=72CupRCuRPXXCvNwucE/1jDQJJRDxROzY5cHpuICnYs=;
        b=qwohG0s0e/837F/XRai1i/oHd5fhChF944EkW8WVpu8GjaAzYyIsG6AGGceoYoBS9u
         aERRoEZeSzltP/0ZC4ux054sjgPGfLafKpqGAzCTdJfCstyArRWDT/QDsWt2Rt4dn4r8
         z6OsdDI4SFlxBmKiPsufGSug+k6LZTqdU/zA30t3lc74C5G1kk4nu8ubaIc/yo3J5sPZ
         VPNCFqkQlWrLEALB+zyJvA/wpCnZBfN8JVC7O6bJbTi1DyURRdS3S+77/o/vO9cYgPXU
         8aYp9YDz6u7qxrMgo6lF6QesuPFhJct4C+u8bYk5v0KtmQn/Pq/MNmsHaF8lvfrujPwp
         dorw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ILnkM6H1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id z5si536834pgu.0.2020.05.11.03.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 03:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id g16so6720466qtp.11
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 03:52:30 -0700 (PDT)
X-Received: by 2002:ac8:370c:: with SMTP id o12mr15522299qtb.380.1589194350352;
 Mon, 11 May 2020 03:52:30 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023231.15437-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511023231.15437-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 12:52:19 +0200
Message-ID: <CACT4Y+aL_R4uVFugsj3wXeXw2oXbe6KQ=YmwD0jCrUH_12ouiA@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kasan: update documentation for generic kasan
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ILnkM6H1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Mon, May 11, 2020 at 4:32 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Generic KASAN will support to record first and last call_rcu() call
> stack and print them in KASAN report. so we update documentation.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Jonathan Corbet <corbet@lwn.net>
> ---
>  Documentation/dev-tools/kasan.rst | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..d4efcfde9fff 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -193,6 +193,12 @@ function calls GCC directly inserts the code to check the shadow memory.
>  This option significantly enlarges kernel but it gives x1.1-x2 performance
>  boost over outline instrumented kernel.
>
> +Currently

Currently is excessive here. Everything in the doc is about the
current state of the things.

> generic KASAN can print call_rcu()

s/can print/prints/

> call stack in KASAN report, it

KASAN is implied for "report" in this doc.
s/KASAN//


> +can't increase the cost of memory consumption,

It does not increase only as compared to the current state of things.
But strictly saying, if we now take the call_rcu stacks away, we can
reduce memory consumption.
This statement is confusing because stacks consume memory.

> but it has one limitations.
> +It can't get both call_rcu() call stack and free stack, so that it can't
> +print free stack for allocation objects in KASAN report.

1. This sentence produces the impression that KASAN does not print
free stack for freed objects. KASAN does still print free stack for
freed objects.
2. This sentence is mostly relevant as diff on top of the current
situation and thus more suitable for the commit description. We never
promise to print free stack for allocated objects. And free stack for
allocated objects is not an immediately essential thing either. So for
a reader of this doc, this is not a limitation.

> This feature is
> +only suitable for generic KASAN.

We already mentioned "generic" in the first sentence. So this is excessive.

This paragraph can be reduced to:

"Generic KASAN prints up to 2 call_rcu() call stacks in reports, the
first and the last one."

The rest belongs to change description and is only interesting as a
historic reference. Generally documentation does not accumulate
everything that happened since the creation of the world :)


>  Software tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023231.15437-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaL_R4uVFugsj3wXeXw2oXbe6KQ%3DYmwD0jCrUH_12ouiA%40mail.gmail.com.
