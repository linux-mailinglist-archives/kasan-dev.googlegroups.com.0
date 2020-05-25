Return-Path: <kasan-dev+bncBCMIZB7QWENRB4NMV33AKGQE2EQC2EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B091D1E0B1D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 11:57:06 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id t5sf6902131vkk.11
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 02:57:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590400625; cv=pass;
        d=google.com; s=arc-20160816;
        b=MEZAnNiGQqBVcEuNFHAkCtTXloGdhs5/mSJW031P4TYg1NlcJ95hlvYIQ2qAM/OGCI
         hFK4qLdGFTzhU/7xBfd+7XZmHFzshVNw5yosTQ6PPH2ukqmOJUsxPy3Em1BUXO6cLAdJ
         2e38ykzsqj/jojdFV6jBGZVjV+knIBJaohKn0CEZKkZLAtsIVLAQ56ILThRKrfMSvbhN
         TQq8uDMwT5XRWmTTYxIbASquIBEs4TI1UM0AIkOLSZr63eXbHC7gC+OaBlbFgpMCYEly
         Q11KsApcBz8DniZcVtjozbY3l6I9q1J13WTnmin1YVMSU6Mp6iIiqEY5b/Gm6eADm48h
         6SMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SvMEwV6iAhEGUEtx57vFJl+BnoJHRrw5ZQPqUKy6m24=;
        b=cW+2ynhVf82F7q3VIurp3jMQHoid9CzvGODCLY0wKnkKn91VwqBVbMOrd4XxINIKzi
         7IuTlDzS67mUJ47uZnvXfpgAPF6Q5q+qHFNaxLyZbogselHiSqa0NHLnV6KONF8pveiW
         vsvIup9raKaLVO8VB2lsDIzTRD5A6JqAGk6c00g8mUQHx8noKSsTAZ7s0RNuslrGpNX1
         HCewxM+eXEcnMv4Z25rq5TMEdc0Ry0KSdU0oMe1CP4LjC69G4oIf8aul+Kts3H60n16V
         I30+N7Vi6TpCVafNmcn44g8O8fVmeaebven9FsvYABunDOa/SZjJTNg6jo317+p+yjXp
         DGww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qvMmSe1X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvMEwV6iAhEGUEtx57vFJl+BnoJHRrw5ZQPqUKy6m24=;
        b=NE61YUKkwhv+xJm1SZf1Muk3c0pckADinL+Z3FNjAignWKiXZh4AmijyDT1dhzcKHN
         Ok/A+FVoB6jQ37Tr+ka+7VEDxWGFY7DrgR+6oF0Zp0X8XOYQgAX+hJgfVs1WlqWNUQ3K
         qr3sG97eREv5kVGcdCK9QrvENOSBrgDVPKZEVyZMjkALyGlpPS/d/r/5X1Dr7ZUi9wis
         jGXJVGQyVdmjnZZtaSJXAyPD4n7uyr6EjUf74UFz64yQ6n7AlCUGwmJz6gf1MtcqvNIe
         jtIvYrRm+Hf18S0/VGU7MF2imnoFEAI5QdPQqqQlWAGR3IgMcQjW9+k9a/B4wqvSJBQ8
         baSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvMEwV6iAhEGUEtx57vFJl+BnoJHRrw5ZQPqUKy6m24=;
        b=FFNY5CpsJnYD4/AHBIx2rVSWBdxlWCnbORC3VrUePygw5nY8VMNUM+VioxDaD1qThH
         nymji0iYwdYjYb5iNv5RDV0iA40lh1ZTOJ0B/gMqwDitdt6MbfDEXgc4S3DskUGwACTR
         mpqux3wrd9mQaZJpa+KEgxbNGvSud+yExL+kjHCgapJa9SYkXkD4K4BYrv/10aFp82yI
         WfKi7NDkBP9WLgVzynspK+lCj8BrgQjaXqYot+rHSFv/8in4d53fFhRBibIqUs12TvDI
         TLoFgyw2Gga7aFX8EC4QQWuLCPnycj2PjVXyJ8u3dNsfv8iGC4rdc3wLi4YsgZmc3gM+
         RpzA==
X-Gm-Message-State: AOAM531oqOryAcHV3O69ec3rbDclO/ZEz5z/2C8wU8xt8NaFS/7E1Q5e
	+na+N1QDegWIvjGCTHB55VY=
X-Google-Smtp-Source: ABdhPJz8YLN3Viz8hlyz1BTSgA+Dh3QHgV/uZxyCCpl4Nuc9rarWS43VQDDMfe7K4W1Px7m/h2QvfQ==
X-Received: by 2002:ab0:2657:: with SMTP id q23mr17344308uao.120.1590400625721;
        Mon, 25 May 2020 02:57:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc91:: with SMTP id x17ls727038vsp.10.gmail; Mon, 25 May
 2020 02:57:05 -0700 (PDT)
X-Received: by 2002:a67:6b07:: with SMTP id g7mr17579234vsc.10.1590400625385;
        Mon, 25 May 2020 02:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590400625; cv=none;
        d=google.com; s=arc-20160816;
        b=mNuMnkr1cq3VLbVwTyoYt3F009ew/+oEnZ7PSwtjDRR+tgymMLSRqPK+HvoAyYDKOf
         uiZ5d0oNNUF0bB3WaSi1Ot40nh1zzc07ePL1qprpfRaUmvBmv6lCZqWtvez14/7DtZdO
         kZej2FYQDMIMUkGxBjP06Qfin/hls+K0zw77gs52dpzzL4ZDSnQ3Agb9UEqnvjxOx+uu
         KKEozPqzM8CtpBjXvjQMwxoYnqiRif95tihVTAQ2oDza8EHyHH+g34Sah9Ia5/uofnXQ
         CkZfi8imUnrlPD7b6wdNlhJdEgLTArrDMhZKvkxrjtCWmm32lUMoS5MV2Nmwk0bjObdS
         4qRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lXJcON4uIxpNxBwaXZsOO47XJesOn1/BpUPO8EArG+w=;
        b=xsT16FdwyGnsQDLztEw45UJzd7xEVBaJuZO6a3XaGnKTZ9uzQdHt3kDj7KEmv7P3Mh
         YBDvsSWmzrs/m7W2xjtaD0zc6xMKyR3ZkunW004zUol2s0or4a1k/6AqrFi3R8bPBPBj
         kWdq+pyRGLdXQedl7VkH7oBjhrk+HQPB4gDG5bwenTQV4eqeuGB+EdqP1g+/MCaiwYza
         y0xlj6deEeLHKDOEftP+fZzn9UKMLN1tbvcyLQ5A8GK5Nv/WdBnjej+Is/+SiA8SKbR3
         uaPu0rzMqIfhk9eHFczqu4oxmyDdya/sp4fEfJttZEk4LbgWX5RQxcEW4uJJhOMVG52+
         QseA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qvMmSe1X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id b10si1054840vso.1.2020.05.25.02.57.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 May 2020 02:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id p4so7797626qvr.10
        for <kasan-dev@googlegroups.com>; Mon, 25 May 2020 02:57:05 -0700 (PDT)
X-Received: by 2002:a05:6214:15ce:: with SMTP id p14mr15030956qvz.159.1590400624833;
 Mon, 25 May 2020 02:57:04 -0700 (PDT)
MIME-Version: 1.0
References: <20200522020212.23460-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200522020212.23460-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 May 2020 11:56:53 +0200
Message-ID: <CACT4Y+agmL5ZOWmNBJyLSTuhy7ekp4HTafABUsqqP+XFd7ErKw@mail.gmail.com>
Subject: Re: [PATCH v6 4/4] kasan: update documentation for generic kasan
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qvMmSe1X;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
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

On Fri, May 22, 2020 at 4:02 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Generic KASAN will support to record the last two call_rcu() call stacks
> and print them in KASAN report. So that need to update documentation.

Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>

> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Jonathan Corbet <corbet@lwn.net>
> ---
>  Documentation/dev-tools/kasan.rst | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..fede42e6536b 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -193,6 +193,9 @@ function calls GCC directly inserts the code to check the shadow memory.
>  This option significantly enlarges kernel but it gives x1.1-x2 performance
>  boost over outline instrumented kernel.
>
> +Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
> +and the second to last.
> +
>  Software tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020212.23460-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BagmL5ZOWmNBJyLSTuhy7ekp4HTafABUsqqP%2BXFd7ErKw%40mail.gmail.com.
