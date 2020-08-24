Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHORR35AKGQEQJXMGHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C9E324FCEF
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 13:46:39 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id f25sf2164043vsp.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 04:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598269598; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZeq+SjQpm/7JR3/EHwB+e+nADMn9bOqUBEnzZe865LFwu9TeeqjaAl3kH+y3vaCaW
         iE37CuelFiWkxfe4RqSxO/mAqEnCMHl9yjNk+NUjNr7DYUFJk20uBGarCkmKu2YMWqmC
         ckgRJwFYFU57d8PqHU912J+dk9/fEwH85h77zVHF1XJ8rR6lezq+pwqqR9e42V15KyHs
         m6k/0GXJ7IUDAu/TI0GmAoAe94gpUOhABwYQLSDAdWG6ecGuxrPm8gdhIz/Gs3Aw/wkq
         LL1pgRv13XT0CgkZg3/rt50ah9LFU0pGfkfse9E6fJm9KyG2b051UpS8hjFFki3/6+RI
         K+hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+KwYttw4tEDAjscCV1kQ6uqqX/A5N2HiUlwh/ry0ANQ=;
        b=e46wF9wvR6macGm0+YDZ8hGXjfwrSXzHXBS3Dj5onq0yQP13HY/TSx4IUm9gPkHs44
         tTZAcwby/zTdnmDTeTxNIeU7JdlUGkVJfPbFzBZm0D7KvYjoY04aaa0UjUW1XNJEZShF
         3wYlnpOqAXZArhDAvuccVKgMQrm2JomK2uzz5gtPXtVIlFU7aaTiq6QM20OC9SEPfVUN
         w3vORXX8IhNy6XL4icmBV7AiNijIQiSzfuqJi7IpFzERRlVZevBtystVHX9GcUenTOto
         fFW0yK/k0cPeUTHcR+Nwn/Qj/SRM0yv9kjaWmsCIjA4z3csd/5BGTjK+RndYhUY7PoMT
         +hjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iuMev4pI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+KwYttw4tEDAjscCV1kQ6uqqX/A5N2HiUlwh/ry0ANQ=;
        b=PX0HP6XqmZujIdiPbiJ87+4aVpqxa/7++KNsfIH+MdgbqxRy/vmLkcSR1JDVFe1LWF
         a8Ah6bVRW9IqL6VazByn0+iLgfcgLfYK/a9Fxtfd/aNf/OKYtvxM0Y3yijyIDFIBXXOT
         pbypPpDUHYyW53IFPuCB2GwkpsgO/lUbBMTv7zWJ034rcB3SpGmMRF9qjPKhyHZjMmgl
         lklhiKy4P5cLSw17Z8d3lOvviuo7DxOu0hFnRuLfrQFd06WaGECCUp07YUwYkI5NmlBX
         Vgjmieg9JSH/s8nRd8yueNWTJNgwbzqvk0HcAprEDEY9dRBmk/fdMPO4/iIrABEC5FCr
         5MFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+KwYttw4tEDAjscCV1kQ6uqqX/A5N2HiUlwh/ry0ANQ=;
        b=oTTdZU7zmXygkMupQ1ZY51+hQ8dtTqOyRhgxW/FSY6G51qKz8Y/N9eMjO1OXCrUKFN
         3I8eX0vb6H4C2IOXsAfDrbtxwiXCOwnbVEfKHjWMQQC26DqpSPTzrBnAKuULfrP+LvLO
         xzk2jIUsAdGrEDFSERErFYyr1FmpSO+U4i9/vygYO0wA3waC1wU2R0BFmt1tEywedYEf
         btO3JihKBAyn5gguvJ1TvfenuFFgggBA4va5l06N0qo5LY9euJefvM68BR1KrpbkWmdz
         gwmeAm7EVlz+0gZpo+Xrv6+s9QBGPFWXcapjUbCAXdcPrsWAhkZEO423D0Mr2gYtFoIq
         xcew==
X-Gm-Message-State: AOAM532sRGZleVxnNVHpAecxCi2XKA3NegT4FTmSD+qn0wb4lOa/yJhJ
	xK9SXj6IjeQkIEjmX9iZhcU=
X-Google-Smtp-Source: ABdhPJwzZDx8gxtWVxVq6Qd9p1TW/7LVc0VKJL0cdEhMYQ70KK3NOJP34gI23wSbHTmrjwBQicRtWA==
X-Received: by 2002:a9f:2611:: with SMTP id 17mr2002164uag.135.1598269598087;
        Mon, 24 Aug 2020 04:46:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4ea6:: with SMTP id l38ls287265uah.1.gmail; Mon, 24 Aug
 2020 04:46:37 -0700 (PDT)
X-Received: by 2002:ab0:60d7:: with SMTP id g23mr2023039uam.122.1598269597614;
        Mon, 24 Aug 2020 04:46:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598269597; cv=none;
        d=google.com; s=arc-20160816;
        b=0pKnQoet1Cl8cRyaW58+FgrkxLfyaYPP2T6DMeE2wYRY2fR3hlV4lJhZ/fIMsB+Ebh
         75vPMgRDZXmStg+krs4K1utE6QIjpPptN5bJIIU/kkvi4Dz+urrmBTK341ZXKN13ERZL
         fInYG+cEOKUmPPDSNVYSfFKb2WPBPkzm5fUYyZV7ilMbauVP6qCkSa5Gusnlqltl7GC7
         E/JW48RzAUawOPyLzVFTdB9IDt3EjQfEBVayiMOmFsnzGfC5Ga0kx9SYTm9o6IEwUEjq
         Yf/TDHn6oQ3grSDamOVq41y+pEpblyf5qgmzGKo23DrHFwszDllgGT0CGr/pyXoHlIE9
         UOUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HSpd9ndfyXeRtsopkN5H4Z9El4e9MphbysoofBmUjKk=;
        b=u6mprbYxZZWjodM8pJFo2B6v2JvLsw5G4PKMUvQDuUpvaUTz/HTFYzdWkFDFpQY+QH
         z1CamNF/0n3pVBaqCWMKp0mtTXT8qqjHmtqcxfM0Sr1f+OH2uF3WSRacO+n3+TBJ68Qn
         JxlVlfMQVXYzdzil5NLiAo7SJ67Pk8935oNl4jf6p8XWONm3si1b5fifbRir4KyLH/zA
         sgg2T3zM3URWuADmVI0tODu6fcnim5vaepS9iUrwyCixQ0wgKLyq6HUzkFlh23GcCrU4
         5kfJ0meMAzMzAqU7puQeZXd+3uoJ2woZztswC27bQJAvDgcRnYnKI+N9k3jzFz0s5TnQ
         a1MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iuMev4pI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id c11si119113vsk.0.2020.08.24.04.46.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Aug 2020 04:46:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id 2so2412088ois.8
        for <kasan-dev@googlegroups.com>; Mon, 24 Aug 2020 04:46:37 -0700 (PDT)
X-Received: by 2002:aca:cd12:: with SMTP id d18mr156277oig.70.1598269596930;
 Mon, 24 Aug 2020 04:46:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200824081433.25198-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200824081433.25198-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Aug 2020 13:46:25 +0200
Message-ID: <CANpmjNOSKQi+wYbCVYqL-LriqCD37GtOfrArB0hyKysaPYyzGQ@mail.gmail.com>
Subject: Re: [PATCH v2 6/6] kasan: update documentation for generic kasan
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iuMev4pI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 24 Aug 2020 at 10:14, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Generic KASAN support to record the last two timer and workqueue
> stacks and print them in KASAN report. So that need to update
> documentation.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Jonathan Corbet <corbet@lwn.net>
> ---
>  Documentation/dev-tools/kasan.rst | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index fede42e6536b..5a4c5da8bda8 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -193,8 +193,8 @@ function calls GCC directly inserts the code to check the shadow memory.
>  This option significantly enlarges kernel but it gives x1.1-x2 performance
>  boost over outline instrumented kernel.
>
> -Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
> -and the second to last.
> +Generic KASAN prints up to 2 call_rcu() call stacks, timer queueing stacks,
> +or workqueue queueing stacks in reports, the last one and the second to last.

We could make this more readable by writing something like this:

"Generic KASAN also reports the last 2 call stacks to creation of work
that potentially has access to an object. Call stacks for the
following are shown: call_rcu(), timer and workqueue queuing."

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOSKQi%2BwYbCVYqL-LriqCD37GtOfrArB0hyKysaPYyzGQ%40mail.gmail.com.
