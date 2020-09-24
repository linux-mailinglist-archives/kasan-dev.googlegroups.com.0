Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXEOWL5QKGQE6PWEE6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F73D277037
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 13:47:41 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id rs9sf1173987ejb.17
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 04:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600948061; cv=pass;
        d=google.com; s=arc-20160816;
        b=m0JvYNMCDkYaQHMRQFy+NfLwWt5LWZvqAfJo+CgYtj/O15uMxf2F7U8BE4M0xE6P8s
         xg/NcX63eQhPQx8RflvQxui93VJenNP42k3eXZMOTNTZGEsVYoycjXn1nNrJ3+BLRME1
         oiZiaG95kLb/NlJ0Q0JmIkzzdWi5bLyJ8iDFrRkdpzdUHE/eF2UDW4ot2qer6DgMtLFK
         l4UWkoqBnR5jUbsKVIxslYRaRJV8MF28e+2Y0FRoDZCg4vvYsqeVw6xXRgpYcwz7X1e7
         iJU0rJhSbBgb+jVtd5P8hrMR2Ca9F6N9UHR8ZBJKfLf83aJNphalhy0irccF7v4SX3bD
         ShBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wQYJrtnruyRFWx+nTjgRNb0olyDKGmmG6AhVpzGE4uc=;
        b=KjzuGSwX4BDr3HGerepBabIyxXurPeNzGxCnAWU+e/U1fFnnF33t4I2bYvYKbiQMI7
         jrwtx3Wpy5dS4X0AqKrr1/scIHFG7jHU6jZld+mEe8q4EYHvEt7NvUTUiHAHCH7EKhP1
         w55i7zC42bUdPWhCxx1EdM4IcT7gRWpV4sVeimtFVfWP6oRCd4TBzCMuqXpn7apf3iuA
         t9gfTxtWhaxC3ZUKnAYRADiEjPdaKHTmTw1GLNrr+Tasg2asIDSALO6IIiHp26fjK+6i
         XNAr0vJ4sjuq7YchRdx9Xq1MBrq7e3CrhT9iSQ+h3T0OfLcHt/VOW+Q66sAiFqlK7ucC
         m4qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TqfH7ms/";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wQYJrtnruyRFWx+nTjgRNb0olyDKGmmG6AhVpzGE4uc=;
        b=mTMT6cs69PGXOU7rfizF7Ioh3DZ72mgMWUx5CxvvHaQmt8u2mpzNmzRwI4M5sfTkbw
         H3Et5g4+HfomjJfJNL6tOCjI1wLITuTdyrPUkf4+clxBYTah/9+75X8Xlae5xdtbwNFW
         mEH6poR1Fk5zM5ng4EMP2N8ZP2T10Sinr511qOfowC1tcCtz/PMkjR9JSZkCA3cp25zG
         +XVdS8lgzq/YJ7U860DyhtbnCQ2SqAG7tZghzYSg02d4+OvD6lujdAFqRw2zhXwza4pp
         KfY9z1UBNpVoQZafTJstC0xKeQRkdV9MS0PR23dOWkN7MqpPmbyEfGbLMWtafIkBasAV
         /MAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wQYJrtnruyRFWx+nTjgRNb0olyDKGmmG6AhVpzGE4uc=;
        b=OAB2K2BzXWWnAluXFsQoSr35+9G4+L9hfxYPSs0bsDXAmNaMBg+vEjM1gCsqFNQ2g2
         uIxSKiG0UG/h4cXY6d1IxdmsVRizYIq1xfVerSZ6NxYlI4gyUU9bRRPfTBnqrmypcbxI
         uQzgci+4ODNP2DNsqOVlfMpUoEoX1Y20gCjYy1ED8Vm3fmhIcm0VLBNmQ+2BHAg+c09Q
         VdEm1uKQEvpHUur3TDXp3DNKR4iYU4jGvvb9hg4WDCe17EVCa0F5ODNsE5/Rbv9V5nB2
         KJvgNJhODt4mAzimlB9+pQxyyn7U9x9cTXpPvL79Pmwq+4TUdK8GKBEDeAPdp0xYzlmb
         8KHA==
X-Gm-Message-State: AOAM531NJgo/dq00+hplfQpd83tLr7znyBHGrxQCtVBAoSBYf3x7ENfu
	muskemIXzgG2XugOLePwvNc=
X-Google-Smtp-Source: ABdhPJyYCj5XQgOb42f2sURZWfjrrL1CHujaR9F7o76tzUyCDBeHsGULjxLqFxlK0DIiYdeZtFoAAg==
X-Received: by 2002:a50:e79c:: with SMTP id b28mr549337edn.371.1600948060952;
        Thu, 24 Sep 2020 04:47:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4c8c:: with SMTP id q12ls1372758eju.2.gmail; Thu, 24
 Sep 2020 04:47:40 -0700 (PDT)
X-Received: by 2002:a17:906:4cc7:: with SMTP id q7mr543039ejt.437.1600948060013;
        Thu, 24 Sep 2020 04:47:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600948060; cv=none;
        d=google.com; s=arc-20160816;
        b=j/DtZ21pmH8lXdVcO2NS11AvpSkcHFJbUUvvwMgLthOitxV5iu6ArvvsoQg/S5S1/O
         a8wTYwhB7XdFVcD5JA4gKK8WCQ/V8r2RQy43LZptQPgeaLUJddspgNSW9SCcqFmNntqw
         63xaL69HjUNH3gDJZQFdYb6kJeGFZOGN4pxwyChU9XYCN1rDWfAdePGO3PISco/IttME
         5Ao4/96NHFghPY6U882rxQVvUbzePMYqpHkPNzgp3h5wUkrAbsEC+W3fX1WUZJJtQZZX
         tpFVBnK+6Iz7dndxmUfmrFPdecIY+auUOaGvIIoMocU3XgXLfHH6z7DsAy2nFGgJi6px
         kgFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gen+1cfeiOVlze5PT7LGWC4Io/Jy9zJpWLjYnIvdBUo=;
        b=msw1unHunDPRIKaZRGv6k3A8ICQ+Vm5ZXrHoxD5BpPlV3qTEo8JyoX6viDizGYvnpl
         tgnVvm7wMK20gW+rSVOWfjXHlGgJE691QCq9TjkGLTBRnj7CbLcAvR2eQ25ryzbhKzdn
         sAfA4h+ctud1BuctXGKa8oL4Ro4pxHMUuN35CHLfZEVtT2YCqVijwU/acjN5PbPsQ2CU
         ibLIyxexNRhixXUn9uehVw3vFhOFFGZH2D+0AioFpQ971iV+9Q3pPvFjySm78QXmAWFI
         lKRE+63XvncN6ED3Iiun7WTyOBYob0PfJsaqvCG677tn2q95WEYA8RkQ++VrAXSls7Cd
         rHKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TqfH7ms/";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id f17si78215edx.5.2020.09.24.04.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 04:47:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id w2so3222837wmi.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 04:47:39 -0700 (PDT)
X-Received: by 2002:a7b:c749:: with SMTP id w9mr4067938wmk.29.1600948059478;
 Thu, 24 Sep 2020 04:47:39 -0700 (PDT)
MIME-Version: 1.0
References: <20200924040513.31051-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200924040513.31051-1-walter-zh.wu@mediatek.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 13:47:27 +0200
Message-ID: <CAG_fn=W2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] kasan: print timer and workqueue stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="TqfH7ms/";       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 24, 2020 at 6:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> The aux_stack[2] is reused to record the call_rcu() call stack,
> timer init call stack, and enqueuing work call stacks. So that
> we need to change the auxiliary stack title for common title,
> print them in KASAN report.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Acked-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> ---
>
> v2:
> - Thanks for Marco suggestion.
> - We modify aux stack title name in KASAN report
>   in order to print call_rcu()/timer/workqueue stack.
>
> ---
>  mm/kasan/report.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 4f49fa6cd1aa..886809d0a8dd 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
>
>  #ifdef CONFIG_KASAN_GENERIC
>                 if (alloc_info->aux_stack[0]) {
> -                       pr_err("Last call_rcu():\n");
> +                       pr_err("Last potentially related work creation:\n");

This doesn't have to be a work creation (expect more callers of
kasan_record_aux_stack() in the future), so maybe change the wording
here to "Last potentially related auxiliary stack"?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ%40mail.gmail.com.
