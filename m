Return-Path: <kasan-dev+bncBDW2JDUY5AORBPWXY6DAMGQECVTR5UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB143B0642
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 15:55:11 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id y10-20020a05651c154ab02901337d2c58f3sf10645144ljp.9
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 06:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624370110; cv=pass;
        d=google.com; s=arc-20160816;
        b=IDfmCsDhrN8QRfdofJ7bdV70xFRCzT9tOwwnjvWEZrCaKkCUUIK20xc0OoR2xq9NeJ
         PAWaimOIgsoec98+GGdWtVlyEdurfPSCLtDFmv6tJ4gauezATfmJOUT3UOUQTz2AyTwe
         m56ZRTx6eDzfLmhvMqvg68kR6bjmhtBNeub+tejCoiWBOwxcS5n8n4PHo4UJMDM/AO7h
         RoLALgzfOLgxqqUfaKkf2lEo04AR79O8WXR4rtcTlgRL0k3hxCUwcINk54yas1RKmsK8
         1bH+/OothUhUpclTvuJ4cFZbqsRi6bYl7j4JPcofwUL08BTZMgZSZQdufcWqbWoA7CGP
         TiCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=k2lK1Aj+qN0yWxMwsm7w85AXfdFcNj0nkhJDICIKmW8=;
        b=NVcGqk4WuRgF+/UurCnUHiAixhU1h2L7fJm7zFhdcTLFvnnJzbo/TyAYBJQBQ51xrQ
         cf501JpTGpgYO8RZGVDMvMEWActSfelSfVpR8UWBk0GvqrImUbnudPn5Km1Qkrmwnsyd
         LkCnxR4JrjyWRPxCbR/lhkx7YojUW1n8f8ZdhfDVltXQWkj02LDEQFxQRpLFDtOZzLBL
         FJuf4zcI+ujqD13QiHuEiYP1hjDJZmbZhh81JIfqkArHMuwOiz7QUiqV1MJvJvOix9Dd
         N/o3Pjpced0D/qId1kQ6JTWcCSSr0BPacspvcixcOh2jQFJlGldczMEOm2K4F1QyXPYS
         o8AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ouzNwjxR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k2lK1Aj+qN0yWxMwsm7w85AXfdFcNj0nkhJDICIKmW8=;
        b=qwicKlnzeiWaHjHwBfEB466WNL8eqYyIGIAlna7DQI1IWr8bF0SG2Xzc4yB/5LGiPx
         3N892fggRwdQmpSaTscIzLTJ6bTSuS/wiEEzw7HTUKB8Dcq92FKFlGD0pVThuVIwUVJb
         00reRng1LhvzxLaqa5hfjjLxJkNh/SFc645h0w1SV1zOgZG880cgyEt1Yg67v0kGZTcp
         TePOYwyIDkJTSqMF/cP0jS+iQGG+EOfthPqqzXf6B9IMGEaje0qO8zASUGGRMQaNmi+p
         +8lLYw3FbWeeULaOHIarMa8EYbGOXzg8QTjW/zxXi+v7A5HJ9ezD1FNpYKDwLBuizpPx
         utUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k2lK1Aj+qN0yWxMwsm7w85AXfdFcNj0nkhJDICIKmW8=;
        b=N22MIYCeGqlhuyVeciWptHu7rUZZyqnbT1SpfHvkaRCzBqTLAVsOk+mTtOL6wW1FX6
         t1N6F22MaHjHK+DYoSLBQdqKRLmqvap+9Mw1aBLXvW3ey3QLiSjn/sm0ufLo1sst0xic
         I+A0r5fCvv/IRLJEB07uu7NStvlIjgRQ1GpA0fD/ZE+tEmQhLawwbXMGyFKmvhZ4/mw3
         7DC3rh0sb4HINAos8AFxVGfrs0C6dVwyT0PW+wh+tfU18U5Fd4J4x5zB2w5aTeZA7iKv
         +evuQFM4FRXRh/IUsVuwfD5hPJUZbKs5AvJKq7INZfgC4pusb/OaidXGFatu1sOfBXy+
         VzvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k2lK1Aj+qN0yWxMwsm7w85AXfdFcNj0nkhJDICIKmW8=;
        b=HXkdw8LxpVkgwob98HJySngFqq/uyW7mwJdHAgwpLBrOhQ7DZTmZCfX9yYlgyfsDsy
         CsL4IFUumgxJQhnjAKKIRo0WJrYfb0K4SalDi1OTZB2DB8Bkqe/44VvCo6iX8jOynDVe
         gonqkDgtp6AdGSVSOZd3r4p7D6MYnKZ6wwisGud4wnwpghGrp2VYelglGw0Ew6zoC5O/
         6E/Ecl7Pda+pGlYVQC3dDcCwgB8JcmY5RuEs68/JRNKWI/wmRsrF4L3sFA9uoLRCyQSm
         1xBgQXDKHli10VzS5wfad+IKYTylah3k5BchFq3K/aAefdxqRQnO4U9CDjxb8VpC9U6/
         2Cxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wgQ2dY14P3fCD6w/yyZSTocXJoSNlBEOEF56n7d9kcVKY+RJv
	DGML+GOs6sBUcnkTeidG0b8=
X-Google-Smtp-Source: ABdhPJxrlZBsm9XHV3QTwutJ/w0cG4x/oTsho9jHaBoelnBOWDQ91ZC4a/glwgiz7h4aX9kExdkPqw==
X-Received: by 2002:a2e:9617:: with SMTP id v23mr3417279ljh.409.1624370110813;
        Tue, 22 Jun 2021 06:55:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f515:: with SMTP id j21ls2337666lfb.1.gmail; Tue, 22 Jun
 2021 06:55:09 -0700 (PDT)
X-Received: by 2002:ac2:425a:: with SMTP id m26mr3071460lfl.458.1624370109819;
        Tue, 22 Jun 2021 06:55:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624370109; cv=none;
        d=google.com; s=arc-20160816;
        b=aXcab4aMYHfr9sYdwHy7ZJuk/x8Aw1snSrid3aGt+1UZiiFsZMz58PKGglqxkP6ToO
         97q3jscqQaPNkce9Td7zXjHTo0U5ToCborylRDIp8PRmJnZFuRli+sWsh1n36hpehMUt
         i1mMz3a3nbtmpAXQ0u0r6pcexPwctOOI/GynDl6RlcIjM0QR97WZi7N4Cj3cJs5kGeQ/
         9rPero8BDE+dAAYKFeLvzMbzWZDZ4/K/yK+KHp+C5rFV2CklzAaji3Cm+EqYNsMJtZ1u
         Rrm4XK62tLjW62lSOay9G2B3AMqDsPmsLiQIzT/UAFGNkmyXjxeOgS2dVls2/dqgZGNc
         VR3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mtJ7IslezInr0IjO/y83W5WcZUNJEOAxkSrY2hYdtzo=;
        b=n9o5L3rivB21+8FPf4hLTONzGbXW2yAoN+E5ZaZeihnD4eDkjsbcgS7Pp/K8fCn+sx
         K3edEhi2Dspnjd8sQE6kNzyiC9kCpZk+jfoZbbAiCbKqb5KLeldkn7gk0yvks2No42pT
         8/ldkDQs9iOQpC2rAuzDGRcxewFYt6liuavkfe9Fa2rLf/lzWY6XMSLHmdWRjLMvMrvH
         xBLKDubfquyouQIAi9S+dsB5N6Vtbmi9fdn8YCNCIbks87sKc/BsX3NTBXBeFuPP+GrY
         qPbevZP3M13N7oogZeLKs8rEYS8X0nJplc2CmAZVcn3jMG/MyZdWOL3cMYEU+C0ZwpTH
         KMNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ouzNwjxR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id i12si123149lfc.10.2021.06.22.06.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 06:55:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id bu12so1430099ejb.0
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 06:55:09 -0700 (PDT)
X-Received: by 2002:a17:906:17c4:: with SMTP id u4mr4217576eje.481.1624370109577;
 Tue, 22 Jun 2021 06:55:09 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Jun 2021 16:54:49 +0300
Message-ID: <CA+fCnZcSy6LqqhbYfiC8hn16+T640uw_rnUzNPg1zsvg_RwYzw@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: add memory corruption identification
 support for hardware tag-based mode
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ouzNwjxR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62d
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

On Sun, Jun 20, 2021 at 2:48 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> Add memory corruption identification support for hardware tag-based
> mode. We store one old free pointer tag and free backtrace.

Please explain why only one.

> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  lib/Kconfig.kasan | 2 +-
>  mm/kasan/kasan.h  | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 6f5d48832139..2cc25792bc2f 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -157,7 +157,7 @@ config KASAN_STACK
>
>  config KASAN_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> -       depends on KASAN_SW_TAGS
> +       depends on KASAN_SW_TAGS || KASAN_HW_TAGS
>         help
>           This option enables best-effort identification of bug type
>           (use-after-free or out-of-bounds) at the cost of increased
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index b0fc9a1eb7e3..d6f982b8a84e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,7 +153,7 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
> --
> 2.18.0
>

Other than that:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcSy6LqqhbYfiC8hn16%2BT640uw_rnUzNPg1zsvg_RwYzw%40mail.gmail.com.
