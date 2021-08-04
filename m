Return-Path: <kasan-dev+bncBDW2JDUY5AORBMUXVKEAMGQESDBOVSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B13973E015E
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 14:44:34 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id f6-20020a05600c1546b029025af999e04dsf287133wmg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 05:44:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628081074; cv=pass;
        d=google.com; s=arc-20160816;
        b=tWM0REMWTASylGD6NHIdJOKjQp/ieS7SrjDy1UnayGbl+a+yGAXium5buLLOsdV6XV
         HRukTVSZjkENsA62mOKTIHFaBd5t+wGkwmadsGj4Ex8RGCVXRmLLZWNuRzaTgsMmuSg8
         sNVqYD1gyxsyd22jNaN1bP6KajgwhLmhkmlvIAn/nJjaR/AoVXRc7XGqXerLGsM3yp3v
         agk5pdrNwABytsjTnTUEzPvQA+wWehLwrhEfuJ1Ze4gkqpjVcoGMes5SU/OOEXyrUgwH
         vN81rGBhRN7Le7fmyuZBT4Emnr9KjlaC2VYi83YchVbyoJ3kQzjTRGoMJbhdz1P4Of/r
         Ul0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=6ov16K1xT7ZE9H+7FMmNTUJsIvRd0AvRWMxLQuv0bXs=;
        b=Z2ODz5vNYxo1ubYPdsrcdFhOjOr3hsUCF4UEtdr6Lr+EvRry1INdp/OE7Hq1CZ+1Hi
         4G3l47L9+7Yia8s4EyuqnnkuSgU8G6AOmw6IAQ3zR+uPb4Nv2Wg43tH1ldRwcoS6cVis
         rAWkFj67I6n2Whs3U47mfLkvV+SMsaqXbtJgI0v6OekR3GXjC4kIfjvhEJ3RP8KuhEci
         JMoayqq6M3OaaUqbI3/wwcterrdnjW3bwku7Y0K6X2jMY48UFbl9TATI08K3JM+ETkJr
         NQAJXJAOQXaQqouuuAcfn6S76eo9+Q7TnDquBSBYiJljE/V7gaQtxqWEZ5jIA/6KycrU
         ePQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L8CPcLBL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ov16K1xT7ZE9H+7FMmNTUJsIvRd0AvRWMxLQuv0bXs=;
        b=gQp64fl/EKGqVYajWAufSdVObfFmwU7DM8pibfzb6hQ8FT8pazE5m0OVGTp3cOJOle
         3+a6eaZsAmSVFYG8TOOPb6Pd4zp0BRSB3xEBTZXzCwnRcBg64AqWGYy3rSL0aFgEvbkG
         j3LwEMyqzqfqJnXN3H+1Sw/xGsHKqsWIHEJa374TQHVmxK41Vd59PPOdkiF2lSbFNEJ/
         5/L3ykbkR1tg/FsjvLyOJdeVEsgIAlx/H071nNYzqHrZM/BVSRiU8Mu4GDHig6gcwHu2
         iHAr2a8aCZTqREy8SnNYRFz8IuGDlIYra9C2HpKeWsMHQBn4MpGLKoqwtkdNGLoILXIm
         YLew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ov16K1xT7ZE9H+7FMmNTUJsIvRd0AvRWMxLQuv0bXs=;
        b=VrJ9OYe6uGCoT0sFqBw3cQTQW4K0UgyxABdGZaSg2LpVCudkIngsJ/A9nZHovm7FZj
         kQfKOzfSHceI9BWLclrxUJDHVpei+iurP0kyOik9rDinnZRGuGA/iMDlYBkHrH+mie+U
         +DbiVyKnAuBBCRT7ICEnVXxXt9UX+20yn3BZjJ6gKA9OVnjtc8CPCSBtt3vtaDCDB6bp
         G79KNpdmidf4yXfBA8hzVlPk2MuR0D1wiSFPVWrjZABTxtyHtsvyFNjPUrbkgWLYLJpt
         j8vOOsNRZGYqjtyUys904NzU49UBP100fkcCtL80hAV/8XPLBDCziggNoRxgr4bY4dVb
         o0fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ov16K1xT7ZE9H+7FMmNTUJsIvRd0AvRWMxLQuv0bXs=;
        b=ZtsLV3vrMjBt2Shmivp/WPoP37itEPX75/3GVDWF3vRyRMBirpmGjyUr8tFaqYYm0e
         mzTQ1PGDZB0xIL+khfzLQfKFYXLYnx4j40+8VGgPfK89v7HMbqXvQ9rSsdQEdBEt73uj
         9anQQqPiZ12s5foAyhKZc+XGwrtfSVsnpX+O/oPnw5GPE/j+Xu0X/67mmIbw1fZU77OE
         PA8lzP7B56HNmz7RD6gYGkMqtFqYdrLJz4TixnLWfc4+LruKtLY9e7faf+LB1vfRiWJg
         28zsI80pO9/dygWmPovq8yZ758IiYjK1ZJGOkXt1KlknzD9zNcQUUEdsh5MH3mXLsiFb
         VkoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qLP6orUggIAHgjRR/kORCj0s4rgZz1KryBQ9sdzGOM66hQKl3
	iNDOrhc4g95v6j5h/E0he3o=
X-Google-Smtp-Source: ABdhPJwWTgQGHHu+jBY97bAmmTzR6NlgA4KdyIvI400DhB2ckRsrRd3gVxvbpZl626luHOCwvK+0Cw==
X-Received: by 2002:a05:600c:3b08:: with SMTP id m8mr9623971wms.84.1628081074505;
        Wed, 04 Aug 2021 05:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a2cf:: with SMTP id t15ls216808wra.0.gmail; Wed, 04 Aug
 2021 05:44:33 -0700 (PDT)
X-Received: by 2002:adf:80e8:: with SMTP id 95mr28726362wrl.388.1628081073647;
        Wed, 04 Aug 2021 05:44:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628081073; cv=none;
        d=google.com; s=arc-20160816;
        b=W0IMPi2dWPd6DS2JnEnG5F3tse6kK9hBbEQpXo6RVF0zPqB72BTJ1hHsGjMNYA0XHP
         EnOEdWFzGfPVzRtesLgGnYG/wuTr7Qw5RuVFwPO1GzzS08cqG/mAZ6aOsDZehlaY7Bor
         OE/NUz2VfgbQG2nD9diL6S4D+xBJUIibQ5my/zhWxXs5O/Th+EdhC+waTpfheBmvLr/+
         rmvEku55m7KFgaDQ5lLfZbLi3Vh8e4OL57DDP9HLbYk+kNeKrDfWEq+9N0EUQVSxq8uy
         cG3m6qvQcakyaP9BvSxYZwc8YhowNBXVVl3gTVC8lV+08ylEZqjT2EDzTNHPshGpYBbH
         yCAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zWvy8sh/+lRbS7C72TP9P5YTqZkTi8RR/qpbQTwlVag=;
        b=B89j6Agr1N+Yb+/PB5NGlhf4GeQU9ev+4+GWyTMHvfR+NzowV0buNxMPC+49UU9x9f
         UoNvIv7qt60wtVK7GnQyt7TP7g2E1S5dwUOFVxzCskannx6UcoxU8p5Ij4Ak+zk1hawD
         L/GGtTcBcuwviB5hfU5fx9NYeEvGXuBRvm/gVjTVyTEsMxhNGrnHEVNqUbqocJhTJC+q
         9bVuctNRn+vk4VZ8d8dvKAjRaDMmjYqGHTkevr2RCxU2feUE42VZTPw7pyprfnV8jjkv
         HNd0KLLeVTgGt/nKpa1LwoQnQKoktWF5B8WYbRTx3g+Nv05IyZk5VZKFZdf3RzyhNY3O
         mkZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L8CPcLBL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id c26si312306wml.0.2021.08.04.05.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Aug 2021 05:44:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id d6so3313750edt.7
        for <kasan-dev@googlegroups.com>; Wed, 04 Aug 2021 05:44:33 -0700 (PDT)
X-Received: by 2002:a05:6402:430b:: with SMTP id m11mr32140537edc.55.1628081073404;
 Wed, 04 Aug 2021 05:44:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com> <20210804090957.12393-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210804090957.12393-3-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 4 Aug 2021 14:44:22 +0200
Message-ID: <CA+fCnZd6d9yFZZBM-zPOC54ZiHGnCxV-XiYrCfbCTzzhRV8H1w@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kasan, slub: reset tag when printing address
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=L8CPcLBL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c
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

On Wed, Aug 4, 2021 at 11:10 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> The address still includes the tags when it is printed.
> With hardware tag-based kasan enabled, we will get a
> false positive KASAN issue when we access metadata.
>
> Reset the tag before we access the metadata.
>
> Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
>  mm/slub.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index b6c5205252eb..f77d8cd79ef7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
>                           unsigned int length)
>  {
>         metadata_access_enable();
> -       print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> -                       16, 1, addr, length, 1);
> +       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
> +                       16, 1, kasan_reset_tag((void *)addr), length, 1);
>         metadata_access_disable();
>  }
>
> --
> 2.18.0

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd6d9yFZZBM-zPOC54ZiHGnCxV-XiYrCfbCTzzhRV8H1w%40mail.gmail.com.
