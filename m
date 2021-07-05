Return-Path: <kasan-dev+bncBDW2JDUY5AORBQOXRODQMGQE6PK72ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FB9B3BBC1E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:23:45 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id p4-20020a5d63840000b0290126f2836a61sf6107904wru.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:23:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625484225; cv=pass;
        d=google.com; s=arc-20160816;
        b=bu+7dtarOI8S8FeGvW92KPLWcDzKhEPVlkKxXYDRZSlnCt5t7DOcAzx+DxsrvjFSWt
         FAS41KwnFb0U+Rw0/EPoPEkqcT4qMEVZqb2Vp+hX7PJQ0jeXtoii2au6f350kg3z9hfZ
         UQuGkNzKunapugp1XxTRm9e6xoEjry00yzrGJdChLNQ/suSb5lpdsTB4/7fSBFwYtkFv
         5nQf/iuHH7boe+8lN6Lwp1bLLTV4kZh6+B7EdxMnzRsSrdZ89TqZ/6pz0cT1KR982R7B
         m8frm5/PncjrgbDMyKtR5ceA9vK24nxkqKu0u++1mluXEfAnRAXgMj0h2F2xHuqCOOee
         tUlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LfbY7MBOvVutDQWaDDAuBZeBqcJ6XnPWNgSRIShE330=;
        b=aKRF+EX7ZpoZXqzEPtc0Ztm2B3144jjWjtUY8Buzrri8K8JTvogPd2Fym+yph5UzPf
         EiROELkomWSC0boM/dWfmh/PDX7vtzY/ZslfBNRsGF0/DYaVf/IAFJDi1BE7FQiKFzLw
         gMnWNQVKY6pQlON6e+94QpXvN3pVak8Xk8K2W4yCtQK5NnqvHQcQyVhducLvm5e8CAh9
         skCWbcZ4tOk9U1O5iTTKmRJoI0FkqEYDS4yI/06PWlH8bDKwd8sIAVCB1ujtwKOcveng
         FRROr141jK2pTdzE10ntcoC2eAYhMAo13UHftIoYC1Ppz+OM9IbzzclGWXn/K3/I4ykH
         EoSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YM1PR4H9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LfbY7MBOvVutDQWaDDAuBZeBqcJ6XnPWNgSRIShE330=;
        b=GSgt4UPmK4AIbNAW+Z6NzbruoRIF7YieJriq2M/yvAg04OiFRyV57MciO2yLCsc1zr
         EWEVtfZ4qta0fB0oBIW5zAlUr7qpdY+dUz82DG/KeOAIJ4Rwj7oet1aHl38YKEmWlr+t
         ETHXpvpAImS08e+7UUx9oxFoY2oBITW91RcdRwSFYzdLQUiuqJCou3M3nJCtb9GRyLtB
         Dw2xZFrmXNr6OAA+KDGqT137wOM0b5tIjDPP9OoGvpCKzOc3pCwKuw+VcXmatb8U/84T
         1xO4HqRCNo3SZULov4wCGQsCuHzUB+HnV+F/gRHEh/78uYGLu1THembgN/fOtJJREaQ6
         qhNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LfbY7MBOvVutDQWaDDAuBZeBqcJ6XnPWNgSRIShE330=;
        b=AjxC9zNlhS+CGfbLkfpEzJ3aQfxESNhtZJvAWUfwuMMpNFjomrUEFUbBGzgQosMOPx
         fYGZGs9BPdjczr2NeawVnKQApKBUAwazEG1sjOEq7JwfyDj6d6UWEz08An212JFvnJyW
         cyN4hcLrfjfc6eKmg+XkisMW/x8IHtrtuF8It5Y6iynsMjnhWKtGFyhE0Amt1dXrnugP
         4aPfR3nqGKoJ4BJAd8DtOU1rHmm6oO1fgUT8OTZiYSIYW0FRgQS3y5LgqeZp8HQKrP/g
         0+uIlTGfkT+F60bh3AiTX+N0eoq0xECkKg/9KmnGzBth7ZcbNurKE9t0PQ4I0Ys/nFlI
         bjdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LfbY7MBOvVutDQWaDDAuBZeBqcJ6XnPWNgSRIShE330=;
        b=E9xIu1KEXEvxQmuy3MJtBzjeSPWwdGhbjIZTyOaXI3XDUo58hCRQwglqQV4Mtc8aWM
         NX42NxN0SCA8M2DnatTolVW9Z3pZJg/26bMfms5mg+vkGV1W3irPoWJ1kgL1ainaLGxa
         lsacWMZ/iA7KtnHlOGM3SWLF7o2PGFW2lJ8NdJiD440UxBamp8HWj3s2KHC8i31Dmsti
         0XxnlzdIFCUpPRCBx247Rx5g4Da0he544h2uhTVo9ym+/yzQ8ySTohoqLLPYbd7gRwEL
         jbgBhuYrktb04fsArpli/AWztJwC4NJcuXq+cyseAbvqY0yrVXRVRIqntuEenPnTSUB8
         +fvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FgAw4G0tNdgxlTeFq8eJY4ZbH6iNSJCImdbLh4N6p740N4b3n
	Bt7niI89lx+KJMFewol8Zpc=
X-Google-Smtp-Source: ABdhPJwsx3sHws8T5MqQOg/59IYdDLikuEPTP8tX5H8byIeWJhYMAyDkwiarqwyU2Vfyg/D1Yru6VQ==
X-Received: by 2002:adf:edc4:: with SMTP id v4mr15178128wro.54.1625484225330;
        Mon, 05 Jul 2021 04:23:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9d:: with SMTP id k29ls2234032wms.0.gmail; Mon,
 05 Jul 2021 04:23:44 -0700 (PDT)
X-Received: by 2002:a1c:a482:: with SMTP id n124mr14797188wme.31.1625484224569;
        Mon, 05 Jul 2021 04:23:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625484224; cv=none;
        d=google.com; s=arc-20160816;
        b=nsYYduma+Ng45iJ/4Beg2Cg1yIrop7vpZRE1ogGuzWFZo1oK+s738ydNIKkk5tbrCT
         CvUFgnzaSrE92EuGHi3pWEWWiVTnN1LrcurgTxkwz0gSHBgAL88PhRepfumXTidKqKOh
         HbDZqhqM0KqfDaekO/4km4uJVeEos7vbn7uoCrVNOAA53tlmO9UZDpkCqJxtqihwEVnA
         /r+jIR2HV6hiDDhtkjNe8Xre6/5iHLY6pSsIQWPuKZbcQ9VCXTN6XmZJ9yhQeAtvhFTw
         PmavBBMyiFAcB/QTlPvwpIX7Sny5h4YezKjw5CeNSEhqfR2RneMJaZtTuDvTlIBG/8vr
         PgWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x/twNUpcgioeZ8e0ihy4OvgQsOjAP9TO2paDyac3Qkg=;
        b=VqznmgM1Amr0qoYY99rd24br29HW+auaNyElQjq8zIG87rAL+5Lgn8xa8mlUx/Xsth
         RyyrW4rSRhNRzZUCdF3y6/XVJMuAhomdWgaCBRJEgQIT9YA28ntyxpWqUnsgBtKwHLne
         E1Y7KTejnu7fdXiyn9MQr/5R53V2OCFlpNHFo4eoUdqxgLlBDu5h0rYzgGrJrjHwGatn
         EejxGIjifETnuLztqsJq0mckrBdbwwU16XJPT69HPlv21RxRg4qBcYzNR1YrXVjMxEPf
         +2zkiuex5SDaC3atPMBzol7PRrlZAyJtOErpzvhxYvBqthcqogbzLMNI30ewohhLt0Av
         NYXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YM1PR4H9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id k18si1330047wmj.0.2021.07.05.04.23.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:23:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id h2so23309883edt.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 04:23:44 -0700 (PDT)
X-Received: by 2002:a50:fb96:: with SMTP id e22mr8621005edq.95.1625484224390;
 Mon, 05 Jul 2021 04:23:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210705103229.8505-1-yee.lee@mediatek.com> <20210705103229.8505-3-yee.lee@mediatek.com>
In-Reply-To: <20210705103229.8505-3-yee.lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Jul 2021 13:23:33 +0200
Message-ID: <CA+fCnZfr3vU3ZwGQk06JFRURDgP7qHF6RaUpJtu5V+w6ToAb8w@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
To: yee.lee@mediatek.com
Cc: LKML <linux-kernel@vger.kernel.org>, nicholas.Tang@mediatek.com, 
	Kuan-Ying Lee <Kuan-Ying.lee@mediatek.com>, chinwen.chang@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=YM1PR4H9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d
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

On Mon, Jul 5, 2021 at 12:33 PM <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
>
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
>
> The penalty is acceptable since they are only enabled in debug mode,
> not production builds. A block of comment is added for explanation.
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Suggested-by: Marco Elver <elver@google.com>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 98e3059bfea4..d739cdd1621a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -9,6 +9,7 @@
>  #ifdef CONFIG_KASAN_HW_TAGS
>
>  #include <linux/static_key.h>
> +#include "../slab.h"
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  extern bool kasan_flag_async __ro_after_init;
> @@ -387,6 +388,17 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +       /*
> +        * Explicitly initialize the memory with the precise object size to
> +        * avoid overwriting the SLAB redzone. This disables initialization in
> +        * the arch code and may thus lead to performance penalty. The penalty
> +        * is accepted since SLAB redzones aren't enabled in production builds.
> +        */
> +       if (__slub_debug_enabled() &&
> +           init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memzero_explicit((void *)addr, size);
> +       }
>         size = round_up(size, KASAN_GRANULE_SIZE);
>
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> --
> 2.18.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfr3vU3ZwGQk06JFRURDgP7qHF6RaUpJtu5V%2Bw6ToAb8w%40mail.gmail.com.
