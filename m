Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIHZU2AAMGQEPA5RREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B4562FF229
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:40:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id u67sf1452525wmg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:40:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250848; cv=pass;
        d=google.com; s=arc-20160816;
        b=mIoIDn3y5yawP+dYUA7qmH717PnSh2oniKudz8AC/De15Byb51z+S3oWsSa4x1M+Pl
         7bZhjwlokURva710iecDxf8iZ2xUbpJXcenYDC+sEXv+EAFxiykyLEzWyRqfY+22ydFQ
         lS2FeCK0Ipm/WpTfQXpscUoeDuXdITjsRStpFtGoXk+cyThpr7KV5jg2YnCbJXSnbtqo
         zlUB1xoz0p2mQDWeuIk0lbv/U9UkhyDzpydvBhFEAcABt2JkhHQggM3mR1xkcNNCIS1S
         ovD3yK85m5cVdljIIcSex3C0hn8K7gRch54gFLqbhJo3HY5TPEjQFKFesW9VMx8UUdzV
         nEtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fQff1a4VpmlmDg8NNCA94nHaVw0lH+04WM+3iWtnu+c=;
        b=HbStV04suhcc+0X6n8j0J8OvOBmMaFz5CAwRhjk6DaKTo5FvpeKEUYvUSsXl4W3evI
         lCbar4dkrD+tnUoEq6n821nQ3D1RUTF0R5oWvbEUEirV9jQdLiiwlzNVp3b4qoU1VPRu
         ZkZ5hYZT/cIjma/yFlHrcjOPCpdc1TDytGJt9Wzhy3cnAEcfSW+bGM04vQnz/BPc+fW7
         jqukPPQpsV2zGGum4UMwdIllWAOeuQFUCNB08PDN21Wr2p95iPNJTQ6j6rOjYorDS4ld
         Do10g/KtZET09/HmbEI0NGV1wShEz5Q0q7uOuIl6Sck25Nx6MYK1ZJrYWMjG8ULn2HnC
         JnhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XV2i4SeR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQff1a4VpmlmDg8NNCA94nHaVw0lH+04WM+3iWtnu+c=;
        b=ZEgR/ukilqbNUW2d+QnVpK/5zT5Ci2drvp9/OD+myZLrjMiYKymfPgxCmgmBEe5vLU
         wRV7bNTuEteUVwmRjvLcPjM2Dt/d36jGNqQQnNl5+VvKMe9TbCi3xMhx3aeZi7InqpRY
         G84uT65eRWkVL8ajqeLBkyR8ayxABXtPCmmrcw1pZsIVm4hUE/cc4Fp2fU/j8COrLsB+
         2woATjN3coJswS8sEw/gEwdYIF+JlxQbEJ9sEvb9b70XRQ7K5WelWDIKGnZI/YL601Zg
         SF94b1s0u6yPaxY0McqSGdrsU3Mg1gmbNoVgd8RIutwaAYVsaheNKiC01Sfx5y0wAwZB
         MMOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQff1a4VpmlmDg8NNCA94nHaVw0lH+04WM+3iWtnu+c=;
        b=VP4HllO6+gIkfvx3OPYD5fDmnI9BeO903R/k/c+uSnO33sXulNpz+Dv3FrfT+Dzx8t
         Mhm8B1VSgGM3uSIatrB3nuYfyy+ytTZq1Z+IhOqabIFpb5BtKzRiLtOxGAteX4riHWyx
         w+C2SeiRmoiE4hxxXaxNzGBBODodNH5uWq6dsz5WnhiZnhqQT3rjtiUmwIdCR7c9HUSr
         7uibe/TrRE21iB/Lu1ZvXDUoosaFcNlZkaRfPgsgrhCt69+ytav+aJj5s8yd3vyCFb31
         BrkH1Has3F7NBKuFXjzYHKCaqGf7M9Bk8tZQa94zxw1ARgpqen+Rc6UFq6bQvGTinw0d
         Rv2A==
X-Gm-Message-State: AOAM531pntOw+Ik9IScLaaJ8XY1AZ+1yhSQpalfTY+2YJaACKvceMX/i
	rt095u0+GvPp8mSrcg/Ji+o=
X-Google-Smtp-Source: ABdhPJw1vc3eH26XZXjwumkn8BXsTEhLdKmYGBJzr30yKwbzGNKijG6z8oepVGto3NGSn60B1nb3Iw==
X-Received: by 2002:adf:bc92:: with SMTP id g18mr575003wrh.160.1611250848425;
        Thu, 21 Jan 2021 09:40:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ed1:: with SMTP id g17ls1748868wmq.1.gmail; Thu,
 21 Jan 2021 09:40:47 -0800 (PST)
X-Received: by 2002:a1c:1dc2:: with SMTP id d185mr394848wmd.175.1611250847562;
        Thu, 21 Jan 2021 09:40:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250847; cv=none;
        d=google.com; s=arc-20160816;
        b=ulB/kgLlZmZsrP1F6AJ13XCs/kdKvwZbX7gj9iZd3dhb2xxDREVcjDxgFr7+yi7nZ4
         5UeIOpDxYNJYKRfASJvq/lCPLo0f3YXxUu8eU2CM9wMsrtmO+ePvhwDvSqc5JZCtKln3
         VKC5sKOIWc/hskWn8x2+7TlatAoFZM4NRK63GEebrZJCnMF8+Lam/k8EL0I2Ti4fPNPm
         z6rMURwlhC1tzU08NvkBUTGhr0eUjHqux4GHcY4I7gJEyDQLOf5xc8rrMg81vVo7brs1
         a5KZwCagGTzoDSz+os1UByupS8RdEcQ458wk0JpnSHuNNhOMrpjbkxxC8yoiIfWVAFqf
         il6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A2Cpd67Ssmhz6ffj791RBLGTQxJBD+P69v5Ph0KgTDM=;
        b=SI6kkNvdWga8Prg80zZTOiq4CrRaL9+pBZknQ/on9XQvqpmRGTCu+pUWsoTCLyNP7V
         oExUdudHtm9uWyUjuQKDWJ4XecbHAvF4xkEtgDx4T3lrq5QCmcOFVUB/Ci/x98liWqWA
         FxTZZhxMrU6/3pT6MTGQwWo6tiHcjyLFGsf1QpEsvECO1vPLyYu6hoVSqv1ylGNNI/e2
         cXuz3fu9xNeNZc0LVet7S+ennC/6wvgMYByUBCM6L5pu/ksaDBDUflhBZO8jXLy8U9Zp
         /NjF47T+cmF82VzAqZyddgjaf3P8OSeMmMNmTXYkTsSuSZ7mLbSBDzBwVQqqnBLdGwFf
         7Fug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XV2i4SeR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id w11si290553wrv.0.2021.01.21.09.40.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:40:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id x23so3447471lji.7
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:40:47 -0800 (PST)
X-Received: by 2002:a2e:984a:: with SMTP id e10mr217001ljj.179.1611250846925;
 Thu, 21 Jan 2021 09:40:46 -0800 (PST)
MIME-Version: 1.0
References: <20210121163943.9889-1-vincenzo.frascino@arm.com> <20210121163943.9889-7-vincenzo.frascino@arm.com>
In-Reply-To: <20210121163943.9889-7-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:40:35 +0100
Message-ID: <CAAeHK+yaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q@mail.gmail.com>
Subject: Re: [PATCH v5 6/6] kasan: Forbid kunit tests when async mode is enabled
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XV2i4SeR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Jan 21, 2021 at 5:40 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN_HW_TAGS can provide a sync or async
> mode of execution. KASAN KUNIT tests can be executed only when sync
> mode is enabled.
>
> Forbid the execution of the KASAN KUNIT tests when async mode is
> enabled.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  lib/test_kasan.c | 5 +++++
>  mm/kasan/kasan.h | 2 ++
>  2 files changed, 7 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7285dcf9fcc1..1306f707b4fe 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -52,6 +52,11 @@ static int kasan_test_init(struct kunit *test)
>                 return -1;
>         }
>
> +       if (!hw_is_mode_sync()) {
> +               kunit_err(test, "can't run KASAN tests in async mode");
> +               return -1;
> +       }

I'd rather implement this check at the KASAN level, than in arm64
code. Just the way kasan_stack_collection_enabled() is implemented.

Feel free to drop this change and the previous patch, I'll implement
this myself later.

> +
>         multishot = kasan_save_enable_multi_shot();
>         hw_set_tagging_report_once(false);
>         return 0;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3923d9744105..3464113042ab 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -296,6 +296,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()               arch_enable_tagging_sync()
>  #define hw_enable_tagging_async()              arch_enable_tagging_async()
> +#define hw_is_mode_sync()                      arch_is_mode_sync()
>  #define hw_init_tags(max_tag)                  arch_init_tags(max_tag)
>  #define hw_set_tagging_report_once(state)      arch_set_tagging_report_once(state)
>  #define hw_get_random_tag()                    arch_get_random_tag()
> @@ -306,6 +307,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()
>  #define hw_enable_tagging_async()
> +#define hw_is_mode_sync()
>  #define hw_set_tagging_report_once(state)
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q%40mail.gmail.com.
