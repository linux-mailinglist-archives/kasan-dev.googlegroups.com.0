Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWLZSVAMGQEQA7Y6DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id AC5647EAB09
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 08:46:43 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-6d30af2399bsf5324632a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 23:46:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699948002; cv=pass;
        d=google.com; s=arc-20160816;
        b=BP7nTi5rdJT3XmBaHiCaj974miMx/T3dfWBBv1+syLY760jCezq20gtq8bNItvyn1F
         Uazzsj8fN3hdDJ/x5MHY13vaQGIBEUuMsThM+++UWqLKmDoUpgOKdbBhpbONkU5vHlWV
         U5htkBbdlkytQZA2nk33XS1844NV5XsMbQWvk0yg2nFC6YPQLANkhX162NYhbN04srLK
         6T6ytkVDuo5Ndr7NiDjAdmIKxuuJE+CGi/biz2emALdNq6wJ6bQggf/ekkimiEzglSlO
         dswb2DZJBk5i0yRLXWdZDv/WIAgLgMV9gVy+ZCt4gOyNKWlUnyGGHkep69ZUv6P8Gz56
         R3FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GPtD36E0xwoMYpcDzRASwYHBsd/4g4MKxNgIqikbHy0=;
        fh=7lms69YJbSIPw5FCAAcrqHFjiMw73kPZyaKLhvdNeuY=;
        b=OuU3TI+reX7kIGC1vdgFYo0ER15+OXaRlVABstT11lPPQ8kS/Y6t/SwkpWYFdjVf5J
         VooXx6A20xx1diAici3aKDaTboG6mn/byeKJOY/8ybyovEIO8FpzBagjjq6lbsV27hbX
         ZZandVOvErkgcGCWqx9Dck4s2MrweoiCY09dP4J3x36kxTP1nSkILqtTf72P5nzf7erY
         Ov1Vheb1fv5F27qY3ejSg7kFVCfV9kWmWSGkR8Dk4OopnqsERW8UiVgR+hfNc8iMImOa
         esMN5KK/QMtuW5DDhYTOn2pVPCOIp9ze+j9ZR8EmXoq35LYqqCAtOyDcQUOBXrZzSIuC
         ANCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XpiQXUWv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699948002; x=1700552802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GPtD36E0xwoMYpcDzRASwYHBsd/4g4MKxNgIqikbHy0=;
        b=u5w2Wa4zUAAqu0ITwcr+aTiJv2nwWa3yoK/JUZzwvK0ZYnq4RXs08mxu+1TJcs99T9
         yzNUt+FBhw+JmtWVLi5qcYFZEHLZb0/oEMB1vO4n+LQHge1nZnyp9bz9+48jHEPq2O2z
         Y+aPIp3kGVpPmBeXk222TIURMSqOphw7M9CCziBzsHtDDNSFLK/CZLEH+aebWkP/HUGh
         +OIqoqT6rBg1QaPnxDWMb6qsyNv0PFO7jnFlRm8UPLicXZSz2xT3qbPduZ9g2qHLNO92
         hGGYKxO/IbSo2bvi2hhzFVLyJ/Py+VpIa6+RqtIYY3lcuobfiSbsV/gM+duBRjS6Qspf
         nnKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699948002; x=1700552802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GPtD36E0xwoMYpcDzRASwYHBsd/4g4MKxNgIqikbHy0=;
        b=j77ihaBSfRmjAIp3y/GesVMuMAo7YJLoc2TbIdIt7sg1qpz29AYmD4GFYM/0QnM35W
         ansY82GKYkc6Bml9vBo6TSkFiKl/eAAu9NCTJsoHnPKaPsa+bKDyEJMqeUW2iJmNGfxG
         NDd3P+JAA6TIS0jnXuwimJQvolTIKuE5cWd2TBrypDEfW+yiXPY3bC35wFthsycLPMA+
         33yC34Ih4yHKchcDzPAkOXrOoajyCF952jh03CGX6Cg/wBz8Qd7IRTGAtYR/eXbzpQvt
         9u2nVNoXgog+MJUNxSxYssLacJHEfdpgeIGH5m6q3THYTDBwBxqbvnHWM3/ZIlfgRVQ5
         X7sQ==
X-Gm-Message-State: AOJu0Yyayy0ZAoVIvec2vDg8Fbt35EstkvpJ3TzrW8Dbz91M0R7aVKFQ
	10ZHXY1YeimP6kVc32/oim4=
X-Google-Smtp-Source: AGHT+IHwdD+HfNux8D16/ZTL0lfPcWD7jZ835tLN+irBsHD9iZwg407d3J6UsY3OGWrITcTmdW2+/A==
X-Received: by 2002:a9d:6543:0:b0:6b9:5734:135f with SMTP id q3-20020a9d6543000000b006b95734135fmr1444802otl.28.1699948002269;
        Mon, 13 Nov 2023 23:46:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:988f:0:b0:581:dbb0:a5a4 with SMTP id a15-20020a4a988f000000b00581dbb0a5a4ls895166ooj.0.-pod-prod-07-us;
 Mon, 13 Nov 2023 23:46:41 -0800 (PST)
X-Received: by 2002:a54:478b:0:b0:3b6:a8cb:1ecb with SMTP id o11-20020a54478b000000b003b6a8cb1ecbmr10211424oic.40.1699948001530;
        Mon, 13 Nov 2023 23:46:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699948001; cv=none;
        d=google.com; s=arc-20160816;
        b=pRYHxzJZDTcSzpNd4KksK2HJdH2cqxDNoottQ6OOrUuFNtQaJbyfN6qgUmxgHqhgOj
         gavWqbWwaC/y0JmJwc3d3fhMXsDi0ZXskexmFs26LGHI7q/w4T2PcK4WSt0HkvkLMSms
         3gnAvflWGDeSkpsxiwfmhJLRqhplo0UhZCQyLh2+VWGGtb+Ys9qTSGT43XA5skHZivuS
         mRO9vrXzi1c5jJiTwPKaczAEMe9WGgzB09KEiB2JH8MYSSnrYFR2Gksk8ZI/bfL58uqd
         f4xxqspzFiPawK1imUUhAhxJ9GbmFDDpx0HASEaAmcu7dfT9tpl4HWg1jhotEXUAPUJ1
         yklw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sX2ZDi+R3Ev6T5LlvMfvdN7qFs7PkFHPelflvttGDD4=;
        fh=7lms69YJbSIPw5FCAAcrqHFjiMw73kPZyaKLhvdNeuY=;
        b=J67KSr0UGO+SQsGOnOT1SHksr8aqUCcSOdGu+/q05xOtNdvnxHSCwNQFVXUD9ig21j
         mNcWmuV1+EVP6KwmXfEYGA70RI0v5HCJjT3vXn6uKEthfGRl8k/OecIY05Wp9sZx9Xm0
         LMEPofKrWzlaG66F30o6lkY2GhtNC6jN6CnBHIVDzcKiR2LvgrMFhAOuyMXeYRZLyBBy
         gckuWmGm+oq7/SaUaJh6WigR6MB5rUQrxuKEcQIKDG05BaiaRerc7x195fV1BX66oM7t
         +K/LgqowekZuvJswKRPFfXMWcDmqe0Bq7eedphVqq2GNC/c3RvyyDg4Iz9Jr5IcjoaQL
         GRoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XpiQXUWv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id m2-20020a0568080f0200b003ae5482a7e2si455549oiw.2.2023.11.13.23.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 23:46:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a1e0cc1a2514c-7ba8e3107c9so2118322241.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 23:46:41 -0800 (PST)
X-Received: by 2002:a05:6102:2908:b0:460:621c:d14b with SMTP id
 cz8-20020a056102290800b00460621cd14bmr9815342vsb.20.1699948000802; Mon, 13
 Nov 2023 23:46:40 -0800 (PST)
MIME-Version: 1.0
References: <20231113191340.17482-22-vbabka@suse.cz> <20231113191340.17482-25-vbabka@suse.cz>
In-Reply-To: <20231113191340.17482-25-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 08:46:04 +0100
Message-ID: <CANpmjNOrA_nfMsu1eaTqauVfc53p5xHxO7TZAueVXyi5Qf9wAg@mail.gmail.com>
Subject: Re: [PATCH 03/20] KFENCE: cleanup kfence_guarded_alloc() after
 CONFIG_SLAB removal
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XpiQXUWv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::929 as
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

On Mon, 13 Nov 2023 at 20:14, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> Some struct slab fields are initialized differently for SLAB and SLUB so
> we can simplify with SLUB being the only remaining allocator.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 4 ----
>  1 file changed, 4 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 3872528d0963..8350f5c06f2e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -463,11 +463,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         /* Set required slab fields. */
>         slab = virt_to_slab((void *)meta->addr);
>         slab->slab_cache = cache;
> -#if defined(CONFIG_SLUB)
>         slab->objects = 1;
> -#elif defined(CONFIG_SLAB)
> -       slab->s_mem = addr;
> -#endif
>
>         /* Memory initialization. */
>         set_canary(meta);
> --
> 2.42.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOrA_nfMsu1eaTqauVfc53p5xHxO7TZAueVXyi5Qf9wAg%40mail.gmail.com.
