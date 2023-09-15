Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFYSCUAMGQEZGP7MZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D15C7A19BE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 10:56:30 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40474c03742sf9677085e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 01:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694768189; cv=pass;
        d=google.com; s=arc-20160816;
        b=CocVxcWBbRKNRgALTlLy4L58FZEQGVOSjzRYJ4ovQxvS/gF/u1g066vu/Nz9OqoXyg
         yGfcpkyR5ZyxbRs9nQPBXcu+UDaaC+q2vtWCxNLBWY8S1ENjpDxaKSbnhJRVwDwfVdF0
         thqSn5X+2kW8WnJdOJWUmU4Udc4pizGA2iKS8QNkbxRF6gHMnN8/zrIZYEQuVlhsXJAA
         6lqgutzQ7+yjC1Hu6FMeSe8zVKtZ2gwua9+r7heliKFa6uWEZA5Q1SY40TZJKweyrL8s
         JDXWB4C++Q016cPMKBXVPh7HfSgbuNpL97Nho6fOZYqiNs8/Pgb6PN1rCf7929y+NHIy
         T/8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XI08BGk5/vegNefs4i98/zrnb7NN59Jn19MDGoFj2wg=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=JKTqI803WP4z9WmF+9efESs6jaKxCtTOdgzhAp1FEOWu/bQ8LJTCbWtEr1aUczejlZ
         raN3TTE76Det7TzfxyVeRauYU/qZ7nUIYuKua9RPFKys2s2kisd3kEn2MX90vWSZwaNS
         0fs2LxrKgu4Po8M2bM6YtUcMqbSn6OZydy+2x+/ujYKH+WlM89dpF6+4gODO0qoTvnzQ
         VSSIdWA/fulEYZX19TUu9kx9SNzfyt4Wr8iNUdKwpO80gqDeCRLPczs8VW0DKMv1X8fI
         ZGB30+tEFy3KmAVwEUjT2LIEE7VIHqsbZgtGQQ7VPGhXhggMSz2ZKvJIdrTKxkZLmSqa
         ujvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zaWzTVKU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694768189; x=1695372989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XI08BGk5/vegNefs4i98/zrnb7NN59Jn19MDGoFj2wg=;
        b=G12mk8m2z9cLDPgBeBwi6gOJEzR1ADw3ES4xNzhvnRC+yqavskkYdKXSxICGuIKes7
         +tvRl4yqifUEvf1QlpMMgHrB9i3Gy+HyoFmfkwryay7+eH06XRLialCqr2zIzIHE+ffH
         kbiuWkrIrpYYf+S/Jy9/1Mp/+iIk/IIQ1gH+ohqgCAS/D7wMhh5pP6RRo5jsBZJzOpj+
         emKZU9/xRe9TMoqx4WUZS1Rp691hJ4QdLT0jFtBSrbUAhDcAiPHvgzoVmBxAuvyDC9a/
         g7MGSyIo+yWtxxyn7N2XBr62aNjbSR5+08iUoYyN9Epx2GupDGTEyzVwplolbMEFD32l
         Hbtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694768189; x=1695372989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XI08BGk5/vegNefs4i98/zrnb7NN59Jn19MDGoFj2wg=;
        b=tLMIypsF0dLFsHGJi/HZ5XlHn+PoNuO7Uonj/zJFGpU6kfHZIOAbLVI/87SjKOHlQW
         yfcWa5nAIj0Ubdh4rLKYEL+5EosO7sd3X78AqvJMYpIZ9UhTG0vsjfGfYYo4SKcZho37
         H1fY58kpAI/bWpjQj11Ej1bGooQLGmBHiBZqEnyQLK8L2TNLQDJY7HaT503CUJXZdUdL
         mYhJgPb6F2GkQyhkR/1HE6nMkwao2eXOnN9hUAsj7cFNMawb8q0f4L4GoDMxeanVa5Ea
         7jtgcxh08ZDyp7zeRqPIMOivl6AvR0iPWhPLcsw8BFMFoOD8H/ZfMF+JuHoQQ+iOg6LN
         qLvA==
X-Gm-Message-State: AOJu0Ywq7ttHGJU+rCeF01uVW2H8OYWETtf6X6Z7mlkXAkCf2DRcEbUC
	Mn86+lvU2NTHMNp0BOSHljY=
X-Google-Smtp-Source: AGHT+IEr1Ll8i9jTBlbj22ACQea9BBLRfVjkguW90BhOHBZOspHwduSObQoRHUZiM072IktyDt1eBQ==
X-Received: by 2002:a05:600c:2152:b0:402:cf9f:c02d with SMTP id v18-20020a05600c215200b00402cf9fc02dmr1057885wml.8.1694768188838;
        Fri, 15 Sep 2023 01:56:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3514:b0:400:87b3:94b9 with SMTP id
 h20-20020a05600c351400b0040087b394b9ls948924wmq.2.-pod-prod-04-eu; Fri, 15
 Sep 2023 01:56:27 -0700 (PDT)
X-Received: by 2002:a1c:7709:0:b0:3fe:e842:60a0 with SMTP id t9-20020a1c7709000000b003fee84260a0mr1121573wmi.31.1694768186777;
        Fri, 15 Sep 2023 01:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694768186; cv=none;
        d=google.com; s=arc-20160816;
        b=a2aCqIGWtBUIzQRiiJJ2mkMbWfW8TKP/BLDa5vzd0h7tDncvGYuYrAo6CXUyrIhk02
         QpUhPVWxwLyutLhWJHfGBqQfpLX6jYvQXYqKrdAPQ1PH4RsaVRVZ+OBhnTr9u/ZTp0Td
         Kp5ZilYosbMfxUa0rMTgsnEhqdPqZLOAknnChsXWhfRt+y8GwZoa9m5tGtH95w8aiGNP
         5RTDjp3MeOmce4nmcrYZsliMbt5+eA6JxxzTjfL2WUeLslQ5tHmZh6+jxY2EzD1Ag3QP
         MjXCOQv4SP055Br0Jx8cqM0iO1v4oDHFJW2q9jM8DCkrIp93jGopzh2N3YTC63Em5pM7
         xfZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BYq8Jh7JCWPHoRmWNIAaNE/xDHzvR7ZVrfUseotBNcQ=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=VfTczy51V/gra3M59D3i4eIyQget7RfpBrmzhABby72VQi9yh0uwhLZQXc/MNZ22mS
         IdNGVKHaUDMApyimkr2TI9o5vvZu/9cvaaYfjrnK2v21PFnLngYkptzmG5fb2U+5N6Dd
         vmcbECoGpGiS8mQJS0KpMcbMEGR/6amGPUT0LLOt5jfXP/LKchu6S5MwUhSecftCNxr6
         3zHW9WwZQAPHZHpp5xsEL09Vi4A49yk0lKksH3ViNzxPhzbinIrN1ZIdYEtVa95k/3sB
         uAhcZvHZOr9Mc141LuiTMSaYvZewM9HKKV+12HbbARSJ4b2huZQvPtdGt5acUvEOCwRS
         D1Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zaWzTVKU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id e13-20020a05600c4e4d00b003fe241a5aabsi469744wmq.2.2023.09.15.01.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 01:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-404773f2501so10754515e9.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 01:56:26 -0700 (PDT)
X-Received: by 2002:a1c:6a0e:0:b0:402:f536:41c5 with SMTP id
 f14-20020a1c6a0e000000b00402f53641c5mr1263710wmc.3.1694768186136; Fri, 15 Sep
 2023 01:56:26 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <658f5f34d4f94721844ad8ba41452d54b4f8ace5.1694625260.git.andreyknvl@google.com>
In-Reply-To: <658f5f34d4f94721844ad8ba41452d54b4f8ace5.1694625260.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Sep 2023 10:55:47 +0200
Message-ID: <CANpmjNP8O-GLQ9m06riX+kjbPSD9sBo+XGtTE2xW=pq9uJFGAg@mail.gmail.com>
Subject: Re: [PATCH v2 05/19] lib/stackdepot: use fixed-sized slots for stack records
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zaWzTVKU;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Wed, 13 Sept 2023 at 19:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Instead of storing stack records in stack depot pools one right after
> another, use fixed-sized slots.
>
> Add a new Kconfig option STACKDEPOT_MAX_FRAMES that allows to select
> the size of the slot in frames. Use 64 as the default value, which is
> the maximum stack trace size both KASAN and KMSAN use right now.
>
> Also add descriptions for other stack depot Kconfig options.
>
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v1->v2:
> - Add and use STACKDEPOT_MAX_FRAMES Kconfig option.
> ---
>  lib/Kconfig      | 10 ++++++++--
>  lib/stackdepot.c | 13 +++++++++----
>  2 files changed, 17 insertions(+), 6 deletions(-)
>
> diff --git a/lib/Kconfig b/lib/Kconfig
> index c686f4adc124..7c32f424a6f3 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -708,13 +708,19 @@ config ARCH_STACKWALK
>         bool
>
>  config STACKDEPOT
> -       bool
> +       bool "Stack depot: stack trace storage that avoids duplication"
>         select STACKTRACE
>
>  config STACKDEPOT_ALWAYS_INIT
> -       bool
> +       bool "Always initialize stack depot during early boot"
>         select STACKDEPOT

This makes both STACKDEPOT and STACKDEPOT_ALWAYS_INIT configurable by
users: https://www.kernel.org/doc/html/next/kbuild/kconfig-language.html#menu-attributes

Usually the way to add documentation for non-user-configurable options
is to add text in the "help" section of the config.

I think the change here is not what was intended.

> +config STACKDEPOT_MAX_FRAMES
> +       int "Maximum number of frames in trace saved in stack depot"
> +       range 1 256
> +       default 64
> +       depends on STACKDEPOT
> +
>  config REF_TRACKER
>         bool
>         depends on STACKTRACE_SUPPORT
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 9a004f15f59d..128ece21afe9 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -58,9 +58,12 @@ struct stack_record {
>         u32 hash;                       /* Hash in the hash table */
>         u32 size;                       /* Number of stored frames */
>         union handle_parts handle;
> -       unsigned long entries[];        /* Variable-sized array of frames */
> +       unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];    /* Frames */
>  };
>
> +#define DEPOT_STACK_RECORD_SIZE \
> +       ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
> +
>  static bool stack_depot_disabled;
>  static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
>  static bool __stack_depot_early_init_passed __initdata;
> @@ -258,9 +261,7 @@ static struct stack_record *
>  depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  {
>         struct stack_record *stack;
> -       size_t required_size = struct_size(stack, entries, size);
> -
> -       required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
> +       size_t required_size = DEPOT_STACK_RECORD_SIZE;
>
>         /* Check if there is not enough space in the current pool. */
>         if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
> @@ -295,6 +296,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>         if (stack_pools[pool_index] == NULL)
>                 return NULL;
>
> +       /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
> +       if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
> +               size = CONFIG_STACKDEPOT_MAX_FRAMES;
> +
>         /* Save the stack trace. */
>         stack = stack_pools[pool_index] + pool_offset;
>         stack->hash = hash;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8O-GLQ9m06riX%2BkjbPSD9sBo%2BXGtTE2xW%3Dpq9uJFGAg%40mail.gmail.com.
