Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKVYSKWAMGQE377NZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A35C81BF78
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:12:27 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40d39a425bbsf8493765e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:12:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189546; cv=pass;
        d=google.com; s=arc-20160816;
        b=xTCeRITFoZZIQcD/GaIfQ4YCS83MROvbzCBbMwcrhCI89eJJoOjq8ylr140QBOaou9
         6ArTRynYf256UmgrAmJRh3kC32lHWNyquh/Q/uEwN7bqJd8tfbcKPHNMhxIPziBGgMoN
         2eLYmBwWKRgqpHkr0+JgCm7yWxEllCr/HSiOrRktRlYmQU85Lm/qJ6H0j3f/s4657ZHO
         CLxOCVsASt9Q17pq3/qqeQ9eBGo/TrB3zsMXvkHlRJBkYLe975q2CviNzoJLtZaRFmlN
         iRXVzV+lKpSkaZ1L+JY05oKWm0k00CGJI5W8MJ3YXB22mkmaUKYedZ1V+bFA0kYmYkGf
         JzpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YAJYCw3GW7q0V5i03znxEb8KpQZhhL8WK+AdMN3oeU4=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=JkZQ7Nqa4ftFTJvte+9GMUrEQ4bUx/u/uolvrm1Vt3jk19LzeNJFehsegjhrkYSqrk
         oiKxGEBa6ryunkPOWhsAHLsYkTSiQmfnvfDx6JJB2158dDGUIihR8cetBeVNAlDHLZy4
         21jZEAaSVvgmicaXhHehhDGAsQ9v9iwGu1RcCCx/1pxPgWddwcTZLK0y2AptgEpFgp47
         aXW+LO0J3wEsETUgNHwz4RBok+JMPoLoB4uyvx+R+7PND+eyY8dpAq01hz4FIaRxp40l
         t9W+8TQA97I+7A1XDbaCc+9KzTEgPQXHI05exQmMbuKR1562/1dNBVdBJT9PjK31dC2b
         A2EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PNIriTMl;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189546; x=1703794346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YAJYCw3GW7q0V5i03znxEb8KpQZhhL8WK+AdMN3oeU4=;
        b=VAO7K7xy3ftyPBT9f0GIVgI71yea+Ynmh0algcpQcyUNI9tVKzjQTFbkYoixqpdiRo
         sWmuwjwSuYPXWEQCx84tDmYWvai99RR/9xP3mzaHX+50F2OcUzmZbtpxGt/BxNvB3Dfx
         lyPaascN+IjrvHvvjx3M0fni7acPFyRGL5ASfq38rHXLuzg/CFNpcZ5owqansUJWV865
         a68p55wJ7SI8/FuWOCdkmMEuaXqGiFAVQsBsXN8tmaJs1sOMg5IeX4gIRpSMuYYCoPMq
         QerZ+mq4VtLu2SJOn8mCLN0TdcE7vhVoOMS/Gvaf2NyG5p9SsjXvYxeituEhuKtwugsJ
         aI3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189546; x=1703794346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YAJYCw3GW7q0V5i03znxEb8KpQZhhL8WK+AdMN3oeU4=;
        b=B+aQSZz+PDx0NikneU+waqRMlbUwv3shQ1ozVW0imoO8budZxvS11wMnjDjaPY+9OM
         +0HXnRFQy3ZYK2mdc+ylpSARuKxA40TAs1tUFipq6bM1Iq7fWu+GKLt3GduLeTfJKTvo
         0VZZHjqYeTu08UEzHAXMCNR7Ud1p2ljfG8uVV3mSiT/hp9dUf844VN54rzRHWvpkXAmZ
         4A/oODVTlhOYvR1q1YpgKgpzCDmHj6nMoKVkuyvKEx+Lw4lRz8INV/n3f0z76k9Oac3U
         xcREiUByIrMbEuUG1iUyiKBx2+9HhcvsJHWVDtWAM0HQsWdhJBYMYuLY4/R7WdGcSqfR
         Ic0A==
X-Gm-Message-State: AOJu0YyUr5KEBf+AlHoW5E/qHfpQ6aiolLhA8ZwXlOZgGq9oNjwQ6zX5
	ocF1e9RDwfqTk0rp6hXC6qw=
X-Google-Smtp-Source: AGHT+IGZxHZQrJq+VbhoL5bPx7rabEAiqutfM6cL7VkjeGeiuA/L8H4ycPRaIPiOBqb5VUCIr/OLDg==
X-Received: by 2002:a7b:ce87:0:b0:40d:2d18:ea88 with SMTP id q7-20020a7bce87000000b0040d2d18ea88mr173266wmj.87.1703189546429;
        Thu, 21 Dec 2023 12:12:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f4cc:0:b0:336:8b8e:5eb7 with SMTP id h12-20020adff4cc000000b003368b8e5eb7ls370665wrp.0.-pod-prod-05-eu;
 Thu, 21 Dec 2023 12:12:24 -0800 (PST)
X-Received: by 2002:a05:600c:6026:b0:40d:3fee:97cd with SMTP id az38-20020a05600c602600b0040d3fee97cdmr158268wmb.174.1703189544391;
        Thu, 21 Dec 2023 12:12:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189544; cv=none;
        d=google.com; s=arc-20160816;
        b=WvYOJ9C03w63U4Nn5lPWRccBvCUWdoWIoIthQxrz2VRXLjaSmxy/GP1/Q58080upTD
         ytfJp0w6HLrr7C8+iT5QZAQf91aUXM4Vd7Nt+rtiUwsCk2x8nTwkwr9BoeQjVDxcvSub
         Bx18cihN1tEMZCxBjqZFg7931IW4QYehgothraTxR1Z7X/RVjd1loMKEFFQMq0rebLgu
         QnulRPTbsvMR4S4FgDaeAP2bsZ9bTtv7xnepurx66EJ9mjqdlzX31hhgXZ8RH+R3+cuX
         WVigDUd5mQ3aqMGji25TXwBC2nyld7NSD7bbQk/k44ddA6aFF44O9Rn3+r7788B4tIR0
         1JCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AOUuUpeABJU7I8+1+Vm/xHhOxyiEVjsNYRzmTn6EesE=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=WsoYGZzPX6+Pd66hnIgJ9jdAmqzq2kcR5z5mUkx0q6wVd17DZoSqHDSEtypo8nxwrt
         7n4VkAF836YkrtPkJU7BSYQS6UIDb/VYX9PNp8TvzBGIEdRce2mvktwJBWHHn+qL/Scn
         dFR33HeQb8VjiJMi8qOdfBt9SS3GXIkJP58YgWgm9dGrQfe5pNUx7VV4U0aV8EufuoNQ
         iE73NqcAoOkG08VP4JIZDLnzzDYtRJPJzuKPQYcV+OyLB/lqOXi4Idc6IA4tMHETphPO
         vGOoNVM/6pBHFChraB1QpUca0i6ZHYsTKOOV3ErHoYQ6H+DbUTekHYMuu1x2rvAWrS67
         CV8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PNIriTMl;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id m30-20020a05600c3b1e00b0040c69a269fesi109374wms.2.2023.12.21.12.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:12:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-50e587fb62fso1831548e87.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:12:24 -0800 (PST)
X-Received: by 2002:ac2:5f81:0:b0:50e:5898:7572 with SMTP id
 r1-20020ac25f81000000b0050e58987572mr92458lfe.20.1703189543635; Thu, 21 Dec
 2023 12:12:23 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev> <20231221183540.168428-3-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-3-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:11:46 +0100
Message-ID: <CANpmjNNkgRbj4jgAGHtKTBB0Qj_u+KmFnBS5699zjL7-p1eV+Q@mail.gmail.com>
Subject: Re: [PATCH mm 3/4] kasan: simplify saving extra info into tracks
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Juntong Deng <juntong.deng@outlook.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PNIriTMl;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::131 as
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

On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Avoid duplicating code for saving extra info into tracks: reuse the
> common function for this.
>
> Fixes: 5d4c6ac94694 ("kasan: record and report more information")

Looking at this patch and the previous ones, is this Fixes really
needed? I.e. was the previous patch broken?

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c  | 12 ++++++++++--
>  mm/kasan/generic.c |  4 ++--
>  mm/kasan/kasan.h   |  3 ++-
>  mm/kasan/tags.c    | 17 +----------------
>  4 files changed, 15 insertions(+), 21 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index fe6c4b43ad9f..d004a0f4406c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -48,7 +48,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>         return stack_depot_save_flags(entries, nr_entries, flags, depot_flags);
>  }
>
> -void kasan_set_track(struct kasan_track *track, gfp_t flags)
> +void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack)
>  {
>  #ifdef CONFIG_KASAN_EXTRA_INFO
>         u32 cpu = raw_smp_processor_id();
> @@ -58,8 +58,16 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
>         track->timestamp = ts_nsec >> 3;
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
>         track->pid = current->pid;
> -       track->stack = kasan_save_stack(flags,
> +       track->stack = stack;
> +}
> +
> +void kasan_save_track(struct kasan_track *track, gfp_t flags)
> +{
> +       depot_stack_handle_t stack;
> +
> +       stack = kasan_save_stack(flags,
>                         STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
> +       kasan_set_track(track, stack);
>  }
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 769e43e05d0b..11b575707b05 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -553,7 +553,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>         stack_depot_put(alloc_meta->aux_stack[1]);
>         __memset(alloc_meta, 0, sizeof(*alloc_meta));
>
> -       kasan_set_track(&alloc_meta->alloc_track, flags);
> +       kasan_save_track(&alloc_meta->alloc_track, flags);
>  }
>
>  void kasan_save_free_info(struct kmem_cache *cache, void *object)
> @@ -564,7 +564,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
>         if (!free_meta)
>                 return;
>
> -       kasan_set_track(&free_meta->free_track, 0);
> +       kasan_save_track(&free_meta->free_track, 0);
>         /* The object was freed and has free track set. */
>         *(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 9072ce4c1263..31fb6bb26fed 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -372,7 +372,8 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
>  #endif
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
> -void kasan_set_track(struct kasan_track *track, gfp_t flags);
> +void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack);
> +void kasan_save_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object);
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index c4d14dbf27c0..d65d48b85f90 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -94,17 +94,6 @@ void __init kasan_init_tags(void)
>         }
>  }
>
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -static void save_extra_info(struct kasan_stack_ring_entry *entry)
> -{
> -       u32 cpu = raw_smp_processor_id();
> -       u64 ts_nsec = local_clock();
> -
> -       entry->track.cpu = cpu;
> -       entry->track.timestamp = ts_nsec >> 3;
> -}
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
> -
>  static void save_stack_info(struct kmem_cache *cache, void *object,
>                         gfp_t gfp_flags, bool is_free)
>  {
> @@ -137,11 +126,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>         old_stack = entry->track.stack;
>
>         entry->size = cache->object_size;
> -       entry->track.pid = current->pid;
> -       entry->track.stack = stack;
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -       save_extra_info(entry);
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
> +       kasan_set_track(&entry->track, stack);
>         entry->is_free = is_free;
>
>         entry->ptr = object;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNkgRbj4jgAGHtKTBB0Qj_u%2BKmFnBS5699zjL7-p1eV%2BQ%40mail.gmail.com.
