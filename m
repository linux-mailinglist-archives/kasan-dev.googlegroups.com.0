Return-Path: <kasan-dev+bncBDW2JDUY5AORBG5X5ONAMGQENB26GBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 536BE610195
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 21:27:24 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id a2-20020a5b0002000000b006b48689da76sf2386065ybp.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:27:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666898843; cv=pass;
        d=google.com; s=arc-20160816;
        b=zO52dKDLNtB+N4tURDjPBfzh/BbMn36DfoRVJ4awiriSatI1nyLZAcuEL3UFR9Dvg0
         80dTKHF/SGPhkmyFpGTYTg4HTdRpVZnwLIGKNE7viLRaJPva1LtiAEZtCpecSrnogGNp
         jU2XA22o0BEGHzUyhg0K/Ef9J1X5EtApMvePgm4CkrN8PfEY8KJUSirPCUhG48AV1eBp
         oWNJjwJGJ6wfA8zRB08L6J979+enpgNToufzwlKYNVQ570BrJclAJ+aiKBaVL26aZIc3
         YCzP+e2NhjD2430Y8KIK5E9m/KYsaqgrhF7bHmCJWqxpzzKkPKUq1LBMB5GMIB4Fq8Dc
         dzIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=p+ueN91Ob5HAcVF33Lq9P+5I4E1cgrW5PMcd7jaUIO0=;
        b=BWq4bsx4Rwnwfxy1a18TnVcLOdI4wrjcJ0dblImmG2ycJSTQBDoD87+cN1KRZLVs29
         verpzIuY4L8p/1QfSIr92l5xThDM5TIn/uYMYHOMXWbYkVlXS37/8GIi3RivTEPidG66
         GMPS7JZM44GSQYuccGsY7M9Aog+mnY7QxWGar774aA64pLFPFVscp5vsRntJmq7jvuNl
         QAxB3pVncjDsA6pWggbVZ4tac3fSit9eoyBNZ7bZyDeL6z4UzsfDgW61/aXbvSDjuBaK
         DNWnYePXbBiM+4j1ZwP8xYmYCprboI3myk+tfiEVNqUhRLg8yfSe0TSixeFaDbCnNYNu
         eB5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cw+mLNmr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p+ueN91Ob5HAcVF33Lq9P+5I4E1cgrW5PMcd7jaUIO0=;
        b=rMHUQIAsXYGLeU7hAFNNr4cz7I/7Xy8KmTXO2fjG+gvhQtxTUYNuzR2QNwsmwS4Eqb
         L2oBIskXL7Ntocxk9++Fr2MiVH3wORnaBLe7xPiOMZ6PIhc+kRPiEMxFCU84uVSqgNkA
         eY3DkvMKBO22mCdOSPon7gkjBYpUO7Dh4uVTe1XR5cLEBjQOiGUefHr6YNc9Sp5/aNVV
         LTcmSAh/zArcN0DC2t3mB2yJUzj3tc3yvYSDDCfYvdYCQJdBUEhyViEFBeemNgDcZiJ4
         m08ZD4Ii3GwMpQG5uwhwdJ0tktwK4FHvLSs+wi3N6NDpXD5dBdDipHc6EOxA3Gh5Lwzp
         /F2Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=p+ueN91Ob5HAcVF33Lq9P+5I4E1cgrW5PMcd7jaUIO0=;
        b=F+VgzxJfZcvTC8mWbdqqzHIUpJVfKkSbCiSprPBVDMgq/1jyrBYmmqWtPMlwboMMIV
         jA47Bog0cLWs2RUEvH/4MLdbuiMF+je/PJkyfiR9A5vzX6Lra+YhugEt8gBfRlDn+ICX
         FlbPKCfi/NyXzB3kZ4/uK+5qaNLA47CUBcW5heKJuhSGae1QcQRHRE7HxUVsZFwL2516
         FfUUgs7s4twGR4gmxtzxFqpxBNkHYM2lF7iM+0xuS327lsDJuJqMJtbnQmACfiX6E18p
         JckQddo7g91mb4Krb1mRI+KSrb49qi5b7vloy4woVBTo8OQHnFsc54noAbnYvkpehug3
         pq+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p+ueN91Ob5HAcVF33Lq9P+5I4E1cgrW5PMcd7jaUIO0=;
        b=cAEgKbgtB6Va8r+OrWbmrlGoyL0E8F/vQis4J/pBRDxZ5wC7wnWwrYZY/x8IfYKNhH
         TeNw2+Fkg6xUJG+5xV7LrOsAZBxgZkT6S9i8Lgd3QCmgGH/fxHP6yUcnZifjEJD+9deR
         4O8MIF9c1XBUH2dD8S1/Qj3yg4rJI0Oq0zDCdm6iTiTSV7iA8a4Hc2zyQACDSHZoDKWe
         J54tke5kWltL5qvvzToQgH684DOkI1wjiWuXa5v7qGbZ2FhtdfWyts+3IjOFbpe1GEem
         +YJtjmpytAZkNvjLGyBRg3yAegagDzwLYIMm3RMznMdXgnjkqHxSZvqckQSzku4fAHIO
         DF7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0efU/zoqrzLvc4gC/ZGG34qJhDJhRFZGghDaqlXFM8W7RB0FXb
	ExCiCN4Cg4uHAkc5ZJP9RRk=
X-Google-Smtp-Source: AMsMyM7ydBd2LONvXy0Iv6TKNm/wqYa8tgi+ma9d2NDZCOi8g8Up/rjxqrqKm8yhmgcuCdLhaJdllQ==
X-Received: by 2002:a25:d7d8:0:b0:6cb:89f4:ba1e with SMTP id o207-20020a25d7d8000000b006cb89f4ba1emr9935364ybg.552.1666898843141;
        Thu, 27 Oct 2022 12:27:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:797:b0:369:433:e417 with SMTP id
 bw23-20020a05690c079700b003690433e417ls34853ywb.9.-pod-prod-gmail; Thu, 27
 Oct 2022 12:27:22 -0700 (PDT)
X-Received: by 2002:a81:3884:0:b0:360:7830:f09f with SMTP id f126-20020a813884000000b003607830f09fmr47075391ywa.159.1666898842642;
        Thu, 27 Oct 2022 12:27:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666898842; cv=none;
        d=google.com; s=arc-20160816;
        b=RaTXymuvmIls13xUenv68pGgpUf0Eq5+iKO9qeX8oLGuq3WJvVL7xDbDLmYPDJWkGM
         lSP4P/CXNKgX/fh8aUR4KzCoHJBdOy8BtA59IoaxqqoO5/tFvtPi+/Z1SUrBL0WcS6Ml
         hfADNJIojBAEaKCMxbGs0Yd4xHbOJDM8w9S5Lk3tuclpg3CizB4YfZxY/0VMAf4Eujtn
         GPxBI1yNmLhVZ8+ozSL0JCHby3LxP9LLrnHdZx0A3Z5InAo15EWnmxAnBkNfX3o0db6I
         YcT2Tm2LIlvhTcW7C3dLu/j/xQxqpCaqEOU0UEGAWOemB6Gjjeyp8U2BzmD45tkjH44a
         JNWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T84PcfyuK8pgheltMcMu03qBrAz+3BklY2VEE5FFI7U=;
        b=Qb1D1pboNiGz8ypBtW3dCitMNgvMHAbJ0AAjZ2ahbxkGM5gpDWUReUQ19pRwaagfD3
         aQN5PjYryG84CPqu2ZJPsiYWoAvCCKZ5o2jAjW1DWCs6oj0HHqq3xSvha18LGSZLhD+s
         J4937ZjT6nL1nsv1+ERhgcsb6rYxCaATj23ttr+D90rfJdoFLKZ99p2lLrOVnzzRS90l
         AddV136Okzq07aj0ulk6en4ho1yuqyTsbDMOscyZY/bgy6A8v8DwZ7AjZH6pVHk8DkgE
         Rr+WWHb0F7L/yhs14mP2zddOzqdEHGx/NAT/10NTaJT9wL0tDgDLWBRMfyI/Zx8hx0y8
         t+XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cw+mLNmr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id bp19-20020a05690c069300b0036bde06a6b6si82348ywb.3.2022.10.27.12.27.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 12:27:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id p127so3493356oih.9
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 12:27:22 -0700 (PDT)
X-Received: by 2002:a05:6808:2106:b0:355:d47:313 with SMTP id
 r6-20020a056808210600b003550d470313mr5550586oiw.34.1666898842407; Thu, 27 Oct
 2022 12:27:22 -0700 (PDT)
MIME-Version: 1.0
References: <20221021032405.1825078-1-feng.tang@intel.com> <20221021032405.1825078-3-feng.tang@intel.com>
In-Reply-To: <20221021032405.1825078-3-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Oct 2022 21:27:11 +0200
Message-ID: <CA+fCnZfJqH=dNsD+aNoGbf-LJ_qn=2fbr-U0nj8wi4u2+V3iEw@mail.gmail.com>
Subject: Re: [PATCH v7 2/3] mm: kasan: Extend kasan_metadata_size() to also
 cover in-object size
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Kees Cook <keescook@chromium.org>, Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=cw+mLNmr;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236
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

On Fri, Oct 21, 2022 at 5:24 AM Feng Tang <feng.tang@intel.com> wrote:
>
> When kasan is enabled for slab/slub, it may save kasan' free_meta
> data in the former part of slab object data area in slab object's
> free path, which works fine.
>
> There is ongoing effort to extend slub's debug function which will
> redzone the latter part of kmalloc object area, and when both of
> the debug are enabled, there is possible conflict, especially when
> the kmalloc object has small size, as caught by 0Day bot [1].
>
> To solve it, slub code needs to know the in-object kasan's meta
> data size. Currently, there is existing kasan_metadata_size()
> which returns the kasan's metadata size inside slub's metadata
> area, so extend it to also cover the in-object meta size by
> adding a boolean flag 'in_object'.
>
> There is no functional change to existing code logic.
>
> [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h |  5 +++--
>  mm/kasan/generic.c    | 19 +++++++++++++------
>  mm/slub.c             |  4 ++--
>  3 files changed, 18 insertions(+), 10 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d811b3d7d2a1..96c9d56e5510 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -302,7 +302,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>
>  #ifdef CONFIG_KASAN_GENERIC
>
> -size_t kasan_metadata_size(struct kmem_cache *cache);
> +size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
>  slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         slab_flags_t *flags);
> @@ -315,7 +315,8 @@ void kasan_record_aux_stack_noalloc(void *ptr);
>  #else /* CONFIG_KASAN_GENERIC */
>
>  /* Tag-based KASAN modes do not use per-object metadata. */
> -static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> +static inline size_t kasan_metadata_size(struct kmem_cache *cache,
> +                                               bool in_object)
>  {
>         return 0;
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d8b5590f9484..b076f597a378 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -450,15 +450,22 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
>  }
>
> -size_t kasan_metadata_size(struct kmem_cache *cache)
> +size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>  {
> +       struct kasan_cache *info = &cache->kasan_info;
> +
>         if (!kasan_requires_meta())
>                 return 0;
> -       return (cache->kasan_info.alloc_meta_offset ?
> -               sizeof(struct kasan_alloc_meta) : 0) +
> -               ((cache->kasan_info.free_meta_offset &&
> -                 cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
> -                sizeof(struct kasan_free_meta) : 0);
> +
> +       if (in_object)
> +               return (info->free_meta_offset ?
> +                       0 : sizeof(struct kasan_free_meta));
> +       else
> +               return (info->alloc_meta_offset ?
> +                       sizeof(struct kasan_alloc_meta) : 0) +
> +                       ((info->free_meta_offset &&
> +                       info->free_meta_offset != KASAN_NO_FREE_META) ?
> +                       sizeof(struct kasan_free_meta) : 0);
>  }
>
>  static void __kasan_record_aux_stack(void *addr, bool can_alloc)
> diff --git a/mm/slub.c b/mm/slub.c
> index 17292c2d3eee..adff7553b54e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -910,7 +910,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
>         if (slub_debug_orig_size(s))
>                 off += sizeof(unsigned int);
>
> -       off += kasan_metadata_size(s);
> +       off += kasan_metadata_size(s, false);
>
>         if (off != size_from_object(s))
>                 /* Beginning of the filler is the free pointer */
> @@ -1070,7 +1070,7 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
>                         off += sizeof(unsigned int);
>         }
>
> -       off += kasan_metadata_size(s);
> +       off += kasan_metadata_size(s, false);
>
>         if (size_from_object(s) == off)
>                 return 1;
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfJqH%3DdNsD%2BaNoGbf-LJ_qn%3D2fbr-U0nj8wi4u2%2BV3iEw%40mail.gmail.com.
