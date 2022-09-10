Return-Path: <kasan-dev+bncBDW2JDUY5AORBIVT6SMAMGQEEGYK5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D995D5B4AC6
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 01:11:31 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 14-20020a9d048e000000b0063936a5db40sf2770683otm.23
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 16:11:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662851490; cv=pass;
        d=google.com; s=arc-20160816;
        b=itavhteqiuNfK7CXzU9yw2vrs3VPYq+EuPmLx3k9raevF2mezZD7BHKzoq+RLGKOOL
         hpUa6rRPFygRmuJqteNRgyq4OOi265NpKyIp6lmdRQFUrGFA2WjqOr30JWlzX4p1kvd/
         OS372D3KBmG9boI9qnDOckStjPFB0rh/OMtjQaXpzHSwI14NtQEWJnYB/bi6Q0OXhOVJ
         mq0Q1h0YZi95yKR83JYFD+KBTRD+KJTZAZ3PahcbLutxxbn6bGmzw9Oj3noiGrrPS9ie
         3yhrWjyTXEo2XIMy6nM+VAlOJB8rQ+kI/469UBoBc1M2ed2owbM1Q1AbK6mNpn0UPBRA
         yKsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4KuRMUbB40P1LLkD7UzXcnNU8gkSRRTKwM3HALOV4Kk=;
        b=Z8WKEm5fra4NzXGSHmZGgIqZUBs91T6OhjtFXJdftUK1Z/hlcTdv18zTDTqJXhT3tI
         61gLJR4+IrkJ//OLq+eegTW8IxQIY58GuB+fsBKhcKFP39yennMIHGLVylsoe7jPQzIs
         OkDlDtOebRXCLBkenS3JfMjfTGM/UZ/AdjuCcTszNnLuQo6IwUxEyPjpsieVnQ29oLvK
         8q0I/DjwgQMKfFx25FX+1NfEGIjJ1+9dkUd6FfZMsEKGOikIp6XYeUrr/uO07ZF+jQCy
         od4CE9ZCRkMp017PJ6NG067vfo1Heuin/6NqxUf1WOk0k7WDJe+Ft9mf6OZfi/5EJO0t
         YP0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kKI9Y/dP";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=4KuRMUbB40P1LLkD7UzXcnNU8gkSRRTKwM3HALOV4Kk=;
        b=pavSKj2otk20qX/GKspTbZfCXaSA7Lkhdte8QHvVyipel16n40DKIooaJLsOBNx6so
         aXpKAGkzl+59zZ0gQ6FxrxQfSFvge4H7cFxIeOpUIjKTaedzMuFsFCHfLwKK3Pl2amLZ
         7ZiCNgv0+nLxYuzlkrbGvKKseiHlx11u7I+c3K3LhouerA8vm5jR7hsTrrjL5e+H+CoB
         7VHS3bkfENyJtDLJv2sdD69HN4BVYLMFnijWPGMlHExrqNnwa3DrYeq2juqBoeb0s0mB
         nNu3KTkMGckjrBad6oQLEh9GIG5B/fYe/ri+ezvOD0owo41jJmWjR56yCFmEE+yT0sCz
         f7ug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=4KuRMUbB40P1LLkD7UzXcnNU8gkSRRTKwM3HALOV4Kk=;
        b=KlLtCEKOvRcPmdCC7mCGcvKw5invoG00taRwyEu4HPpeLf7lQEEGYtVq64QyvClhxv
         M8THeQAy7e8dzQ6s0MHVxQnkPrOOR9JBwxBKZzPfRnhB7HaANbYIyv9xXdK+KA+qBqv5
         f6EgOF3llCC5Ct9LS36bFvYRPwBHxmbkYMWbuNlTJ8RiAnYKQQvSn+PHARouJE94GYTA
         XV0w+E9IbK08/qTkkCipXHS0G0OWgna4ryO0OUrng5w2UTkE4liQgjaRUtvjqQp1vvYG
         KH2w3YymRynnxPOj9YRBdPwON1TViv4xTdLtBNT3pTZNRQIcuisonrLX7dQbvURrUI3J
         ZrNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4KuRMUbB40P1LLkD7UzXcnNU8gkSRRTKwM3HALOV4Kk=;
        b=DVbjc+WPehMMbFXBQqcxUIK8p5ZyK/Q/2yZOW15vHYrabwJYwZMb5y5ahO5lsokx36
         Evx59+7LQvXXeWtnQdgwlzkXCUVKZdzNenIbMsGoeBzT0UWs2C7uRl8EryRFp55BiEGO
         zOpACQWoUYIlTn5nkNLs8RKY6BxO7zfgPYCM1XhEx4NV84ke9a7HCvDjkgYmi22kZk/d
         TJlAG9BphxmWUwyFr18zaz6dNF11pb3aD8cy3K5Z7nyE5Zqt0eEgMmYXtnEmiy2mXus8
         LEoAUQYeZiiLd/XZUJ1V47WfXnelUkVEMpqD++VpUSdHDdFA8Ctew2h4YbJ1ve7nrN96
         FpRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3xSVFoq8rQ9cPDGdF6zwgV5VsnxFqViaGEjiFa9DMJjsqRRIDK
	mHfMFJMU7AOdifGOxuc4otI=
X-Google-Smtp-Source: AA6agR6Lq7GIZREAhXlCdHXZo3YBv+T2nCuDMLX91ugEM3/hlnrMPf/sNcZx+dRe/mchP2Vv8IXrDA==
X-Received: by 2002:a9d:2de4:0:b0:639:158c:ec87 with SMTP id g91-20020a9d2de4000000b00639158cec87mr8149093otb.204.1662851490656;
        Sat, 10 Sep 2022 16:11:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:645:0:b0:344:8f41:1800 with SMTP id 66-20020aca0645000000b003448f411800ls2318920oig.10.-pod-prod-gmail;
 Sat, 10 Sep 2022 16:11:30 -0700 (PDT)
X-Received: by 2002:a05:6808:118b:b0:34d:8f58:d95 with SMTP id j11-20020a056808118b00b0034d8f580d95mr4571950oil.22.1662851490242;
        Sat, 10 Sep 2022 16:11:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662851490; cv=none;
        d=google.com; s=arc-20160816;
        b=q0ZdmvMQA6jQe9ixMmmS1/HXCgAfxPoCAVUItUhzRe11O8pNQyElAyRQQ+d5MeapGl
         1Ov6vucV5V1NNLDQ00UGdVyH+zPWp67SJM0WWbSSoREaq4lqLkRqkL/J52fSxy7cqC/2
         8MxqttHEQZrM7cvDLKT+MMkP4OvghfKnK6LdYyaofpFZZYiLsbbOzZ2EKcstlPr3WmrA
         xMey+l1hso7XOQHvD0EbHmafID2/IVy2I6nTU7avuc+mlnDslbJ2f8lpQU2BbwHNWNuL
         WHBQvj1IIL0tT8mBy1gFQid4rwDw//z8FsUcwObBKEs+hP1t/F4WWAnZCECN0gSQ8EoK
         exbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jLcAZDQOWnQUWa/zS3ZhETCWwFUmZvMcvW1wH6uC4IQ=;
        b=LtWAqrs0MVLp/YBe6kyn8TEwfA+exTRGq8pvxtRaPyFuDx1TOcdMFZdDMTjiIEjfSb
         UByy3t7/P81+scEij24B0REXmJX4BZp7E0k63ByNbMwV/n2333hYwSTTztdydCRPQSjP
         3tS0bLxBxSMCrcHmE36/M+c346/5wf13khtP6aU0P9LjejbG3WiLalTula8BVookdsJH
         leYijLkxuqvEKOdJ1XKYecDari4KSAEtiSwdlh1A0tZ1H+QLAOq5dwF0V3+LnqeA+/tM
         ZP0OVobhqqIfiUqhyou1GVrwK6FvVGFe6dwgwzbGGDXoLgQius0D0XdlKwIM0TUXWSAz
         QqXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kKI9Y/dP";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id x24-20020a056870a79800b00101c9597c72si503105oao.1.2022.09.10.16.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Sep 2022 16:11:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id w2so222643qtv.9
        for <kasan-dev@googlegroups.com>; Sat, 10 Sep 2022 16:11:30 -0700 (PDT)
X-Received: by 2002:a05:622a:11cf:b0:35b:a369:cc3 with SMTP id
 n15-20020a05622a11cf00b0035ba3690cc3mr7113419qtk.11.1662851489754; Sat, 10
 Sep 2022 16:11:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220907071023.3838692-1-feng.tang@intel.com> <20220907071023.3838692-3-feng.tang@intel.com>
In-Reply-To: <20220907071023.3838692-3-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 01:11:18 +0200
Message-ID: <CA+fCnZdSUi6mC1e42bztst2tvhc-sLZdnj=Sr=doqxOokXmwTg@mail.gmail.com>
Subject: Re: [PATCH v5 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
To: Feng Tang <feng.tang@intel.com>, Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Dave Hansen <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="kKI9Y/dP";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c
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

On Wed, Sep 7, 2022 at 9:10 AM Feng Tang <feng.tang@intel.com> wrote:
>
> kzalloc/kmalloc will round up the request size to a fixed size
> (mostly power of 2), so the allocated memory could be more than
> requested. Currently kzalloc family APIs will zero all the
> allocated memory.
>
> To detect out-of-bound usage of the extra allocated memory, only
> zero the requested part, so that sanity check could be added to
> the extra space later.
>
> For kzalloc users who will call ksize() later and utilize this
> extra space, please be aware that the space is not zeroed any
> more.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.c | 6 +++---
>  mm/slab.h | 9 +++++++--
>  mm/slub.c | 6 +++---
>  3 files changed, 13 insertions(+), 8 deletions(-)
>
> diff --git a/mm/slab.c b/mm/slab.c
> index a5486ff8362a..73ecaa7066e1 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3253,7 +3253,7 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>         init = slab_want_init_on_alloc(flags, cachep);
>
>  out:
> -       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init, 0);
>         return objp;
>  }
>
> @@ -3506,13 +3506,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled section.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                               slab_want_init_on_alloc(flags, s), 0);
>         /* FIXME: Trace call missing. Christoph would like a bulk variant */
>         return size;
>  error:
>         local_irq_enable();
>         cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index d0ef9dd44b71..20f9e2a9814f 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -730,12 +730,17 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>                                         struct obj_cgroup *objcg, gfp_t flags,
> -                                       size_t size, void **p, bool init)
> +                                       size_t size, void **p, bool init,
> +                                       unsigned int orig_size)
>  {
>         size_t i;
>
>         flags &= gfp_allowed_mask;
>
> +       /* If original request size(kmalloc) is not set, use object_size */
> +       if (!orig_size)
> +               orig_size = s->object_size;
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_alloc and initialization memset must be
> @@ -746,7 +751,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>         for (i = 0; i < size; i++) {
>                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
>                 if (p[i] && init && !kasan_has_integrated_init())
> -                       memset(p[i], 0, s->object_size);
> +                       memset(p[i], 0, orig_size);

Arguably, with slab_want_init_on_alloc(), all allocated memory should
be zeroed to prevent possibility of info-leaks, even unused paddings.
Perhaps, Alexander can give his opinion here.

Thanks!


>                 kmemleak_alloc_recursive(p[i], s->object_size, 1,
>                                          s->flags, flags);
>         }
> diff --git a/mm/slub.c b/mm/slub.c
> index effd994438e6..f523601d3fcf 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3376,7 +3376,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>         init = slab_want_init_on_alloc(gfpflags, s);
>
>  out:
> -       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>
>         return object;
>  }
> @@ -3833,11 +3833,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled fastpath loop.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                               slab_want_init_on_alloc(flags, s), 0);
>         return i;
>  error:
>         slub_put_cpu_ptr(s->cpu_slab);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-3-feng.tang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdSUi6mC1e42bztst2tvhc-sLZdnj%3DSr%3DdoqxOokXmwTg%40mail.gmail.com.
