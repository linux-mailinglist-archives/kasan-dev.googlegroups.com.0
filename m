Return-Path: <kasan-dev+bncBDW2JDUY5AORB2HSY6MQMGQET55CRKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA65A5EB0FA
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 21:11:37 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-34d188806a8sf70387087b3.19
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 12:11:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664219496; cv=pass;
        d=google.com; s=arc-20160816;
        b=EwADFHQvIM5aqqSs6d0V2NCqrZh3+PqJiQKbIVjsquNfpLmL5j5yBs5G7ZeeND7ONW
         OnGz2FuiZPXlnpv17INgjz1Eoeoxz1TRCk7rlJeR/w+j6uW89B+z5g3vJFjtLAUDSOWa
         IVi5ldHyHfomyVW3oUgKw2agG1XvI0gW1keBhf91G6bnEkJ7EThVny+sYee7bNAFzIQg
         UkD5wiQNHHMWMhMOEsHWKMrEHgyOYLyiBcKuXboJIzUdnth0/jt/2OTLTYAAvE+yZ25k
         KAwg8OzKJR1ErrvbGWIzQw8c1MsoHoi4jkX9HNKrtGI4z8pbgDiA9t+i6vsl7AEAwpwB
         QC4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=72cF58qcPm/wnJz0kRiBBIEAi4WTHxAXgfluL9gS46o=;
        b=tepU+lNuMeWIZAvdGu9vJPprKGZNmnoFWhHCCVx2Ry2cNhVFnnbcU5aASX6LrVNQti
         bcS4H4fAMm8/KZ6E1G4VuRTD40a2R0/jA9KpKvYyBFkg6iGvE121eomy+vDQVk5Kt6hd
         NF0ntjZmnV64XFr2mclrEkyjWziMZ/bdwiNtwY32IFE7hoW59hxiKDTOTqbu5spFgSPh
         C6AG5Px+ZsmusYEkVbut/vGtKkRCBi2EnpnFHbnGa0b5fc5i29ZNRDdFyoYWg5dDbjEn
         lO+2r64pGAJxGSym22lW6juexbi4Ib5fE+oTHMO67tvtbuBz9P+b3ZlUVpugJKuGRsNz
         2BwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lAXDle+S;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=72cF58qcPm/wnJz0kRiBBIEAi4WTHxAXgfluL9gS46o=;
        b=VS9ojZheCsQbHDgR8eQgFBXcGXW4Kcx1THUWxY8EDcbfPmSCatwJOsiz4Ga+53ZecD
         v1Ul+qTrURZN76wAKazKuaKzGixVZGI8S9hB0LIXADizcCKmtzjVC/eNuZMJmV8ARSvG
         wgXRMhPNVLd93GYr/ogPNMTchVILwJKGa9viFVIiOI7bOUmTgq8UIrVPL/3prXK5FPdd
         kz4RyohjrWnWoAkbYPfBUIrxWkk3VPWRmf5/bMmb8fBmlQ01+q9TXqizP/JoaBPpIjFw
         SU/BCdSj8swLFjXzfuVFFbpxtPX37wlr4F06dg4zxT6ixuhR+0MK6SpLfrQzXZbngg7G
         CM4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=72cF58qcPm/wnJz0kRiBBIEAi4WTHxAXgfluL9gS46o=;
        b=VhHi/LnCy/OymV9uTw9WSY6k5emJ1FnhbBA6sHqsc6cEsb4KIpDSMZuTgTZPj3ieI3
         IvZPVMOQwChBSjHytVGFSPvT1STl7L0jGmWOmzSJd9FMEuK26zJZC65AAU3yQWkI5m8R
         R1Ydw3I6gzxXPEG6CjdTB5jMsSH4Alm20787Q+dzVc+/FnZLyGh5jJi2U8alA1WPg6rb
         fL1bRLKcbnD6usTh4XzGZD/HOxBsnB1zDPfHXnGVUuh00L6kcD3rDASWm3723an72srz
         sev6Wxd91RyPcnBF9MgPTgiWgdZfau8c9Ao5BdJSecpvpzbSNregUes/V05IxWr2W6k7
         VIXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=72cF58qcPm/wnJz0kRiBBIEAi4WTHxAXgfluL9gS46o=;
        b=epLFgaEu44K8F+LXHkNFF/KVf/VvCYXJwGrHlT8kOgjdM1JacIkJEkC5xf8x3vnidq
         mPT3lZr3wG/Ma/cRHtZYP2PTetZ9fs8Aa583XCtAtsgXLxst6tBp+am8JE3b18Ejq9Zk
         Udiemssib5pHyXWM3r9RoICCtvwBYQCG7k6h4DFIUOdGqs9vBwduPImlcx1+6HVnDnWL
         jVVtDlVi9i4I8Hq2PFjmDCIQOf3ZQwWe7StTIy05LkxdXcX5CYBS5y56/Ex8DFpYY/U0
         BiKkiws7Qt196JW3RKBFqU62FhRFR6XmknV/PekOQTPn/X47ysDeh4CLWqltmjDzZQMH
         otaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3LH+pXW+Tsc7ajsHc4RALx5VrpINSURO3IUmuS4bw7TBmsm3dj
	qM93S0UT635U+ndV0LyfOGk=
X-Google-Smtp-Source: AMsMyM6nBl7z2tWnqUetgQ/3xo/G66Kp8Fyd80ZV6639L19eS+iyV/4E7Nvy2y65KU4hAI9hY68uYg==
X-Received: by 2002:a81:1097:0:b0:34d:187d:3a47 with SMTP id 145-20020a811097000000b0034d187d3a47mr22767519ywq.499.1664219496425;
        Mon, 26 Sep 2022 12:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a224:0:b0:6b3:e91f:8e6 with SMTP id b33-20020a25a224000000b006b3e91f08e6ls266123ybi.7.-pod-prod-gmail;
 Mon, 26 Sep 2022 12:11:35 -0700 (PDT)
X-Received: by 2002:a25:ba13:0:b0:6b4:bed2:917 with SMTP id t19-20020a25ba13000000b006b4bed20917mr22493272ybg.76.1664219495857;
        Mon, 26 Sep 2022 12:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664219495; cv=none;
        d=google.com; s=arc-20160816;
        b=V4WyMNbh1T134l1Y3/Qs89cwy+xVULDEF1G4Br8Clijn06pcVU/bIKGZKOAXScjXsM
         4m/vieG1D//JmF2zW0rqO9sw6FfVPunbFukDS+iDd750Nl3F0TLjr3ooz/48ZWjQXfgh
         i8yt/sMhwTpUK755W6qbHw3jOdwOywvnyUKEVgmn7QA35o1SAnPU4vZK1Y3v5QSsBFrJ
         onrrWmKlNJMwRWT0n08gfulx/znyGMgUNhtgXADkBso3R8/iaJSNTm5uL8qq1/TwnhjF
         OEiFklIIBb3t14Xl//deeHWdz8GBKbuBOld1ixy1xdJRaJgG3cCcb4yl74yRcCGEknLz
         CEXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3CHGQtxrUEIPS7Vs0U1v3kZ+VKfNuIhTmwS0yCWeTpg=;
        b=XrPj14iTH4iSjdoh4meBgII6bVXckU6DI81UZ1uKXlMV/HacjPV1uPkosBNzIzbvMt
         6YE2OAZZeNcEgCHQfSjYagvi5xM3mu+W8gWPjisjHtelBvasPONaVr4abAbs+TD9edTR
         guTu6QqG+WF5mLODCgodQhnPDeot5FbbcFz0n1v9k9G1b1mxva1q7yMHcqo3/NBRcoLZ
         cb1NNwG10FDzchjij0JV/drFlO9nKYovqKJPPJTXzJkkGBqnxEbZPI2qWFveLqZnVYw9
         +dDQCIvnR+Jmn9kxg0lVSu+JAIH4e6K8HoDuPotqd1f2ZXm6M88JBSHT0PCmH92/MJ5Z
         m3IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lAXDle+S;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id l71-20020a0de24a000000b00349f81a2957si1449842ywe.1.2022.09.26.12.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 12:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id a20so4718705qtw.10
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 12:11:35 -0700 (PDT)
X-Received: by 2002:a05:622a:11cf:b0:35b:a369:cc3 with SMTP id
 n15-20020a05622a11cf00b0035ba3690cc3mr19317849qtk.11.1664219495572; Mon, 26
 Sep 2022 12:11:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220913065423.520159-1-feng.tang@intel.com> <20220913065423.520159-3-feng.tang@intel.com>
In-Reply-To: <20220913065423.520159-3-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 26 Sep 2022 21:11:24 +0200
Message-ID: <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
Subject: Re: [PATCH v6 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Dave Hansen <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lAXDle+S;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::834
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

On Tue, Sep 13, 2022 at 8:54 AM Feng Tang <feng.tang@intel.com> wrote:
>

Hi Feng,

> kzalloc/kmalloc will round up the request size to a fixed size
> (mostly power of 2), so the allocated memory could be more than
> requested. Currently kzalloc family APIs will zero all the
> allocated memory.
>
> To detect out-of-bound usage of the extra allocated memory, only
> zero the requested part, so that sanity check could be added to
> the extra space later.

I still don't like the idea of only zeroing the requested memory and
not the whole object. Considering potential info-leak vulnerabilities.

Can we only do this when SLAB_DEBUG is enabled?

> Performance wise, smaller zeroing length also brings shorter
> execution time, as shown from test data on various server/desktop
> platforms.
>
> For kzalloc users who will call ksize() later and utilize this
> extra space, please be aware that the space is not zeroed any
> more.

CC Kees

>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.c |  7 ++++---
>  mm/slab.h |  5 +++--
>  mm/slub.c | 10 +++++++---
>  3 files changed, 14 insertions(+), 8 deletions(-)
>
> diff --git a/mm/slab.c b/mm/slab.c
> index a5486ff8362a..4594de0e3d6b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3253,7 +3253,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>         init = slab_want_init_on_alloc(flags, cachep);
>
>  out:
> -       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
> +                               cachep->object_size);
>         return objp;
>  }
>
> @@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled section.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                       slab_want_init_on_alloc(flags, s), s->object_size);
>         /* FIXME: Trace call missing. Christoph would like a bulk variant */
>         return size;
>  error:
>         local_irq_enable();
>         cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index d0ef9dd44b71..3cf5adf63f48 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -730,7 +730,8 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>                                         struct obj_cgroup *objcg, gfp_t flags,
> -                                       size_t size, void **p, bool init)
> +                                       size_t size, void **p, bool init,
> +                                       unsigned int orig_size)
>  {
>         size_t i;
>
> @@ -746,7 +747,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>         for (i = 0; i < size; i++) {
>                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
>                 if (p[i] && init && !kasan_has_integrated_init())
> -                       memset(p[i], 0, s->object_size);
> +                       memset(p[i], 0, orig_size);

Note that when KASAN is enabled and has integrated init, it will
initialize the whole object, which leads to an inconsistency with this
change.

>                 kmemleak_alloc_recursive(p[i], s->object_size, 1,
>                                          s->flags, flags);
>         }
> diff --git a/mm/slub.c b/mm/slub.c
> index c8ba16b3a4db..6f823e99d8b4 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3376,7 +3376,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>         init = slab_want_init_on_alloc(gfpflags, s);
>
>  out:
> -       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +       /*
> +        * When init equals 'true', like for kzalloc() family, only
> +        * @orig_size bytes will be zeroed instead of s->object_size
> +        */
> +       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>
>         return object;
>  }
> @@ -3833,11 +3837,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled fastpath loop.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                       slab_want_init_on_alloc(flags, s), s->object_size);
>         return i;
>  error:
>         slub_put_cpu_ptr(s->cpu_slab);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfSv98uvxop7YN_L-F%3DWNVkb5rcwa6Nmf5yN-59p8Sr4Q%40mail.gmail.com.
