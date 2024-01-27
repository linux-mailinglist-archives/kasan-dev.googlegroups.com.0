Return-Path: <kasan-dev+bncBDW2JDUY5AORBIGE2GWQMGQE5LUE5WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id D60E883E924
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Jan 2024 02:53:37 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-337d70f889csf701020f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 17:53:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706320417; cv=pass;
        d=google.com; s=arc-20160816;
        b=u5OLqu4UvyeLPN5/RNf1zPUgKSgQ0n/APqyimmrQ0xD/bCCKX4CEaBjJ47geutHElx
         qU2y23FeMrYrQpdpFQ21TKlbZJpu1tYYfEeJzd0WUbjrn066lSl3PssFgxzPbeA7QJsN
         fPa+uGDOyJqZDnf5UzlAxy9mZQTjvHa8UoafCSnFGLHxWIV8qS9POI0SK7fFXaL1rRM7
         CgqNjMtAJWwWruyPOojSP2uURGhrk34c8d2MdXkXNT3YXuBzFiuQaGUzZRDtvAkar/nr
         MP6R/Eq7w0+Lj9kNhMtMvEwYQ8SINy4d8GlJ6mzjUTNsIORpvSxQH7pkkefRq3YQ3dAv
         BdRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=z9d61HShnE8Fe/il1W3qgIhH3PTB3NgHgALKhxAR18k=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=SJhDqy5w8rX7lS092AH8EKS8BqKGzcf7LdSstWQi53rQXelMBjC2KwgGALVxPXFVlF
         fU6DI/sPduEKoZqCkjQuShpcVWoDXJYiXRdd/SxKAPOlWbHOzSN9MQMbj2jgPdIaUo69
         cGNSaw/YMDMehGaSmeB6vNnkuksdi1/6UxlJzAyJKWKA685843OgBLqmvAOmAt3QGrr4
         rpME3JYJLLQknD6XmUaDc6z0Qkp6o10/hBWyYeZk02i/2H0m3mHQwW3aXq54793xS3Zf
         kzAXnM14eGfkVb3lQ2z5GMVa1P3+3MDafdibOFnamV3mvTbrqc2gforMOwe8pmROjkES
         aFWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NnyuW9UU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706320417; x=1706925217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z9d61HShnE8Fe/il1W3qgIhH3PTB3NgHgALKhxAR18k=;
        b=XVP+pYQevBim8pTLmcdRt8qI7C1+goIN05AB1ggndpFBil81LiB0L+H5CjcMQh2nFg
         SnsiOLM/7DgCuMWZgxlCxMubhtAF0MFBC6EdU6XeTDiCgdl1C1zdi+a+z5HyZqKNUhVY
         F32oqi8eO3KX5SNDkMYuethwTvt7A36DOjBf95Xf26C8H/LsRqbHS0o+VXXXT4NYKwV7
         nFgXsd7AsfPAEeJ2jlE6LjFfM1WU4jL7u9z//B5nAFMNy7ukfEMEZLxlDJtCLFsZlM73
         fOgmzKZQIM6PXQSr5VPkgIih4KsjsjzmfmYr5il1xCFbCp4KjF2X77jSoBW6CyfTIDSo
         Nd7A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706320417; x=1706925217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z9d61HShnE8Fe/il1W3qgIhH3PTB3NgHgALKhxAR18k=;
        b=mPC/ew787IzVEgZih83036V3cd2gmxlkdD/gq+zIB/PX4AafZduVBJlFwJfP7VmpV1
         NmiaIA42oFpd6GScvLa270GKqp37Fsxbigx3tlhQBfJTWjySAzqFzWAQG4s3IrkISyrx
         HUyuheXkMR/OcKxIemJpE5qobJdFnzBxYwa+v4VJSRWhQ7D8QXBLk9+76rnThrHPlCC/
         jJrKqa1eEx6fHcJHzA4C5wWstahMysn2YVA6EYCxrSvSA/yGVFKcS0cBViPzg9mkOSdj
         LyuNukO7sawZEeYa+WfRmTCVDHcdL+LniqbopsYNbiqMFPYNUMyphCwVfmDcqLPJg4j0
         nGKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706320417; x=1706925217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z9d61HShnE8Fe/il1W3qgIhH3PTB3NgHgALKhxAR18k=;
        b=vukeZ6BIWT7TiSIBJ9hKIdw+3hHymtV3gxrB0rzT7At0K7SqqdCZtObu5o/BtEBOCb
         A5nexqmYi3rJadSAXVRlm7Qd/3ROJLymSPgr8v2sjB5o+gsWV+tEU2qjpk5qWanRoP8l
         O473MxZZ3gx4BvGrUIxIbK4Wnh1mUBpeTGTcGd9FfM1nbhqyDVnkMgTPwnJPvueZaEa7
         5/kdlIpfXM2fqJ0fQFw/MVfo8Q5XCAKRmq3VW79dWPxmTmNuMFBChWdkH3w0ixvqYaxF
         NNVwTcwLaJjklehHxRr+aRJjQZPKl4oKw0nsDr8c9295DhuJ3IQFKbqUtsmIfNPzfk13
         dqsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxiwBke1iRYdp3nbX5py5eCNKtohkmyBGdmKxxTMnYuWvYbLtUO
	lJclLHwFiXVQEd7J3iibvWAuZUg12Zq7Ie0WwsqPKkO3EBw3v9kp
X-Google-Smtp-Source: AGHT+IFm8dNRDSL5f4bSOc6kctZmX5mNZJbrTGryCG91Q9E3uWSpABo2JUZk9uuRRTjb4PCyMcMmHw==
X-Received: by 2002:a5d:4247:0:b0:337:c99f:f34a with SMTP id s7-20020a5d4247000000b00337c99ff34amr313022wrr.3.1706320416887;
        Fri, 26 Jan 2024 17:53:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a48:0:b0:339:48fa:cc09 with SMTP id t8-20020a5d6a48000000b0033948facc09ls673909wrw.2.-pod-prod-01-eu;
 Fri, 26 Jan 2024 17:53:35 -0800 (PST)
X-Received: by 2002:a05:600c:3106:b0:40e:52d8:c0c8 with SMTP id g6-20020a05600c310600b0040e52d8c0c8mr472579wmo.129.1706320414985;
        Fri, 26 Jan 2024 17:53:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706320414; cv=none;
        d=google.com; s=arc-20160816;
        b=RHjL3Xe/XSk1mwsVsdWdQqQ+zcumdZjVEjSKgfB1V7Ng7jdPvkcreaRHGowxynbixj
         SMVNsPiGTdceGXgBzI/EjR67a58hQyIYM2U7RlaiFjUmZ8hTsoj/pEgRx00wYjKx6TQH
         ZW0xOgm+HRB1s09r0bP/r4130tmmLKtU8c02nQel8QVAs177C3hJk9NcYOa8/DRDSIVf
         xsRs7NIFYSccO601MCk2aMRgP/ejLh9ZQ1CO6xcWi/geZC68D46zQOw3i7qUF4LcdvKp
         gN0R/gP3S7Kq4YEXQz/RPH63BbPCDdpZFO4k1ufM5oYqkr1Tm3RmsJD7q2BWbV/bOoLr
         KTKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WXrbWEt/1qQdJy8DYI2a1Mv/37w6xBSoBjlES19/LuY=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=ryMm1n4r/z90WM2FPn0dEy9I4FLEVjPODMTQWdoFdbM0E5pC7BUq7CxgUiZLBBlKxN
         wYA4X/OFPQMzhJofdIBFoW+Xas3gOoySFW6A1pElHKcUBncaszdI0+9UYunMjYL4qwbC
         N18n1lDWe1BRyrNIwuC7efX5BWAFVUDrg1xFcGVNzx/LNpD3CMwN/lRG6xLKxH+ttJK5
         lU1VdlGaWVr8RBf7b5bxvGARfD8tzGzzeAI7geDprqvUFRTTq2ore7IiRY97FB0V5HTR
         Sdbvkp7oqygmB4gI39MbaXZFXIXlfnX9Z3ZUFQWRAjsiuVIkBe33Pqyrds7T4plULAy9
         EzNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NnyuW9UU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id n39-20020a05600c3ba700b0040e9f730cd0si168868wms.1.2024.01.26.17.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jan 2024 17:53:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-33ae3cc8a70so110481f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jan 2024 17:53:34 -0800 (PST)
X-Received: by 2002:a05:600c:3515:b0:40d:5b0c:736c with SMTP id
 h21-20020a05600c351500b0040d5b0c736cmr447423wmq.127.1706320414219; Fri, 26
 Jan 2024 17:53:34 -0800 (PST)
MIME-Version: 1.0
References: <20240125094815.2041933-1-elver@google.com> <20240125094815.2041933-2-elver@google.com>
 <CA+fCnZc6L3t3AdQS1rjFCT0s6RpT+q4Z4GmctOveeaDJW0tBow@mail.gmail.com> <ZbPFUXNeENyuwync@elver.google.com>
In-Reply-To: <ZbPFUXNeENyuwync@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 27 Jan 2024 02:53:23 +0100
Message-ID: <CA+fCnZeOmHf-zjMnorXJQCyy3em9sMVS_uKaRUwZkbhVRVbRmg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: revert eviction of stack traces in generic mode
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NnyuW9UU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Fri, Jan 26, 2024 at 3:44=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, Jan 25, 2024 at 11:36PM +0100, Andrey Konovalov wrote:
> [...]
> >
> > Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > But I'm wondering if we should also stop resetting metadata when the
> > object is fully freed (from quarantine or bypassing quarantine).
> >
> > With stack_depot_put, I had to put the stack handles on free, as
> > otherwise we would leak the stack depot references. And I also chose
> > to memset meta at that point, as its gets invalid anyway. But without
> > stack_depot_put, this is not required.
> >
> > Before the stack depot-related changes, the code was inconsistent in
> > this regard AFAICS: for quarantine, free meta was marked as invalid
> > via KASAN_SLAB_FREE but alloc meta was kept; for no quarantine, both
> > alloc and free meta were kept.
> >
> > So perhaps we can just keep both metas on full free. I.e. drop both
> > kasan_release_object_meta calls. This will go back to the old behavior
> > + keeping free meta for the quarantine case (I think there's no harm
> > in that). This will give better reporting for uaf-before-realloc bugs.
> >
> > WDYT?
>
> Yes, that makes sense.
>
> You mean this on top?
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ad32803e34e9..0577db1d2c62 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -264,12 +264,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, voi=
d *object,
>         if (kasan_quarantine_put(cache, object))
>                 return true;
>
> -       /*
> -        * If the object is not put into quarantine, it will likely be qu=
ickly
> -        * reallocated. Thus, release its metadata now.
> -        */
> -       kasan_release_object_meta(cache, object);
> -
>         /* Let slab put the object onto the freelist. */
>         return false;
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 8bfb52b28c22..fc9cf1860efb 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -510,20 +510,6 @@ static void release_free_meta(const void *object, st=
ruct kasan_free_meta *meta)
>         *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
>  }
>
> -void kasan_release_object_meta(struct kmem_cache *cache, const void *obj=
ect)
> -{
> -       struct kasan_alloc_meta *alloc_meta;
> -       struct kasan_free_meta *free_meta;
> -
> -       alloc_meta =3D kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               release_alloc_meta(alloc_meta);
> -
> -       free_meta =3D kasan_get_free_meta(cache, object);
> -       if (free_meta)
> -               release_free_meta(object, free_meta);
> -}
> -
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>  {
>         struct kasan_cache *info =3D &cache->kasan_info;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 216ae0ef1e4b..fb2b9ac0659a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -390,10 +390,8 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct=
 kmem_cache *cache,
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>                                                 const void *object);
>  void kasan_init_object_meta(struct kmem_cache *cache, const void *object=
);
> -void kasan_release_object_meta(struct kmem_cache *cache, const void *obj=
ect);
>  #else
>  static inline void kasan_init_object_meta(struct kmem_cache *cache, cons=
t void *object) { }
> -static inline void kasan_release_object_meta(struct kmem_cache *cache, c=
onst void *object) { }
>  #endif
>
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_f=
lags);
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 3ba02efb952a..a758c2e10703 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -145,8 +145,6 @@ static void qlink_free(struct qlist_node *qlink, stru=
ct kmem_cache *cache)
>         void *object =3D qlink_to_object(qlink, cache);
>         struct kasan_free_meta *free_meta =3D kasan_get_free_meta(cache, =
object);
>
> -       kasan_release_object_meta(cache, object);
> -
>         /*
>          * If init_on_free is enabled and KASAN's free metadata is stored=
 in
>          * the object, zero the metadata. Otherwise, the object's memory =
will

Please also add a comment saying something like "Keep per-object
metadata to allow KASAN print stack traces for
use-after-free-before-realloc bugs." to the places where you removed
kasan_release_object_meta.

Otherwise, looks good to me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeOmHf-zjMnorXJQCyy3em9sMVS_uKaRUwZkbhVRVbRmg%40mail.gmai=
l.com.
