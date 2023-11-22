Return-Path: <kasan-dev+bncBDW2JDUY5AORBOGO6WVAMGQE46QPB4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D1F097F3BC3
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 03:28:09 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-28035cf4306sf451735a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 18:28:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700620088; cv=pass;
        d=google.com; s=arc-20160816;
        b=0jEBvf0xb8dRkj4O17vq9Q4dPpFTuUlLa0aFzRVwf5TkpyWGQxDExQxWs9SZ0kjDnr
         Hn58VKDJe2begDZ7hk+sAkpJgB4DoJLQEJFvouRHwh713QOeHv6wSNYRVE+abwsl/VU1
         VPV/9NwDjBOD4dFOPvG3ZfUNfswjl5mgnVuo1xY1eBOEDYqPFU79tBUqRnqThU9++6ci
         Pnl91tE2ExSxJNuLPzGm0NDXSdkNplc9mCTSrxk+FJ8Xy0Qcchya9ZovYfLvaC5uIH0x
         c1fcT5pIcOPkpQlRxz1a07nS8h1I5lUhHo6b+dw6dGaXB4MUTBH18T/TJG2OJIVNIEIm
         A8PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gLeuTtZZ1btrgVqyomy2FWPDC9WUtft3scOO0oOU7xU=;
        fh=3qba5YkzTL+bXHTu4hEoWcPGCZaYcQppgGBvzQQIBIU=;
        b=0QuJ2yVCe+k25pQMMo62ixxJiV7SGVM29ZGcpjBtfDbvD6OpZXhfcxAjEf17fTkhnG
         3p5agbe3w5tzGO/vf0K6bgph2q7Dtg0sQv2JHbvqeIwCt/R5nimfjhzBcM2CjvndH1jj
         P2lG8U4nU6XsOU4Wbi/TQWq4TdurIv+5FmSIeFMTUbtskQ3IT9nG3zeOM0jDMDnkAOi3
         sTr/BxHhiuLJzab4v2psT5+VR7QXH6z5/rld7+mNT+2wD6OSCTGn/myC7DYNssE1Wood
         OugYh8j6zhqNu2SE9AbgrICcrPsZVFLMtxNz0uaB4pmvr0yXh+MbZxOqSZAdR+XEgeVM
         sqxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PkAsC8kp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700620088; x=1701224888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gLeuTtZZ1btrgVqyomy2FWPDC9WUtft3scOO0oOU7xU=;
        b=IbIzphWOiQBMZtS3wkhD49Yy/WfuRETumCK6ueFPCcWMvSJf9/aH+RRE+Ki8q5y1Ur
         S2bVkmFdeHdg7vtLqs0yqQCjwRnC/WExgVklT0m2UpKVNCShnEXmvlwP7hISj2YR+gNQ
         b1sikU9kll9wIPcClP2HCsP82Rt+7B3ivXIrLlboCuc6/RQAAZV3XcnzWQKaTwOWg2s0
         Mg+ZL6hEe+tDB6HDOmJbEzUyUUCfmU3cJGiSYwBO+xDJ7/+8OtwhAvs4xXCwPUbvnN4C
         dgczEYiJDAjSrqjdtxaSkj9RzRVX1qHbwsRTRhnkBcAy7pVq8jb9hx0zSV4VPv2ohVu/
         wLGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700620088; x=1701224888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gLeuTtZZ1btrgVqyomy2FWPDC9WUtft3scOO0oOU7xU=;
        b=P9EWl+qpEIvO29+kZEFoGTPX9wcx4FzAdTTe1R1OAqTE8F9vVE/ix0/BPXZcPZf9Y9
         L4fUTSLK/VVexRHH+SyhtcmZS6RkIpqtdj8WpaibJmekAvLwPAyCgg99+H+s5z7KOmH2
         0v4HOww7tnENKHdQxnGEkBuyJF61Z6Fi1NuoOVVb13q1kiHBsc5Ap/vdf1eu1fz73XCf
         ykJlLk1Mfmf2pTEFgb9Wy339aLqrBzx44deDt5ohTtlicuEBIWO3PVg+7LO2MaD9daLi
         L3csaHihk/nb+/z6Z2mkzkW7qZxjGrsk41hgZ5FsWQsQJ64L1YSo7FgXz5H4S6BQ2VuK
         iLFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700620088; x=1701224888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gLeuTtZZ1btrgVqyomy2FWPDC9WUtft3scOO0oOU7xU=;
        b=s+qLBBrKWqXRgcoRUJAbLwxKUfnyTIpJIfeunAzVqt0lqczEcNBSWcdljzYQXHT4FF
         SOVkCjN8N1mIm2KUyxMsmOwC3pWt7uPO/EVGhJUmvQI6Sl4/EAOV7UnqUDhqsm/jwRq+
         aIqh2o5MFUURidg1PRPWbA9moDZBQq+AOvZxipH5+LZyYIYn/6ClKZmra9BNktumZZlH
         i6jO9R3/BrGkH8NV5JPKh0ts3bH/vGmXtPRdZu10IwRf0CqTCcG02XFVvd2lFTOYlP2z
         a2Bkss+sVJTSbR3hZer3y/GVUb3yjTh5jqXgb/x++m0RXs4EnCZdxiQEnk5R+k2LDUq7
         aqpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxCFFy4cepDyx6DIqz4GLTSGkK4RAr3hBvse3ASpBoa0SG176Nf
	K153Ws+vsrvb/AZEkLUzCCo=
X-Google-Smtp-Source: AGHT+IHarmBkmDcXSTKif3dTtWLqfuOaJe+NMxZzJM+NjvLQNtdR9Hc/sfs9oxQhvjbNLAH1TtBSXQ==
X-Received: by 2002:a17:90a:854c:b0:280:4af4:1a41 with SMTP id a12-20020a17090a854c00b002804af41a41mr6779278pjw.15.1700620088163;
        Tue, 21 Nov 2023 18:28:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f696:b0:285:104c:6c8d with SMTP id
 cl22-20020a17090af69600b00285104c6c8dls273452pjb.0.-pod-prod-00-us-canary;
 Tue, 21 Nov 2023 18:28:07 -0800 (PST)
X-Received: by 2002:a05:6a20:8421:b0:187:449d:a4cd with SMTP id c33-20020a056a20842100b00187449da4cdmr1714215pzd.27.1700620086947;
        Tue, 21 Nov 2023 18:28:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700620086; cv=none;
        d=google.com; s=arc-20160816;
        b=YDA0j3vQKKrUkkyhnw8IEcVd209P4fKBfer45nzpp+X3Hw54uRYhO2dFO8HtWlYd0Y
         YMbbifsjhLjT3zDPigy7osC8atYd3skfpsaqOWva9gyKlL7jYPDcalPr2o3oK69YU0aq
         PIdmBMw3QTkhCyimTOYkF5UB9deeo+pBgTV3ny8AjMkfwhLuKP7bwFE8BsxxRl25PL6P
         fk3pqTStH4kxn0oDCJkuX4rAx+5VTo8GB6Fa7J9KEHEFq/MLhbO6GIWx9p6mTbD2mg1w
         rTLY9rKtm538Vq4YMtcqyVFyZjkeGkH6rVE+TXcrff7xjhDn2rqJA57z8i1sZiV8bel9
         o89g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kfTZswEnYt7aHpTJOx6kD98hPK28QoQ/YumgrlaBkC0=;
        fh=3qba5YkzTL+bXHTu4hEoWcPGCZaYcQppgGBvzQQIBIU=;
        b=uo7hzh25KCLm3A4YXHiBgMBR2g7QkvYa/yptQc+qECy+9XklX/yBsYjWElQxAEBYK4
         e5l9e1AAPqMHmretFglHVmcYvI8OGpiq6E+001o8I+U58sHoek0RPwcV2QjWl9O4SkcL
         SlsFSF5ldLcovFp19bnSUEGFODtw4BtbNoWa+qrWpbmpIvotK4MH2a3wKMBnB5rk6/lI
         n/dY24V9TP07dD3ZPWLXkxfaHUaWKO9Gv9dck3KOsLf/2AG5gjD0xO0yHrNCtH2R/Cok
         WrjrGCA+syUx6s0KVgWxvZCjxzTe+abLZku6TX5vD0cz1TeFFc7Wyrn/Loy+T+Vo1Svj
         L7ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PkAsC8kp;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id p10-20020a056a000a0a00b006c99448fdf8si643000pfh.6.2023.11.21.18.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Nov 2023 18:28:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-5c1acc1fa98so306496a12.0
        for <kasan-dev@googlegroups.com>; Tue, 21 Nov 2023 18:28:06 -0800 (PST)
X-Received: by 2002:a17:90a:fe90:b0:280:4a23:3c84 with SMTP id
 co16-20020a17090afe9000b002804a233c84mr6491607pjb.22.1700620086495; Tue, 21
 Nov 2023 18:28:06 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752C0ADCF4F90AE8368C0B399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752C0ADCF4F90AE8368C0B399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 22 Nov 2023 03:27:55 +0100
Message-ID: <CA+fCnZfBM=UU0AyArERNMxBMeaPvbV-e6uyQDpwgqA5c6_f_DQ@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Improve free meta storage in Generic KASAN
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PkAsC8kp;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e
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

On Tue, Nov 21, 2023 at 10:42=E2=80=AFPM Juntong Deng <juntong.deng@outlook=
.com> wrote:
>
> Currently free meta can only be stored in object if the object is
> not smaller than free meta.
>
> After the improvement, even when the object is smaller than free meta,
> it is still possible to store part of the free meta in the object,
> reducing the increased size of the redzone.
>
> Example:
>
> free meta size: 16 bytes
> alloc meta size: 16 bytes
> object size: 8 bytes
> optimal redzone size (object_size <=3D 64): 16 bytes
>
> Before improvement:
> actual redzone size =3D alloc meta size + free meta size =3D 32 bytes
>
> After improvement:
> actual redzone size =3D alloc meta size + (free meta size - object size)
>                     =3D 24 bytes
>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>

I think this change as is does not work well with slub_debug.

slub_debug puts its metadata (redzone, tracks, and orig_size) right
after the object (see calculate_sizes and the comment before
check_pad_bytes). With the current code, KASAN's free meta either fits
within the object or is placed after the slub_debug metadata and
everything works well. With this change, KASAN's free meta tail goes
right past object_size, overlaps with the slub_debug metadata, and
thus can corrupt it.

Thus, to make this patch work properly, we need to carefully think
about all metadatas layout and teach slub_debug that KASAN's free meta
can go past object_size. Possibly, adjusting s->inuse by the size of
KASAN's metas (along with moving kasan_cache_create and fixing up
set_orig_size) would be enough. But I'm not familiar with the
slub_debug code enough to be sure.

If you decide to proceed with improving this change, I've left some
comments for the current code below.

Thank you!

> ---
> V1 -> V2: Make kasan_metadata_size() adapt to the improved
> free meta storage
>
>  mm/kasan/generic.c | 50 +++++++++++++++++++++++++++++++---------------
>  1 file changed, 34 insertions(+), 16 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 4d837ab83f08..802c738738d7 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -361,6 +361,8 @@ void kasan_cache_create(struct kmem_cache *cache, uns=
igned int *size,
>  {
>         unsigned int ok_size;
>         unsigned int optimal_size;
> +       unsigned int rem_free_meta_size;
> +       unsigned int orig_alloc_meta_offset;
>
>         if (!kasan_requires_meta())
>                 return;
> @@ -394,6 +396,9 @@ void kasan_cache_create(struct kmem_cache *cache, uns=
igned int *size,
>                 /* Continue, since free meta might still fit. */
>         }
>
> +       ok_size =3D *size;
> +       orig_alloc_meta_offset =3D cache->kasan_info.alloc_meta_offset;
> +
>         /*
>          * Add free meta into redzone when it's not possible to store
>          * it in the object. This is the case when:
> @@ -401,21 +406,26 @@ void kasan_cache_create(struct kmem_cache *cache, u=
nsigned int *size,
>          *    be touched after it was freed, or
>          * 2. Object has a constructor, which means it's expected to
>          *    retain its content until the next allocation, or

Please drop "or" on the line above.

> -        * 3. Object is too small.
>          * Otherwise cache->kasan_info.free_meta_offset =3D 0 is implied.
> +        * Even if the object is smaller than free meta, it is still
> +        * possible to store part of the free meta in the object.
>          */
> -       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
> -           cache->object_size < sizeof(struct kasan_free_meta)) {
> -               ok_size =3D *size;
> -
> +       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
>                 cache->kasan_info.free_meta_offset =3D *size;
>                 *size +=3D sizeof(struct kasan_free_meta);
> +       } else if (cache->object_size < sizeof(struct kasan_free_meta)) {
> +               rem_free_meta_size =3D sizeof(struct kasan_free_meta) -
> +                                                               cache->ob=
ject_size;
> +               *size +=3D rem_free_meta_size;
> +               if (cache->kasan_info.alloc_meta_offset !=3D 0)
> +                       cache->kasan_info.alloc_meta_offset +=3D rem_free=
_meta_size;
> +       }
>
> -               /* If free meta doesn't fit, don't add it. */
> -               if (*size > KMALLOC_MAX_SIZE) {
> -                       cache->kasan_info.free_meta_offset =3D KASAN_NO_F=
REE_META;
> -                       *size =3D ok_size;
> -               }
> +       /* If free meta doesn't fit, don't add it. */
> +       if (*size > KMALLOC_MAX_SIZE) {
> +               cache->kasan_info.free_meta_offset =3D KASAN_NO_FREE_META=
;
> +               cache->kasan_info.alloc_meta_offset =3D orig_alloc_meta_o=
ffset;
> +               *size =3D ok_size;
>         }
>
>         /* Calculate size with optimal redzone. */
> @@ -464,12 +474,20 @@ size_t kasan_metadata_size(struct kmem_cache *cache=
, bool in_object)
>         if (in_object)
>                 return (info->free_meta_offset ?
>                         0 : sizeof(struct kasan_free_meta));

This needs to be changed as well to something like min(cache->object,
sizeof(struct kasan_free_meta)). However, with the slub_debug
conflicts I mentioned above, we might need to change this to something
else.



> -       else
> -               return (info->alloc_meta_offset ?
> -                       sizeof(struct kasan_alloc_meta) : 0) +
> -                       ((info->free_meta_offset &&
> -                       info->free_meta_offset !=3D KASAN_NO_FREE_META) ?
> -                       sizeof(struct kasan_free_meta) : 0);
> +       else {
> +               size_t alloc_meta_size =3D info->alloc_meta_offset ?
> +                                                               sizeof(st=
ruct kasan_alloc_meta) : 0;
> +               size_t free_meta_size =3D 0;
> +
> +               if (info->free_meta_offset !=3D KASAN_NO_FREE_META) {
> +                       if (info->free_meta_offset)
> +                               free_meta_size =3D sizeof(struct kasan_fr=
ee_meta);
> +                       else if (cache->object_size < sizeof(struct kasan=
_free_meta))
> +                               free_meta_size =3D sizeof(struct kasan_fr=
ee_meta) -
> +                                                                       c=
ache->object_size;
> +               }
> +               return alloc_meta_size + free_meta_size;
> +       }
>  }
>
>  static void __kasan_record_aux_stack(void *addr, bool can_alloc)
> --
> 2.39.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfBM%3DUU0AyArERNMxBMeaPvbV-e6uyQDpwgqA5c6_f_DQ%40mail.gm=
ail.com.
