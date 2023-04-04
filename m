Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI62V6QQMGQE4TO7WXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F6F66D5BDC
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 11:25:56 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-5419fb7d6c7sf316711957b3.11
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 02:25:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680600355; cv=pass;
        d=google.com; s=arc-20160816;
        b=LV2xwFAz/ymZDuLlMxuj31zRO5wbSWufLkLXYN0YjnyzJZMxCb4BbJEcwrI8ZYLqu3
         KJy1HmA6VuaQz76S0PjR1MAfCtnXkHhQ5Rv4q8aSeHUzy8J2i1AOWrsBUuEWyu6AeZSn
         9gnYUYBAWkhQlCGukYAvM4DIl++bvlZHolPSKanXETZEpc7H9K/UV/g1tTUqGo64Wezw
         OjXCTV9FlWXENghH5vyk0dW5LSNz9q04rO9NKtrUJ4mCRYdpJ09RWzJyNPKkvbklVjWZ
         fYiThl5ayAG97V3U0ISunm2SUwPUJS8tdg9PT8VsFho5/zEeB2sO7jdjWPTdtA3XroXc
         SPUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A9S1f5Uubh8jiVaARJxm7RCl5ngOs/z79e4wGXq8TQM=;
        b=ICu27jJRuv71kHqvBh+fmSrhXDm0iB0m6oi9rkPHs5lWnPxEgOgwDu85OrPsAjiq1g
         nRVGWNBjZEIbcw7EFDuO81XsS5ckyaWBFvYr274svkhnOYv5D2KwgxLJYzFcy/2Fm/jd
         zzFkpIq0ZQ7NHjWaPq/KS5sDRiPQsfL4vB6B+1r4JKra1PKgrGmnpc3fRCs/xYV+Fw9+
         mxeSX6xDR7sSqKR8VdF754BgtdRummZmAQRJbob6TLdDsD6qh8jTVvbEiIgKjyWtKZQg
         nI3iYZcXv6koN/XAOVmWiIJA8pnnsyPsdeoYbMxMLS3Pl74JnxRaGAl2pdetelM3W5r8
         5Cfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ha74+lmM;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680600355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A9S1f5Uubh8jiVaARJxm7RCl5ngOs/z79e4wGXq8TQM=;
        b=k301+6u4hDj5hhNOKMCMXq7XobJA+DMcOofadXoENzrJ8VPbsXV/G0YjPrthqLrakO
         OicC4PMu1YV6toP1b7jv8PpFUq/jMdPkdJ0mU7H/A/dL1iDId61DHh4Pk7PQ8okH3Ghu
         1ybplQwaFsafn1Uy8Bp3YC7XakDbu/wAoqageCj6jdhiBVNoADqBBoU0aXNbtVCVTp1t
         LUHX3BWf2BIvxBzkzGCsQ+O9FAIy8AVGoXpt+oVWw83EjYCTejEhVphcrc0jGkNUSvQW
         enddqvtVEuIdltyHLSF5bD2NPbwPUzATWvd/x3smI50+XCVQvZz9Wm/OjBUJEeg07fTe
         1GCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680600355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A9S1f5Uubh8jiVaARJxm7RCl5ngOs/z79e4wGXq8TQM=;
        b=xTbYP6RJqj/MzxfMMovmmDMZPz45ngDDV6OAvNsrAX+p2ccOBXaGG9E+pq/342dXGg
         EsiEEcaca+Hddx8ZfkKVntH7b9+FIWx5lH/UzTCQTHAkfspYEdy7uSeTclEU8LJTFLqG
         Va7prfQ3TcRubc9eu6gWQQYs1oaJxcfirkb3lLZz8kcsme8LEhFaS6s1DW1LG1N3Kyd4
         fpw3wdwNzKK4N/LQdUMACipimJGDLdnN5nYYD5f2Vd9kYgpjOWROJQJmoy5IVJ1FZO/W
         q9dXO+0rSLDdDke4emtAyIMpY5A1wshBY3sGk52xQsW5oua4YB4VVM6wRpMoDqcRLAbw
         VI5Q==
X-Gm-Message-State: AAQBX9fnE3De6Y9ROkzK1s2iQvIo+14pBibomneLa0W/wQgytpnAY6hT
	VKdgTmeXEdvGoGLI9CHMFmM=
X-Google-Smtp-Source: AKy350bbkKQu2vZmgIHtdj11Uzyk3P4BBrxqRknRkfOSeMk6ehEQr+keOAPHmm5CWpd3cQ7fpFBSxQ==
X-Received: by 2002:a81:ad0b:0:b0:544:b7ff:b0df with SMTP id l11-20020a81ad0b000000b00544b7ffb0dfmr1199895ywh.2.1680600355402;
        Tue, 04 Apr 2023 02:25:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:543:b0:b7a:4d20:a84f with SMTP id
 z3-20020a056902054300b00b7a4d20a84fls9264628ybs.3.-pod-prod-gmail; Tue, 04
 Apr 2023 02:25:54 -0700 (PDT)
X-Received: by 2002:a25:51c2:0:b0:b72:841e:9e79 with SMTP id f185-20020a2551c2000000b00b72841e9e79mr1966771ybb.14.1680600354828;
        Tue, 04 Apr 2023 02:25:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680600354; cv=none;
        d=google.com; s=arc-20160816;
        b=cuf79QMjNnxfGaPHY8OyS1OvFMVqE7HnVfIzwDlDsHAXuTB6kzZf1/XIuQjTNQ2i+Z
         W1X2JProXgpV60hBKk2o9TL4c8t11/WOrGywgMtoqfc5E7glTGu5aVDj3ypLOZDYKh7b
         MgCb8jwGu0CpL9vPA63yJ4PqRKE1XIytxMTm1At3H15i2aemhud1hBUNKadT7YioZp9G
         2CWNWIb7XsD0b1St3qmGiYpeFMcjNoj4XQXNBHERwBRbhzy5kZI7U+LYlOLmplqwn3KV
         8GNsfrICTHNroU2SYAlmBW4iSNPfxvTPZuO9pgWuOClCZIkqKNPd1AGv+AeFlJNKk4Bo
         E+FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zj3a2MYNbkCFssTfjIF9gvNI8FfTYBgR4BuPPz6nhXc=;
        b=fE9RA0GptmmqcC2tZpMNHUGU3kAyzeWEuCDxPOeSGUUQ+g5KPvFQ+fv04rjnaTsJlf
         87jQ94/X3PAQxvIFUE5C9GE15FgWhnARbvkRSyNnGZd86dkr/m9RCK7cJEU5u4A2tLnA
         IbrEmjnrzwl3E3FRI5Pol4r3Y/8nVXhkl/fktpRD8cMMPLZBgJhukHQGdlP+OJp/es+G
         9Ps7aWQwFI18s4UijiygV5094tfxENhxUt6l6GYJGph716nEkmH9s23AMcLnAAjAUOcl
         xJWTHP52hz4JE2saNufoWRWOvxd+kjwiWA/pDhVI3nu8/xHJYyv4TQu4cTTjrWz06hGO
         3sxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ha74+lmM;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id ck3-20020a05690218c300b00898c1f86550si932427ybb.4.2023.04.04.02.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Apr 2023 02:25:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id j7so37898195ybg.4
        for <kasan-dev@googlegroups.com>; Tue, 04 Apr 2023 02:25:54 -0700 (PDT)
X-Received: by 2002:a25:2605:0:b0:b87:8580:ee37 with SMTP id
 m5-20020a252605000000b00b878580ee37mr2158593ybm.60.1680600354405; Tue, 04 Apr
 2023 02:25:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230403122738.6006-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230403122738.6006-1-zhangpeng.00@bytedance.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Apr 2023 11:25:17 +0200
Message-ID: <CAG_fn=UEah3DLYm2yKxBKg=L=Qc_PSnrKhZ2==snbw05XAtVZQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: Improve the performance of
 __kfence_alloc() and __kfence_free()
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ha74+lmM;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> +static inline void check_canary(const struct kfence_metadata *meta)
> +{
> +       const unsigned long pageaddr =3D ALIGN_DOWN(meta->addr, PAGE_SIZE=
);
> +       unsigned long addr =3D pageaddr;
>
>         /*
> -        * We'll iterate over each canary byte per-side until fn() return=
s
> -        * false. However, we'll still iterate over the canary bytes to t=
he
> +        * We'll iterate over each canary byte per-side until a corrupted=
 byte
> +        * is found. However, we'll still iterate over the canary bytes t=
o the
>          * right of the object even if there was an error in the canary b=
ytes to
>          * the left of the object. Specifically, if check_canary_byte()
>          * generates an error, showing both sides might give more clues a=
s to
> @@ -339,16 +348,35 @@ static __always_inline void for_each_canary(const s=
truct kfence_metadata *meta,
>          */
>
>         /* Apply to left of object. */
> -       for (addr =3D pageaddr; addr < meta->addr; addr++) {
> -               if (!fn((u8 *)addr))
> +       for (; meta->addr - addr >=3D sizeof(u64); addr +=3D sizeof(u64))=
 {
> +               if (unlikely(*((u64 *)addr) !=3D KFENCE_CANARY_PATTERN_U6=
4))
>                         break;
>         }
I am confused. Right now this loop either runs from pageaddr to
meta_addr if there's no corruption, or breaks at the first corrupted
byte.
Regardless of that, we are applying check_canary_byte() to every byte
of that range in the following loop.
Shouldn't the two be nested, like in the case of the canary bytes to
the right of the object?


>
> -       /* Apply to right of object. */
> -       for (addr =3D meta->addr + meta->size; addr < pageaddr + PAGE_SIZ=
E; addr++) {
> -               if (!fn((u8 *)addr))
> +       /*
> +        * If the canary is corrupted in a certain 64 bytes, or the canar=
y
> +        * memory cannot be completely covered by multiple consecutive 64=
 bytes,
> +        * it needs to be checked one by one.
> +        */
> +       for (; addr < meta->addr; addr++) {
> +               if (unlikely(!check_canary_byte((u8 *)addr)))
>                         break;
>         }
> +
> +       /* Apply to right of object. */
> +       for (addr =3D meta->addr + meta->size; addr % sizeof(u64) !=3D 0;=
 addr++) {
> +               if (unlikely(!check_canary_byte((u8 *)addr)))
> +                       return;
> +       }
> +       for (; addr - pageaddr < PAGE_SIZE; addr +=3D sizeof(u64)) {
> +               if (unlikely(*((u64 *)addr) !=3D KFENCE_CANARY_PATTERN_U6=
4)) {
> +
> +                       for (; addr - pageaddr < PAGE_SIZE; addr++) {
> +                               if (!check_canary_byte((u8 *)addr))
> +                                       return;
> +                       }
> +               }
> +       }
>  }
>
>  static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size,=
 gfp_t gfp,
> @@ -434,7 +462,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *=
cache, size_t size, gfp_t g
>  #endif
>
>         /* Memory initialization. */
> -       for_each_canary(meta, set_canary_byte);
> +       set_canary(meta);
>
>         /*
>          * We check slab_want_init_on_alloc() ourselves, rather than lett=
ing
> @@ -495,7 +523,7 @@ static void kfence_guarded_free(void *addr, struct kf=
ence_metadata *meta, bool z
>         alloc_covered_add(meta->alloc_stack_hash, -1);
>
>         /* Check canary bytes for memory corruption. */
> -       for_each_canary(meta, check_canary_byte);
> +       check_canary(meta);
>
>         /*
>          * Clear memory if init-on-free is set. While we protect the page=
, the
> @@ -751,7 +779,7 @@ static void kfence_check_all_canary(void)
>                 struct kfence_metadata *meta =3D &kfence_metadata[i];
>
>                 if (meta->state =3D=3D KFENCE_OBJECT_ALLOCATED)
> -                       for_each_canary(meta, check_canary_byte);
> +                       check_canary(meta);
>         }
>  }
>
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 600f2e2431d6..2aafc46a4aaf 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -21,7 +21,15 @@
>   * lower 3 bits of the address, to detect memory corruptions with higher
>   * probability, where similar constants are used.
>   */
> -#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(add=
r) & 0x7))
> +#define KFENCE_CANARY_PATTERN_U8(addr) ((u8)0xaa ^ (u8)((unsigned long)(=
addr) & 0x7))
> +
> +/*
> + * Define a continuous 8-byte canary starting from a multiple of 8. The =
canary
> + * of each byte is only related to the lowest three bits of its address,=
 so the
> + * canary of every 8 bytes is the same. 64-bit memory can be filled and =
checked
> + * at a time instead of byte by byte to improve performance.
> + */
> +#define KFENCE_CANARY_PATTERN_U64 ((u64)0xaaaaaaaaaaaaaaaa ^ (u64)(0x070=
6050403020100))
>
>  /* Maximum stack depth for reports. */
>  #define KFENCE_STACK_DEPTH 64
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 60205f1257ef..197430a5be4a 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -168,7 +168,7 @@ static void print_diff_canary(unsigned long address, =
size_t bytes_to_show,
>
>         pr_cont("[");
>         for (cur =3D (const u8 *)address; cur < end; cur++) {
> -               if (*cur =3D=3D KFENCE_CANARY_PATTERN(cur))
> +               if (*cur =3D=3D KFENCE_CANARY_PATTERN_U8(cur))
>                         pr_cont(" .");
>                 else if (no_hash_pointers)
>                         pr_cont(" 0x%02x", *cur);
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20230403122738.6006-1-zhangpeng.00%40bytedance.com.



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUEah3DLYm2yKxBKg%3DL%3DQc_PSnrKhZ2%3D%3Dsnbw05XAtVZQ%40m=
ail.gmail.com.
