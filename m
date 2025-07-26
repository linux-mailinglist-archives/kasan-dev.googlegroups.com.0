Return-Path: <kasan-dev+bncBDW2JDUY5AORBUNCSXCAMGQE2HNN63A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3924EB12CE9
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Jul 2025 00:06:11 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-6083f613f0esf3256468a12.1
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 15:06:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753567570; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZUAYi2wrGGv2A9H6klnqsnkvp7gxrsQo4FPnJm3LmpeZtEqhZVS7ub4c/ia3rcCbQd
         zat7nx6/6I6YX44qCbjCxesW5PZ/js73kicFJ9zcKweaGozYcaXX1tsr6VKY9T/YBuy2
         0LdZkjXLQAYnmzpSgJkajrOgsXQLIXy8GWopDzjLOFBbzZ9SLVrnD08r8ZrawioB6O0i
         QReg/l5onE+dFMTyTu6B/RqH9/JPVTXvK3spblYU2bW5do0Z4kWQoY1b14749oFwo9OZ
         O1TjrGg3vTGpSSg3UJCuGcYkEwp6S7lKCpavygC+IqX6QRChlAntshOt6LWFZf6pHLvy
         Ad8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=bUgxF7IaS2VKxrXUIv460kCR445bo4XeJcY8QIvPwYQ=;
        fh=aIHG4/0UB0k4jixUIJLu7TB9o7gn4WoPhsvoTpgiq5M=;
        b=W5/yyHvbaGmizvBW1Daq/dsvd3gTZJFvjCjxTZZCPJQbVX/JO0du2o2RMx38U2pUdm
         VeUO6APfEi6yhhja/OmNnN/Bohj6jWR8CWN3DtS0GKubEpJMgfGp/Rn7DUmsre7LeJrH
         dVBg5nNt4/TMYWpdZBw+kIZKrPP17Z6LWJdj7vEX+kVAl3LJsuvDN/qdLvt3q8G2vQO6
         drk92BNDhBigYEkVBD5LDW/KK0FwFSRXzTrTYjbNiicoSYdcZZ9QS/WiTJ687CDJaImo
         H4VdkBvOv8OOQ/0KhodrlncPOvsQ6VuqYlqUYcrjB8A5axz92maJRPN/GrGj+ui30dur
         +q/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aZ5HyKjj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753567570; x=1754172370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bUgxF7IaS2VKxrXUIv460kCR445bo4XeJcY8QIvPwYQ=;
        b=VeqzxnB0/TrSaK2dZwEz2TGsRjfLkQ7MqM7A1gGSJeEXPWPxWE6GL/NlBjAx+NDFmY
         VDNS4x8z5GZfOaD2PXq/UXDyrZnFjlsgFLse61vq/ILcA08XtyS9fewAvFPAhOyieZmD
         +Bm+LIJqFNCK24QYH9CpO3C9VsqHF6pvy+cBJnNM99AT0DsehkRKs6lviKNCSsV1GiNp
         k4YXYq4pVTzqLS99I0S6xmjeKIvS5hGwfzWPp/+vXvCMTRSqH3j+mBCDdcrMR+SxkA2s
         mf1eyAX6eJU2Zo4zb2IYYhz9z9EB8vn2npoELdlErOxgUxFM5167fMVFM6OixHLbVT6m
         C92g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753567570; x=1754172370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bUgxF7IaS2VKxrXUIv460kCR445bo4XeJcY8QIvPwYQ=;
        b=a6y3UKO35bGR665gO3MI6/6P2CVuuD7eDqdr3OI0xlZCa228qaBIjH6jEZw8/RtNtj
         27ACvfYwC4BtHstHQkMTf0aFdlEkt08RNSHVMVs6MyjeZbilTmdkT7j2pG2Qo7xepDFb
         jqqxj6WMGDrYeyHjJLXpkIWLHkHVh0bZrxEZVaEuNUPGTEKJxdWDPkcyyYmix77FkxiD
         47ADDWJYcjzjkf/KvjafdnsHIh/Y4Com273qNeQRK7BSnbYBdD8/vy7Hb+itbgyM4C/9
         2htMeYR5ebHQbeT2TVMFcH8rETbIMjqFjtRoB7Qznv8tZPVBv86OcbZqBFDySMbaOTNF
         vlSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753567570; x=1754172370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bUgxF7IaS2VKxrXUIv460kCR445bo4XeJcY8QIvPwYQ=;
        b=ZqHrkULnYhpYjEJZYVAekpFc0mbgL1bcQd7p8zSLRAiy7lmvKK1iUElv2nui0Xp4+D
         3aze4cL/atIWkAzQMj8u/92mPLYSr13neqECjXYfdG4mt1NiU/lA60PnYPms9W3HN0Mc
         dUrcr/0TajaYyrAn7BmCQHrom6X3/rbcq8CuMJCdHmD2ucMiCqeKcXr0Zq9DY8rTQMNY
         1RQ2rd3i9BHMHN3semAyHvUplQfoIlKezIF9jKu3l5a4x1r4xP90rWTV9pyuaGvOyad1
         ea1UP9NR0MP5O2BED2zt3/WfxAEdtFSOIMqNQBxJc5wC++EaRdOGpAi03197jOFthXqE
         6igQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyzMEYA3Yk3UuYS+PXPBYZ6f8ctraInjFYm4woeKQRJavaiWSULE0TPTNbedLrXyvc8cldfA==@lfdr.de
X-Gm-Message-State: AOJu0Yzv2kh6oQJRzpuCnv7Fnzf3Gqd4+XSnUelVTuq/kRa4xJJk2FBp
	RljTqwYsrVahw2mHbgVe1Ikl6kCCZRXTXPYMkMCk7Lsibp/Dam6IbuLh
X-Google-Smtp-Source: AGHT+IGVcziDug057pJokhwHazFblFxm5A0tuWuQtOnn9ZiFJ8l5SQP7MLQNSuSjokXEmj64lgijSw==
X-Received: by 2002:a50:8e13:0:b0:612:3d0c:a728 with SMTP id 4fb4d7f45d1cf-614f1d6a985mr4748379a12.12.1753567570109;
        Sat, 26 Jul 2025 15:06:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdKI7m1qWH28R775MKPShXHuGYdmPDojumHGtOqaIOovA==
Received: by 2002:a05:6402:3583:b0:601:956f:a0c3 with SMTP id
 4fb4d7f45d1cf-614c0aa3158ls2877731a12.1.-pod-prod-03-eu; Sat, 26 Jul 2025
 15:06:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyVNtVW946BaBBB4BVlCdGzFQWEfa+57eVUMRvxQq6PVJkmyFwT/uRDcuKKvePTNCvs2F+pHF6Cpo=@googlegroups.com
X-Received: by 2002:a05:6402:234e:b0:607:20d0:4e99 with SMTP id 4fb4d7f45d1cf-614f1df6900mr5998027a12.21.1753567567155;
        Sat, 26 Jul 2025 15:06:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753567567; cv=none;
        d=google.com; s=arc-20240605;
        b=j1eU+FcZbMTPFLazNoygnG3lkqYMyGMH9D+M5cVsFWEE047qUFx/xj2gZqbIYklZPl
         vkr2IHsxVtoeOl42ZnwR0/HK8cOOBCq+aFHjE+LjQYXHKjmx4EhNXfohN5sxuxR5zLs1
         suW44glhARNUxlcciCJn1+A4nL5hJkh54nJBCeJt2rlj+uUKmSC5dfYtftXA+lb3R2hR
         A5LBczqp6v546hApjmktTiy16Q71Yy8hfUdQ6bH6woV8tCjd+FO7iH/DFKPLx5jzPpAb
         k4I7jmqIIWJ37/EO5cP6yu2L993aNc/X+SljHrxXTke56h+D/zOmxh5p8/PPETCzTkuq
         rqLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sJ0HbWh5wMU4zq+nDQgi0w5mYaeF8gFdCN3zESWgjG0=;
        fh=yCXxssgoJVP1r0YiFFyC3CAicBsZXeotAIqX6I0Lmw4=;
        b=O3QqMyliwCryXAlSy1YPMgdCcwvs4fVpNOFFDKfidoaGKnEYKOY74QkcKfvG6/e/Dz
         oP8Qlk1QH9Xx2IEfnk/peoh8DxFgCi37fHfVtG5sQxu+oht+mr3EejXjBfYH+zjqShgf
         vcVEf00C1OF397d0+uR9GL9wbPDST4iRq5aGFjPrcwkpts1Bclh+T8OXNrxVlsDpRUcT
         kHo67ajoPS0xyKp9He1dfe5oXonqUtZnHou5WoAuM5MFNN0XcUZthIDImS8syh6fgJbB
         aLlCk0/2A3h0h+0o+QuLJ191sAlv+3uYislLKdk90TKLIxTvMeM3+D6hzSk/wz/xPKyf
         yfmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aZ5HyKjj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61530cd9882si337a12.5.2025.07.26.15.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Jul 2025 15:06:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-451d54214adso21137575e9.3
        for <kasan-dev@googlegroups.com>; Sat, 26 Jul 2025 15:06:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCfLyaY1DChrpxNZuy8PYLd95ZH99WDKvWY67KWD1e8d7+wJFczsO3/V6B51s/d/lMg2lzDHvOWgM=@googlegroups.com
X-Gm-Gg: ASbGncuG4iRVfsoSIVMYCTH7lBIxUQlDPecdcBC5TqR2Z/qHC3KtM/SUKJnC3o1o2Nv
	A9J9WLU6M2HxL+rpsyi5j+zY+SAvCdRzXypNrOcZm9532NWKO2kMynr689ZPsntWKseJwmOCtuo
	OEomHarydB868e5IaC6w3IsYzlzY4k8+rlP4J7hMVeV17ztvd4TUOthpooirmjGaiDWRTkx+1Ho
	LQ1WXFG
X-Received: by 2002:a5d:5886:0:b0:3b6:18be:3fbc with SMTP id
 ffacd0b85a97d-3b77671d232mr4837781f8f.2.1753567566495; Sat, 26 Jul 2025
 15:06:06 -0700 (PDT)
MIME-Version: 1.0
References: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com>
In-Reply-To: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 27 Jul 2025 00:05:55 +0200
X-Gm-Features: Ac12FXxVMLsmLFrJvmkI7l9TDJQ09BGxwghdFh3bJQfvTulVExlWwMj6B4rNIpk
Message-ID: <CA+fCnZcyh52CqY+XDMMjc6f5KQoaji=7KiFM-6+2NidjfyNVGQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: skip quarantine if object is still accessible
 under RCU
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aZ5HyKjj;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 23, 2025 at 4:59=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Currently, enabling KASAN masks bugs where a lockless lookup path gets a
> pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
> recycled and is insufficiently careful about handling recycled objects:
> KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarantin=
e
> queues, even when it can't actually detect UAF in these objects, and the
> quarantine prevents fast recycling.
>
> When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
> CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
> after an RCU grace period and put them on the quarantine, while disabling
> CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediately;
> but that hasn't actually been working.
>
> I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
> could only trigger this bug in a KASAN build by disabling
> CONFIG_SLUB_RCU_DEBUG and applying this patch.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  mm/kasan/common.c | 25 ++++++++++++++++++-------
>  1 file changed, 18 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed4873e18c75..9142964ab9c9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -230,16 +230,12 @@ static bool check_slab_allocation(struct kmem_cache=
 *cache, void *object,
>  }
>
>  static inline void poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     bool init, bool still_accessible)
> +                                     bool init)
>  {
>         void *tagged_object =3D object;
>
>         object =3D kasan_reset_tag(object);
>
> -       /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(still_accessible))
> -               return;
> -
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
>                         KASAN_SLAB_FREE, init);
>
> @@ -261,7 +257,22 @@ bool __kasan_slab_free(struct kmem_cache *cache, voi=
d *object, bool init,
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init, still_accessible);
> +       /*
> +        * If this point is reached with an object that must still be
> +        * accessible under RCU, we can't poison it; in that case, also s=
kip the
> +        * quarantine. This should mostly only happen when CONFIG_SLUB_RC=
U_DEBUG
> +        * has been disabled manually.
> +        *
> +        * Putting the object on the quarantine wouldn't help catch UAFs =
(since
> +        * we can't poison it here), and it would mask bugs caused by
> +        * SLAB_TYPESAFE_BY_RCU users not being careful enough about obje=
ct
> +        * reuse; so overall, putting the object into the quarantine here=
 would
> +        * be counterproductive.
> +        */
> +       if (still_accessible)
> +               return false;
> +
> +       poison_slab_object(cache, object, init);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
> @@ -519,7 +530,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigne=
d long ip)
>         if (check_slab_allocation(slab->slab_cache, ptr, ip))
>                 return false;
>
> -       poison_slab_object(slab->slab_cache, ptr, false, false);
> +       poison_slab_object(slab->slab_cache, ptr, false);
>         return true;
>  }
>
>
> ---
> base-commit: 89be9a83ccf1f88522317ce02f854f30d6115c41
> change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24
>
> --
> Jann Horn <jannh@google.com>
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

Would it be hard to add KUnit test to check that KASAN detects such issues?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcyh52CqY%2BXDMMjc6f5KQoaji%3D7KiFM-6%2B2NidjfyNVGQ%40mail.gmail.com=
.
