Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB2G5R22QMGQEL5WIPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8597293D4DE
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 16:12:59 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-369bf135b49sf1094294f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 07:12:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722003177; cv=pass;
        d=google.com; s=arc-20160816;
        b=n9PvT8lDXI0bZDo6J+nbSQqCxB2kcjBBMMTIM+AW/MjMwtbhgOVABTAWCVPzYr7lDH
         k1dUrJHPLEUVuPLZXv3iNWax+c/ut7FsJATPLs7stbkBQdiD6DnBLqFQRa/JbPgft0CP
         McHnxuL4nfwWsGdAUD9opiBJ2nZCQMnE/NciyviuYHqvm5zsfEOhKZR2Cm6CDs6ZaPrJ
         E8PO5+AaztkZvMwM5HimfggMiKBL/05JaZafofVECID5SjQ3G+8vppNRWxgbre3fmn/8
         /QB+wV2yBBs5bZ+PLc3jm9eSy9vR9H6/RSjuKauMyaTHvLYe2DV72Mcy7p7W7auII9nH
         U5zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pqtCEcYftFzU4DZa/0J8jm63HwtnD22XkHGs8aAXhVU=;
        fh=4Lj+mWVqHKnZlEGPO2lhFYwJlzud+el1zPY/JfMsvdA=;
        b=K7T+uYb9nTKhZWwRk/+3k0per7MlM8rmdeNCMhXqImKBgmENl8NKaTCOMZKJpmRNrY
         UXOswJMcDxFocSdeHjD4+GJkTTHJ5p2Iy95vFqe9aRjzODc5jFafjmvQMSXCGOC+lbQc
         l14b5ofj5c7nUvauninVsg6rDOhQhWrHAbbGwVv1OEiIdniJZ7DK1vyMqZWYOt7AOIWD
         K+bZH+oRK406JFkNGvyO81tgOxhKzjwwHmtFpK4Dx/t4wtqU32xFReEPBDYQZwP8F6xI
         M2UwQJ9RuL9kXMRavLE9YQuaRe2l11rlzKJVFWY/Xv4SuUt7T+LXRrcATjwBx6QrdURS
         dEdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EOuIhqYS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722003177; x=1722607977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pqtCEcYftFzU4DZa/0J8jm63HwtnD22XkHGs8aAXhVU=;
        b=lMxDiVt0RjYOTlcQ6eQXhTczpYsYJZMa+Z79zfi5a6AA9taJPK6hfu1qwYOAaSrweU
         4PLsAmyIed6adLYcQ7sVkHZ70DRu6ITGNiQbcyvrq9uWSXuewvuk2upxlkj33A03NNHz
         LAz/OLI2LZqtvyQBBQLIXptSqHMqlH+29KNo+SY3ANh4y905dn0VAKGuQx43QWnuZJz7
         hcaJ/Bhl3f8Tc90Ob/pAZuiA2JebjIQrcwr+sxhm2G2gjcBIAigpHDFc1dRv29R1EpWj
         lTsEGhKdusaxAqIrhmHk1l3dYlk3B5JbQr64GGMoSuSHM3NAHXsZz+ld3bB7cyASevhn
         ryRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722003177; x=1722607977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pqtCEcYftFzU4DZa/0J8jm63HwtnD22XkHGs8aAXhVU=;
        b=AqrynnrnOEl0WOFoeavKUp2fIRcpLHJQguI3z9XJizd2oYSPTlw3jvUGcieCwywYZA
         NVS69Zo3oBIRXNuTe47Ukq5zVuVU39P0y/TRAVJmcVum08QX/Uri9bqO9T8NcoLnZMWQ
         9jNT7/pmOjFhwEVE8LVQ/z1vViVNXjmCrUhm9+HRsxTy3YDhfPtnP91qGWsJdHMB9kCV
         y6pMnRWP+xMNowjA088tMcDds+B2rQBMYSkuBedl4ufOvkdLit0Uxe94Tlhgv1fdemiZ
         5fD6ewbnyYGz8DaYgAMHGIO2evcX2tEgXTw7QcQUU5bHjLYCnKld/k8pHvd4kZbRViPl
         YbpQ==
X-Forwarded-Encrypted: i=2; AJvYcCVeIL5SnZ4ROoCJH/C3Pxoc86YwG+gD+X19AT+H4UeuMeSQMvRuMwz1kZspQD68IKaq/sGtwZAbitPFOvSGeSooaNvQ1efrLg==
X-Gm-Message-State: AOJu0YzlxQou2+ttgT9xOjwLg3VQYpPjGn3LGFe32EICUz9zckRclhfh
	nhyv80frp4avRHHOkpGd5kRjmsMr5Tu26TOpA8XzN8G0UYJS+fc8
X-Google-Smtp-Source: AGHT+IHFRJN7Z5x8Nm2rK77bzAS1NAJnETgzr21AJGBGXNahn/5jUqAn7M3HQCSVFaI3H3BEMOREhA==
X-Received: by 2002:adf:f9c5:0:b0:366:df35:b64f with SMTP id ffacd0b85a97d-369f6667e81mr6757355f8f.4.1722003177140;
        Fri, 26 Jul 2024 07:12:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:510d:b0:428:1081:6352 with SMTP id
 5b1f17b1804b1-428108165e9ls641615e9.2.-pod-prod-00-eu; Fri, 26 Jul 2024
 07:12:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJook/AwtTOZ5jZBH60e6+Rb5V6mnqvz2npcEifOFYw6YTddwMEr3h+GyvzhoHNOk7h+iAZyiD7jqJSe7sDf3aqsg/k4yMCw5Tbg==
X-Received: by 2002:a05:600c:42d1:b0:426:676a:c4d1 with SMTP id 5b1f17b1804b1-42803b01f15mr44784285e9.8.1722003175481;
        Fri, 26 Jul 2024 07:12:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722003175; cv=none;
        d=google.com; s=arc-20160816;
        b=p8Pnu0gFPb/Yw3LjsA/NpiZCCydODQmuectRw6mqtHVwfZU/rRVC0cPTyZLdV6fQGj
         /zlXG6hNvcHEL5qqqsP+mCTk0kUXAat6rAL1Bf+7H679lILFXbjGLVqBBbPyY17kMIIJ
         5nB7iZ7rVmhQjM47MH+LnY7zaOr06XCNBNhAn+xkbm+UVeGmyWVf04KjAOjaarkvN7D+
         AizmCVKHoiKK2L5ASq3+hX1jREYsO83qjw+lNXKWFxRnLxCIZ+WsMh1ecONy8/f0pcQd
         FNXH2CxE4v/HQq+I26r116MlL1JG1Z3ZMYMzemxYpsn9/HPeQQFEy1Xl58zcsj6vGFpe
         VeUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QsYsv/ZNLS2uwAP6W4x6DqGmZNcJZ9nt2gTTMFgcvkc=;
        fh=X9KUm4bIaX1bhJcQVLkvzR98knz7RxrtIRCbzIEW4W8=;
        b=lxqZ+66kl4GTcHmbYLwNlRN9wHCgW0IC47au5xDqB+fcnEVYn7l1qgxxej+Nr1lCKz
         W/p5TBPZd4mV9xW8nxxuxPRx1jeQzeLdKrLJpjeHhDoxYjpVE0npZcHGXoj6WXwNBrbc
         Cjg3QHL+ZWjkD9q1PpeX6plI24CBPTnWMBAID5dArVB0GS0P8pMKVFtPxYB2nEgSeUu1
         vmG7zFf/a5EiedekvJ6k0ennPtlzxcdSbPvHkPMKbEfahHhOY5DFmFh2OZkDQn9jH/jF
         9H3xyj8uKlWkce4jykuwueLIeqx/V6wKRItEEN8xGjmslCy05U9S3G2lnrZbOY+yjkDA
         dw9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EOuIhqYS;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427f1f6e8f0si4045195e9.1.2024.07.26.07.12.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jul 2024 07:12:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso15702a12.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jul 2024 07:12:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAirhqCGb8MJy0E97iQ4+fWI1fBbzm/UiT2Qru4dosDRAYFc3cV0EikGS/La0KIwnN+Gdt4tUeMWCv9IMq9sHOTWqklZccFPpCDg==
X-Received: by 2002:a05:6402:524f:b0:59f:9f59:9b07 with SMTP id
 4fb4d7f45d1cf-5aed9392d97mr171742a12.4.1722003174333; Fri, 26 Jul 2024
 07:12:54 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com> <CA+fCnZc1ct_Dg7_Zw+2z-EOv_oC4occ-ru-o6-83XYQneBxpwA@mail.gmail.com>
In-Reply-To: <CA+fCnZc1ct_Dg7_Zw+2z-EOv_oC4occ-ru-o6-83XYQneBxpwA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Jul 2024 16:12:17 +0200
Message-ID: <CAG48ez3FES1ySuuv9VtDqCxEfw7xPqdvOd4oTEdQ25+1NvSAsQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EOuIhqYS;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::530 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Fri, Jul 26, 2024 at 2:44=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Thu, Jul 25, 2024 at 5:32=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
[...]
> > diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> > index afc72fde0f03..0c088532f5a7 100644
> > --- a/mm/Kconfig.debug
> > +++ b/mm/Kconfig.debug
> > @@ -70,6 +70,35 @@ config SLUB_DEBUG_ON
> >           off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
> >           "slab_debug=3D-".
> >
> > +config SLUB_RCU_DEBUG
> > +       bool "Make use-after-free detection possible in TYPESAFE_BY_RCU=
 caches"
>
> Perhaps, it makes sense to point out that is related to KASAN's
> use-after-free detection in the option description.

Hmm, yeah, maybe I'll change it to
"Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
and then we can change that in the future if the feature becomes
usable with other SLUB stuff.

> > +       depends on SLUB_DEBUG
>
> Do we need depends on KASAN?

My original thinking was: The feature is supposed to work basically
independently of KASAN. It doesn't currently do anything useful
without KASAN, but if we do something about constructor slabs in the
future, this should make it possible to let SLUB poison freed objects.
(Though that might also require going back to deterministically
RCU-delaying the freeing of objects in the future...)

But yeah, I guess for now the config option is useless without KASAN,
so it's reasonable to make it depend on KASAN for now. I'll change it
that way.

> > +       default KASAN_GENERIC || KASAN_SW_TAGS
> > +       help
> > +         Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if t=
he cache
> > +         was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
> > +         kfree_rcu() instead.
> > +
> > +         This is intended for use in combination with KASAN, to enable=
 KASAN to
> > +         detect use-after-free accesses in such caches.
> > +         (KFENCE is able to do that independent of this flag.)
> > +
> > +         This might degrade performance.
> > +         Unfortunately this also prevents a very specific bug pattern =
from
> > +         triggering (insufficient checks against an object being recyc=
led
> > +         within the RCU grace period); so this option can be turned of=
f even on
> > +         KASAN builds, in case you want to test for such a bug.
> > +
> > +         If you're using this for testing bugs / fuzzing and care abou=
t
> > +         catching all the bugs WAY more than performance, you might wa=
nt to
> > +         also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
> > +
> > +         WARNING:
> > +         This is designed as a debugging feature, not a security featu=
re.
> > +         Objects are sometimes recycled without RCU delay under memory=
 pressure.
> > +
> > +         If unsure, say N.
> > +
> >  config PAGE_OWNER
> >         bool "Track page owner"
> >         depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 7c7fc6ce7eb7..d92cb2e9189d 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -238,7 +238,8 @@ static enum free_validation_result check_slab_free(=
struct kmem_cache *cache,
> >  }
> >
> >  static inline bool poison_slab_object(struct kmem_cache *cache, void *=
object,
> > -                                     unsigned long ip, bool init)
> > +                                     unsigned long ip, bool init,
> > +                                     bool after_rcu_delay)
> >  {
> >         void *tagged_object =3D object;
> >         enum free_validation_result valid =3D check_slab_free(cache, ob=
ject, ip);
> > @@ -251,7 +252,8 @@ static inline bool poison_slab_object(struct kmem_c=
ache *cache, void *object,
> >         object =3D kasan_reset_tag(object);
> >
> >         /* RCU slabs could be legally used after free within the RCU pe=
riod. */
> > -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> > +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
> > +           !after_rcu_delay)
>
> This can be kept on the same line.

ack, I'll change that

[...]
> > +       /* Free the object - this will internally schedule an RCU callb=
ack. */
> > +       kmem_cache_free(cache, p);
> > +
> > +       /* We should still be allowed to access the object at this poin=
t because
>
> Empty line after /* here and below.

ack, I'll change that

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez3FES1ySuuv9VtDqCxEfw7xPqdvOd4oTEdQ25%2B1NvSAsQ%40mail.gmai=
l.com.
