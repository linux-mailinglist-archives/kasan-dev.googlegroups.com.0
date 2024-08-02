Return-Path: <kasan-dev+bncBDW2JDUY5AORB7HJWS2QMGQESSXN5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E66C9463F8
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 21:35:26 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ef21a82381sf24292311fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 12:35:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722627325; cv=pass;
        d=google.com; s=arc-20160816;
        b=eo0yoXeE3OBk36QR3o+6HdQroJayizMAJyAOMhc7LgR5Ohd4zi0ZU1Egp3daIq6Ane
         VCp6P8ko685xDFesBqhAwWrtqUvBYv58SZXLxHgc2HPb0PkRdw8PNfaLaEL6lW/6V1Gb
         oFC/OXd1TMB2DWMwNTQY2SvWGBzF3rkpnvTIPkbI6n+7XplexDVsG/F83ngt/HSvsS5B
         DeD5APyNJ5HfW+qAgSJtckDA749D26jUGjmQT0luuE6enal5+NX5Pc8e8rFD4ZCC8O/u
         n3bSLJ2zJzjQ6WFtNZ5HfP/TbbeaWTDTp5eUx2p5J/qjbEoRRrpELmKh0b3aZeCUouYj
         NwGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=L4dtBk+TpJ4U2MZ0CGVbOwEqFO9k+aZ8csWU7mxdgCI=;
        fh=WjQ3UAaZr/z/thkOj0msvAsTjoP5XBJmXg2k4wa6lpc=;
        b=URYhtkoKaZRkbjIJbuCKPvc8zYAbGkSe1BE0HT+cjVGi0lo4rVPOyDWMORWEMgFy1K
         2OpOQJag+VcPEL5MlpCh57rMmdziGp5ueuvGFGc3MHyWgmHXs350h13ZRwMlVqhU/wtx
         JEK6If1cVaUJL4iuOkVAUumNwHtnbTZBC9wulbJJoJXtvXHlc+aW3gC8ra8c2QncLb++
         YWHXJmSVLnBn29kmkVygRZ6p848UmZtJvwi2pBm23D/FZR6Vg5RCjMWvCiurt6VzlDYq
         tNa+RzvzAfNtB0gq8CZutcZuoNv3lwuW/U5rYGPCSyb2SQXsSpuoG4nJFolQ99+ULHl2
         3PeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H1+WepK5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722627325; x=1723232125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=L4dtBk+TpJ4U2MZ0CGVbOwEqFO9k+aZ8csWU7mxdgCI=;
        b=ofS6lCJBSvqSv01Ee74gkT2ZAkGopor6n3nH0P5+7GyJXfbdRbFy5FYDwP4JaZGuUY
         qjKqnN6KDoPNdhF4kbb6Ahof6mudE1nIOFUMZ5ncRLlYphIs1zJt7eLkd6Ybn2fdpyxP
         PTuEpmDaasf+QPS0Gs8+Ffy/pngyBw7VQ667ffrKipnOLZkqKaZgslXnn5WcPErKXKbg
         cZK0A66gxAbNmPTJuA7dwMBmlpytZG8FbJw1YuuKnP65wJvyK9iS7e+VifbBsw88idz/
         n8x89qtqgB+wTqTvvUUcs1QnCoOQz3iyV97Tq1NEKFBdIugSiV9CseNHbShfixcb+3Fm
         d4Sw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722627325; x=1723232125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L4dtBk+TpJ4U2MZ0CGVbOwEqFO9k+aZ8csWU7mxdgCI=;
        b=Z1uRXd0P513JnPdPanLTIOwWKM6b4O6m6dxH5x/YzwMQMATiDlQYKwASVxrj3VAdMV
         BbNUS1XW+kmFvE7tB7x3j5CzixhJo/0zQawKy8x4EjlcjJknytM66bbyS8lF+oZ6ZfK2
         5k4gu30kwtEime5NSroUMOGpObGUxEGYN7rq3Szj6ITwjKL2C7D0uaXgfDyB0fLMi805
         uMKKWPXNcEuS/KAamRjnkCko+zcq5sOChvudcIGSOqMGD6nb5i/GhKMImp/mtwis/Nst
         JoQ/6SVQUuC3H8DgpLYGhaA3asHtOT2mx+Vi40+RWrOwbeD2XNqwnGNrS756WF1QC1t2
         AfeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722627325; x=1723232125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L4dtBk+TpJ4U2MZ0CGVbOwEqFO9k+aZ8csWU7mxdgCI=;
        b=DF0G86nAbFzB9E9pHCfV14/pAXK5brJ1wH9pwZ5oRAQVYyjGdJHiMvVfRBooKLGvx9
         L1kgoARFFboc6jcwhthzHGQRgUosTKK0ca8x0keOhIpdGpyfQnFze9boiwC5R1usjbck
         mzwrj/2MhmRDnw7ImtnUrT82mEMkRsHx1jchFIaLdPsP6Izh8z5EsCRWlT/GSLqXkCTV
         882TSAi8tYPi66BRpOoOG+sGFgbb/W7SpV/CdRqvXCkn+Q/pXSaamGXhOQNB81pQADwH
         2r5mUMphAzYMXqdB2fDXLSEuZUoQvSyyYeOidLgDNDMnkGDvpTpKL0e9ZJZCbpCb56up
         wRYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqaXczxSletDhUssX7MKjCk2yI/22S6jzKpvRquUFQ0SNtjywANBzDZ0K5PNGbS8dPLG6K5iQiI4szTTxVey7U/bscnVGpTw==
X-Gm-Message-State: AOJu0YzN+OhM79vvRTrBzruCW0xcleaSkPLHhU1uDXDc85it+gs+Ouel
	ORKfqO1F6EA0/zlOH21aPDvDhqLZgH+aNM+MtdC5Vafzzy7wb47m
X-Google-Smtp-Source: AGHT+IHzF9XzHIhOGSpJAcW4dHXCdg3gnkqrfW3ge6CCbH+jOz5KgABT1YBE5yORSZFCoFsMThyAEg==
X-Received: by 2002:a05:651c:2129:b0:2ef:334e:7c36 with SMTP id 38308e7fff4ca-2f15763ac2fmr21447701fa.6.1722627324835;
        Fri, 02 Aug 2024 12:35:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2281:0:b0:2ef:2b5b:5a6f with SMTP id 38308e7fff4ca-2f16a30e54cls578491fa.0.-pod-prod-00-eu;
 Fri, 02 Aug 2024 12:35:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVut+HwxPi0QGGmM+7PodRPLgR8T/t8oe+QXEvuizYfl5hyh6Qd0W4m4CuOwpuDU6+7Zac3MzGyX7sSWPUD930iTPjY8vR+WDDhXA==
X-Received: by 2002:a2e:9004:0:b0:2ec:347a:b020 with SMTP id 38308e7fff4ca-2f15b13c649mr12342241fa.12.1722627322760;
        Fri, 02 Aug 2024 12:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722627322; cv=none;
        d=google.com; s=arc-20160816;
        b=Xgi6VEoGzTSGZhWRoLejGN3F2soCuy3nolk1z3M71e7TQ25iK1vxAgM9H2dUHdAIUO
         S8oVKCg0MkZF8W3RF6UEWmWUxkjS4aTnUcbVjxoxW4miOt2hyo1+tpg4vx0j4SasluzU
         G3CuP6yRYVUMVJA3o5g2jDjA5OFLlIkSjj5Pghwjm81FPxP0RQSs6j/n1cI2NA4DqksR
         iiPS/8Cg6EiG57DISyilKykU9nPyrtb6zmXgXGlCC3EhfgUbJtEPZvSdwan9pgLmkCCF
         nB7pHtlB6pX9AYRkZPqX2tJUkpAxSo1j5pIAK7bytOFAca+dI6ayvOktfWhmb1B5p5eM
         P4Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hYUx5VYfzdcL2cZbcEL5FqwVX5ykzwG2TQHVubtZro0=;
        fh=3P6+M8RVcfIVOABxWPGGbkYyJauwTTa6sOgNbRmrRPo=;
        b=wwtJujz6VdXAuITwe1SPz7tAJVP7v7xKPVz5ZdaFOfilP6buaRAFzvIxhke2hLH2/h
         H6MKrafY+nJ5FhqQMhVZaKhjFZhGiQ9st7/0fGmc7NsYdlh0QOw7isvuG8IS29B82g93
         WsbbrbRbKXnZN+EuepuTcvYzad7Q8jdsz+6Gk4dzPqo6B1t4pNaTquf4HAK7hTGMsoWM
         lQVnq0TsfUTS3KvtB1aDVrdxDxOsXGUxKcO0L1+E1V1c+vsBs+h4zhyjjm2E7GFP4ttb
         IuocxIw+GO1DMDFazPdZDmSe0h7IQLF1aXENNPstqnEacM60WLqfNvCD9zILNS8FQE79
         GiAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H1+WepK5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e291dbasi504221fa.7.2024.08.02.12.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 12:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-368313809a4so2095207f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 12:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXx9NL1wDKKRi4wW3C5FZtjRr00t7AyOQj3tDYdb/hp7R7sKPskcKS+68S8evTQRYj1Jq+U1tfVGNOPhkEX9VCtTQlJv/BNebCb1w==
X-Received: by 2002:adf:ef4f:0:b0:36b:c65c:661e with SMTP id
 ffacd0b85a97d-36bc65c66b1mr1411494f8f.13.1722627321544; Fri, 02 Aug 2024
 12:35:21 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com> <CA+fCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH=Zg@mail.gmail.com>
 <CAG48ez1guHcQaZtGoap7MG1sac5F3PmMA7XKUH03pEaibvaFJw@mail.gmail.com> <CAG48ez2bqYMPS2D7gFZ-9V3p3-NJUYmYNA113QbMg0JRG+pNEQ@mail.gmail.com>
In-Reply-To: <CAG48ez2bqYMPS2D7gFZ-9V3p3-NJUYmYNA113QbMg0JRG+pNEQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 2 Aug 2024 21:35:10 +0200
Message-ID: <CA+fCnZdNWPnjSvPF5dg0NA+f8y=rtxtbDC13cZJCz+rQVb=ouA@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
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
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=H1+WepK5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Fri, Aug 2, 2024 at 1:23=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> On Fri, Aug 2, 2024 at 11:09=E2=80=AFAM Jann Horn <jannh@google.com> wrot=
e:
> > I guess I could also change the API to pass something different - like
> > a flag meaning "the object is guaranteed to no longer be in use".
> > There is already code in slab_free_hook() that computes this
> > expression, so we could easily pass that to KASAN and then avoid doing
> > the same logic in KASAN again... I think that would be the most
> > elegant approach?
>
> Regarding this, I think I'll add something like this on top of this patch=
 in v6:
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b63f5351c5f3..50bad011352e 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -201,16 +201,17 @@ bool __kasan_slab_free(struct kmem_cache *s,
> void *object, bool init,
>  /**
>   * kasan_slab_free - Possibly handle slab object freeing.
>   * @object: Object to free.
> + * @still_accessible: Whether the object contents are still accessible.
>   *
>   * This hook is called from the slab allocator to give KASAN a chance to=
 take
>   * ownership of the object and handle its freeing.
>   * kasan_slab_pre_free() must have already been called on the same objec=
t.
>   *
>   * @Return true if KASAN took ownership of the object; false otherwise.
>   */
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
>                                                 void *object, bool init,
> -                                               bool after_rcu_delay)
> +                                               bool still_accessible)
>  {
>         if (kasan_enabled())
>                 return __kasan_slab_free(s, object, init, after_rcu_delay=
);
> @@ -410,7 +411,7 @@ static inline bool kasan_slab_pre_free(struct
> kmem_cache *s, void *object)
>  }
>
>  static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> -                                  bool init, bool after_rcu_delay)
> +                                  bool init, bool still_accessible)
>  {
>         return false;
>  }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 71a20818b122..ed4873e18c75 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -230,14 +230,14 @@ static bool check_slab_allocation(struct
> kmem_cache *cache, void *object,
>  }
>
>  static inline void poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     bool init, bool after_rcu_delay)
> +                                     bool init, bool still_accessible)
>  {
>         void *tagged_object =3D object;
>
>         object =3D kasan_reset_tag(object);
>
>         /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_d=
elay)
> +       if (unlikely(still_accessible))
>                 return;
>
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
> @@ -256,12 +256,12 @@ bool __kasan_slab_pre_free(struct kmem_cache
> *cache, void *object,
>  }
>
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init=
,
> -                      bool after_rcu_delay)
> +                      bool still_accessible)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init, after_rcu_delay);
> +       poison_slab_object(cache, object, init, still_accessible);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
> diff --git a/mm/slub.c b/mm/slub.c
> index 49571d5ded75..a89f2006d46e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2221,31 +2221,34 @@ static __always_inline
>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
>                     bool after_rcu_delay)
>  {
> +       /* Are the object contents still accessible? */
> +       bool still_accessible =3D (s->flags & SLAB_TYPESAFE_BY_RCU) &&
> !after_rcu_delay;
> +
>         kmemleak_free_recursive(x, s->flags);
>         kmsan_slab_free(s, x);
>
>         debug_check_no_locks_freed(x, s->object_size);
>
>         if (!(s->flags & SLAB_DEBUG_OBJECTS))
>                 debug_check_no_obj_freed(x, s->object_size);
>
>         /* Use KCSAN to help debug racy use-after-free. */
> -       if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
> +       if (!still_accessible)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_AS=
SERT);
>
>         if (kfence_free(x))
>                 return false;
>
>         /*
>          * Give KASAN a chance to notice an invalid free operation before=
 we
>          * modify the object.
>          */
>         if (kasan_slab_pre_free(s, x))
>                 return false;
>
>  #ifdef CONFIG_SLUB_RCU_DEBUG
> -       if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> +       if (still_accessible) {
>                 struct rcu_delayed_free *delayed_free;
>
>                 delayed_free =3D kmalloc(sizeof(*delayed_free), GFP_NOWAI=
T);
> @@ -2289,7 +2292,7 @@ bool slab_free_hook(struct kmem_cache *s, void
> *x, bool init,
>                        s->size - inuse - rsize);
>         }
>         /* KASAN might put x into memory quarantine, delaying its reuse. =
*/
> -       return !kasan_slab_free(s, x, init, after_rcu_delay);
> +       return !kasan_slab_free(s, x, init, still_accessible);
>  }
>
>  static __fastpath_inline

Ok, let's do it like this.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdNWPnjSvPF5dg0NA%2Bf8y%3DrtxtbDC13cZJCz%2BrQVb%3DouA%40m=
ail.gmail.com.
