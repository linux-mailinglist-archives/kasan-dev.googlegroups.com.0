Return-Path: <kasan-dev+bncBDW2JDUY5AORBTHCRO2QMGQEQDNDTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B80A893CC2D
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 02:43:57 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-36835f6ebdcsf1073718f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 17:43:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721954637; cv=pass;
        d=google.com; s=arc-20160816;
        b=0f6CQH+uXJJVCnxCMOwpArIjpE/nXt83xp7CRPk/qWidLXik2fNgIftablso9fTrqW
         nf1CxstrOu8hDGmiekLxUPKMSs6cZf11+8gzWEaT1kmnDzFi6HX/NrCMWo0JLUUvrR3/
         xL8muQdh/Dh0907OBlfSLJHe4SiNQlIYTGlKx2bWCY0XE4YdT51E9wpEz8cnXwmcmdSY
         60wgjLzapNhBqi/yBBeBcLcaFzbFPPH97nlKOaf/+FGwbiwYCEE+suuZL3PtoY0x1tXt
         Vml9jOskBiWGKN4WWE9p6T49JS0F2DoxTVbv0/FXk3Wj223oY2CZ8tX37686/mGPEuaZ
         1MYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=hfgEKW5CFnD28kPuSl+4UefRatFCLtGCuTIPJLNKncY=;
        fh=2CADSboonOZYzrsE2tGJLgcoJ4in9R5Oc7VaxfK0Lsk=;
        b=jdzq5IVCKB3Y2BDcruRVrCU43zgSTG5uUuh+aRbtkIepT5DrYF5XNkT5QF69fEb9PM
         4Ojr0xVzCLXlX+xJMtRIJLqNEgEIBvQlthMbCcJQwX2xsR6i9jCyALruWmpr6pEkxlVB
         0WGYQuSWVkgLXGr9QTRi0rhuZAwz4wdsx7p8LvH3UblrldSP6MM8UAaNNqH52BT2wshu
         MVr8MzkcP6AOjuDKOOLi+iN6egFAHJ/13WNVbiFk9tpXnxONtgMWy+2qdI7LgYBQGYzi
         JpMtyeVKf6jB+lGA50qIeGDoSMKKswguL+Ku1H+zwddQhXLWf9+e79X1npqHQNiJzUK6
         gL3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RmZRIsz1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721954637; x=1722559437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hfgEKW5CFnD28kPuSl+4UefRatFCLtGCuTIPJLNKncY=;
        b=hMD6riDqmaiTFs34ujTV0TRbGFjXRA/SshdC9c7QUULllqviDsIZlVY173Wrqauc6I
         jir9cOUr7IK+NWjy7tWD5H6SmFu+031cROhzGEx51gwHsqlRZRX5b0zTmnWXqUmM7lHQ
         bWk0tQKyOwx8Dhw5ASCR0XylcEmNBRqny030ocHXzsO2BXMW4gNHy0+Umd5H8nnfbm8F
         zmZB6aSuKQV2MFVj61uEGUFsnYRFNiA5P4Dht+kkn4e8N1oP5algON1pS2Y3KwCTAJJj
         9keeaXhE6bI+h6/i/MtI4P51U8hut5zPeQ7Tfcvzrtl1LmX6g90/OR9+jr3Bqu564o+c
         8e2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721954637; x=1722559437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hfgEKW5CFnD28kPuSl+4UefRatFCLtGCuTIPJLNKncY=;
        b=GmN+J77NnbNoA3jmkky3SqZDfroPSOJhxl3kHUY6XCiWmA3uD1h7rIEKDdt9ukKHZZ
         c+Mp1+xhEFusXwwmG8DnJf4+TrjzmR9lN84fQxCEYSAreC1p2GKEHoy5anP+WoNgUU1e
         ZqhGyLTpeBplnmQP/srwzrXu0a/6faWb8VbsgCXNnP30mBJD86B44o+6iRxCZf1JZHUG
         UD4qMZET82Mlo+1MaWfSt/6WiqNA5UlHshsPmJvv70111BDwlDN71VUEGndCOIkLzsDW
         SLbgpJaPJ/AcGAALv5Konv8uJdBSNxZfwCnDrHV03mxi8PY2JbVBGNxQsF45Ov/PI4FE
         YcRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721954637; x=1722559437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hfgEKW5CFnD28kPuSl+4UefRatFCLtGCuTIPJLNKncY=;
        b=jDa19lSBZVWYaMuetLp1Fu5QOJqpdEtjKfzl1WBhDxzoGo6vJNfPyoFF53E7GGbl3K
         5U+aknMk9YJSiP/lcq6UR/HKpaKGi/RnWqa3uh2aS9I3zOge5r1drSH9Q0GWp5Sw62XJ
         spnFxSL/Qea1t9iwAjTzKB93PREFwSZcH4NJNpx7Rfqz1diS1uuVagGn7rhWhurCVbSd
         H42ljdtj3U7F+5yTzzqOZKQPD0nt/RiAMhEVqAsZpYkxAHum7RETQFRMVxARXqG/u2ZC
         JORs3eX5JwNXERBHaE+MXtV3oDB9ZweBF9FS/Bbxy+yl6wmUSwHXOyLqb5KCB7CNaqwu
         Ot1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVK6oHecNAohQt47POJXuNHtyVRsI+HrS0/VLSWCW+EJTR8bEyDRusROIYk5tqLcCmZ0384TYsxrQVoVsBbYLaIvHKUt/5y7Q==
X-Gm-Message-State: AOJu0YwsWzPlLLgzyu++1Jo+dSNd/nOHnV/z6uBG8gXgG4+2g1M36hZM
	TjV+ttz7LYR7H0y0msuia9M8+oRSJzeqaq5Jml65THnIyPNiXKE9
X-Google-Smtp-Source: AGHT+IEegBGYdQUuegE59s4vjHUseXbF7jDCz3kFTVi1Dr65qR+zgPz+KBafxEeIs6qjxHrHrT7BoQ==
X-Received: by 2002:a05:6000:1809:b0:366:ebd1:3bc1 with SMTP id ffacd0b85a97d-36b363818d8mr2458368f8f.3.1721954637058;
        Thu, 25 Jul 2024 17:43:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f108:0:b0:368:1198:b9de with SMTP id ffacd0b85a97d-36b31ac83b0ls458862f8f.1.-pod-prod-08-eu;
 Thu, 25 Jul 2024 17:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/GrgcoyVGj+dSO2jdAKqMnwZegUVGRk5Y01EIx51IBqav7H6AO7fYOfwxw18GbOsYWlnIw2uFOGiPp3rsudao0/+wTBzgZrgfwg==
X-Received: by 2002:a05:6000:1887:b0:367:8e18:535c with SMTP id ffacd0b85a97d-36b364217c9mr2976101f8f.43.1721954635223;
        Thu, 25 Jul 2024 17:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721954635; cv=none;
        d=google.com; s=arc-20160816;
        b=qNXROn2rkxx54ANQFiM97Yk01Su20xYgRAfzkAdFQw443VUP2M4MB+lKr2Ftt8ToLG
         m3BA0n1K+c8eYUf+seThRHnfXYo+S0TsOsEmKarSP52dii2mXhV9uoFqRIVqnBzmyOG/
         aCTTYSs91MHZzvnGX9gcnjgP5RH8jPMXEZ95TQhbzw0YTNKH113t60Hevush6NpreRci
         GDRAk5gfs6uaQcPKZZfiyegI2hulujnRkBVhuxkImhm+SkAB4O4sMFf78NENFuP8vKfT
         06tipcmzsxLZio8kaeodHbdWvnCWnl0uNARvO824gLsWZMDq1W216k13YmaIaiR2+WdI
         lKMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xYO5SO4GDvuXPDiqp7OtLZoWNem0w1AFsK/JqDBRgRw=;
        fh=NycbMXm2kDXFwHz2SLfnUFsontHZgq9ft8jYfUySSoo=;
        b=sjEIeeftUBMK8mHcjTGJnHWII0ZelUjFUaHk+VLUoi2Qf0RhC/B3E7ua1LaCgQ2jJ6
         Do0BUL4xgpf4/YFBh2ak2O7Ohev0jwDEfB0jUhT2Hm9yBGKDWJ1lbxgCp6vlh1hNIef5
         4bK8dDXVzR+gpDi26dnHHFDaw/R3Rru5d5CFRFjMbdjnm/oybSVsOeRzp5w4nQ5s31et
         GLopDhmHkBnutG9xXeUg4apAIql+M0sl86pWa2as/ZdEabfuc1nnj6/YD0UzF2r6Q1mF
         Ko92/ktD2yIMC1XS08KFjJ0//gOvhW/mtkl0j769LTqhXc8qC4MkzS4SGLbW6JdImC/H
         vP8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RmZRIsz1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a7aca6e70c6si6367166b.0.2024.07.25.17.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 17:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3686b285969so915622f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 17:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9zHnQ2K7x86jAtLvDv3yImKS3HtzoN6cLPlYLChblTBEGIobXjFZVCp6VHoIUcRKAkIB+MQN+LBfmdo7d9NdZRO1HU8a4KdBDlQ==
X-Received: by 2002:a05:6000:112:b0:367:8a72:b8b4 with SMTP id
 ffacd0b85a97d-36b363a30b9mr2518002f8f.33.1721954634536; Thu, 25 Jul 2024
 17:43:54 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com> <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com>
In-Reply-To: <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 26 Jul 2024 02:43:43 +0200
Message-ID: <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
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
 header.i=@gmail.com header.s=20230601 header.b=RmZRIsz1;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Thu, Jul 25, 2024 at 5:32=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Currently, when KASAN is combined with init-on-free behavior, the
> initialization happens before KASAN's "invalid free" checks.
>
> More importantly, a subsequent commit will want to use the object metadat=
a
> region to store an rcu_head, and we should let KASAN check that the objec=
t
> pointer is valid before that. (Otherwise that change will make the existi=
ng
> testcase kmem_cache_invalid_free fail.)

This is not the case since v3, right? Do we still need this patch?

If it's still needed, see the comment below.

Thank you!

> So add a new KASAN hook that allows KASAN to pre-validate a
> kmem_cache_free() operation before SLUB actually starts modifying the
> object or its metadata.
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  include/linux/kasan.h | 16 ++++++++++++++++
>  mm/kasan/common.c     | 51 +++++++++++++++++++++++++++++++++++++++------=
------
>  mm/slub.c             |  7 +++++++
>  3 files changed, 62 insertions(+), 12 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 70d6a8f6e25d..ebd93c843e78 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -175,6 +175,16 @@ static __always_inline void * __must_check kasan_ini=
t_slab_obj(
>         return (void *)object;
>  }
>
> +bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
> +                       unsigned long ip);
> +static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
> +                                               void *object)
> +{
> +       if (kasan_enabled())
> +               return __kasan_slab_pre_free(s, object, _RET_IP_);
> +       return false;
> +}

Please add a documentation comment for this new hook; something like
what we have for kasan_mempool_poison_pages() and some of the others.
(I've been meaning to add them for all of them, but still didn't get
around to that.)

> +
>  bool __kasan_slab_free(struct kmem_cache *s, void *object,
>                         unsigned long ip, bool init);
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> @@ -371,6 +381,12 @@ static inline void *kasan_init_slab_obj(struct kmem_=
cache *cache,
>  {
>         return (void *)object;
>  }
> +
> +static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *objec=
t)
> +{
> +       return false;
> +}
> +
>  static inline bool kasan_slab_free(struct kmem_cache *s, void *object, b=
ool init)
>  {
>         return false;
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 85e7c6b4575c..7c7fc6ce7eb7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -208,31 +208,52 @@ void * __must_check __kasan_init_slab_obj(struct km=
em_cache *cache,
>         return (void *)object;
>  }
>
> -static inline bool poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     unsigned long ip, bool init)
> +enum free_validation_result {
> +       KASAN_FREE_IS_IGNORED,
> +       KASAN_FREE_IS_VALID,
> +       KASAN_FREE_IS_INVALID
> +};
> +
> +static enum free_validation_result check_slab_free(struct kmem_cache *ca=
che,
> +                                               void *object, unsigned lo=
ng ip)
>  {
> -       void *tagged_object;
> +       void *tagged_object =3D object;
>
> -       if (!kasan_arch_is_ready())
> -               return false;
> +       if (is_kfence_address(object) || !kasan_arch_is_ready())
> +               return KASAN_FREE_IS_IGNORED;
>
> -       tagged_object =3D object;
>         object =3D kasan_reset_tag(object);
>
>         if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
=3D object)) {
>                 kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT=
_INVALID_FREE);
> -               return true;
> +               return KASAN_FREE_IS_INVALID;
>         }
>
> -       /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> -               return false;
> -
>         if (!kasan_byte_accessible(tagged_object)) {
>                 kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT=
_DOUBLE_FREE);
> -               return true;
> +               return KASAN_FREE_IS_INVALID;
>         }
>
> +       return KASAN_FREE_IS_VALID;
> +}
> +
> +static inline bool poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> +                                     unsigned long ip, bool init)
> +{
> +       void *tagged_object =3D object;
> +       enum free_validation_result valid =3D check_slab_free(cache, obje=
ct, ip);

I believe we don't need check_slab_free() here, as it was already done
in kasan_slab_pre_free()? Checking just kasan_arch_is_ready() and
is_kfence_address() should save a bit on performance impact.

Though if we remove check_slab_free() from here, we do need to add it
to __kasan_mempool_poison_object().

> +
> +       if (valid =3D=3D KASAN_FREE_IS_IGNORED)
> +               return false;
> +       if (valid =3D=3D KASAN_FREE_IS_INVALID)
> +               return true;
> +
> +       object =3D kasan_reset_tag(object);
> +
> +       /* RCU slabs could be legally used after free within the RCU peri=
od. */
> +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +               return false;

I vaguely recall there was some reason why this check was done before
the kasan_byte_accessible() check, but I might be wrong. Could you try
booting the kernel with only this patch applied to see if anything
breaks?




> +
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
>                         KASAN_SLAB_FREE, init);
>
> @@ -242,6 +263,12 @@ static inline bool poison_slab_object(struct kmem_ca=
che *cache, void *object,
>         return false;
>  }
>
> +bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> +                               unsigned long ip)
> +{
> +       return check_slab_free(cache, object, ip) =3D=3D KASAN_FREE_IS_IN=
VALID;
> +}
> +
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                                 unsigned long ip, bool init)
>  {
> diff --git a/mm/slub.c b/mm/slub.c
> index 4927edec6a8c..34724704c52d 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2170,6 +2170,13 @@ bool slab_free_hook(struct kmem_cache *s, void *x,=
 bool init)
>         if (kfence_free(x))
>                 return false;
>
> +       /*
> +        * Give KASAN a chance to notice an invalid free operation before=
 we
> +        * modify the object.
> +        */
> +       if (kasan_slab_pre_free(s, x))
> +               return false;
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_free and initialization memset's must be
>
> --
> 2.45.2.1089.g2a221341d9-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe-x%2BJOUN1P-H-i0_3ys%2BXgpZBKU_zi06XBRfmN%2BOzO%2Bw%40m=
ail.gmail.com.
