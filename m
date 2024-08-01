Return-Path: <kasan-dev+bncBDW2JDUY5AORB3FKVO2QMGQEIYMBAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 02883943B11
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2024 02:23:10 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-428e0d30911sf1299545e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 17:23:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722471789; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCjBnz9Np0uzP9KVhGyFsVnaNsFrieFDWdz5gEClC1/jI8E4FOWC7Bilciz0k/Zx2o
         p63Si6Wleq27MSGbg9jJdYJNkcbAImir1h4Z4CMPIO8dKO9hlc5YLSLunn1GX2VHsfnp
         SS+kUZIqn1wsNkdwwcbqC3j5pszsueBBi4VP2UZm8e1s0z2+XrJiE3PwPPOzaAlpu+Cm
         4F3Jn1n2oEko7Ov1mfkBOd+6kocqL8ELk9s+9mmJqPvhPOBztwZeBLYjkF+gcx9n60ZF
         oBYj2n2sy/YAp/dKgSeCaVzHu5ENGfmqaS91hkMrE4JZPbXZmYBTbXgHcz6MFGH+eMlI
         AnCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=UUCURHOEpcl6xVLcM+0kc/gOqtSqCZnVjj6go5R7vfU=;
        fh=v/yu3ip4xOuOn8F7MC5e18wLawqaPdB83AQ/KlhpVyE=;
        b=Vjfq66D5sX+A/7SR3EupBfvNg8DBjwkyIukr52Wvf+w0AxsTRnKrAGMNT4Yt1FD8D+
         YAawrHi3QZUUGqfLG8mbopdNDtDcRYH3kA03ISNYSGiX49+aojtYMZ8hOW7N9xCqOIA8
         kKEujeTCH6zRzxMB5uiXWWQJ4H5BJMRUGFP14Qi+A4gvK8n4cq1gfy92KKJ8xUNSCQqU
         WDPyg9AcITBgdHrpFERsar9LdCeZgz6TFOzHZNXOCo3FCortSzHBrWS+9E9rYpU5UpCl
         9GTmz8GqlkATvAt4ktmpSxly7PiNJrzhameupvFcE9bohHiDfGV7wYKZ57AzgWdSmHMM
         DJkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KQXnBpPW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722471789; x=1723076589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UUCURHOEpcl6xVLcM+0kc/gOqtSqCZnVjj6go5R7vfU=;
        b=jrEzrkh4PtOUpJh5Qf4N7aSbdpQzGJyX5M5Gso2xgMjt6kBY/fBdJYqigOTfEbJ/jQ
         hM5W2HMc+sCk1Nd3qGbsLal19v4xaoubWn4VhC3fUAEhSNjJYe9WMScYdVpk+t4IWnS7
         uHK8blekOPnDAw6eL9xpwMPNxPa9s8qhjjWl4i915jPBavqyDKPGyDeBTpfcSmmHQPmg
         RwtKEmoaISY5lsikrQ2aNjrgwCXHSgeVS08KUOwk6vt80xZzBr6y97S+UNg8VDY0+pm/
         smnxCdi0Cpgc6FU583a/+uJPcFi48S5XRzmZtOM6jKzICmI53NlQwVdkCPB/nENmW0qW
         vsmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722471789; x=1723076589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UUCURHOEpcl6xVLcM+0kc/gOqtSqCZnVjj6go5R7vfU=;
        b=nHmORnDnsoyrX05XowUqPWHhrVrcrm/xWPYU6HXq4Ek19Y8sC7YJe3dScpLyZ4ziW4
         6g/EcRYB3v9CI3aznOkzHRiT5s6foa9NmkRyv4ttZwYfELE1FCgiqgYk/Ez1knp+HK++
         VUx3zAqGB86CDDXL4FmajfGWn37MVPQw5UtigTIgUngwmPWhv34oYUNsXZbYTiQMV6Xh
         1E8QCCe3JPq5JHMNoaG36hvHhefezafE9gVZFb552ejmpYNc9ejwca78QYClJV4IS4FM
         U6Mknd1HWJ4vsJ+8/Ndh77kySh1dJYogua90Swp4m81DokqV5pAiTQOffLeDQeCQ4tAm
         G3Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722471789; x=1723076589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UUCURHOEpcl6xVLcM+0kc/gOqtSqCZnVjj6go5R7vfU=;
        b=RxkVLwOW69jZfmF+1BX5CiMXSi1ypzlURXMFkePg6xnxLZHQ5SKT5qQm2GgqyioIgw
         PphdU7p2MtMRgjI6zhktmDC8RPwAdUPA9eQ6JQ8Nhq7aRqykaLmMnFzjC5KeRLsvQTUC
         Ls3HIuUd2JL91nyRdlSxzhu39UnljYejNA0BFmLx+6Z2UiCUCS5grUz1sxY9aw89r6V0
         hCuHy4KJs2b1cj6lL4+h1en+iQewhvueDsDDLspQxXpsbw5pWFw8rYiU625G/jP/DUM2
         d61AvBL0MUa1NClPw66oxCrtz9E3527ZAxMXkITRCZ4Jx5Hd2lT1LlbZ/6Dh9nqxMo3L
         et7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqC+djgRA2OugzxzttgKhQzv+/0RoLUsDaa79muZ1fGIK2R9EQ+j47grXUDAU69DUCaweuREbeXmzOMveu6TqTRzseQoSnVg==
X-Gm-Message-State: AOJu0YyRjp2pyYkpZkZFNLtw4R8xoNJBF2VgWI99P7ul3Dsbqe75AGUj
	EBYbE6DHK5RyHoYJM+W3/xpi0omS+GFnRn2TQc1VHqPHAfOunNX7
X-Google-Smtp-Source: AGHT+IGRedu5XJtk9oU1a96m0X3Xp67qTT4bPbKqDIo+8ipTbCKQ2HcQebH+zXHLo+P1Er4Vi3q05w==
X-Received: by 2002:a05:600c:a01:b0:427:dae6:8416 with SMTP id 5b1f17b1804b1-428b03219f0mr4628745e9.36.1722471788578;
        Wed, 31 Jul 2024 17:23:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3513:b0:426:68ce:c99e with SMTP id
 5b1f17b1804b1-42803b69c50ls33896145e9.1.-pod-prod-03-eu; Wed, 31 Jul 2024
 17:23:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUFq6uiPXo/rEXZ0ZW+WLU1kx46FQgyZhbYekE5N0wl2DBqK85cYxHKkFUtYAqowikOtr/F9BZ187qhi5M8ra5FoXi0lG0zV74hw==
X-Received: by 2002:a5d:67cc:0:b0:368:3789:1a2 with SMTP id ffacd0b85a97d-36baacc9cd9mr490773f8f.21.1722471786484;
        Wed, 31 Jul 2024 17:23:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722471786; cv=none;
        d=google.com; s=arc-20160816;
        b=W86NN0wiHi19iOdOKnnVrFc392sZNUkCjipJMYX0V+eaNAl3B2Wffsrw+dCzFW1nn/
         34AeTYQgKD9nZkghoPxE/attiH2W/bpmXd4WKq3sTGM/f2wZClux6cJ3x8v1oXIcWzJF
         A52qKeSS1GXYJbXWJTsSKl/nhRd8kfvbM+ZEdzlZXXEfc9knh2U6ZcjyuatHuZRumGIt
         Un7r9yEj1PCoKziwUP4mKYfOIJ1TUC2gAD1ykVICg29NzjmN5QSVkoe227CequljlPhn
         +xUWUuUAy3VmAEsFDFsJogdOw4Tydia8lvBemtXNIcIY9p2lBM0gDnuEPcNDIDvajkQP
         wfGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vsRe15f8SeekhA1unFJl3x8nWV4+YMvQOTBZActqfL4=;
        fh=NTDAMfK2kpnAQvpuMGHuxtHavFdWArgB8FwSq5Ytpdo=;
        b=ELis/GzArJSULPFb+AkCEELTHd+XfqFPxTb3j8MiEixOyvmkzKPuyDK2h7srpwAd+C
         siBQQ4F2Nj9zz8UAu+a+i3eiNXlHZEsQ6ccyiangFtyiBVU7y/cQIfj1jFaFBVX1zUHF
         4DPsAdLzrx0UAVpYxdDV3NW3LUjkpb24P/D1/wtMGRQYr+tbKmorjKcKgvztI+XKq/Az
         rPXsdrYWfmmiWR3BMTbNTTN5ztU0Fq/7uxlc9e3uxFcjiyhPAWCLKtGkYi4rPVqc33p1
         fvsvrZnU5A7/QJg1QE0LCxQVxR1WCxcfuLNkQ/xa+HgbCcTuC8YXb1AepXT46y+j7yxS
         h9aQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KQXnBpPW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36771c4fsi308527f8f.2.2024.07.31.17.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 17:23:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-369cb9f086aso3512653f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 17:23:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9qdmkzeTlVOfLNf6KvTVrRyiwrSOosaj3DMbeQ7MevWHxwe0sJZmKd83OTXffVGufFqvZnA67LZYkvfdQR97hWeG0RW/00IfiDQ==
X-Received: by 2002:a05:6000:188:b0:367:9088:fecc with SMTP id
 ffacd0b85a97d-36baaca26cfmr431122f8f.7.1722471785502; Wed, 31 Jul 2024
 17:23:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com> <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com>
In-Reply-To: <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 1 Aug 2024 02:22:54 +0200
Message-ID: <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
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
 header.i=@gmail.com header.s=20230601 header.b=KQXnBpPW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Tue, Jul 30, 2024 at 1:06=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Currently, when KASAN is combined with init-on-free behavior, the
> initialization happens before KASAN's "invalid free" checks.
>
> More importantly, a subsequent commit will want to RCU-delay the actual
> SLUB freeing of an object, and we'd like KASAN to still validate
> synchronously that freeing the object is permitted. (Otherwise this
> change will make the existing testcase kmem_cache_invalid_free fail.)
>
> So add a new KASAN hook that allows KASAN to pre-validate a
> kmem_cache_free() operation before SLUB actually starts modifying the
> object or its metadata.

A few more minor comments below. With that:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

> Inside KASAN, this:
>
>  - moves checks from poison_slab_object() into check_slab_free()
>  - moves kasan_arch_is_ready() up into callers of poison_slab_object()
>  - removes "ip" argument of poison_slab_object() and __kasan_slab_free()
>    (since those functions no longer do any reporting)

>  - renames check_slab_free() to check_slab_allocation()

check_slab_allocation() is introduced in this patch, so technically
you don't rename anything.

> Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  include/linux/kasan.h | 43 ++++++++++++++++++++++++++++++++++---
>  mm/kasan/common.c     | 59 +++++++++++++++++++++++++++++++--------------=
------
>  mm/slub.c             |  7 ++++++
>  3 files changed, 83 insertions(+), 26 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 70d6a8f6e25d..34cb7a25aacb 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -172,19 +172,50 @@ static __always_inline void * __must_check kasan_in=
it_slab_obj(
>  {
>         if (kasan_enabled())
>                 return __kasan_init_slab_obj(cache, object);
>         return (void *)object;
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *s, void *object,
> -                       unsigned long ip, bool init);
> +bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
> +                       unsigned long ip);
> +/**
> + * kasan_slab_pre_free - Validate a slab object freeing request.
> + * @object: Object to free.
> + *
> + * This function checks whether freeing the given object might be permit=
ted; it
> + * checks things like whether the given object is properly aligned and n=
ot
> + * already freed.
> + *
> + * This function is only intended for use by the slab allocator.
> + *
> + * @Return true if freeing the object is known to be invalid; false othe=
rwise.
> + */

Let's reword this to:

kasan_slab_pre_free - Check whether freeing a slab object is safe.
@object: Object to be freed.

This function checks whether freeing the given object is safe. It
performs checks to detect double-free and invalid-free bugs and
reports them.

This function is intended only for use by the slab allocator.

@Return true if freeing the object is not safe; false otherwise.

> +static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
> +                                               void *object)
> +{
> +       if (kasan_enabled())
> +               return __kasan_slab_pre_free(s, object, _RET_IP_);
> +       return false;
> +}
> +
> +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> +/**
> + * kasan_slab_free - Possibly handle slab object freeing.
> + * @object: Object to free.
> + *
> + * This hook is called from the slab allocator to give KASAN a chance to=
 take
> + * ownership of the object and handle its freeing.
> + * kasan_slab_pre_free() must have already been called on the same objec=
t.
> + *
> + * @Return true if KASAN took ownership of the object; false otherwise.
> + */

kasan_slab_free - Poison, initialize, and quarantine a slab object.
@object: Object to be freed.
@init: Whether to initialize the object.

This function poisons a slab object and saves a free stack trace for
it, except for SLAB_TYPESAFE_BY_RCU caches.

For KASAN modes that have integrated memory initialization
(kasan_has_integrated_init() =3D=3D true), this function also initializes
the object's memory. For other modes, the @init argument is ignored.

For the Generic mode, this function might also quarantine the object.
When this happens, KASAN will defer freeing the object to a later
stage and handle it internally then. The return value indicates
whether the object was quarantined.

This function is intended only for use by the slab allocator.

@Return true if KASAN quarantined the object; false otherwise.

>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
>                                                 void *object, bool init)
>  {
>         if (kasan_enabled())
> -               return __kasan_slab_free(s, object, _RET_IP_, init);
> +               return __kasan_slab_free(s, object, init);
>         return false;
>  }
>
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static __always_inline void kasan_kfree_large(void *ptr)
>  {
> @@ -368,12 +399,18 @@ static inline void kasan_poison_new_object(struct k=
mem_cache *cache,
>                                         void *object) {}
>  static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>                                 const void *object)
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
>  }
>  static inline void kasan_kfree_large(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 85e7c6b4575c..8cede1ce00e1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -205,59 +205,65 @@ void * __must_check __kasan_init_slab_obj(struct km=
em_cache *cache,
>         /* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
>         object =3D set_tag(object, assign_tag(cache, object, true));
>
>         return (void *)object;
>  }
>
> -static inline bool poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     unsigned long ip, bool init)
> +/* returns true for invalid request */

"Returns true when freeing the object is not safe."

> +static bool check_slab_allocation(struct kmem_cache *cache, void *object=
,
> +                                 unsigned long ip)
>  {
> -       void *tagged_object;
> -
> -       if (!kasan_arch_is_ready())
> -               return false;
> +       void *tagged_object =3D object;
>
> -       tagged_object =3D object;
>         object =3D kasan_reset_tag(object);
>
>         if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
=3D object)) {
>                 kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT=
_INVALID_FREE);
>                 return true;
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
>                 return true;
>         }
>
> +       return false;
> +}
> +
> +static inline void poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> +                                     bool init)
> +{
> +       void *tagged_object =3D object;
> +
> +       object =3D kasan_reset_tag(object);
> +
> +       /* RCU slabs could be legally used after free within the RCU peri=
od. */
> +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +               return;
> +
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
>                         KASAN_SLAB_FREE, init);
>
>         if (kasan_stack_collection_enabled())
>                 kasan_save_free_info(cache, tagged_object);
> +}
>
> -       return false;
> +bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> +                               unsigned long ip)
> +{
> +       if (!kasan_arch_is_ready() || is_kfence_address(object))
> +               return false;
> +       return check_slab_allocation(cache, object, ip);
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> -                               unsigned long ip, bool init)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init=
)
>  {
> -       if (is_kfence_address(object))
> +       if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       /*
> -        * If the object is buggy, do not let slab put the object onto th=
e
> -        * freelist. The object will thus never be allocated again and it=
s
> -        * metadata will never get released.
> -        */
> -       if (poison_slab_object(cache, object, ip, init))
> -               return true;
> +       poison_slab_object(cache, object, init);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
>          * onto the freelist for now. The object's metadata is kept until=
 the
>          * object gets evicted from quarantine.
>          */
> @@ -503,15 +509,22 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
>                 kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, fal=
se);
>                 return true;
>         }
>
>         if (is_kfence_address(ptr))
>                 return false;
> +       if (!kasan_arch_is_ready())
> +               return true;

Hm, I think we had a bug here: the function should return true in both
cases. This seems reasonable: if KASAN is not checking the object, the
caller can do whatever they want with it.





>         slab =3D folio_slab(folio);
> -       return !poison_slab_object(slab->slab_cache, ptr, ip, false);
> +
> +       if (check_slab_allocation(slab->slab_cache, ptr, ip))
> +               return false;
> +
> +       poison_slab_object(slab->slab_cache, ptr, false);
> +       return true;
>  }
>
>  void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned lo=
ng ip)
>  {
>         struct slab *slab;
>         gfp_t flags =3D 0; /* Might be executing under a lock. */
> diff --git a/mm/slub.c b/mm/slub.c
> index 3520acaf9afa..0c98b6a2124f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2223,12 +2223,19 @@ bool slab_free_hook(struct kmem_cache *s, void *x=
, bool init)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_AS=
SERT);
>
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
>          * kept together to avoid discrepancies in behavior.
>          *
>          * The initialization memset's clear the object and the metadata,
>
> --
> 2.46.0.rc1.232.g9752f9e123-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfURBYNM%2Bo6omuTJyCtL4GpeudpErEd26qde296ciVYuQ%40mail.gm=
ail.com.
