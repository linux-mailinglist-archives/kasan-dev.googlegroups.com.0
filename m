Return-Path: <kasan-dev+bncBDW2JDUY5AORBTGEZOWQMGQEFBUGWAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BBB1683CF7A
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 23:35:57 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2cf2fd27e1csf16503601fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 14:35:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706222157; cv=pass;
        d=google.com; s=arc-20160816;
        b=PGI2FGq2GF64b4AWewZFEJ8Hecqf3lV5q4+iVXiTpJHdA9IX5MhV+RaXNMowqMtX2Q
         kuYsjDtM8CyCGlPcuYlwzvaCEmgh/F0w4VNEumnwlv9n9Wsg9C2AT/BsR2fzFkhapRXC
         2tems+Zv9Df47jIXLoLU2b7mdlbFAbV/uq5aHe/zjtVdRA9ow/Xiy6mzMXvu3K3Psu3l
         IXpD11U32nNrGrhYAXY6eC8fujK/4WGYlCPNauZoEOKVr3l/nyhJcU9ng6lFEfiJSW44
         sOI82DeYRCWUGNbALxQT1cBSXkuqrnOZP7PMRhHraTrlE0M1Y8OFNW8dNCzZairCOd7v
         eXOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=N2XUm+N84PispywFHSCI7P7w4CbXjMX6Kodmdtt7OKs=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=leqf5gCRLxJg3rXs2WbX80rTirgv2EWcqjWkmN2Rfnp7F6p5LndYusiKbcYikh5f3x
         1QjVtXTHocH7T0TFOpc66lozhUNPK1PCwQ4jnYc1X9K/gPhnob6SFoPBtDn7yVvC4/PG
         H+NuaOoI0X8qzqjxDQo0/9pILiA2Fx31LKRt33H3RfQeDr+xVIeEgnRrZosOHNwr3dT+
         oxB/2RNvlly402YOnDtPrUqGmtUbMYg9UT7GU/WxzK9GWOO+3TSGGx+Pmak/gNGPjEEx
         fO5H6dDRJTknKp94VLtiGTKcBmyYYUU/dGDRfWAVwpFRVl2BlhlzfqApvI6X5ewO5ROs
         fb/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=g9a0yuLh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706222157; x=1706826957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N2XUm+N84PispywFHSCI7P7w4CbXjMX6Kodmdtt7OKs=;
        b=PUomRMh2ej70H9wgWBlvnX2PO7e2Qi0gLzOmtYJrYajsYx3l6SD1dYg9mlZZehgFh2
         z9rxosvSOr2/RMoSIPFWqRJuUSz/KhNYa/vVnl7cEHsgdbLRBECWhSXfk81u09ByynAE
         pIABPUTDwwgFcx3+faI6Cn7YHYWJRb2MoFgbhDKX80kquNb/o8ta0eePUXmmkUL4TFSb
         Nf8Z1y/u+bx0LKqZqgGtiWxycoGNnP8VxDOxVqAMktO7LWFVTPpalw2codbT5lvFX2Pj
         fhe5JdjtMkIB/0DMJ3v82ad45JKR+dOkDmnID3vQTQkM7MPVRDj4/CtIeJ3AaTs+9bw6
         3zNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706222157; x=1706826957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N2XUm+N84PispywFHSCI7P7w4CbXjMX6Kodmdtt7OKs=;
        b=AV5j2MUBhH3227zbYAC82Hmknf8s9ZWMiTF/ViTuHN2Lrnm3Tv+9gEX6sCyMY9MRoL
         rm3OCmqlN0bb5SCipqm3H3ds6XJyiE/WUqwlTFNSpM4zE0gOq1S34aB4bKXV/LQFHJkR
         18QmGoTkKIIJQdURgjhz4ub5YQO2+lONkhPLukKlpbYUs4BPPF5XNc3O6UWJdyQ1N59H
         DFVpIHiZvASs+uJEYs6OobsjM0C0vayOVEUsjYnO386MWdQW4yhwfXLmOamPM5f5wP4I
         SyQlU6CvS1QwZNmzlvuPX6bggvixcNepw9LDQ10+6au+Z/fkHSupToJJD4kxQ+l2ZDza
         3p1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706222157; x=1706826957;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N2XUm+N84PispywFHSCI7P7w4CbXjMX6Kodmdtt7OKs=;
        b=ieRpwWlRgFVTI07s02/881CiG40R12KLzLgKhCs155d+dZHNob9CMU+6/fLQpOH2qi
         z0QBbrk+ye0SumA6Qjat7i2xgEPWsKfHQN5DCsSzdpFL4tIFaPaRPLBCVPt/iz9upKQS
         f4l7TZsx1UZqc0Y3P8ppi/5/7ZhfeNohmWR+y+x34sWHMpCSxyMVdncMpwLtsMedEgGu
         fOC6nettdJVjlPYO8S8mOBa9zL3i47G96dlrUH/ETb5u+1N3j2iNz8qPBONtzSf1jyUC
         QuBqZ8pqt12HfbfWOvV5GrhupDYKtXBbkNBazYBiJvBZ9ed58RjFj06dFDc7WNW83Q9c
         dhyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7ExDq000PfQoZ8v8gV7FZA8RhcZ5YkELaF5eg5znhW/zSAiBm
	VR7P9pw/F1DvjbmSvHFDsypkVP34DJOYFshpzZZzvg4bYiFOOkOC
X-Google-Smtp-Source: AGHT+IGubkiCqxnMtnXq8tlVa1cjcgVsDzXT3deJAZwUXoXjNIkZ6CzZborIJiTe1oxEz/HSdijLiA==
X-Received: by 2002:a2e:b611:0:b0:2cf:2bf:286e with SMTP id r17-20020a2eb611000000b002cf02bf286emr174345ljn.66.1706222156449;
        Thu, 25 Jan 2024 14:35:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7a09:0:b0:2cd:b310:f5af with SMTP id v9-20020a2e7a09000000b002cdb310f5afls51198ljc.1.-pod-prod-04-eu;
 Thu, 25 Jan 2024 14:35:54 -0800 (PST)
X-Received: by 2002:a05:6512:614:b0:510:244a:1318 with SMTP id b20-20020a056512061400b00510244a1318mr91467lfe.76.1706222154433;
        Thu, 25 Jan 2024 14:35:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706222154; cv=none;
        d=google.com; s=arc-20160816;
        b=uzpeUpaDxTGpKszKD3aekzQD7NmhxkPelC/akvDhyQeMhEaAdd5FgHA4bJTURZ57Sw
         LPLz4isscNwdM4E1yq6tivw/ZLKxXH428CWsnNQIyJ+DBYmPK6kZ6agKRwWNxvUNdBvt
         arnob15SJCaE4dFQCb8lv21Az2WYzTKfUocFUlh+9w/erJraExfm5nm1wjQIo/Pqon3L
         PVLd2IlsylhUy8DlAOU9cbH3ECAEbeF/Zppj2pcZRU4SC2GIqxjM4YS7eNugr2AjVqcQ
         oMjVRYNRbFFhVsrGGPb6fsYfXja3bp9eD9Vm5OFezEwFOV1oFOmLLO/IPz+iPColHOQc
         0GTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ASPyASwMfpiYxl1C+amLASNi2699ENzeTUD4Y5JDI5E=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=BsTXRrdWNkuxyIaHNUBjCZCfr5MaICa8LWwyC/zfa32KP0Fo9OC5zdAb/OXo5WMAw1
         5HJfFas0VlW4Ar3V0k8b+nb2SmEomc7zr5bn1ah8XfRqgB7mlWCE93tubiXABXvZw/oc
         mDuqrnRz1me2kfASLHpA/UKOQ4N+dE8r8IxVmjLSUX3q4+YLY5xnlftoA0JAQwPlDygB
         Td0nll6zdTHG41ADotQ4r8+3JmYsEC26/l7K+V7HzUAmyGfy61vv4LEhSBIa5oAHBbbr
         75BsQWetGFubVfyImra31cRaEfI8BiNKtidIuZqXnSZjYcX6Ex7B5PdYW4TTcSmtSika
         0FHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=g9a0yuLh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id b23-20020ac25637000000b005101ebc5293si70661lff.11.2024.01.25.14.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jan 2024 14:35:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-339237092dcso5114856f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 25 Jan 2024 14:35:54 -0800 (PST)
X-Received: by 2002:a5d:6a88:0:b0:337:bf7f:a2c7 with SMTP id
 s8-20020a5d6a88000000b00337bf7fa2c7mr319823wru.23.1706222153744; Thu, 25 Jan
 2024 14:35:53 -0800 (PST)
MIME-Version: 1.0
References: <20240125094815.2041933-1-elver@google.com>
In-Reply-To: <20240125094815.2041933-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 25 Jan 2024 23:35:42 +0100
Message-ID: <CA+fCnZfzpPvg3UXKfxhe8n-tT2Pqhfysy_HdrMb6MxaEtnJ2BQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] stackdepot: use variable size records for
 non-evictable entries
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=g9a0yuLh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
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

On Thu, Jan 25, 2024 at 10:48=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> With the introduction of stack depot evictions, each stack record is now
> fixed size, so that future reuse after an eviction can safely store
> differently sized stack traces. In all cases that do not make use of
> evictions, this wastes lots of space.
>
> Fix it by re-introducing variable size stack records (up to the max
> allowed size) for entries that will never be evicted. We know if an
> entry will never be evicted if the flag STACK_DEPOT_FLAG_GET is not
> provided, since a later stack_depot_put() attempt is undefined behavior.
>
> With my current kernel config that enables KASAN and also SLUB owner trac=
king,
> I observe (after a kernel boot) a whopping reduction of 296 stack depot p=
ools,
> which translates into 4736 KiB saved. The savings here are from SLUB owne=
r
> tracking only, because KASAN generic mode still uses refcounting.
>
> Before:
>
>   pools: 893
>   allocations: 29841
>   frees: 6524
>   in_use: 23317
>   freelist_size: 3454
>
> After:
>
>   pools: 597
>   allocations: 29657
>   frees: 6425
>   in_use: 23232
>   freelist_size: 3493
>
> Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> ---
> v1 (since RFC):
> * Get rid of new_pool_required to simplify the code.
> * Warn on attempts to switch a non-refcounted entry to refcounting.
> * Typos.
> ---
>  include/linux/poison.h |   3 +
>  lib/stackdepot.c       | 212 +++++++++++++++++++++--------------------
>  2 files changed, 113 insertions(+), 102 deletions(-)
>
> diff --git a/include/linux/poison.h b/include/linux/poison.h
> index 27a7dad17eef..1f0ee2459f2a 100644
> --- a/include/linux/poison.h
> +++ b/include/linux/poison.h
> @@ -92,4 +92,7 @@
>  /********** VFS **********/
>  #define VFS_PTR_POISON ((void *)(0xF5 + POISON_POINTER_DELTA))
>
> +/********** lib/stackdepot.c **********/
> +#define STACK_DEPOT_POISON ((void *)(0xD390 + POISON_POINTER_DELTA))
> +
>  #endif
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5caa1f566553..1b0d948a053c 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -22,6 +22,7 @@
>  #include <linux/list.h>
>  #include <linux/mm.h>
>  #include <linux/mutex.h>
> +#include <linux/poison.h>
>  #include <linux/printk.h>
>  #include <linux/rculist.h>
>  #include <linux/rcupdate.h>
> @@ -93,9 +94,6 @@ struct stack_record {
>         };
>  };
>
> -#define DEPOT_STACK_RECORD_SIZE \
> -       ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
> -
>  static bool stack_depot_disabled;
>  static bool __stack_depot_early_init_requested __initdata =3D IS_ENABLED=
(CONFIG_STACKDEPOT_ALWAYS_INIT);
>  static bool __stack_depot_early_init_passed __initdata;
> @@ -121,15 +119,10 @@ static void *stack_pools[DEPOT_MAX_POOLS];
>  static void *new_pool;
>  /* Number of pools in stack_pools. */
>  static int pools_num;
> +/* Offset to the unused space in the currently used pool. */
> +static size_t pool_offset =3D DEPOT_POOL_SIZE;
>  /* Freelist of stack records within stack_pools. */
>  static LIST_HEAD(free_stacks);
> -/*
> - * Stack depot tries to keep an extra pool allocated even before it runs=
 out
> - * of space in the currently used pool. This flag marks whether this ext=
ra pool
> - * needs to be allocated. It has the value 0 when either an extra pool i=
s not
> - * yet allocated or if the limit on the number of pools is reached.
> - */
> -static bool new_pool_required =3D true;
>  /* The lock must be held when performing pool or freelist modifications.=
 */
>  static DEFINE_RAW_SPINLOCK(pool_lock);
>
> @@ -294,48 +287,52 @@ int stack_depot_init(void)
>  EXPORT_SYMBOL_GPL(stack_depot_init);
>
>  /*
> - * Initializes new stack depot @pool, release all its entries to the fre=
elist,
> - * and update the list of pools.
> + * Initializes new stack pool, and updates the list of pools.
>   */
> -static void depot_init_pool(void *pool)
> +static bool depot_init_pool(void **prealloc)
>  {
> -       int offset;
> -
>         lockdep_assert_held(&pool_lock);
>
> -       /* Initialize handles and link stack records into the freelist. *=
/
> -       for (offset =3D 0; offset <=3D DEPOT_POOL_SIZE - DEPOT_STACK_RECO=
RD_SIZE;
> -            offset +=3D DEPOT_STACK_RECORD_SIZE) {
> -               struct stack_record *stack =3D pool + offset;
> -
> -               stack->handle.pool_index =3D pools_num;
> -               stack->handle.offset =3D offset >> DEPOT_STACK_ALIGN;
> -               stack->handle.extra =3D 0;
> -
> -               /*
> -                * Stack traces of size 0 are never saved, and we can sim=
ply use
> -                * the size field as an indicator if this is a new unused=
 stack
> -                * record in the freelist.
> -                */
> -               stack->size =3D 0;
> +       if (unlikely(pools_num >=3D DEPOT_MAX_POOLS)) {
> +               /* Bail out if we reached the pool limit. */
> +               WARN_ON_ONCE(pools_num > DEPOT_MAX_POOLS); /* should neve=
r happen */
> +               WARN_ON_ONCE(!new_pool); /* to avoid unnecessary pre-allo=
cation */
> +               WARN_ONCE(1, "Stack depot reached limit capacity");
> +               return false;
> +       }
>
> -               INIT_LIST_HEAD(&stack->hash_list);
> -               /*
> -                * Add to the freelist front to prioritize never-used ent=
ries:
> -                * required in case there are entries in the freelist, bu=
t their
> -                * RCU cookie still belongs to the current RCU grace peri=
od
> -                * (there can still be concurrent readers).
> -                */
> -               list_add(&stack->free_list, &free_stacks);
> -               counters[DEPOT_COUNTER_FREELIST_SIZE]++;
> +       if (!new_pool && *prealloc) {
> +               /* We have preallocated memory, use it. */
> +               WRITE_ONCE(new_pool, *prealloc);
> +               *prealloc =3D NULL;
>         }
>
> +       if (!new_pool)
> +               return false; /* new_pool and *prealloc are NULL */
> +
>         /* Save reference to the pool to be used by depot_fetch_stack(). =
*/
> -       stack_pools[pools_num] =3D pool;
> +       stack_pools[pools_num] =3D new_pool;
> +
> +       /*
> +        * Stack depot tries to keep an extra pool allocated even before =
it runs
> +        * out of space in the currently used pool.
> +        *
> +        * To indicate that a new preallocation is needed new_pool is res=
et to
> +        * NULL; do not reset to NULL if we have reached the maximum numb=
er of
> +        * pools.
> +        */
> +       if (pools_num < DEPOT_MAX_POOLS)
> +               WRITE_ONCE(new_pool, NULL);
> +       else
> +               WRITE_ONCE(new_pool, STACK_DEPOT_POISON);
>
>         /* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
>         WRITE_ONCE(pools_num, pools_num + 1);
>         ASSERT_EXCLUSIVE_WRITER(pools_num);
> +
> +       pool_offset =3D 0;
> +
> +       return true;
>  }
>
>  /* Keeps the preallocated memory to be used for a new stack depot pool. =
*/
> @@ -347,60 +344,48 @@ static void depot_keep_new_pool(void **prealloc)
>          * If a new pool is already saved or the maximum number of
>          * pools is reached, do not use the preallocated memory.
>          */
> -       if (!new_pool_required)
> +       if (new_pool)
>                 return;
>
> -       /*
> -        * Use the preallocated memory for the new pool
> -        * as long as we do not exceed the maximum number of pools.
> -        */
> -       if (pools_num < DEPOT_MAX_POOLS) {
> -               new_pool =3D *prealloc;
> -               *prealloc =3D NULL;
> -       }
> -
> -       /*
> -        * At this point, either a new pool is kept or the maximum
> -        * number of pools is reached. In either case, take note that
> -        * keeping another pool is not required.
> -        */
> -       WRITE_ONCE(new_pool_required, false);
> +       WRITE_ONCE(new_pool, *prealloc);
> +       *prealloc =3D NULL;
>  }
>
>  /*
> - * Try to initialize a new stack depot pool from either a previous or th=
e
> - * current pre-allocation, and release all its entries to the freelist.
> + * Try to initialize a new stack record from the current pool, a cached =
pool, or
> + * the current pre-allocation.
>   */
> -static bool depot_try_init_pool(void **prealloc)
> +static struct stack_record *depot_pop_free_pool(void **prealloc, size_t =
size)
>  {
> +       struct stack_record *stack;
> +       void *current_pool;
> +       u32 pool_index;
> +
>         lockdep_assert_held(&pool_lock);
>
> -       /* Check if we have a new pool saved and use it. */
> -       if (new_pool) {
> -               depot_init_pool(new_pool);
> -               new_pool =3D NULL;
> +       if (pool_offset + size > DEPOT_POOL_SIZE) {
> +               if (!depot_init_pool(prealloc))
> +                       return NULL;
> +       }
>
> -               /* Take note that we might need a new new_pool. */
> -               if (pools_num < DEPOT_MAX_POOLS)
> -                       WRITE_ONCE(new_pool_required, true);
> +       if (WARN_ON_ONCE(pools_num < 1))
> +               return NULL;
> +       pool_index =3D pools_num - 1;
> +       current_pool =3D stack_pools[pool_index];
> +       if (WARN_ON_ONCE(!current_pool))
> +               return NULL;
>
> -               return true;
> -       }
> +       stack =3D current_pool + pool_offset;
>
> -       /* Bail out if we reached the pool limit. */
> -       if (unlikely(pools_num >=3D DEPOT_MAX_POOLS)) {
> -               WARN_ONCE(1, "Stack depot reached limit capacity");
> -               return false;
> -       }
> +       /* Pre-initialize handle once. */
> +       stack->handle.pool_index =3D pool_index;
> +       stack->handle.offset =3D pool_offset >> DEPOT_STACK_ALIGN;
> +       stack->handle.extra =3D 0;
> +       INIT_LIST_HEAD(&stack->hash_list);
>
> -       /* Check if we have preallocated memory and use it. */
> -       if (*prealloc) {
> -               depot_init_pool(*prealloc);
> -               *prealloc =3D NULL;
> -               return true;
> -       }
> +       pool_offset +=3D size;
>
> -       return false;
> +       return stack;
>  }
>
>  /* Try to find next free usable entry. */

Please update this to specifically mention the freelist. Otherwise,
it's hard to understand what's the difference compared to
depot_pop_free_pool without reading into the code.

> @@ -420,7 +405,7 @@ static struct stack_record *depot_pop_free(void)
>          * check the first entry.
>          */
>         stack =3D list_first_entry(&free_stacks, struct stack_record, fre=
e_list);
> -       if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
> +       if (!poll_state_synchronize_rcu(stack->rcu_state))
>                 return NULL;
>
>         list_del(&stack->free_list);
> @@ -429,45 +414,68 @@ static struct stack_record *depot_pop_free(void)
>         return stack;
>  }
>
> +static inline size_t depot_stack_record_size(struct stack_record *s, uns=
igned int nr_entries)
> +{
> +       const size_t used =3D flex_array_size(s, entries, nr_entries);
> +       const size_t unused =3D sizeof(s->entries) - used;
> +
> +       WARN_ON_ONCE(sizeof(s->entries) < used);
> +
> +       return ALIGN(sizeof(struct stack_record) - unused, 1 << DEPOT_STA=
CK_ALIGN);
> +}
> +
>  /* Allocates a new stack in a stack depot pool. */
>  static struct stack_record *
> -depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **pre=
alloc)
> +depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depo=
t_flags_t flags, void **prealloc)
>  {
> -       struct stack_record *stack;
> +       struct stack_record *stack =3D NULL;
> +       size_t record_size;
>
>         lockdep_assert_held(&pool_lock);
>
>         /* This should already be checked by public API entry points. */
> -       if (WARN_ON_ONCE(!size))
> +       if (WARN_ON_ONCE(!nr_entries))
>                 return NULL;
>
> -       /* Check if we have a stack record to save the stack trace. */
> -       stack =3D depot_pop_free();
> -       if (!stack) {
> -               /* No usable entries on the freelist - try to refill the =
freelist. */
> -               if (!depot_try_init_pool(prealloc))
> -                       return NULL;
> +       /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. =
*/
> +       if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
> +               nr_entries =3D CONFIG_STACKDEPOT_MAX_FRAMES;
> +
> +       if (flags & STACK_DEPOT_FLAG_GET) {
> +               /*
> +                * Evictable entries have to allocate the max. size so th=
ey may
> +                * safely be re-used by differently sized allocations.
> +                */
> +               record_size =3D depot_stack_record_size(stack, CONFIG_STA=
CKDEPOT_MAX_FRAMES);
>                 stack =3D depot_pop_free();
> -               if (WARN_ON(!stack))
> -                       return NULL;
> +       } else {
> +               record_size =3D depot_stack_record_size(stack, nr_entries=
);
>         }
>
> -       /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. =
*/
> -       if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
> -               size =3D CONFIG_STACKDEPOT_MAX_FRAMES;
> +       if (!stack) {
> +               stack =3D depot_pop_free_pool(prealloc, record_size);
> +               if (!stack)
> +                       return NULL;
> +       }
>
>         /* Save the stack trace. */
>         stack->hash =3D hash;
> -       stack->size =3D size;
> -       /* stack->handle is already filled in by depot_init_pool(). */
> -       refcount_set(&stack->count, 1);
> -       memcpy(stack->entries, entries, flex_array_size(stack, entries, s=
ize));
> +       stack->size =3D nr_entries;
> +       /* stack->handle is already filled in by depot_pop_free_pool(). *=
/
> +       memcpy(stack->entries, entries, flex_array_size(stack, entries, n=
r_entries));
> +
> +       if (flags & STACK_DEPOT_FLAG_GET) {
> +               refcount_set(&stack->count, 1);
> +       } else {
> +               /* Warn on attempts to switch to refcounting this entry. =
*/
> +               refcount_set(&stack->count, REFCOUNT_SATURATED);
> +       }
>
>         /*
>          * Let KMSAN know the stored stack record is initialized. This sh=
all
>          * prevent false positive reports if instrumented code accesses i=
t.
>          */
> -       kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
> +       kmsan_unpoison_memory(stack, record_size);
>
>         counters[DEPOT_COUNTER_ALLOCS]++;
>         counters[DEPOT_COUNTER_INUSE]++;

I wonder if we should separate the stat counters for
evictable/non-evictable cases. For non-evictable, we could count the
amount of consumed memory.

> @@ -660,7 +668,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
>          * Allocate memory for a new pool if required now:
>          * we won't be able to do that under the lock.
>          */
> -       if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
> +       if (unlikely(can_alloc && !READ_ONCE(new_pool))) {
>                 /*
>                  * Zero out zone modifiers, as we don't have specific zon=
e
>                  * requirements. Keep the flags related to allocation in =
atomic
> @@ -681,7 +689,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
>         found =3D find_stack(bucket, entries, nr_entries, hash, depot_fla=
gs);
>         if (!found) {
>                 struct stack_record *new =3D
> -                       depot_alloc_stack(entries, nr_entries, hash, &pre=
alloc);
> +                       depot_alloc_stack(entries, nr_entries, hash, depo=
t_flags, &prealloc);
>
>                 if (new) {
>                         /*
> --
> 2.43.0.429.g432eaa2c6b-goog
>

We can also now drop the special case for DEPOT_POOLS_CAP for KMSAN.

Otherwise, looks good to me.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for cleaning this up!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfzpPvg3UXKfxhe8n-tT2Pqhfysy_HdrMb6MxaEtnJ2BQ%40mail.gmai=
l.com.
