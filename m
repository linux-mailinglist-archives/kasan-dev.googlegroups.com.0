Return-Path: <kasan-dev+bncBDW2JDUY5AORBHVZUGWQMGQEWECVURY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 931FE830FEB
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 00:02:55 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2cccd597247sf105289631fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jan 2024 15:02:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705532575; cv=pass;
        d=google.com; s=arc-20160816;
        b=su89G+a1HRGis+eGXGrKhdsn9PSv0xWiM3bEWhPeXg31o1ia+G3x0ERzVOYL0WwTAz
         UV5OlZ0msZUoX+ztSlltwt6u9ldbWifta1GmfIzWvYv0ribHY6ofMCS4jjRhNkonuxr7
         m2zqXjEncLMMoU5GJ7z2ppEurK+MFmTMd/so4pvC5gbZNGFlK4gjtODvcawnwZaME2Dd
         Z0B8aFFSha/ov1aqpzI0qnM1yN4NATn7HgAxPhc5mYmCX7+6S+TImeQD1aMbup07nmxU
         YUgL1XRzGT6vPrSggfzzr7nir0S+AVUA/iGB4mQjnCPDnTMOo33C0z6fN3Y5u4J06Jko
         GNkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=nEjgH3wVYtgwtr27UuPptoAAvGl1FkNc3WJZeP1dLPo=;
        fh=poFGwJWhanyqHgQ8/uJ5hrXDTGXlsSSieqR/Xi40FjI=;
        b=CwcDsacb1eOrbWPJJ8yWV9wZnrAqJDP+bsrIvreH+K/xxCWNaBqF9PIjUqbscT0IB0
         pxapOBmjHmPJ93SsVmE5FBkGyUgKQ8Eq+IJriT7p03znlkb8Nj23Tr+hQ1a8I06ANBSH
         NIdkeVZow19gh31cAUAcR3cSDX+ZigNlEd4Z3SAPKtmBXLrEWrqbg+9+/4FT4TB33wSi
         YheJA99EkrClDlJPzWWvbMocHKvNjuTZNqUZw9WBY9X43csm3UxncMNnTwSLmMzt12w+
         UEiIikCs2nVhuzKB9CC8do9bIOr5rRaO8yurYKRjnbN1RWzllgJQZmT1XITBH4COhrBi
         /gkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="CQ/swPJQ";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705532575; x=1706137375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nEjgH3wVYtgwtr27UuPptoAAvGl1FkNc3WJZeP1dLPo=;
        b=sidPopA2gJ+ljQZJEHNQl1mtflqJy/Kdf63PuEwDh7iBM/R8QYZBWv+Hlcd2Uw/GXl
         DBAOW2lJszZ7iMBLJH3Fjo4qVGwcOHupdeEXY9vLMTGYxG6K5oTmXbfXYyZHjzGBKhpm
         6X+ZC/s0iRcPzyw0rEIM/4rvth4DrSYNR4y211RRjypfgii0qitwEosOMQ58nS+pk0rp
         9sZJfrXRdRGKI680kGa+NaPPeIUDMPwlCK+1tbN+IYrhZxHhqQqzMUUY13q4nRn3yxhD
         6IMjWKEK3tLYJGlmFbZOQXF8KbjrlYk7QoYlsno4xgcILWTB8YyWIxLHF0GZkFaHhRRi
         py2Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1705532575; x=1706137375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nEjgH3wVYtgwtr27UuPptoAAvGl1FkNc3WJZeP1dLPo=;
        b=DRN6XzlcOzXgbz6gibvSFiQlF0rJfUxfJONyXmTBk/0riMYzcdMnIxcRNI0OMxQEuO
         gi/NuSXpXvkJDov5o3e2ahe6/N2auzn3B45+Z70v9mCYZvSyqy95wj0XnvM/HAEoE0fF
         ifzTfY9mtarhwFog9oR0EaFzzKbZLE0AmbzOiMFgz9s40uazQO3u4lZWVkTY5aQDojyc
         eB9/MjQLu41zCwz5f52MEwRb0q1Oq2VKjLNiXsonbh75nw3Z5Xux5JEa7IjVkAtIUhJC
         c4SVqRF4OwjiUddcMWUtzBm19uP0iQ1MbJiNY09iURtizFGsnCA61odq3CfTbA3CmDfg
         tdWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705532575; x=1706137375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nEjgH3wVYtgwtr27UuPptoAAvGl1FkNc3WJZeP1dLPo=;
        b=JpsqiN3yXP9cx0wWirBEQFhVYIYFXZrd8D4UuuAg292Nt+PS551inJf89b1wV9xfMH
         jYcSTROjWqdXWr1sjNUFPbzsVgaBxYUzmWZELGkmIVuUZAhpnhNY7fjna3ShTQMxX8pm
         rdezKJoGq7y1z9NJG60D2veoGgsJpXYAeFxyNy5geaYpxwCojsT/wSKrPEMxR6T5IC7o
         vS22Pc1a+uRGJtnqbMouUhMiTx0BTm1taBPHIbgZP8Hw0sLVNG76h2QTY6Y8sjoE76hY
         lU0sznkzFMGZfBlK+PDnFsvoMowJc/T634O8itCPFZ3umbIOnwRPKlJFFnBjMaGJdxjD
         LKjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy40fMhidRR1zjhWmkMUJ9lRTWlDUMoa/T7iI09doBF94IEIv4H
	hxq1lpDs/bIXh5Edss4l2Dg=
X-Google-Smtp-Source: AGHT+IFekxHC1Sfhl/PEEfeQFO0HEj6cHRNpbSG9/RP1GZmDz6qLcykj05BbUWEmFYDtTZHhpBBIzw==
X-Received: by 2002:a05:651c:1592:b0:2cd:f5b9:b306 with SMTP id h18-20020a05651c159200b002cdf5b9b306mr107917ljq.115.1705532574488;
        Wed, 17 Jan 2024 15:02:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a11:b0:2cd:eb51:129b with SMTP id
 by17-20020a05651c1a1100b002cdeb51129bls65903ljb.2.-pod-prod-08-eu; Wed, 17
 Jan 2024 15:02:53 -0800 (PST)
X-Received: by 2002:ac2:5974:0:b0:50e:3d60:7784 with SMTP id h20-20020ac25974000000b0050e3d607784mr2124838lfp.235.1705532572540;
        Wed, 17 Jan 2024 15:02:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705532572; cv=none;
        d=google.com; s=arc-20160816;
        b=Wuqw4Bh9IzzEtHYL+lb46yfKitlzY9DdIPPbgjKKavyv4GPZrbUt5h1JwDW4vNVwIU
         gJR5MVsFdb3CK8G0g+d6L3kGvi6CvgXDOMUe4l69y2DxZsvM41/NigiVAfHZ11wTYfzm
         6qhRPHvRWqyhtgnATMyyWqwLD5jNmaQxiIPwnJqrkyoFVnMRFdxB6jKg8Av4wWbySqAm
         ttaCvgpGJnMfhSf+lhMR4rwUCsgA1+YF57Maa5HgHpFyE7ZFoV3Bi1SL0JLkr3NcCg0t
         3SzfX3UyDZtP25EdlFwX4IoLmaA/2H5P0F2vQHr/FafstOOmsI+ko7NkLE+/Ruc9EvM8
         f+og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SGuwmcM9VZPWGXdP4OLSWh6XXl1zTy0Ln1eSOnA9S5c=;
        fh=poFGwJWhanyqHgQ8/uJ5hrXDTGXlsSSieqR/Xi40FjI=;
        b=oKtG8Trq24fsmh3n4IqdqH8rgpyVAGKYJJSIZWZIDSSuKe7SzFd1FCN2pqWApHqTBB
         f4DkZoilsOsUTV0MkSYcRc4mDAtFK95hluIi+fI2V+QOE5gGHBuhXBuWBi9ZGo/XG7ee
         F7F8Qqrz2G/LDLJWvIo6B8f0/y0HH3zoJcG8LuapW9p3MdHbxTVQmR++MdbfmN10pM5I
         D04RwCpvVWSf890REZ/sqIP4zxxIDoqX/J+CS+J/VD5rWep56EYpraAMTeFUrkMPVAkf
         ls6h9I9I438D9nKW2jBEPsRmO6WGMlog2xhnRoLMkaUQVy8eawrHtqGFvTTFMEZFn8h6
         MLmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="CQ/swPJQ";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id n5-20020a170906088500b00a2b190de0a4si457100eje.0.2024.01.17.15.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jan 2024 15:02:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3366e78d872so11568423f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 17 Jan 2024 15:02:52 -0800 (PST)
X-Received: by 2002:a5d:5887:0:b0:337:c5f5:1f2d with SMTP id
 n7-20020a5d5887000000b00337c5f51f2dmr409309wrf.274.1705532572055; Wed, 17 Jan
 2024 15:02:52 -0800 (PST)
MIME-Version: 1.0
References: <20240115092727.888096-1-elver@google.com> <20240115092727.888096-2-elver@google.com>
In-Reply-To: <20240115092727.888096-2-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 18 Jan 2024 00:02:40 +0100
Message-ID: <CA+fCnZcx4vnD=xun-tDQS27EUYKd2VLZQ3s4Vnm3sTTpz2WCXw@mail.gmail.com>
Subject: Re: [PATCH RFC 2/2] stackdepot: make fast paths lock-less again
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="CQ/swPJQ";       spf=pass
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

On Mon, Jan 15, 2024 at 10:27=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> With the introduction of the pool_rwlock (reader-writer lock), several
> fast paths end up taking the pool_rwlock as readers. Furthermore,
> stack_depot_put() unconditionally takes the pool_rwlock as a writer.
>
> Despite allowing readers to make forward-progress concurrently,
> reader-writer locks have inherent cache contention issues, which does
> not scale well on systems with large CPU counts.
>
> Rework the synchronization story of stack depot to again avoid taking
> any locks in the fast paths. This is done by relying on RCU-protected
> list traversal, and the NMI-safe subset of RCU to delay reuse of freed
> stack records. See code comments for more details.
>
> Along with the performance issues, this also fixes incorrect nesting of
> rwlock within a raw_spinlock, given that stack depot should still be
> usable from anywhere:
>
>  | [ BUG: Invalid wait context ]
>  | -----------------------------
>  | swapper/0/1 is trying to lock:
>  | ffffffff89869be8 (pool_rwlock){..--}-{3:3}, at: stack_depot_save_flags
>  | other info that might help us debug this:
>  | context-{5:5}
>  | 2 locks held by swapper/0/1:
>  |  #0: ffffffff89632440 (rcu_read_lock){....}-{1:3}, at: __queue_work
>  |  #1: ffff888100092018 (&pool->lock){-.-.}-{2:2}, at: __queue_work  <--=
 raw_spin_lock
>
> Stack depot usage stats are similar to the previous version after a
> KASAN kernel boot:
>
>  $ cat /sys/kernel/debug/stackdepot/stats
>  pools: 838
>  allocations: 29865
>  frees: 6604
>  in_use: 23261
>  freelist_size: 1879
>
> The number of pools is the same as previously. The freelist size is
> minimally larger, but this may also be due to variance across system
> boots. This shows that even though we do not eagerly wait for the next
> RCU grace period (such as with synchronize_rcu() or call_rcu()) after
> freeing a stack record - requiring depot_pop_free() to "poll" if an
> entry may be used - new allocations are very likely to happen in later
> RCU grace periods.
>
> Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
> Reported-by: Andi Kleen <ak@linux.intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> ---
>  lib/stackdepot.c | 329 +++++++++++++++++++++++++++++++----------------
>  1 file changed, 217 insertions(+), 112 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 80a8ca24ccc8..db174cc02d34 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -24,6 +24,8 @@
>  #include <linux/mutex.h>
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
> +#include <linux/rculist.h>
> +#include <linux/rcupdate.h>
>  #include <linux/refcount.h>
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
> @@ -68,12 +70,28 @@ union handle_parts {
>  };
>
>  struct stack_record {
> -       struct list_head list;          /* Links in hash table or freelis=
t */
> +       struct list_head hash_list;     /* Links in the hash table */
>         u32 hash;                       /* Hash in hash table */
>         u32 size;                       /* Number of stored frames */
> -       union handle_parts handle;
> +       union handle_parts handle;      /* Constant after initialization =
*/
>         refcount_t count;
> -       unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];    /* Frames=
 */
> +       union {
> +               unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];    /=
* Frames */
> +               struct {
> +                       /*
> +                        * An important invariant of the implementation i=
s to
> +                        * only place a stack record onto the freelist if=
f its
> +                        * refcount is zero. Because stack records with a=
 zero
> +                        * refcount are never considered as valid, it is =
safe to
> +                        * union @entries and freelist management state b=
elow.
> +                        * Conversely, as soon as an entry is off the fre=
elist
> +                        * and its refcount becomes non-zero, the below m=
ust not
> +                        * be accessed until being placed back on the fre=
elist.
> +                        */
> +                       struct list_head free_list;     /* Links in the f=
reelist */
> +                       unsigned long rcu_state;        /* RCU cookie */
> +               };
> +       };
>  };
>
>  #define DEPOT_STACK_RECORD_SIZE \
> @@ -113,8 +131,8 @@ static LIST_HEAD(free_stacks);
>   * yet allocated or if the limit on the number of pools is reached.
>   */
>  static bool new_pool_required =3D true;
> -/* Lock that protects the variables above. */
> -static DEFINE_RWLOCK(pool_rwlock);
> +/* The lock must be held when performing pool or free list modifications=
. */
> +static DEFINE_RAW_SPINLOCK(pool_lock);
>
>  /* Statistics counters for debugfs. */
>  enum depot_counter_id {
> @@ -276,14 +294,15 @@ int stack_depot_init(void)
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_init);
>
> -/* Initializes a stack depol pool. */
> +/*
> + * Initializes new stack depot @pool, release all its entries to the fre=
elist,
> + * and update the list of pools.
> + */
>  static void depot_init_pool(void *pool)
>  {
>         int offset;
>
> -       lockdep_assert_held_write(&pool_rwlock);
> -
> -       WARN_ON(!list_empty(&free_stacks));
> +       lockdep_assert_held(&pool_lock);
>
>         /* Initialize handles and link stack records into the freelist. *=
/
>         for (offset =3D 0; offset <=3D DEPOT_POOL_SIZE - DEPOT_STACK_RECO=
RD_SIZE;
> @@ -294,19 +313,31 @@ static void depot_init_pool(void *pool)
>                 stack->handle.offset =3D offset >> DEPOT_STACK_ALIGN;
>                 stack->handle.extra =3D 0;
>
> -               list_add(&stack->list, &free_stacks);
> +               /*
> +                * Stack traces of size 0 are never saved, and we can sim=
ply use
> +                * the size field as an indicator if this is a new unused=
 stack
> +                * record in the freelist.
> +                */
> +               stack->size =3D 0;
> +
> +               INIT_LIST_HEAD(&stack->hash_list);
> +               /* Add to the freelist front to prioritize never-used ent=
ries. */
> +               list_add(&stack->free_list, &free_stacks);
>                 counters[DEPOT_COUNTER_FREELIST_SIZE]++;
>         }
>
>         /* Save reference to the pool to be used by depot_fetch_stack(). =
*/
>         stack_pools[pools_num] =3D pool;
> -       pools_num++;
> +
> +       /* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
> +       WRITE_ONCE(pools_num, pools_num + 1);
> +       ASSERT_EXCLUSIVE_WRITER(pools_num);
>  }
>
>  /* Keeps the preallocated memory to be used for a new stack depot pool. =
*/
>  static void depot_keep_new_pool(void **prealloc)
>  {
> -       lockdep_assert_held_write(&pool_rwlock);
> +       lockdep_assert_held(&pool_lock);
>
>         /*
>          * If a new pool is already saved or the maximum number of
> @@ -329,17 +360,16 @@ static void depot_keep_new_pool(void **prealloc)
>          * number of pools is reached. In either case, take note that
>          * keeping another pool is not required.
>          */
> -       new_pool_required =3D false;
> +       WRITE_ONCE(new_pool_required, false);
>  }
>
> -/* Updates references to the current and the next stack depot pools. */
> -static bool depot_update_pools(void **prealloc)
> +/*
> + * Try to initialize a new stack depot pool from either a previous or th=
e
> + * current pre-allocation, and release all its entries to the freelist.
> + */
> +static bool depot_try_init_pool(void **prealloc)
>  {
> -       lockdep_assert_held_write(&pool_rwlock);
> -
> -       /* Check if we still have objects in the freelist. */
> -       if (!list_empty(&free_stacks))
> -               goto out_keep_prealloc;
> +       lockdep_assert_held(&pool_lock);
>
>         /* Check if we have a new pool saved and use it. */
>         if (new_pool) {
> @@ -348,10 +378,9 @@ static bool depot_update_pools(void **prealloc)
>
>                 /* Take note that we might need a new new_pool. */
>                 if (pools_num < DEPOT_MAX_POOLS)
> -                       new_pool_required =3D true;
> +                       WRITE_ONCE(new_pool_required, true);
>
> -               /* Try keeping the preallocated memory for new_pool. */
> -               goto out_keep_prealloc;
> +               return true;
>         }
>
>         /* Bail out if we reached the pool limit. */
> @@ -368,35 +397,53 @@ static bool depot_update_pools(void **prealloc)
>         }
>
>         return false;
> -
> -out_keep_prealloc:
> -       /* Keep the preallocated memory for a new pool if required. */
> -       if (*prealloc)
> -               depot_keep_new_pool(prealloc);
> -       return true;
>  }
>
> -/* Allocates a new stack in a stack depot pool. */
> -static struct stack_record *
> -depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **pre=
alloc)
> +/* Try to find next free usable entry. */
> +static struct stack_record *depot_pop_free(void)
>  {
>         struct stack_record *stack;
>
> -       lockdep_assert_held_write(&pool_rwlock);
> +       lockdep_assert_held(&pool_lock);
>
> -       /* Update current and new pools if required and possible. */
> -       if (!depot_update_pools(prealloc))
> +       if (list_empty(&free_stacks))
>                 return NULL;
>
> -       /* Check if we have a stack record to save the stack trace. */
> -       if (list_empty(&free_stacks))
> +       /*
> +        * We maintain the invariant that the elements in front are least
> +        * recently used, and are therefore more likely to be associated =
with an
> +        * RCU grace period in the past. Consequently it is sufficient to=
 only
> +        * check the first entry.
> +        */
> +       stack =3D list_first_entry(&free_stacks, struct stack_record, fre=
e_list);
> +       if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
>                 return NULL;
>
> -       /* Get and unlink the first entry from the freelist. */
> -       stack =3D list_first_entry(&free_stacks, struct stack_record, lis=
t);
> -       list_del(&stack->list);
> +       list_del(&stack->free_list);
>         counters[DEPOT_COUNTER_FREELIST_SIZE]--;
>
> +       return stack;
> +}
> +
> +/* Allocates a new stack in a stack depot pool. */
> +static struct stack_record *
> +depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **pre=
alloc)
> +{
> +       struct stack_record *stack;
> +
> +       lockdep_assert_held(&pool_lock);
> +
> +       /* Check if we have a stack record to save the stack trace. */
> +       stack =3D depot_pop_free();
> +       if (!stack) {
> +               /* No usable entries on the freelist - try to refill the =
freelist. */
> +               if (!depot_try_init_pool(prealloc))
> +                       return NULL;
> +               stack =3D depot_pop_free();
> +               if (WARN_ON(!stack))
> +                       return NULL;
> +       }
> +
>         /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. =
*/
>         if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
>                 size =3D CONFIG_STACKDEPOT_MAX_FRAMES;
> @@ -421,37 +468,73 @@ depot_alloc_stack(unsigned long *entries, int size,=
 u32 hash, void **prealloc)
>
>  static struct stack_record *depot_fetch_stack(depot_stack_handle_t handl=
e)
>  {
> +       const int pools_num_cached =3D READ_ONCE(pools_num);
>         union handle_parts parts =3D { .handle =3D handle };
>         void *pool;
>         size_t offset =3D parts.offset << DEPOT_STACK_ALIGN;
>         struct stack_record *stack;
>
> -       lockdep_assert_held(&pool_rwlock);
> +       lockdep_assert_not_held(&pool_lock);
>
> -       if (parts.pool_index > pools_num) {
> +       if (parts.pool_index > pools_num_cached) {
>                 WARN(1, "pool index %d out of bounds (%d) for stack id %0=
8x\n",
> -                    parts.pool_index, pools_num, handle);
> +                    parts.pool_index, pools_num_cached, handle);
>                 return NULL;
>         }
>
>         pool =3D stack_pools[parts.pool_index];
> -       if (!pool)
> +       if (WARN_ON(!pool))
>                 return NULL;
>
>         stack =3D pool + offset;
> +       if (WARN_ON(!refcount_read(&stack->count)))
> +               return NULL;
> +
>         return stack;
>  }
>
>  /* Links stack into the freelist. */
>  static void depot_free_stack(struct stack_record *stack)
>  {
> -       lockdep_assert_held_write(&pool_rwlock);
> +       unsigned long flags;
> +
> +       lockdep_assert_not_held(&pool_lock);
>
> -       list_add(&stack->list, &free_stacks);
> +       raw_spin_lock_irqsave(&pool_lock, flags);
> +       printk_deferred_enter();
> +
> +       /*
> +        * Remove the entry from the hash list. Concurrent list traversal=
 may
> +        * still observe the entry, but since the refcount is zero, this =
entry
> +        * will no longer be considered as valid.
> +        */
> +       list_del_rcu(&stack->hash_list);
> +
> +       /*
> +        * Due to being used from constrained contexts such as the alloca=
tors,
> +        * NMI, or even RCU itself, stack depot cannot rely on primitives=
 that
> +        * would sleep (such as synchronize_rcu()) or recursively call in=
to
> +        * stack depot again (such as call_rcu()).
> +        *
> +        * Instead, get an RCU cookie, so that we can ensure this entry i=
sn't
> +        * moved onto another list until the next grace period, and concu=
rrent
> +        * RCU list traversal remains safe.
> +        */
> +       stack->rcu_state =3D get_state_synchronize_rcu();
> +
> +       /*
> +        * Add the entry to the freelist tail, so that older entries are
> +        * considered first - their RCU cookie is more likely to no longe=
r be
> +        * associated with the current grace period.
> +        */
> +       list_add_tail(&stack->free_list, &free_stacks);
>
>         counters[DEPOT_COUNTER_FREELIST_SIZE]++;
>         counters[DEPOT_COUNTER_FREES]++;
>         counters[DEPOT_COUNTER_INUSE]--;
> +
> +       printk_deferred_exit();
> +       raw_spin_unlock_irqrestore(&pool_lock, flags);
>  }
>
>  /* Calculates the hash for a stack. */
> @@ -479,22 +562,65 @@ int stackdepot_memcmp(const unsigned long *u1, cons=
t unsigned long *u2,
>
>  /* Finds a stack in a bucket of the hash table. */
>  static inline struct stack_record *find_stack(struct list_head *bucket,
> -                                            unsigned long *entries, int =
size,
> -                                            u32 hash)
> +                                             unsigned long *entries, int=
 size,
> +                                             u32 hash, depot_flags_t fla=
gs)
>  {
> -       struct list_head *pos;
> -       struct stack_record *found;
> +       struct stack_record *stack, *ret =3D NULL;
> +
> +       rcu_read_lock();
>
> -       lockdep_assert_held(&pool_rwlock);
> +       list_for_each_entry_rcu(stack, bucket, hash_list) {
> +               if (stack->hash !=3D hash || stack->size !=3D size)
> +                       continue;
>
> -       list_for_each(pos, bucket) {
> -               found =3D list_entry(pos, struct stack_record, list);
> -               if (found->hash =3D=3D hash &&
> -                   found->size =3D=3D size &&
> -                   !stackdepot_memcmp(entries, found->entries, size))
> -                       return found;
> +               /*
> +                * This may race with depot_free_stack() accessing the fr=
eelist
> +                * management state unioned with @entries. The refcount i=
s zero
> +                * in that case and the below refcount_inc_not_zero() wil=
l fail.
> +                */
> +               if (data_race(stackdepot_memcmp(entries, stack->entries, =
size)))
> +                       continue;
> +
> +               /*
> +                * Try to increment refcount. If this succeeds, the stack=
 record
> +                * is valid and has not yet been freed.
> +                *
> +                * If STACK_DEPOT_FLAG_GET is not used, it is undefined b=
ehavior
> +                * to then call stack_depot_put() later, and we can assum=
e that
> +                * a stack record is never placed back on the freelist.
> +                */
> +               if (flags & STACK_DEPOT_FLAG_GET) {
> +                       if (!refcount_inc_not_zero(&stack->count))
> +                               continue;
> +                       smp_mb__after_atomic();
> +               } else {
> +                       /*
> +                        * Pairs with the release implied by list_add_rcu=
() to
> +                        * turn the list-pointer access into an acquire; =
as-is
> +                        * it only provides dependency-ordering implied b=
y
> +                        * READ_ONCE().
> +                        *
> +                        * Normally this is not needed, if we were to con=
tinue
> +                        * using the stack_record pointer only. But, the =
pointer
> +                        * returned here is not actually used to lookup e=
ntries.
> +                        * Instead, the handle is returned, from which a =
pointer
> +                        * may then be reconstructed in depot_fetch_stack=
().
> +                        *
> +                        * Therefore, it is required to upgrade the order=
ing
> +                        * from dependency-ordering only to at least acqu=
ire to
> +                        * be able to use the handle as another reference=
 to the
> +                        * same stack record.
> +                        */
> +                       smp_mb();
> +               }
> +
> +               ret =3D stack;
> +               break;
>         }
> -       return NULL;
> +
> +       rcu_read_unlock();
> +
> +       return ret;
>  }
>
>  depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
> @@ -508,7 +634,6 @@ depot_stack_handle_t stack_depot_save_flags(unsigned =
long *entries,
>         struct page *page =3D NULL;
>         void *prealloc =3D NULL;
>         bool can_alloc =3D depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
> -       bool need_alloc =3D false;
>         unsigned long flags;
>         u32 hash;
>
> @@ -531,31 +656,16 @@ depot_stack_handle_t stack_depot_save_flags(unsigne=
d long *entries,
>         hash =3D hash_stack(entries, nr_entries);
>         bucket =3D &stack_table[hash & stack_hash_mask];
>
> -       read_lock_irqsave(&pool_rwlock, flags);
> -       printk_deferred_enter();
> -
> -       /* Fast path: look the stack trace up without full locking. */
> -       found =3D find_stack(bucket, entries, nr_entries, hash);
> -       if (found) {
> -               if (depot_flags & STACK_DEPOT_FLAG_GET)
> -                       refcount_inc(&found->count);
> -               printk_deferred_exit();
> -               read_unlock_irqrestore(&pool_rwlock, flags);
> +       /* Fast path: look the stack trace up without locking. */
> +       found =3D find_stack(bucket, entries, nr_entries, hash, depot_fla=
gs);
> +       if (found)
>                 goto exit;
> -       }
> -
> -       /* Take note if another stack pool needs to be allocated. */
> -       if (new_pool_required)
> -               need_alloc =3D true;
> -
> -       printk_deferred_exit();
> -       read_unlock_irqrestore(&pool_rwlock, flags);
>
>         /*
>          * Allocate memory for a new pool if required now:
>          * we won't be able to do that under the lock.
>          */
> -       if (unlikely(can_alloc && need_alloc)) {
> +       if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
>                 /*
>                  * Zero out zone modifiers, as we don't have specific zon=
e
>                  * requirements. Keep the flags related to allocation in =
atomic
> @@ -569,31 +679,36 @@ depot_stack_handle_t stack_depot_save_flags(unsigne=
d long *entries,
>                         prealloc =3D page_address(page);
>         }
>
> -       write_lock_irqsave(&pool_rwlock, flags);
> +       raw_spin_lock_irqsave(&pool_lock, flags);
>         printk_deferred_enter();
>
> -       found =3D find_stack(bucket, entries, nr_entries, hash);
> +       /* Try to find again, to avoid concurrently inserting duplicates.=
 */
> +       found =3D find_stack(bucket, entries, nr_entries, hash, depot_fla=
gs);
>         if (!found) {
>                 struct stack_record *new =3D
>                         depot_alloc_stack(entries, nr_entries, hash, &pre=
alloc);
>
>                 if (new) {
> -                       list_add(&new->list, bucket);
> +                       /*
> +                        * This releases the stack record into the bucket=
 and
> +                        * makes it visible to readers in find_stack().
> +                        */
> +                       list_add_rcu(&new->hash_list, bucket);
>                         found =3D new;
>                 }
> -       } else {
> -               if (depot_flags & STACK_DEPOT_FLAG_GET)
> -                       refcount_inc(&found->count);
> +       }
> +
> +       if (prealloc) {
>                 /*
> -                * Stack depot already contains this stack trace, but let=
's
> -                * keep the preallocated memory for future.
> +                * Either stack depot already contains this stack trace, =
or
> +                * depot_alloc_stack() did not consume the preallocated m=
emory.
> +                * Try to keep the preallocated memory for future.
>                  */
> -               if (prealloc)
> -                       depot_keep_new_pool(&prealloc);
> +               depot_keep_new_pool(&prealloc);
>         }
>
>         printk_deferred_exit();
> -       write_unlock_irqrestore(&pool_rwlock, flags);
> +       raw_spin_unlock_irqrestore(&pool_lock, flags);
>  exit:
>         if (prealloc) {
>                 /* Stack depot didn't use this memory, free it. */
> @@ -618,7 +733,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t h=
andle,
>                                unsigned long **entries)
>  {
>         struct stack_record *stack;
> -       unsigned long flags;
>
>         *entries =3D NULL;
>         /*
> @@ -630,13 +744,13 @@ unsigned int stack_depot_fetch(depot_stack_handle_t=
 handle,
>         if (!handle || stack_depot_disabled)
>                 return 0;
>
> -       read_lock_irqsave(&pool_rwlock, flags);
> -       printk_deferred_enter();
> -
>         stack =3D depot_fetch_stack(handle);
> -
> -       printk_deferred_exit();
> -       read_unlock_irqrestore(&pool_rwlock, flags);
> +       /*
> +        * Should never be NULL, otherwise this is a use-after-put (or ju=
st a
> +        * corrupt handle).
> +        */
> +       if (WARN(!stack, "corrupt handle or use after stack_depot_put()")=
)
> +               return 0;
>
>         *entries =3D stack->entries;
>         return stack->size;
> @@ -646,29 +760,20 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>  void stack_depot_put(depot_stack_handle_t handle)
>  {
>         struct stack_record *stack;
> -       unsigned long flags;
>
>         if (!handle || stack_depot_disabled)
>                 return;
>
> -       write_lock_irqsave(&pool_rwlock, flags);
> -       printk_deferred_enter();
> -
>         stack =3D depot_fetch_stack(handle);
> -       if (WARN_ON(!stack))
> -               goto out;
> -
> -       if (refcount_dec_and_test(&stack->count)) {
> -               /* Unlink stack from the hash table. */
> -               list_del(&stack->list);
> +       /*
> +        * Should always be able to find the stack record, otherwise this=
 is an
> +        * unbalanced put attempt (or corrupt handle).
> +        */
> +       if (WARN(!stack, "corrupt handle or unbalanced stack_depot_put()"=
))
> +               return;
>
> -               /* Free stack. */
> +       if (refcount_dec_and_test(&stack->count))
>                 depot_free_stack(stack);
> -       }
> -
> -out:
> -       printk_deferred_exit();
> -       write_unlock_irqrestore(&pool_rwlock, flags);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_put);
>
> --
> 2.43.0.275.g3460e3d667-goog
>

From the functional perspective:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcx4vnD%3Dxun-tDQS27EUYKd2VLZQ3s4Vnm3sTTpz2WCXw%40mail.gm=
ail.com.
