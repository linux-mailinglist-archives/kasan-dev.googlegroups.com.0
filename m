Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPEQXSTQMGQE5AZYACI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D9BF78D47F
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 11:13:33 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-51a5296eb8esf4213312a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 02:13:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693386813; cv=pass;
        d=google.com; s=arc-20160816;
        b=SLCjnuXNUhTbSkS1ji99vUjS6ZRFqj4iEgY4sTb2hKTSQ2FtUp/AIS+cMZ/MM30Its
         JD8gdiOrEeCuHNApxrlFLwO5hnQNOhhCjeeiKqUsrIBt2/pd2WowAMhDrDyo91SsEXM6
         UJ/jpUVll3dqoRDuYTFmqJ58LaLVJU2tcS1o92EadVREQ1D8lKmpQg/waq8Shw0heeXr
         Sa1DELjvhb0lvkGmwdEWIDrqoDtGHCEbsw4rvtfN2p4X8xHnL+xXrm1IOXy2qGPmOx2A
         zfxYD9tOoIEU2W6M5KML3bZPDQq8mqvGlodZvVGrCZZk98YjPcIIoLpTr+Kj0dgBYR/s
         N5NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qoPExYVGrsONqtVnhTGjcnadBbFe07pc3RSU3dpUnNA=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=Qn6/EN5GLjGEvjPL54Qn/Tkjz9AZTkNDGT3TJzSKuFlpYVq5i39ttLqfKucCeJ7tNI
         0Lf+sescKXnVqX+XwyBpWTDcKJkJEdiwnkuogNMQx9bG17rhSEuDZupNuYakkAYX8Nzy
         f1TNDnBHXu+6sMgfOxcNnfkryAWj/90yr7/oHHNc1LBtWEhPuv1Df1I+7o8asJQ0TVPD
         9wjthUAIWm1G2S6uOorZc/fCTJBijRKbnIYWl6tafeY9OYp4a0ovFgzONiTddI242fkJ
         HhSRQSatQHR4VfEzyOemkliSbt2wdZJaeObHTvc+L6ESIAP8MWxi0N6AnW4d72kkHNsS
         8mXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pCC955bU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693386813; x=1693991613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qoPExYVGrsONqtVnhTGjcnadBbFe07pc3RSU3dpUnNA=;
        b=e79cBHZS4Mg9tl/5o/OXCEcP2jEQY6VStzd6M5UjbykwkukA73Ae7YixPpM+SBhDMJ
         bfuVI94sHK0TX8tg7alDlgbGf0LsNgIiol1BV1iRi+u5Sn+i+xR6t+3FZukXhI0c06qK
         kGaTQLH/rO/lKrzZwPLHlXfZWT5/Ul5Aa4k4YwowE6R/ZMHone1plmX0nOUpakAAzH0F
         PAW7NCIucBtlttA8zNweUAeTW85uLp4YdeOaDQFdk+AIvB3FqS+9lR7gPzqkovWym6kw
         cS+wgMxvCK0ysymn/q2iOOIHB1VIuznCUIe/7jv8/+W28/Go19aMRL5m2IyntesDtBJ3
         ymxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693386813; x=1693991613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qoPExYVGrsONqtVnhTGjcnadBbFe07pc3RSU3dpUnNA=;
        b=iRnILBfgiLgaeyV2KNYzdvs06wHbry5AeAFAU5BoPx7Di69wpke1QnJtO5OJmYIa5V
         Uc9HNNzVjciFQgl4yaI3yc11LLZrDg3biWfGywhMlW0vMfRmuYfPoSd/pXBlxCaRS2f9
         6v5XZ4i2g3N8ZAoLxVYU6wHRckQzmOLpN0WNV+4E/8GZXielhpY1xIDVl7QJUoLa1We8
         ZCFm8DsuLWN0oyUcctr5kssqSakjHLAONVS9ZX3dutgIWyZNMH+x5T4JC4T7wPfKnJG+
         FS+9Bc5KZ+DPWfc/7ECQsA+glVf732G5Y9p79vsB4+Nl4r9OMQI2TvVUp6NYEih4fY1J
         MkWQ==
X-Gm-Message-State: AOJu0YwLJG/TFPZKZWbrIeLCUbFqBSEdck+Kd1+ErkWwrsNQ+cV8UfqL
	MP57P+GAfcV3D5PmXpNpSCs=
X-Google-Smtp-Source: AGHT+IFcYq4AjJpVc45IV8DImkgx48wEKrka74+nhpcC/znQmWtSRcAyBTanKDkqkKvyPgvAHNoxGg==
X-Received: by 2002:a05:6402:120b:b0:52a:3ee9:a786 with SMTP id c11-20020a056402120b00b0052a3ee9a786mr1270985edw.26.1693386812788;
        Wed, 30 Aug 2023 02:13:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d841:0:b0:522:3a21:f22d with SMTP id f1-20020aa7d841000000b005223a21f22dls75829eds.2.-pod-prod-04-eu;
 Wed, 30 Aug 2023 02:13:31 -0700 (PDT)
X-Received: by 2002:aa7:c74c:0:b0:51d:95f2:ee76 with SMTP id c12-20020aa7c74c000000b0051d95f2ee76mr1332166eds.27.1693386810926;
        Wed, 30 Aug 2023 02:13:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693386810; cv=none;
        d=google.com; s=arc-20160816;
        b=CTD3GHDo8XaBlmZFcQ1u/puhBpSLmHVWCpkyQyOGCq8sldRiGYiQtKz47AXXtUf262
         Fk5FAIQBSma9h1Fu4YJbJGk6/0OMLLhpbiBd+HE6UHYekY0HUyo0sv8HmB4mMoTtz7R8
         //R6QRbu4LZsIt0aEN1c7dH6vIgAXOF0KkH4Br5f0J7UIfpBXj58HtDrYuro1NeEbPy9
         RUis5VT6zdKK37OmXdTSjuoRS3rBRMAE6vIvjIJvK++7AJ4cvmpJUCWeYn6k8IaoV0JE
         h4LWaBZX0Niauhcw47AFp1VpiVIJPmrTSJFYoTyI8pGv54vi3Lt5I8rWpXfkp7w/41/H
         xp0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zhyEw/ePQDVdb4vOINYViLe53fZAlgyX/muJWosF9Kc=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=g1yKJmtcVWf0227CFbk68W6F54SkuJITjEDG5sftLweniKM3ecpSMEv80/g4W2pp/S
         o52Jaf7IP+TqYrJU2G7FNYVtcwfAEXYQ8m0eq2TIqfvi/pi4gxRQ67s6i5Jbpo9Em1J3
         0tCqeCTvcOTT+UF/ISWi0UlHdZYpGrchvl+i5OsMdPEng4PXkA/Wg9MSzS3e/fSabRe0
         bNCAw54GpDgGKju+YOyy2+wOrHjS+JcIZ1mlgw294C48xeHgJsM18Dk91cvPD+1xhZgn
         QsJoGhsfP1JL3/tI0PuPGVqCmNam0Ydd9Nl2aP7JMygdpDa/5afr4TnaMf3bSclrZnir
         NyQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pCC955bU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id dn17-20020a05640222f100b0052bced1f364si314254edb.4.2023.08.30.02.13.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 02:13:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-31c73c21113so4732865f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 02:13:30 -0700 (PDT)
X-Received: by 2002:a5d:69ce:0:b0:31c:7001:3873 with SMTP id s14-20020a5d69ce000000b0031c70013873mr1009604wrw.60.1693386810299;
        Wed, 30 Aug 2023 02:13:30 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id n8-20020a5d4c48000000b003140f47224csm16003124wrt.15.2023.08.30.02.13.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 02:13:29 -0700 (PDT)
Date: Wed, 30 Aug 2023 11:13:23 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
Message-ID: <ZO8IMysDIT7XnN9Z@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=pCC955bU;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Aug 29, 2023 at 07:11PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Currently, stack depot uses the following locking scheme:
> 
> 1. Lock-free accesses when looking up a stack record, which allows to
>    have multiple users to look up records in parallel;
> 2. Spinlock for protecting the stack depot pools and the hash table
>    when adding a new record.
> 
> For implementing the eviction of stack traces from stack depot, the
> lock-free approach is not going to work anymore, as we will need to be
> able to also remove records from the hash table.
> 
> Convert the spinlock into a read/write lock, and drop the atomic accesses,
> as they are no longer required.
> 
> Looking up stack traces is now protected by the read lock and adding new
> records - by the write lock. One of the following patches will add a new
> function for evicting stack records, which will be protected by the write
> lock as well.
> 
> With this change, multiple users can still look up records in parallel.
> 
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/stackdepot.c | 76 ++++++++++++++++++++++--------------------------
>  1 file changed, 35 insertions(+), 41 deletions(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 9011f4adcf20..5ad454367379 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -23,6 +23,7 @@
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
>  #include <linux/slab.h>
> +#include <linux/spinlock.h>
>  #include <linux/stacktrace.h>
>  #include <linux/stackdepot.h>
>  #include <linux/string.h>
> @@ -92,15 +93,15 @@ static void *new_pool;
>  static int pools_num;
>  /* Next stack in the freelist of stack records within stack_pools. */
>  static struct stack_record *next_stack;
> -/* Lock that protects the variables above. */
> -static DEFINE_RAW_SPINLOCK(pool_lock);
>  /*
>   * Stack depot tries to keep an extra pool allocated even before it runs out
>   * of space in the currently used pool. This flag marks whether this extra pool
>   * needs to be allocated. It has the value 0 when either an extra pool is not
>   * yet allocated or if the limit on the number of pools is reached.
>   */
> -static int new_pool_required = 1;
> +static bool new_pool_required = true;
> +/* Lock that protects the variables above. */
> +static DEFINE_RWLOCK(pool_rwlock);

Despite this being a rwlock, it'll introduce tons of (cache) contention
for the common case (stack depot entry exists).

If creating new stack depot entries is only common during "warm-up" and
then becomes exceedingly rare, I think a percpu-rwsem (read-lock is a
CPU-local access, but write-locking is expensive) may be preferable.

>  static int __init disable_stack_depot(char *str)
>  {
> @@ -248,12 +249,7 @@ static void depot_init_pool(void *pool)
>  
>  	/* Save reference to the pool to be used by depot_fetch_stack. */
>  	stack_pools[pools_num] = pool;
> -
> -	/*
> -	 * WRITE_ONCE pairs with potential concurrent read in
> -	 * depot_fetch_stack.
> -	 */
> -	WRITE_ONCE(pools_num, pools_num + 1);
> +	pools_num++;
>  }
>  
>  /* Keeps the preallocated memory to be used for a new stack depot pool. */
> @@ -262,10 +258,8 @@ static void depot_keep_new_pool(void **prealloc)
>  	/*
>  	 * If a new pool is already saved or the maximum number of
>  	 * pools is reached, do not use the preallocated memory.
> -	 * READ_ONCE is only used to mark the variable as atomic,
> -	 * there are no concurrent writes.
>  	 */
> -	if (!READ_ONCE(new_pool_required))
> +	if (!new_pool_required)

In my comment for the other patch I already suggested this change. Maybe
move it there.

>  		return;
>  
>  	/*
> @@ -281,9 +275,8 @@ static void depot_keep_new_pool(void **prealloc)
>  	 * At this point, either a new pool is kept or the maximum
>  	 * number of pools is reached. In either case, take note that
>  	 * keeping another pool is not required.
> -	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
>  	 */
> -	smp_store_release(&new_pool_required, 0);
> +	new_pool_required = false;
>  }
>  
>  /* Updates refences to the current and the next stack depot pools. */
> @@ -300,7 +293,7 @@ static bool depot_update_pools(void **prealloc)
>  
>  		/* Take note that we might need a new new_pool. */
>  		if (pools_num < DEPOT_MAX_POOLS)
> -			smp_store_release(&new_pool_required, 1);
> +			new_pool_required = true;
>  
>  		/* Try keeping the preallocated memory for new_pool. */
>  		goto out_keep_prealloc;
> @@ -369,18 +362,13 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
>  {
>  	union handle_parts parts = { .handle = handle };
> -	/*
> -	 * READ_ONCE pairs with potential concurrent write in
> -	 * depot_init_pool.
> -	 */
> -	int pools_num_cached = READ_ONCE(pools_num);
>  	void *pool;
>  	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
>  	struct stack_record *stack;

I'd add lockdep assertions to check that the lock is held appropriately
when entering various helper functions that don't actually take the
lock. Similarly for places that should not have the lock held you could
assert the lock is not held.

> -	if (parts.pool_index > pools_num_cached) {
> +	if (parts.pool_index > pools_num) {
>  		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
> -			parts.pool_index, pools_num_cached, handle);
> +			parts.pool_index, pools_num, handle);
>  		return NULL;
>  	}
>  
> @@ -439,6 +427,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	depot_stack_handle_t handle = 0;
>  	struct page *page = NULL;
>  	void *prealloc = NULL;
> +	bool need_alloc = false;
>  	unsigned long flags;
>  	u32 hash;
>  
> @@ -458,22 +447,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	hash = hash_stack(entries, nr_entries);
>  	bucket = &stack_table[hash & stack_hash_mask];
>  
> -	/*
> -	 * Fast path: look the stack trace up without locking.
> -	 * smp_load_acquire pairs with smp_store_release to |bucket| below.
> -	 */
> -	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
> -	if (found)
> +	read_lock_irqsave(&pool_rwlock, flags);
> +
> +	/* Fast path: look the stack trace up without full locking. */
> +	found = find_stack(*bucket, entries, nr_entries, hash);
> +	if (found) {
> +		read_unlock_irqrestore(&pool_rwlock, flags);
>  		goto exit;
> +	}
> +
> +	/* Take note if another stack pool needs to be allocated. */
> +	if (new_pool_required)
> +		need_alloc = true;
> +
> +	read_unlock_irqrestore(&pool_rwlock, flags);
>  
>  	/*
> -	 * Check if another stack pool needs to be allocated. If so, allocate
> -	 * the memory now: we won't be able to do that under the lock.
> -	 *
> -	 * smp_load_acquire pairs with smp_store_release
> -	 * in depot_update_pools and depot_keep_new_pool.
> +	 * Allocate memory for a new pool if required now:
> +	 * we won't be able to do that under the lock.
>  	 */
> -	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
> +	if (unlikely(can_alloc && need_alloc)) {
>  		/*
>  		 * Zero out zone modifiers, as we don't have specific zone
>  		 * requirements. Keep the flags related to allocation in atomic
> @@ -487,7 +480,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  			prealloc = page_address(page);
>  	}
>  
> -	raw_spin_lock_irqsave(&pool_lock, flags);
> +	write_lock_irqsave(&pool_rwlock, flags);
>  
>  	found = find_stack(*bucket, entries, nr_entries, hash);
>  	if (!found) {
> @@ -496,11 +489,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  
>  		if (new) {
>  			new->next = *bucket;
> -			/*
> -			 * smp_store_release pairs with smp_load_acquire
> -			 * from |bucket| above.
> -			 */
> -			smp_store_release(bucket, new);
> +			*bucket = new;
>  			found = new;
>  		}
>  	} else if (prealloc) {
> @@ -511,7 +500,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		depot_keep_new_pool(&prealloc);
>  	}
>  
> -	raw_spin_unlock_irqrestore(&pool_lock, flags);
> +	write_unlock_irqrestore(&pool_rwlock, flags);
>  exit:
>  	if (prealloc) {
>  		/* Stack depot didn't use this memory, free it. */
> @@ -535,6 +524,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  			       unsigned long **entries)
>  {
>  	struct stack_record *stack;
> +	unsigned long flags;
>  
>  	*entries = NULL;
>  	/*
> @@ -546,8 +536,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  	if (!handle || stack_depot_disabled)
>  		return 0;
>  
> +	read_lock_irqsave(&pool_rwlock, flags);
> +
>  	stack = depot_fetch_stack(handle);
>  
> +	read_unlock_irqrestore(&pool_rwlock, flags);
> +
>  	*entries = stack->entries;
>  	return stack->size;
>  }
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO8IMysDIT7XnN9Z%40elver.google.com.
