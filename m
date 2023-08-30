Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEX6XOTQMGQEIJEALUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ED0E78D425
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 10:34:27 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-52a08d02c62sf4125953a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 01:34:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693384467; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfrUHkloYi81bXlVVBUGQYouBcLi6O59HgcCYGEtdNkdvtIgX1WXdZIhvfpBdsE34X
         5tij4Gi9aGhq01ejllhF0WiOQwLCL9pYQmeyZjAdsl98N0yq7DiBDCV1DZeFzygxdtCx
         cSZULRbOH+XfZS+NFlvNyf/CO3bBcuFmXaihTDB3jNkp8A9Ly+YC8vQxPXLl1Pvxlvj1
         j0VAFGyrtOoxhpzluCMp7e18y7ANF6ocdI+h1UmjVwUC4AOp8QfLkCtVf47y1N54Ja7W
         XD6IIqOv0vztbS3n5zXOG8NEDm/1XPV8/8qCmauTQP9xBuoJhe0J0GpkwLAwqKOYv/wq
         UPIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Gy59JMlBpgwnxZviaMr7XQ5pYgwIoVog93G8fJEBlu8=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=ZiO3a+dnkihMyqdHGwYVoL08LSZrM+LnLQc7zWL3MWNYGh139801UfaE6nnjR6row8
         JPQbFRZjGG/UtH5JlFU6qhs8iV6KD36/FXOzVl3ekc+PC+bjccnD6ZcjcE9zsJPXrygq
         fxz57ns/hyD3w4PtnXE532aScUoUKauPyGh8Km8t4O7L/LbGXsBf08I/h4u1Rb+f+xth
         31jZX+W3+ZRXZVO49QWKcymLYmC9nC5kvDVKTVc7h8FKKo0jpkKv9x3vmQEs5RvHjEzZ
         19YS5mL41hGTwS/5aC8ZNIMP1Dj5VQCkEeHKxioFs3fF9V5CU2hTc8UD5mEs9T8MBKhP
         Zb8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MZDc0sAO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693384467; x=1693989267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Gy59JMlBpgwnxZviaMr7XQ5pYgwIoVog93G8fJEBlu8=;
        b=VS6s+PkJRPE0Qchc89G82ZoFLbzQkQbW1Mvrdz/XsL/T+tEJAiFSjGQ9nma/9qXJj/
         lCjwbWafZ9XONwVviS798CFSW6lou6aUrOAVWjeK+ZoI4dC6YJ8OHyxJtgMFnbZmDMab
         oqHygr8+7ts7mjKuerZth5m/RPy+FRVjOLV6B3ijik0qfJuZ8fbvFnz04qhm3IjyCbbr
         I4tF4KN6GQh0w2kX/TcRansLgx4xLo4rQV/USjhJOTcTLploI1o99abLJIZue5mRKG8M
         GM75j+7YueMQPpMrcQNHZv0lDYGDceKjqeqPvSwuoLWfdjFZXasLtcCFuI4tEQ1wpX2s
         VYug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693384467; x=1693989267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gy59JMlBpgwnxZviaMr7XQ5pYgwIoVog93G8fJEBlu8=;
        b=QLMplqEpErdU/GRsYQWaez7YgV5fIcwZtc9ZF+7jaULMkuTbDXp6hPUEGWoU/XrgzB
         8hDA3NimtMeyYa8uHpJ9ABVUYINUbF4NtZ5VvYOcMbnh14+Axz3eJ/Dtx4KjYgFS2jBN
         VwxmMsQs68jqG0HS4+PjZHlTtm6JQaXsZdqUFUXLSlzZoby4dxzErs7eS9julM64Xibo
         hEAQF5AL6OpVNTOyXAFObVLcmvifPC5l17pLt3iJc89DTrCZZmcNPk17pCpPpcLdfeJF
         b1yEFpu9jlqG5M6+YT+yzD9HhQKciZBpb7vsOTd5+Gkd/+RMazWpE1J5dAYxGeal+MLW
         i+PA==
X-Gm-Message-State: AOJu0YyQlz2xAfkVO0vkIqq60HwSPJT25zt9zUGDuchJcmqM2FVFtJWC
	X6UkAdOShjrOcO80boxLobg=
X-Google-Smtp-Source: AGHT+IEWwGYpLo1mOi6jIgJl676U+2WVSXbsGha8kfwAQlUv/qvQAQIHxg65p49loHZ3wsurHNuiLA==
X-Received: by 2002:a50:ee82:0:b0:525:950d:60ad with SMTP id f2-20020a50ee82000000b00525950d60admr1424307edr.25.1693384466710;
        Wed, 30 Aug 2023 01:34:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:160e:b0:51b:d33b:40c7 with SMTP id
 f14-20020a056402160e00b0051bd33b40c7ls147496edv.2.-pod-prod-08-eu; Wed, 30
 Aug 2023 01:34:24 -0700 (PDT)
X-Received: by 2002:a50:ee82:0:b0:525:950d:60ad with SMTP id f2-20020a50ee82000000b00525950d60admr1424214edr.25.1693384464771;
        Wed, 30 Aug 2023 01:34:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693384464; cv=none;
        d=google.com; s=arc-20160816;
        b=DTBkPJMZatcm4fS3ueQhVAFFM5YTl+YFcfeBUwBgCRaAE32R+CKv+2sQNRpkS3c4Os
         TVK+V2CCQuIITnmkpm3lQGw9erj3husfg1ILN4ihbFGqgNbXwa5CYtDh6XrpZvEjo2NW
         5ak4TtpQ2P7FHfv5t++ozx35LR5N29och9Jkdi/IESCjj12HGQA/6o7Y0gHLZezsmG7j
         5ACsN6UmRF06FcUaHCX79N2FSkKtEHXyLdMYMDw4y/F/fwz2dpdXkVtIVjLubeYsT0b3
         y17rCv/WU1z03pAr7VloDfdsccpqAg51d44oc6WWZC2gVKPrLW5rW21Jzq8DGO1tHiU3
         Kv8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Pt0PhngddEXeQF55w8XLKCuMlgv9f/y2sGmaKeHMR1g=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=0pWOytwTbDfQMy7RLRP+u1v5yLTKgEh8RnOXldK3Wt00NtJXKW6brmXUWiC1aNsRgh
         jW+QDR4eSnAIB1Yd5eEejEmp4GMsUKTWMG90q+dSRNddbNgflvpum1KkzS3zY+u+wHL3
         5YOvivlUuxcGhU1hb/c0XcYqo+lSwZAkNz5mY4nscGLxlqkw9bJ/GhPprfrQI37vq9mJ
         dpzrirEJeG6355ZzaFgpUin19VESbhHWqDcIg4f1lrvIanmGZfAbEpLxpKucyfJq7399
         080yMP/R52lky4HZYwBkYmtYoah4kJcpiYFnScPD/pIimO8EUEB7uFei1CyGygg8oyGc
         NMSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MZDc0sAO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id ek22-20020a056402371600b0052a08bb403bsi949412edb.3.2023.08.30.01.34.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 01:34:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-2bceca8a41aso78101121fa.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 01:34:24 -0700 (PDT)
X-Received: by 2002:a2e:b60e:0:b0:2bc:d3a8:974a with SMTP id r14-20020a2eb60e000000b002bcd3a8974amr1259289ljn.24.1693384463909;
        Wed, 30 Aug 2023 01:34:23 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id o18-20020a05600c379200b003fee65091fdsm1505056wmr.40.2023.08.30.01.34.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 01:34:23 -0700 (PDT)
Date: Wed, 30 Aug 2023 10:34:18 +0200
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
Subject: Re: [PATCH 06/15] stackdepot: fix and clean-up atomic annotations
Message-ID: <ZO7/CqwhzqulWP7K@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <8ad8f778b43dab49e4e6214b8d90bed31b75436f.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8ad8f778b43dab49e4e6214b8d90bed31b75436f.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=MZDc0sAO;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::231 as
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
> Simplify comments accompanying the use of atomic accesses in the
> stack depot code.
> 
> Also turn smp_load_acquire from next_pool_required in depot_init_pool
> into READ_ONCE, as both depot_init_pool and the all smp_store_release's
> to this variable are executed under the stack depot lock.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> This patch is not strictly required, as the atomic accesses are fully
> removed in one of the latter patches. However, I decided to keep the
> patch just in case we end up needing these atomics in the following
> iterations of this series.
> ---
>  lib/stackdepot.c | 27 +++++++++++++--------------
>  1 file changed, 13 insertions(+), 14 deletions(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 93191ee70fc3..9ae71e1ef1a7 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -226,10 +226,10 @@ static void depot_init_pool(void **prealloc)
>  	/*
>  	 * If the next pool is already initialized or the maximum number of
>  	 * pools is reached, do not use the preallocated memory.
> -	 * smp_load_acquire() here pairs with smp_store_release() below and
> -	 * in depot_alloc_stack().
> +	 * READ_ONCE is only used to mark the variable as atomic,
> +	 * there are no concurrent writes.

This doesn't make sense. If there are no concurrent writes, we should
drop the marking, so that if there are concurrent writes, tools like
KCSAN can tell us about it if our assumption was wrong.

>  	 */
> -	if (!smp_load_acquire(&next_pool_required))
> +	if (!READ_ONCE(next_pool_required))
>  		return;
>  
>  	/* Check if the current pool is not yet allocated. */
> @@ -250,8 +250,8 @@ static void depot_init_pool(void **prealloc)
>  		 * At this point, either the next pool is initialized or the
>  		 * maximum number of pools is reached. In either case, take
>  		 * note that initializing another pool is not required.
> -		 * This smp_store_release pairs with smp_load_acquire() above
> -		 * and in stack_depot_save().
> +		 * smp_store_release pairs with smp_load_acquire in
> +		 * stack_depot_save.
>  		 */
>  		smp_store_release(&next_pool_required, 0);
>  	}
> @@ -275,15 +275,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  		/*
>  		 * Move on to the next pool.
>  		 * WRITE_ONCE pairs with potential concurrent read in
> -		 * stack_depot_fetch().
> +		 * stack_depot_fetch.
>  		 */
>  		WRITE_ONCE(pool_index, pool_index + 1);
>  		pool_offset = 0;
>  		/*
>  		 * If the maximum number of pools is not reached, take note
>  		 * that the next pool needs to initialized.
> -		 * smp_store_release() here pairs with smp_load_acquire() in
> -		 * stack_depot_save() and depot_init_pool().
> +		 * smp_store_release pairs with smp_load_acquire in
> +		 * stack_depot_save.
>  		 */
>  		if (pool_index + 1 < DEPOT_MAX_POOLS)
>  			smp_store_release(&next_pool_required, 1);
> @@ -414,8 +414,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  
>  	/*
>  	 * Fast path: look the stack trace up without locking.
> -	 * The smp_load_acquire() here pairs with smp_store_release() to
> -	 * |bucket| below.
> +	 * smp_load_acquire pairs with smp_store_release to |bucket| below.
>  	 */
>  	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
>  	if (found)
> @@ -425,8 +424,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	 * Check if another stack pool needs to be initialized. If so, allocate
>  	 * the memory now - we won't be able to do that under the lock.
>  	 *
> -	 * The smp_load_acquire() here pairs with smp_store_release() to
> -	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
> +	 * smp_load_acquire pairs with smp_store_release
> +	 * in depot_alloc_stack and depot_init_pool.

Reflow comment to match 80 cols used by comments elsewhere.

>  	 */
>  	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
>  		/*
> @@ -452,8 +451,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		if (new) {
>  			new->next = *bucket;
>  			/*
> -			 * This smp_store_release() pairs with
> -			 * smp_load_acquire() from |bucket| above.
> +			 * smp_store_release pairs with smp_load_acquire
> +			 * from |bucket| above.
>  			 */
>  			smp_store_release(bucket, new);
>  			found = new;
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO7/CqwhzqulWP7K%40elver.google.com.
