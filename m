Return-Path: <kasan-dev+bncBCO3JTUR7UBRBVOK2SWAMGQEYN5ADNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0228C822A07
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 10:13:59 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-50e55a909basf7613504e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 01:13:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704273238; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tddp5/GwpfDV9MiiuXlYwHKV5ee9B+38hXgWr7VRVtxtslNBZq5E2yRhhabB/rOZXR
         CQPxFgwUbyfIIEt8IJbVuvPktETdohBac5AuWKvwetWZUR85sgFCkHJsFSPgPSk5A40G
         tnbchgXu+2u/PSg4OxEwqf3gcmjIMPmbe6kFsRSiMZz9xuj0hZPn4vDI9kIuAqgxoZp6
         eqGIoXbftLJ94s/bgeplYF/W7eAjxLLTd8IVo6/xnGj2R0O0GbS5MZZ6L+7Kch1HwBx5
         U0Lp8qWC9A321aZEw2NhIDnGe3HdQW1d4D7uKXNe4sD+z3RwJuFM1imEMYHVh6OIX+uF
         VNXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xVkxkuPal2lxUE4dFMkg1U6JPMv4odp0NeOIiHam2BY=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=JItRz64PKee9E31Y3/qiz5n2CxAah+P0URjuCv2z/gWlA1Dtisui+nyLmijH92t0zw
         jmAUfiJt14cITTAp3t2vmCSnBqg6M7D4AdLf0SUbULPcPTv063zUYjfiRd4bKgwgiLCh
         GFbJwoAldhZSj/f+tiEQARop2K6n55SEXVhD+VkLbsA2LjYD07aKXzJJ5QBGg/FuwFyZ
         db/1j6jiVs0SB+6e8F4WIUgr+JS7D101vRNJsKfAwy2dlpCqV2aWWXIFEnJP+sPLM/lh
         f2AwkEBqjGhR+jF/H17ptNkT9+HeUz7z4I1VXuQ46D+rNhq6yEbFjQf49e3ofQNg7Mfa
         K42Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=RcliW7Lr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ctkUNYaY;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704273238; x=1704878038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xVkxkuPal2lxUE4dFMkg1U6JPMv4odp0NeOIiHam2BY=;
        b=IKdPUIHm2+KbmsTLjtXGgWzXxWppqiz7r91iT4ZNm21DuOHTJnDsyUKNDYAyz6KSY1
         10LgtfmeqfdaQwAa/52/ihPjizzX3yKHfYUG+OO4sNplJ9maIdiBc6Q5V7HTmj+PMd74
         iz570azIxnDPfHCNdWw03QKO17ye+pZiF03VoOUBYHdT6jQlLXd0YETbJIQXiDk1ray/
         EIxabuVBtyQIiH2hEIxH6ainMYo3vpWOfM8qDT7RUe6V3pLM5AjGksunDioFaLiEbCLW
         Rek646+bD8qcd6GsatVnsjVnPMgYaMpNOl/REY9i9DB2RhQvSq63d+eSKaisdJRlzpUr
         reLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704273238; x=1704878038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xVkxkuPal2lxUE4dFMkg1U6JPMv4odp0NeOIiHam2BY=;
        b=sKOx2qhRCffD0nhAYQEizKFOEn514mc+/ceF9UVeMhlPHOmFJabdHE8jRlCw7/iIDE
         msnpKJsq2Ti6R3iZiE5USqkEL4OA6xfD4G4nGVOg30Bl0nKEkUHIK5LinVxOHqYf3lFA
         d9XngT9MWaph1Gg7UmZqRvaXLp3YJXhYh1/K8KQkA8w2a68oZjEruI2j1dj8oJn6gtYY
         0Ks8EUCrokI2TyJ9GJFSwargUqBeNCii2ipTkp478i/cwQHddJg0dHBardR1Vnu799GB
         V90m6gry3Ol+gPNAO+To0SdK4HAbUI5JiOorvJow7cD2atdG5vvl9zj1a6lTZeZRgH29
         p+yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw7VmCQYetQFI9YkVKJsiMxGqD6r8GsPw4HAu+lSoVlXQKi9QPr
	I3tl3uUaXG765MSmf+oyqfI=
X-Google-Smtp-Source: AGHT+IFldAExqujBLbNS0VAiKDYzFhNbb6/NjifT2AePYzYqCkK7DXM1cFjAseJ0WKT7qiBXV+KdVQ==
X-Received: by 2002:a05:6512:3404:b0:50e:9e5b:27a with SMTP id i4-20020a056512340400b0050e9e5b027amr1177162lfr.194.1704273237432;
        Wed, 03 Jan 2024 01:13:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e88:b0:50e:7b04:a7a2 with SMTP id
 bi8-20020a0565120e8800b0050e7b04a7a2ls34719lfb.0.-pod-prod-02-eu; Wed, 03 Jan
 2024 01:13:55 -0800 (PST)
X-Received: by 2002:a05:6512:2252:b0:50e:936a:9209 with SMTP id i18-20020a056512225200b0050e936a9209mr2242479lfu.152.1704273235448;
        Wed, 03 Jan 2024 01:13:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704273235; cv=none;
        d=google.com; s=arc-20160816;
        b=m3BTWk80KJDbQwHRSkxuM5/oHNSffhcmb8CgY6GdZrkOrwRGHKLoKrQk3WQ+LPy7Iv
         D3SJghfjZKHKONCERdM6XQZB5EuBHVZTOpBifgQKV3a8G0VUzo1AuqG+qxzEjUq7JDOP
         1nWyIO0fXjld8r8n268AR1tJZYZs0ZEZKHAyB+2Rh+wRYXNe6na87AWltZ0qLMn4wpgk
         FBXjj5V3AL9ZbuI7sg1UOkxk9g4NEYLAiYxj7cKMFAxExGcApqNGOb1yOsoJ1uKgqXwM
         9ostNzhr7/s69tP8kD9/nJ8cdz6s8y/8clPuFZEZ6fyxKKH3znIpDjbxiLrnB7m8Yy6Q
         tFjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=OaUGx3HlxrUaYynmTLyTYeD/XbRLOHVkk+knRajgh5o=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=psMiQjjrWYXg6awxzdHU3o3Ijd5oxSmAJG+FKW9pbYoSyJ713OMJz7wLQAnKlNdNCZ
         2S/e54cwv11EtmyxCb+Z9k2ZV783yGGjQsD1lXZ4H51XACfQ8dAR/rugaDHcRycUF3zc
         LiKOSFRpze3mobPB4AFfuV8ADnXZdhDrFlukqd/SNMOPqbonRSlc9yZbdljqMccXM0gJ
         5SQRFMKjhyiNOOETQct+oDPE9WXQRxNkoi310oIpCK8aNTmNA1QG7PTS6oI+aWmtASOz
         /xDeLrOWtX8aNEWAbP5lVsL1HJX4V2jnElVBs3v30pVW9jA27zmWSlHanK3FyVrTrVjq
         xY9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=RcliW7Lr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ctkUNYaY;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id b10-20020a5d634a000000b003367f2ef462si860490wrw.8.2024.01.03.01.13.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 01:13:55 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 90B1621C64;
	Wed,  3 Jan 2024 09:13:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A25EE13AA6;
	Wed,  3 Jan 2024 09:13:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id sq7tI08llWUNawAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 09:13:51 +0000
Date: Wed, 3 Jan 2024 10:14:42 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZZUlgs69iTTlG8Lh@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-6.01 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.de:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.de:dkim,suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Spam-Score: -6.01
X-Rspamd-Queue-Id: 90B1621C64
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=RcliW7Lr;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ctkUNYaY;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of osalvador@suse.de designates 195.135.223.130 as
 permitted sender) smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:10PM +0100, andrey.konovalov@linux.dev wrote:
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
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>

> ---
> 
> Changed v2->v3:
> - Use lockdep_assert_held_read annotation in depot_fetch_stack.
> 
> Changes v1->v2:
> - Add lockdep_assert annotations.
> ---
>  lib/stackdepot.c | 87 +++++++++++++++++++++++++-----------------------
>  1 file changed, 46 insertions(+), 41 deletions(-)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index a5eff165c0d5..8378b32b5310 100644
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
> @@ -91,15 +92,15 @@ static void *new_pool;
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
>  
>  static int __init disable_stack_depot(char *str)
>  {
> @@ -232,6 +233,8 @@ static void depot_init_pool(void *pool)
>  	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
>  	int i, offset;
>  
> +	lockdep_assert_held_write(&pool_rwlock);
> +
>  	/* Initialize handles and link stack records to each other. */
>  	for (i = 0, offset = 0;
>  	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
> @@ -254,22 +257,17 @@ static void depot_init_pool(void *pool)
>  
>  	/* Save reference to the pool to be used by depot_fetch_stack(). */
>  	stack_pools[pools_num] = pool;
> -
> -	/*
> -	 * WRITE_ONCE() pairs with potential concurrent read in
> -	 * depot_fetch_stack().
> -	 */
> -	WRITE_ONCE(pools_num, pools_num + 1);
> +	pools_num++;
>  }
>  
>  /* Keeps the preallocated memory to be used for a new stack depot pool. */
>  static void depot_keep_new_pool(void **prealloc)
>  {
> +	lockdep_assert_held_write(&pool_rwlock);
> +
>  	/*
>  	 * If a new pool is already saved or the maximum number of
>  	 * pools is reached, do not use the preallocated memory.
> -	 * Access new_pool_required non-atomically, as there are no concurrent
> -	 * write accesses to this variable.
>  	 */
>  	if (!new_pool_required)
>  		return;
> @@ -287,15 +285,15 @@ static void depot_keep_new_pool(void **prealloc)
>  	 * At this point, either a new pool is kept or the maximum
>  	 * number of pools is reached. In either case, take note that
>  	 * keeping another pool is not required.
> -	 * smp_store_release() pairs with smp_load_acquire() in
> -	 * stack_depot_save().
>  	 */
> -	smp_store_release(&new_pool_required, 0);
> +	new_pool_required = false;
>  }
>  
>  /* Updates references to the current and the next stack depot pools. */
>  static bool depot_update_pools(void **prealloc)
>  {
> +	lockdep_assert_held_write(&pool_rwlock);
> +
>  	/* Check if we still have objects in the freelist. */
>  	if (next_stack)
>  		goto out_keep_prealloc;
> @@ -307,7 +305,7 @@ static bool depot_update_pools(void **prealloc)
>  
>  		/* Take note that we might need a new new_pool. */
>  		if (pools_num < DEPOT_MAX_POOLS)
> -			smp_store_release(&new_pool_required, 1);
> +			new_pool_required = true;
>  
>  		/* Try keeping the preallocated memory for new_pool. */
>  		goto out_keep_prealloc;
> @@ -341,6 +339,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  {
>  	struct stack_record *stack;
>  
> +	lockdep_assert_held_write(&pool_rwlock);
> +
>  	/* Update current and new pools if required and possible. */
>  	if (!depot_update_pools(prealloc))
>  		return NULL;
> @@ -376,18 +376,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
>  {
>  	union handle_parts parts = { .handle = handle };
> -	/*
> -	 * READ_ONCE() pairs with potential concurrent write in
> -	 * depot_init_pool().
> -	 */
> -	int pools_num_cached = READ_ONCE(pools_num);
>  	void *pool;
>  	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
>  	struct stack_record *stack;
>  
> -	if (parts.pool_index > pools_num_cached) {
> +	lockdep_assert_held_read(&pool_rwlock);
> +
> +	if (parts.pool_index > pools_num) {
>  		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
> -		     parts.pool_index, pools_num_cached, handle);
> +		     parts.pool_index, pools_num, handle);
>  		return NULL;
>  	}
>  
> @@ -429,6 +426,8 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
>  {
>  	struct stack_record *found;
>  
> +	lockdep_assert_held(&pool_rwlock);
> +
>  	for (found = bucket; found; found = found->next) {
>  		if (found->hash == hash &&
>  		    found->size == size &&
> @@ -446,6 +445,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	depot_stack_handle_t handle = 0;
>  	struct page *page = NULL;
>  	void *prealloc = NULL;
> +	bool need_alloc = false;
>  	unsigned long flags;
>  	u32 hash;
>  
> @@ -465,22 +465,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	hash = hash_stack(entries, nr_entries);
>  	bucket = &stack_table[hash & stack_hash_mask];
>  
> -	/*
> -	 * Fast path: look the stack trace up without locking.
> -	 * smp_load_acquire() pairs with smp_store_release() to |bucket| below.
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
> -	 * smp_load_acquire() pairs with smp_store_release() in
> -	 * depot_update_pools() and depot_keep_new_pool().
> +	 * Allocate memory for a new pool if required now:
> +	 * we won't be able to do that under the lock.
>  	 */
> -	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
> +	if (unlikely(can_alloc && need_alloc)) {
>  		/*
>  		 * Zero out zone modifiers, as we don't have specific zone
>  		 * requirements. Keep the flags related to allocation in atomic
> @@ -494,7 +498,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  			prealloc = page_address(page);
>  	}
>  
> -	raw_spin_lock_irqsave(&pool_lock, flags);
> +	write_lock_irqsave(&pool_rwlock, flags);
>  
>  	found = find_stack(*bucket, entries, nr_entries, hash);
>  	if (!found) {
> @@ -503,11 +507,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  
>  		if (new) {
>  			new->next = *bucket;
> -			/*
> -			 * smp_store_release() pairs with smp_load_acquire()
> -			 * from |bucket| above.
> -			 */
> -			smp_store_release(bucket, new);
> +			*bucket = new;
>  			found = new;
>  		}
>  	} else if (prealloc) {
> @@ -518,7 +518,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		depot_keep_new_pool(&prealloc);
>  	}
>  
> -	raw_spin_unlock_irqrestore(&pool_lock, flags);
> +	write_unlock_irqrestore(&pool_rwlock, flags);
>  exit:
>  	if (prealloc) {
>  		/* Stack depot didn't use this memory, free it. */
> @@ -542,6 +542,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  			       unsigned long **entries)
>  {
>  	struct stack_record *stack;
> +	unsigned long flags;
>  
>  	*entries = NULL;
>  	/*
> @@ -553,8 +554,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUlgs69iTTlG8Lh%40localhost.localdomain.
