Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWYYGMAMGQEFU7LGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8530B5A9209
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:25:07 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id q16-20020a1cf310000000b003a626026ed1sf548194wmq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:25:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662020707; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pxll9TJYsDhrgiqQf0svU6rX6p5HXJrWxi77cD87IFFS0yIyAECOaB7RhG5qEDiqF+
         isa5sWyCxQAZ3YDxkFbYveOJzoeHlEyA5+MxbpGLAvnDVL+F3JNRxxenZeR+lYxUw1VK
         okMbMQ3RpjfIwpJxTZh59rxmY4otQUtuaYEuH7O9Sg5ZiIxTu1tisDJH/nFC9+6zZc1o
         ZuPcT//e0ej1EJ7CdPF2omcVFKAmX6H6Xj1KvBpxWuxEDtqnjRQfeF+MIAQpMnYOCLyo
         pU252lQdDSHgaqt11cImQOvecp/9VE1aiGRcNCrzZPjvpDIUa6eW+vZOopYfAoDBoDlB
         C67A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jSuDScsp5rhPsyyFigaF/YhduzTIpsuHVfpFUAkTOS4=;
        b=xZH7eJKobAr3gGjuhGdx0IJ/46fLsYXnbeaTB6FTbFZqgE4+/d+RnlRlv9iXG8vd2j
         GV6V3vdP4fwBl4tszFu21Dy5Lv0zVPt7UYo7u0uEv8IiExYIQ62JfyGWwGOxFYtl4aBY
         UKKlVXTVoZ8bRar8Mwd2Ovtv1Kn7o4JfwynFiJDZXZIY53drdeAwJwAiQWJ5hZVnYq0U
         nJQiM6YqKgeNxRm2zRVKD/DgoPQ4m8kuCIv8GUHQ+0KeJvr02hAdj86hO0ZUfWjk127O
         +ee/aLjoIYxuE2n3UnFSKeEwMMFgpuVxvmcZP9LJ5LkJxmyabJCo+U4GPRk60f3ALhx4
         I2/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cotNXp9I;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc;
        bh=jSuDScsp5rhPsyyFigaF/YhduzTIpsuHVfpFUAkTOS4=;
        b=aEak/bZFKLnhEZuqnYA3QPwKXVCpGvMOfWtoS9sx2CVgTZwjv9VOLUokVTU8xS45GY
         Se5RGh7jZnODO9BPLRVGreDK/XK8wr98YDKJ9xHc3+AKKajqq8ERzMlHV3Lysm3fEk0Q
         hmKrKNp6yHAlwVSpyEjJXjMHuLFC66Vbvb9Xo1NK7NZJ05QxplfkR/l72C0Z0Dhi4Ys+
         foyEFBR5gDUXyNfg8e2+cEod3HX5XMe7jXpbHhhew3s63+h+py5k74D21Pe/+BLAw8PD
         mbxFb5eyh9BKPAAPM7wMNeiFWSvJX9/mX0fh5nHrJJBsLud8bf0NqwuFk7YGRSLqFvr0
         cEFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc;
        bh=jSuDScsp5rhPsyyFigaF/YhduzTIpsuHVfpFUAkTOS4=;
        b=34aDNqS4ubIoBMYlxgjo3jDid6cM4N+wH1PGPZ3qk5OXMnte513fB9qUsoaeift8je
         O1QYagCCwSyyDnBfchl2nayXqAMDVPgjMqRExRoQfx3pGVxc1isa1UM4TilnIUrisBuF
         W1v4sXA0x+8WTAFkrDMmBVvNq530btAGxyvvTCP8sh4rnR/GS/2KYGd28lUuJQDs25Vq
         EVW2sUwQujxyvzUs0/NhmBuJNKXFfvYGs/uo0OrZThBZxP2qVKEsoIJIWGAkIp2iGf53
         8LGOcczFsnceDDxDHNmmrpyBc5EvlDQvO3xy4eAtI7lxNuDnedHsrESf7UPkQmvgZjfV
         FvYw==
X-Gm-Message-State: ACgBeo2c8xShhvKYOv3/lmlvb3DWWOSXC4vIzNSULlTdlIM+ULejAlZe
	GhkwtcqSoeai/wWmk/0QuKQ=
X-Google-Smtp-Source: AA6agR5DSiwJxsN+7ltOKQ7vYMQhkd7d65ExniKR6gDGjbPXFI8WTStU44UtyNgS2rv01Jt1GgGlRA==
X-Received: by 2002:a05:600c:3d09:b0:3a5:e408:ca19 with SMTP id bh9-20020a05600c3d0900b003a5e408ca19mr4475043wmb.135.1662020707172;
        Thu, 01 Sep 2022 01:25:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls1837135wrb.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 01:25:05 -0700 (PDT)
X-Received: by 2002:a5d:40cd:0:b0:225:7425:fac1 with SMTP id b13-20020a5d40cd000000b002257425fac1mr15013335wrq.30.1662020705854;
        Thu, 01 Sep 2022 01:25:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662020705; cv=none;
        d=google.com; s=arc-20160816;
        b=tB3v9pxiYN3nCEzFTlqqChuSY/rDIAXokmvBm9PfYxKHBdu2Mm+K3x2n4k+8nlbPUA
         XvkNVpVumgxVEKR7GL4NV9BIdK6ft73OuuspT23HAcGhb776ecqOiMIPPj3XRmswdoJQ
         o53N4lGKjBMRE5893QUBPAlEwoa3DvJySfe8q7BfpNUKg9YJhBcmuzoNUWM9rlThucVH
         DIJCT/pfkX7BmRgqvcySz1v89bsbwtd59VJiBlIOT5ocQHreIY+KSoTUfYm7lbGUoxQX
         ggyFIseZYxjVSjJ/e4WkwNrA7WfA6Bpse1tUSvFQntvVhCHQC9RtO1VY1b1MvzG5qPIE
         PAaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tcbWBRi6iAnXzpZ7/OAu6BZVPbwwwyPcddKIZpKIvmw=;
        b=ONKtfMjhY0PWFvz0qC/nB99VNlLmHDHWxsFciDaCb3ETfch6RP8y5EV30nmZhxFJqt
         eDB1emwNRviRk1EThnfePifRss8ybankUTp8fYKXgQRXzxPrc/07eDGj27ehCNmEw7Rf
         K+STWjdSHa/UOFLOLboiIXhPDsSdJDSQVp9ecBk5iK7Wr+TtdCZq+O/IgFM6hFJoAC+5
         YsAGY+vClnImzr2W/zYpEjK5QZgDuLJTGPBOjaOwO0NKLkzArHZaex2kc7QKA5FVv9qP
         X55raUbnnqaQgupvx5YPTuNTL/j3xLStkskdFeGmOx2gQBd7KKfYvQhuRFGPPhgNFOzz
         lNpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cotNXp9I;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id i7-20020a5d4387000000b0021e8b3a5ffesi718853wrq.2.2022.09.01.01.25.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 01:25:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id s7so6385121wro.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 01:25:05 -0700 (PDT)
X-Received: by 2002:adf:e110:0:b0:226:2e2c:bfe9 with SMTP id t16-20020adfe110000000b002262e2cbfe9mr13984427wrz.432.1662020705380;
        Thu, 01 Sep 2022 01:25:05 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:401c:31df:7ab:1b94])
        by smtp.gmail.com with ESMTPSA id i17-20020a1c5411000000b003a1980d55c4sm4419310wmb.47.2022.09.01.01.25.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 01:25:04 -0700 (PDT)
Date: Thu, 1 Sep 2022 10:24:58 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Oscar Salvador <osalvador@suse.de>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Michal Hocko <mhocko@suse.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Eric Dumazet <edumazet@google.com>,
	Waiman Long <longman@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
Message-ID: <YxBsWu36eqUw03Dy@elver.google.com>
References: <20220901044249.4624-1-osalvador@suse.de>
 <20220901044249.4624-2-osalvador@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901044249.4624-2-osalvador@suse.de>
User-Agent: Mutt/2.2.6 (2022-06-05)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cotNXp9I;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
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

On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> We want to filter out page_owner output and print only those
> stacks that have been repeated beyond a certain threshold.
> This gives us the chance to get rid of a lot of noise.
> In order to do that, we need to keep track of how many repeated stacks
> (for allocation) do we have, so we add a new refcount_t field
> in the stack_record struct.
> 
> Note that on __set_page_owner_handle(), page_owner->handle is set,
> and on __reset_page_owner(), page_owner->free_handle is set.
> 
> We are interested in page_owner->handle, so when __set_page_owner()
> gets called, we derive the stack_record struct from page_owner->handle,
> and we increment its refcount_t field; and when __reset_page_owner()
> gets called, we derive its stack_record from page_owner->handle()
> and we decrement its refcount_t field.
> 
> This is a preparation for patch#2.
> 
> Signed-off-by: Oscar Salvador <osalvador@suse.de>
> ---
>  include/linux/stackdepot.h | 13 ++++++-
>  lib/stackdepot.c           | 79 +++++++++++++++++++++++++++++++-------
>  mm/kasan/common.c          |  3 +-

+Cc other kasan maintainers

>  mm/page_owner.c            | 13 +++++--
>  4 files changed, 88 insertions(+), 20 deletions(-)
> 
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index bc2797955de9..5ee0cf5be88f 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -15,9 +15,16 @@
>  
>  typedef u32 depot_stack_handle_t;
>  
> +typedef enum stack_action {
> +	STACK_ACTION_NONE,
> +	STACK_ACTION_INC,
> +}stack_action_t;
> +

missing space after '}'. But please no unnecessary typedef, just 'enum
stack_action' (and spelling out 'enum stack_action' elsewhere) is just
fine.

This is in the global namespace, so I'd call this
stack_depot_action+STACK_DEPOT_ACTION_*.

However, .._ACTION_INC doesn't really say what's incremented. As an
analog to stack_depot_dec_count(), perhaps .._ACTION_COUNT?

In general it'd be nicer if there was stack_depot_inc_count() instead of
this additional argument, but I see that for performance reasons you
might not like that?

>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  					unsigned int nr_entries,
> -					gfp_t gfp_flags, bool can_alloc);
> +					gfp_t gfp_flags, bool can_alloc,
> +					stack_action_t action);
> +void stack_depot_dec_count(depot_stack_handle_t handle);
>  
>  /*
>   * Every user of stack depot has to call stack_depot_init() during its own init
> @@ -55,6 +62,10 @@ static inline int stack_depot_early_init(void)	{ return 0; }
>  
>  depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  				      unsigned int nr_entries, gfp_t gfp_flags);
> +depot_stack_handle_t stack_depot_save_action(unsigned long *entries,
> +					     unsigned int nr_entries,
> +					     gfp_t gfp_flags,
> +					     stack_action_t action);
>  
>  unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  			       unsigned long **entries);
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ca0d086ef4a..aeb59d3557e2 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -63,6 +63,7 @@ struct stack_record {
>  	u32 hash;			/* Hash in the hastable */
>  	u32 size;			/* Number of frames in the stack */
>  	union handle_parts handle;
> +	refcount_t count;		/* Number of the same repeated stacks */

This will increase stack_record size for every user, even if they don't
care about the count.

Is there a way to store this out-of-line somewhere?

>  	unsigned long entries[];	/* Variable-sized array of entries. */
>  };
>  
> @@ -139,6 +140,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  	stack->handle.slabindex = depot_index;
>  	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
>  	stack->handle.valid = 1;
> +	refcount_set(&stack->count, 1);
>  	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
>  	depot_offset += required_size;
>  
> @@ -302,6 +304,29 @@ void stack_depot_print(depot_stack_handle_t stack)
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_print);
>  
> +static struct stack_record *stack_depot_getstack(depot_stack_handle_t handle)
> +{
> +	union handle_parts parts = { .handle = handle };
> +	void *slab;
> +	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
> +	struct stack_record *stack;
> +
> +	if(!handle)
> +		return NULL;
> +
> +	if (parts.slabindex > depot_index) {
> +		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
> +		     parts.slabindex, depot_index, handle);
> +		return NULL;
> +	}
> +	slab = stack_slabs[parts.slabindex];
> +	if (!slab)
> +		return NULL;
> +
> +	stack = slab + offset;
> +	return stack;
> +}
> +
>  /**
>   * stack_depot_fetch - Fetch stack entries from a depot
>   *
> @@ -314,30 +339,42 @@ EXPORT_SYMBOL_GPL(stack_depot_print);
>  unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>  			       unsigned long **entries)
>  {
> -	union handle_parts parts = { .handle = handle };
> -	void *slab;
> -	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
>  	struct stack_record *stack;
>  
>  	*entries = NULL;
>  	if (!handle)
>  		return 0;
>  
> -	if (parts.slabindex > depot_index) {
> -		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
> -			parts.slabindex, depot_index, handle);
> -		return 0;
> -	}
> -	slab = stack_slabs[parts.slabindex];
> -	if (!slab)
> +	stack = stack_depot_getstack(handle);
> +	if (!stack)
>  		return 0;
> -	stack = slab + offset;
>  
>  	*entries = stack->entries;
>  	return stack->size;
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_fetch);
>  
> +static void stack_depot_inc_count(struct stack_record *stack)
> +{
> +	refcount_inc(&stack->count);
> +}
> +
> +void stack_depot_dec_count(depot_stack_handle_t handle)
> +{
> +	struct stack_record *stack = NULL;
> +
> +	stack = stack_depot_getstack(handle);
> +	if (stack) {
> +	/*
> +	 * page_owner creates some stacks via create_dummy_stack().
> +	 * We are not interested in those, so make sure we only decrement
> +	 * "valid" stacks.
> +	 */

Comment indent is wrong.

> +		if (refcount_read(&stack->count) > 1)
> +			refcount_dec(&stack->count);
> +	}
> +}
> +
>  /**
>   * __stack_depot_save - Save a stack trace from an array
>   *
> @@ -363,7 +400,8 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   */
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  					unsigned int nr_entries,
> -					gfp_t alloc_flags, bool can_alloc)
> +					gfp_t alloc_flags, bool can_alloc,
> +					stack_action_t action)
>  {
>  	struct stack_record *found = NULL, **bucket;
>  	depot_stack_handle_t retval = 0;
> @@ -449,8 +487,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		/* Nobody used this memory, ok to free it. */
>  		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
>  	}
> -	if (found)
> +	if (found) {
>  		retval = found->handle.handle;
> +		if (action == STACK_ACTION_INC)
> +			stack_depot_inc_count(found);
> +	}
>  fast_exit:
>  	return retval;
>  }
> @@ -472,6 +513,16 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  				      unsigned int nr_entries,
>  				      gfp_t alloc_flags)
>  {
> -	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
> +	return __stack_depot_save(entries, nr_entries, alloc_flags, true,
> +				  STACK_ACTION_NONE);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
> +
> +depot_stack_handle_t stack_depot_save_action(unsigned long *entries,
> +					     unsigned int nr_entries,
> +					     gfp_t alloc_flags,
> +					     stack_action_t action)
> +{
> +	return __stack_depot_save(entries, nr_entries, alloc_flags, true, action);
> +}
> +EXPORT_SYMBOL_GPL(stack_depot_save_action);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..f434994f3b0d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,8 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  	unsigned int nr_entries;
>  
>  	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> +	return __stack_depot_save(entries, nr_entries, flags, can_alloc,
> +				  STACK_ACTION_NONE);
>  }
>  
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index e4c6f3f1695b..794f346d7520 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -106,7 +106,7 @@ static inline struct page_owner *get_page_owner(struct page_ext *page_ext)
>  	return (void *)page_ext + page_owner_ops.offset;
>  }
>  
> -static noinline depot_stack_handle_t save_stack(gfp_t flags)
> +static noinline depot_stack_handle_t save_stack(gfp_t flags, stack_action_t action)
>  {
>  	unsigned long entries[PAGE_OWNER_STACK_DEPTH];
>  	depot_stack_handle_t handle;
> @@ -125,7 +125,7 @@ static noinline depot_stack_handle_t save_stack(gfp_t flags)
>  	current->in_page_owner = 1;
>  
>  	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 2);
> -	handle = stack_depot_save(entries, nr_entries, flags);
> +	handle = stack_depot_save_action(entries, nr_entries, flags, action);
>  	if (!handle)
>  		handle = failure_handle;
>  
> @@ -138,6 +138,7 @@ void __reset_page_owner(struct page *page, unsigned short order)
>  	int i;
>  	struct page_ext *page_ext;
>  	depot_stack_handle_t handle;
> +	depot_stack_handle_t alloc_handle;
>  	struct page_owner *page_owner;
>  	u64 free_ts_nsec = local_clock();
>  
> @@ -145,7 +146,10 @@ void __reset_page_owner(struct page *page, unsigned short order)
>  	if (unlikely(!page_ext))
>  		return;
>  
> -	handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
> +	page_owner = get_page_owner(page_ext);
> +	alloc_handle = page_owner->handle;
> +
> +	handle = save_stack(GFP_NOWAIT | __GFP_NOWARN, STACK_ACTION_NONE);
>  	for (i = 0; i < (1 << order); i++) {
>  		__clear_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
>  		page_owner = get_page_owner(page_ext);
> @@ -153,6 +157,7 @@ void __reset_page_owner(struct page *page, unsigned short order)
>  		page_owner->free_ts_nsec = free_ts_nsec;
>  		page_ext = page_ext_next(page_ext);
>  	}
> +	stack_depot_dec_count(alloc_handle);
>  }
>  
>  static inline void __set_page_owner_handle(struct page_ext *page_ext,
> @@ -189,7 +194,7 @@ noinline void __set_page_owner(struct page *page, unsigned short order,
>  	if (unlikely(!page_ext))
>  		return;
>  
> -	handle = save_stack(gfp_mask);
> +	handle = save_stack(gfp_mask, STACK_ACTION_INC);
>  	__set_page_owner_handle(page_ext, handle, order, gfp_mask);
>  }
>  
> -- 
> 2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBsWu36eqUw03Dy%40elver.google.com.
