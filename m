Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH7PYGKQMGQEX3GWDZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 817B9551AC7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:35:28 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id k32-20020a05600c1ca000b0039c4cf75023sf6899672wms.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732128; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ee8ADAOeM7Boe5uwwaScE38joGkQgFYQyS8vEOHqyvZY0DHBkLC7IzytVbZXROlPRt
         2WqEapXX6BKfVHE2B6PisByg4njALH1sQ9FDEbYZD05lsM08ATBgRstRD5XccfkusFJ6
         n2JcLNg/e1kDcBOJTcmDVwPOoUHQVdRCPvALA65BMexkpp08LORM4rNJxB0kuwaRrFmW
         xXY7u9alH3WbMl5suEB3Kmy8ZnUXZ5ZzI1cLjr9b3w+njuzitm3NGvstLGyvBD0vjZKw
         LDFOf+6Gtf02dHEz+5lqvbcTG5/YK8ggZQ9DNATyJQAL/ovad5phSGN1lxS1zo48qXli
         iU7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5J+1x7JuOVXxskNCqC5AFsHuHY+knDQ5t03695+3Bok=;
        b=PEOX5X5MrDGhi2+yrTJYtidDLoM0wUGzwlnJQHmifyOua2pbI8t+Tc/ql6tLvnOupN
         ODAMCqFsjmN9kyBn6b68m+07WZkqmbEsZWfEGkShTydHu2WIaTe895a8QeOCrFTIH47U
         AOYGTE8hA3lE8+W/ae6HDuMXarc4RGp8N1+ZDOtqFTVgq9q1psLqqCNpDkZujOIXpZda
         TYGV1JyCJ/rZjogu6GkvfylOjWWDMkheuMqo7zLziyHzkiKtQ4jB1FNNTBmR/skjcdHL
         ciV9yEPcQl3ps/t2Z2B/ofOqmmHFn2h50WEwM9Tgewe1/egd4sxgykKRUTztjcid/A1U
         X4UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rsOpJuRQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5J+1x7JuOVXxskNCqC5AFsHuHY+knDQ5t03695+3Bok=;
        b=fqqgK+7GzrasXZyskYuvPbsrOGkoNyK7MxA3WEGTtThsHJ+NVig1Mi9r/p4gxhwel8
         koIn5UM3qkL1xou4pk0si4IxopXWxtGddA30QBYRoQVa8nB60MfHC9CAsSiRHfvkw56e
         3u/fl2M1SVFV+YugX+tpmpfb/RNChfVPxlKKGcV2tNPUuLkEAQkvu9RQ+kPnOGrzBwEY
         gPT+U+fm0uHg95r8+1WtvbzGs/YAXmTBzwxX5pokjD/lW5sGN7PUFfjxP/5J5BJOOwE7
         KTBIxru27kvjK47Lk9bxgp78dKIag3yICZs+eQQXy2Hp2higfLvm9ptRtalJLkvKAyJt
         5KbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5J+1x7JuOVXxskNCqC5AFsHuHY+knDQ5t03695+3Bok=;
        b=haHPiYz0/Gin1MmXOnHbi+RthG9I22Jaqy4gyulR0GnlEWFR4E6Z0U4iTszHofiD03
         O8+XIjfvSmnUVEBmk96f8rDQ6jEnHvN67LiWo1JTW2iqMYnM0WKM3LYCFM38lNSe1lGH
         keXKa7h5HgagVWBLRT0C2KAd+Vn9qgrMLFKmZQOoibG/LGyBqhz7s142X2Y/sgT2AVXp
         8JbhrD10j17Etl1MOjcK1Tt+ljFkTt9v5SUX9clXVqXfSepUFkcMYz9DGhk0MPpTBHPe
         PUSiyRSCKN1A5VgmkjBJWsE5oEr0pbVz9Pt2MsLCDDP/nwn78NB/H6uxPHJ7OVYOYHXz
         jvEA==
X-Gm-Message-State: AJIora8AelKEXQVK3naxF4p8EmXQLWnwnMsBS1QQn7+/Dfi42AXePAm/
	zriMwoI9UWHQN2/7NuqagUo=
X-Google-Smtp-Source: AGRyM1uWNEbE9XQrHy0+8K+KO/xSGuXz60cgFi4yvuEkkiWG51VRtTt7cq+99QjJ/jo+85kfvDno7g==
X-Received: by 2002:a5d:4649:0:b0:218:4d6c:3f3f with SMTP id j9-20020a5d4649000000b002184d6c3f3fmr23030258wrs.148.1655732128134;
        Mon, 20 Jun 2022 06:35:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8c:b0:39c:5b80:3b5c with SMTP id
 bi12-20020a05600c3d8c00b0039c5b803b5cls5433756wmb.2.gmail; Mon, 20 Jun 2022
 06:35:26 -0700 (PDT)
X-Received: by 2002:a7b:ce87:0:b0:39c:5509:660c with SMTP id q7-20020a7bce87000000b0039c5509660cmr24920468wmj.163.1655732126920;
        Mon, 20 Jun 2022 06:35:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732126; cv=none;
        d=google.com; s=arc-20160816;
        b=KUdZwzrIKilk7OELaZ+Bw9xThE8Gy6WLOADCQ6V28aPtyAQqA5AALFPW+ZeVXECDt4
         tIcWScm7yARN2f4tYTn71DJBEf5ikz9U/B8VbhDXQhdnVkjM4WKWOmKYH7DpCfop0iJL
         rPE5V4boEz5pY/781glQQAqMN0Hyoffth+g/2ZPEMM+P3VRcCtnjsZQFdl7s8y8sjJVl
         yigZJkL84L3M//ikA0hYbZAtJlRlsksliEOIUMuLJaAfefKZ9ZqSqviMveGA76M0JzWO
         /r/kriKlRfmNd5KNPsKP5Xe9soY687rLlSuZsSmpaTXtiEr+aZE+PqUt8rsenmwzyI/r
         kysA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HAkMTw3RnZa1KmlhutNG14tDB6CYw3hV2uXbql6UXzk=;
        b=hkvOSS8Z1wY1gqywNz8vrat540332/D0ozQVfFqzfJB0Ge0rAxCNmG94yp0jiII/td
         OnNgvs9umiDB1OW7Ala1oQfivhwEf/9YmHxUj8nc12lzAxkov+1Bv22JXK0c8RjzefXd
         0aZoP/ofSyjSBT9F6RwlGbtFzJRF5GBqF44vSlc2U2KwAkLMqZXN31AExSd391L9co9H
         Jyr0hWCdsS1vENIaIQvG8dhxVEyB8nqjnPMogtdwLKwXKDD7r4ctL5rqo9BaCu69twUr
         Kwe2oC1Uo3OWopjZ13psN6hL+bXFrnDLSx2FeYpMoXfMwuJstgZT0llsOIr0zBiN3nF0
         stuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rsOpJuRQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id m18-20020adfe952000000b002132c766fd7si530439wrn.4.2022.06.20.06.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id g27so8065905wrb.10
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:35:26 -0700 (PDT)
X-Received: by 2002:adf:ec4f:0:b0:21b:90c0:139e with SMTP id w15-20020adfec4f000000b0021b90c0139emr4242107wrn.550.1655732126280;
        Mon, 20 Jun 2022 06:35:26 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3746:a989:7595:e29f])
        by smtp.gmail.com with ESMTPSA id j19-20020a05600c1c1300b0039c5645c60fsm27203906wms.3.2022.06.20.06.35.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jun 2022 06:35:25 -0700 (PDT)
Date: Mon, 20 Jun 2022 15:35:19 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 31/32] kasan: implement stack ring for tag-based modes
Message-ID: <YrB3l6A4hJmvsFp3@elver.google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
 <3cd76121903de13713581687ffa45e668ef1475a.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3cd76121903de13713581687ffa45e668ef1475a.1655150842.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.3 (2022-04-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rsOpJuRQ;       spf=pass
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

On Mon, Jun 13, 2022 at 10:14PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Implement storing stack depot handles for alloc/free stack traces for
> slab objects for the tag-based KASAN modes in a ring buffer.
> 
> This ring buffer is referred to as the stack ring.
> 
> On each alloc/free of a slab object, the tagged address of the object and
> the current stack trace are recorded in the stack ring.
> 
> On each bug report, if the accessed address belongs to a slab object, the
> stack ring is scanned for matching entries. The newest entries are used to
> print the alloc/free stack traces in the report: one entry for alloc and
> one for free.
> 
> The ring buffer is lock-free.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> The number of entries in the stack ring is fixed in this version of the
> patch. We could either implement it as a config option or a command-line
> argument. I tilt towards the latter option and will implement it in v2
> unless there are objections.

Yes, that'd be good, along with just not allocating if no stacktraces
are requested per kasan.stacktrace=.

> ---
>  mm/kasan/kasan.h       | 20 ++++++++++++++
>  mm/kasan/report_tags.c | 61 ++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/tags.c        | 30 +++++++++++++++++++++
>  3 files changed, 111 insertions(+)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index c51cea31ced0..da9a3c56ef4b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -2,6 +2,7 @@
>  #ifndef __MM_KASAN_KASAN_H
>  #define __MM_KASAN_KASAN_H
>  
> +#include <linux/atomic.h>
>  #include <linux/kasan.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/kfence.h>
> @@ -227,6 +228,25 @@ struct kasan_free_meta {
>  
>  #endif /* CONFIG_KASAN_GENERIC */
>  
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +
> +struct kasan_stack_ring_entry {
> +	atomic64_t ptr;		/* void * */
> +	atomic64_t size;	/* size_t */
> +	atomic_t pid;		/* u32 */
> +	atomic_t stack;		/* depot_stack_handle_t */
> +	atomic_t is_free;	/* bool */

Per comments below, consider making these non-atomic.

> +};
> +
> +#define KASAN_STACK_RING_ENTRIES (32 << 10)
> +
> +struct kasan_stack_ring {
> +	atomic64_t pos;
> +	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_ENTRIES];
> +};
> +
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>  /* Used in KUnit-compatible KASAN tests. */
>  struct kunit_kasan_status {
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 5cbac2cdb177..21911d1883d3 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -4,8 +4,12 @@
>   * Copyright (c) 2020 Google, Inc.
>   */
>  
> +#include <linux/atomic.h>
> +
>  #include "kasan.h"
>  
> +extern struct kasan_stack_ring stack_ring;
> +
>  static const char *get_bug_type(struct kasan_report_info *info)
>  {
>  	/*
> @@ -24,5 +28,62 @@ static const char *get_bug_type(struct kasan_report_info *info)
>  
>  void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  {
> +	u64 pos;
> +	struct kasan_stack_ring_entry *entry;
> +	void *object;
> +	u32 pid;
> +	depot_stack_handle_t stack;
> +	bool is_free;

If you switch away from atomic for kasan_stack_ring_entry members, you
can just replace the above with a 'struct kasan_stack_ring_entry' and
READ_ONCE() each entry into it below.

> +	bool alloc_found = false, free_found = false;
> +
>  	info->bug_type = get_bug_type(info);
> +
> +	if (!info->cache || !info->object)
> +		return;
> +
> +	pos = atomic64_read(&stack_ring.pos);
> +
> +	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_ENTRIES; i--) {
> +		if (alloc_found && free_found)
> +			break;
> +
> +		entry = &stack_ring.entries[i % KASAN_STACK_RING_ENTRIES];
> +
> +		/* Paired with atomic64_set_release() in save_stack_info(). */
> +		object = (void *)atomic64_read_acquire(&entry->ptr);
> +
> +		if (kasan_reset_tag(object) != info->object ||
> +		    get_tag(object) != get_tag(info->access_addr))
> +			continue;
> +
> +		pid = atomic_read(&entry->pid);
> +		stack = atomic_read(&entry->stack);
> +		is_free = atomic_read(&entry->is_free);
> +
> +		/* Try detecting if the entry was changed while being read. */
> +		smp_mb();
> +		if (object != (void *)atomic64_read(&entry->ptr))
> +			continue;

What if the object was changed, but 'ptr' is the same? It might very
well be possible to then read half of the info of the previous object,
and half of the new object (e.g. pid is old, stack is new).

Is the assumption that it is extremely unlikely that this will happen
where 1) address is the same, and 2) tags are the same? And if it does
happen, it is unlikely that there'll be a bug on that address?

It might be worth stating this in comments.

Another thing is, if there's a bug, but concurrently you have tons of
allocations/frees that change the ring's entries at a very high rate,
how likely is it that the entire ring will have been wiped before the
entry of interest is found again?

One way to guard against this is to prevent modifications of the ring
while the ring is searched. This could be implemented with a
percpu-rwsem, which is almost free for read-lockers but very expensive
for write-lockers. Insertions only acquire a read-lock, but on a bug
when searching the ring, you have to acquire a write-lock. Although you
currently take the contention hit for incrementing 'pos', so a plain
rwlock might also be ok.

It would be good to understand the probabilities of these corner cases
with some average to worst case workloads, and optimize based on that.

> +
> +		if (is_free) {
> +			/*
> +			 * Second free of the same object.
> +			 * Give up on trying to find the alloc entry.
> +			 */
> +			if (free_found)
> +				break;
> +
> +			info->free_track.pid = pid;
> +			info->free_track.stack = stack;
> +			free_found = true;
> +		} else {
> +			/* Second alloc of the same object. Give up. */
> +			if (alloc_found)
> +				break;
> +
> +			info->alloc_track.pid = pid;
> +			info->alloc_track.stack = stack;
> +			alloc_found = true;
> +		}
> +	}
>  }
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 39a0481e5228..286011307695 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -6,6 +6,7 @@
>   * Copyright (c) 2020 Google, Inc.
>   */
>  
> +#include <linux/atomic.h>
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> @@ -16,11 +17,40 @@
>  #include <linux/types.h>
>  
>  #include "kasan.h"
> +#include "../slab.h"
> +
> +struct kasan_stack_ring stack_ring;

This is a very large struct. Can it be allocated by memblock_alloc()
very early on only if required (kasan.stacktrace= can still switch it
off, right?).

> +void save_stack_info(struct kmem_cache *cache, void *object,
> +			gfp_t flags, bool is_free)

static void save_stack_info(...)

> +{
> +	u64 pos;
> +	struct kasan_stack_ring_entry *entry;
> +	depot_stack_handle_t stack;
> +
> +	stack = kasan_save_stack(flags, true);
> +
> +	pos = atomic64_fetch_add(1, &stack_ring.pos);
> +	entry = &stack_ring.entries[pos % KASAN_STACK_RING_ENTRIES];
> +
> +	atomic64_set(&entry->size, cache->object_size);
> +	atomic_set(&entry->pid, current->pid);
> +	atomic_set(&entry->stack, stack);
> +	atomic_set(&entry->is_free, is_free);
> +

I don't see the point of these being atomic. You can make them normal
variables with the proper types, and use READ_ONCE() / WRITE_ONCE().

The only one where you truly need the atomic type is 'pos'.

> +	/*
> +	 * Paired with atomic64_read_acquire() in
> +	 * kasan_complete_mode_report_info().
> +	 */
> +	atomic64_set_release(&entry->ptr, (s64)object);

This could be smp_store_release() and 'ptr' can be just a normal pointer.

One thing that is not entirely impossible though (vs. re-reading same
pointer but inconsistent fields I mentioned above), is if something
wants to write to the ring, but stalls for a very long time before the
release of 'ptr', giving 'pos' the chance to wrap around and another
writer writing the same entry. Something like:

  T0					| T1
  --------------------------------------+--------------------------------
  WRITE_ONCE(entry->size, ..) 		| 
  WRITE_ONCE(entry->pid, ..)		| 
					| WRITE_ONCE(entry->size, ..)
					| WRITE_ONCE(entry->pid, ..)
  					| WRITE_ONCE(entry->stack, ..)
  					| WRITE_ONCE(entry->is_free, ..)
  					| smp_store_release(entry->ptr, ...)
  WRITE_ONCE(entry->stack, ..)		|
  WRITE_ONCE(entry->is_free, ..)	|
  smp_store_release(entry->ptr, ...)	|

Which results in some mix of T0's and T1's data.

The way to solve this is to implement a try-lock using 'ptr':

	#define BUSY_PTR ((void*)1)  // non-zero because initial values are 0
	old_ptr = READ_ONCE(entry->ptr);
	if (old_ptr == BUSY_PTR)
		goto next; /* Busy slot. */
	if (!try_cmpxchg(&entry->ptr, &old_ptr, BUSY_PTR))
		goto next; /* Busy slot. */
	... set fields as before ...
	smp_store_release(&entry->ptr, object);

> +}
>  
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
> +	save_stack_info(cache, object, flags, false);
>  }
>  
>  void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
> +	save_stack_info(cache, object, GFP_NOWAIT, true);
>  }
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrB3l6A4hJmvsFp3%40elver.google.com.
