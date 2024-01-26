Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPZZ2WQMGQEPIJKVJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8608F83DB70
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 15:08:18 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-339222e46a0sf315959f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 06:08:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706278098; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q8QjD+Q40emFHPyYPxdZdrUNzChsffhJR6kEF+hryxng+2wTYDPTfDqYzztW9QrBlB
         oFIXXsH7LeiaQ/KKTchdkeLZ0CY5EKzGFTnAc8OBG79cL41N1FHA+WyNTX61ABiWLntb
         P6uY66K8x12dJtfAtjgJkCR1CteFj2VZyOGe3OXKHSz9o3tTEeMadhhIb5wyeGi8TrsU
         rAdiebB9ycrVtwPqZywL7xdM7qKKPf+I/8gnfviJQmGAaVIltAo6DGjVcUHw7nGLnbY0
         0NGCr0EHVTcqNX3xc/mbGYpVa+NUWpBsZSkK8Y3SLPSLOe3JK//pJ7N2EYi11cLHgjxk
         M51g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=27lV8QYZpxyc5I3efCmWHToyUTPpct6f0/FW45uC2zA=;
        fh=BI3rcWnDvL/7fXSIgr+SN/3NGEHrtjNtnNQ2IyTlgaQ=;
        b=D89OXJX0nYZd65+AMfwagWBXdqPEOYonFicbEcrDCwE/TjXmVyk3fXSy0J4oA8cbf7
         b3XJwuPP6xiHBetL/xxjlsjfXUbasW7xgZ2PdFhzGuvBW9VYdBWOrO5gruhiohDXJZe+
         QR45LnVP15ybgBfRgCHFD9HnIgXiDSBHG+PipQESTw/CIHMWXblnu8+fPKyJnDn29UbO
         +gMjjK6mGWInA9DUbI9dl4viyjmHBDEPJfNcdVSo91TSDPS1rX6ZXZcUtcGUDcuv7ohc
         i+7RpvO5zosQyM0FZ/gNvmCAJuhCykO71qrDGmcYDkUmVGsUU9ysPohzZLWMrFNn32gk
         Y70w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ThsR59vE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706278098; x=1706882898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=27lV8QYZpxyc5I3efCmWHToyUTPpct6f0/FW45uC2zA=;
        b=N6ubB65L41fQUnPzd37xkBJ55/CmYQcPwkIKiaZ38YeJYnv0F3uuy4tHk2//mJuC7Y
         J7ajPk5g5zxwWv0lxKuJ8N78l7GfxVrizw5ikaiQt/1wyvWggTRb/huWMaAdn/V1S1F5
         wjB5B1o8fBddlMM8UP8GccbWdYM1mpwFsOLFUsZaWLMUFBF+ENlYMnTR4ouG9hUOc+7Q
         sRqg3j7j0wXjCfkB/mu7GuNooTRKaHHkNRqUefHfCvLqDZs4ce8lMpQzZWTQ+PgCUUH8
         afjGAp9RFzQnPnypJfbGGc3Ihe4LtJkMbaMM8ZXLfOU2Exex8XswEUQcl3BKUZ5eJnYL
         e8Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706278098; x=1706882898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=27lV8QYZpxyc5I3efCmWHToyUTPpct6f0/FW45uC2zA=;
        b=UsdRPq2PUxYuLUanCJoMzs5fzdHIByCBP/0F3nj/re11Ad7tp2maLHD6n7gNUyUWM/
         Xg00hhDysWJeBWQATc9eAwynFXplpLIZEwxErfkPwOXVsDnBR/1z1s5LXjjKgGBxdkV3
         v2lQ0EWFurJs0Wg8Lc308+WxpjITkxYJbELmvXYTJrxao+zkHRUVDPjxc58EWv6+X2eU
         vtchbj64ZBX4wqj7ksHXBd3tN2RPGuJB18nu8jqPzpbymxtWaS0Fjb+XaK+f3XR8s0Y4
         oG81jpJc5cReevIM0jwMbE9R4zQBf4F4lH7Tf6/4ayBnCipM8rXFYCM8kYgfrMdshIMU
         ERzA==
X-Gm-Message-State: AOJu0Yzib1pzxhngzxKe0/vqKri2ABvwp/BQSaorZS+cScBFsUJPjdom
	xnH2PRWRlCWjqKNzAwkd59H5ZaSXjlDdkcT9z+hV2FeA82Z/YKUo
X-Google-Smtp-Source: AGHT+IFncBtsHzT6SYFL4zIgAL54TaFhz65z2ezTlgddfr5fmjovYj7pyvCt/vwjzCZAYT1TOxy1ug==
X-Received: by 2002:a05:600c:6029:b0:40e:dd4a:d3ba with SMTP id az41-20020a05600c602900b0040edd4ad3bamr641641wmb.134.1706278097223;
        Fri, 26 Jan 2024 06:08:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f85:b0:40e:af43:5129 with SMTP id
 n5-20020a05600c4f8500b0040eaf435129ls256452wmq.1.-pod-prod-07-eu; Fri, 26 Jan
 2024 06:08:15 -0800 (PST)
X-Received: by 2002:a1c:7419:0:b0:40e:e748:ba5f with SMTP id p25-20020a1c7419000000b0040ee748ba5fmr265162wmc.140.1706278094974;
        Fri, 26 Jan 2024 06:08:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706278094; cv=none;
        d=google.com; s=arc-20160816;
        b=dWYW8faXI6YMJotfrS2f5/qBn7Pt/tvRElWr0GsnCcfj8um26qS6rggNrlrfS4bPmK
         dxBfkwK9wlBflBKXJNxYOuHYuVtsrHSpgbn1Lx1u+UduLbMBHx+ijwC6b8tMRTfsYuoj
         /t5A+JZMvqS+I1vfOg3SYYDfgvfop18MetrN8RCGCQbTn9gUJCFhsYKW1DXdEtcTbsqw
         Q8nQe2VHzgatVeLp/i+vrihnAJ9kYbGMq6vWqw1Rq2eAhH4lR8p+dcwOGGw3Dz3XTxDN
         g+b49J4jg6EK9ckYgAL5/EGCiLrr4aMfDqVcJblGzFbtfwKuowOLiFNy+0tXlA0wZZPC
         11PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/VI/OXzcFzlYXsdPLN9N03OpjAt6MEKivygrHh6SqEg=;
        fh=BI3rcWnDvL/7fXSIgr+SN/3NGEHrtjNtnNQ2IyTlgaQ=;
        b=QUiRmQjEy00RdgLrbZA05UaVIKax+daRN0d7xz5QaEA64gSxud4O9Qea1ehyXD0eCO
         oSMV9fhydwBw1fdJg47xB4XqQ1zPUwCLLH36pqxYXpj3zK2SFbPon6R6ob2xv7OIrvWj
         lhqFHtlVS4cL7xx5v8VlPNUszatpd1KsnyDsQ5nFforwpMpciwgMy99j9i9nPGJEHdIv
         zsFicw0a2hir2S8sbIvu0rJ6zQJbX2m80pvbFQv4D2gWLcUM13i4uR7wrlg9mdxzsY5s
         LRO0sedrAPKOGHmv27gFKxyQpbt6MByQr7n5hzwrPwkR/4n+CJeV9yG5ou1iwKAW0WAq
         NHYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ThsR59vE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id jd2-20020a05600c68c200b0040ee0a44a92si33778wmb.2.2024.01.26.06.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jan 2024 06:08:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-40eac352733so9106365e9.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Jan 2024 06:08:14 -0800 (PST)
X-Received: by 2002:a05:600c:3421:b0:40e:c363:bc15 with SMTP id y33-20020a05600c342100b0040ec363bc15mr979356wmp.65.1706278094299;
        Fri, 26 Jan 2024 06:08:14 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:3837:e733:e624:7fe2])
        by smtp.gmail.com with ESMTPSA id k35-20020a05600c1ca300b0040e4ca7fcb4sm2013199wms.37.2024.01.26.06.08.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Jan 2024 06:08:13 -0800 (PST)
Date: Fri, 26 Jan 2024 15:08:08 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH 1/2] stackdepot: use variable size records for
 non-evictable entries
Message-ID: <ZbO8yD_ofPQ1Z2NT@elver.google.com>
References: <20240125094815.2041933-1-elver@google.com>
 <CA+fCnZfzpPvg3UXKfxhe8n-tT2Pqhfysy_HdrMb6MxaEtnJ2BQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfzpPvg3UXKfxhe8n-tT2Pqhfysy_HdrMb6MxaEtnJ2BQ@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ThsR59vE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as
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

On Thu, Jan 25, 2024 at 11:35PM +0100, Andrey Konovalov wrote:
[...]
> I wonder if we should separate the stat counters for
> evictable/non-evictable cases. For non-evictable, we could count the
> amount of consumed memory.
[...]
> 
> We can also now drop the special case for DEPOT_POOLS_CAP for KMSAN.
> 
> Otherwise, looks good to me.
> 
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> 
> Thank you for cleaning this up!

Thanks - probably will add this change for v2:

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 1b0d948a053c..8f3b2c84ec2d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -44,17 +44,7 @@
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
 #define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
 			       STACK_DEPOT_EXTRA_BITS)
-#if IS_ENABLED(CONFIG_KMSAN) && CONFIG_STACKDEPOT_MAX_FRAMES >= 32
-/*
- * KMSAN is frequently used in fuzzing scenarios and thus saves a lot of stack
- * traces. As KMSAN does not support evicting stack traces from the stack
- * depot, the stack depot capacity might be reached quickly with large stack
- * records. Adjust the maximum number of stack depot pools for this case.
- */
-#define DEPOT_POOLS_CAP (8192 * (CONFIG_STACKDEPOT_MAX_FRAMES / 16))
-#else
 #define DEPOT_POOLS_CAP 8192
-#endif
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
 	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
@@ -128,18 +118,22 @@ static DEFINE_RAW_SPINLOCK(pool_lock);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
-	DEPOT_COUNTER_ALLOCS,
-	DEPOT_COUNTER_FREES,
-	DEPOT_COUNTER_INUSE,
+	DEPOT_COUNTER_REFD_ALLOCS,
+	DEPOT_COUNTER_REFD_FREES,
+	DEPOT_COUNTER_REFD_INUSE,
 	DEPOT_COUNTER_FREELIST_SIZE,
+	DEPOT_COUNTER_PERSIST_COUNT,
+	DEPOT_COUNTER_PERSIST_BYTES,
 	DEPOT_COUNTER_COUNT,
 };
 static long counters[DEPOT_COUNTER_COUNT];
 static const char *const counter_names[] = {
-	[DEPOT_COUNTER_ALLOCS]		= "allocations",
-	[DEPOT_COUNTER_FREES]		= "frees",
-	[DEPOT_COUNTER_INUSE]		= "in_use",
+	[DEPOT_COUNTER_REFD_ALLOCS]	= "refcounted_allocations",
+	[DEPOT_COUNTER_REFD_FREES]	= "refcounted_frees",
+	[DEPOT_COUNTER_REFD_INUSE]	= "refcounted_in_use",
 	[DEPOT_COUNTER_FREELIST_SIZE]	= "freelist_size",
+	[DEPOT_COUNTER_PERSIST_COUNT]	= "persistent_count",
+	[DEPOT_COUNTER_PERSIST_BYTES]	= "persistent_bytes",
 };
 static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);
 
@@ -388,7 +382,7 @@ static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 	return stack;
 }
 
-/* Try to find next free usable entry. */
+/* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
 {
 	struct stack_record *stack;
@@ -466,9 +460,13 @@ depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_
 
 	if (flags & STACK_DEPOT_FLAG_GET) {
 		refcount_set(&stack->count, 1);
+		counters[DEPOT_COUNTER_REFD_ALLOCS]++;
+		counters[DEPOT_COUNTER_REFD_INUSE]++;
 	} else {
 		/* Warn on attempts to switch to refcounting this entry. */
 		refcount_set(&stack->count, REFCOUNT_SATURATED);
+		counters[DEPOT_COUNTER_PERSIST_COUNT]++;
+		counters[DEPOT_COUNTER_PERSIST_BYTES] += record_size;
 	}
 
 	/*
@@ -477,8 +475,6 @@ depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_
 	 */
 	kmsan_unpoison_memory(stack, record_size);
 
-	counters[DEPOT_COUNTER_ALLOCS]++;
-	counters[DEPOT_COUNTER_INUSE]++;
 	return stack;
 }
 
@@ -546,8 +542,8 @@ static void depot_free_stack(struct stack_record *stack)
 	list_add_tail(&stack->free_list, &free_stacks);
 
 	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
-	counters[DEPOT_COUNTER_FREES]++;
-	counters[DEPOT_COUNTER_INUSE]--;
+	counters[DEPOT_COUNTER_REFD_FREES]++;
+	counters[DEPOT_COUNTER_REFD_INUSE]--;
 
 	printk_deferred_exit();
 	raw_spin_unlock_irqrestore(&pool_lock, flags);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbO8yD_ofPQ1Z2NT%40elver.google.com.
