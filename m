Return-Path: <kasan-dev+bncBAABBJV43KUQMGQEZCE7BHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 14A807D3C53
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:08 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-507ceeff451sf3633953e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078247; cv=pass;
        d=google.com; s=arc-20160816;
        b=nncsn99DBjwv0pXOH0Nxvnu7MaMqy2kQqT2vF/mbiutV1aEHFRQmqp9y+JOlyrb/Om
         BEVVzSc25aQDwbC5HFk6Ktz92MnxHNCk68inTH5cgQNLhlW0D3Ks2ofGfcuZ16YGdogU
         0q3tKbBWXDI7SsjBrJtqRStZ/K5hJYzwEpUo+6kAHfGU6RyDmlFlKgO6NgtOqfwBF5S7
         P80wTJ125LAX5utOgq1CIhkoCKDGqoMUtoWWeAPt1qjMxktjFEzUXVm9rzaPQQf+RiT1
         6LLq90dflgRs9mbVi9xqpejJrHADfSfk1pSCai6xYl/gWVZRo4VMmlhtfvNn3/n9AGRn
         foMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KZy5ecdiKtPVmx0/nSMrB2oX4qoQQBGfFq2JGgUzr5U=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=NfZpANt/wK5qhFj6xYQ7TNPwIFF1/GRnoMQJTBwpuRZI21Z9uvKgf1yl63/eIW1tt6
         E89+FQLpNqTt7Ouh7wgCRjiCxd4PJvcnx3F3nbKwr8KSd1keBNELp9mCzIUYqV4P0eYV
         0UaFnIaNJ75YbeMLx6uibBmwj/gY1Kxeo6YZXSW0d90GDtEcCfsNEWIK1aVCXtfwUXTp
         pAeJvdwDEHCZbftBsISRF0QjHDlBIi5oqhFd6iXIwE/mTCj0LZBFSwbdIE+O04Q9DAbd
         niXQee7mh3bMyV3LKcB5CiFWWxQbWPhUK9kmZqn0DVGVQAeGVQsDYLdYuCxYtzOgVk8O
         vcLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NfBcevWE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078247; x=1698683047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KZy5ecdiKtPVmx0/nSMrB2oX4qoQQBGfFq2JGgUzr5U=;
        b=VdfcDSeyp1XfZD+btMv4wyhHddEJxREycDyjePH1QNiv6doIxcUQ5M9ND0IcQ29VnC
         qH/r0RpJ+/i6B6/xx8FJqP3sp7YuQi+4y7zObLlhw7jBYlad50lAmaz+CZVrqKvKDZfw
         +uO+zAPubqoSjKpI/LbTCzISxX+CTiyHSso3Zm+nOaMYT4zZgcpjPEvJEnf2c0DuKKu2
         8oKwDdpx2KgdnjYLLsEj7LEh7Srf4MNa1rifftN4z4wnNmm2+PbM1V00HjD30QtO1nkj
         S/WAaX0ncUuohdhvEnU9vjXMSmkLJZOmg45umJwrs4w/bNZ3FZ+RdVMvrBteNlthnL1C
         EgLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078247; x=1698683047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KZy5ecdiKtPVmx0/nSMrB2oX4qoQQBGfFq2JGgUzr5U=;
        b=h5vlzGMAew3sLqKxJDwnta7vvahAeOimqge3E4cuKpV6aZfCneL8UmqNFUJO/h9yQh
         mgdsHj7D3RUiP0SMnHgYN4OzsYYknsPJfLma5wRTfSeKIZJGdUUNKp1ggb5d+zqQcIAU
         vG3QTT45NfFZcYiizNLcewQf8caPPMxumPChnAZRLgck0mD4MWrsm8eM7uuiRqXfaaht
         IlFnQRjKfAX1eq6CFjHl1U4nfxjAVXqmsfCHz4WS7/MrrFU8hdDWm5be1JGPrKDn9oJr
         j13f61vuL0iAttcXqtasr5UOjXtb0NM+fjHpD/RKi0OTBTMSRvtSrm03r5D34wVGxkdj
         Z/IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwU4FQdGVopxuJL1CoY7x0PvD/dceYeDX6PstH0/C3YMFB1+1bS
	0Q3H8zOMJ6uJTK7lfJ5xSY8=
X-Google-Smtp-Source: AGHT+IEmBH2WBVEgMpryfh93cjgO3ejZ1upYrvCWghZNouqC8b63k/icBEX7NeOc5mWaXPlzLvTGaw==
X-Received: by 2002:a05:6512:481:b0:503:367c:49c8 with SMTP id v1-20020a056512048100b00503367c49c8mr6557558lfq.5.1698078247113;
        Mon, 23 Oct 2023 09:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:46f8:0:b0:507:c72c:9d87 with SMTP id q24-20020ac246f8000000b00507c72c9d87ls49073lfo.1.-pod-prod-02-eu;
 Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
X-Received: by 2002:ac2:5e9c:0:b0:503:1875:5ae5 with SMTP id b28-20020ac25e9c000000b0050318755ae5mr6663494lfq.38.1698078245533;
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078245; cv=none;
        d=google.com; s=arc-20160816;
        b=bDp6JgGC+N/0CgPhobgtP7GnFhkboDnU/J/SXXqGJ9hfRpTsMvXGY/og3iWwnOtAT3
         fZ7ZzscX80KVHmebwHZllLf2/fjhHbVFOCP1xLKqXqwyZh/WRRLvDqVPU7BqpRx+4se+
         9D87adwC0FdRNBzmtPXlvpianURsqzleQKp7eNqYnB5AbsjFJXAK9kulXPZsrKzPrMJq
         vWmsxpw60GmBNQuhXJLkPmJSInDOZcsux0TzmbdOgAVk8oQ4ruoeODR2i60Qe+epoULv
         sq9EiosHPYtIreqC21V8wWuiTrP93X0rHQFA/jHN1N1QanNeEUud976udkOBWbnbkviL
         Lgtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ApzhSzVlCGqOU4aCEVUKgk2/C6zStSgrVwNwdDBjs8U=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=mQMwHDXRx6UaP1MWtScvXzkZKQs8s7YTCDsu5geInykt9nXy6gC95WOgllqIn3fYRh
         y1j5mI3laOj1Zzq94Dr9nMFAp+eoTFE9DqjqzW/hG2tMI8WON6DhbCFRmCnXiZVmC3/u
         gsVXdYNcVUWE7/O5WID4VpxB5uJPEw9m4+dwpxSHsbsxn1UAdhu12g0vO8ip9Oqulg/y
         cFivgm6hQgE+iaicpsdDawyNFuN8UUEyc1c1IZrWxMYfbBbXj7ZNhIdFgsJZ4yno9dqZ
         ecnyDgQsz73YyhKrHYflGj+LXROU5G2MvZ+Tmr6/jpSAe54HMGej67V2k4mREoB7qTwK
         bAew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NfBcevWE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-197.mta1.migadu.com (out-197.mta1.migadu.com. [95.215.58.197])
        by gmr-mx.google.com with ESMTPS id 16-20020a508e50000000b005378cb9a578si495953edx.2.2023.10.23.09.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) client-ip=95.215.58.197;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 09/19] lib/stackdepot: store next pool pointer in new_pool
Date: Mon, 23 Oct 2023 18:22:40 +0200
Message-Id: <852c5fed993f6b1e21beca9faa85e0fc2d9b84e6.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NfBcevWE;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Instead of using the last pointer in stack_pools for storing the pointer
to a new pool (which does not yet store any stack records), use a new
new_pool variable.

This a purely code readability change: it seems more logical to store
the pointer to a pool with a special meaning in a dedicated variable.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 7579e20114b1..5315952f26ec 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -85,6 +85,8 @@ static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
 static void *stack_pools[DEPOT_MAX_POOLS];
+/* Newly allocated pool that is not yet added to stack_pools. */
+static void *new_pool;
 /* Currently used pool in stack_pools. */
 static int pool_index;
 /* Offset to the unused space in the currently used pool. */
@@ -235,7 +237,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
-		stack_pools[pool_index + 1] = *prealloc;
+		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
 
@@ -266,6 +268,8 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		 * stack_depot_fetch().
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
+		stack_pools[pool_index] = new_pool;
+		new_pool = NULL;
 		pool_offset = 0;
 
 		/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/852c5fed993f6b1e21beca9faa85e0fc2d9b84e6.1698077459.git.andreyknvl%40google.com.
