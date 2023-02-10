Return-Path: <kasan-dev+bncBAABBW7ITKPQMGQEP7R4URY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 48D8969290B
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:16 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id a38-20020a2ebea6000000b0029065ed6963sf1883241ljr.16
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063835; cv=pass;
        d=google.com; s=arc-20160816;
        b=MvxG2sN87vrfZ1xfAZtqyVhrGPvkNXEzR1EIo1D58A+sUBitS7aDo6BZF/qSjEVzvO
         2aToevdQKuDOaq/0CIG8TofK5lnbBDWczR4za9AxCVV7ZXeeSEu7jPecmCrZVCET5gG2
         jc5kBT5nQmYbCDKZCa34epMufGOB1EwuoYJBKPEqZGgs0b9Ha5iNKInblz6yKhoPnX6d
         DXksm5F5dkDBEPcJGUHRJLgf/3xOwQWAYnd6RFlLnbvoGpXwr/S1bqAA4g7ETb0i4RN/
         KuheDwznyWVm23h980juBn8dWKcuyOi4KW3q4eWop7wDgexeyi9XSqw6rqYlDuKmKejV
         PhDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0exTReL7mHWJ9JLqsA8Ohk/Mr6MLccgA4xYRKQdGDVY=;
        b=zjc7/9WXs0zMsyyWs4dW6Fu0PgyyUTZm7Ydw6N9oWD+eWDQ9YidFyBHkC/i+u3Fuuo
         pXMyCilWI+4iy7fxfe4HpKWW4S2X4R0nph+cN9EuN8648glpJONKTBFuzKXdmy0Gqs8t
         5EOFz/ejiTCWFG1ioEvUc9cPGYhET5+EsTX4sCYw+eV+Gd5l3o/Iy8OHoYg1AOyBnWsb
         NG1YDHbJK3T/3U5iOFFZUZeebf0SGZM1nl7HM63VOTvFEZz/ZrpNjaced+ezY8twbWMa
         nrRr4kMU9kg6SI1H2+tCfMycQ3hIcAlN3GZtHtdzmbrlEgoiNVnZFjDm4ZNI+gvcZuob
         xKhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oyhVeDaz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0exTReL7mHWJ9JLqsA8Ohk/Mr6MLccgA4xYRKQdGDVY=;
        b=L5cxsKjrLP3p34KGHcct+xj0y5g8L1X3+jjvaTaVKaf27fgSrYnKd32shz2O/8Y3Ld
         Mz/0iaExCSw/AL56K8jHE+IjmZmWyKhlCd+RNA/4yWnGcJQdzNVjDImd2zRVbdzb5Jli
         8QTCmQNeo9hWfZP+dVDdFgkArFsOuk4ByXsyvbIraKEqvEn7tna1hypOldR2yh+iGla2
         6RY/kp0sRlQiAu1CNlr6jyqiM/MmwYiLG8cz9LVGxoqywNu8Csq7bNnc1+43WxSD0ACG
         KjowC5EaJYLk0WYMLl2IBMqEZ9YDVfZ0WAOQ9Op25GnnGAR92IcjnAsLM0tFInujqxQK
         9Lyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0exTReL7mHWJ9JLqsA8Ohk/Mr6MLccgA4xYRKQdGDVY=;
        b=3tSU0OyrHxvQcywpCcDj/Tj7zbC3CP2C1L5Adhxl2N/SCZriYPDGEOelSaCizK8qPb
         DqPLFGRs0TZhZmiPscrOcaJ2fzxuZf9+5/LnNoFzT9dnlxVejwIIiDlri8433mwR/Lmp
         4OWiALSDe7gVai0ltFKg+7IGQ8T/fkXN0pmlqwX/kXNsFtGK1eWCKjV+fVUZzyNjdhby
         dvvTraZG+HEBhI9XjI8rRaYKELNWBGPMLgSgPS8BI8jc5/V74JFNzM+HdO1KsMQjUpC4
         1gsydnYlUlpeYrCCPy39TTD0oNXKxNSNQ8US6OnDkx4wiqesokIzVgsv93G7yqlAE4GZ
         HpqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWIr0lrwy+gyWaYkPbsBIbKEyNFGmvfqwRjjP6hFl9bLGd1mtu8
	lODAsDBE7EeoOqWmIx8rkLY=
X-Google-Smtp-Source: AK7set9ZQrhwBcA0IU84ywEK8iLqmVNrVsIyd5D6qdQ30g8IHE01tsZI04y1ZcfZouW0xBhNsxrTOw==
X-Received: by 2002:a05:6512:62:b0:4ca:fe64:1011 with SMTP id i2-20020a056512006200b004cafe641011mr2496682lfo.164.1676063835559;
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:4e12:0:b0:293:186a:1056 with SMTP id c18-20020a2e4e12000000b00293186a1056ls1113152ljb.10.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:17:14 -0800 (PST)
X-Received: by 2002:a2e:9ed3:0:b0:293:1cea:e132 with SMTP id h19-20020a2e9ed3000000b002931ceae132mr4386346ljk.7.1676063834551;
        Fri, 10 Feb 2023 13:17:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063834; cv=none;
        d=google.com; s=arc-20160816;
        b=dy8VORyVf3t+dpBEM+TiwKfkKMpOxFNZEGl3N3bZ8HiqSmVS4UMhwBRabcCHSprl//
         Tisn43bRUSiNXxyy6jCLmDKge8HNKcxquy8e3+pFNId9l0VoN4qN2IIimXE/rrRSVQIH
         O7IZ6K9z2OdtPIH4VMWdpaoRRdL8/8waSVV/S0IHmkUACUAG/XLxYlMfnGFH5NKWNCn5
         kGo+EhNahxgu6Gvbf3pLIh6KubYDbUADzRrtgt7je21ihh+izOK50ZxwsWlIS+Dh4t1V
         DDzbzO66759rHge0nK+EI+llCqQQY7D+r9fcAMbaRu2dM7XeIyVA/oLelRgTRP56/yOU
         LVlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f9A90r0/KX/Fhu2j5j2j+xtwq4a98UiE0RWErOhidkA=;
        b=Uzh1NZxq2PuENqVdgCh7nmBGrUBBtLtCQSa1+8nSJ09hG1qJKwALJBKVrZIX4bYkFk
         N0IGrjQ06+zuywp6VB6VVtbwNeFw//sOXFjdEnkjHnzBEBid10q5GhDe1FdPJI/xf/3E
         ANAdm8/hVcClxgkRtg85gIsnxVYIXbk6MN3Mtm3dRpcCJOjr6KypXdFvJ1Mp0gg4QLPt
         c7JjhgaTpvktnrFE68xd9ShLHboHbR2ygZIpAi12zy6FP2TcQE/DJOZnVDEdqfpnHk3k
         yjRHqZRvh2wO8Tk0dt7dQbtxExFFXBATa2mUXJDhQV21FAqmL388CHMIO+KIDsWJztPX
         Dl9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oyhVeDaz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-141.mta1.migadu.com (out-141.mta1.migadu.com. [2001:41d0:203:375::8d])
        by gmr-mx.google.com with ESMTPS id z7-20020a2ebcc7000000b00293215eee9esi304134ljp.2.2023.02.10.13.17.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8d as permitted sender) client-ip=2001:41d0:203:375::8d;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 06/18] lib/stackdepot: lower the indentation in stack_depot_init
Date: Fri, 10 Feb 2023 22:15:54 +0100
Message-Id: <8e382f1f0c352e4b2ad47326fec7782af961fe8e.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oyhVeDaz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::8d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

stack_depot_init does most things inside an if check. Move them out and
use a goto statement instead.

No functional changes.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 70 +++++++++++++++++++++++++-----------------------
 1 file changed, 37 insertions(+), 33 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 9fab711e4826..3c713f70b0a3 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -165,46 +165,50 @@ int __init stack_depot_early_init(void)
 int stack_depot_init(void)
 {
 	static DEFINE_MUTEX(stack_depot_init_mutex);
+	unsigned long entries;
 	int ret = 0;
 
 	mutex_lock(&stack_depot_init_mutex);
-	if (!stack_depot_disabled && !stack_table) {
-		unsigned long entries;
 
-		/*
-		 * Similarly to stack_depot_early_init, use stack_hash_order
-		 * if assigned, and rely on automatic scaling otherwise.
-		 */
-		if (stack_hash_order) {
-			entries = 1UL << stack_hash_order;
-		} else {
-			int scale = STACK_HASH_SCALE;
-
-			entries = nr_free_buffer_pages();
-			entries = roundup_pow_of_two(entries);
-
-			if (scale > PAGE_SHIFT)
-				entries >>= (scale - PAGE_SHIFT);
-			else
-				entries <<= (PAGE_SHIFT - scale);
-		}
+	if (stack_depot_disabled || stack_table)
+		goto out_unlock;
 
-		if (entries < 1UL << STACK_HASH_ORDER_MIN)
-			entries = 1UL << STACK_HASH_ORDER_MIN;
-		if (entries > 1UL << STACK_HASH_ORDER_MAX)
-			entries = 1UL << STACK_HASH_ORDER_MAX;
-
-		pr_info("allocating hash table of %lu entries via kvcalloc\n",
-				entries);
-		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
-		if (!stack_table) {
-			pr_err("hash table allocation failed, disabling\n");
-			stack_depot_disabled = true;
-			ret = -ENOMEM;
-		}
-		stack_hash_mask = entries - 1;
+	/*
+	 * Similarly to stack_depot_early_init, use stack_hash_order
+	 * if assigned, and rely on automatic scaling otherwise.
+	 */
+	if (stack_hash_order) {
+		entries = 1UL << stack_hash_order;
+	} else {
+		int scale = STACK_HASH_SCALE;
+
+		entries = nr_free_buffer_pages();
+		entries = roundup_pow_of_two(entries);
+
+		if (scale > PAGE_SHIFT)
+			entries >>= (scale - PAGE_SHIFT);
+		else
+			entries <<= (PAGE_SHIFT - scale);
 	}
+
+	if (entries < 1UL << STACK_HASH_ORDER_MIN)
+		entries = 1UL << STACK_HASH_ORDER_MIN;
+	if (entries > 1UL << STACK_HASH_ORDER_MAX)
+		entries = 1UL << STACK_HASH_ORDER_MAX;
+
+	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
+	stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
+	if (!stack_table) {
+		pr_err("hash table allocation failed, disabling\n");
+		stack_depot_disabled = true;
+		ret = -ENOMEM;
+		goto out_unlock;
+	}
+	stack_hash_mask = entries - 1;
+
+out_unlock:
 	mutex_unlock(&stack_depot_init_mutex);
+
 	return ret;
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8e382f1f0c352e4b2ad47326fec7782af961fe8e.1676063693.git.andreyknvl%40google.com.
