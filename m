Return-Path: <kasan-dev+bncBAABB3G34CPAMGQEVOXUKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A85681BCF
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:57 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id x12-20020a056512130c00b004cc7af49b05sf5963321lfu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111917; cv=pass;
        d=google.com; s=arc-20160816;
        b=s59Ss9ptSv6ra08CQoQPEoAxH4gt7Gl9kO5jiXTF4y4KkcXhG+VVVeOJTrGaddNym5
         wDXIqHr9dui/EyI9YBu2Jqwju9oLaCBQHAY0qkQg2FzGmIRTZmugEzzzUCJdlo8KCyjH
         sB/du9In7CJ5B0EaTrivInWrGdkjxrmjp78GZTloPjTl3NKCvzhIhn83jXoBCD09Ze+D
         sOXP6cHFyVm/xWMxXmzl4C+08jiOPW0pHB0UwYjDRduq++q8JKkuFK78Ch7XMeIdlFpV
         oYRpz/1hQ9tOZD7rhqUltEgsOCHb/j/B0JOMKC5Jaz6iqCzEzlt4qPUFa6AQRS+h9eWL
         mmBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+54N9iG3h/fMlQNehp4znOcPXKUNpgq8sVuNVzuPgVw=;
        b=C+U91j5gWjNPSFZmWsX98caYAZz4+VaPzSsBP9gwE49za9kFXTbY+fzJDhLbST/Ger
         ZV+zRLA/2Xg+70dpr0pmhocB+l32OSmAJqpzBFEzD/ZjkbijNGBjk7PWZV9A/oJnJEbO
         JdENLhjvcLg7TK2Zh0UQ8fuiMWrvkdXmURf/yU9bv1jqOE+pxY/PJ6enme9xoaufN97N
         xtKiov3JCVeB4CbOy7eXISAIn3f0bDgshKsRbozMnvpXCv0QvM3nH8UGvQhFCsANAsqz
         W+BHz6ZP375OfybE1L0FvqjIcIigiXNR8kRWVhRo8Ycxr1xs8tQ+zoQD/4XhnX4wUK+2
         W64w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eYNx9UpT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ed as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+54N9iG3h/fMlQNehp4znOcPXKUNpgq8sVuNVzuPgVw=;
        b=p4uaNo98dbAxwI6Z0fBTmC8F7mxvoeA0eeRzh8vRUFoANbo7Au/xI5c/xhFCwRRJlw
         mgFofwJDtJPUCJc7aqu4N50Rxh4dP7/Q5+1N1ZqvGicelpWC6kA0JX6NhThhufO0La4b
         eNAWiVhprmdCKShuIZAMrtAejvhvl5MNz1grnaXhOO79MQXa0iZQy05XLWGwqUnRyYzp
         qMSfpQekW1dP5HWktBbsZa7Eu82cAUc2M+2ZUaTt/mBk3z2pXJs/OYu7e3+dhVH09AFf
         yyOxOQk6S4VL+9dHv9F5YyxGozCAlPk80rU4yDQ+AUqZC395TOHIjzxbTypxClzu5YAh
         qp/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+54N9iG3h/fMlQNehp4znOcPXKUNpgq8sVuNVzuPgVw=;
        b=ox5N3RafQaG5nt4aFtm1R33VekgKU9jLQ3DWkV6QyXgas+de3+o//KhWjZN1wLk+l9
         qGNu/tDcXGwFyuQiksxvw4+Unpy3lX056ed3CKLd4hf0P/NP0+ejn9NvYLMPfyT9qb1I
         0m7AiRMzf5vWGVadK0HQK5MaJPCBH0PVd3YN22khY6Km0w+SiSHMs6lRd+ET4IC61k6p
         WonRIEdlxoDICM1J4WPZ2VCWy+JY5ZtIZo5COfd7VIEsDF7AKVjvl/baPcOuwCbKr6Uq
         WGbJo/eHWRzyKbg3PNx9N5kfrytgf6fSX7ttjlXYvryw23s67aH1uGOcDMOt3aJnOhoD
         qbIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXb5PDImFYlejfxozr53lNe7M5sRQQNyW1clAUv/fAWlUIidfSE
	t6yZTDFQJ1BOVWQwGHy+GfU=
X-Google-Smtp-Source: AK7set8wdrqPgiC8lq0BW7m2vsRu9pRZRTgnec80aRans7t9iJfBWUx9rpyIkC6026kGcq3YsmpqaA==
X-Received: by 2002:a2e:9099:0:b0:290:6a8c:babd with SMTP id l25-20020a2e9099000000b002906a8cbabdmr540377ljg.59.1675111917014;
        Mon, 30 Jan 2023 12:51:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3116:b0:4c8:8384:83f3 with SMTP id
 n22-20020a056512311600b004c8838483f3ls766399lfb.3.-pod-prod-gmail; Mon, 30
 Jan 2023 12:51:56 -0800 (PST)
X-Received: by 2002:ac2:5229:0:b0:4b5:5dea:85ad with SMTP id i9-20020ac25229000000b004b55dea85admr11889996lfl.12.1675111915944;
        Mon, 30 Jan 2023 12:51:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111915; cv=none;
        d=google.com; s=arc-20160816;
        b=dT12G2QT2d23G4uMvuQ1cc34MJ13sCpbknNUXmtXFq7OL3EzLSSHCer4UwljZm9H0k
         3B5Ko1622JA5DYTnuqpoGkyw2uGtNRDlRlnQeonaz1Rq3mC4+8jRBWfMAIxFuY6o7PEw
         pRI2K5uR3InoajKl7L2w/ZuWBE5b8RgR/RXeRlinMV/2NG+5OBkPuDKysvOEpPROnmxc
         gc2sqGksGKUf/f8NyOG7MFVnZowXtMPD2m7CMwG5T+Q2h6g+UftanfgpEo9hAqBTheCv
         Jke+vjx2r5KVYpN8InjlM1/DsExC+38cI4GMNLBzR/zzJ5dZW1lKn10nDsHfIYCTnhaM
         3OWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RlJNrgwkJjY9MAGqUmKKlmI8AUnL0lcVfhP1HY83LkM=;
        b=Pi60T838eA4QAAxuqMYl2NYhubkmJRM4Ypa0kPhAXNUSjEunIG+/fNcJce9l5Q1v7V
         i3thyHfeWM3mB4Ehry7ceiAO2WJb5FHnQhhWkpR/b8xDoZ9SiS8L9dYHrGngjAm6xjG2
         nLVnnanj0Ll7SBgsiRWkQH4vvO9bGwxStLkc9pEvVdYqUN1ig3gsfZTe4q3WgOKmJKZg
         8J5oS5Mm6yVyGrnJiuXefcnqm49ygKA7JnO6p7U3o5fc4VLMKD9xZbfA3tdZt2ZZbWtG
         clm2pdzun4iHLOD+19kFbDbUHKvx9dKS1cLrYYMYLmVR5ZuYkg1cqsD4zyWjsJq/Ec3b
         RBjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eYNx9UpT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ed as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-237.mta0.migadu.com (out-237.mta0.migadu.com. [2001:41d0:1004:224b::ed])
        by gmr-mx.google.com with ESMTPS id i13-20020ac2522d000000b004b58f5274c1si804414lfl.1.2023.01.30.12.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ed as permitted sender) client-ip=2001:41d0:1004:224b::ed;
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
Subject: [PATCH 13/18] lib/stacktrace: drop impossible WARN_ON for depot_init_slab
Date: Mon, 30 Jan 2023 21:49:37 +0100
Message-Id: <7e7434a0d4e8a71138aec2c8a3c69a4eebf49935.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eYNx9UpT;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::ed as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

depot_init_slab has two call sites:

1. In depot_alloc_stack with a potentially NULL prealloc.
2. In __stack_depot_save with a non-NULL prealloc.

At the same time depot_init_slab can only return false when prealloc is
NULL.

As the second call site makes sure that prealloc is not NULL, the WARN_ON
there can never trigger. Thus, drop the WARN_ON and also move the prealloc
check from depot_init_slab to its first call site.

Also change the return type of depot_init_slab to void as it now always
returns true.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b946ba74fea0..d6be82a5c223 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -218,16 +218,14 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-static bool depot_init_slab(void **prealloc)
+static void depot_init_slab(void **prealloc)
 {
-	if (!*prealloc)
-		return false;
 	/*
 	 * This smp_load_acquire() pairs with smp_store_release() to
 	 * |next_slab_inited| below and in depot_alloc_stack().
 	 */
 	if (smp_load_acquire(&next_slab_inited))
-		return true;
+		return;
 	if (stack_slabs[slab_index] == NULL) {
 		stack_slabs[slab_index] = *prealloc;
 		*prealloc = NULL;
@@ -244,7 +242,6 @@ static bool depot_init_slab(void **prealloc)
 			smp_store_release(&next_slab_inited, 1);
 		}
 	}
-	return true;
 }
 
 /* Allocation of a new stack in raw storage */
@@ -271,7 +268,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		if (slab_index + 1 < DEPOT_MAX_SLABS)
 			smp_store_release(&next_slab_inited, 0);
 	}
-	depot_init_slab(prealloc);
+	if (*prealloc)
+		depot_init_slab(prealloc);
 	if (stack_slabs[slab_index] == NULL)
 		return NULL;
 
@@ -436,7 +434,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * We didn't need to store this stack trace, but let's keep
 		 * the preallocated memory for the future.
 		 */
-		WARN_ON(!depot_init_slab(&prealloc));
+		depot_init_slab(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&slab_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e7434a0d4e8a71138aec2c8a3c69a4eebf49935.1675111415.git.andreyknvl%40google.com.
