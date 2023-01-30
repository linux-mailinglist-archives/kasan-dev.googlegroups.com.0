Return-Path: <kasan-dev+bncBAABBLG34CPAMGQEL25MHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A402681BC1
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:53 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id o5-20020a05600c4fc500b003db0b3230efsf10127954wmq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111853; cv=pass;
        d=google.com; s=arc-20160816;
        b=msk+mBUMIQqnjYEU6n73QD8W8nuzkp7lHPsI18LuPwQcaPQySRY6ODZ3fH8xrZv5yA
         Ksj+Ws88jYRtmOtf2LcFdbnYXw6LySd+KtduZERVjjlE3T00pNS4LGxPhpVegleCP5/1
         4PTHoEZzVyq0+dOX7yd0m9hA6uBmnmQg85j8hXCIbQZPeDTz9vdEgvQkMehaTF2cZb4t
         dAg02Up5sYjIhbge2/6Vq3mrmIeXd5I4FXC3nYwNK7V6F++/MRQHMf1m8//x0F8wW9dk
         vNCm4Trp3dAcfBwd0ZBDNRfQ5mWCXRU10MQfsLptFAyzz0Ci59bk07M2W9UMRQKTV8uD
         +gyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KeWD7XZRb/m5zw+wF2Xt7Tesm8se1M4VQsxXIxhaNSQ=;
        b=TTtEkqF1TcAlrfmKSd1geVjENnPXRXoBB4mX2lghANzt3ggiYVXuY7lwpRhcxdJKQm
         pcyvgcbvoP1XyJcjSXwFG9fDV9QK40egLZAI31sQ1RbcV1gpeTcsy9Lkb4uf0ljh3u3h
         9KR8n0zfzFtN2C5DpZwIundF298l7OJfMKyBYzXe4AoOTDbhkRnuEABtU8FK1k6VwdD5
         DUhl+HMdTpsXOm6kMarzaKbSW28Um0rUtAzW0lu6yi1x354EOu5umjmFQn2/9QF0RETt
         edDUhJpJBOXdu2bzubBRasrLnh7cNR267mtRIXNrzkth7Y6JvYojwQ5llUN98cv5EuPO
         xDQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OaUFrjC9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KeWD7XZRb/m5zw+wF2Xt7Tesm8se1M4VQsxXIxhaNSQ=;
        b=Iisbz1flIwk8Mn/gqcO5zJCun+eKd+M3Eccp9byyZC2GeyKj21QnRrnBMyzUWTape4
         W0fPfy0e0gZfEG0lPsw8Xk7PMPW+Nh18J+I/XpoSJLwO3kGTid35GLAyusG49cCBz6iT
         jK+y+DFfNtphc3VGT4ObfMUocDcwh5ZmWkCnqJ5PwrvIqypeFppaZLixN4cFatx3+SaD
         z6jXZboLVx/7dS+oxCyPNL1hUGoGX6JvftS8WUzAe3eYPnVIJqibDjdv5JKyQvNHyn45
         3Q4NTL51LopiqPS83evC8k0ZoJPSZaFmp6u5WipiqEGeCTi20+uWEYtlEK3jPdjv3KFj
         LEDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KeWD7XZRb/m5zw+wF2Xt7Tesm8se1M4VQsxXIxhaNSQ=;
        b=DJAe0nSkK8zec6sMF31knMsHLX+z5/zvg5CTaqq7dVTcC59irgRimTy+27+egc2DjO
         SYf2iqLLftfbCTf+x2z/kaCdpuDMZbLoQmFj7ieq1s4m3kTvLYztoaQhuIWqiEvYLHms
         /uY1+WM2vvS+a0uva2LYtwg8PAVMfnyCgLJWq43afuJ5JkkAYwEp2tlyT9xna+cle8Gz
         CjiJziRK2oyay1maidSZt5jG7TafRsLbVM+QbYR//9HR5gZS/E8xMs/ZqaeNl21oq1f9
         mPw6iqhcA/qnkOrPeezWFGaykiSJ0tM3IBnwaZh25ai5cdxAaHiizMmYKwJ1grHQM8tq
         hNxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koIJzpp3T7QLS4WOLy+Hk3v+JkPRwGUAMru36sIvvCc6V6nrwMs
	+N3k3vfBrmU9+YCAsrAe8Gs=
X-Google-Smtp-Source: AMrXdXudkb4P1MtVjEn/Jy2MUr05FyGCxsgW1xAhPeVsdXr45O//cL2sui/tPAevW899Van89PjtOg==
X-Received: by 2002:adf:ed12:0:b0:2be:13ad:ba3a with SMTP id a18-20020adfed12000000b002be13adba3amr2610127wro.316.1675111852991;
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3509:b0:3cf:72dc:df8 with SMTP id
 h9-20020a05600c350900b003cf72dc0df8ls3367395wmq.0.-pod-canary-gmail; Mon, 30
 Jan 2023 12:50:52 -0800 (PST)
X-Received: by 2002:a05:600c:4e51:b0:3dc:9ecc:22a with SMTP id e17-20020a05600c4e5100b003dc9ecc022amr2994958wmq.8.1675111852102;
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111852; cv=none;
        d=google.com; s=arc-20160816;
        b=AIBsm65ig4BYUahUwJTCngOHQygn17/CAQh/s6LgWeeBnYW3HZJaY3y1wpkFa8S7Ft
         2EQGit0fgEPIy3OTHdkXs6NUo3NggVBeNJwwPA2HHDJJ349KIBcUqJH+5TY7fO7GCDOa
         DStzB+PqGRk9DMejpEOZ2r2nLK/sG6xMpS6uiGORPL3Dmx0PscA24ZJRXB9M+avCnSsw
         BXUJPNWXfmog5G+AhvBido8q2hndf0fpOckbHM//pzxsAETZ5n0AFGg1/NG8AYw/XeGc
         S1jUtxt3eXxCaUL8JEFSic5+z81g65Yu2aJeXEbHT704mEUYM4jkm+7T9/e0xSWivB56
         oiIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tjOybIkwS91rz6SeT9/1Q1LG8Upe4qgP6MFeV739ipg=;
        b=rDguts1EH4Yc0GQ+fJtnDav/thuEJlzQZWza6zNXxXYuqDi1MKUjlSxbcuyRZKMVBC
         13ehGhKvvohmtrbbc3wBeD4S+sLa8KUfucy+bhNiqIvBUdkaRVz4VissHPX55AojNT7n
         4HUYlM4pfXf1HJptjcZroSkTaOskVP8hMF6kO0b5eVvhl4E5wfbJNZsyMvWYxgaUvz+f
         KpWXVUe5bzfPMmzDBY0qoItQxllv5oMXeiBO0zk7d0NHv/KJvTKL95zWEb+4fsUXz8k3
         vU1xZY666PYQk0JApKohPlduQROFyD3JCu5rkfB1w+2o0eTe6O2uLomIg+fO1IJ8iywv
         e96Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OaUFrjC9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-224.mta0.migadu.com (out-224.mta0.migadu.com. [2001:41d0:1004:224b::e0])
        by gmr-mx.google.com with ESMTPS id o41-20020a05600c512900b003d9dfe01039si1174564wms.4.2023.01.30.12.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) client-ip=2001:41d0:1004:224b::e0;
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
Subject: [PATCH 07/18] lib/stackdepot: lower the indentation in stack_depot_init
Date: Mon, 30 Jan 2023 21:49:31 +0100
Message-Id: <eb6f0a014b8d0bfa73a8bbd358c627dc66cf51b7.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OaUFrjC9;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::e0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 70 +++++++++++++++++++++++++-----------------------
 1 file changed, 37 insertions(+), 33 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b06f6a5caa83..cb098bc99286 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eb6f0a014b8d0bfa73a8bbd358c627dc66cf51b7.1675111415.git.andreyknvl%40google.com.
