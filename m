Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBJ4YYKKQMGQEFZQZDPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 02E68551F9F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 17:03:05 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id br5-20020a056512400500b00479a5157134sf5566292lfb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 08:03:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655737384; cv=pass;
        d=google.com; s=arc-20160816;
        b=dDI/PKs7NPe1dXzpu0ZPZtArxGLtZHYcWwmWcdUOiGSz7EiSJzps3R3SUEgGvWMq40
         H4TX47K/LCjB8tZ2N2tU0w1IsGDnvRi4aRts54qutzu9922AMCBI/5L5EIjro/HPuVYx
         pPWCMJChgXibfEnKf2khcsGqoqNIMMnzykIXh3BhV7EvsdqYOFju+mIoDl48H1xNVO3U
         ZvIdN97+GzSAs32AzldU8HUn5/bHa880BQQ3qri4w2C0IZ7uyv+McoefqHPQEOtubCsR
         fUGS5MNBtJR5Ulkzf7evbcciQjdNx1+Ej8v0JYXX2yoCBP3Z0Wxq9TtJwqmVXFSDPAoL
         lZpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o1f6O864tfBPuEQQXdghRhFPq95vSxIbqxzuuBmw5ts=;
        b=PHu4BVRfe1DWcUOrLsg+sLwDoelmZEtZ7V7rd1HOyKytMy7kEoQIPkQN2C13G/rUqd
         qfa9dgm6r5HPDnhJOR1HP7Lblm3G526++At5kNN6L/upJbR8gf+y3XBM611vXg8/tQSG
         nVFGziGQgZ3rT1re9ZI9WQFrDGQYs5ZguXYOaoDbnoaE83eVpDH1Tycc/Jrr4nkF+rH7
         iYgfBhDvIDQQRzVeLvXVPBevA2rO6F/K42Sjv7ASYayDQck40WVsJ28LiFSV/q3tz8iu
         Ho6D24y/LYpxJyQ1q8IkVqGW9/1tkxzt5fFH15kcMspWg43d/FqziRcD7ergq7eU2aRY
         OF1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jOSWh3cS;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o1f6O864tfBPuEQQXdghRhFPq95vSxIbqxzuuBmw5ts=;
        b=r3Uqycw35gJA6GEAUHwbmY6WSpaz/pqC5cGLUCMoVruOKY7SeC0uqQf+/CO/e3bxx0
         ZjIyZxURp4c6MORfOYHZAyp52mN35jVYttfml1VBOnpTkXtpTFNGkub4nIbmN+dS5oSO
         PvNbacpLEe756YHcmDSIo1+HhRV4h619eMg2WHBCu7d7SZRrFaknvcYPgleGPVaWqLeG
         5TrVns/WI/oWFQNIYZfH/yPiMiyQbJGoJVmhzv6yA8qGVa4+YcCxlAc36XW0NGEvTGWw
         XLUow7Ld/7IGbjGDPMOF4BEnzqGwUClyF/akWfMyzZakIQA1AkdDds8dtGpuEihpcZXD
         QEUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o1f6O864tfBPuEQQXdghRhFPq95vSxIbqxzuuBmw5ts=;
        b=lrvtn8q864ciiNTQqMyC3bmRQTISWsDXX08kEayef6nEtoQRgZhUMKrVvbtTJYV2Gw
         8N2kownDbTw83sbQXdAIUUL1ZAesn8UWAD0QEdPJs5jML1QDKoWUz/tEsxDhKxz5wV1v
         p/QpWjgWRBNtNM4AOIWrYcXYot+hrxB27k/eS4dD1J1Q0ylKmEylr656+4EF8Xhd90gO
         acj8o2DWV4NkZ+KjIx5ha6Ys67zxOJ0MkQpNPeBMeFB78NkySHelbvyXn34ylJzzVRtx
         kTDwJV1Eee8cLGlQGvCQIQrLHaI/omDCWJKFRKSfcUiA/HWpfxXllxtFGsqZ4yNu8pNg
         gSYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9V4KslIoScOlcvhACD8uuZgLD0BlVd1RQAV8xeq6pD2YxiE/il
	GJDt35eoJ+9gKKBWSlIYovE=
X-Google-Smtp-Source: AGRyM1tu6hKPgOQLwPv6Kb8G9ckD8E2Y5DMWKu6WsRMwUykreoS9SCX3XpXAeLNLA5Ouh/a2UTRR0A==
X-Received: by 2002:ac2:4f11:0:b0:479:3554:79d with SMTP id k17-20020ac24f11000000b004793554079dmr13771835lfr.417.1655737384256;
        Mon, 20 Jun 2022 08:03:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als385811lfa.2.gmail; Mon, 20 Jun 2022
 08:03:02 -0700 (PDT)
X-Received: by 2002:a05:6512:2614:b0:47d:c632:896b with SMTP id bt20-20020a056512261400b0047dc632896bmr13753822lfb.532.1655737382731;
        Mon, 20 Jun 2022 08:03:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655737382; cv=none;
        d=google.com; s=arc-20160816;
        b=uo9mlBtfq0kbPM57COFPiRn4x5NJk9l7n682cGuXFIHyPk076SCoF0BnHAnj8w+jvc
         K1tLzvglPMCPY8Ukyv5lGbUZmIT51NJeQevsD/mX9Pb0Sz8nJ6TSQ+k9s+kcA+d17Cel
         mEiHay3KWMCYphtgMCaqKnRChhCH6NTKWgJowpgnAOAva4lEprBNxROAdY8afOLcIDY8
         ehzavxdHnxRSFinu0fps+f91+Swv/8Y0u4wWuUT8UxL/6m/GH6yqKYJyLOEHVo1V/7KE
         t/WnpxwGVPRbG9elLZgtvcgDSGNOfbmLRHF2vb/rdkkz0ZPq/29sT0pwTKJaDMLHZ3zT
         elvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=t6itNPFCM/lnavaNprI7q2GJhGFOOJ4FXVt/3QTMdTs=;
        b=wc8nA8fxtk8/VAFmn8ZccVQq8EvDGbDU+GbNj+Onw1EjNpKoCYAgOSoZ/zk6GRQX4j
         9w25Y3HEXs9UyRRV3+8iVEGfjURqB9+H4CoLZvEYYtdQZxp0hbDJGeTOlerWihhKr+g1
         247bknotpT3GPu9zvQn/hDKH8Ewxr/0P3czLitY51pWBH03QSfJ/e+yod+v0Wq/FTNlG
         gvmRD3x/yRuD389PphMFoVlMxvIXKt3vrd/i4OnzQHVHLgJVDlQ7NWyqtiW0K7S/+yFj
         VKdl9BOPX4QuHprq37w6C9xtPkRqB0flsLlQ5mDp8KRSwEFwAgDtJ9YgUeR4S9JurbaR
         95iA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jOSWh3cS;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id x13-20020a2ea7cd000000b0025a71229262si102293ljp.3.2022.06.20.08.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jun 2022 08:03:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 110EB21B79;
	Mon, 20 Jun 2022 15:03:01 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DE54F13638;
	Mon, 20 Jun 2022 15:03:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id M0+9NSSMsGIucAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Jun 2022 15:03:00 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER with automatic sizing
Date: Mon, 20 Jun 2022 17:02:49 +0200
Message-Id: <20220620150249.16814-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.36.1
In-Reply-To: <20220527113706.24870-1-vbabka@suse.cz>
References: <20220527113706.24870-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jOSWh3cS;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

As Linus explained [1], setting the stackdepot hash table size as a
config option is suboptimal, especially as stackdepot becomes a
dependency of less "expert" subsystems than initially (e.g. DRM,
networking, SLUB_DEBUG):

: (a) it introduces a new compile-time question that isn't sane to ask
: a regular user, but is now exposed to regular users.

: (b) this by default uses 1MB of memory for a feature that didn't in
: the past, so now if you have small machines you need to make sure you
: make a special kernel config for them.

Ideally we would employ rhashtable for fully automatic resizing, which
should be feasible for many of the new users, but problematic for the
original users with restricted context that call __stack_depot_save()
with can_alloc == false, i.e. KASAN.

However we can easily remove the config option and scale the hash table
automatically with system memory. The STACK_HASH_MASK constant becomes
stack_hash_mask variable and is used only in one mask operation, so the
overhead should be negligible to none. For early allocation we can
employ the existing alloc_large_system_hash() function and perform
similar scaling for the late allocation.

The existing limits of the config option (between 4k and 1M buckets)
are preserved, and scaling factor is set to one bucket per 16kB memory
so on 64bit the max 1M buckets (8MB memory) is achieved with 16GB
system, while a 1GB system will use 512kB.

Because KASAN is reported to need the maximum number of buckets even
with smaller amounts of memory [2], set it as such when kasan_enabled().

If needed, the automatic scaling could be complemented with a boot-time
kernel parameter, but it feels pointless to add it without a specific
use case.

[1] https://lore.kernel.org/all/CAHk-=wjC5nS+fnf6EzRD9yQRJApAhxx7gRB87ZV+pAWo9oVrTg@mail.gmail.com/
[2] https://lore.kernel.org/all/CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com/

Reported-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 lib/Kconfig      |  9 --------
 lib/stackdepot.c | 59 ++++++++++++++++++++++++++++++++++++++++--------
 2 files changed, 49 insertions(+), 19 deletions(-)

diff --git a/lib/Kconfig b/lib/Kconfig
index eaaad4d85bf2..986ea474836c 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -685,15 +685,6 @@ config STACKDEPOT_ALWAYS_INIT
 	bool
 	select STACKDEPOT
 
-config STACK_HASH_ORDER
-	int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
-	range 12 20
-	default 20
-	depends on STACKDEPOT
-	help
-	 Select the hash size as a power of 2 for the stackdepot hash table.
-	 Choose a lower value to reduce the memory impact.
-
 config REF_TRACKER
 	bool
 	depends on STACKTRACE_SUPPORT
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5ca0d086ef4a..e73fda23388d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -32,6 +32,7 @@
 #include <linux/string.h>
 #include <linux/types.h>
 #include <linux/memblock.h>
+#include <linux/kasan-enabled.h>
 
 #define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
 
@@ -145,10 +146,16 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	return stack;
 }
 
-#define STACK_HASH_SIZE (1L << CONFIG_STACK_HASH_ORDER)
-#define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
+/* one hash table bucket entry per 16kB of memory */
+#define STACK_HASH_SCALE	14
+/* limited between 4k and 1M buckets */
+#define STACK_HASH_ORDER_MIN	12
+#define STACK_HASH_ORDER_MAX	20
 #define STACK_HASH_SEED 0x9747b28c
 
+static unsigned int stack_hash_order;
+static unsigned int stack_hash_mask;
+
 static bool stack_depot_disable;
 static struct stack_record **stack_table;
 
@@ -175,7 +182,7 @@ void __init stack_depot_want_early_init(void)
 
 int __init stack_depot_early_init(void)
 {
-	size_t size;
+	unsigned long entries = 0;
 
 	/* This is supposed to be called only once, from mm_init() */
 	if (WARN_ON(__stack_depot_early_init_passed))
@@ -183,13 +190,23 @@ int __init stack_depot_early_init(void)
 
 	__stack_depot_early_init_passed = true;
 
+	if (kasan_enabled() && !stack_hash_order)
+		stack_hash_order = STACK_HASH_ORDER_MAX;
+
 	if (!__stack_depot_want_early_init || stack_depot_disable)
 		return 0;
 
-	size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
-	pr_info("Stack Depot early init allocating hash table with memblock_alloc, %zu bytes\n",
-		size);
-	stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
+	if (stack_hash_order)
+		entries = 1UL <<  stack_hash_order;
+	stack_table = alloc_large_system_hash("stackdepot",
+						sizeof(struct stack_record *),
+						entries,
+						STACK_HASH_SCALE,
+						HASH_EARLY | HASH_ZERO,
+						NULL,
+						&stack_hash_mask,
+						1UL << STACK_HASH_ORDER_MIN,
+						1UL << STACK_HASH_ORDER_MAX);
 
 	if (!stack_table) {
 		pr_err("Stack Depot hash table allocation failed, disabling\n");
@@ -207,13 +224,35 @@ int stack_depot_init(void)
 
 	mutex_lock(&stack_depot_init_mutex);
 	if (!stack_depot_disable && !stack_table) {
-		pr_info("Stack Depot allocating hash table with kvcalloc\n");
-		stack_table = kvcalloc(STACK_HASH_SIZE, sizeof(struct stack_record *), GFP_KERNEL);
+		unsigned long entries;
+		int scale = STACK_HASH_SCALE;
+
+		if (stack_hash_order) {
+			entries = 1UL << stack_hash_order;
+		} else {
+			entries = nr_free_buffer_pages();
+			entries = roundup_pow_of_two(entries);
+
+			if (scale > PAGE_SHIFT)
+				entries >>= (scale - PAGE_SHIFT);
+			else
+				entries <<= (PAGE_SHIFT - scale);
+		}
+
+		if (entries < 1UL << STACK_HASH_ORDER_MIN)
+			entries = 1UL << STACK_HASH_ORDER_MIN;
+		if (entries > 1UL << STACK_HASH_ORDER_MAX)
+			entries = 1UL << STACK_HASH_ORDER_MAX;
+
+		pr_info("Stack Depot allocating hash table of %lu entries with kvcalloc\n",
+				entries);
+		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
 		if (!stack_table) {
 			pr_err("Stack Depot hash table allocation failed, disabling\n");
 			stack_depot_disable = true;
 			ret = -ENOMEM;
 		}
+		stack_hash_mask = entries - 1;
 	}
 	mutex_unlock(&stack_depot_init_mutex);
 	return ret;
@@ -386,7 +425,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto fast_exit;
 
 	hash = hash_stack(entries, nr_entries);
-	bucket = &stack_table[hash & STACK_HASH_MASK];
+	bucket = &stack_table[hash & stack_hash_mask];
 
 	/*
 	 * Fast path: look the stack trace up without locking.
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220620150249.16814-1-vbabka%40suse.cz.
