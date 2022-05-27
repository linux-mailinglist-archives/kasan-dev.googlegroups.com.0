Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB6HPYKKAMGQEUZB4MTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 65F9B535F5A
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 13:37:29 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id m19-20020a05600c4f5300b003974eba88c0sf2559400wmq.9
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653651449; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/1wQcq42s1QvrTIdIwm7KGmB9j2Ea3ZSA19N7Tq1JcjoojjrrMsmi+eWCGfz327/s
         GrEdERJJdDshDGg7oFx+om7tbaXpEAoheifjU3eBlpqWTQjiv1zmn4rJaGz0KQPFFyWP
         EcEY5Da94o7kr/9svVAaOfpV55dUdPOgz0K74gw/wF+C41yJMzO6v8iiQygkIwpQ+hwg
         +pTs3MQ6X3+GBW6DSd0ZDOD6+3Bsq25dcL9rIS3l3YvEpBdic5Iodj0GzOo8WFSh+dp5
         R+lbobjbb68H6a8wp4rnxnCaO0eooV08rQhI6X6jSpTX1FgpbiWwtdqyzJAC6VNupPbW
         dvuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I3c+aH06Ir4gm5YLQ6yEGErVGFe+OS9FimjDdzKoHGo=;
        b=xvl85bbeyE94O83XUGfyOub6oFIFdgTari20amgu842fwQ853tA+14FyOw1CVqp1GG
         rObYhOT8wzu3DgT2ez2Tzs1of5FkPPi5MAbYSNkv30vV474EdrPF+z8XZGwSpD77v0VT
         w4aJL2RPXmrQ+GVpaIUJIPeM65oAdANeMmwAP8rQq77DSwj3KWqhqEZdtXs1iRko/a7H
         Db0EBueiYd3fxQfwtK/Gedv8mJ9wOYUVHQHd8KcR859GTvZ3PXqCwdU5QRxS0QCOsEhj
         jlOm2LHRNL5bsFvDcC+bTIuIVB1x+pueCkvRFp2F1Zk7xRZXtM3A++1UPYWXYlzKt0Wc
         9GXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="AmN+/hYV";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3c+aH06Ir4gm5YLQ6yEGErVGFe+OS9FimjDdzKoHGo=;
        b=iIRdZiKUVH6w5be+R+sPnJh4ytYm9WAKrsfQ/Y7LCTY+HmVhYUERluCxeFE7O7mSzr
         Jn6L85Y3xVrlXt4nlrZSqFrsAcx2tS9NlSof72rsBxH4Ux/pfmjWlAG0g+qwqbb/9hVp
         mGGtGsYFHrW1kINbh4eDrERjOH0XfdPdACv+ZHdB8wZES4e5YWa6UDaLX0JPZm+0vKIp
         DnfO2z2QBfcns/oGPamxpXL9XnF4izLNV4hpMBJkXnyH/Ra6tyx8W5RNijmGRXCUdkvn
         QjT9KKEVivHYsezL1AIs3I+r8NJtdHpHqvVmSQskZ6fK1UJ3JVW6kI1/GOyAYJLQ5E8k
         vc1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3c+aH06Ir4gm5YLQ6yEGErVGFe+OS9FimjDdzKoHGo=;
        b=B3xhXvZ4LThhFpo1zaNLDUodm87NTnjB2LIwIp5HmGUIr1w0INPpej5OqJf1oHtwtS
         EhxWEoidZElvAXEnUCyUAfzpBBjpTMNz3ilp08HrVnnl4RheAWv45oA2L9h3M0nWZPAT
         I73yeKLfCUWo1+w/rRH9mAfgswu1tFapazhFARP74ZV8GFQ7vnPkewL9aESyt72AFih3
         mZmAmKKoCIy+ruKbW6uHL7BYpGTBLcom6drHcVBYxiG1AWqIG1zvcd+9KA9bApOXpYlK
         0h1PO0zsiSG7mGFP1ewdj+GmZii6JM5sRnHdgFi6iCWTtRDuibvQKl5ioIs6tcAwhXev
         FcdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jfS4PT8/Qq1eAieBAiasbO+VZ+TTf1zAA2n2oTDiImmrWaVCr
	4AVP2+yGBUqXkHA4E2y59QY=
X-Google-Smtp-Source: ABdhPJzpWw4hdflq8JS6txQ/dHSxL9vRVkBkmu208biu5DiLFUzYToM1UP4PW9d0qDkHXJ0nRsiL6A==
X-Received: by 2002:adf:f889:0:b0:210:178b:8532 with SMTP id u9-20020adff889000000b00210178b8532mr2528991wrp.549.1653651449098;
        Fri, 27 May 2022 04:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9c:b0:393:ef44:c49d with SMTP id
 bg28-20020a05600c3c9c00b00393ef44c49dls5834009wmb.2.canary-gmail; Fri, 27 May
 2022 04:37:27 -0700 (PDT)
X-Received: by 2002:a7b:c5c6:0:b0:397:8a39:37b with SMTP id n6-20020a7bc5c6000000b003978a39037bmr2558909wmk.182.1653651447655;
        Fri, 27 May 2022 04:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653651447; cv=none;
        d=google.com; s=arc-20160816;
        b=K59p54pho9ivsJ7URMF2cJpQzxFqXPddcC8rphsearZxUk4eKY475v4oCHhaJ1Xlo6
         OE4AI2SiP6OQKxayhW5QbzQjFaW/Qyy6pNy82lgIUyXdtZeWRjxZqR3r/PXDS+I2wB1o
         9FrNrMI0Sop8hDJClNwvy/E6lZ/p6hczqBRjiVQMkOjhHliRpUT85WCMDDCHdzzuygNm
         kb1xkD5m1vXOd4Yv0aJZEmix2lqwHac0L1yCoimtKTIAuUA5SpBA+garqTHXcySpFJvB
         fXcfnanBME8gA+7XvX7mtj0NFGzmCCpHuQRpysqVWMgKf0cYr57gmCvpvFagkWuK2/I+
         EzCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=kXusmkwxceHRkiBRNvi2J/m0PO64GWg/sAaKBfj8UU8=;
        b=Xo5bkgOqNp8Vylw+yBUI7pUtivZFSIHITAgLhZXtgkD2A4gJCQ8m49+Ea5AsPC3Czg
         lanUXp9g6I9JaRf3DlgdyvW3gJF3tAmQbsTf4iCdpxEEMidOdfb8K6bPIPGtqF1MKKXq
         k0Vtvv1u0xIG72v22K5Ca38JA0T7Ih8FYF0bGbFYnxUejUZfsrA2PjyUgtQMuvbEod3K
         m21emyxcbU8qoCW8O/6zYBumqF47C07IC7q0snetPD05D2/7xBekssp318SM0RoqQ9jD
         lH/DqsURRHURHA7CTHxggTC5i1aP2S8rhrHuwMqqROYJHXURCJBkMegGXT/iojDxgINs
         OtUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="AmN+/hYV";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id g13-20020a05600c4ecd00b00396f5233248si655258wmq.0.2022.05.27.04.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 04:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6B825219BA;
	Fri, 27 May 2022 11:37:27 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4F72913AE3;
	Fri, 27 May 2022 11:37:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id GEvpEve3kGKQDgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 27 May 2022 11:37:27 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [RFC PATCH 1/1] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER with automatic sizing
Date: Fri, 27 May 2022 13:37:06 +0200
Message-Id: <20220527113706.24870-2-vbabka@suse.cz>
X-Mailer: git-send-email 2.36.1
In-Reply-To: <20220527113706.24870-1-vbabka@suse.cz>
References: <20220527113706.24870-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="AmN+/hYV";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
dependency of less specialized subsystems than initially (e.g. DRM,
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

If needed, the automatic scaling could be complemented with a boot-time
kernel parameter, but it feels pointless to add it without a specific
use case.

[1] https://lore.kernel.org/all/CAHk-=wjC5nS+fnf6EzRD9yQRJApAhxx7gRB87ZV+pAWo9oVrTg@mail.gmail.com/

Reported-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 lib/Kconfig      |  9 ---------
 lib/stackdepot.c | 47 ++++++++++++++++++++++++++++++++++++-----------
 2 files changed, 36 insertions(+), 20 deletions(-)

diff --git a/lib/Kconfig b/lib/Kconfig
index 6a843639814f..1e7cf7c76ae6 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -682,15 +682,6 @@ config STACKDEPOT_ALWAYS_INIT
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
index 5ca0d086ef4a..f7b73ddfca77 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -145,10 +145,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
 
+static unsigned int stack_hash_mask;
+
 static bool stack_depot_disable;
 static struct stack_record **stack_table;
 
@@ -175,8 +180,6 @@ void __init stack_depot_want_early_init(void)
 
 int __init stack_depot_early_init(void)
 {
-	size_t size;
-
 	/* This is supposed to be called only once, from mm_init() */
 	if (WARN_ON(__stack_depot_early_init_passed))
 		return 0;
@@ -186,10 +189,15 @@ int __init stack_depot_early_init(void)
 	if (!__stack_depot_want_early_init || stack_depot_disable)
 		return 0;
 
-	size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
-	pr_info("Stack Depot early init allocating hash table with memblock_alloc, %zu bytes\n",
-		size);
-	stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
+	stack_table = alloc_large_system_hash("stackdepot",
+						sizeof(struct stack_record *),
+						0,
+						STACK_HASH_SCALE,
+						HASH_EARLY | HASH_ZERO,
+						NULL,
+						&stack_hash_mask,
+						1UL << STACK_HASH_ORDER_MIN,
+						1UL << STACK_HASH_ORDER_MAX);
 
 	if (!stack_table) {
 		pr_err("Stack Depot hash table allocation failed, disabling\n");
@@ -207,13 +215,30 @@ int stack_depot_init(void)
 
 	mutex_lock(&stack_depot_init_mutex);
 	if (!stack_depot_disable && !stack_table) {
-		pr_info("Stack Depot allocating hash table with kvcalloc\n");
-		stack_table = kvcalloc(STACK_HASH_SIZE, sizeof(struct stack_record *), GFP_KERNEL);
+		unsigned long entries;
+
+		entries = nr_free_buffer_pages();
+		entries = roundup_pow_of_two(entries);
+
+		if (STACK_HASH_SCALE > PAGE_SHIFT)
+			entries >>= (STACK_HASH_SCALE - PAGE_SHIFT);
+		else
+			entries <<= (PAGE_SHIFT - STACK_HASH_SCALE);
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
@@ -386,7 +411,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527113706.24870-2-vbabka%40suse.cz.
