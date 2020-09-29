Return-Path: <kasan-dev+bncBCS37NMQ3YHBBEX5ZX5QKGQELB3GWVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CA02B27D5DC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:36:02 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id m25sf2190267wmi.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:36:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404562; cv=pass;
        d=google.com; s=arc-20160816;
        b=fmS0u5n4CFwqDC9fU9hi1kZK6Eyzz13aMvrDHQaPXgaWb2hyRZ6ZXFx4DG3BRM2LkW
         yUC4iJxZYAjcSTEgU3k1kYY0ja545gAyEqmcIZs9MxbshxuuLSiq6sewNHLC/xIDvbbd
         tei9KRw/JZmo+ZhMFhEQblyZZ0wzK83+5IhI00DzAT1VQiihOhi2ehTUjeVGH4c7Ojrb
         glJZW6b9bZnZ8xHHmliXA3R5yjIxVzua8p3ffAggrEtCzQqrtGgC5O7IMicp5sgar8HR
         EaGF+rpoPvujECNHngScd7IMAU0AeFMEt8gnUABIm0lwH6G+XEKBr6WrAcTeu14xucAL
         dQ7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+tnnNYFkAPsBF/BO5js+JqffMD0r5qemsPWXjS7oBJg=;
        b=z0U5IGBjAt43HMYTEpNdyb7NorFm2iFkp/bt35AP0Sr30bVP3z/7jBhrZnsZGh8Ize
         wFd1zrtYUsRtjiXfHsaNKNSVQX63FIY28aU7MLrNAxpA+X5aZtdqesjHHlYkbTa16a8V
         xPyal0uwgZ54YZl5jJZhjAwUQ4Ao2QB6OX7duHPUUs0anU5dajK37SFrK3L7/hW9pVYn
         I7tbXTUcRX+sW+DH8Hv7dRTV1O79sUwiptZmYVPJk98CshwI3foFsgB4ogxuFUZiPCDG
         o2uscnTW2JzA5z1GfonB2kVt4RmWwViZJbJ2H3V9xOpUMTbFK/u5cM2PNhiIX4NbW0ii
         U6GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tnnNYFkAPsBF/BO5js+JqffMD0r5qemsPWXjS7oBJg=;
        b=ZRQ3YxNzwgDAqvDQsjgZAevsH5QV1CEWJN3Kkae7x9wElnWu0pO1cpAzg/kYdMB5zK
         sH38ZaGnhujYnmP5FY6X8p1SttSk4XVQg8yIH9D/EbssgHCSg4PCwbfMhNlRbeP1iCoZ
         Lt2dfUPgtkFhtXy5K4AG1vtE76bfGD2Arap0kysCOxJYXjWYowj3iZ4u4pxhCYA8W7tf
         ugQTNfd+dIEpsaWYrBnxwg8IHaKnv6xG7Gr5dccKe2duOBCT/DHovZQfUcnM/kZN1Pwx
         cRRKDihtW467l1tpAr9JnxfJRnRm6bU2O1/On9GCx7azqodtcFcA9rX2ooHqDcfjDBiq
         bixQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tnnNYFkAPsBF/BO5js+JqffMD0r5qemsPWXjS7oBJg=;
        b=X7C0W4TjfjXaJuVyrtpPIE0OQf7K0+shTNXyTKNpRGLlna1lKqHd8Xcuh41PrRgQ7r
         EFE2F2pG87DJSaq07H+ZfRakJHdarYe4kkdqyuIRz1js0u2RssTdcTTG5TJ/e4zJmJ+6
         sqFzXk6MCLuhfhQ0sSKHIL49AVK3sdCiOsfACw6pqdX26F+4ctxdUi9/tfxgre51CD06
         gIxZO/9c8V2ueRih/4f1y7AAAK//sGsykhm3EeRmFGJXtkeISRwZLb/GjqSEcx1k4Pae
         sHCtfBrXUGdSv0/+qPJMR3CtuEjziz6CGPxm574AXNHhYrp50oi/ed66kqxUxGbqZ4eg
         wdCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533muY62u84BvO8d6+qsZW7v79IHw6aBToiG3rYnfJDJubwBRQDk
	NG9mBY2KJOWFsI3H+bdMII0=
X-Google-Smtp-Source: ABdhPJxFAq9N8YXpuvF403yDipJ4Xch3WDrtPqtLBvLXl7YKHbmOISUAUMUN3bdmMqjLYXVR5TaNqg==
X-Received: by 2002:a5d:44cc:: with SMTP id z12mr5980870wrr.189.1601404562511;
        Tue, 29 Sep 2020 11:36:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls1190457wmi.3.gmail; Tue, 29 Sep
 2020 11:36:01 -0700 (PDT)
X-Received: by 2002:a1c:f715:: with SMTP id v21mr6393744wmh.117.1601404561697;
        Tue, 29 Sep 2020 11:36:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404561; cv=none;
        d=google.com; s=arc-20160816;
        b=uv0erfHlktNNOK4j3e/Xh8K3QnoJGOmzEBJmVrglBf+2I+XyKU1bQpBg/FcMy0J9zD
         AJ3YkEKako8Gk1mk0FNYOUHz+uREIK8Ja+CAHJamj7ZjCIN1FoOO0P6K10yVyW7tf4R+
         gkvr/MPKoPiBfmGdkKwnxmWGfW5JV/ZNOHMESyT14anHoB6AgWTEfeQZvOkDKSXNbRwt
         C0dCZldZ65g/O4GxhYUYHahHz/i6NXXyXcLtuLKIbYCdC/RoGfIdyxujdVD/gXxB06Hc
         lVCsCxWjNuUQwlktIGC34msHHJuaw4Bn8Vsqcg13bigFQH6dpNkRePe6OowY0pI0Ezbw
         q0mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1AriX1I1xNfjnxfNSmAKzK7wEz9F3HLx249hrusGBIU=;
        b=GvdxpsKJzGx9qDkX5rGM1Fzx8W6ZT431X4TO5BsN7dbG4VCN8ncuiHOiyIJGXTbr4E
         ag1o+/FvR/6/s108yMoOZNo9rPxqGwCyO4T2K+Fr45vXoI1Ek6SmumffbfFXntmyUUOg
         D6BN2Fl3BDrAcaiejtJclAJJbxrxBsHn18Tww7dzObcmAQKJmQqHJJ6F6YH86i8fsyhm
         BFmaiMwTd9Ue9Ag1uRGYiiwwKy9Mt+5hHOStWkNTk2Y8jfH1tPUJVRj5qlLGpW1vX8D0
         B6X3gqRmAISNEKTIpatMn6Ur56wcPs1Et/PoD1wD5bJdnFpwYcOtp65eG3MnHfH5io4R
         mPqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f68.google.com (mail-wm1-f68.google.com. [209.85.128.68])
        by gmr-mx.google.com with ESMTPS id d19si131566wmd.0.2020.09.29.11.36.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:36:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) client-ip=209.85.128.68;
Received: by mail-wm1-f68.google.com with SMTP id l15so7221032wmh.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:36:01 -0700 (PDT)
X-Received: by 2002:a1c:6a08:: with SMTP id f8mr6140532wmc.151.1601404561398;
        Tue, 29 Sep 2020 11:36:01 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:36:00 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 5/6] lkdtm: Add heap quarantine tests
Date: Tue, 29 Sep 2020 21:35:12 +0300
Message-Id: <20200929183513.380760-6-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Add tests for CONFIG_SLAB_QUARANTINE.

The HEAP_SPRAY test aims to reallocate a recently freed heap object.
It allocates and frees an object from a separate kmem_cache and then
allocates 400000 similar objects from it. I.e. this test performs an
original heap spraying technique for use-after-free exploitation.
If CONFIG_SLAB_QUARANTINE is disabled, the freed object is instantly
reallocated and overwritten, which is required for a successful attack.

The PUSH_THROUGH_QUARANTINE test allocates and frees an object from a
separate kmem_cache and then performs kmem_cache_alloc()+kmem_cache_free()
400000 times. This test pushes the object through the heap quarantine and
reallocates it after it returns back to the allocator freelist.
If CONFIG_SLAB_QUARANTINE is enabled, this test should show that the
randomized quarantine will release the freed object at an unpredictable
moment, which makes use-after-free exploitation much harder.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 drivers/misc/lkdtm/core.c  |   2 +
 drivers/misc/lkdtm/heap.c  | 110 +++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/lkdtm.h |   2 +
 3 files changed, 114 insertions(+)

diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
index a5e344df9166..6be5ca49ae6b 100644
--- a/drivers/misc/lkdtm/core.c
+++ b/drivers/misc/lkdtm/core.c
@@ -126,6 +126,8 @@ static const struct crashtype crashtypes[] = {
 	CRASHTYPE(SLAB_FREE_DOUBLE),
 	CRASHTYPE(SLAB_FREE_CROSS),
 	CRASHTYPE(SLAB_FREE_PAGE),
+	CRASHTYPE(HEAP_SPRAY),
+	CRASHTYPE(PUSH_THROUGH_QUARANTINE),
 	CRASHTYPE(SOFTLOCKUP),
 	CRASHTYPE(HARDLOCKUP),
 	CRASHTYPE(SPINLOCKUP),
diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
index 1323bc16f113..f666a08d9462 100644
--- a/drivers/misc/lkdtm/heap.c
+++ b/drivers/misc/lkdtm/heap.c
@@ -10,6 +10,7 @@
 static struct kmem_cache *double_free_cache;
 static struct kmem_cache *a_cache;
 static struct kmem_cache *b_cache;
+static struct kmem_cache *spray_cache;
 
 /*
  * This tries to stay within the next largest power-of-2 kmalloc cache
@@ -204,6 +205,112 @@ static void ctor_a(void *region)
 { }
 static void ctor_b(void *region)
 { }
+static void ctor_spray(void *region)
+{ }
+
+#define SPRAY_LENGTH 400000
+#define SPRAY_ITEM_SIZE 333
+
+void lkdtm_HEAP_SPRAY(void)
+{
+	int *addr;
+	int **spray_addrs = NULL;
+	unsigned long i = 0;
+
+	addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
+	if (!addr) {
+		pr_info("Can't allocate memory in spray_cache cache\n");
+		return;
+	}
+
+	memset(addr, 0xA5, SPRAY_ITEM_SIZE);
+	kmem_cache_free(spray_cache, addr);
+	pr_info("Allocated and freed spray_cache object %p of size %d\n",
+					addr, SPRAY_ITEM_SIZE);
+
+	spray_addrs = kcalloc(SPRAY_LENGTH, sizeof(int *), GFP_KERNEL);
+	if (!spray_addrs) {
+		pr_info("Unable to allocate memory for spray_addrs\n");
+		return;
+	}
+
+	pr_info("Original heap spraying: allocate %d objects of size %d...\n",
+					SPRAY_LENGTH, SPRAY_ITEM_SIZE);
+	for (i = 0; i < SPRAY_LENGTH; i++) {
+		spray_addrs[i] = kmem_cache_alloc(spray_cache, GFP_KERNEL);
+		if (!spray_addrs[i]) {
+			pr_info("Can't allocate memory in spray_cache cache\n");
+			break;
+		}
+
+		memset(spray_addrs[i], 0x42, SPRAY_ITEM_SIZE);
+
+		if (spray_addrs[i] == addr) {
+			pr_info("FAIL: attempt %lu: freed object is reallocated\n", i);
+			break;
+		}
+	}
+
+	if (i == SPRAY_LENGTH)
+		pr_info("OK: original heap spraying hasn't succeed\n");
+
+	for (i = 0; i < SPRAY_LENGTH; i++) {
+		if (spray_addrs[i])
+			kmem_cache_free(spray_cache, spray_addrs[i]);
+	}
+
+	kfree(spray_addrs);
+}
+
+/*
+ * Pushing an object through the quarantine requires both allocating and
+ * freeing memory. Objects are released from the quarantine on new memory
+ * allocations, but only when the quarantine size is over the limit.
+ * And the quarantine size grows on new memory freeing.
+ *
+ * This test should show that the randomized quarantine will release the
+ * freed object at an unpredictable moment.
+ */
+void lkdtm_PUSH_THROUGH_QUARANTINE(void)
+{
+	int *addr;
+	int *push_addr;
+	unsigned long i;
+
+	addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
+	if (!addr) {
+		pr_info("Can't allocate memory in spray_cache cache\n");
+		return;
+	}
+
+	memset(addr, 0xA5, SPRAY_ITEM_SIZE);
+	kmem_cache_free(spray_cache, addr);
+	pr_info("Allocated and freed spray_cache object %p of size %d\n",
+					addr, SPRAY_ITEM_SIZE);
+
+	pr_info("Push through quarantine: allocate and free %d objects of size %d...\n",
+					SPRAY_LENGTH, SPRAY_ITEM_SIZE);
+	for (i = 0; i < SPRAY_LENGTH; i++) {
+		push_addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
+		if (!push_addr) {
+			pr_info("Can't allocate memory in spray_cache cache\n");
+			break;
+		}
+
+		memset(push_addr, 0x42, SPRAY_ITEM_SIZE);
+		kmem_cache_free(spray_cache, push_addr);
+
+		if (push_addr == addr) {
+			pr_info("Target object is reallocated at attempt %lu\n", i);
+			break;
+		}
+	}
+
+	if (i == SPRAY_LENGTH) {
+		pr_info("Target object is NOT reallocated in %d attempts\n",
+					SPRAY_LENGTH);
+	}
+}
 
 void __init lkdtm_heap_init(void)
 {
@@ -211,6 +318,8 @@ void __init lkdtm_heap_init(void)
 					      64, 0, 0, ctor_double_free);
 	a_cache = kmem_cache_create("lkdtm-heap-a", 64, 0, 0, ctor_a);
 	b_cache = kmem_cache_create("lkdtm-heap-b", 64, 0, 0, ctor_b);
+	spray_cache = kmem_cache_create("lkdtm-heap-spray",
+					SPRAY_ITEM_SIZE, 0, 0, ctor_spray);
 }
 
 void __exit lkdtm_heap_exit(void)
@@ -218,4 +327,5 @@ void __exit lkdtm_heap_exit(void)
 	kmem_cache_destroy(double_free_cache);
 	kmem_cache_destroy(a_cache);
 	kmem_cache_destroy(b_cache);
+	kmem_cache_destroy(spray_cache);
 }
diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
index 8878538b2c13..d6b4b0708359 100644
--- a/drivers/misc/lkdtm/lkdtm.h
+++ b/drivers/misc/lkdtm/lkdtm.h
@@ -45,6 +45,8 @@ void lkdtm_READ_BUDDY_AFTER_FREE(void);
 void lkdtm_SLAB_FREE_DOUBLE(void);
 void lkdtm_SLAB_FREE_CROSS(void);
 void lkdtm_SLAB_FREE_PAGE(void);
+void lkdtm_HEAP_SPRAY(void);
+void lkdtm_PUSH_THROUGH_QUARANTINE(void);
 
 /* lkdtm_perms.c */
 void __init lkdtm_perms_init(void);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-6-alex.popov%40linux.com.
