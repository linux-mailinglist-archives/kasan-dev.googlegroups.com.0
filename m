Return-Path: <kasan-dev+bncBAABBQVB5GVQMGQETD2Z6NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 138C0812415
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:48:03 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-333405020afsf6390077f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:48:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514882; cv=pass;
        d=google.com; s=arc-20160816;
        b=PL3oL4/c69kzLyRIPQDowL7Y9geOVzVAeIOYdDBR26KVvnOoEnKmQiU27XDURVU9vt
         9WCC/uqyQKaTF0SLuC2+3mYUaUztLfXPz+XTJtxLeZ0l1k5qSF7VGU9D9hpK7avfbsYY
         C9RQw5zuJYKvsSbV2THwdETAcTq2CRhbPJh5t4VrNNw3mr2Uej3rzkipCB58Z3aqZxx+
         YxnItUD+tQPzk18Dx8B9pO1InnNN3hfWOYe02gMF4o6jvSQJ43/8R8toe7neErJJ6tJ3
         1koMYEsDX/+lbbnKrOb89q/EF4iC6FlBeYCVc/dgKenQsMIjx8PQeig/XCOuF7GOkw2J
         boag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3HtwR9ilgEz2rYi4PJ18uWtEa0JVCz3+eBsAYGZgl2U=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=JXfaDWYvYfUMDCXFC/QHLQnI6v3hHcRYnTt3xZklkyA5LkGz6R+f8jD6v6ZmihUfYm
         yxkC4ouNf6YrcT1rTuR5lS4shicSq9hTd/Xyc+Lj0ZFkckWYpjvVWVftowm0bRevU8gD
         QQDy1p4wSM0SICQFnnKgax0+wyw2cKJPhi11TViHJS7gksG/q7ybSaS+Tvs4yJxeRH2G
         Spw/9AOLrqYzPo/Xs8yjuqW6d0iLPLZloFJJnAZslGEaRhJmTK1pViMlV2Ee8x7Mb3OZ
         rG2LI4g5gkAYpwxJXXUsnD7o1skzhbMm5xVW4zRT8nFn0ej1b8Qnso5ylKDeH2x3/K7k
         U4pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukeh5H64;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514882; x=1703119682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3HtwR9ilgEz2rYi4PJ18uWtEa0JVCz3+eBsAYGZgl2U=;
        b=DG6gGJkFHjdfKZxo9Aha5UK/1qCxit8gH7C8TZy6u/UhOE/de1XyRE9rsAVrBO7McQ
         kx5uiYNU1o5ybUp329AaT/1sMRm1aeC3qUfmtupwAgiMQeGy4CQoVMzl1qNLAmfshLCN
         Cycrt0mVB/C+0QCaXavrxgPoIPZZaXKAY9tixR/QPtS0uMOBrM3sHaIKMFbxS4d8T25w
         s+mVkiVbk5+tGMrMK32X5ufV52ATPbu6ErogRlD+k9Y4DNh/0a84zm/f507LJ2V3jWJk
         GGR5Bjs2zwo+CYm3lJch368bKD+P/oes5lA68QB5sZYhuBhQbGI73vBBOihGEjcfWT2G
         P5sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514882; x=1703119682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3HtwR9ilgEz2rYi4PJ18uWtEa0JVCz3+eBsAYGZgl2U=;
        b=QbNlgxQxaNYKtTNm/xtm563SCl7NYp4ZNTI6pUPqYKpYoKU3ZKdYB2Ns58noXR+nHP
         WiVtDnoeCMRmVWyKFByCCVRUgmiLdkiqRj0fBk07BkTLM0vmEhJG1hpqAF8ZuvAO9VGI
         TtKa9vqqK3EkbNaROI6RxTx+A80h6HA/PBMmT89UXhRA+vNxkTTmK66OICRaLlhR1QO1
         6CFnoIKwCWsw9b19qUqzy64y7BGC5IJSy0O1UXgMr7OAW61zO6cJCKbAezvOd0LVfHk+
         Fs0CWJEN6YFUWgB63MoVwfzJu6b8jnuRDGb9/ARVcHyki5XCrh98Ko5rdHt86z61a3uf
         QWlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzvzE9FWAEngIxOXPcSB+quyDiCQnM7rJl7+E+oKao6kPjy2Zi2
	6jGNmpX5SYEDSeDhDT6HS2g=
X-Google-Smtp-Source: AGHT+IGuy/J3Y/eTr+LcZVfOCIFGQKZuefFdXqrL6qabZDcs8xTMyREZP4gkzffyYrzwxDpssnz4QQ==
X-Received: by 2002:a5d:4850:0:b0:336:421a:3d8f with SMTP id n16-20020a5d4850000000b00336421a3d8fmr919604wrs.6.1702514882290;
        Wed, 13 Dec 2023 16:48:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4901:0:b0:333:60f3:670e with SMTP id x1-20020a5d4901000000b0033360f3670els867569wrq.0.-pod-prod-05-eu;
 Wed, 13 Dec 2023 16:48:01 -0800 (PST)
X-Received: by 2002:a5d:48d0:0:b0:333:2fd2:5d5d with SMTP id p16-20020a5d48d0000000b003332fd25d5dmr4438562wrs.143.1702514880911;
        Wed, 13 Dec 2023 16:48:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514880; cv=none;
        d=google.com; s=arc-20160816;
        b=XexolYfOIlFXNkOGZqd6v8pCsvHOE369sutEvX5n4LDI21i/RM2jbfMMEyq3i5F7wS
         f2shhEtkbqpR+zWsq/i6HzXv5PAoey6y5b2P9WP6wLypM1GPodvY6E8ikAGYV/HJxFV6
         ZSwjLG4SGPjDoN7ypUO3+D0or7PIQThVuRtkKjbhhOBtY77c82VP3E0uHY5DENDku1BH
         0DXVPyt37DJB3HVCtZJtjype1C8qYXN/fYJdh9Mnevm7eMEi5p7iihawJXIQkoUFG7l4
         5a4rcFQSZ2zxPxzjBQzLPETORKOUTl6TAsBF1/xGT6/0FHdClyhKiD+s/Tnl2p2YV3sE
         km2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8YssiUYIuDBfUgViHa8UWZbb+o2fPyHhfOU9iGYPOo4=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=WEC1QynSc5R0qI0BO5FJEjnedeZ9eixnwtgiDI9gs8fr+mhfpL+mto5aIV70uLYtxn
         ohoh/24PTQ8IxuNb7MY6Rlo/LAUxOiatgjg9U5BOeUsnbtQTuO1zFHJNEoRmtil0H9ef
         xRoA00c0/TZXFuEezBDfjk1rFHWNBNIoITWhhoLLnnSBXBVOLw/EYxZ/x3bbBfJemy0O
         0JXDs8Ohl4KbFYEYJYr5DF9qA++6YrbJUmE3MAzkHpCCUZ6CpzQsBi74Su0IF4ypyoc2
         Udx9cO3WtzBXJUZ+mlYvzywaca3SIPszAc2gei7hHw7wZSA9bygapdqBJ9KMazcwBLJO
         gWaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukeh5H64;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [95.215.58.185])
        by gmr-mx.google.com with ESMTPS id c26-20020adfa31a000000b00333463f5f71si69450wrb.0.2023.12.13.16.48.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:48:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) client-ip=95.215.58.185;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Subject: [PATCH -v2 mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
Date: Thu, 14 Dec 2023 01:47:52 +0100
Message-Id: <88fc85e2a8cca03f2bfcae76100d1a3d54eac840.1702514411.git.andreyknvl@google.com>
In-Reply-To: <cover.1702514411.git.andreyknvl@google.com>
References: <cover.1702514411.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ukeh5H64;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as
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

kasan_record_aux_stack can be called concurrently on the same object.
This might lead to a race condition when rotating the saved aux stack
trace handles, which in turns leads to incorrect accounting of stack
depot handles and refcount underflows in the stack depot code.

Fix by introducing a spinlock to protect the aux stack trace handles
in kasan_record_aux_stack.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Use per-object spinlock instead of a global one.
---
 mm/kasan/generic.c | 32 +++++++++++++++++++++++++++++---
 mm/kasan/kasan.h   |  2 ++
 2 files changed, 31 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 54e20b2bc3e1..b9d41d6c70fd 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -25,6 +25,7 @@
 #include <linux/sched.h>
 #include <linux/sched/task_stack.h>
 #include <linux/slab.h>
+#include <linux/spinlock.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
@@ -471,8 +472,18 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 	struct kasan_free_meta *free_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
+	if (alloc_meta) {
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+
+		/*
+		 * Temporarily disable KASAN bug reporting to allow instrumented
+		 * spin_lock_init to access aux_lock, which resides inside of a
+		 * redzone.
+		 */
+		kasan_disable_current();
+		spin_lock_init(&alloc_meta->aux_lock);
+		kasan_enable_current();
+	}
 	free_meta = kasan_get_free_meta(cache, object);
 	if (free_meta)
 		__memset(free_meta, 0, sizeof(*free_meta));
@@ -502,6 +513,8 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
+	depot_stack_handle_t new_handle, old_handle;
+	unsigned long flags;
 
 	if (is_kfence_address(addr) || !slab)
 		return;
@@ -512,9 +525,22 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	if (!alloc_meta)
 		return;
 
-	stack_depot_put(alloc_meta->aux_stack[1]);
+	new_handle = kasan_save_stack(0, depot_flags);
+
+	/*
+	 * Temporarily disable KASAN bug reporting to allow instrumented
+	 * spinlock functions to access aux_lock, which resides inside of a
+	 * redzone.
+	 */
+	kasan_disable_current();
+	spin_lock_irqsave(&alloc_meta->aux_lock, flags);
+	old_handle = alloc_meta->aux_stack[1];
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
+	alloc_meta->aux_stack[0] = new_handle;
+	spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
+	kasan_enable_current();
+
+	stack_depot_put(old_handle);
 }
 
 void kasan_record_aux_stack(void *addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5e298e3ac909..8b4125fecdc7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -6,6 +6,7 @@
 #include <linux/kasan.h>
 #include <linux/kasan-tags.h>
 #include <linux/kfence.h>
+#include <linux/spinlock.h>
 #include <linux/stackdepot.h>
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
@@ -249,6 +250,7 @@ struct kasan_global {
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
+	spinlock_t aux_lock;
 	depot_stack_handle_t aux_stack[2];
 };
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88fc85e2a8cca03f2bfcae76100d1a3d54eac840.1702514411.git.andreyknvl%40google.com.
