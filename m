Return-Path: <kasan-dev+bncBAABBAESRCWAMGQEQNL26BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 323A3819226
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:20:01 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-40c4124a064sf272225e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:20:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020801; cv=pass;
        d=google.com; s=arc-20160816;
        b=TcI9F+SQn436UG5QGMhOJevm7n98MHF5BnUPuwCePL681EHUbUiEDP+AZWFXORNEa6
         MFxiyQiYP+jFz34n7opCQvSgrCpWUDTgFGOz3RDP8sTpWwr1RZNVXA5BOnf1TJnk5bNh
         SlEWN/8aU84hx+8K6AOTMzP+KdBoktSQPQ35RNBrEHeJtn8NjkHgPbhSB+0+JflkPUkn
         d/QA2fgcANMFxPrCP2OSGfDutZn1m7gOltRQBrRV7TIoREGAvTb9erHLEFU3SAz32F+Z
         8UNE8E+mIDdDeqpvEeHzVNO7+L7l6NS6ukZc8gps6WT9yzG9r8GIknuMW8kEHwfrn/xb
         PwHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OWW2auXam3h/tIQulI2kwqYT6U+WPInb8GLXOmQVPis=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=0jEx2paOG28zSNSNOaE1wwPy9w94bHR3jfE7nKJ/uYBDRMaZwlumx9Uo1Q+MtrLyPg
         yQB2CYxDcEPXvq/GwbftOCb/PiCjgnan+ic2WPIhx1B/xzHRY8C7D3yRKN9aENEHPn0D
         qJXYW5QLemAaSQY7qRexGFDt7Si2BgDY6duobxcBIi1gU0vPZJn9aXNYfS1LV5t8B8kx
         3qmD8b9q6MBMEb4laKx8L3YlpW6NCLdZh3Dgr75QQffrlVxsLBS0PxCjuEETj46RSlkS
         DVoXe82h05uUpWh+ZNI8ivjECeI7qanhyBnfgkROfaBj2CbzevZElOuTlQzFuK+JmLzx
         M5vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IR+Whe6+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020801; x=1703625601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OWW2auXam3h/tIQulI2kwqYT6U+WPInb8GLXOmQVPis=;
        b=lX0dUxjWEJsPRgNm3STMMIx38/fx9pLswQbFPqnF+i2DVzTNiN3+C+C17Nwgs58CCc
         +JdN3olfsG4F+81rYbXCd1ziGIGWPntYjX6zXHtLDYfDSxBhgseRiba2wKTPIa8n6J3R
         oKJKYXFWMOuDsGdrS2aKOZGYdQbJo480vU/maBjDyWWgPya97VF8RDBuEs/TkcA8ajs3
         ByZ9VfUl6ugtHrB8fZ0Ww7YJQlKYTEbOHH5/WeZ37+sBQAidBz62Yl7DfNdyBusFEpr2
         ajdMTEuKV5OpudZijr9sLHffCSjfEL/PBTsRuqkNsc4SYYJFC/MSpliMyzOeaHCE7uqD
         5Jdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020801; x=1703625601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OWW2auXam3h/tIQulI2kwqYT6U+WPInb8GLXOmQVPis=;
        b=jqZioWKZveloiunUoXNPvnAJvLqWR0/m7M3KnPpbkx0shkiie2HtHtPLRiwMNuiz7O
         oz7M954IErwmWSPPep+v3Ze8/hABQx4hND96ActRfD5uK0svzKHULka5Trq1xGgWWZa/
         KiaIJoHGA810gtJFw7h7ykO34/jPk/Cm1g5PqnqueFpB9x2BK2MGuvv3oaUsOEm+I4Ft
         4+oDP1NXn7+Xr0ayhoAVc84AVU/PoGS6mwab+Asmub9EIsEoLXyhwhHPXpMYKVT9QU9A
         zLDuPOSxXTFLh8mrJQmz/1yj4X/1X2sLz+yOjFIA3FqQA5uXbHR8MKH8OcCYTXN6eLoX
         jPEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxv+PZvTRo96OUWwN3d+/Fus0DJ78YgnmU7LCagWwPznic3tmSI
	hFTs4h/fgjEFEAwKPVssYB0=
X-Google-Smtp-Source: AGHT+IGtfelap9RzhiEXKoLHypX0ebxHUeH63907P4VyWGZsUGuDdg/AF2XhvALELpZ+4mqlYSNlqw==
X-Received: by 2002:a05:600c:3b9d:b0:40d:2361:d0a2 with SMTP id n29-20020a05600c3b9d00b0040d2361d0a2mr45408wms.4.1703020800732;
        Tue, 19 Dec 2023 13:20:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:700e:0:b0:2cc:7d17:b9b8 with SMTP id l14-20020a2e700e000000b002cc7d17b9b8ls413205ljc.2.-pod-prod-07-eu;
 Tue, 19 Dec 2023 13:19:59 -0800 (PST)
X-Received: by 2002:a05:651c:a12:b0:2cc:854b:556e with SMTP id k18-20020a05651c0a1200b002cc854b556emr824150ljq.70.1703020798928;
        Tue, 19 Dec 2023 13:19:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020798; cv=none;
        d=google.com; s=arc-20160816;
        b=zI9BluLDoL5CNvSoriAwDKoECLj99WuCPgfMug3LbcrZ5zo5Zic6KsxCCyiHPmtSUw
         rOQsHOIk6Kq9ITT2azVow6WMdvq7ORgkZtz9+wDI0o1Wr/DqjBGcayi5k0POM5lOnMTm
         5FUndMMRb8wEelZtlyHfU9QK/SUWMNIKIt2iIgDikSgtbCrJyOdU9Xa9YIDbqlVsQYW1
         i6m0IbffscEfDloZTy409lF2S5gLdmaaEiFQMM8eEv1TvvRdEYoj3qwp7SXJ1qaUnTvH
         DzMvtMEWmMQBKj/FqYDRzm4x5y9j6yvPUqvnbROeJS3lOeZdzavkN6GywP0KKQbpQz2L
         0xTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IugD6msAA76PLOkulY8RL+cRtUx1nL2a5VcYM7ZPFvs=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=OE8pYk6jKoTwCZ6CWK2bbAobamgoiMC6BCukqDYNgN1AtxFq6OuTACypS+0LEJ8Fdv
         7ogkoLzy5n3f7MdYDblY1PJP52qHU9pDpKYXsOBSZWbgX6hjXek/GkZko+mZ5Z7pqxHf
         FY4tgpUMlHwURv0T0fBd8ZytwVGorwvuT9fSfWsSQv2wZNCnMrWSy7SS+oTbUcp/SQLq
         kQB7upqO/1vPlJxRYLQwI8dywbt19kehK/k6xHCAgloibyYwU/4aQ3U/k4z00FFlZ/ug
         LHPu1zzDFFYWU0WK8EphPTExMmaaFN9VPhJ2SO1TUA1udYj2BbsfXhsy1uDy6rf/UdXx
         dInA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IR+Whe6+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [2001:41d0:203:375::af])
        by gmr-mx.google.com with ESMTPS id b28-20020a2ebc1c000000b002cc65dd648fsi330245ljf.2.2023.12.19.13.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 13:19:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) client-ip=2001:41d0:203:375::af;
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
Subject: [PATCH v3 mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
Date: Tue, 19 Dec 2023 22:19:51 +0100
Message-Id: <1606b960e2f746862d1f459515972f9695bf448a.1703020707.git.andreyknvl@google.com>
In-Reply-To: <cover.1703020707.git.andreyknvl@google.com>
References: <cover.1703020707.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IR+Whe6+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

kasan_record_aux_stack can be called concurrently on the same object.
This might lead to a race condition when rotating the saved aux stack
trace handles, which in turns leads to incorrect accounting of stack
depot handles and refcount underflows in the stack depot code.

Fix by introducing a raw spinlock to protect the aux stack trace handles
in kasan_record_aux_stack.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Use raw spinlock to avoid lockdep complaints on RT kernels.

Changes v1->v2:
- Use per-object spinlock instead of a global one.
---
 mm/kasan/generic.c | 32 +++++++++++++++++++++++++++++---
 mm/kasan/kasan.h   |  8 ++++++++
 2 files changed, 37 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 54e20b2bc3e1..55e6b5db2cae 100644
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
+		 * raw_spin_lock_init to access aux_lock, which resides inside
+		 * of a redzone.
+		 */
+		kasan_disable_current();
+		raw_spin_lock_init(&alloc_meta->aux_lock);
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
+	raw_spin_lock_irqsave(&alloc_meta->aux_lock, flags);
+	old_handle = alloc_meta->aux_stack[1];
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
+	alloc_meta->aux_stack[0] = new_handle;
+	raw_spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
+	kasan_enable_current();
+
+	stack_depot_put(old_handle);
 }
 
 void kasan_record_aux_stack(void *addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5e298e3ac909..69e4f5e58e33 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -6,6 +6,7 @@
 #include <linux/kasan.h>
 #include <linux/kasan-tags.h>
 #include <linux/kfence.h>
+#include <linux/spinlock.h>
 #include <linux/stackdepot.h>
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
@@ -249,6 +250,13 @@ struct kasan_global {
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
+	/*
+	 * aux_lock protects aux_stack from accesses from concurrent
+	 * kasan_record_aux_stack calls. It is a raw spinlock to avoid sleeping
+	 * on RT kernels, as kasan_record_aux_stack_noalloc can be called from
+	 * non-sleepable contexts.
+	 */
+	raw_spinlock_t aux_lock;
 	depot_stack_handle_t aux_stack[2];
 };
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606b960e2f746862d1f459515972f9695bf448a.1703020707.git.andreyknvl%40google.com.
