Return-Path: <kasan-dev+bncBAABBVGL32VQMGQEA34BGJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8439980DFE3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:14:13 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2c9fd9c1bc3sf46725261fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 16:14:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702340053; cv=pass;
        d=google.com; s=arc-20160816;
        b=uG1QIlYH11IFSIxQtMMA+BZEw7onZ2pcwMGKLPHbxmwihGoWruZMGNoAPITnBT0neO
         XUTltSdKabZ01dPWwz13PX61/yrhUUiCdGEVyrIgNS+Qu6NnQNpEyEJ4yglQkJ5frpLh
         +VNNcNhxPUPsaJ0ZVQNnho1r+uJ31f4X17BUnN5o6zsIeOyQ+L7ZVzVz7dz+m05Vv70y
         4mWI7gba9L32QQ8FU2Bd6IlFNGeZW9SDgMphk+/gbtkr/TfoFhmiJO4987EWSbB/QHcA
         UxYqh0WaBXoGchTmyWQut8PGZfnyTL6mhDxs2DEzhWTNItoMoh0Of1YpFBBGm1tNt7rp
         JmWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nJbCl8QpoSCC7V6hrf4jRl/H8wOt/ob2N2wQCgQMyUs=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=sEQSOqxcq85VhKy+5DGQXIJoJKcBauSuZzdKlT9Fyh5po0KsSlqvBMOqM1WnJVrXjs
         mjkoPwWKHpkOfoxQMW9rIBGIbSQH9RCC8/1zsKvQMm2fa8f99chioAI7aeZKjdTqVJTT
         95HtK1Mb7qnv9aT6mFjtiZfBesbsYS8KLHHtCio3fkm/Da3TVRrFNlVIVnmbT8n+6UeU
         XULi5GhNjtNfniR8daoarrnCrOTVE6ieGRGq08U0fLMML1kPwBeKzhdBfNnq/8sM1fWe
         fvII0JrTAqFLiOqh1aymIpymKiWiZLpcvIM10pHIh6+fxPwJDxUJmG4dmLznArhl/zLW
         9iLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="UvkDjF/5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702340053; x=1702944853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nJbCl8QpoSCC7V6hrf4jRl/H8wOt/ob2N2wQCgQMyUs=;
        b=uHaDYlasKBIRe8FgF6Mt9C1aNSDmtLLzMlFlBdIJXaW4CUVWAyjhJaeEF1vCYh+ZGk
         rIPRSvI5UjxTUp9X/1Db8YMEMUwpX6VhpnnWnw4JBrIf+pYEquWDUTjvHj4NpmOKWq7r
         GKBEenD1l4k5yyG/XxT1QLx4RgM6zslWy667kSc5/PWaK6w6P1w8IMMepeVTd519q/Eg
         UjAy/XFuJaIdj0V++ab/ftiUib7vtvnYD0FIAogmHyTmyPLJPc0uC9MhCKENiFhgCUWE
         ETokB2x6STkqtTNnCRL3DClGHxduGGV7loc6n0E5a3ZhwF0U0Tho4+pKbn/uEijUrtjM
         PuYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702340053; x=1702944853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nJbCl8QpoSCC7V6hrf4jRl/H8wOt/ob2N2wQCgQMyUs=;
        b=sBZnOLwqrM/qzDqarSinPNRUv3OEwzacd0i0uj8FTSmxovUi3jbkG2FGweLJT00Y1h
         Yb5V0H2Z5fw7/ttpw6EqILrMJcCbDj9S2Wq883hTxdOSJFZtq8XeT9wxUKvYGSh1BTds
         UObanjK7ruaKhr1wKP/PkTG5RYUX9m4xuEiH6Xs9bfjs7CewnQO/Y4xzhBb+UGaFnkUC
         wsv7TRaljFFOAAjCzyswXe5gYrUZcjOMIlkbN3z2PRW8b7R5dGir/d89nB0VRJzbUpKw
         1oAGLKQgLYKPMhtOQI9P4CY9vgRbfLzqPNGqm1gOMAgA/w/L5Gd/vbH9FQIhRwawEtOE
         sO2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7xmMEq4dnvi8HQjg/5dssD+e5/Dn6nURobaff56bGUl9OV/Ex
	NeupiZucKAQUzPeL7IX03iA=
X-Google-Smtp-Source: AGHT+IHg4fMvqfHplrAlq5llAu48hFtVeFHREAp7JkfTs4FVAb9Mk6hwsn6tdNkEXNapdC53ZJhzMw==
X-Received: by 2002:a05:651c:199f:b0:2cb:2b69:bb0 with SMTP id bx31-20020a05651c199f00b002cb2b690bb0mr2216429ljb.7.1702340052425;
        Mon, 11 Dec 2023 16:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b0a:b0:2cc:2751:3377 with SMTP id
 b10-20020a05651c0b0a00b002cc27513377ls259207ljr.0.-pod-prod-03-eu; Mon, 11
 Dec 2023 16:14:11 -0800 (PST)
X-Received: by 2002:a19:750f:0:b0:50b:f560:a3dd with SMTP id y15-20020a19750f000000b0050bf560a3ddmr2286907lfe.118.1702340050684;
        Mon, 11 Dec 2023 16:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702340050; cv=none;
        d=google.com; s=arc-20160816;
        b=zzuc+fTeD0Mz7l0sxChUh2XP72gHPmT7W84ejkuXkNEmSsLYE+3Q7WQGoKp7Bn63As
         3mhaRSDENNB42bY3Zip/rhIETozwK35+eIZ0RO0HZBflUq3sa+QcrSwt16Sx23MgQRKo
         TeubA5e7f9Z4wK2bkAbv+a6nH7wzJrdL3qh8trzPJ/QHe9ie1I2F225DzCfhbv2Qo4ZY
         uQvywZ8vTHf/6YpgLqH3rGfFwrIhFNj0hOm65Jzuh/W+D17glbNQAWuBNhy7zCbqCaJe
         5rHxN3Lki63godYTVhByQosF78vyIAc+GT/YCrRkJFI4QO7Wh4iPoHWjJxAxI/fAWO5h
         lttA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=x4Cn8Rdft153TNfaMCqmpUoRbUij/xgpu9Ka1HxHDYI=;
        fh=xumGgQ3/A3VHYu1DQDaIWA+Xl29EI5lD+bm6U+z1O60=;
        b=1BJ9xYb8QcaT4/obk9HnmJkqL2DZJ5ZotDw+VA5fv89PrTC+eFj6xGo5qiqMbMZ8yG
         Tq5nloo8hqSJMtiKTOXABqXpd4do/Xnb7XmSBPX34bg03FM2Z4ObrX3Iz+FcM/gp2NPG
         ToITUiYbt3G3HB2vzCxOxr1R/MY4KhRCu9hjERTMiuS8mrMrt0GaENE140gSNX0oA3hr
         PVlgbQ0PBBp1QNI+DOzYWHtBYT6WTsGVHe7oZJGcXzIWfZRusFdoCwkqlzr2jHj9BFlx
         CpfzDBg6MgpD4ZVMbr9SZ3cwsZVVznfIPvlNftVXVyHFcRst93uobWQTOGzFPwfsdVIX
         Kwuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="UvkDjF/5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [2001:41d0:203:375::ad])
        by gmr-mx.google.com with ESMTPS id f14-20020a056512360e00b0050bfb2c1afdsi348205lfs.11.2023.12.11.16.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 16:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ad as permitted sender) client-ip=2001:41d0:203:375::ad;
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
Subject: [PATCH mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
Date: Tue, 12 Dec 2023 01:14:01 +0100
Message-Id: <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
In-Reply-To: <cover.1702339432.git.andreyknvl@google.com>
References: <cover.1702339432.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="UvkDjF/5";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
trace handles.

Fix by introducing a spinlock to protect the aux stack trace handles
in kasan_record_aux_stack.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This can be squashed into "kasan: use stack_depot_put for Generic mode"
or left standalone.
---
 mm/kasan/generic.c | 15 +++++++++++++--
 1 file changed, 13 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 54e20b2bc3e1..ca5c75a1866c 100644
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
@@ -35,6 +36,8 @@
 #include "kasan.h"
 #include "../slab.h"
 
+DEFINE_SPINLOCK(aux_lock);
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
@@ -502,6 +505,8 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
+	depot_stack_handle_t new_handle, old_handle;
+	unsigned long flags;
 
 	if (is_kfence_address(addr) || !slab)
 		return;
@@ -512,9 +517,15 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	if (!alloc_meta)
 		return;
 
-	stack_depot_put(alloc_meta->aux_stack[1]);
+	new_handle = kasan_save_stack(0, depot_flags);
+
+	spin_lock_irqsave(&aux_lock, flags);
+	old_handle = alloc_meta->aux_stack[1];
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
+	alloc_meta->aux_stack[0] = new_handle;
+	spin_unlock_irqrestore(&aux_lock, flags);
+
+	stack_depot_put(old_handle);
 }
 
 void kasan_record_aux_stack(void *addr)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl%40google.com.
