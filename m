Return-Path: <kasan-dev+bncBAABBU6L32VQMGQE3YPKGUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D4E8B80DFE2
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:14:12 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c9f5bf236fsf39273141fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 16:14:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702340052; cv=pass;
        d=google.com; s=arc-20160816;
        b=J0C47AqdmP1WIRypj2xwSuZ/eBUDq9qoXeFJ/EBrFWf6sfHctg/XON8RQEGEQCK7uK
         gpzFL4tKBCmtkxmU3qNpF1M9BvYcfqDNrUqkWaMMvGdr9nJ03G9prSq9+y2ucWF4zyF9
         Ihl2RBCvBDRgC/FMbjQ604L+bmT/i7nkewhnftIqetj5tHSGRwTGIgUQRNYbF0zzcL16
         NtrtX1uPxY6cDTDDf5VeaAvAww9adOW0l2NYmXggyADse9NZ5K5zAgbWxm46CNDE8lze
         hzowv8GYxFXgKMOFb0uuzR+odq/H/CF71CPXClmrkQEpm2akm6//ylxB6DWjTsrp6ueR
         /HlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oAp+ExCDwMTvjCHszMSBZFm66yeBsQNOlT5Bb/ayT3Q=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=GmOkmi8Qaw/1s1Ie6KQkWe6WTqM5pxES038/9l0Kng++6jxJNG6wXXLQ3dDjtbMeqs
         fp4cg/6nIuXTPg/QZpCGwIOqdSHtdIAOwbaW3WfONXu7GCBWRFZc7GxbwnHLz0hknPdn
         SueDVFHoXhgXkwWQszxTOVVHu7klW+qdEYtwiIUxPTkWajfahsJFcKknK5PmHmoPUCz8
         h0QqzOZ55PVSZmFcuFRDaFQljV7MgUcbczbYcdrueCACnp/5lcJQX7UtU3nHXI8Pge9i
         tlR6lte5kyZfdfLesRh1OtXEXfxkghXKwyRI9OL7px7FWqT8eAvvDX2kbDNWDibzEHmO
         3LZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZFY0MXvU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702340052; x=1702944852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oAp+ExCDwMTvjCHszMSBZFm66yeBsQNOlT5Bb/ayT3Q=;
        b=ciDb3oetyHjJ+c/drRiPB3EENPyGu9hxTijnPmmr8kgqJIcSdfxChr2Z7YhH80gvjV
         Yr5E/lEVklX+LjuCzuSYroJE+R77p+K/pmaGmReETIYLsNSN3wQ3qWefJDSpVLvLt3hA
         DC+RyMsyY4eOexzxTmFBgrKt8W/T40g6fVCcddy/0EPSe0Pm/8AomzDxL1q47wNsGZpi
         yVapCcmpiRQ828AD9PusviC1W2rBtVvhw57BKXrAHFRde1SldIiFKqi0HcB3xnii8AhK
         O2blBEHMMeBUZF7F6H0PkKMi7aUG2aNZHpl2FIMTH2rhkV2GVkeqCdH8Yko5KMrMHoQe
         fGsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702340052; x=1702944852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oAp+ExCDwMTvjCHszMSBZFm66yeBsQNOlT5Bb/ayT3Q=;
        b=X/P8tYekIX0RdXxA7nKTjCw79y5rHEFosNJrxfmoMeUazyI1a4VtDtGlDBeGV5LmXZ
         TFfLK6yGJ8dRg6xkZqfrFDh8oz4RMNGBwZpBszK9SxJd0eTQL35ETekEefy9jrlgEd/e
         Pm+cOpHk9xGnbzUGANvRxMlMtt33hQ/Kn9/cq3F/ofpmgK0TINiW2bxf0NbB7anLcvnv
         RmFCsumo5e/bCQLIBxSKfaJ3/o51rIS+vtJ5CSTx1YbvNvjtigZtLYNMKV8PjsaOkiNU
         o7MVRJbh51VxCwPw/Cb4OnpUNgb+GrSbX0ZlqvBK3vMHyH/3JBG1TEFiLN9C+87LyFfe
         w3ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywngr2qLs136KyS/6bwqYYkppLUkxykmBFtEEbIPJGJBKG1DTeQ
	hy7TpKxwEll2r/wJYAuOHaE=
X-Google-Smtp-Source: AGHT+IE0IRDX77MHz4EvJt/oKBfx54SM3egKMesSxo3+4ILIUBKEQ6eX93dUspPPNrT+nKjn+nSiQQ==
X-Received: by 2002:a05:651c:1145:b0:2cc:1ee4:a930 with SMTP id h5-20020a05651c114500b002cc1ee4a930mr2270448ljo.106.1702340051672;
        Mon, 11 Dec 2023 16:14:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2123:b0:2ca:70:d358 with SMTP id
 a35-20020a05651c212300b002ca0070d358ls473783ljq.0.-pod-prod-05-eu; Mon, 11
 Dec 2023 16:14:10 -0800 (PST)
X-Received: by 2002:a2e:87d3:0:b0:2ca:3d1:e251 with SMTP id v19-20020a2e87d3000000b002ca03d1e251mr2734159ljj.62.1702340049958;
        Mon, 11 Dec 2023 16:14:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702340049; cv=none;
        d=google.com; s=arc-20160816;
        b=kRjj8Vdv/ORxXQdVrKVMuqe29pBP3V5aCrVpM1S84HBq4NTsypPTw3lPWyaspUi08m
         4LToAs6I1vAbpLIsp37cgqygTgBMFBCzFkhGWVyQgT7NFWS/6RYrIxNjK/N4EqU9UoXJ
         iCYPvXIvgPKImhqnXgluQuQm+5SpvUvjQrf+GMM8Z14mMjtIe06J/nAp/iD04UZufibo
         lCxV0Y5pqWJXYKPFVrO+cGVex3UGU+4zOpelPH7E5NPzwMD0i/QLU6Y02qArHqgvWUho
         +Ih0s7LEPrR+FtODLBpx6RcMvpAQBnu0BjaRSCUFmWogrEnt5ixoaX0SMu+wyWANDcjF
         JgMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vOaXJmSZ4mgcOuCRTmHs9viCNJ5mspLX8zhenk2W1qY=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=bfPgo8mR9Ymfw9fPQhpt0VkiLvefFKDRhowZsnoF9/vxEnUqzzf1H7XZjmgaGGY7YF
         v5zxhPiJxwIMqEY1HGdSPFpAyK9AHcz/OOhNIF3DVprGvIDk6CoBmh+rCven0atq903U
         QyUJnc02E3vFGk/NXua03bB1O0/fapz4GqO7PDRcf6upLtPCci8X5nWR61/mqwoYcH8c
         JXn/IX8Al5SHm3LVNsxjvN81AYVXyURN6zUz+TBgjAhINYP6zKQn9Uw+Hwrc+XyGC+PR
         zHmwtE/SUTFj3lkR5JIn34b8wE0YDf0eguQ/r9eatf+B21pzSrvQ4dAQ7i/RyqzUg1z/
         R+5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZFY0MXvU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta1.migadu.com (out-183.mta1.migadu.com. [95.215.58.183])
        by gmr-mx.google.com with ESMTPS id b2-20020a05651c098200b002cb2a04e581si304649ljq.5.2023.12.11.16.14.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 16:14:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) client-ip=95.215.58.183;
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 1/4] lib/stackdepot: add printk_deferred_enter/exit guards
Date: Tue, 12 Dec 2023 01:14:00 +0100
Message-Id: <6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl@google.com>
In-Reply-To: <cover.1702339432.git.andreyknvl@google.com>
References: <cover.1702339432.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZFY0MXvU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as
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

Stack depot functions can be called from various contexts that do
allocations, including with console locks taken. At the same time, stack
depot functions might print WARNING's or refcount-related failures.

This can cause a deadlock on console locks.

Add printk_deferred_enter/exit guards to stack depot to avoid this.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@google.com/
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 870cce2f4cbd..a0be5d05c7f0 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -506,12 +506,14 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	bucket = &stack_table[hash & stack_hash_mask];
 
 	read_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
 		if (depot_flags & STACK_DEPOT_FLAG_GET)
 			refcount_inc(&found->count);
+		printk_deferred_exit();
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
@@ -520,6 +522,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	if (new_pool_required)
 		need_alloc = true;
 
+	printk_deferred_exit();
 	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	/*
@@ -541,6 +544,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	}
 
 	write_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -562,6 +566,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 			depot_keep_new_pool(&prealloc);
 	}
 
+	printk_deferred_exit();
 	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
@@ -600,9 +605,11 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 		return 0;
 
 	read_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	stack = depot_fetch_stack(handle);
 
+	printk_deferred_exit();
 	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	*entries = stack->entries;
@@ -619,6 +626,7 @@ void stack_depot_put(depot_stack_handle_t handle)
 		return;
 
 	write_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	stack = depot_fetch_stack(handle);
 	if (WARN_ON(!stack))
@@ -633,6 +641,7 @@ void stack_depot_put(depot_stack_handle_t handle)
 	}
 
 out:
+	printk_deferred_exit();
 	write_unlock_irqrestore(&pool_rwlock, flags);
 }
 EXPORT_SYMBOL_GPL(stack_depot_put);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl%40google.com.
