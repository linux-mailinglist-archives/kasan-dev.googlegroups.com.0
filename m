Return-Path: <kasan-dev+bncBAABB74RRCWAMGQELB6ZDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B213819225
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:20:00 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-40c691ffad7sf33806025e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:20:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020800; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5EOZpWFu91Y1tyyYYN1bCHoNGr6ru/fOk87hxM4AllNhQyCyIoRHlfnm0KFn9Cstt
         QZ6l0BtUon5c4voINctcdnpUn16OexrX7s6rhUWIna87+UcH42vTsDU+wl/lOg6W4lRW
         +Vg+2bvS8RopUSajDaaqKf3GF1ZtQ17BAhMWXhqbJdo+LM2MwuSRByFTKWTeQbKURd5e
         nMCJQs0KUfVktUYmUx+MrpD7CCiaod0D7r3ScxuPweZCYDxBEXq3AsOuACRjiKLkb2Ll
         jLYubEtIptfq+4yuUkUXTgWSZxAV9e6T4haa/fQnj/GWfxjgrbaZ8nXmTr9srT/iRPCs
         3lug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kfxYQIYRm8Hqxk/eoTpp9IVDJ2+0rzNW2E2HE8aU/pk=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=Ip9+Y9jTfiY+B2DA7ulXswC67Maj6ds+dl6o8D0B2a2JOD5LHQU++GbyYuLZFrRX3f
         TrOxUfXqNx5b1jmfcLpdLU3UbofisyUEbtkZ/tGfPec35JqoDPpTjZRNOAlcwJz4gQI8
         MZwE1LvVMDtWGn86aAo4yOBlnvybjBXnGf9G023U2SvEauB788ff5z1UG/iOZbTbUZ4I
         Cge2nA8/1kbkFJgTYaovfXSp6jxjMyF21miJqD/GOQZ+29VaTp/aX9edLCJZA2geBXNZ
         ZkUphWyatRzc5qc9ZuKviXh4L3npGkCilnX/qDRZdXEZ7OMrzfuMN3J80lUCzHZC+wjL
         m6hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=elb7wJjm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020800; x=1703625600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kfxYQIYRm8Hqxk/eoTpp9IVDJ2+0rzNW2E2HE8aU/pk=;
        b=uXASVCalLJO1zfh6BZkyEbw45niZedYcFQGfH+29qsMzEgrdBh8tx3urmcfWuiFQD9
         cWzzUk0Vy5wo819texFoScXy2Ilyjee2amTxSzXaEDTdmJV1kiqtq9EyP6gA1KtxuxLE
         wQFfNCsOkE/60hY+u/nKtFaa962DiyvsSz035MHvqB9jQdfZyccfS15bdrervw2bz28S
         QVg6EzQBANUhLSVpEmDXwiU/6Z2crSnoU2OvihJfc0fQWxzf/hIxibp/I37+NQgP1uCC
         Mi8M8gwaHRpnLIK8crEJtpKNcctKxjxUoQahwsmFf4++LRolTaa6Jl1XRKbeCmaFSUF2
         WOlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020800; x=1703625600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kfxYQIYRm8Hqxk/eoTpp9IVDJ2+0rzNW2E2HE8aU/pk=;
        b=lYuRC6c/uqVYDB0MaEMZMbMl5BDwmhoElZyCA64+Fio73xTJuxL4e3CG2OwMigrRui
         2wFy7fD3Pql3AWosT6nw10X9qvkopBydQYajNuw7/FjqGZ7Y6k7Y+D2peLyzA5eey0nK
         j6X4igSDZ9muL3A77/rWsUEj8jp/fJh5BTt5jiip4y0Xj69XnO62DEDtdheABSF4QTC/
         gBIWM6zd3y/E0/g8Hocu/rvyL2ldBeW0csE/79Y/CC4gUSIKebl9gcrZ6mDQKASq1aet
         GOAZZDAvaxqFBd1HufGahJJzpDCOvgLPCPOMLJJAKETJb0W4KZ4XJCCML7bIUzeTcNCa
         jvBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzb24LGOoasgP/QrT6RJ71NLC5cb09tf6ChuYGUppHvSv2v2FeK
	YR/hKZnHGbhC83bBYZkdWAo=
X-Google-Smtp-Source: AGHT+IErBp+JpPxJdvWpYeMPkTtm8AQXfWK0hzLtuCwtW3uuLt/8dBjjTweeNlJrZQwWoHqusUkCiA==
X-Received: by 2002:a05:600c:ccd:b0:40d:2d25:b8ee with SMTP id fk13-20020a05600c0ccd00b0040d2d25b8eemr308746wmb.171.1703020799395;
        Tue, 19 Dec 2023 13:19:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6b50:0:b0:333:35b2:703 with SMTP id x16-20020a5d6b50000000b0033335b20703ls794808wrw.0.-pod-prod-08-eu;
 Tue, 19 Dec 2023 13:19:58 -0800 (PST)
X-Received: by 2002:adf:fb03:0:b0:333:2fd2:766d with SMTP id c3-20020adffb03000000b003332fd2766dmr5015287wrr.94.1703020797705;
        Tue, 19 Dec 2023 13:19:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020797; cv=none;
        d=google.com; s=arc-20160816;
        b=AlIwkfEYvkUiRxi+ToNTHVEarRq2K991wVGFqWUvoZfHibNlddXowAdl1eUaCLptd2
         3PcNmKuRmQQ9F/QbxnJHqnYivmshY5lW2s2iZy7okZBoUyN4BXHBLXItgY1TzAXrN4Jo
         vBD6bpGXw4kU2D1P9tFru0k61huSky9l4mAUBTo6XO7pH2Gfw9TkdRKW1yxPwwGBdits
         INkDh9oWfxjMeN8X5bkPb7rsxUq7LYANB/7b3iIU2bBqz55C4XWaOGzK6KGqqGjvFcti
         RhgCaTE+rWUJVclaXI2RiemtcBiSbJEpDdiMFjZFyvAyXVcLsnYDqKIXwjU1suOvpmjE
         NmWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nejB0rN/5EGuA3SQQpabp67CuxIikS5y1NrnTFuMISI=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=uZDVB81oh2o6an7OmoO+zHJJV1UBM7ShF+uaEVAPrEXqq4bDq2A9H7QDhNyDYl8DMc
         ZW0g+4UEm3xupFxMFsye02NlJhRNfQ1/EmLlxwUkRpzeE6o3wkj+LpOs0jL41PhhUfna
         9UO/P4SsOg3+k6g/WMLqWbeyuDB0zp6IKTnKV1H+D2l8tkcmkkQHLv/QsDM4Vg603ZoI
         smjhAnB6UHcdAZqKejlCKlfTeikSxaL81RD9+GfEOUweNS9J31awiJXtcujn3Gy2+L8R
         Yg0znok/Cgw6dnAjpEj6y4VGqeHOsXqY/fQ84SGY25TyU4yb/8fyYJGO5CKzLVHZEiEo
         Ffog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=elb7wJjm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta1.migadu.com (out-180.mta1.migadu.com. [2001:41d0:203:375::b4])
        by gmr-mx.google.com with ESMTPS id a10-20020adfe5ca000000b003363559ace4si606171wrn.5.2023.12.19.13.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 13:19:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) client-ip=2001:41d0:203:375::b4;
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
Subject: [PATCH v3 mm 1/4] lib/stackdepot: add printk_deferred_enter/exit guards
Date: Tue, 19 Dec 2023 22:19:50 +0100
Message-Id: <82092f9040d075a161d1264377d51e0bac847e8a.1703020707.git.andreyknvl@google.com>
In-Reply-To: <cover.1703020707.git.andreyknvl@google.com>
References: <cover.1703020707.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=elb7wJjm;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Stack depot functions can be called from various contexts that do
allocations, including with console locks taken. At the same time, stack
depot functions might print WARNING's or refcount-related failures.

This can cause a deadlock on console locks.

Add printk_deferred_enter/exit guards to stack depot to avoid this.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@google.com/
Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Fixes: cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable stackdepot for SLAB")
Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82092f9040d075a161d1264377d51e0bac847e8a.1703020707.git.andreyknvl%40google.com.
