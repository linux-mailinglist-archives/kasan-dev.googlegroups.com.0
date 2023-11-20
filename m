Return-Path: <kasan-dev+bncBAABBMVX52VAMGQEOJM2AIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C427F1B57
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:31 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50aae89f8fbsf61e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502451; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsnrQFrpNy+ZkkCqUh2c8HC943AlPjbIVmEONH5CJEtOFnWjUMEbfHQlctJzPWGA2d
         19kLUr+hFiKciUmMQmTJgy4++szMpUlY55OHdnyLvBl9HL5g2w+RMpPzoFjVYZx4JtzQ
         GC8nNrk3hylClbp4GwIoYZgXe1sczybSY3saqM7YxKsueCLSErwpoyFu5+04Zf4VDUUP
         DoSL4N+nvRhWxBIMKQypy+ag7sgVGhYBFcgMzKuG4hPx0RkyMX1mcj015xnukRT6ACF7
         gSIft2S68m8YCJgSA5CeJPU160JUY8WITIVRJuPgGytaTsxQ+siseEs5eEaZR3pFV8S7
         qrsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=x14+J3Ijehr7L07qvLSzMqORvr79C3XHAMPXrH+JU8w=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=VoBhINPi+9wca7upUUleuqlWyI0K5c7hGzSQB+ln3vCpZT0zEH/xdIXYN/i04pDDuL
         zSg6bSY6p7LqZC3aAkDVvbJX+2+fDZC9Et2UHfopcg1jdbVuc8OY6nzmWyZEe6/SwCjd
         GoAQP1p0ffjPJjhw1oVeMjYBI669Xtb8EQLc+d/O+rf9C8xqtb8FwA0CjIJZ6dDU/J1S
         K+hpjjU2dAsVA1K6ZB+lHips0ulw+bw+JGuKBRF8hO36FToji+eHVWTMjN7ZeZ0myCa1
         Zx44/GQ8NB9xIP3/9XVVGKTPkWTpBqj8DHB1Iz52nlRU1CejMKjtZsGPUdi1OHfX9Qm6
         0CWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DpwTRKlG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502451; x=1701107251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x14+J3Ijehr7L07qvLSzMqORvr79C3XHAMPXrH+JU8w=;
        b=DymnrF0r4YWMCqkk6XgaGpToL377b/g6FBao5AtgST6bc5e5aHXiDYEghlTqIomXUd
         mhp8Ku+vKgH2ASZTQiSSJcYROsQYNDTkMk8xU5nBD8IHTQAoweMGRiCFsFNvqSmPrxiM
         xAK3p7ZW4ywl4Bi15WYaDpYDIxuKYoh0sYJKf+nMooPHY9Ik3jn5ll4WOOLOFuGgYsYW
         wBBgch/AuvZabv1F89YGt/fe1YYapHPr0Nx9gsng1oLv3TBy3qZmnxtzK6cYWEU5V941
         6JO50mHKmXxRe+Dq+7ebfaOxr9yyjx6m6FmT/K5+dfr6vrEJsZxjons/96whd5e9fFFe
         Niwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502451; x=1701107251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x14+J3Ijehr7L07qvLSzMqORvr79C3XHAMPXrH+JU8w=;
        b=Y5QQxWkyLwsqNhMspoMpV86pJ28YzxY05hkMGSBVpVZoYb4AuyRprnUgBoQDGTjm+q
         aaB17CRRQP4BcDtN0msChdAJT7U2O6fNnOvQgWs8lRJ0B6a97C4eGgMOAIuvHCfKNFNJ
         uX44/G8CBmODGBLpfm1QfOKTYtAPLm9OPFGHFa1K7eNlyr8WGOgJNMTs98IC6WiziIT1
         AVrIOUUTUSWgebkrT20PEAqVpnUQ/dlfD99ZdwaXkumxKO/5JyzEG6Oru62sdzT8T2Yt
         JrFfZJPwWp7TlXUwl29Rzs+b0mxG+3HROHv/cn3p92arJKUuLbkROvyvY0zHca+0A/4D
         R1Og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxCaj62ECO2+nXMwvDrPM+qiA0lvsFRl4Mh+GWeKC0wnkd/YYxV
	DKF2qn/d+PNYpD26l4FcGzo=
X-Google-Smtp-Source: AGHT+IFVx5gnff7yz65A8eH8heH1/7jMUhHAhpyQc2rOrNiYmX3kYoa0/89UtAT5KbWZf8g2qqvJkg==
X-Received: by 2002:a05:6512:401b:b0:50a:a7e5:eb93 with SMTP id br27-20020a056512401b00b0050aa7e5eb93mr138197lfb.2.1700502450607;
        Mon, 20 Nov 2023 09:47:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:83c6:0:b0:2b9:b171:d776 with SMTP id s6-20020a2e83c6000000b002b9b171d776ls842230ljh.2.-pod-prod-04-eu;
 Mon, 20 Nov 2023 09:47:29 -0800 (PST)
X-Received: by 2002:a2e:b0ed:0:b0:2c0:a99:68e7 with SMTP id h13-20020a2eb0ed000000b002c00a9968e7mr5565734ljl.19.1700502448834;
        Mon, 20 Nov 2023 09:47:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502448; cv=none;
        d=google.com; s=arc-20160816;
        b=TUHV7nWnAXFOAFgeKoK4MONU96mCDxZmvW9AXOavZZD+vcLu6PP9ZcKL2StIBryL5z
         tMQHa/hQShvSvGhXxusrvSR3U5XNTfX834VRVKYwFS+h5GzToOma1hYLYhvx0UpZ7tE5
         Dre4QTIFaMIgbxAz52iiCxQ+OIKLgBu3Bkw+tj5gyEY1A7qN0+bJRr6McGlQvg5x2vwO
         kDp9j5QraOPrturYWvYCjHjoJgp4jCc5a4OLnw5udaJJ4ONEX6yhvZn5je5bxiMze18R
         EXu54WenBz34hCewiU52j8teBzOMO+mfwz3LRweDu0IORluLiv/dRfRR8n2j8pQaEnwO
         JOPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VQKv8ipVyqmLqtwmF3tWarfk+ElO5xq6wgwn4qj22hY=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=KuR9wIPn0jlZfluP9EeAFzZjsvAzpT7NxaywxzyXzxsrYZ+EKaZEOa5L6+g34k270t
         CaAd+dk474Wl6igXyXJk0U6bJMitGvkLGwLJj6gu01IopRVLwqqT7HzOEgddIEsbdeji
         tbS8d3hAFQLZJgLPOZ0RE7gkv/03qVloC31991gEPPmTzG0BTY44uvXYL7pUeDCl69za
         S0SpniGPb/pgH6Ci2y5vy+Jzo9Kzpygt88OpKL8rf5LQkUEnZ28F5ElrCTQl1GsODQ49
         p8vynjdaGdyppg/wJp4SHFcz3gX3Z6VUCg7u/m7N7/yMjtAyJx/+n0GCv6hAYcet9814
         AOIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DpwTRKlG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta1.migadu.com (out-183.mta1.migadu.com. [2001:41d0:203:375::b7])
        by gmr-mx.google.com with ESMTPS id bg22-20020a05600c3c9600b0040a25ec1ce5si709947wmb.0.2023.11.20.09.47.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) client-ip=2001:41d0:203:375::b7;
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
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 03/22] lib/stackdepot: simplify __stack_depot_save
Date: Mon, 20 Nov 2023 18:47:01 +0100
Message-Id: <3b0763c8057a1cf2f200ff250a5f9580ee36a28c.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DpwTRKlG;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The retval local variable in __stack_depot_save has the union type
handle_parts, but the function never uses anything but the union's
handle field.

Define retval simply as depot_stack_handle_t to simplify the code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index f8a8033e1dc8..3e71c8f61c7d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -366,7 +366,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
-	union handle_parts retval = { .handle = 0 };
+	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	unsigned long flags;
@@ -383,7 +383,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	nr_entries = filter_irq_stacks(entries, nr_entries);
 
 	if (unlikely(nr_entries == 0) || stack_depot_disabled)
-		goto fast_exit;
+		return 0;
 
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
@@ -449,9 +449,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
 	}
 	if (found)
-		retval.handle = found->handle.handle;
-fast_exit:
-	return retval.handle;
+		handle = found->handle.handle;
+	return handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b0763c8057a1cf2f200ff250a5f9580ee36a28c.1700502145.git.andreyknvl%40google.com.
