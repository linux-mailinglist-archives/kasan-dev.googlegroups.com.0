Return-Path: <kasan-dev+bncBAABB3W34CPAMGQEU3ZDXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A35E681BD1
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:59 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id b24-20020a0565120b9800b004d593e1d644sf5899947lfv.8
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111918; cv=pass;
        d=google.com; s=arc-20160816;
        b=wm5awH4EkfLEIF4EEsu8V7u+YKSv5iAEO9zEWR3wVA6Gc9FxbZsfSu9nYyScOxaEdk
         enEOq4P0F+BKgbBeaiBIKF/8wykKqRLr7dYwp7VfwS8lG7GUlxcLIKOcO7FUE/eA1VPm
         TPcO/axxERjBrnMqH5fFmA+SzA6aTUrd8X4QEY9l06ShwuWl+Elw/DI00G59sf1JicNp
         VJ9ZJwtkS2uQesYUokdPOth4+3qPCNoI4hoSmAO4fjjrICVIOyte1clB8f+2YqwHsIuo
         uZTipg14htWKY3Yxw1G+RBYzwMMr1QmxgqLxIivQISsxpWqSURI3Dl5zLWBcncn/91Ev
         81dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VVmeCeKlPrh/Nkq0/vrxfB0LS1OHT5qiJbm6OUNeGX4=;
        b=vslpg1VQDmvZEa3wCRu6fo3UmDaD1xmr+5vNMLbLJzDqZsfkkWRkXcQav7wOMAJD17
         Z2guIwPD4Q2fmFmO0UGlNy+CogwfYWfyPXZ2EyVc4GRffAtPHSpiSL8/A182rVdKVfXv
         CCESPNumel5K2wmP46fHsDXsRQkZUNNUSRIQe4zG6G1geCdJd2PHyk4ws9FUJgtZNUP3
         lXS3wX+QAJQv0vfKrqPrvo2moOSIEaBF+HvUzAOshM1AXnevR+bwFOTU2sBjKfVXcqOS
         PJ/d5ilHOhmO4GbubCFBCV983+Y1iIgcrxo3NwKtVwkl6l0kzKGpFzKvyRnm93H5Pwld
         iMuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wXtDfrkY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.191 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VVmeCeKlPrh/Nkq0/vrxfB0LS1OHT5qiJbm6OUNeGX4=;
        b=DUO/0JuaP1/KLEL+12F0Qjjd5xCAsQPj5slpiPoNWoU5NxMVww9aGHCTqC/wInKbX2
         Fqgk9SwhGtS+wE2d9jcmLS75y1X/3rfNPNNgKPzWA52hPiju/8JWeAz+TNLrdUI35qDC
         vEu3BBU2+PBt3wPSr4LKSHRN6IQT7SlabAlUnzZjE/4GUZO+CS2dHXqXyMIlM04M1oLI
         hFGZXsqXrpsoLZi1beFGC9iC3aqfxU3M0T3E3J087k+GIexXRz6FArbbLcq/OZXbue1g
         VO4UnyyUPls9jSfUvYCzYGwtOgvBiFYzFQzoqP4JAf/MvFixXokMhkc6RSC8e8CpocM3
         arSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VVmeCeKlPrh/Nkq0/vrxfB0LS1OHT5qiJbm6OUNeGX4=;
        b=Kje52lfZ24V0CBc4Xx/UJM3FBdmoI+oamcIeyreuIdEfQFjgqH74UVGfECcBeiJmO0
         5LCUaUucNjpJVdWz5N7YRDVsBsp0KUjrBtYjPGeVnjDMqvDSjpjxqbet3pNIWUkaHNqx
         97LVAjVMtu0HdSSK2ghcdGBRLFUHHdKSle9j5ularQ162EI3hoq4Hf6lLF5Miyno9DrE
         3FUZ7GO1bvltf46N0sWD9kDWqaR6YunlWEyPa/vJhBr9LN5/78AGQFVT6dgFXy9JDF0B
         yPevITT5V9UHlDllHc5BE2iXwi37B1oIsL2d/fOe3YZoT+D/OrzY1K2C+gDntJ3lbEix
         XoDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq1IbuFdFJLzSAEJdYHH9YoEYlhnhrWhurH2dUVgCt9Oh4Sd+DC
	Jy+PY5636im5MY48gAxlqpo=
X-Google-Smtp-Source: AMrXdXsu5uqeVomL2GqDm6lFqCearoe0Zfr9QO0o9WpQVw2WDbvdxcLPjdY/aV7mRuz/gtJEt+lQMA==
X-Received: by 2002:a19:f506:0:b0:4cc:f829:6698 with SMTP id j6-20020a19f506000000b004ccf8296698mr4901782lfb.40.1675111918475;
        Mon, 30 Jan 2023 12:51:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls762741lfc.0.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:51:57 -0800 (PST)
X-Received: by 2002:a05:6512:159:b0:4cb:3a60:65cc with SMTP id m25-20020a056512015900b004cb3a6065ccmr11206658lfo.5.1675111917424;
        Mon, 30 Jan 2023 12:51:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111917; cv=none;
        d=google.com; s=arc-20160816;
        b=gxwg6rOtlJMVyYICMIBFLfc5tbr9nqHhriJkwjaARJHuMqJPpTwr/t+5m5wUzm6fRd
         H1M0amn/0jXJvr8den9RN3JC8LWH0FuMJYiP19O2tJg6QeqRL8krrlSjDhOXU8n3LgNZ
         LmA60e+gpJKt9OGt6xLmBTRq5neqTFvJwVNT9TiHgvxQrp6nbEebngFBITYXbqMrOxbn
         00cB8B6cAR3v+jBb5S1nqqOt7nVkf7XpEk22cYuFcZRlqefp8GMpFNBanH6XTh4dCDl+
         U18yabaZFLo/DeMca9JDeT+mAvQ60NX2Sd2OV2aDGVnPwCCbf+z5/tL7y9S5Q1XJSuPP
         /wFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HatpIAXF9ywMATjIlRO5zkwkJoWVcZESn/qWFP01cUE=;
        b=OldPH+SY4mvHCWPzq6i3wRdqE8lkSCdHecrWgQz3n0Vw5rgRm5MxvJ94kgxAOBDNki
         TON2n1BqEOCbvFlJC3ZFgfucER7IZzMvpG55jUhOb0XQhzqKicYMDIR3XoYi5sXGVPLL
         wpGBzKwB+DqbQXfF9o+W5C/Gp0Ynjx8vzj6dSG94UI8zmPdUb+9rqDBFY+iubUzgIN6G
         +A3Wd1nSX2797c2c8zjJVXaMOOAFLfjPr6w6XIKnCH360Zfc6PkjdxpJj1NQQ3BtFa/S
         EbSTGONCkmS8+GvZp6jrc7IxyX8WVGav0h1kQueVJtRTWxsUc8kbqClrOtlp94lpPinm
         wcEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wXtDfrkY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.191 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-191.mta0.migadu.com (out-191.mta0.migadu.com. [91.218.175.191])
        by gmr-mx.google.com with ESMTPS id y5-20020a056512044500b004d579451cc2si775213lfk.12.2023.01.30.12.51.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.191 as permitted sender) client-ip=91.218.175.191;
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
Subject: [PATCH 16/18] lib/stackdepot: annotate racy slab_index accesses
Date: Mon, 30 Jan 2023 21:49:40 +0100
Message-Id: <19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wXtDfrkY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.191
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Accesses to slab_index are protected by slab_lock everywhere except
in a sanity check in stack_depot_fetch. The read access there can race
with the write access in depot_alloc_stack.

Use WRITE/READ_ONCE() to annotate the racy accesses.

As the sanity check is only used to print a warning in case of a
violation of the stack depot interface usage, it does not make a lot
of sense to use proper synchronization.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 13 +++++++++----
 1 file changed, 9 insertions(+), 4 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index f291ad6a4e72..cc2fe8563af4 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -269,8 +269,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 			return NULL;
 		}
 
-		/* Move on to the next slab. */
-		slab_index++;
+		/*
+		 * Move on to the next slab.
+		 * WRITE_ONCE annotates a race with stack_depot_fetch.
+		 */
+		WRITE_ONCE(slab_index, slab_index + 1);
 		slab_offset = 0;
 		/*
 		 * smp_store_release() here pairs with smp_load_acquire() in
@@ -492,6 +495,8 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	union handle_parts parts = { .handle = handle };
+	/* READ_ONCE annotates a race with depot_alloc_stack. */
+	int slab_index_cached = READ_ONCE(slab_index);
 	void *slab;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
@@ -500,9 +505,9 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle)
 		return 0;
 
-	if (parts.slab_index > slab_index) {
+	if (parts.slab_index > slab_index_cached) {
 		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
-			parts.slab_index, slab_index, handle);
+			parts.slab_index, slab_index_cached, handle);
 		return 0;
 	}
 	slab = stack_slabs[parts.slab_index];
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl%40google.com.
