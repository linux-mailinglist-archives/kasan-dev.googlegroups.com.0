Return-Path: <kasan-dev+bncBAABBG7JTKPQMGQEHHPJMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2337A69291B
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:18:20 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id bp18-20020a056512159200b004b59c4fb76bsf2716936lfb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:18:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063899; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q3MCMyDfD8ykAAfVCQ6Oa+t/xA7SfIqse3cfwxSpUf2DLgYEn+fPnnQD8Y1edU2+Df
         NTgjdklx0X+mvbTDaAC/AF/lULRqLMMX+fGEX4YU9bm34aRIIkTuPOEFp9nUd7PMPCWF
         G25tciTjl8wKOa56xeOHdG2GPjKLAVb83yxd3KbZUNvMJTc4JcC/9W8ZVYEfT8dTnekq
         XtfdEX8thxjM+wB55AbWghtgXMT8YCMccXkAc71wpzDlNr62pfoU2Kw3d7BFUPj1Nju1
         551ER2Eib/1MzBQmMxB1SHtRtBABGiCnCLuT7AvzYLXQ6TkK5wsZlQm4aOYsSgTjhoyA
         a9BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hx6U9dqq01GnDL+leGUdtayefY0UmAjZKO3PRnlAhoA=;
        b=JHcgW/BPMIXRGagh+Ahtzgl9vIENBCLGkJg0qORGW3TDDemMb3E/vIvGIWTfmqKBq5
         hmfCKuQkXjIODvvxlJWfPxFlw9fd483KxKqbOLSiDnxqmK/jqSx1GNHFGlllGH2Df/gW
         QWxl/UmtNMDIRfHZ8AAfjdtVmMars55EnXLhBCJ4TgQv9eTUM6CBhutxjSR89oWYummM
         rTpsIXfg2iCkiscu/J6w/GatQVM3GoCk9yfTeag3ik4p8++unDzh10lefLAwuiM3NsMm
         hi9VqYYSt9SZABkMXW6GNXOu2ckZoWJ1VbTmc3FSHLPFviK0T/u0eHwsxtDqbW7b77Kw
         3duQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="sVBTl7/5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.142 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hx6U9dqq01GnDL+leGUdtayefY0UmAjZKO3PRnlAhoA=;
        b=YaEPDaLvtfKWJ0Wlc9uMcue8UQooba+c648+gMZ6veZ6ug+WHSTXopKkbzAsUcNuOG
         VYqtVMSLNbVVoFJiDwCQs+ko0v7Z0yZj7oUGq7IIoggQcliBq4iQ7H6RhfatT5bQV9zc
         m7eT+dptEyg7vwnorlxJ26jY68aYR/NDupBip0yLXyRqNgissD+xpGvIjUgtnxjusQPj
         vcRdV2Z7ddBRXp6j5MBMjLnewxHh2y9l9pM8218+JM9s5Byg9xj2P8+NH6jSb5bpkZR1
         A/BCZGpog3cLrkCOAZuiFbsYf+XcB4j3uAkO8+jg+ruj3W867y5+xRXPnbL9AX6apPXo
         ZBbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hx6U9dqq01GnDL+leGUdtayefY0UmAjZKO3PRnlAhoA=;
        b=N7GynSsV2EamaxutKThzgDuzUVSxB8ECtmcHB6Ya0drlYgK0vY0lPoHt4FaJmzA6pq
         HXj1NEvQTXdqhc8eYhzEymEN6oOf6DnSjfHMo7EvEwDGOmx1U5jKWbaDTXzxbyC38bg+
         +Bi9iv+52JUu/l+0TLFxuebmXvIemvtjo3gOqO2myISVe1j2xrICyCsESO7NTfZZARVD
         PuEdwroFOpakSZCFiKOCLVwEwgew6i/ZS03pzR54wLJViC68CmYpZpLTpeXCOT7oyxCJ
         DI7uRujx/da9xjFVmTy0U4b1RMz1+7KvV2HrBuqPBsGvo9xzM5Yld3Br6WJ8EjbV/0ec
         SC/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKURn7e35IvkwIQwiRN15f4H+Ip+w2/k8+Ui34Z+uf4/AqczxMyg
	uTiUyHjcb5R9riiFo+kOhnM=
X-Google-Smtp-Source: AK7set/ry6MMnmvQGxsa2nDsjhZhiZSYYDhupNeCFx6gMpG1BDFJVP29W6RVK9TRBWjqv2kz687uZA==
X-Received: by 2002:a05:6512:25e:b0:4d6:f432:23d9 with SMTP id b30-20020a056512025e00b004d6f43223d9mr3080612lfo.111.1676063899648;
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2526:b0:4db:2bf0:d4b5 with SMTP id
 be38-20020a056512252600b004db2bf0d4b5ls1471175lfb.0.-pod-prod-gmail; Fri, 10
 Feb 2023 13:18:18 -0800 (PST)
X-Received: by 2002:a05:6512:398e:b0:4d8:86c1:4772 with SMTP id j14-20020a056512398e00b004d886c14772mr4417027lfu.7.1676063898740;
        Fri, 10 Feb 2023 13:18:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063898; cv=none;
        d=google.com; s=arc-20160816;
        b=GYPP092YaI6w2KUSHgfsTg77w5eTtywSNHGNDrqSuDBAm3w+hViMh/zAuKGESygBxd
         1i17yd5kY8bCbceHnOJo//w/PS/wb2dCfP60gP28jQ9KFrgbTvjIRWGwbWnTLCND7eXS
         imjXzFl20wPANsYwS7Oyi8avoV87cHFbf+d4NOaL7dBiubbztEsatoP3QhnhWAmJkDGv
         P26q/acuvpeh6heVV1auQgZOshNe17Tej+8BRi6MMWoSkgltmLPOzx2BnM4Gy09PMlpZ
         dbIoNY4OKapkRtWgd8gpQmI8UWJDF31h1Yw0Iizx86yW7bDeG2Yu0g235XPnenSbawzP
         BYTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pGvDrOxyRt5kOFDmqXD5ITBuCpaHJonxkPgV6Sd4X2o=;
        b=qRP7ez/DC4mFBjlauM7n9PIee8ri7E9CbHfCmkG4iSvx8RwwMcgbRcZC5gjId6Z5aZ
         iMfq6j2C8fUrKWlABlKtE5PbLamfmaz0QL/lCYwFpsrcFH/mKnVnk/PV4NEbnBEtCNto
         qx6jhWTTKZSj3oKmo1ba4jHrLlCWZaRskFUFc7bTp2PsgKUrx/FaAmYfMAoA3gsWuUD2
         sZB5Z4M4R2xLhwPWtyhtfESOOnqjfWyhfg0CVGCeKgZvYPBlU4lMJBOpflVIYJtxeJv0
         0taT0o2guyFbQBdZjiNU2/oolIIu/RR5zaf/hOGfOr9zp5k09SGHy7F6dSLsNoNrZRcq
         cV7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="sVBTl7/5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.142 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-142.mta1.migadu.com (out-142.mta1.migadu.com. [95.215.58.142])
        by gmr-mx.google.com with ESMTPS id w12-20020a05651204cc00b004ce3ceb0e80si327966lfq.5.2023.02.10.13.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:18:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.142 as permitted sender) client-ip=95.215.58.142;
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
Subject: [PATCH v2 13/18] lib/stackdepot: annotate depot_init_pool and depot_alloc_stack
Date: Fri, 10 Feb 2023 22:16:01 +0100
Message-Id: <f80b02951364e6b40deda965b4003de0cd1a532d.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="sVBTl7/5";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.142 as
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

Clean up the exisiting comments and add new ones to depot_init_pool and
depot_alloc_stack.

As a part of the clean-up, remove mentions of which variable is accessed
by smp_store_release and smp_load_acquire: it is clear as is from the
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 34 ++++++++++++++++++++++++----------
 1 file changed, 24 insertions(+), 10 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index d4d988276b91..c4bc198c3d93 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -218,32 +218,39 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
+/* Uses preallocated memory to initialize a new stack depot pool. */
 static void depot_init_pool(void **prealloc)
 {
 	/*
-	 * This smp_load_acquire() pairs with smp_store_release() to
-	 * |next_pool_inited| below and in depot_alloc_stack().
+	 * smp_load_acquire() here pairs with smp_store_release() below and
+	 * in depot_alloc_stack().
 	 */
 	if (smp_load_acquire(&next_pool_inited))
 		return;
+
+	/* Check if the current pool is not yet allocated. */
 	if (stack_pools[pool_index] == NULL) {
+		/* Use the preallocated memory for the current pool. */
 		stack_pools[pool_index] = *prealloc;
 		*prealloc = NULL;
 	} else {
-		/* If this is the last depot pool, do not touch the next one. */
+		/*
+		 * Otherwise, use the preallocated memory for the next pool
+		 * as long as we do not exceed the maximum number of pools.
+		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS) {
 			stack_pools[pool_index + 1] = *prealloc;
 			*prealloc = NULL;
 		}
 		/*
-		 * This smp_store_release pairs with smp_load_acquire() from
-		 * |next_pool_inited| above and in stack_depot_save().
+		 * This smp_store_release pairs with smp_load_acquire() above
+		 * and in stack_depot_save().
 		 */
 		smp_store_release(&next_pool_inited, 1);
 	}
 }
 
-/* Allocation of a new stack in raw storage */
+/* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
@@ -252,28 +259,35 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
 
+	/* Check if there is not enough space in the current pool. */
 	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
+		/* Bail out if we reached the pool limit. */
 		if (unlikely(pool_index + 1 >= DEPOT_MAX_POOLS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
+
+		/* Move on to the next pool. */
 		pool_index++;
 		pool_offset = 0;
 		/*
-		 * smp_store_release() here pairs with smp_load_acquire() from
-		 * |next_pool_inited| in stack_depot_save() and
-		 * depot_init_pool().
+		 * smp_store_release() here pairs with smp_load_acquire() in
+		 * stack_depot_save() and depot_init_pool().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_inited, 0);
 	}
+
+	/* Assign the preallocated memory to a pool if required. */
 	if (*prealloc)
 		depot_init_pool(prealloc);
+
+	/* Check if we have a pool to save the stack trace. */
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
+	/* Save the stack trace. */
 	stack = stack_pools[pool_index] + pool_offset;
-
 	stack->hash = hash;
 	stack->size = size;
 	stack->handle.pool_index = pool_index;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f80b02951364e6b40deda965b4003de0cd1a532d.1676063693.git.andreyknvl%40google.com.
