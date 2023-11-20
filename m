Return-Path: <kasan-dev+bncBAABB45X52VAMGQE52Q5K6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 583537F1B69
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:36 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c6f3cd892csf43931981fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502515; cv=pass;
        d=google.com; s=arc-20160816;
        b=gmv8YmIbz2Mn9CCT+Kp5AMi8jgMPj6bzUnSt5YhoKjSX4n5TMCHL1F1ppNg4Zkkqzo
         RqW+duJCUKkaAtvqiL2LLo90q0LB3lvyjXeGcq+P9n0r1Iu0Se5Y5zMCHFbGeJRhb4Ha
         f23xiwyZKxqCckr+8jjqxy4mcWlPPGVs0Ibny9KId+0BzcSrGLI5TBqqqKJbGZ4kh1Oj
         GLvDGIjx5Fw52gO8jk9nxYkAZCPxkzcl8rwAT1ROwCfMnpF7efc3QPfvxmsSUWJFNEk4
         qrFcUhHJWBr8Yyx4MaeWcCZ2C50pqRJaJfnP9aKunbm+x/T9MTx99nxXrzRTJRwNYekX
         Kmdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8QhUiATtBrdbdziAsdEDLLO3K4thu7zqDYnO5JBHrZ0=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=a/QaAjRA19wdvmRJIx7N//CgrOcwg8E9/jo5lLrPkXYJPuT+RQSwafkjvba74Bx4s9
         1kJcs4jGaR2btXMj8r1YzHhJdXrJthUeB2XwTE3IO/HyysvbGbzC1vgzC18W1FqIVV6J
         TeX46G979AwWLk8vAAQhVHB3rtFaRQwu+5cSMkhmRog3NElMeugcFrs0GSwYHmTj3YKh
         fmlYUyFFMwvMBxGDwE7HEJr1s3rHd9NkfkHVDnyWLpUjlGe73z2BadIq+hDfaARdFdGZ
         GwtkaWegCLWlJsdF2kPIl6FaFD4uJvWFHbsNyba7SIj/1F4nAKPwz8j3qRXPwOEGUZBW
         WAxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=v29OoaCr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502515; x=1701107315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8QhUiATtBrdbdziAsdEDLLO3K4thu7zqDYnO5JBHrZ0=;
        b=CPlzx1XkTjRbJNsQqz+EagNrr4B4xVsLkG+fujvUzahvoiOfwuLxxnDEczb++w06fP
         qWM/nWbnxQnZ8LKZhrrhGv55Kim67ykUtQMzu0bzyCNS1WdrpY9UoTDNCkNGv5qSUNdr
         MTwpkitPfkiphEjQqlnKZ+uMrwOaCTnz6oJHjr49CAYF0ii/s7jO4gHh5kJQCPGELbRZ
         HkbTEow0GZc/dSSXQz643/hJXRE9AbdxENi+u+2P6Gqx+DbR4tw9m67R6ETOPHL0+Guw
         CiS5p4VkDk0ekW/bjOzejRJEJBJ12nnkslnIQXKNQ0rmU9UaVjpDOLxEdzBEixt+JQ6U
         WiRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502515; x=1701107315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8QhUiATtBrdbdziAsdEDLLO3K4thu7zqDYnO5JBHrZ0=;
        b=GqzY3WyiYcvcQcNErlHG2lPtpUK7LmMl5i/U7COw5HXvP558Svhcw9qQVaw4VPervH
         p6hB2dVTDNmOdEwc2X4G4wYHUYqIj0i96x+Iwpvm82OCCNvmPinMrRPC4iO2FMoCD9te
         HvoeQGq71hpmVWIc2KNOtuXVD8aepKTRWAQ/EAIZwF5FLnLW8NSoaS38AZNvumKM2Fe4
         y7Zh9yz1BbTzznKVTYgEk2HW+/wgFxmC95BYKoC4L8G0eDKgL99yrqGcZNmx11Uuc+k3
         ASCWBwgiXLt3KTKJS9gbZhilJXiG9oLp6gwwsidPamilI3iGCSYh9proxLsqcQSuSS/Q
         cLbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywth69y1Uhf7MQPgfv/oVjipuc9tX2vUTF0x1xTG/qzNVUHDnG6
	66ZHw8CVCo8STG6LtdWfA1E=
X-Google-Smtp-Source: AGHT+IHnACzKUY5MfJWAppSxkRvAyxK6r9EODTOc0O8rGYGvQP+ozKvhgA7EaV3NVm7rabJMOJ3fUQ==
X-Received: by 2002:a2e:82c1:0:b0:2c6:edfd:658e with SMTP id n1-20020a2e82c1000000b002c6edfd658emr5369220ljh.52.1700502515253;
        Mon, 20 Nov 2023 09:48:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:83c6:0:b0:2b9:b171:d776 with SMTP id s6-20020a2e83c6000000b002b9b171d776ls842488ljh.2.-pod-prod-04-eu;
 Mon, 20 Nov 2023 09:48:34 -0800 (PST)
X-Received: by 2002:a05:651c:48c:b0:2c8:7173:6123 with SMTP id s12-20020a05651c048c00b002c871736123mr5600215ljc.32.1700502513675;
        Mon, 20 Nov 2023 09:48:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502513; cv=none;
        d=google.com; s=arc-20160816;
        b=Q25Bad1AJzDDJIIKbv1RlJIZautK0J5L6p1BMij+QShz4ep8LLY9qqB4reY8KKcKP/
         JEftGYhSRUJcWcei+bJf3cjtrCxBa3xWpWR9vjVTt0wiUg9SHBK9J+20lTnZUfb+VZJh
         H8Se2bCrQ/6Ady3xzfWf3mLcFnBAlWtNjoyNMaDEn/kPIE2JTHo5To5hbVmkQ/pyg1L5
         KlwbczETbOjVU1Ue3vkiIGPCrkq3AojPT7zSdqyPMbhVUxwniB05fnoN1CiTiu7HRUXO
         FibnxS4n6QUHCzw8LvOznE3nUToqMcaXAvnEKEECHG4omekItqrl+QvBFh3w4lcO/dvz
         MAvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pu1XFZGC+3mxYm/tNoBY6t9qKRkAeXfQVUMTHQNQJK8=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=fAzIlnhTeCEEpTCADFnPMZT1DulR1L+oojjGhOaIlwojXEs7nuYRMOrgj3noYO8ZLo
         0LSPDe5/yFObjt1toqIV49J8LPIi1tjUZSTBSWpvyRfwgSTdDxPA0XWRSK41MYey7KZZ
         Bo5O9/ccYFq643QnAaA+I2CzRAihd6ot3FvfrSFg+j9CVjYeWQbLLQ/dd7DJCqOtSQ9C
         sbyT/R8t1+tBmZ0BK00rnWpHmkjkDmUdBqtEcibuAm6aC1QnPnyblALdrYAvonY3POnV
         BqdwY1u8Utnxklm/0Ek+Q/oGxGmXXH7qrxklzj8XLqAl6mYFnsizfku8IO0gxIdGFm2v
         yFSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=v29OoaCr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [91.218.175.185])
        by gmr-mx.google.com with ESMTPS id x22-20020a05651c105600b002c12145a0cbsi308128ljm.7.2023.11.20.09.48.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) client-ip=91.218.175.185;
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
Subject: [PATCH v4 06/22] lib/stackdepot: use fixed-sized slots for stack records
Date: Mon, 20 Nov 2023 18:47:04 +0100
Message-Id: <dce7d030a99ff61022509665187fac45b0827298.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=v29OoaCr;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185
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

Instead of storing stack records in stack depot pools one right after
another, use fixed-sized slots.

Add a new Kconfig option STACKDEPOT_MAX_FRAMES that allows to select
the size of the slot in frames. Use 64 as the default value, which is
the maximum stack trace size both KASAN and KMSAN use right now.

Also add descriptions for other stack depot Kconfig options.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Keep previously existing Kconfig options not configurable by users.

Changes v1->v2:
- Add and use STACKDEPOT_MAX_FRAMES Kconfig option.
---
 lib/Kconfig      | 10 ++++++++++
 lib/stackdepot.c | 13 +++++++++----
 2 files changed, 19 insertions(+), 4 deletions(-)

diff --git a/lib/Kconfig b/lib/Kconfig
index 3ea1c830efab..5ddda7c2ed9b 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -713,10 +713,20 @@ config ARCH_STACKWALK
 config STACKDEPOT
 	bool
 	select STACKTRACE
+	help
+	  Stack depot: stack trace storage that avoids duplication
 
 config STACKDEPOT_ALWAYS_INIT
 	bool
 	select STACKDEPOT
+	help
+	  Always initialize stack depot during early boot
+
+config STACKDEPOT_MAX_FRAMES
+	int "Maximum number of frames in trace saved in stack depot"
+	range 1 256
+	default 64
+	depends on STACKDEPOT
 
 config REF_TRACKER
 	bool
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e41713983cac..682497dbe081 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -58,9 +58,12 @@ struct stack_record {
 	u32 hash;			/* Hash in the hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
-	unsigned long entries[];	/* Variable-sized array of frames */
+	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
 };
 
+#define DEPOT_STACK_RECORD_SIZE \
+	ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
+
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -264,9 +267,7 @@ static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
-	size_t required_size = struct_size(stack, entries, size);
-
-	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
+	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
 	/* Check if there is not enough space in the current pool. */
 	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
@@ -301,6 +302,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
+	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
+	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
+		size = CONFIG_STACKDEPOT_MAX_FRAMES;
+
 	/* Save the stack trace. */
 	stack = stack_pools[pool_index] + pool_offset;
 	stack->hash = hash;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dce7d030a99ff61022509665187fac45b0827298.1700502145.git.andreyknvl%40google.com.
