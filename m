Return-Path: <kasan-dev+bncBAABBNWL3GMAMGQE46PALIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CCA55ADAB9
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:15 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id s1-20020adf9781000000b002286cd81376sf845128wrb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412215; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZrjQJgFiLeRUqBGCqgL4prSvQGhZeJ6x8AuuRAZUCb/jrtxe4s68BVSfVPUUt6155q
         NXQamq2j+kBma0gWG6k7eSlMmAsatMATPBzsR6Ggm3771b7e4QKMI7nCXIwvQH8JIFcE
         knB6xH++iuBFD5XgeSmKvFN888HallgPg384UMatnCC8/Csrx+G/vGdKM5JB6eKG0XMM
         EkciaU9AEVR9/aNmNTsD1FxU1/VSGZ7MxPO1ZPoh+Ro9+sh2Fx7wdb89IR5PEY1itZ6W
         g66DNACrvVChK07D69966nUzchYhhlp8/MkMCxQwyTUS5hGY0cbX4q4CTGF79rR0ISoM
         PwOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T4strdofYdEsNHgBOdNrmS/NXavWfxWF8/kgzSqVoMM=;
        b=SamadXSRKq61TThGUg3OLctLKO9TvEfN8shhSu45ZGW6i3KKNa/Pv3aqZImVeUU727
         J4o8Rx66Z5eGDav1wHA4oV7tyBfCkfFBAfHvmw9etIocOy2G7ynTJ45aQxha54568/Mb
         cGsa+IHZZGc7Q3kBU2XyUX2cNKwCXjtvuXnVgNVHSEiyNRIXXx7vI5f5kczi35EyKaA2
         234lTcSm26l5gPn9OgPJItHPyBULEXd1YBpA5H20i3jKGvXnt7w+z2z3nx3aJ9UF4Nl7
         Q3RaNFLdnR37SKKXaGS1mKpBbi+wPvcAJS6CTSvx1MI4u4o45DfkbYWGqCUQNjrDyO91
         sKqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sl0b0kWx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=T4strdofYdEsNHgBOdNrmS/NXavWfxWF8/kgzSqVoMM=;
        b=hRFzFHq2iIYRjGr9pXjCOXeS5derwB815y6RDgPxCa0KPDEer5oen0f+v5UJ8Xl2+I
         ZYxb3itiAADllhZC7GRE+ulaiATu4pljhCEBEdxSwb4gwKi6yTFRulYhQqn6FQaPdOl8
         ksO6TB7VcSpoNtODHyBgtitzHe2oB6aPc0LXRZJAPkW4DkrhlMxf12MLXiEHIw0Rx6jr
         vJHzC2ooQl75creOEoT5PaFc8vEmjJZKq+CvYSY31EaH7mKHjc2hZTr6SoO0mTnohFBw
         sDYUoCGieyBT0pue4ONF2E6Eo5Fh4B8USP77LolGkUGnA5G25hhcKWbqyqXCE9/SQlpJ
         ajzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=T4strdofYdEsNHgBOdNrmS/NXavWfxWF8/kgzSqVoMM=;
        b=4GOXkcybkhiduGXdETKZMq1j4QXNfi0RsLZ8WYtUddMXLzaIQI/XmgxWHhi7Lpx9gn
         dzcJ7M3Qkm/a6b/mjGJQPus3NvIjiE0GCrBRKhPseiQDGgWe0EuTzej7IKE6O0R7WcV0
         ZfGfkVj15vnq79XqOnYaakEVNsQtC+RFfMZPgjL15lbaEiAe4OdoYTEJoV+gf5se78jM
         NiPhdlPtULoHuLwA3aKL7Q+0gziInvcC5NdlooFJzv0Z7uAFuVB2hpXaV0C0yGJgE8et
         49OLOmnGsT3EO3GQri34c8syb20zDw/R6xJU8Dxr0r6EXOBwfcmrHI8Xn3m8y5xYBXGe
         D/yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0qwsgypXEQBZUyfzGHHNmRyGrTGadqhoPSh1rhojzs/NrNt9kq
	6IX4eunb7XObJFogEur6w14=
X-Google-Smtp-Source: AA6agR6dVKYb4uUjkcYHpJNV2U+91UplIxYvOYgRd3IXx8aNgGkaXjKlugjPqDjBYYZN99zu74E34Q==
X-Received: by 2002:adf:ecd2:0:b0:228:6439:a24 with SMTP id s18-20020adfecd2000000b0022864390a24mr5183939wro.401.1662412215054;
        Mon, 05 Sep 2022 14:10:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6018:b0:3a8:3c9f:7e90 with SMTP id
 az24-20020a05600c601800b003a83c9f7e90ls5124392wmb.1.-pod-canary-gmail; Mon,
 05 Sep 2022 14:10:14 -0700 (PDT)
X-Received: by 2002:a05:600c:1988:b0:3a5:f47c:abce with SMTP id t8-20020a05600c198800b003a5f47cabcemr11849316wmq.121.1662412214441;
        Mon, 05 Sep 2022 14:10:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412214; cv=none;
        d=google.com; s=arc-20160816;
        b=kZ7ugJGx2uyrUGoPhiMOzPrjwQ/DDfjwdAFtNJne5jidnO8ilIi0SizH2Tuc9B7h+F
         ZtpSyPDsQCi75WIiuSbIgL1cSGKcsTUylypzh7Y2sYUhTLDggN55ey1yTxzZC+bgMmSu
         9XZ0COcfJy0fJbHDh2hZH2vcHFCF+Cz60MTdtgYmqL6OwB2S4LAzU/t52nCS9Loxeqbr
         s9KyMItyE+gLTGZ/XFWbvkIUJ2BWiGZvJqykgbT7A+bpy1XebexRblrTfRbTgVEPkgse
         fDSj90ekiJQqv5xC0mr546ISZ5nURHkiBivAKgG51eMwfuFzr4sCcwA76gHRTVSJ08kB
         oD4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oPxPsap+uxlNu3NKWwUVtxgClQ4bQ77Qpub3ubuEwik=;
        b=EVOV98fNC2WfByHDbH/W0S5y4Pp3zKI7QcqNz25ffgF016zxWnYoCO/SuKoBIect2p
         TGQeCj4zHp1DPO6CqDIg1P2zT1CsrKp9mxhfL/FR4sZeVGavceRjiYFEfpDVUU/T15j/
         pYTB641CiPnsnk4gMnZvHnYxoqbQ+COUW13jVQ6HaSS2ZflvYnN146WvyOmxRAn+M1dS
         QJr2miYbqy04MchlEeIblBSOSk8jN3KKnRfhAwjMgDccbYT1fMgk3FSdWGxznvcqE/yV
         l+HyNg35etBX3vKr4FVE/Y7sUmNVzgRom9fetg8LMZYSfVTD73gw3xa0nYeWW570ivSl
         3tCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sl0b0kWx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id n20-20020a05600c501400b003a5b20f80f5si829689wmr.1.2022.09.05.14.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 24/34] kasan: make kasan_addr_to_page static
Date: Mon,  5 Sep 2022 23:05:39 +0200
Message-Id: <66c1267200fe0c16e2ac8847a9315fda041918cb.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Sl0b0kWx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

As kasan_addr_to_page() is only used in report.c, rename it to
addr_to_page() and make it static.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  | 1 -
 mm/kasan/report.c | 4 ++--
 2 files changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cca49ab029f1..4fddfdb08abf 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -291,7 +291,6 @@ bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
 
-struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cd31b3b89ca1..ac526c10ebff 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -206,7 +206,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 		pr_err("(stack is not available)\n");
 }
 
-struct page *kasan_addr_to_page(const void *addr)
+static inline struct page *addr_to_page(const void *addr)
 {
 	if (virt_addr_valid(addr))
 		return virt_to_head_page(addr);
@@ -289,7 +289,7 @@ static inline bool init_task_stack_addr(const void *addr)
 
 static void print_address_description(void *addr, u8 tag)
 {
-	struct page *page = kasan_addr_to_page(addr);
+	struct page *page = addr_to_page(addr);
 	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66c1267200fe0c16e2ac8847a9315fda041918cb.1662411799.git.andreyknvl%40google.com.
