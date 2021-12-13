Return-Path: <kasan-dev+bncBAABB2EB36GQMGQE35WVZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 941B04736D8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:44 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id c4-20020adfed84000000b00185ca4eba36sf4153426wro.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432424; cv=pass;
        d=google.com; s=arc-20160816;
        b=sjvu6cxHgCB+kgUYI1+RttODUkvhXtXr417d/Zfu8+LTyY7JrmBUukoYJfw+1iqGnI
         4U+xs9XzRoa+Y+e7IGZOWT6EWXeUjaQcY+cjNRVGL7Fva8abBg1eokCYXaq3Hq4iWBpE
         rptadCR6r1J57QI7dzq79arIbuRO+2tRrJaRHSRoALV5yujf7AKgJWRoarvkNGjgFrig
         T23IhJVge2pGXrabl4XJW1NuAzbBWaBPyOWQgkrIaHENvH6ij+fQC6eTWiM5CDgOIAMF
         TadvI58I1WnW+KBPt0E5dZhY+rGsE+BiFeFCl05bfNcZ/PEKL6KBIFvdMszgbuiSiGQP
         jqjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0II7GNrjSEB8wJdbVeq3hULXBIieyJ3hJ422ChiMoCg=;
        b=GLWbyQyceJpygL2W6ujFtgRfgTudgkN+JJQCRGwaSPOo+oM5yLRM5rzBiryeFCtkxu
         ghL4hj2tYVi/EqbyZDoaeCE+MKLojH9l1v+9jBt8eQfhWnx+bm0WQZ4GntEMYnaZM3yd
         ol5xOQqiC8+ui2tJCMsaFr7seQeT/dQk+z3ii4qGbwIO4e9jx5CSQxqvkq3GUug09ojt
         OSndyngioxWqp5UtWwqrk24ENqehv5nMJP+OU8end+zkZIcrn2Fsk59WTUFVmaor4sF3
         eZafhkIsp6KRizTtU+/lZGwQOne9coVdv1t+KLFC1+CGde/6XdKQ1puAasJqcvgF/I6V
         BtLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VSO7sqm1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0II7GNrjSEB8wJdbVeq3hULXBIieyJ3hJ422ChiMoCg=;
        b=SUSLsEwpvIpN+lheSARol2jpbkCoeFjk5689JNm6QwKDTdb/VGTI8ktgRU0Qc3aOzR
         qSx1gPQKhRvO93P2SmrdegzRPN0bcSVy1JQe21w7wfljfPMlIbF0VlYl8srolsBbCoXH
         1i8xITPxb92LiLJ4wlTMLeC5ntII/gfJLaw/RJq7fsXWzpxa+TFeau5o7HYsMukz/R4c
         Ex09BFbQe4KyXsXjI+rdnQp42mLyV7fgeCuku4mQr08q/imL+RRwL2OFvpyOgl06X1hi
         map3T10BCPPsJuZE2cVnmfjirLJfgEnOBFOpq8Tudd0PKK3lbEsBWVHqUgcD956YpPW3
         mGWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0II7GNrjSEB8wJdbVeq3hULXBIieyJ3hJ422ChiMoCg=;
        b=X/BpdUDm6uYMGhjRJKRC0/NuN77ZIb8sRCJArkqBzCX8mTr9e/IDavCV2gYAwESkCk
         U65hfEesnIxIX3FS4vKSQg50D/5Z8CfPBpQEaIvbObfxzIO2nDVD55IbKz47ijXyC6Fc
         FcAFg7Fpj4XVQ1647dJGK4FCLt3VAJNwNKGnSIalrcapeinLLuvSm+UKqj4g6U+Q/aAI
         EFGuBRHVPzNhpVE25Q9TxwnSjf4UVJTDeF3vQ3rux85qhw2YRxhvuw+mMVLLh/IZvd6T
         i0Yg5ySb29o2uYdyl2Uza0Xl//rZpeZd4hY6jt8+msfn4MW2m2EumJSVCwROTiIUppzR
         nJHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304Sq1fWVJgks8Dsv+6aPSiHsJoooQ8hy5fF5PJeYtpdGsa+JWZ
	D3S4C8A0t0TupqpKUNDxe3M=
X-Google-Smtp-Source: ABdhPJwzodjphtzkw6n6AauSTCzgvce9RGk2np1Z/90WAXLaeI3lUViailEy3xTnKJGWtvU+6U5ywA==
X-Received: by 2002:adf:cc8d:: with SMTP id p13mr1243975wrj.274.1639432424380;
        Mon, 13 Dec 2021 13:53:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbcc:: with SMTP id n12ls93626wmi.1.canary-gmail; Mon,
 13 Dec 2021 13:53:43 -0800 (PST)
X-Received: by 2002:a05:600c:a55:: with SMTP id c21mr41055601wmq.191.1639432423576;
        Mon, 13 Dec 2021 13:53:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432423; cv=none;
        d=google.com; s=arc-20160816;
        b=hoMl5iRWTgbiwDLtVl8KDQso22yn6+Mr8vO+xtKNbFy94qptvqLhFS6o6X/9LdkNFT
         jAGTGh5wksBvCXOJLREbSQvF3SpSiglOuboaOxM3PxvlW1GO0OMzwNUVTLBLK4rD4W3X
         9+Ri1dMIdtakL34IrWZ2D6BFDAKBH8n7DuG8AGdG1PMEgUPrmlR6AwhzXi8xKsM7XYCi
         SwYFQFMTlINl8BjN/Y37vjseZIimQNh7cNjSrnJUpq0HUawMXwP7WpBnybEDrvRVt+zH
         ADQDivyNgrkDwCXK+UwZhWg2J2al1hS6ra+nqz55ZBFyVHFD9WJojkvu3Cvapwd3aoe5
         +olQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dOh19dmutFQ/pltDwA8i5MQc8W9IDJ9Ae5wPaYnC3pU=;
        b=F5RsBsiuE0TfMfoRcv4M6LOpFXFMkwdsCDFsDMMB71Y3FHRNVu3XwZEoh7Le6XVDPf
         6Tt5MjJYT4LlP/kKNFgJCoseAuEmAlrw9Nx+SpZuEqx8bkxjkDD7fqSCLhPV2xFD/W6i
         HCPvIX4EQJ0Wj7smhEicU5mlctLLtuYsufwdbCt9sb/m14oh4NE9c7tmLOt2vOSloxc+
         OPI5RfQAtf6JFpvNalz3pj9okZ0SQ78jXdyjfKr5L8on15mpIY+S9P6bv3XQr7M9SoGm
         byKbVAicRh6iHfElOs78Nm9p7klj7bWGjPNQJdsOrKbc7VCVrkKAQu7lURGHcnhLw42C
         16CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VSO7sqm1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o29si14662wms.1.2021.12.13.13.53.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 14/38] kasan, page_alloc: simplify kasan_unpoison_pages call site
Date: Mon, 13 Dec 2021 22:53:04 +0100
Message-Id: <e151ad13878c5706bc4491c2a69d11b0819e67ec.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VSO7sqm1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Simplify the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the simplifications for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 17 ++++++++++-------
 1 file changed, 10 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 90a2f353d230..497db24ed169 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2433,15 +2433,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (kasan_has_integrated_init()) {
-		if (!init_tags) {
-			kasan_unpoison_pages(page, order, init);
+	/*
+	 * If either a software KASAN mode is enabled, or,
+	 * in the case of hardware tag-based KASAN,
+	 * if memory tags have not been cleared via tag_clear_highpage().
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
+		/* Mark shadow memory or set memory tags. */
+		kasan_unpoison_pages(page, order, init);
 
-			/* Note that memory is already initialized by KASAN. */
+		/* Note that memory is already initialized by KASAN. */
+		if (kasan_has_integrated_init())
 			init = false;
-		}
-	} else {
-		kasan_unpoison_pages(page, order, init);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e151ad13878c5706bc4491c2a69d11b0819e67ec.1639432170.git.andreyknvl%40google.com.
