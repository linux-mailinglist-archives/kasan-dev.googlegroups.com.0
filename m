Return-Path: <kasan-dev+bncBAABBXUIXKGQMGQEJZK66BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A5F2F46AAB1
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:02 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id i123-20020a2e2281000000b0021cfde1fa8esf3021985lji.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827102; cv=pass;
        d=google.com; s=arc-20160816;
        b=XlrqHOUMOGbYcyVnge7fCHu+7PTLW289f/2NrW3vzvPDiza6ZtpMtscgy+tLR1aoba
         /oXQIrGj2TFSb156vC+G3eX5coBawZLPbGtF+RZekGcFYyDgRWkP93Cxj41rLZyOvU1T
         NGhwyZUlK0sPdFMLcGN9dVym4TWGIxysYH3mUuVbr2M8Tk6Wp++krDQFqj04uKwvyMqN
         w5qfEjnec4EvijjnozfDCiKHxuZEhYVhs2GTKkvqR7tPR7MuBhcX8I8A2QuC2NmeaTeN
         cM5BLoygjl1ihrtFjArfCiukRt/KesKxR1RMd4Foi79esF1+f36N5pCInyFTYDxS0vm/
         002w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M7gm8qn/kOWZ1HrcBS5M8bB/rcG8anVUXuXXTsW3Wc0=;
        b=C3EqIK46/cimcHkHtLj8k+9rq5xu1EHd/ExZv8Q8P2HB/8sLBxxcoRYRcSE7TwyfZL
         P3YjdeFwlHQG3KksEWyi4nXIFfYwxqp9aoV9NQ0iOCgFdZuL6V56CRCYyoNv9szSRcVV
         cJQqayytwMGFlb9fccBDKXD+pM/kpVGB6kgcxETzGx1lDHu0Uiyoz8HRd21T5FU+vWnb
         AKVBfk/jt4QC7C19AV+X6gD+wCSHm1A6tWYRfJyisQ6fHMWTanDuPn64Wow4hc2YLmAK
         gHrK2hGIsQxW3RNmae0nL9BREw+FYX+9lQZjZ7ogx4IpxErFRDNGUKT/KDUA/bwRVi16
         A1+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XpQsncOO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M7gm8qn/kOWZ1HrcBS5M8bB/rcG8anVUXuXXTsW3Wc0=;
        b=mkPLeOBEuA29ftITewn3+3DD0ZFilUaIywBhBWCpAGV6YJEUoD0kCmxJ09xVa2hR3B
         GUfk+K18Iauj7vbQCiEutf1C5L4R6mNzqAI9jrlS1bayH43iVZvA3o7txvkGQYumyxiK
         4X923QTUc6eicdUkqFeNFFUWEFVLGHJhKacKNbEHQz2FpaGCs1oEQUCUAhcb5Ej6vJQ0
         tjuPt6oYdUDY+AZjbPjrTV1nEC6HOS15hFm1pfbvg97/HQc8xU3xiCj1PsTeUd+nUwzG
         Fzhy8MI1s/i04BYuT6A1RCxUcmDLHsUJzlrc5AmXtRAyvcO38UrB0NVSsckG2PcfkcsY
         FnKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M7gm8qn/kOWZ1HrcBS5M8bB/rcG8anVUXuXXTsW3Wc0=;
        b=fuybaLYQZ7+y5UNjIaQx60yDjlxBikMbHGryTdzQSSMfZZBvPTtut2wYuL5yrKvKEb
         5mkkKMj/ePmdnLe8FS8PKRrH9D4xmSrk7oJ9j+dBkVVlEGLcihvsaV+ejEG+8t9JJzDJ
         bsVWGl2+NxATlBTKB5aPSp90I6vzlLnRx9//8MJ+pI8lm5H3LXu8acv8c6FALyWiE7vE
         zSrYJDoZ4HuM5S/nuSb+914a0aGChcbtWHEQjBYvysUoMiZuv3D0RpykW+F1zXjPfUPp
         sJZOp/2vpXNy5LWjEfV7C9IvIXwrsmti5D5KOZxReRTgyah7cBepLgxoCZvV+msjHLfU
         2hxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532b1R5DoVLLcInrNF4r8GMvyFyS9JUx45Sa9bl8PTZbXdz6/tYl
	huFilwZPGkI0/k2pK4CBTGM=
X-Google-Smtp-Source: ABdhPJwkZTaV4lFxrTMkapE3BLcL5uknvUoIX+JxiasX87yhLTbISQJJpJWefqfxhJ4fbp1QQpmk6A==
X-Received: by 2002:a05:6512:2347:: with SMTP id p7mr5318999lfu.304.1638827102200;
        Mon, 06 Dec 2021 13:45:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1926872lfu.2.gmail; Mon,
 06 Dec 2021 13:45:01 -0800 (PST)
X-Received: by 2002:a05:6512:1115:: with SMTP id l21mr36132630lfg.201.1638827101388;
        Mon, 06 Dec 2021 13:45:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827101; cv=none;
        d=google.com; s=arc-20160816;
        b=E3HV2gq4nk/VD/Yq6AfXL/3hkvjVf3Sn1iwI9qZmejg0pc6BytKjVX0gqH2DN76RFA
         fBQhme6Ld/BScH8qBPlD7uvZC0+qcoa0hkVhez4506vb2EXoUlB/CENgQU6o1jBkKuWU
         D/H2ZClCWKm/gdLkPWYph8WlrORdPczCl9on75gyjKgMT7gXr6vd27/d6JnU2BpmA+OI
         EuoNA4OWAxUygbxnfJxRcwgHiHNpozPs7tOZj7tEWTAJH20ybTSTXs8ta3kGw2Pcnnr2
         3TaJnfUMYVcdthqGZbpAMFrnQRTjWi0ExYweV5fhX/M/WCOT+lTMkyYKl5+QONqwh3xe
         xFHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ir/Gb9vyo5VTknMlksNZZRWU049BNvYKgeMRmdqw2Yw=;
        b=jOq5TY7nn/HPhlfIQAR3L1ri8CPgRnE/c+LtiM4+Uym+3HnEZ/ieOXNiGQ86vSqmqo
         KtnRLDpTK8TO2QB03OEMBfxI9yqKzXAFaTu6qTyjMpfK6z/zxpePDiM8sP/RLOcryVeX
         ZzcsNXM8OZijU8+0GRPPybPKF4XLTzmnaNTC3SlZBELTK1LqLePC5qnnt0jcH5+SMu4P
         drLGWy6X71a+SiigwIJ0xV7ETCHI6KcnVlujs3n2l7UtapHXp1zRFia4wXGTc7ES0FVD
         8HnDPNSH2WNCec2lbJNdfyIR+59Sx8016gHO+APd1KxBfTAwx2lfSHMQMooD8pCz75Lk
         IBng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XpQsncOO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id e15si1056752ljg.0.2021.12.06.13.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 11/34] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Mon,  6 Dec 2021 22:43:48 +0100
Message-Id: <b078167b0f4dfd10f36e5625bfdec638d37abec8.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XpQsncOO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

The patch moves tag_clear_highpage() loops out of the
kasan_has_integrated_init() clause as a code simplification.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index d33e0b0547be..781b75563276 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2404,30 +2404,30 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
+
+	/*
+	 * If memory tags should be zeroed (which happens only when memory
+	 * should be initialized as well).
+	 */
+	if (init_tags) {
+		int i;
+
+		/* Initialize both memory and tags. */
+		for (i = 0; i != 1 << order; ++i)
+			tag_clear_highpage(page + i);
+
+		/* Note that memory is already initialized by the loop above. */
+		init = false;
+	}
 	if (kasan_has_integrated_init()) {
 		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
 			SetPageSkipKASanPoison(page);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i != 1 << order; ++i)
-				tag_clear_highpage(page + i);
-		} else {
+		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
-		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i < 1 << order; i++)
-				tag_clear_highpage(page + i);
-
-			init = false;
-		}
-
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b078167b0f4dfd10f36e5625bfdec638d37abec8.1638825394.git.andreyknvl%40google.com.
