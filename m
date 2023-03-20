Return-Path: <kasan-dev+bncBDKPDS4R5ECRB6EY36QAMGQEZJJPO6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 14D536C0923
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 04:01:14 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id c11-20020ac85a8b000000b003bfdd43ac76sf6087014qtc.5
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Mar 2023 20:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679281272; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zm15Y7VvaQvVpkYOaigsNhBHn5EpbuC+gmEDD/zCHLOFFnUXgD7j98edq9Z5yMuCWX
         M3xu+ZmmDVxzVrc5Pg5xnxvEZBUNTVyFiJFGm0knbFREHqx2eUSEfUyoRmI0LOrZA5cy
         huhUtlpxMsfGo5mo3DYZBF/gsdtPtWtIerxrR4+qVaefwlSsbWyIYIhQyIlKNWr5exxq
         Z+zis/DVh3LQnAQWCuU93IcK8hr98s9RTIei2/qvgp/r403pom1rRgcWfWtNLxHyVWG5
         P9as3d+Lqj/AJNH8SRkLdGNLi0KlMs7tp1o403PywgmXGPxXvEfwKQbybqH/AlrWusnA
         6+5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2rBM18PYhKi5jEWQApTzukTs8O83iRAtIwqKTMUaGhY=;
        b=snp3zGYl6YJh4u6E+zjCUNYe26bYdJ3+VRNmJSTUPsrmTfhGq7PXpxpLFH+UnyvaIB
         1SFmJ1dIiSfvGH+Wgfq37awGkQNjvClNOT8bcpWZu5BRLUELSMuIVXsxt06ytoMqejBu
         QNPMM+64jpkphyhaFhCvUPJ5L9MjiBHlSaa7TVyFzfW07ibKjRcSZvS4PIJOJKItQX1N
         NW+z5MlX2UfwsZgxTINBMAxOjxQb8yR26rrlwyp1TXh0/kkMsgyBajSkifPOhrq5QsoQ
         uPYfV0SLkSRe7L7/65oXTGjD/6wNyK16gld2rWpHCZY0MxxqZXPztwrsCgSVKwENPa/K
         /ARQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=kXzMdTPb;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679281272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2rBM18PYhKi5jEWQApTzukTs8O83iRAtIwqKTMUaGhY=;
        b=q0YyWTZgvznlBKi89u0BDS4hppfJ6dZLgmt/REEAnNZSj3oTBhwi3Dwopv4PMEh8fW
         cP9VC9v78Hhjeh6nLZ/U616pApnipzxSxB+5wnhqbvJYcC923X/nOZmlwExcRUW7Jf0l
         Fjm5dsIYXCA+L9OQf3tmx5k/G8epfUlGqpYGriouID3EpPNhWZO4w2Bisu9EEbgUvF/x
         TBTZtnr6IYaVjnHWZqvQrVOJi+PpIVdhAkU5Qp5cTGBJKbVhZb/l/t4kdhETt7tY+tWA
         39zTATWKtbqoLR2OPXdD4hZjqBLZfDM/gxGx+Rzw4LoMfnU4AUxIGzuvxxWr/s6RT9/w
         5mZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679281272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=2rBM18PYhKi5jEWQApTzukTs8O83iRAtIwqKTMUaGhY=;
        b=kp70RZq/6v32cENoM24AuC+FI5VQJOiPF5I5MNG+nu1OSj/RuBGs/SwqkVNeTMU7OJ
         F5puFBMJOw3Lc69zImqezNyagW7aOfLRqq949cBwYqDVbX0gBLs1Enu+PIhvYE6AW927
         evIyHPkT5BYvu4pGsnfG9y61EPiMYrNFBGeMnqk8n+oArUFAkWJ1v4vO4QmaqPrzQoFo
         dVpSH/DIRKN3X9xU20oQh6ye0l9LJXjUdsDV1x07lCLH4KuIf4KR8kRpyJdjUGWenJv5
         n9QjRnfOJBpJ0XsWOIpt4BVudTsWJQwvtJYO7oqQV3RMvg6ApLTPBET7+2Tc1nn0L1iD
         Qxww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWZJI70pPv8oqAGvxokBJmcV3jFdsXkYz8HBZ29bOfeFXTgf8ll
	gyE1WcCNfrX0lBAfKaWU4+E=
X-Google-Smtp-Source: AK7set9DmdOUcy6/01ujVne1hcZzvKV/qlTciJTD2kxrifpuZoTouX4/41lkGc7mQkw6nCygbQTQoA==
X-Received: by 2002:a05:620a:859:b0:745:718a:8c61 with SMTP id u25-20020a05620a085900b00745718a8c61mr6667918qku.4.1679281272662;
        Sun, 19 Mar 2023 20:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5312:0:b0:57a:efe1:9777 with SMTP id y18-20020ad45312000000b0057aefe19777ls6893568qvr.4.-pod-prod-gmail;
 Sun, 19 Mar 2023 20:01:12 -0700 (PDT)
X-Received: by 2002:a05:6214:1cc8:b0:5ae:4094:cf80 with SMTP id g8-20020a0562141cc800b005ae4094cf80mr24504350qvd.10.1679281272149;
        Sun, 19 Mar 2023 20:01:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679281272; cv=none;
        d=google.com; s=arc-20160816;
        b=SmfUebbBYGKVxi7RPlMbtJus8lRPOYx6zpWxyuQd2W7GrCyoDDqNL4S+brviWMAUsP
         TuRobZkHjcaoTFZiT3o730KjnHnemuSj/QQ3aDsM4QZ8iobN8v+6MIP1CKE8PPHF3z9w
         9uYaBE2zZalw9sTOiuVUUvhPLSNL1zNEiu9/Au2Ppdh8sv3sdBEN+5Qg5vt9jMlfvfST
         IP1PvIL5ARuBQMcXXcEaHY047HRbjwHpV2W9TFgxABZfqJhqrfSmJb7nc9tiIZhF9FKS
         d2U3UuoP3lOIJCi0VO+WSTA2RLYnvcBCRE1ef3Wq0mLwpCt7+6jlk9gWgEsGPhsDnOMe
         u5vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1F7l7Tv9LSQ3FV0WZzvP63T8ZRGBiz+hyWwDqQtTFrk=;
        b=0sNWG/LYYhB9JNjxK/N48WovWFtj7BlhELpdsBIaFTdwJ+bLKvcYMu07aR7gPWWTQT
         bk3dddMFNWdvPm2T4qylX4D9RtS3onLDFzOcscJViBJuZ5q9dBHXZv76Tg0VQ9xx2V34
         6Cu9iQKChsFaU6ar1HXjfENsny6S5YZ6t03mwhSXlvJYHWUEZ4Q932m19o4IS0rB5Q9K
         Nok/1isQ23lw6V5N18qDHnCz7vpzI78EigZxj0yV/jBygRpzob8+LDG0Nb95Ot1l6gR+
         xHyN6XzctU15oRlc6BhdIwMOgwTsStpgTevlpbPBl3GSq043nhMWPcvWMAuReoLFhIHH
         pH6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=kXzMdTPb;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id dl5-20020a05620a1d0500b0072ceb3a9fe4si403409qkb.6.2023.03.19.20.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 19 Mar 2023 20:01:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id j3-20020a17090adc8300b0023d09aea4a6so14946965pjv.5
        for <kasan-dev@googlegroups.com>; Sun, 19 Mar 2023 20:01:12 -0700 (PDT)
X-Received: by 2002:a17:90a:56:b0:23d:4e9d:2eb0 with SMTP id 22-20020a17090a005600b0023d4e9d2eb0mr16866142pjb.36.1679281271272;
        Sun, 19 Mar 2023 20:01:11 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([61.213.176.5])
        by smtp.gmail.com with ESMTPSA id y17-20020a170902d65100b001a1c69cc0besm1844972plh.200.2023.03.19.20.01.05
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Sun, 19 Mar 2023 20:01:10 -0700 (PDT)
From: Muchun Song <songmuchun@bytedance.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	sjpark@amazon.de,
	jannh@google.com,
	muchun.song@linux.dev,
	roman.gushchin@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH] mm: kfence: fix PG_slab and memcg_data clearing
Date: Mon, 20 Mar 2023 11:00:59 +0800
Message-Id: <20230320030059.20189-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=kXzMdTPb;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

It does not reset PG_slab and memcg_data when KFENCE fails to initialize
kfence pool at runtime. It is reporting a "Bad page state" message when
kfence pool is freed to buddy. The checking of whether it is a compound
head page seems unnecessary sicne we already guarantee this when allocating
kfence pool, removing the check to simplify the code.

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Fixes: 8f0b36497303 ("mm: kfence: fix objcgs vector allocation")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 79c94ee55f97..d66092dd187c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -561,10 +561,6 @@ static unsigned long kfence_init_pool(void)
 		if (!i || (i % 2))
 			continue;
 
-		/* Verify we do not have a compound head page. */
-		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
-			return addr;
-
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
@@ -597,12 +593,26 @@ static unsigned long kfence_init_pool(void)
 
 		/* Protect the right redzone. */
 		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
-			return addr;
+			goto reset_slab;
 
 		addr += 2 * PAGE_SIZE;
 	}
 
 	return 0;
+
+reset_slab:
+	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
+		struct slab *slab = page_slab(&pages[i]);
+
+		if (!i || (i % 2))
+			continue;
+#ifdef CONFIG_MEMCG
+		slab->memcg_data = 0;
+#endif
+		__folio_clear_slab(slab_folio(slab));
+	}
+
+	return addr;
 }
 
 static bool __init kfence_init_pool_early(void)
@@ -632,16 +642,6 @@ static bool __init kfence_init_pool_early(void)
 	 * fails for the first page, and therefore expect addr==__kfence_pool in
 	 * most failure cases.
 	 */
-	for (char *p = (char *)addr; p < __kfence_pool + KFENCE_POOL_SIZE; p += PAGE_SIZE) {
-		struct slab *slab = virt_to_slab(p);
-
-		if (!slab)
-			continue;
-#ifdef CONFIG_MEMCG
-		slab->memcg_data = 0;
-#endif
-		__folio_clear_slab(slab_folio(slab));
-	}
 	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
 	__kfence_pool = NULL;
 	return false;
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230320030059.20189-1-songmuchun%40bytedance.com.
