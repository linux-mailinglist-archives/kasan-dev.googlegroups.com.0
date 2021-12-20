Return-Path: <kasan-dev+bncBAABB57ZQOHAMGQEDKPNLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4844447B58A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:24 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf5163280lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037624; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJJdPelP02zyljwYNmoOl81PwyZRwtOL0ZJ2uefXpPprgWI8jCXrV+ga17HbqHN19Z
         ZEGFJYYRDTtEZz87tXCIqXNxVAFe747kZE5YJuT/PQc8/OaawKXxUlNRbSF6fel4BjN2
         M/p9XEcmGD963F2H4fX7roy18BXc06Icaf5QRarVKwgzO8jlzv9bvgbRKU9p9iHQu/pz
         /1YSaxXuBmEetuWLgRgXccPt/nxbVAmTedoh/0O06Gv7NdC0DeLM/VzdWSdT3LWAX/XO
         wfZlhMihj1WnYrEQuT/2N8ukXA257b/VipfkC8bhLwr0s6nBU3kQJcNXb9K2614FngYN
         4qHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JtWLcvt4zdOh+5HwXwqsjOFUd+6ntbM52h81tzTPAPQ=;
        b=e4NTqHqrTMvUO+SXsoxyo1IigyAZGxh6OzEsC9uQZzTlMuqikU9hmAXeXDd9OurVfh
         9Ee6crdUZEWslqSQJ1gKr1LWSKA5e2gA/Pkr9lIbesLUkXNISl2fc5tl9EbnWzoLhgdJ
         93vYJ1HzZ84D995iNe7l7HtmWbhqSEkgT1aI6Xxus1YwH/P8svmElCfFP0qWuDU1lJKp
         vqBDvUXZsA4OWvGfmSPm7LnWEsfC5goTSnKXYRjRYsbr52IV9YgVSNIYHbiQjxze6dvE
         EB/6FRMyuaAf5g+2gqKF+FVregxOvEhPkhf04t5mT01dX1mXLeNy18/ij6CNtsfJbgYK
         NeAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qrHZ97tA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JtWLcvt4zdOh+5HwXwqsjOFUd+6ntbM52h81tzTPAPQ=;
        b=OdSK8E5VMtpdNhZ70rwMqFIOSnW4K5p+c+K7xcdNt3hnT5juqfhE4/BmkbFe/c1jUF
         zbHU6tl92WrPk/mOteaucARbKNRFzgIJbBjHWmqp7XvR6tDJr0GUtEgDqrzo6sk2BW1w
         Wd8B/KlRy+VvDcgi4/RwKilcfHZ0eKPaGwtj7/VWIt3HKimKZmD51vmpGBz5Dxx9x0k9
         egAvscftvfD4kC1drvsjnD0e/RBeGYPAf1gpn8umYCU6Ed/ovxeLOSt02XD/3VomIZTy
         FngMKri+7v7nll1s7/iqIa1Va9/qmNKSoLVIDq9h2I0c/eF+M1h8G0CjXOPOpjsSJS5J
         pcsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JtWLcvt4zdOh+5HwXwqsjOFUd+6ntbM52h81tzTPAPQ=;
        b=4z4OUKXUH83aLFK0wNeQgi6o0FxQ0Na+IPF4rdDIRd5L4ZtPfGU84bM/IDcC9IjvPX
         y9MKICtDYSRhx1qcHGUWOoL6a+ZqzjnBzYTmUNAlRAzFNpalNixpQomztx6MUJMs6AtR
         24mkuc2fEN5vgEgpE3Ja4b2xWeLfrHqGOSeoW843ia9Wj9tgpAGxitbfpVDgh2KqFqIk
         ejbBXv2J9S/f2e1XbXQqujV2Z83EuFhW1M9JHK5Bw6oyKeSA9owkWwI6C9t7kTgk03Wy
         BAmiAIFjBKgSEgXAqe0Rub4lgwVPvhoRUz30WNucVsw+viEDcnQfRyPSTyXZloqktDeq
         6Kfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531X9d5cAlfnXlDO9+jKCn2siLhyxryL6pNRYAqXVitqeeQM1dwh
	wgRHI9Xv1VaILa+DiUHsCjg=
X-Google-Smtp-Source: ABdhPJzvGn/eemjA/FBizYyD+7xqnvfad27iM7A9bas4YTBBM2zDDAK1NJ5IKTdO7FKpOULQfWZaPQ==
X-Received: by 2002:a05:6512:108f:: with SMTP id j15mr167206lfg.340.1640037623881;
        Mon, 20 Dec 2021 14:00:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls2692275lji.1.gmail; Mon, 20 Dec
 2021 14:00:22 -0800 (PST)
X-Received: by 2002:a2e:3e17:: with SMTP id l23mr69530lja.380.1640037622874;
        Mon, 20 Dec 2021 14:00:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037622; cv=none;
        d=google.com; s=arc-20160816;
        b=ldTk0JVbri/2nCf9SQzrjfWZzsWuCsmX0y7QQ4jEwUZMU2In8qweCgqkSP9qNDqh2O
         L3trbBx2GjK3dOC6MgKBVHoyjMTOPO0HId+m0jJNbk4x4ht//gElI26ivxP9pBGKsO7H
         EBUYZQW0eqmn9Lp8YraVoN6FnFHM1GWLjyEkF7igtYdLGT5OVhBx3b6ba3+U97N1/qi5
         0oemM+LvaG4FLhs3zeoW7MccHfZbldth1Q/aGG+tRTgmAPdwC0qgeYziLqgRrOq5lhfD
         Zmevhua4M4jP73o49rnjDxkbGmaLyuv0UJUZeeu7RfchAZFJuN1kixaARrhY4LLo35Yz
         /+2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lnm9A41ImFCEtqp3Gi0grxBV1YcMXYG5Az9GP4mftA4=;
        b=fzJHdttdheYe3Lnbfa12sCQ1c3cGk2CpQg6TSVOhNZ8DnKnwq+bWlDZCEybvdBxUVa
         AvhNsygXXRI30abtWL5yV4w1AQyDULBf/xOdXoScd7RVI02ESwWAz6W86LthSQ0HnjO6
         W2i86D1MFmaoAn6zmcGw19W240bW9Oq1Fhfh5c8KE/G30f5HHRfdMYwmKaZaVTezeDbT
         pimnP/9Ayis8sEAhTbBojGaXQpqb48Qu8Gz6TuZyfq/y2J9rgRqawNIUqncVpREOhmtd
         LtqRu3dC3URxEVWBY9QqxUhj1BqsVIzdyjUB0PUG3XaHB8svKd8OQTHSq8mMN+Zd8KZ+
         ZI6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qrHZ97tA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id w21si991435ljd.2.2021.12.20.14.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v4 19/39] kasan: reorder vmalloc hooks
Date: Mon, 20 Dec 2021 22:59:34 +0100
Message-Id: <e1a8ccbd0d16e32c70570044bb346fd237914c25.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qrHZ97tA;       spf=pass
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

Group functions that [de]populate shadow memory for vmalloc.
Group functions that [un]poison memory for vmalloc.

This patch does no functional changes but prepares KASAN code for
adding vmalloc support to HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/kasan/shadow.c     | 43 ++++++++++++++++++++++---------------------
 2 files changed, 31 insertions(+), 32 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 55f1d4edf6b5..46a63374c86f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -418,34 +418,32 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
 
 #else /* CONFIG_KASAN_VMALLOC */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size) { }
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
 	return 0;
 }
-
-static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
-{ }
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) {}
+					 unsigned long free_region_end) { }
 
-static inline void kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
 #endif /* CONFIG_KASAN_VMALLOC */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e5c4393eb861..bf7ab62fbfb9 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -345,27 +345,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	return 0;
 }
 
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison(start, size, false);
-}
-
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
@@ -496,6 +475,28 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison(start, size, false);
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e1a8ccbd0d16e32c70570044bb346fd237914c25.1640036051.git.andreyknvl%40google.com.
