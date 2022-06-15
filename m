Return-Path: <kasan-dev+bncBDY7XDHKR4OBBJHVUWKQMGQE76V6TEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B1D454C1BA
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jun 2022 08:22:30 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id o10-20020a056122178a00b003688829b94csf1089270vkf.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jun 2022 23:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655274149; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xnzqy/z9HIijb9/mpvTqOVJT9obe46pATVuOdUg5GliGIAuGUciziy/PV5lrhF5DTO
         GaJFxO70Z4bwtb9Pe+F/YI8JrvCgyFtYmE6f7T1ky+CBZoeOPFNp7A5KQs4n54pr0w/H
         +FScKbuYn763U8GToqLJ/x2ppRNUhKlhzqhGsnQrt7wzqfGeAW5HP/7rJ6bvmE09WIvf
         +uJtxZEqT4WbBCOTNmw/vUQCpdXZCgIPGs2WU5xIEKz435Jl+1C0gZHFt8J/Mh5Ni0xf
         v3ZKuyZ4quTqVcD6dkUbgnIoa3fUldLXwt+qu7aJZKhsUE87B9C3CrXmORw5512BKePG
         FHlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=V0zvxDQzNEdRwGIsyI53EmjC1fpfBDGrNhBesHI49a4=;
        b=ltWh5F20kVrGroX5+EkVNGWJt/kYvNx1S79vQDbCQ3YFRnJTiGq9zQQM9zma8+0HQM
         pDbtwA34a3bSImViCQv71sdJ8Ce17yoT400ohp3ocRhPFtxC4NbwRW0oKth9/jBUmsii
         /wKARbCwsO3jVttTwZ1I46O8dzwGE4PTSap0ALN/TITxm5FN6SJ8euYBX9zEQiwX1zqB
         Zjw/x/ypfPQMBmWKSz3LgP+l0nrcAMDyfdNs3RkEEPGfswz8pOPSBTC7OdU/tpSEHyOm
         5yfDpbYfaiaxCV77uTKuJkIhDxlt7o8rqwWrMWiTLmyeYXGPBDh8RozqPvuyoYedUapM
         9X4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=V0zvxDQzNEdRwGIsyI53EmjC1fpfBDGrNhBesHI49a4=;
        b=EpCRCEZe+L8Q0khXS1hEJHlPlxcs5qLrUbgJ/GieP2pdL893xqdn9tyIQx12zbQx4R
         3XVtOIXXql57Y8XCXtg+zMqkvKJIRrO4IxHpvcFDt0XsPONHk18jreNxUPleZkXpRGSJ
         5MM68pbAP8wpPKC4TIztQLjx+a5KxcoH4W6LGOmsbxY/JLdvOoaV3uyfQSxuHAMwqAJW
         4RnHDB+CFCiwxjdYYRz+gFdVF1p7ekOgilARZG1amDOBO4EnglPQAtuBd1CjFlxYhjM8
         VBMQ9t53rSWU5eciPAEth5CbRumoHUKqycMHh5G37GpjipcTELVKVuOopIrxQ6hGFWoA
         Di2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V0zvxDQzNEdRwGIsyI53EmjC1fpfBDGrNhBesHI49a4=;
        b=T3QrSMHlwwf95Rx3mKeV/1RnM2gj1kAn0oThAR/FWJcNqKu82r+7oJv3sPE3kJ3GaI
         fX1nNpDFK97cszm5OhuAJ1iTBkqKXl1bUw82zwL2lVqr14KV61NHbRlM3pHsZgK0UASp
         FMQs4bMIJPJMwcZVCJ/lePynDgKn3TsYH6gg+F0zqbs+qx5XDJm14DHtXZrnZfKg8jUW
         e1NE0OOMIs1XLI7VkIqzF9phV/+5UTm8KWKqSX4IMJ5QIz/G511o4Rb+3aPc179Rhl58
         WwCgOpSad+VZQz5y30azyT28SW9dUA9XMvE8nzCTAUahkLimPkYQrn1o6doHIB5Fqnow
         Y/fg==
X-Gm-Message-State: AJIora+jDitqEEb4KRDkViohKnVSiZvVUsBd2c2dOQot+uazfIdGfSds
	ao7vDDg6Ggvxxew7AhEDATw=
X-Google-Smtp-Source: AGRyM1uN445C/1z4JLBXZrCOe7a4D15Y8GFAHrOhxdyTaX8KnQcTGg/MVMMBWIt7fUP55GYb5LegjQ==
X-Received: by 2002:ab0:6902:0:b0:379:a445:3bed with SMTP id b2-20020ab06902000000b00379a4453bedmr1170076uas.84.1655274149110;
        Tue, 14 Jun 2022 23:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:148a:b0:35d:f1da:7bce with SMTP id
 z10-20020a056122148a00b0035df1da7bcels738105vkp.8.gmail; Tue, 14 Jun 2022
 23:22:28 -0700 (PDT)
X-Received: by 2002:a1f:2048:0:b0:35e:3d39:addf with SMTP id g69-20020a1f2048000000b0035e3d39addfmr4046819vkg.28.1655274148452;
        Tue, 14 Jun 2022 23:22:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655274148; cv=none;
        d=google.com; s=arc-20160816;
        b=zS3Qk47VcGe7rCIbJXbyHHnjPUitalMn4Mf69aKtz6LoMFTQJU2AKHnKcz3UFaeWij
         iiF7EZDg91QkkDVdJfgnEhBi9b/wwvJoN7cIZ1eXODsd7cQZ4AnEIWhwIDa1xVqjn6mT
         9jzBbr7Wb+I64Kec5PFHYpmj4X96+a4rmbtAwqHt2vESEYUxedNyZY1UzaTrvTkPX+S1
         LXERZ7jBijFs6MzcuRsVG8T6x4Qu9gnidaLYw0uGhmhW5da071UpU244zAsVTJ8o4S/Z
         0wPac9qrZFj8Tp2FDBTJXnoK8TJMNpnyO6qvUkxl1/7DjxxRnyAmNECL8bFLQKNwaWJN
         7xVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Joj8h3eWOZx+FAtMEOqqvJ4QF8D3ShmcYjyO0+6Gxyg=;
        b=jCr5ZnMwVj9UVH5cmmKqhP/XWLRBNJIIvEEFFpXTkgNVPLMkQe1n2LD9nAYhjOtoUk
         T4MsJ2/2nTjYgD3O5XdbdrQQEkgtXq80TB3jeQKhgdMyBE/g6H07Z151Qd0c1ptTFkgf
         TolTTkSc6goqoB6m1SPFIfFnvQDAzQLu8WcP7R0Aj3JQkxqEtOkYBpSMrN6F3tjskedg
         srkgxQC1nyHzz1TUcJTuLsiCBxGX4Rd2szuvVVTfpcT0kHeyypKzMqymtYXhwWVfuoXr
         FKQtPG27gTjKxWIUvwcvopuIKekVUF6ariQ4DmSIZTjLXRbf7hTtsuI9tKKien0lgjQV
         sESg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id m21-20020a056122139500b0035d09187a08si652943vkp.4.2022.06.14.23.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jun 2022 23:22:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: cd9724fa7c8e4e0eb7d75559d32416f4-20220615
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.6,REQID:c68bc38a-e216-406a-a0eb-2bfcbb8ac190,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:100,FILE:0,RULE:Release_Ham,AC
	TION:release,TS:100
X-CID-INFO: VERSION:1.1.6,REQID:c68bc38a-e216-406a-a0eb-2bfcbb8ac190,OB:0,LOB:
	0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:100,FILE:0,RULE:Spam_GS981B3D,AC
	TION:quarantine,TS:100
X-CID-META: VersionHash:b14ad71,CLOUDID:7e5848f6-e099-41ba-a32c-13b8bfe63214,C
	OID:f3505d2ee169,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,QS:nil,BEC:nil,COL:0
X-UUID: cd9724fa7c8e4e0eb7d75559d32416f4-20220615
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1039634672; Wed, 15 Jun 2022 14:22:22 +0800
Received: from mtkmbs11n1.mediatek.inc (172.21.101.186) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Wed, 15 Jun 2022 14:22:21 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by
 mtkmbs11n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Wed, 15 Jun 2022 14:22:21 +0800
From: "'Kuan-Ying Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <chinwen.chang@mediatek.com>, <yee.lee@mediatek.com>,
	<casper.li@mediatek.com>, <andrew.yang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>
Subject: [PATCH] kasan: separate double free case from invalid free
Date: Wed, 15 Jun 2022 14:22:18 +0800
Message-ID: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Reply-To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
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

Currently, KASAN describes all invalid-free/double-free bugs as
"double-free or invalid-free". This is ambiguous.

KASAN should report "double-free" when a double-free is a more
likely cause (the address points to the start of an object) and
report "invalid-free" otherwise [1].

[1] https://bugzilla.kernel.org/show_bug.cgi?id=212193

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
 mm/kasan/common.c |  8 ++++----
 mm/kasan/kasan.h  |  3 ++-
 mm/kasan/report.c | 12 ++++++++----
 3 files changed, 14 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f..707c3a527fcb 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -343,7 +343,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
 	    object)) {
-		kasan_report_invalid_free(tagged_object, ip);
+		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
@@ -352,7 +352,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (!kasan_byte_accessible(tagged_object)) {
-		kasan_report_invalid_free(tagged_object, ip);
+		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
 		return true;
 	}
 
@@ -377,12 +377,12 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr))) {
-		kasan_report_invalid_free(ptr, ip);
+		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
 	if (!kasan_byte_accessible(ptr)) {
-		kasan_report_invalid_free(ptr, ip);
+		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_DOUBLE_FREE);
 		return true;
 	}
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 610d60d6e5b8..01c03e45acd4 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -125,6 +125,7 @@ static inline bool kasan_sync_fault_possible(void)
 enum kasan_report_type {
 	KASAN_REPORT_ACCESS,
 	KASAN_REPORT_INVALID_FREE,
+	KASAN_REPORT_DOUBLE_FREE,
 };
 
 struct kasan_report_info {
@@ -277,7 +278,7 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
 
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
-void kasan_report_invalid_free(void *object, unsigned long ip);
+void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
 
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b341a191651d..fe3f606b3a98 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,8 +176,12 @@ static void end_report(unsigned long *flags, void *addr)
 static void print_error_description(struct kasan_report_info *info)
 {
 	if (info->type == KASAN_REPORT_INVALID_FREE) {
-		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
-		       (void *)info->ip);
+		pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
+		return;
+	}
+
+	if (info->type == KASAN_REPORT_DOUBLE_FREE) {
+		pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
 		return;
 	}
 
@@ -433,7 +437,7 @@ static void print_report(struct kasan_report_info *info)
 	}
 }
 
-void kasan_report_invalid_free(void *ptr, unsigned long ip)
+void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
 {
 	unsigned long flags;
 	struct kasan_report_info info;
@@ -448,7 +452,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 
 	start_report(&flags, true);
 
-	info.type = KASAN_REPORT_INVALID_FREE;
+	info.type = type;
 	info.access_addr = ptr;
 	info.first_bad_addr = kasan_reset_tag(ptr);
 	info.access_size = 0;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220615062219.22618-1-Kuan-Ying.Lee%40mediatek.com.
