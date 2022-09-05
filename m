Return-Path: <kasan-dev+bncBAABB6OK3GMAMGQEG7UHGPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CD715ADAAF
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:14 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id ga33-20020a1709070c2100b0074084f48b12sf2618881ejc.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412153; cv=pass;
        d=google.com; s=arc-20160816;
        b=wEnweTjTghJ0sB1DK859ugrK73qJzPKVjSnt/vdLyCdjI+HEGt8SwXsvw/+yJJ+QmZ
         2UhS2e/Ew3RFrBRn68Vt6rF4GWU6bfSlRrEdlaLYD6Hy4Ka5PuL8e0m5oToqhjNzhYcP
         7JhljtlRqcRQM+UsehoTVc1k5NIkSsBehU98vIcJn/K5ZX0zKkiUDx0Am9VtR/gmyzEQ
         ecUVltKcNSHWW6nT/qd5ZomhaJrZ4+Y+i5Fb81aMV5TQzQLElVpgOV43oF/8j0k60noG
         rzO2yV4sYo0NzVO/BMa/arWQZuNqbyJnNfADLhW5ksjHCu94uDQ2PempRQovDyLQuQ99
         wgVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gFUINT2j6jNEIAj9b1TtP1LfAnEJ7F/zxQiIHm3Bpnw=;
        b=0TWnwJwsXz7q9WusyPoQ7UAIZ7Kf8qTPKPfOLNvX10BgnI5NzZhu+pOwCYLTVNz/2Q
         FUX4PJph7LtsDvhU7SSCusELMs06LSlLaJbbUkSDv8LpE8nkVEsFxGmcI9owu5/c8fKq
         BiDUStmY26GO39GcbWm3B1On0L/wP20tKJI2CG4yzY2O+LPDHbefsnEXkxWwI58OnO4z
         BoXRasaTMhCHgTblbsxv03mOZwx8/VJyKQHoXvv9kdFyNMvWs7xDqxCVXI5b+shluhyQ
         U5TwxSDkuZa9m9l3/IUg87ZRiD+Xc0OV8OarMRRkL587PLWf0IF3oJjTzzEAJj72kEUg
         Jh1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=P0d43fe+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=gFUINT2j6jNEIAj9b1TtP1LfAnEJ7F/zxQiIHm3Bpnw=;
        b=hSeILIn02cwBTssW947L4nvwoVnpXpN8x6B44GYF4iI5skofwA/wwYq5b9+6S2+Xkl
         eiXCVzkeIs4yie7RdnMgXt66JMhbmodxgSHu7NjMuhDaO11saFMFx4Rgpr9W1nXsMQ+j
         OJfn+3nkLlC4hDk/2M+16tHvMNL5ZzP0C7ln3l4CO2iDc+Nwz4UBKbF/hPgfQU3jhQ3j
         3chK4Q8PBjkHfTB/zJBXVOlwnJKrd4RwByng3IjHGj8bKRnaQiGmshDK4xnm21mNkqGo
         bibG5Vqq0c0LV63IYJsh0hV8G9pjG9gz82A6q37h4D3F/RNbBcWzGAT/+pOsq7cRvIgH
         CSHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=gFUINT2j6jNEIAj9b1TtP1LfAnEJ7F/zxQiIHm3Bpnw=;
        b=y7+SnD1gM0JEcLp+zQFcbebn+hPCh06UoVV1RnODdmP6Dwuw3Fn/mledtehiOqEERu
         taSatnHZZmkr3IjpwjERo76rntzcQlqN32ERM7ydyFSXpFOS7VrvJBsj4NtpKcBwzUsf
         I9M/Do9cXewxC0zH1Qr+TbAgcWDSimeOAj9O6BITamuxcmPmTqd0ipTENmAS1ezMcyLw
         FY5kKGQeNbd343FCy+S6ofULTydBNUOja7wGv1RRjgp9LbiOzwEAZX8vBQlQWGJWPFfJ
         41UmwEajoK43wpQg88F2+xHM8lEiLfBFjWDuvJv3ZE+aD8aGLRMiGTPbjDJYSt/+8c4w
         +zRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1BYJX11+haZuFPnGjVyStwxQIF25nJg2+ji6hDae3dBb94BnAj
	mwPwc7gcp3Nb+/LdkwU/9tM=
X-Google-Smtp-Source: AA6agR4enbqAHxTW2zxHH0OflVitDTRwrf9YCEbLMKVWmgAfWMMbT8X5zcY/utSonjlmRRUazKQ3lg==
X-Received: by 2002:a17:907:a06b:b0:73d:dde9:75a7 with SMTP id ia11-20020a170907a06b00b0073ddde975a7mr35033135ejc.52.1662412153857;
        Mon, 05 Sep 2022 14:09:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c8:b0:448:77f2:6859 with SMTP id
 x8-20020a05640226c800b0044877f26859ls8000756edd.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:09:13 -0700 (PDT)
X-Received: by 2002:a05:6402:26cb:b0:448:2af2:bb81 with SMTP id x11-20020a05640226cb00b004482af2bb81mr36128462edd.424.1662412153216;
        Mon, 05 Sep 2022 14:09:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412153; cv=none;
        d=google.com; s=arc-20160816;
        b=Nq4tesooWFhk+mr/KowA7tGKAububjKwa6L6kTsCHWzphS4oCWl0dEn3DiOD6zHA0o
         J4RIAcMz6iC/g3aX1TCYh3Ns1Ih/i25kC87VzKTWHRkPxiKFoBTLorfHxpz3FI+fuw+j
         YSf69VGMzNE+skmu8o1Owng8cfHSoc4hf8bgOhXgULxfMiVw88n/WaJPATkit9+gq+ui
         v1d4UykmM1rGy9DCeaFqDhhkwt5ttBIJu3jAaAYFHx6I+YgcHo98fC2/k2+7DDsk5zaL
         j8nmNbYEA8GCPyydgd3U2ifeKH8lyMQOZwf0YZP2N/B4NQauiZpGuJ+ENnRqpoNLA/f6
         1DPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YPa6DnblrUNaCp9j+8qvSRfWbXda4Oig2+szurtqS5U=;
        b=vwa0Jdp55D5CKjIxWJ6JZ1JmC1Tp1YXfxDCrKK2frCZ4XjZs8tpxwCvD9nx/sE5z3/
         VI0exs9uuu/h7W8awVR5lKMLw/Y2eIm/PMt6NDCW/Wj81jC/ik6Dfs/lyfc0NNQY0htM
         8p7GgC6F5bYfg8fvdy2qlzG1yMt02HVaVm5A92UIOEOBAT9Hbv/5gE9bRhyZxZUkSdG5
         N/yTlPyYnb3s7vlAyLrsmcIp2n1EYyCHxcbRctm3j73s24iNT3yHM7ueW3KepAMFn1uB
         +NNRiboeAT0oOcQ5esOzfsLqCCHPxigWNvhi47BNX14UzKMz9VN6LQYZnsyP3Q/vYAly
         3Eig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=P0d43fe+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id d5-20020aa7d685000000b0044ea33a8ac8si126292edr.2.2022.09.05.14.09.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 23/34] kasan: use kasan_addr_to_slab in print_address_description
Date: Mon,  5 Sep 2022 23:05:38 +0200
Message-Id: <8b744fbf8c3c7fc5d34329ec70b60ee5c8dba66c.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=P0d43fe+;       spf=pass
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

Use the kasan_addr_to_slab() helper in print_address_description()
instead of separately invoking PageSlab() and page_slab().

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c |  7 +++++++
 mm/kasan/report.c | 11 ++---------
 2 files changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f8e16a242197..50f4338b477f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,6 +30,13 @@
 #include "kasan.h"
 #include "../slab.h"
 
+struct slab *kasan_addr_to_slab(const void *addr)
+{
+	if (virt_addr_valid(addr))
+		return virt_to_slab(addr);
+	return NULL;
+}
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 570f9419b90c..cd31b3b89ca1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -213,13 +213,6 @@ struct page *kasan_addr_to_page(const void *addr)
 	return NULL;
 }
 
-struct slab *kasan_addr_to_slab(const void *addr)
-{
-	if (virt_addr_valid(addr))
-		return virt_to_slab(addr);
-	return NULL;
-}
-
 static void describe_object_addr(struct kmem_cache *cache, void *object,
 				const void *addr)
 {
@@ -297,12 +290,12 @@ static inline bool init_task_stack_addr(const void *addr)
 static void print_address_description(void *addr, u8 tag)
 {
 	struct page *page = kasan_addr_to_page(addr);
+	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
-	if (page && PageSlab(page)) {
-		struct slab *slab = page_slab(page);
+	if (slab) {
 		struct kmem_cache *cache = slab->slab_cache;
 		void *object = nearest_obj(cache, slab,	addr);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8b744fbf8c3c7fc5d34329ec70b60ee5c8dba66c.1662411799.git.andreyknvl%40google.com.
