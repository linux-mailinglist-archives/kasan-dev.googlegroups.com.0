Return-Path: <kasan-dev+bncBAABBWFUTKGQMGQE3ECC6HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6700946405D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:40 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf3863378wrc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308440; cv=pass;
        d=google.com; s=arc-20160816;
        b=VnEhDrSlZOOqvh3HxV5BnhedGovoLrObt5zsBYHZ5zV2kSxxv4JmdlLPEHyRs2rODA
         45FmCRK6e7jCj+e2QIU27rzhIkAztiJz9zN8zsh8jEMGGt2oDyNliw7aeIKLQ8Lx+Eu1
         VQLwHvbq1TEH9e+W+pJA5UFLZMQ4thMjtb/Emwj6IydvvzCskK2RHCVYRpNFyH83g+MD
         5zb4BeyZ6gkDGPN5PHjax49a3tLPuAi/BP6A98fsvFr/ReG78OBB3NRrj4sCWwy4a6tC
         V8nGVr2BatsNaAfeSeUs0EY55ZdxKdNmFMtp8h8lx6P0FF7MjuRA5rRbSAm4JIcb0CKv
         LClA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HxOERjMa8AROh1LRrjmAyr0JVy6pWb7dxctTRaiDHVk=;
        b=QcQf527oKO8c2mrjj/K8l4h2N/EwcMDehOe7lzZ4sWppIQ+l2q5whMz6BkifgEfmL+
         aVUfn+awqtsTkTghFqpQXfJBvVVN5fM8BTMbf8UaJxWYq0kJ2PnxdBz6yMVAWC66VT+Y
         FRXeIYYX2QU2r8tkTZUpTEWS1c3cPTiKvgbvZeoJsYyaQvwt4alFhiIlcgKwswfdVlul
         RzaRd10vGUJcUyV9aqR/BLTJjVIX+IzGWuaktZf3uv1K+EndOsG1zfxhmR/ZavhW8Ou0
         Hmp+DrAwEKLuw0Me6xI6Ux56uj9MRina1MlUK8tZKJDEP5xsA52lHHEQVbAy4xrifVnW
         n65Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="A1yF/Qsa";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HxOERjMa8AROh1LRrjmAyr0JVy6pWb7dxctTRaiDHVk=;
        b=PrrNIBUGHikZ04vebeQLc8f4sZHH1+8AXVdXFhCZdiJYsgqB41z7OsxHKsg4OEJmSe
         bsHG5mnfMHSnWOUgsNdceyzDZAQTvjEnUgoIGbj/8LEdP5BLPjNCbyPeeCAekjtND3kN
         3N1ErK7qPgcyjw5SKYGCvHvT0I8DJaIMEaLaq/yffZER4cfqAeJFjUEa4NpxgF8LuWYw
         z1xjZ/jC/c2q9xOo9nq3YeCE+CKRbOQ4eRitKQ6RjtqjWVeiCdK2+ir6YXIrqy0dc97m
         yCamsyb2g2XAiOVkApJDAE/HCTNdZt+nm8D2nco8YTG0xP4ch2+dZVS1HsGJNILBEvhl
         nJow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HxOERjMa8AROh1LRrjmAyr0JVy6pWb7dxctTRaiDHVk=;
        b=asroCEPAzlGf0yYiJ2Ke6rDIb/1rJlPfGYZMRkQGkuM0yHH+/YMH8oUSWiwjfWlRhQ
         Z//qvMrwb8lXjmK2qZO5njP+QH6Y8qiEZxe3K3xHTU6eIAnCRxYMCQRQh6sbRQvjE/AV
         mj5v/OtlbfLPdkjyDOcVR9c5TrIs0t+05zUGmWF7yGUR1qPG0uKAjb2lnj+6/q/9D9qh
         gbAXAap6x58la/1StseWQ0uR4E7YRl5N94Q9qw4+/9sAlktrNeFtisTUmW3oQOoJdaYm
         BN4nXxEDHeg22TiPuzScJFXhYfIv9WbYyyeq8fQ/zKXIWMw9LUTyRSLNiNtLA0jB5dVR
         f5JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531258MCvauN4W9LojIsGt3KKvx8jSZ6louYLJNpSop1zH99pRDU
	I3y8HKzb6iAZSIiVp+7GLis=
X-Google-Smtp-Source: ABdhPJxIXCBVyjcQ1KAa+QxjSJECskZWi+2Vx+sKqB65//GcsbP51QsELbEzLfeGLRPfv5DpsRc70A==
X-Received: by 2002:adf:8bd8:: with SMTP id w24mr1772386wra.540.1638308440184;
        Tue, 30 Nov 2021 13:40:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls123687wrp.1.gmail; Tue, 30 Nov
 2021 13:40:39 -0800 (PST)
X-Received: by 2002:adf:97c2:: with SMTP id t2mr1731504wrb.577.1638308439483;
        Tue, 30 Nov 2021 13:40:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308439; cv=none;
        d=google.com; s=arc-20160816;
        b=wbSslWDiXDUjYI6bJPDhNE2QYgObQn7BEi0A1BE6EdavHB+IjBK4a9mXc0epLWFRoR
         lJCBqDcD8xQ3lTJWIjSO3LPBSsqgV0z8lf13t0c4TB1wf1x8fdWZl9PEh2BqcReAtf4E
         NRxg+nXVM0T0A8F93BnezeAOvLt06ZUM6LLP/RT5J+QUsB3i+K4CwdRgF8CQ78FfhmVp
         9rprTSbdhHKmNo7k+aQJadqUU3NiKj/TpTTDIuSxY8+973TKdqI4jWx/AFWoZMPhtPSJ
         pfscGXtxghSu9EZ4g8U506rr+EkvpGlfVmc/eIOxbhi3g5/SZoZja0/fSzAs6+d1JKCz
         BIiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4G8h4hgySaJey6iKxW5y4/UhksHPaOzWIIS8r9vmE5w=;
        b=RVQ0SRVTJcn8F3llZZz44t+4SHaKWsobqoPaiNf9sAndiAGBTmf4j9ixc+kwZIZMv4
         y/dir3DeUR4dZh0nBNyvHpusCCR07AKlyKtn+p4RVXs/ToVB6ck0fsIhTDcJ2JV9IYGK
         JgNbXz/1HRBZVec7Fn6EOyM+SN7aOrGJG1JvGW0T75NRbuFFgOWLGWOubxFV+/nn1T1K
         RhkIDtsrYHNb00kF2AtRgBQb7R8hGTAmyIBtdTbbsstTh6vpXmHVfhipYLxVPN0otZRf
         48HMIfyBzQn0qMT93gQOzKfy8TAPFjGOS6bQwlqXZ1/G7swTp4Ig5lVME9FDV5ZBxLy8
         3V5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="A1yF/Qsa";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o29si784228wms.1.2021.11.30.13.40.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 01/31] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Tue, 30 Nov 2021 22:39:07 +0100
Message-Id: <4d98c25d3cb7898fa27510d612742b6693b37cd5.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="A1yF/Qsa";       spf=pass
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

Currently, should_skip_kasan_poison() has two definitions: one for when
CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, one for when it's not.
Instead of duplicating the checks, add a deferred_pages_enabled()
helper and use it in a single should_skip_kasan_poison() definition.

Also move should_skip_kasan_poison() closer to its caller and clarify
all conditions in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 55 +++++++++++++++++++++++++++++--------------------
 1 file changed, 33 insertions(+), 22 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c5952749ad40..c99566a3b67e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -375,25 +375,9 @@ int page_group_by_mobility_disabled __read_mostly;
  */
 static DEFINE_STATIC_KEY_TRUE(deferred_pages);
 
-/*
- * Calling kasan_poison_pages() only after deferred memory initialization
- * has completed. Poisoning pages during deferred memory init will greatly
- * lengthen the process and cause problem in large memory systems as the
- * deferred pages initialization is done with interrupt disabled.
- *
- * Assuming that there will be no reference to those newly initialized
- * pages before they are ever allocated, this should have no effect on
- * KASAN memory tracking as the poison will be properly inserted at page
- * allocation time. The only corner case is when pages are allocated by
- * on-demand allocation and then freed again before the deferred pages
- * initialization is done, but this is not likely to happen.
- */
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return static_branch_unlikely(&deferred_pages) ||
-	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return static_branch_unlikely(&deferred_pages);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -444,11 +428,9 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 	return false;
 }
 #else
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return false;
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1258,6 +1240,35 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
 	return ret;
 }
 
+/*
+ * Skip KASAN memory poisoning when either:
+ *
+ * 1. Deferred memory initialization has not yet completed,
+ *    see the explanation below.
+ * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ *
+ * Poisoning pages during deferred memory init will greatly lengthen the
+ * process and cause problem in large memory systems as the deferred pages
+ * initialization is done with interrupt disabled.
+ *
+ * Assuming that there will be no reference to those newly initialized
+ * pages before they are ever allocated, this should have no effect on
+ * KASAN memory tracking as the poison will be properly inserted at page
+ * allocation time. The only corner case is when pages are allocated by
+ * on-demand allocation and then freed again before the deferred pages
+ * initialization is done, but this is not likely to happen.
+ */
+static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+{
+	return deferred_pages_enabled() ||
+	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
+	       PageSkipKASanPoison(page);
+}
+
 static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
 {
 	int i;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d98c25d3cb7898fa27510d612742b6693b37cd5.1638308023.git.andreyknvl%40google.com.
