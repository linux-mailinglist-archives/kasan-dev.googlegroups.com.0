Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM6V26MAMGQEF2JDMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D4FC5AD256
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:24 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id k6-20020a2e9206000000b00267a6d3f0e4sf2790155ljg.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380723; cv=pass;
        d=google.com; s=arc-20160816;
        b=cvKByor/El6vnX91La+iBSTzTmRp+SX4tB23mez6ihFp4Q0iUHn/KyZmgXjH+HVjkB
         /0qUSbJEAis/WmFySz62E2V/YaVFEOkXEH77EQsPHvBkxL/tcqxgUcDZ+ZJw84cZ8mdm
         +55ceRTcfeensXxjM0xc9dgwMmRoi04SNinw1rw9MJNlEQlhjYY5uXCOiKrxEbgvRp9Q
         3NH9E6OHegT57Y/FnWoKFP/KxXwfNR0wZ9INwVXyueYv7bHc1atCj3zKd42I31CZxNk2
         VgTmlUxx9IIFQYRpTrONxUOmNN/a3IROcbJLJrgTmLXBU34/5DxO/FDTf9JmPKsnclTJ
         ylaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Hq0TjxNhRaY+aI2TCyWlsaH01iepkfN3KTbGFZwfnF8=;
        b=Cjrt1GXdpSzVbb0IZ5AgbQqIRstzvnivWblMpoEKXxe0/hrvxocJcV+BZprmrWGAe9
         BCgK+fzK8rC4PgmzIeVnAyYQ1srVAD+xVYqAKkU/A4P5XajeFeXLtn+f4TjfKxWykAQk
         9sLZXdmO0IWJ3Xj66a3WNtDDMAOSiOEI19wj1KaKXRTqdbB07yCm50mr5ODrWnDOzCkw
         MC+Me3IoykwPZY+omHLntdqQTr4W37ii8v48HXGqNhje0V5wuLIua3bNiH/TEA9Agaom
         vzKsIRVWPIPxO9zYHzWJnuBsMkgOeWxgk5tVhQsuenOWPFu48NS2R2r1hniNh5KvaPd6
         fvuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d8oJ2o++;
       spf=pass (google.com: domain of 3suovywykcf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3suoVYwYKCf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Hq0TjxNhRaY+aI2TCyWlsaH01iepkfN3KTbGFZwfnF8=;
        b=txqwA7PtNV5GHmNojgkxpw+jWbrkc6OVK7zZvhnTLsACrg+r5voYFy2HbLhoB+M/zt
         8i5iGTdyrqJGcfP3Hk0qsuIjmy/6wrFjePYvvbN9t9cPEIEZQC82eLAnddUWAXiNnurt
         C78t24F2WyH+s/XAxlbzPv4bHSccpJ4grQ6KEvPFFL03yp+sMCSQM/zwp8z3MQ8MRWWu
         MRv++j5Rl6MOzOxDZ1AeGyEgqb3hENzkwsNCDFGCbDYqMDCo20Ae8wlh/+jfgkGQyzAL
         xrJTzjugGRgjZn58riWZAbz6Ki3xHs8E98+dL+2t3UNTh8umP68FHoUzVYZnvZJQsKr5
         DxDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Hq0TjxNhRaY+aI2TCyWlsaH01iepkfN3KTbGFZwfnF8=;
        b=wiLXOg4Zzy6uuL/wApxi8qPsFMyhNZS0w/JSnWh+d5IBLhiWWQWox2rHMZyAZm1MhP
         Jru2ZQF3SRnrmE+S+kpJ+wV/gb6uE2y/LiQ2qjAfBXqfndlyaNYpv+5BBnAj1S51hZN1
         7Swl9lqRv6G3kppyR1ZHpAxm20ZY6nAFmrlLbZnD31x4qEZafv4maSRqFZLK2NnK/mkZ
         o9HqvocpAbwxm6wvhdF8z57CGQTAS1Y+HlkAJDCBk1S2WdETUnmU84iAb/SOTA4cp4o9
         WmuuRE/tUMWWPxhdZBTT9hObjfUHbW/b/gvoAR82DCHZDu5GXWYSv/bDt+qyDRjjYpZR
         LKEQ==
X-Gm-Message-State: ACgBeo2R/FPI24/vqnDsLudK0lEH/iUiXUk5EbCvvtAuotNzqhwAWUaY
	NOkTY2Hq7q8nSFWZSsg1TfI=
X-Google-Smtp-Source: AA6agR4ONIA2dmSU9wbQQKN5jo21kUtZL1qvBcR/ElqmExj8cnLY34C22KDeSaj5131DxupsXMmIUw==
X-Received: by 2002:a2e:7a1a:0:b0:26a:558e:5acd with SMTP id v26-20020a2e7a1a000000b0026a558e5acdmr1768741ljc.312.1662380723788;
        Mon, 05 Sep 2022 05:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3fa:b0:494:799f:170 with SMTP id
 n26-20020a05651203fa00b00494799f0170ls4741822lfq.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:22 -0700 (PDT)
X-Received: by 2002:a05:6512:3d1f:b0:496:84fd:fd7e with SMTP id d31-20020a0565123d1f00b0049684fdfd7emr221597lfv.32.1662380722701;
        Mon, 05 Sep 2022 05:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380722; cv=none;
        d=google.com; s=arc-20160816;
        b=sFQ8qmidJvZZc//nxlJAN5mYGI+6BCFKOSnr8rJ3qaszYi2GGDTBNHH4x78gGgoPjN
         MerALOJFfHQdAWRkbCa2WyQzkWaS9stQokCez+fdm5eivuRUtZnnMx0BnT9a+IDyszaV
         3BnWOBtwDYay7lNssC0TFkEgoSyQO79vUsqN6FG4LTKsnn6VFpacG6QXL34Bnse7GBoK
         tA29lFT9O3V74Rum7YdkgD7fjGibX0hbf3ePbkLBibgc2Vsp6c56XXRMX6r6BzHa156I
         fVDB/9j3et3a4JSX0FP8tZDTWGtDx2K26z72a1wmOgo1h6MofAYJcNSnpc+UJfYDyUAy
         5nvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PTsTfo/gJDV7iQzWmhln0w3yo3kBxDNSc9M3IZOTBoE=;
        b=MezUyYOcHM3InDrkYBxwpBTA4w4GrwZcWTK3ym4x/VfGDjq/hXxYGNkqZjK3SlSpvT
         EWTHRagcgNCffOgcfocZ4zj5+9lAB4D+GNA/TOHilLXv03vwCSPxQjIhHlCKAUwULajp
         GmfoNIVZlqXoayOsQ52bgdE7tZ0RpaP0dF1vwVCbIsGWUnK5xx1BEPPrlBGFgF2Qzuvo
         EO9NE1V6FtqT+8KyYOugHaFOaCxmeGsJV3saBRJgkLKtwjUGuBECEHr3HvJMGVOWrf4h
         WfSr9K3sMhxUOatwib+dHRzUijnCrxxEvftMG/GPKFTQeCrTt2mBzv13EcHkvEWZWEE6
         EFuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d8oJ2o++;
       spf=pass (google.com: domain of 3suovywykcf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3suoVYwYKCf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id n17-20020a05651203f100b00492e3b3fd98si367474lfq.8.2022.09.05.05.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3suovywykcf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id f18-20020a05600c4e9200b003a5f81299caso5302025wmq.7
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:adf:e74d:0:b0:226:d514:8c29 with SMTP id
 c13-20020adfe74d000000b00226d5148c29mr22189326wrn.664.1662380722163; Mon, 05
 Sep 2022 05:25:22 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:17 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-10-glider@google.com>
Subject: [PATCH v6 09/44] x86: kmsan: pgtable: reduce vmalloc space
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=d8oJ2o++;       spf=pass
 (google.com: domain of 3suovywykcf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3suoVYwYKCf0lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN is going to use 3/4 of existing vmalloc space to hold the
metadata, therefore we lower VMALLOC_END to make sure vmalloc() doesn't
allocate past the first 1/4.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- added x86: to the title

v5:
 -- add comment for VMEMORY_END

Link: https://linux-review.googlesource.com/id/I9d8b7f0a88a639f1263bc693cbd5c136626f7efd
---
 arch/x86/include/asm/pgtable_64_types.h | 47 ++++++++++++++++++++++++-
 arch/x86/mm/init_64.c                   |  2 +-
 2 files changed, 47 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
index 70e360a2e5fb7..04f36063ad546 100644
--- a/arch/x86/include/asm/pgtable_64_types.h
+++ b/arch/x86/include/asm/pgtable_64_types.h
@@ -139,7 +139,52 @@ extern unsigned int ptrs_per_p4d;
 # define VMEMMAP_START		__VMEMMAP_BASE_L4
 #endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
 
-#define VMALLOC_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
+/*
+ * End of the region for which vmalloc page tables are pre-allocated.
+ * For non-KMSAN builds, this is the same as VMALLOC_END.
+ * For KMSAN builds, VMALLOC_START..VMEMORY_END is 4 times bigger than
+ * VMALLOC_START..VMALLOC_END (see below).
+ */
+#define VMEMORY_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
+
+#ifndef CONFIG_KMSAN
+#define VMALLOC_END		VMEMORY_END
+#else
+/*
+ * In KMSAN builds vmalloc area is four times smaller, and the remaining 3/4
+ * are used to keep the metadata for virtual pages. The memory formerly
+ * belonging to vmalloc area is now laid out as follows:
+ *
+ * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
+ * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
+ *              VMALLOC_END+KMSAN_VMALLOC_SHADOW_OFFSET - vmalloc area shadow
+ * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
+ *              VMALLOC_END+KMSAN_VMALLOC_ORIGIN_OFFSET - vmalloc area origins
+ * 4th quarter: KMSAN_MODULES_SHADOW_START to KMSAN_MODULES_ORIGIN_START
+ *              - shadow for modules,
+ *              KMSAN_MODULES_ORIGIN_START to
+ *              KMSAN_MODULES_ORIGIN_START + MODULES_LEN - origins for modules.
+ */
+#define VMALLOC_QUARTER_SIZE	((VMALLOC_SIZE_TB << 40) >> 2)
+#define VMALLOC_END		(VMALLOC_START + VMALLOC_QUARTER_SIZE - 1)
+
+/*
+ * vmalloc metadata addresses are calculated by adding shadow/origin offsets
+ * to vmalloc address.
+ */
+#define KMSAN_VMALLOC_SHADOW_OFFSET	VMALLOC_QUARTER_SIZE
+#define KMSAN_VMALLOC_ORIGIN_OFFSET	(VMALLOC_QUARTER_SIZE << 1)
+
+#define KMSAN_VMALLOC_SHADOW_START	(VMALLOC_START + KMSAN_VMALLOC_SHADOW_OFFSET)
+#define KMSAN_VMALLOC_ORIGIN_START	(VMALLOC_START + KMSAN_VMALLOC_ORIGIN_OFFSET)
+
+/*
+ * The shadow/origin for modules are placed one by one in the last 1/4 of
+ * vmalloc space.
+ */
+#define KMSAN_MODULES_SHADOW_START	(VMALLOC_END + KMSAN_VMALLOC_ORIGIN_OFFSET + 1)
+#define KMSAN_MODULES_ORIGIN_START	(KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#endif /* CONFIG_KMSAN */
 
 #define MODULES_VADDR		(__START_KERNEL_map + KERNEL_IMAGE_SIZE)
 /* The module sections ends with the start of the fixmap */
diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index 0fe690ebc269b..39b6bfcaa0ed4 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -1287,7 +1287,7 @@ static void __init preallocate_vmalloc_pages(void)
 	unsigned long addr;
 	const char *lvl;
 
-	for (addr = VMALLOC_START; addr <= VMALLOC_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
+	for (addr = VMALLOC_START; addr <= VMEMORY_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
 		pgd_t *pgd = pgd_offset_k(addr);
 		p4d_t *p4d;
 		pud_t *pud;
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-10-glider%40google.com.
