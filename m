Return-Path: <kasan-dev+bncBCCMH5WKTMGRB76CUCJQMGQE5S6IUQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D95FD5103EA
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:47 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id az27-20020a05600c601b00b0038ff021c8a4sf1499961wmb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991487; cv=pass;
        d=google.com; s=arc-20160816;
        b=psdMHapnR0MIWh1eDAayJd9UadWvpb0ppzwshf/pw8CQXBXdwPM15gLLZ76qh9m7oA
         cMya2JRdxlhLRctpEmc+tyqLXnHeqLHNek4O+hT+uzjaq4TmZNhxtOI3PLqAXiASTCiH
         WTrunNKksU1OgTQSi+04rebF7bL7c49xOr9u3HFSgy/j0K2ywgzKo3UqPeRAV9mnoWeg
         VxZCztidYoiOBt4Damzet+JtXYypdS/B8UCnXBIaukZDwej3QbcoROM40KAFw61lCVQy
         pLSxUssW4I5OeDM37qwUGQZ+8+Fw0f3rmpiPKpxaOqw0baWzyZ4rqgimpi1l30Pb+sWm
         8jxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0QZqqt9B6CDYOAM1/zDjYC3VKgvf0VmRBheHEOy/+Fc=;
        b=n/G8YLkKQM9He6M+atrOTlPg6cPikbFYV5/Pegn29PkD4BskhtzvOwFU/cGsHd7min
         ddCDSTkyRSLMXgj7UHFbOZ0WRn2UrJftiS5r0iKV0w4XRFHBf+Wcj2F9xKwAG7sve/T+
         yqXH0TjinNcb6QHLGKY3MReh6eNP6hkkhCS/uEfAofh6JcAsjMCGGArqZFFjDzsJmSLD
         8c7TO5EXEM3gKCgFdePrRRLdalr0pLtihND0ij7wSvct9iUmEyNW5uiFi3500NH5PZUP
         yBkyZAagN9WbJJ1VXMfjvKt2DX2nvNLg+Ze1kt6Xu9of1lt8FeVfhbdKaxAtqsRasNXo
         uNNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="m/GoUZBV";
       spf=pass (google.com: domain of 3fsfoygykcxoejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fSFoYgYKCXoejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0QZqqt9B6CDYOAM1/zDjYC3VKgvf0VmRBheHEOy/+Fc=;
        b=TJ6iBlGfd4c+EM4koaVlVoNVg6GBTZ1rrWoRkeTfM21eeeIycGY4OuyUZB+/vPPxcB
         b8PdV8Im0LZhDr8jxeCDHPH44Coo6/9HySQuHLOSQF7X5NcGC+QiUYyID4DAMGbGRoLx
         q7P3njopR+RAdIOd1Q+GtILKcrWLY/xUHuYvEATZ7Ecm2BWnvKEiKMMz3G1qOKhzpYga
         jkn9ZPbqJ07ZeEjWFnwAP7/Yw2Kqt9WhtihpLSbLt25jHk40+UzA1fAuPhemTSHluvW9
         A48bn21B5pqQ9g2dV6ZeFDoyn7OQ//WuVPurDk22tz/gIMPVuukmKmypAjU5vHU6JyUN
         y0fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0QZqqt9B6CDYOAM1/zDjYC3VKgvf0VmRBheHEOy/+Fc=;
        b=RE74LQI+uvWWcUuCpYwBjPFXDM6thMo1GsKck3RmVhWwIu0iKhsHOR7R2lmvKCvgA6
         1Ptr1y8Qo3hhmphVkAPtcp3sfQWeYdPrvK26ImvfsmOV9M0+RMKRzJrSspyVPC8lr5Cu
         4xGnRAtf1h1bilfH5vVcDAc21Ox/yYrNxmDdAJiVd3CyoUDIaPrj0+aulqlsVjcHahxP
         w8A8+E63kbJ3OKyRLqCns14XUwbMGDBl8UrMM1QbvHVnoUvDOeDFQifDgFOfr5cDquCa
         innqMN4kAGpDbJJ/EKyz00lXxd8tIDb+ws9gHva0fo3GqeMQCVS+/b7eP2lr8QCqwTqe
         pO+g==
X-Gm-Message-State: AOAM531syXSgweRhDtltzVwBmyWDSVl12g00DKmJz5vtkuomjzigRxKK
	zLUxjkSz5HSL4TjN9prA1gw=
X-Google-Smtp-Source: ABdhPJximCkwn66B7kXio0zt9JHqQz3TAk3HN+vUoRUpbo15o4WU58dnwJc616xDC5SlITMMkDDUdQ==
X-Received: by 2002:a5d:5983:0:b0:20a:8801:597b with SMTP id n3-20020a5d5983000000b0020a8801597bmr19142470wri.287.1650991487549;
        Tue, 26 Apr 2022 09:44:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20a:eafa:40fb with SMTP id l4-20020a5d6d84000000b0020aeafa40fbls1005558wrs.3.gmail;
 Tue, 26 Apr 2022 09:44:46 -0700 (PDT)
X-Received: by 2002:adf:fb48:0:b0:203:f986:874a with SMTP id c8-20020adffb48000000b00203f986874amr18881184wrs.614.1650991486603;
        Tue, 26 Apr 2022 09:44:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991486; cv=none;
        d=google.com; s=arc-20160816;
        b=RxqFYMoJ6mV5e1OcUGfT42eqe3EJthNDqYgI1mk5MRUdXhSkdmIYO2HBsRTFmHjbyX
         bPAGhsBFA+SyJwMm4LzBggRsCuVZGUxv+ANx1vXOL8PH5oSrgImmtE2nt/dnICIsYERA
         u+q1eXQvS0jkuwy2bBzPW4Cl1tZU6NhVGm8uYDyW16yr3mJ0l/KrxFUXBi3JQWZLIcVs
         M+9WHuxCuWjsZtULuMjP/GPLDQu8h79cyyhoSUHmvLmAgpDaS+ZoNiUuQegLABJRPsAM
         6iJJZb1cr28onZa2WZmYZysw+nYTlcX2NgFmgLDuMAW99Y2ayImUyuMj6BvLlL9ScKdn
         jsHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=H2XcU3OLx+0JTyyML32bzgUT5MJiV2tDmnYI11nI1dE=;
        b=QEruUYGCZxlFDiBX29S4goVhvZ6WFvIkf+igNunX0x6djIsjiSs0YqvBUgIusA5Uu4
         2WnM4uUNCPh+29iKL1uNSjQ1s4ctKvg2tME8vtsYO1oPobe4MrhhKA+oR8Zy1HZplHUV
         2I/O36PM9H6fFan9GyL8U5Gkw0XIePP0s+DKYwcYvfuxvi733U9LPgJLqvUqG/2bgOvI
         NM92s645GsWIkwnh1YZJl7uNzt+USEh/iVO2ek/9HucbyJahxWioSp3QHZWmZ6W3e44j
         QIBZeK+AxunYqKT61Hpnhpb1CjAdh/AL8t15EYe0W7RxW+idfkgTTISkGukmHC/impcE
         9lMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="m/GoUZBV";
       spf=pass (google.com: domain of 3fsfoygykcxoejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fSFoYgYKCXoejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bg1-20020a05600c3c8100b00393ed6e46d8si117244wmb.2.2022.04.26.09.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fsfoygykcxoejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hr35-20020a1709073fa300b006f3647cd980so5653114ejc.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:46 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:4315:b0:426:155:e4a3 with SMTP id
 m21-20020a056402431500b004260155e4a3mr1554638edc.324.1650991485934; Tue, 26
 Apr 2022 09:44:45 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:39 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-11-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 10/46] x86: kmsan: pgtable: reduce vmalloc space
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="m/GoUZBV";       spf=pass
 (google.com: domain of 3fsfoygykcxoejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fSFoYgYKCXoejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/I9d8b7f0a88a639f1263bc693cbd5c136626f7efd
---
 arch/x86/include/asm/pgtable_64_types.h | 41 ++++++++++++++++++++++++-
 arch/x86/mm/init_64.c                   |  2 +-
 2 files changed, 41 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
index 91ac106545703..7f15d43754a34 100644
--- a/arch/x86/include/asm/pgtable_64_types.h
+++ b/arch/x86/include/asm/pgtable_64_types.h
@@ -139,7 +139,46 @@ extern unsigned int ptrs_per_p4d;
 # define VMEMMAP_START		__VMEMMAP_BASE_L4
 #endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
 
-#define VMALLOC_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
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
index 96d34ebb20a9e..fcea37beb3911 100644
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-11-glider%40google.com.
