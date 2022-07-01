Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3UG7SKQMGQE63ELQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0261456350F
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:43 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id az40-20020a05600c602800b003a048edf007sf1085546wmb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685422; cv=pass;
        d=google.com; s=arc-20160816;
        b=ymQKLCzjRa22sU0lO+pCnIns+LpHhymDETlPYAPUkJNbMUTjmbo7lWgkNYXe+yLW2q
         YDgiG4Uxo+OajDsARMto7nkOnAFumZyMz5K3pTvTGyYSqaQocxTwnHxe72+cwIbVCeYi
         1cELEbQSc/Mwi8SbVzZaJxBPwzZMDQSV0ZafXJvvVNJWP2Vwow6Bcqlwew11PUBz4Xxp
         8oswtAjn6cXIGPcgNZ3oF9Y/326V56fSpULuKHLo3seLRCUne1shfrz/28sIej7Ia+fl
         9TNxZxx+d48pqAUL3yU7E1HjV4k5ITmQZRBxJdNhz6tDV8ff/sLalCTTDnHBAyW43Mpv
         Pd8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eXgdvHoWMPyr8JNsQe+UBUOk9vqsslFDzBcvhnPXE7o=;
        b=n1x7EvcIiQl+ciOFSkg4fWApD0T2Wocw3xoi5HKG1rtbB6UNvCMmUIUySPbmJ3xmzV
         kSYUl7iieCi1gCYFHwg/BkUrrrwB5U4uIH4eVb+rptE91FsGuEMhueu06mQBMv6JG1U7
         Y5EjGq77efAr65kN/oIDs7Ju/xPMW+0HLsOTdJ+OOMalIsxWtZkJ4LRPVeRIj8iTwSfp
         P+qlMaku4V8fQlRRbX0ixkFgVoQZoXXpssnF3PCe9BnEw3CKsUxFOwbpkrLT5geCsifN
         2d3G/+inPAfQOCYlGGoAdHHvpuZ1yKxmlG/bbh/Tsh/V/LCFyWjLqvuGdXpEKejFbHwU
         4d2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U+fVjLRG;
       spf=pass (google.com: domain of 3bqo_ygykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bQO_YgYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eXgdvHoWMPyr8JNsQe+UBUOk9vqsslFDzBcvhnPXE7o=;
        b=VtBoy5U02qdPDYXdbiNezmMnqeXWoglzGmMOIA8cAv1ewmg4ELFLp3AGmt7BIAWdDz
         LjCNL3K9vi5pMjsABGJjasKABKUEBm2J6m0+oys2R0O7SdrBhIUIbfScl00gnt51Qux7
         o0tE2Zu7jzf1+jwzjg2j7KtKRfMouHZO+sAlhtHVaj/HlAeUEPdr+RjrPCwHtTHTocFH
         lFHY6zuqL+ZHnZlERmrvNGpTGWU3w4tYYiKvCeHSOZ0FKo5skpXS1r0oAJUYYlkkLrNY
         V6512QGenSripl9rgEhdixtUqlDfBfjQnR4D6TGBW2OU1fZJh6c1ZxpE6tkHuEvLGKMk
         pnRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eXgdvHoWMPyr8JNsQe+UBUOk9vqsslFDzBcvhnPXE7o=;
        b=MMExWHdVT2cqa9J71kX/E9Fn4BzUTKrAgef5gYwhxeRAAbfKAjtBj/O9cS77pYeO3r
         w2D9ibfOEuKje8dHowLUgesycVgt5Ac/g5dUMOJM48EDh0UXfFNNhQIOWUK2sYOZs2NN
         SKBucNbo6nXop5ZfSy2g8hjHCiO1fvywknOgw5vKBHRYlYDnMMlwWPSyhqS50Egv9qPk
         n9pScN99a0BXzYIjP+a7bwRFlTf27aHncRpDbalfRabLnyq1KEzbWKGimqOnWd1BvAM0
         b00Mz94iEtPtad0YilXZQjJDO0lAor9cEBZ2JG2BTzB0DumO8TpnfZnzqy2AUjAjl3LQ
         zNsw==
X-Gm-Message-State: AJIora9TN4oIQKM7ZeZWMr269jmTNToAWdmQ2bIrEGVOFHepJBHp8gUq
	OiO8RnwuVRWQZjlrjvUTGd0=
X-Google-Smtp-Source: AGRyM1ulHWslJEkosJhhaduTMEgkllUvYhXl6wzFmzncW74eK70quedqD7rKuzzUC8OaWMlpxDR+cg==
X-Received: by 2002:a05:600c:b51:b0:3a1:71b0:a115 with SMTP id k17-20020a05600c0b5100b003a171b0a115mr14854844wmr.41.1656685422423;
        Fri, 01 Jul 2022 07:23:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:178b:b0:21d:350e:23a6 with SMTP id
 e11-20020a056000178b00b0021d350e23a6ls9194012wrg.2.gmail; Fri, 01 Jul 2022
 07:23:41 -0700 (PDT)
X-Received: by 2002:adf:ffc5:0:b0:21b:bfd5:caf7 with SMTP id x5-20020adfffc5000000b0021bbfd5caf7mr14747825wrs.353.1656685421453;
        Fri, 01 Jul 2022 07:23:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685421; cv=none;
        d=google.com; s=arc-20160816;
        b=AvGDsKPMJlKF+H9oYG5C091E5PtgjT28PoDsBF0eGK9HjnCYsQ2cF2gamIap2QXRTe
         RcZu1BW3brWVUELbYW4Vonos3D6/b2E0qaeqNKQjcUMdczqOKsWV50IFxg4ZVToyLVP4
         M0S7kP6lo8G9XjIXRyOnQsEgENgVWQxd+2QCmG1SvRCtTl3JOY0fAP8Mnmc54mot8a5A
         3xtBo00nAOhqokpjOLW1dy2oADxpiwkgswM5YNtOHboB9uRnB0YtZcWWovSdE97KmYSF
         cNHews+X5TgRvNfqf8f9Mp05R68TuxtHDQ6bhSNMzcEXZq/Gzc4NBVbzkbydKGSZp0W4
         AzTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9CmKhXrgq4R//9cDj1zsNax3tT0d2FywVlyLyC3NqDY=;
        b=ao+6YyHUIPjhZ5tpuf8Ue9r4il2seMIr4bdmq0U6qmm6nNcP3DAxLm0ckZiOcmZFv1
         Xfwad/dITNVBfA1kPudsfZn2IK49rt6f7v93b8qMRm7HbSU98T1efZh8Ni8LAX5rqDzY
         wfpq8UUzL6oHne7iZwtiFLHOOhzTmHiIpKjM9Ex6gaxxp54RGQ06g5k098JxwqjOoch2
         m3c2fZ6WTS48dUwpz3zCn0+xxyaiGIrHe5ijP5vuCOwKELPMl+8HpzSMjMvSSKXZ5S26
         ZVKYRZflGmY7iCtyn+zHBxdi5SMqzqopjYDeCJcfl3KEnYBVaTthbNLKLTy0cdTBD3/j
         if3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U+fVjLRG;
       spf=pass (google.com: domain of 3bqo_ygykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bQO_YgYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a04819672csi299683wmb.0.2022.07.01.07.23.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bqo_ygykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id 7-20020a170906310700b007263068d531so844862ejx.15
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:1914:b0:437:8f32:96e5 with SMTP id
 e20-20020a056402191400b004378f3296e5mr19396026edz.218.1656685421053; Fri, 01
 Jul 2022 07:23:41 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:34 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-10-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 09/45] x86: kmsan: pgtable: reduce vmalloc space
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
 header.i=@google.com header.s=20210112 header.b=U+fVjLRG;       spf=pass
 (google.com: domain of 3bqo_ygykcyww1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bQO_YgYKCYww1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
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
index 70e360a2e5fb7..ad6ded5b1dedf 100644
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
index 39c5246964a91..5806331172361 100644
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-10-glider%40google.com.
