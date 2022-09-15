Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIH6RSMQMGQEBZLSEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CCDD5B9E06
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:05 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id m3-20020a056402430300b004512f6268dbsf12391873edc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254305; cv=pass;
        d=google.com; s=arc-20160816;
        b=DsEnX9bzn7QMSrusTEfbMxqeL+cdgxkBvFYnMsrogxCfVN5UEhj22L0wxjLLX5nLmb
         0DiMR86plMQz1WTVuDHTkOXenMOCvR3/K79GyKAc5apRpkMXPRIj+JZIGfyeObHS2sLA
         62uolzkZNKecz//96dyhS9xJ/x1MhD87d7+DXBhyx28ZnvXKM5bjXZNA6xkvPa3lohVK
         I59TH7rjQa4jzRnftcrjNPucG0lsGbIZp3tBey3xoC94N9Hkd8Rs0ZWygg+NFA91dDq+
         dcw8UWtZIkN7Z8a1vV9c/7dX3So4+EuZelCO6PjjqyO1jm9AoMTP0fx+0w/hUhHECiYq
         dIVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=4XSQ6M+n2JCB/xxL1Qk1UdfWOnGAVSEenoQU7CYnnkU=;
        b=VEaDCHZGhBXHU3In7z0JaqFaWOV8DfbPGJGAcd+8uKF2eTO9WGEn+1dALgWgHMHlu0
         OIEVuo5Q4XMXeY6k+Gyts4dOtnKrCqHWYHmuarByOgC5Z4Zt2ZAOamsZDVInXir3tc9U
         vj8QEZ5+YK14h/nWW6MBHuz0ZGjmgLa6UY8oKGS8pUTXlkU8L5SLMYgk6OmOP2bE/zNC
         pJo0RkEPPfkVlzW6bBHUW63UhZMCK9ENrhk0I8c0+sFk14D0S+WEOD3VNFh8pOtWTtuo
         POrHyvTVgpnI1zmWlZymFR2h/uTpOoMn9pRKzrXiApmBLGv/l0rL1Ni0Av6+K0kLPtzG
         4ttA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JPgXbB5I;
       spf=pass (google.com: domain of 3hz8jywykcuosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Hz8jYwYKCUosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=4XSQ6M+n2JCB/xxL1Qk1UdfWOnGAVSEenoQU7CYnnkU=;
        b=onvH+nIQtc792f+4v0WQIJfoK82JXp5KSYAhDLlCYPw+1Y1gO6GfSFYVquNutmR/Ut
         gCwynxg+WKPjvo4LEwKhDff7SPKyLTBxjAPrPz3LHFMRgqRD2A08kuPxakQRU+acXATi
         UJZEhheeQ+8fQtbiU/8m54nERkQBzLMSroopr+rmxSVsujMhddEBDNZB/tQrvkYYIyQA
         ihG9mtb31o0gy/l6dZyVEWIhnFa3J/PAmUdGZarhbwGazoLD9MTDq8QyezgsOEH3+Nxo
         m7/bfX9KVx7HVunGTuTcNQuBGp8mctoz5dRfVVRAoCLmbXHgaJITeLeI8OJPAC4U0cLi
         o3PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=4XSQ6M+n2JCB/xxL1Qk1UdfWOnGAVSEenoQU7CYnnkU=;
        b=40txM6gHJcmv2qJWaJmyI6ofrN2Ic5wV3gXTPWSAAUx6ihNvRLOtXt4d6z/y5zIE/j
         u/LtVAZr1sqHDFZxJ2nmAXpykENXnAXkXvIXa+S6ifrDYC1Zew/BB0PV2OWwXXz6dvdb
         muuY/GAAw5TKlhuHuspj49TqhHpieAdiYxjAb1dyIOF2mnlAWKpWUuZyeHZyRQVbt+Y+
         9cT2zUVpp4RHHYW6ewfEqiBoGTmrGBriR2QmosJ2lYZPb7h6dU65hhFlii/mSQrUUWiN
         04rxPiYIaQxrkdT8AsuQt9kGb6u9k3Aw9FG8oXSYZ37g/J6nO93/ulb17btVOq2xgo0H
         yGUA==
X-Gm-Message-State: ACrzQf0jORIaQzaB16RmJV7CLUwnQzkCattyWKll2HqRkFwLO3CxrBuA
	W//jGXTCcTnRBYWTSt1hAaI=
X-Google-Smtp-Source: AMsMyM7zF4A6NJj1uyob47CJylKCH7RKPC2tBNiHv3lxgypiG18b1UOdqLKgIBd9Ynqu5W89g6CPMQ==
X-Received: by 2002:a17:907:b0e:b0:77a:d97d:9afc with SMTP id h14-20020a1709070b0e00b0077ad97d9afcmr284968ejl.199.1663254305145;
        Thu, 15 Sep 2022 08:05:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:278e:b0:44e:93b9:21c8 with SMTP id
 b14-20020a056402278e00b0044e93b921c8ls2969401ede.1.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:04 -0700 (PDT)
X-Received: by 2002:a05:6402:5ca:b0:43b:6e01:482c with SMTP id n10-20020a05640205ca00b0043b6e01482cmr254793edx.189.1663254303437;
        Thu, 15 Sep 2022 08:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254303; cv=none;
        d=google.com; s=arc-20160816;
        b=nKwEWumrS/iw0YE1xdmKeUGSc5BYo6/uVFiiVN0jJutiyZTwA6QaDiIfqw7VwuRqn8
         RszSUFS7O9+im4aoMZKXce90xy0qnEmw2EMRvgXC8d3gz1DUqYPZUafFVlAhywsEADoj
         tWEXYpUWshFMTiBWaNOhlzouXxT4+OJohMRxuHyrJZ6TL1YTnjyNh+gZpwkZ0WZVFy/O
         pwv4bqKkcZDGw0sD3LbfXkTqxTZl3Oqfwq38Hk+LnmBckv08qW/9bGEKR4gNn3GHvwMS
         P3QNVM5XYDcaeoflKeqyqC10YSORjP8XuKQeplKxBteQZ/p7r8WNz8GhE/6ZaknTmgNE
         lXNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PTsTfo/gJDV7iQzWmhln0w3yo3kBxDNSc9M3IZOTBoE=;
        b=iSFDwUi1AdvPhoAVAu/p3HWd6u1I3pPsxfP9sLlIPchlmc8xTfIQ+3WGTcsXY2fIGj
         O+jTmcZjkbt4CJugDTZeMmZ0voNy8IXs8TYxNhREaf3VCzVF6Yg99GPNqhU8zKiIngyw
         yDxVB2FjDWyyiccO/h5xhRUUUyhaP10Um5j69TOGSIYqy6Db99ucrNfoPXoMbUzcKV4U
         mlxSRCp8baawM0uI3QAccb8kUgUbcAYbFQtKL9n+82nsSVhHZGwf40iGFouZg9bcB99G
         JSRRLUQMFPnkW+keYBmKqCXUY/FS6LzfAfxljzmWAKXpOWGVum9Pzd+n5YvTiUMST3fJ
         o1ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JPgXbB5I;
       spf=pass (google.com: domain of 3hz8jywykcuosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Hz8jYwYKCUosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id c12-20020a056402158c00b0044608a57fbesi551804edv.4.2022.09.15.08.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hz8jywykcuosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sa22-20020a1709076d1600b0077bab1f70a3so5765977ejc.12
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:03 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:2cce:b0:77a:6958:5aaa with SMTP id
 hg14-20020a1709072cce00b0077a69585aaamr280253ejc.245.1663254303074; Thu, 15
 Sep 2022 08:05:03 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:43 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-10-glider@google.com>
Subject: [PATCH v7 09/43] x86: kmsan: pgtable: reduce vmalloc space
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JPgXbB5I;       spf=pass
 (google.com: domain of 3hz8jywykcuosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Hz8jYwYKCUosxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-10-glider%40google.com.
