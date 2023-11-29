Return-Path: <kasan-dev+bncBD2INDP3VMPBBMPBT2VQMGQEIQ6QBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B6D547FE233
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 22:44:18 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35d37340e5bsf117765ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 13:44:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701294257; cv=pass;
        d=google.com; s=arc-20160816;
        b=NoceLPEwobIz9HUVIbam/RAA5HKWedpjiQF01vB7ClYPXML0inEF7AmdPmLzjQ7D7M
         cv74eF8oHAVLUKbKhT/B0VHQ8E8v/mYXEqtIP2EI1W3aoBSQNYiyiG1iAHkx2oBurQXI
         aCo/S1O7aSb0k7lFS0u4Jon1ZHgQuRY48Y338x0yq24eL6vXA4LPRC/I+QNB7AUG8L0C
         naurXssQleyuYkAjc9S7ZZslLQ7B9fEVB9lQ1mw2mXoeHEWovPGXA4zrUHKu+fadD/dw
         fZD9RQJOFJAsuuwq+oYFIKkQuHbe7AdufRg8F0r6MwOkH7vVpyjVfonwwrOFYgot4apn
         +ilQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZReK06640IYgPSmDQVT8Ds/ckn+4jphqduC7Lt578Zc=;
        fh=x8a3OjaLFwIU7qMtOgGoexhvLtunbmhI+SfwfyrBClc=;
        b=N2TcJ5ZguM3gbbYS+GlkuE8CRVG+TBEodkMMnjtv3Awfd81Pdt+DqEweh97lGwoKac
         4cNNYSinDGKpbfuis33ii9NYkdd9Pz49xTdwqy8kqsMUykiUcu8SnzJLCFiuhOVGHQyi
         P0A1GqsmGNfbpbd1u50zRr/YxTnMXVEGgIexNnfFaOstRYYN7AfYPvq9++hBK2cyJXHQ
         An+SyNlHwrxEQl+ItteFU7DFGdcBZBy7XlgOVzXsEwzUDFkHuMEYDr9SPFoYpTv2+qov
         1BUOOnTvmEg8deY3rWgufKE4XYoMH1KoxUrLyx1Ta6kQ7doWHSzbhJCWGn8k7nkm3fWZ
         CKwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QAlYoBZp;
       spf=pass (google.com: domain of swboyd@chromium.org designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=swboyd@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701294257; x=1701899057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZReK06640IYgPSmDQVT8Ds/ckn+4jphqduC7Lt578Zc=;
        b=B6NjcDVcnmBgLm82GqdJ9qbG6A6BEKor409JScY0YQF6/xSa0/zbc4kNrF5q9PXgjI
         N+Q2ydxMTWU3CYDwcfg+ixarw03pS19gC4rFY8Qp4G38c6cUhZyvjDNfjl6Oabqg1vMN
         HTrLD7n8OKfNYBR1eJdrOcp9GIbIkPgN7QY4vDX9wCUWWc3oP50FEyIqhC016I2/Lcab
         tpykg6GVh3PyrobJQ9189gNYdDCBKIMHmmk/9luW5PfBfoKlStyUpXSi1GvpSJnVYyUT
         pVIueEk2oeqnukIG3EilKXV2srqRzbVcqh6lgc6vbC3TylnYG0JEVhZrj9rxac3Ymsiv
         /v2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701294257; x=1701899057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZReK06640IYgPSmDQVT8Ds/ckn+4jphqduC7Lt578Zc=;
        b=uRWw8pNeLmRy5A7QjAmzKn+W8GAQ8uniyn3z+Xei+8pBNoR4IjUV9F8Z4Oz7ZrSuVN
         BL3KG4d2tYc7aF6LUcqFoKLo62hJ5GNitXH6PELgCZlQUJlamACBGXjtApK85pu5EYQY
         onEH4ADlV/0KXOz/O3/BgKQ+Q0TKLrGQTWU9bGCnOnDFfKOIeRSi4mw5OAzdpxkHkugp
         vSRvaxRKGMy5oknksg6N+A6K6tyEkKOvcHcqDEne5F08Dl++6C4Qnpv4mM2jUwgJ9pPI
         QNK9Ww6mfAzLSyGb9IqEo/BtC1Wr9vmLgQmIYsIORNu4BbiJ0lMIe7m72hsUCS7cH4nK
         buDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzWs/8Mre3w5ZbOUuPGifSRo4AXHAG5KWoRDvMP+9bqTg7J9tHm
	zrqcRNrSCDJEfGnFiag+Yis=
X-Google-Smtp-Source: AGHT+IEw0rreBR/w7UHhjNKtt6+fBxPzwHQEPLEPnSgtCvqb3LbbohiJIVPBwNudBtNFOiYPx4WOqg==
X-Received: by 2002:a05:6e02:23ca:b0:35d:2d08:d729 with SMTP id br10-20020a056e0223ca00b0035d2d08d729mr5730ilb.3.1701294257178;
        Wed, 29 Nov 2023 13:44:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c6a6:b0:1fa:a4a0:84be with SMTP id
 cv38-20020a056870c6a600b001faa4a084bels291055oab.2.-pod-prod-09-us; Wed, 29
 Nov 2023 13:44:16 -0800 (PST)
X-Received: by 2002:a05:6871:58a1:b0:1f9:e123:4fb with SMTP id ok33-20020a05687158a100b001f9e12304fbmr23149823oac.55.1701294256578;
        Wed, 29 Nov 2023 13:44:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701294256; cv=none;
        d=google.com; s=arc-20160816;
        b=BaO0CyxPrBL0eBVp3L4JbhhGOpXmclZdUlJZ0ZbEA49n3ojea3dxKuS6jsGpQ2GTMb
         fV2yplme8eMdUabbLZObVWOEYjiJV4ONa1DoeKbqO/RshC2E/hYUdiiZpXq1a6m5LLLc
         N+ptCs66R46XcMf61KTUOc60JPGp58qtT6+Zqd7BBO9RJTZLuE3Tc8ebndy4WLioKh4S
         4NQFyMobI1BUZwV4qjwVVoDeLj/bla8XsyzjIWD/W7d2L0G+siOhjrq+E1awZS98HUdC
         osrp7BuMWYoaOh3jj9Obg18FXQhkzsX5aPPTQ9lytUFS54oRuNOfZWMJbf1PcICJGG50
         RaoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oaAuMlegGKyvqGQjlfSP0WNWjaMX9AyKOGu0wZi1ey8=;
        fh=x8a3OjaLFwIU7qMtOgGoexhvLtunbmhI+SfwfyrBClc=;
        b=Raf9DB3iBI3H/cB2RSATB5jwCupAxdYsRMMihC25pks0muLd/UV1dj+4UkOBpPRF4i
         ThMnYL+C/DgvctxYotZgFV1GJsK6lfaUNjxtg4JKJaN8TckWdMqegJhcHDiaHG4NCGE7
         5TbZrdm9oPsDgZFfc6QCKDAAVfI+rQlmzKDf7lb05Ol9DK5dhfQa78zz0o22xHIe8WAe
         6SRzkIyPN+/JfzhtBF/A/UZdI+IhCyCoRCoTSlbmfASAP9wsSBytx/0Irmy8CC1eyMPa
         +rQ0rFVjO5I1bS/17Z5N53tAGGWQFmsRkyqQ4qI6tH53QfbS3//sR86K7whljwU3gF61
         7+Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QAlYoBZp;
       spf=pass (google.com: domain of swboyd@chromium.org designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=swboyd@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id bn18-20020a0568300c9200b006c44affd0c6si1179582otb.2.2023.11.29.13.44.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 13:44:16 -0800 (PST)
Received-SPF: pass (google.com: domain of swboyd@chromium.org designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-5c229dabbb6so228522a12.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 13:44:16 -0800 (PST)
X-Received: by 2002:a17:903:249:b0:1ce:64fb:e507 with SMTP id j9-20020a170903024900b001ce64fbe507mr23901888plh.27.1701294255812;
        Wed, 29 Nov 2023 13:44:15 -0800 (PST)
Received: from smtp.gmail.com ([2620:15c:11a:201:d538:51cb:f23a:b78c])
        by smtp.gmail.com with ESMTPSA id n10-20020a170902d2ca00b001cfcbeceacesm6793162plc.117.2023.11.29.13.44.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 13:44:15 -0800 (PST)
From: Stephen Boyd <swboyd@chromium.org>
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH v2] lkdtm: Add kfence read after free crash type
Date: Wed, 29 Nov 2023 13:44:04 -0800
Message-ID: <20231129214413.3156334-1-swboyd@chromium.org>
X-Mailer: git-send-email 2.43.0.rc1.413.gea7ed67945-goog
MIME-Version: 1.0
X-Original-Sender: swboyd@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QAlYoBZp;       spf=pass
 (google.com: domain of swboyd@chromium.org designates 2607:f8b0:4864:20::534
 as permitted sender) smtp.mailfrom=swboyd@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Add the ability to allocate memory from kfence and trigger a read after
free on that memory to validate that kfence is working properly. This is
used by ChromeOS integration tests to validate that kfence errors can be
collected on user devices and parsed properly.

Cc: Alexander Potapenko <glider@google.com>
Acked-by: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: <kasan-dev@googlegroups.com>
Signed-off-by: Stephen Boyd <swboyd@chromium.org>
---

Changes from v1 (https://lore.kernel.org/r/20231127234946.2514120-1-swboyd@chromium.org):
 * Removed ifdefs so code is always available but fails without kfence

 drivers/misc/lkdtm/heap.c | 60 +++++++++++++++++++++++++++++++++++++++
 include/linux/kfence.h    |  2 ++
 2 files changed, 62 insertions(+)

diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
index 0ce4cbf6abda..4f467d3972a6 100644
--- a/drivers/misc/lkdtm/heap.c
+++ b/drivers/misc/lkdtm/heap.c
@@ -4,6 +4,7 @@
  * page allocation and slab allocations.
  */
 #include "lkdtm.h"
+#include <linux/kfence.h>
 #include <linux/slab.h>
 #include <linux/vmalloc.h>
 #include <linux/sched.h>
@@ -132,6 +133,64 @@ static void lkdtm_READ_AFTER_FREE(void)
 	kfree(val);
 }
 
+static void lkdtm_KFENCE_READ_AFTER_FREE(void)
+{
+	int *base, val, saw;
+	unsigned long timeout, resched_after;
+	size_t len = 1024;
+	/*
+	 * The slub allocator will use the either the first word or
+	 * the middle of the allocation to store the free pointer,
+	 * depending on configurations. Store in the second word to
+	 * avoid running into the freelist.
+	 */
+	size_t offset = sizeof(*base);
+
+	/*
+	 * 100x the sample interval should be more than enough to ensure we get
+	 * a KFENCE allocation eventually.
+	 */
+	timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
+	/*
+	 * Especially for non-preemption kernels, ensure the allocation-gate
+	 * timer can catch up: after @resched_after, every failed allocation
+	 * attempt yields, to ensure the allocation-gate timer is scheduled.
+	 */
+	resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
+	do {
+		base = kmalloc(len, GFP_KERNEL);
+		if (!base) {
+			pr_err("FAIL: Unable to allocate kfence memory!\n");
+			return;
+		}
+
+		if (is_kfence_address(base)) {
+			val = 0x12345678;
+			base[offset] = val;
+			pr_info("Value in memory before free: %x\n", base[offset]);
+
+			kfree(base);
+
+			pr_info("Attempting bad read from freed memory\n");
+			saw = base[offset];
+			if (saw != val) {
+				/* Good! Poisoning happened, so declare a win. */
+				pr_info("Memory correctly poisoned (%x)\n", saw);
+			} else {
+				pr_err("FAIL: Memory was not poisoned!\n");
+				pr_expected_config_param(CONFIG_INIT_ON_FREE_DEFAULT_ON, "init_on_free");
+			}
+			return;
+		}
+
+		kfree(base);
+		if (time_after(jiffies, resched_after))
+			cond_resched();
+	} while (time_before(jiffies, timeout));
+
+	pr_err("FAIL: kfence memory never allocated!\n");
+}
+
 static void lkdtm_WRITE_BUDDY_AFTER_FREE(void)
 {
 	unsigned long p = __get_free_page(GFP_KERNEL);
@@ -327,6 +386,7 @@ static struct crashtype crashtypes[] = {
 	CRASHTYPE(VMALLOC_LINEAR_OVERFLOW),
 	CRASHTYPE(WRITE_AFTER_FREE),
 	CRASHTYPE(READ_AFTER_FREE),
+	CRASHTYPE(KFENCE_READ_AFTER_FREE),
 	CRASHTYPE(WRITE_BUDDY_AFTER_FREE),
 	CRASHTYPE(READ_BUDDY_AFTER_FREE),
 	CRASHTYPE(SLAB_INIT_ON_ALLOC),
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 401af4757514..88100cc9caba 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -223,6 +223,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+#define kfence_sample_interval	(0)
+
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool_and_metadata(void) { }
 static inline void kfence_init(void) { }

base-commit: b85ea95d086471afb4ad062012a4d73cd328fa86
-- 
https://chromeos.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129214413.3156334-1-swboyd%40chromium.org.
