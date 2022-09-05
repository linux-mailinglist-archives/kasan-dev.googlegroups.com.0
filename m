Return-Path: <kasan-dev+bncBAABB4WJ3GMAMGQEN3LKO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C85F5ADA97
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:07:05 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id x20-20020a2e7c14000000b00267570ecceesf3236662ljc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:07:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412019; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp/5BWLzJ9uvQvI3i0nde+cceTUM8eVCFGw758QNsqC/ynxQpMvPIelE5Wn34GCVr3
         tkyScoSCIATuDQ1/65B8ZWJ3iGg/RBqPP4uX6yeqHiM47mOctKv7gc9vLhOpb90jFNcg
         bG9hnvT9FqdI2kSfNzaKut8+YgD82eB/ooE46Z5B0u/C320jUorY1B+c/FtJVDDJh1S3
         KTKUCJGN63Tj+VpcjU8g6lNiLY5V+6cgitR4U1+nJ/9UZ9ce45b+LL1vkO/hEeOFlCgy
         sTzwxeUZjEjmJitvTAHOBesd6BPMPxMFcWfNYs9zL7AFLgLxvGLZGSZHTKD8o3MfqGax
         FOfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wLPJmW7nS3WRlrRVkK23dPH5kaEAftOFsdyAIFwH+8c=;
        b=XtsQ1Qtq+wQkGmLPiwSfuF+VOG+dC4SRRiYtmmgzhsdQsmFymojAbvSYxXWsR82+is
         ivQuEeBOh1W8TASqRvFCdLagbQbaI6IPk3oH9dRw6eifVNIutTMCk/6Q02xA5MmoBJGe
         Y5b9a9cu+SPftYItwbMJUoHIhJufLdbr4RwtzO4JfTSB3sCLU5gjnc0aedoiht23Zp24
         W80/zFHsr9TU/zelxDHdJ5KlEx0qwRFQLAtu0dvOAwcpYvMZ4Qit+3osW2Q4xHZiO0RI
         kKyHXt1XOwDcwu95VGeqswJzolcIvSMhHjOKZFJAY9I0A871HZKe317SHBcBbMWCGoMc
         wuMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JOS7+Esx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=wLPJmW7nS3WRlrRVkK23dPH5kaEAftOFsdyAIFwH+8c=;
        b=RwBTaBcDgZtT2rk2NVVgaiiZrR+3VKJ0bRBJKSsIWceXzYuL3LrstocHCfFWz239fP
         EPKPVQtEyJjDI9S7qnnk5CX6r8mJKn5JmN2QM1O8nteYamR/GXI1L8e8wXv+rIfFHR++
         +7/8J4xspKM8CsZURdbLggFZhA2Wdc/EBYBwymr0P1ocGprRQkU+23bwy8F9dRPAGDHd
         5qS5OKq2lrBaQlb47DwMaf3/QD09L8aeaRYQPGGku2oLXW2zM8aCBzEtgBrIF7nDfatM
         rhi0Yinv2llpxY9qxo/R4IqiLhXj0hAd4Ufzw0lVREat1/nSBOASp4grX2xHNu31Ni0V
         dhSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=wLPJmW7nS3WRlrRVkK23dPH5kaEAftOFsdyAIFwH+8c=;
        b=MO7KVjC13JpUE8n14Q6/vCvmzb+EwC3AfBClWo8k0lPbelXnodCkgpyR/uTf5d37ay
         +3HYFRfsBeTD5LLWwrYd6lO4gHrqujo4uPlwmq6K2aoJCQynmkSRM6kTtbjY7q7+wVJv
         Fr2z1mVu8iNEo0lFQ43+frW5xpOt949MyjyHeo9wNfAVtmZRcGl2fN8Y+lxppSM7Ae4y
         u3YSCJMipR1rTNTU/5Kda40Ii4uWbRyPbFCJ2952rLzboi/xlJR/rtyl2Soi+3uPKoNs
         jLnpgfmE+7xUy7YYMx8Rey89VZVehiwGwBtLaMpQuezP20DtKV0ugLH6BB0D7q5gpmNH
         QFDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1SiqWWK4vyXsD5Gy/NtJRvhXJOTcv+l5EF92chO6oPVkXc57a9
	ZgGOcrD4asMKj/bQH5MZEeo=
X-Google-Smtp-Source: AA6agR468zE+Yxkq0U/LSwKQGErsTOOT7DSx2z6zUIEUKFsWDqsNvz4omspWkJXDY1Xovva7oA/vyg==
X-Received: by 2002:ac2:4901:0:b0:494:88dc:7efc with SMTP id n1-20020ac24901000000b0049488dc7efcmr8396532lfi.408.1662412019444;
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls5364955lfo.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
X-Received: by 2002:a05:6512:22c7:b0:48b:38f3:79a8 with SMTP id g7-20020a05651222c700b0048b38f379a8mr17664191lfu.530.1662412018358;
        Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412018; cv=none;
        d=google.com; s=arc-20160816;
        b=WDuNedz/Hr+O76mV0xssp2gnaugYPMCzxIIKaofc1lm+0Z9ISqzBDgoCNdbu7fwBRp
         r6yzUKylmSXM2485Il/qJ8cNetLfx52cXdgXdyd2zBR/ojkw32xq0IeJsUX+Qv+PTixi
         rv3fL16BLVH2ro8Xu57qHxnWXG/3dOZ8TUoRD9IRirth4PsfViipZhkTChVmQ34KbXEt
         O528uYFgFP+YMPx0AZ88k3HDUizeDS3odFdo4X1vmsrjUh+VZVPUKIIHK2UgjhXVvpzG
         MOI3rlQRzmbusTgLPV1AuSpmge2eNnNMnTERT/kWQOepDzM6GIHElIyu5IUNDRVdVAIS
         Ur+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cBQnY/iz4lgxaz3ImBZuwQTq/5ht4rGHDbWWswxKJOI=;
        b=VhOBRwlWJbJL3qnppsZYImP978jP/1BqgvDBPCGcFkelJPKynBgxK7FT0IxCbUeetQ
         JwlKgEo/0fxJ3jqVnZhTxqUoKf/+kNVuQfd1pwlMCoytn8lUhx8ecKBOvo3DGb/yW0vN
         YzflB47qFMkOFYlFm43JMN3MQG2Ls2ZJbu3YONmELsrYTwX7wO5p4RTbW5seDqF4wjcz
         7Ojj5No5HNwGn9xh0W24yKMFnYp3tz2rQlGVU0Mfo3/OZUGJh/HUty6mvY2AfmSFNejF
         hDjnGL85adyVDyJwfoL0qZn+JbXAXxigBp4F19Tc1U7GPUPPlxQ6ydIaiPjGQ/MF6ey6
         9MBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JOS7+Esx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o20-20020ac24e94000000b0048b1833caeasi433462lfr.3.2022.09.05.14.06.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 06/34] kasan: introduce kasan_print_aux_stacks
Date: Mon,  5 Sep 2022 23:05:21 +0200
Message-Id: <67c7a9ea6615533762b1f8ccc267cd7f9bafb749.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JOS7+Esx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Add a kasan_print_aux_stacks() helper that prints the auxiliary stack
traces for the Generic mode.

This change hides references to alloc_meta from the common reporting code.
This is desired as only the Generic mode will be using per-object metadata
after this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h          |  6 ++++++
 mm/kasan/report.c         | 15 +--------------
 mm/kasan/report_generic.c | 20 ++++++++++++++++++++
 3 files changed, 27 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 15c718782c1f..30ff341b6d35 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -266,6 +266,12 @@ void kasan_print_address_stack_frame(const void *addr);
 static inline void kasan_print_address_stack_frame(const void *addr) { }
 #endif
 
+#ifdef CONFIG_KASAN_GENERIC
+void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
+#else
+static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
+#endif
+
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index fe3f606b3a98..cd9f5c7fc6db 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -270,20 +270,7 @@ static void describe_object_stacks(struct kmem_cache *cache, void *object,
 		pr_err("\n");
 	}
 
-#ifdef CONFIG_KASAN_GENERIC
-	if (!alloc_meta)
-		return;
-	if (alloc_meta->aux_stack[0]) {
-		pr_err("Last potentially related work creation:\n");
-		stack_depot_print(alloc_meta->aux_stack[0]);
-		pr_err("\n");
-	}
-	if (alloc_meta->aux_stack[1]) {
-		pr_err("Second to last potentially related work creation:\n");
-		stack_depot_print(alloc_meta->aux_stack[1]);
-		pr_err("\n");
-	}
-#endif
+	kasan_print_aux_stacks(cache, object);
 }
 
 static void describe_object(struct kmem_cache *cache, void *object,
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 6689fb9a919b..348dc207d462 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -132,6 +132,26 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
 }
 
+void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
+
+	if (alloc_meta->aux_stack[0]) {
+		pr_err("Last potentially related work creation:\n");
+		stack_depot_print(alloc_meta->aux_stack[0]);
+		pr_err("\n");
+	}
+	if (alloc_meta->aux_stack[1]) {
+		pr_err("Second to last potentially related work creation:\n");
+		stack_depot_print(alloc_meta->aux_stack[1]);
+		pr_err("\n");
+	}
+}
+
 #ifdef CONFIG_KASAN_STACK
 static bool __must_check tokenize_frame_descr(const char **frame_descr,
 					      char *token, size_t max_tok_len,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67c7a9ea6615533762b1f8ccc267cd7f9bafb749.1662411799.git.andreyknvl%40google.com.
