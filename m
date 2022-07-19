Return-Path: <kasan-dev+bncBAABBLHN26LAMGQE5CDI5BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DDD1578ECA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:25 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id z28-20020a0565120c1c00b0048a2049d2fesf3849724lfu.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189484; cv=pass;
        d=google.com; s=arc-20160816;
        b=PLXqWnD5yVBleiGcz5Kd0ghH7xZynTvKYEguFrau0JY3MM2vhtVrpF2hggQ5m3OwGg
         2vOJ+ii7xP0Uf+O/7LEcbTNoGvejRL629RsMil5IYtnZfIVH1mXRGIRo9YATwd16jVsf
         drje49NpLOTtdP5eK4I78Kaj0ioCErc5q6O7jzLw2WQLXX2cO2ZcY9ta+e17HE5hLpAA
         CbX+FLHd10D/bUst13GIzDcNxV12QAn6fKXIMlp1VQY/jbCvDReEO2iW01vbVas5vCfI
         jNmQlBn/gSfQSBAFZ1hnRDvS9v1qIPb49WaFNGyOwd2jJ1xJK+56a7LZpYvtC8USotPR
         ubUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gqT8T8ysvPmQrWClxaBSnTe7nKdqM6cTC3p/DORaB4Y=;
        b=MU3gG6AqA7IDQSPtxX5GDgrfEN9I/q3kuKs7DoEz6wX5d61FrqeDetJ7uuQ6eYNz9r
         9aIoG5fDpZnmjjd/eQPTKTSA7yHLHz/6PkCp+WwmLeCCNrRsMrGQ3+7LgxaR/DrN6k5G
         V+Ivr4GCGESZ/hmFbCpLNmcZu551BG44RLV7Mu3xnmbJp50OgQtiMaUYJI7i7LvZh3Bm
         knPKhNoiek+97qCxMFLkPKYSj+gh7iCIy3mLaxz617Wo0DMP7T+1IZJkdGuSOI6LbGCu
         f8BDRySEhdH8VrC/DQaAOs7U1HHo2NNChSrYVteFLnCXtBiqN2Vc10KuFvNL9uqZMtRW
         2cdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CLMXnkWO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gqT8T8ysvPmQrWClxaBSnTe7nKdqM6cTC3p/DORaB4Y=;
        b=lz8ytt/K4k6kKKe6GOxJDGddjhep6iI4Xog7ZrBEZIDy9PjPtt0NpswkMBp8aJXNXw
         2WT4FnQ6B2mc5TN8z38t/685+U5NTr0vkcspcxazyBoc6RNOxfgL7ORm/5jC26aSDLxG
         9i6C6xojGVjE7uUXivegUa2lQoAmve/ekAGMX+SxU229XWCQW0qdSWKo6zWuz7GrAhPb
         0fjvWAMuOjUBtAwZNsLs+cJRgzBaiRRtnsA6cHWPy0N7xDrEdh0mO8DdJU0nP0BFdTRd
         VcIA7t+gITg1cqwBxZO+aVOs9jJcGvtQboeoO5BgtnUaV+VVl9JTpcnz7HmgxP/7Q8w3
         FefQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gqT8T8ysvPmQrWClxaBSnTe7nKdqM6cTC3p/DORaB4Y=;
        b=LXCyTC83giJd77T/QFbi6PmqFw/tJnJ+Iw5amKk52Ar27VuHQJKdGu1+mhbmKtxvg8
         AdFL+dMPD+LHVC6P97vt2y30dGGzd3qLf3Dvi/vGrIRt1CJQb/JnjPz8UlutVn46QAkC
         XOmMPoZnmwJKajSq2xZ/6js3dq5CEWYSq3y5HRH/+h1o+ou6sm9+bhOIGOK2AvdlFFXt
         8PxWv2gzZgd3FGWrWh6g2VYaNsT+0rzi+hU1WF4TxUvnRGMYmYZoIl0jU+CjTpzMTCb6
         XebgZkpVPwc9IBb2iqfjXE5Hm50P9xXpT/Sa/vlCONbgDUg34BsMNo/KTalf03zfEv6F
         RISQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/BR93uxUIj1SdFDmfrGhnSWiqy/Ic5s0RbN8E8h0f7wqxJzpwu
	B/7w0S4t8P12nMYFDYCvq6M=
X-Google-Smtp-Source: AGRyM1sFxN2i7vm3LT5++z8QWjiGcb8LMo9InCq9JVviJgGtD7PFx/kQ7N8qmvfimrjmxkOUiWPCzA==
X-Received: by 2002:a19:6510:0:b0:47f:baaf:e3be with SMTP id z16-20020a196510000000b0047fbaafe3bemr16950694lfb.139.1658189484714;
        Mon, 18 Jul 2022 17:11:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:c42:0:b0:25d:b04e:9cc5 with SMTP id o2-20020a2e0c42000000b0025db04e9cc5ls115930ljd.11.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:11:24 -0700 (PDT)
X-Received: by 2002:a05:651c:499:b0:25d:6cca:6060 with SMTP id s25-20020a05651c049900b0025d6cca6060mr14352185ljc.115.1658189483930;
        Mon, 18 Jul 2022 17:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189483; cv=none;
        d=google.com; s=arc-20160816;
        b=R+BF0/D/Z2hW4LYVzrRw1yP/U0+7TDQh6SUlWPp3gTxENjPjPZsY8aA+CXPXqedWan
         rVpaSa2SavbiFZ4877V4nEFqnCboPS/i3nlSLnnX2TJTtqPJDao4UYOPGkUWTWB+a3bW
         3QVgGYJz47tqRgEzoLjLCAGukEJRPqopZtqpfYjqFZxFLwPews4pzpjwxfWd+/tx8K+s
         xVyIAdE9E0/oMFMgKmE/wyqoK93PvaRjBEW4w5VUA0HA/sa+K53UX4tjfb+luDYoNsoN
         iawO2y5rchIvWuE/hi5ygx4TH88AHpm7kUXzYNqnSGUTmEfkoq2GsPh+v4Q1vdAE/mwG
         kC2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1ehF4bGijVTADFCfUkTF0e1lkPULvRdunOUAUodeJIk=;
        b=PwWM+AP0K5CXbX63XAX302JSDV45hBYaOuuj95Xs+6eCbQPLOl5F0zjJvWshE1VAGq
         //R3cqJGBhS+GW2kxljNgb7sLz70NhggA9PsjOHRy1S05JlMBhWk8PPl+6OvCSeyzaJ2
         kB5nTBdH6pzmH3xKizpxXfHNk8+imWWmigLPv3/sl9jzHhv1W21cXkA4vdiEE6nKIIkW
         Cl629v/Cs3iZxTRjT0ya4NSPtRv3G0LGZIefptBse3bxv4ykS78QVw68TN4L4LHnhcMZ
         1epDsD8XdH4jctUU9/0J/BmDuzYK6C3qAq1Xez9l+/fOSOzAcEO1cmBw4acokl+y9+ud
         GaeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CLMXnkWO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id g7-20020a056512118700b00489d2421c05si402607lfr.4.2022.07.18.17.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 06/33] kasan: introduce kasan_print_aux_stacks
Date: Tue, 19 Jul 2022 02:09:46 +0200
Message-Id: <b94138a02e12dd8f1417dd815a183b296bcc70ef.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CLMXnkWO;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b94138a02e12dd8f1417dd815a183b296bcc70ef.1658189199.git.andreyknvl%40google.com.
