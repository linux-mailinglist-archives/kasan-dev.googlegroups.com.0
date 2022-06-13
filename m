Return-Path: <kasan-dev+bncBAABBHFWT2KQMGQEDICT6GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DB9A0549EBB
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:29 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id c5-20020a056512238500b0047954b68297sf3497279lfv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151389; cv=pass;
        d=google.com; s=arc-20160816;
        b=u/B8ElVvM8pc79dVgPUkIi5KUxZjGpWKOHZTW02it27QLSnYpaC3uHtToQba76YOE5
         XpOrn5jmzAAJfXR2RVi1JCqHeXv5OfjbaFTdZKtw12or0SWBLZuWqewfa5fIZ5maEPBd
         1pgSnJyalqhH2ky7FEP8WlkV820pq4oFDhDx6AnPal8IiRQsN+fPgtGfLeOx8bonwe5d
         rrEMs7IUjnXX0tWJWEL/OUxTeDzJyTme43R/pAGVD9rZygRcvYutBXubA1dGqYGORDhk
         R0lwOIJEORRj/SYIDi2wqZqT0ln9WKOqpza91Y0Bs+Ewns2vTWVl6qI8eOZwsk4x9sTh
         TX+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j7L+QrQtjDBxd3ovX/0ettZRHHhaS30W5DrgGcGsxN8=;
        b=EJDNgiZzW+9ZCeFI/R2mIC5Ey4YRL4fnvlk+DjcvrFT0jo16rowyoyC/L9UbfFe95J
         8r2B1lsh3L9vopeugzSWvvC6JBWAeAFaS6kYP+7c3FY8I42MLobYeDl1F5oTXUDwdTW+
         amCm2xBjZhpYpvlghptOJImfHPoAc8fbRWcdBLqSJNqBKStFzkZHjDyyvWa49OE11vNc
         u+93DBOTWjarYxN3fQ2OvSvGq+SHdHDxgNmHeEAS29qen/gOazisfCUcwh0xQTI4FH6T
         pgyv3hrimGVIa7y1J5LAiWaizAux8EqfQWCh1uAXthiBGD+n6n/SjmBJ0bsD+xBPGvem
         78pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pbdzxZpr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7L+QrQtjDBxd3ovX/0ettZRHHhaS30W5DrgGcGsxN8=;
        b=d0o65sSs5ACd2HeeSijhskQmDmj94qFyC4H0LFSyPbMuhFnM1pKzNpuTsjoSXeOeGO
         cxO6ojOilPKsAlLJlLA5M8DpHtyteZ5iAq9sdmf2rr0N5+GJkej/iKpfXorliUjohugN
         WwW6fQ4NOKSMdfoq/xiniulqGuH7pbwTfoFgnCab63aH++bpcQ392k/pf8QZQbU1Anch
         GxERLOvI7qFwXlAXaHyW+ihnNLmAeTjslqFwKpnHjAb65G7gwhlRFaVJ7TTr6nki+Hv+
         NRcdUy0bIvSjdLSjgZnVMSppKkGOFkahTJGBFhoHYrQZpRWf0QXDycympDYlc/Z7RQIX
         M8Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7L+QrQtjDBxd3ovX/0ettZRHHhaS30W5DrgGcGsxN8=;
        b=mNZtt+dFDG/1BWZbaw3iVkyrYW17qJGkR9Yd99s0068QoYz0q6y1wSrK44tCYNKy27
         6uY8goB/OuqcDNukqrtWijCTIUw6Nv7h6jiDpeTLVDelcTOVat3Xt3NReDbp0L3QaUaE
         5G7AvtFb2iX2kREtyUam5TS+ekGC8Rj/Y60JzxP4M54rhnpn1TmnkjJW1qJ/wDUbNwvd
         JRiFf89N28p+UYk4fT5+sBkO/6wJkhPDox6FhCCn27gXL3644X1+UttHjWHQDo/wvR35
         ZB0KI9/LW9Ehw8PTc3on8M+x6AYQWqH1Gcm4dZdWoyM8Zg5pZNCmeAywYJvo/Rpv/AvP
         pY1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9WuYgnV1nJ15D28YL8dPPzng+2Ic6yjd3mGN1GRZRzoh+K45Z9
	etw6n/GHY4oMpBd5QmiXCjs=
X-Google-Smtp-Source: AGRyM1uCeEta4oNKEcVHWZv22dW8eidp2Hw3AtFZmQ9zH+tlbndg0eOqorOVtjdG6tJ2bNaWLSo9bQ==
X-Received: by 2002:a2e:9252:0:b0:258:fc8b:490e with SMTP id v18-20020a2e9252000000b00258fc8b490emr637718ljg.309.1655151389164;
        Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860e:0:b0:255:7ff6:f956 with SMTP id a14-20020a2e860e000000b002557ff6f956ls457009lji.2.gmail;
 Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
X-Received: by 2002:a2e:b8d0:0:b0:258:ef46:8c56 with SMTP id s16-20020a2eb8d0000000b00258ef468c56mr612923ljp.325.1655151388492;
        Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151388; cv=none;
        d=google.com; s=arc-20160816;
        b=mcvpV8zHf/DckkFpB59t4a8gFdiMHSawwXfH01UnRVAYAQXm79/t5XJlC1z0T+W9mo
         tTTrc4ihyGJHXU5sy8EOaJlqJL07yWCEBxZ3LAP16fsEf4QdT1LnxPXuDNGHvAYI9Lmg
         uNlG3yyRSiRSzWfC1Zg8yHdvCig7k2rP0BFeuAakxN3al6JQs/8MXcfliJ9V+tY8B3bs
         gbjdDkuR2NGVjmLtR0+tGOr2NFauu0cqTHAHws51msn8uvgmQEjRSX1D7wt9X22GYWtm
         33X8+dUqocibQutq1ZRSJl8ICAGkt9kAHL1LQQfm+3X3qhe6xQGz98wjP+PlB24hgsAA
         daEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JiOjwm2R97mupyKaCc5esPRsyojrd6x1cjK2UXDXXcc=;
        b=frypF82wL6WJY3dZtlntSCUsVx//vfheFgKl4IWjVqBImV0NusESXl7vcy7gTMYnGR
         /Wrb+BNg8wmbSl1r1h+2ja8hKF2Re4idKnFNhduHrgtSMGpBHnG5Hp4SoJGAC462HoSK
         aPRacLaWeFYJBFWjnE+3BBQPleEaNZoTf4tVsydXH22qtbRViVDnpdNtcBvdYMMYVri8
         f46k9rdVPQdnspn7mb1wG/HxKNC14gXLbghAsJ6dkV1PtGunaVTY3k6ZJkCbzqybQJk1
         n2cECxuq5vUKo6YC0/3v9Sw1jXyFi0P9sehVeuf3IC1tNZ536Dve0MFy0UNzVUqL38UC
         VFZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pbdzxZpr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e12-20020a19674c000000b0047866dddb47si298869lfj.2.2022.06.13.13.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
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
Subject: [PATCH 06/32] kasan: introduce kasan_print_aux_stacks
Date: Mon, 13 Jun 2022 22:13:57 +0200
Message-Id: <11a7bfb5ed5de141b50db8c08e9c6ad37ef3febc.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pbdzxZpr;       spf=pass
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
index aa6b43936f8d..bcea5ed15631 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -265,6 +265,12 @@ void kasan_print_address_stack_frame(const void *addr);
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
 void kasan_report_invalid_free(void *object, unsigned long ip);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b341a191651d..35dd8aeb115c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -266,20 +266,7 @@ static void describe_object_stacks(struct kmem_cache *cache, void *object,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/11a7bfb5ed5de141b50db8c08e9c6ad37ef3febc.1655150842.git.andreyknvl%40google.com.
