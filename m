Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC7J4HGAMGQEUNZITXA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MGkZEY50mGnhIwMAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBC7J4HGAMGQEUNZITXA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 15:49:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FFD9168858
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 15:49:49 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59e0a441c8csf1412615e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Feb 2026 06:49:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771598988; cv=pass;
        d=google.com; s=arc-20240605;
        b=HK+2OPpr9QyTZXbTpzKHYqi8JT2UoBDd1eq9JZTNtIXukzdQNsBlUzTRWiTI4MnaOM
         ct1kqJJ06sFuKAUjJh/E+ums6mGxDf2e50lTsQ7k9FSJztkffzxZareCocpsZCj2qSlW
         tq3PImslpji6C2KfXlBUHgJP7Qhs2dMCRheXlIw9Iz/tU4ONB/8lz98pthx1XMwv6eqS
         60IkwSXJ5qOtX8HbWqDwArjhZoHRUCeOVw8mGZ+uDPPK6e+mMohz4zzuY+Lw1QuSCio5
         aDP/9/66co5+SeeAlr8ecFSQ2hzNQmQ6y2IX7rdObWpYbhfbfUWkHyJoUVyxoE4uhGfE
         s7YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=lTya3fHD0CAqLitd6nP647QAKh9Y/BgMQ0b8ceJYaXw=;
        fh=zz9uaiYdB/cJlp3dK9moKI5VL7WiSHcQ+xheAWP7ANQ=;
        b=W0eENfXJs7z/LlMhoHB9EFC54bFnMBUfs5pH+dyFw9YrRv7W0QF3KCmvNIOGNptgRY
         dy5s3sp8fyeseTSNtzZE9VANo39hEHUilPWT6Qk4KWY+/LRhrbfni0G/S0Tw9EiwlqQi
         nB+Nm5RNNKxFqeaW520I703t1xYDDPf8bc0o2aTfPYQRDetK+ioC/P7w76+gIo4lJRUB
         9q24nattiBqwSrjk/GyLyY34MOjn/BBUNLhNniGQtuMZyPaGUuyJpZPobfVlZTUXbNWn
         GhjodO/CjzQzFbdvbCQ1s0WQdINhxbBJdfFTiGjuZ1cpN3mXeLKtZbwi9mFa46LFomeH
         dDnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MpjrsydS;
       spf=pass (google.com: domain of 3ihsyaqykcscjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iHSYaQYKCScJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771598988; x=1772203788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lTya3fHD0CAqLitd6nP647QAKh9Y/BgMQ0b8ceJYaXw=;
        b=qcbZcSsSoM20q7GIlhSu8fTRIrrtDTvKggM6/uog5NursirnruPKnEt5rgKcztivgs
         ZD0M0kdONqmuz6K8WxyKX7aJVhUpoV23eRA53VTE8e+SA4tbGEzfHhRxnTBVp1eaalhR
         5CvT1bTQsh5IC7YEV8W0BKlpsxqJDedImp0vwayMaMVn4vxDTLaDkuAfcSG1w8OAPi4o
         4yYoUt9rQO3SQTqSG6jX6gvotacM3uG2XYvkMHV/hWU8guRhXoinUSNbrbRFv34qVdtw
         xePicJwmIjU2ACjlYaoR1zo+L4pyUFhjCIjXXIhX+5nKTKFXPZFTjVdySq63d9WapPvJ
         osdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771598988; x=1772203788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lTya3fHD0CAqLitd6nP647QAKh9Y/BgMQ0b8ceJYaXw=;
        b=CG6r2/+cJcwiV9zZgAKJAqyrf89YkP+fS3O9ZG8SeLbcQ5WuHTSqEShi4ABVumXZNY
         rlRucA991Zb7hRhg+bp5TWr9muzqq3WY6HzQtVIOhaPouMUilzJJfjkgwxoHbev03DVF
         an9+gJN+ne+Svs7dhuQA+30bApEtLIUE0d3pSQiLEqM45w2jf0+kIFUBjNUn+7HgTOSq
         iRoo//tJ7Gl1GlisNIXJtl1D1Pf3GWkbSL5c2QCmAYl0IkK3CKgSWA8W7fgzhtmzvwlN
         dlPNI4YBLiwf9qP8MerSFkS8nX2GbxTzcUqxdhtLMW7jLuYBN8RDfbkYbNlGYw5WKu9U
         6Aqg==
X-Forwarded-Encrypted: i=2; AJvYcCUSRFSYFE6hWOsfZwCgHSakz1DLyeqKTsnTxCBHwTrRwScBxem5JHmhNqpA40ogrE/uOsRclw==@lfdr.de
X-Gm-Message-State: AOJu0YwBB7a1jWKER0le+IM2h+olNSDv7wLTtS7qRtFUoXoL/wJcqbfR
	i1/P6CQPXQZbNO9fmW+3e4rrpitoB30149mDnhG4H5qiESvO6OzB1kUd
X-Received: by 2002:a05:6512:2211:b0:59e:4856:91a5 with SMTP id 2adb3069b0e04-59f83bbc50dmr3257395e87.24.1771598987997;
        Fri, 20 Feb 2026 06:49:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GUMNo0pRQbpdq4TMPjstK6qAvYYh3uZIxkzpqQhRrVrg=="
Received: by 2002:a05:6512:2313:b0:59b:6d6e:8447 with SMTP id
 2adb3069b0e04-59e6524c876ls2336569e87.2.-pod-prod-08-eu; Fri, 20 Feb 2026
 06:49:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXzWkwMQUUrXVl+RfLNCnuygBUOss4hIdbPxyd/X9QLV7mS1C6oAUuGNHvGhwC2TM2KEZ8azvm/ucI=@googlegroups.com
X-Received: by 2002:ac2:4e0b:0:b0:59f:8301:49ad with SMTP id 2adb3069b0e04-59f83b97cfemr3478605e87.4.1771598985473;
        Fri, 20 Feb 2026 06:49:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771598985; cv=none;
        d=google.com; s=arc-20240605;
        b=iBhpurJ4rDWLV83JUhM7CxTFsaC6ggCCHW8pAwTfGNgqLMDrZG+NQ3EH0w2/uiL70e
         +lbiCaLiExfFuEXyKFiWUCWIJrzSrr8noeYYJEVEIifM0AA3d9MhkXctcOW3YfotMOOv
         UBTElFXQ5U5clmtXQK3uVsQnTHPD3haLn8udPkmt40LFiI2lTJalj0nnF12mIqYm3jbW
         fGLg4F1/vsoBG6pWB8BxYTM+Q6cUK7Agy2NZmwBNixuJDDyYHFfzmQB1EdI7Loy5JvLi
         ESpn/NG1cvENvUsdce+QT3WYDnnH0G7P7onNz2fL2o2m80lfHrm0DLqkTzj9LOhoLEiQ
         ELqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=7l0Rk7sxPzClSemlodKxJT0xAUIi4Uh2P1WbS8uB91M=;
        fh=2sJAwbjqV/QDivh3VdVh2r1IXHJhoVPHS8wp8w2aRzc=;
        b=lSUNxPy2rmLWwUVM7Mqfu5iLIb4fp+++ZJ+IwsJT3WuhEl3kHXHQZKcBjWcoxXUyZM
         RMoJje5hvuDo1c2im/5KXvGWaQX8Z7LOc/BxfvaJuG5+vR3oMaZ1eihlxgZ5u+6tWsoP
         tKEFdSvC3UulRSmoggdUYjfWpaHbXl5gRaHehVH/JRrZ6wc4j39iKFcXTnsAw5EPQhxq
         N/8DqFbnjDVVowL/tArm+IaI2zo/caKW5TRy2iauLu0TkaC9AxZF/k22YfMMxw3QC6Rx
         NT2WeBIj4SyDSGovlGd2F30RYfTAQeVaNrsF4hmUm7UFFE8l5YHIeQh1ppDZ8DNcaChS
         A58g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MpjrsydS;
       spf=pass (google.com: domain of 3ihsyaqykcscjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iHSYaQYKCScJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59e5f563bc0si747985e87.2.2026.02.20.06.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Feb 2026 06:49:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ihsyaqykcscjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4837cee2e9bso17294495e9.3
        for <kasan-dev@googlegroups.com>; Fri, 20 Feb 2026 06:49:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXTsqvKHWkN3+lOgOiP0yT82s7h3ZMOTp1cjLlt4/4xmqvDB0bWKA2szl76mBBQjLjcy7XLVosw4WU=@googlegroups.com
X-Received: from wmhn21.prod.google.com ([2002:a05:600c:3055:b0:483:6e28:c16f])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b2f:b0:47d:885d:d2ff
 with SMTP id 5b1f17b1804b1-48379c1faccmr309919275e9.29.1771598984385; Fri, 20
 Feb 2026 06:49:44 -0800 (PST)
Date: Fri, 20 Feb 2026 15:49:40 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.53.0.345.g96ddfc5eaa-goog
Message-ID: <20260220144940.2779209-1-glider@google.com>
Subject: [PATCH v1] mm/kfence: fix KASAN hardware tag faults during late enablement
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, mark.rutland@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, pimyn@google.com, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Greg KH <gregkh@linuxfoundation.org>, 
	Kees Cook <kees@kernel.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MpjrsydS;       spf=pass
 (google.com: domain of 3ihsyaqykcscjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iHSYaQYKCScJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.79 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBC7J4HGAMGQEUNZITXA];
	RCVD_COUNT_THREE(0.00)[4];
	RCPT_COUNT_TWELVE(0.00)[15];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,arm.com,kvack.org,vger.kernel.org,googlegroups.com,google.com,gmail.com,linuxfoundation.org,kernel.org,tugraz.at];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linuxfoundation.org:email,mail-lf1-x13e.google.com:helo,mail-lf1-x13e.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim,tugraz.at:email]
X-Rspamd-Queue-Id: 9FFD9168858
X-Rspamd-Action: no action

When KASAN hardware tags are enabled, re-enabling KFENCE late (via
/sys/module/kfence/parameters/sample_interval) causes KASAN faults.

This happens because the KFENCE pool and metadata are allocated via
the page allocator, which tags the memory, while KFENCE continues to
access it using untagged pointers during initialization.

Use __GFP_SKIP_KASAN for late KFENCE pool and metadata allocations to
ensure the memory remains untagged, consistent with early allocations
from memblock. To support this, add __GFP_SKIP_KASAN to the allowlist
in __alloc_contig_verify_gfp_mask().

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Greg KH <gregkh@linuxfoundation.org>
Cc: Kees Cook <kees@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: <stable@vger.kernel.org>
Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Suggested-by: Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>
Signed-off-by: Alexander Potapenko <glider@google.com>

---

This is a follow-up for
"mm/kfence: disable KFENCE upon KASAN HW tags enablement"
that is currently in mm-hotfixes-unstable
---
 mm/kfence/core.c | 14 ++++++++------
 mm/page_alloc.c  |  3 ++-
 2 files changed, 10 insertions(+), 7 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 71f87072baf9b..30959c97b881d 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -999,14 +999,14 @@ static int kfence_init_late(void)
 #ifdef CONFIG_CONTIG_ALLOC
 	struct page *pages;
 
-	pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_online_node,
-				   NULL);
+	pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL | __GFP_SKIP_KASAN,
+				   first_online_node, NULL);
 	if (!pages)
 		return -ENOMEM;
 
 	__kfence_pool = page_to_virt(pages);
-	pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
-				   NULL);
+	pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL | __GFP_SKIP_KASAN,
+				   first_online_node, NULL);
 	if (pages)
 		kfence_metadata_init = page_to_virt(pages);
 #else
@@ -1016,11 +1016,13 @@ static int kfence_init_late(void)
 		return -EINVAL;
 	}
 
-	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
+	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE,
+					  GFP_KERNEL | __GFP_SKIP_KASAN);
 	if (!__kfence_pool)
 		return -ENOMEM;
 
-	kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
+	kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE,
+						 GFP_KERNEL | __GFP_SKIP_KASAN);
 #endif
 
 	if (!kfence_metadata_init)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index cbf758e27aa2c..9d1887e3d4074 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -6921,7 +6921,8 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
 {
 	const gfp_t reclaim_mask = __GFP_IO | __GFP_FS | __GFP_RECLAIM;
 	const gfp_t action_mask = __GFP_COMP | __GFP_RETRY_MAYFAIL | __GFP_NOWARN |
-				  __GFP_ZERO | __GFP_ZEROTAGS | __GFP_SKIP_ZERO;
+				  __GFP_ZERO | __GFP_ZEROTAGS | __GFP_SKIP_ZERO |
+				  __GFP_SKIP_KASAN;
 	const gfp_t cc_action_mask = __GFP_RETRY_MAYFAIL | __GFP_NOWARN;
 
 	/*
-- 
2.53.0.345.g96ddfc5eaa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260220144940.2779209-1-glider%40google.com.
