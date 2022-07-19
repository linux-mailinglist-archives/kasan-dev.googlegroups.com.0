Return-Path: <kasan-dev+bncBAABB4HO26LAMGQEZGDVA6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EFC578EFD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:40 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id f13-20020a0564021e8d00b00437a2acb543sf8774127edf.7
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189680; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ui691VAD5qW3gXtVULaj0HfaYEQP/5tHirhpEqns+3GCe0wtQwU5wKdeUU7ivdGfc2
         E98AyBf5CPtT2BFLbDaf7zouyZGRtLuOPdCzFF2HyC9teU2srABHTVe5GtHr7W7Hfb+4
         1eXIzG0mhASg9QT+IwmnJFbqmXUi9Nbcu28gkn9CvoOBLcoHnES8Z5KwGMhJGgTQn0FN
         YPNhxoBIvHbTv7Uetgo0WZyeECldT4jK3L5HiBNwv7kdTYJqqJxG3mn/pCBl6r9dhQzv
         PsFg2sgb2cg10TPe891u9Ypyx3UKqufEHxaWwYwibu/xM73cJ18Kt49B/aSQJemeHL9V
         26wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tOuxDHWIvcjBidAcPrTwIQN9wVaEQ+ZtvoW6s1P07QY=;
        b=OPNgGK+TnCqDnPtKgbsCmydwbAjYy3lqNXJSv4K+xoNF3POn4LBPLOOHY/Q8Iv+F/+
         9qFvrusJCHtgMJZgPxCts89IzsiQ1hKxp7tzyF2F+kZXOJM1RNl3xeuXE2PA7E8z+SyH
         c13dqn44IclTRov4bgsX08ACaz5yfuFJTsDOUpQ89dVbU4hk1rjF3pnTl6rFmPIWHk/m
         Crstn/KfW42e1mmNKMEw3jaVzFCuPD/vAL24wryrSmLoxePqX5cbCTgcn8WQIiCaVLL7
         Fp9eVyXJooqioLAQOmzyic/9rdfnGa3Xi8BtcLH1IHrDdmvUWqPuc4NX9GD1mDau8+zq
         plkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="G/1EgNqi";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOuxDHWIvcjBidAcPrTwIQN9wVaEQ+ZtvoW6s1P07QY=;
        b=Ws36UzGUW6DlNhyGiBUdZOIxmYtziDMY/m6taSK4RySDap0BAcviitUok0Cihzi1Ht
         DC6ZfnlTabEk4NptHlr7IkrG2QHFTdlYX4j3wW2FwCo95FaBNBvTLz3LR2jWn0MZJ8PB
         mZ0MHuSmOr+rWm3EBw+Notggr8pWWjcuV8fVcuAgLsu9YhSaLwNKtW/xg7CfhCyy8GND
         5tOmoI3+c2ETeTzabwdD3tsex2ULcO+4sUdJ6e5+HpJrVpwNLo4KgrYhlX/z+Okafls/
         AOOwKJAsX9m9xQ71qLFjCnpcm2ZeTHbnKQ9M72T3K9pUGIO3U+9DWhS9m32CKrBk1Cdy
         4kpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOuxDHWIvcjBidAcPrTwIQN9wVaEQ+ZtvoW6s1P07QY=;
        b=TxXfBUUPGFiNQs6i5Zy9mssAqqQxru/J6Qip6XdUJqaQtm1tFqpJSMZe2+Bi7XJKHx
         F+Kl7x6qTygkTKoDfwQPFPt2hozx/+1lEbHGWULg92fxNQ2fvmktWzBJsk8Tps22rD39
         eUPjvsJXBnDUfpjtcfys+o3k5EDZInUyC3JCDDbGkAWQZ6MMAffU5O9/a36VgOIx5JcF
         xSFkapckB5XILm8D0q8dzhuQN+tgezXQC9vJnQG0PkmChLFB6HiEpYd+RXaaVEWdWEKh
         dS0ZfwmXabNFL/nw7WF/BQ+QofgMbHh6S/iRtDcwb7wbBryGebiPwc3Oku9vAV3YYf4x
         lJww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+FXJz7d4IuKlu0knZKHEF2Dm9f8AKZ2MQRZTE00cBk2scdLtxS
	3hwGUU/+Myz3etWTCsHixk0=
X-Google-Smtp-Source: AGRyM1ucCuSkKhjBT58+7kZykBhQe1tyI/QBflyzXvJCwJBNP2SWWC2kLU4JlDXLbjXxuo06QAjMSA==
X-Received: by 2002:a05:6402:3219:b0:43b:6f3:8ccb with SMTP id g25-20020a056402321900b0043b06f38ccbmr40884530eda.345.1658189680289;
        Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3653:b0:72b:564b:c25b with SMTP id
 r19-20020a170906365300b0072b564bc25bls202888ejb.7.-pod-prod-gmail; Mon, 18
 Jul 2022 17:14:39 -0700 (PDT)
X-Received: by 2002:a17:907:d26:b0:72b:8311:a167 with SMTP id gn38-20020a1709070d2600b0072b8311a167mr27851170ejc.89.1658189679593;
        Mon, 18 Jul 2022 17:14:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189679; cv=none;
        d=google.com; s=arc-20160816;
        b=aepddAkYrC4+Z7tHs9gXkNyhzV3+tl02dRkODgPrqKx88NPxU4XAxC2rjJShNjg3Y9
         iCFVRK/8SdD8Qbc1y7jfR7aoYo35IkAEhfuIymHcqWSUUhwHdohxkL2AkbTX+WzJDNAS
         ZpIka6N22onbwVV8LMoG5+sVeAmbu0W7yolTpz05EZbf0XhMLmxyObf3dcipWLIIdgzB
         cLweYvOR0+0OfFhbqoD+P0V/TUEh44Os3HYGLLyXqrHYsy1bq/mmiAVPIcqQ4ShMFTbX
         MgQinOKx4l7zhO5lwRn0LyA0uQ8fqCoOl3BQE6nuKj4nCZxlg/Psts772jsKLmGSORYX
         WKgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ypNhLiBtVU9jJolzs9O2aAagUc+2IhpYDk0p45hBQrA=;
        b=uXbu0EDKVvXOcxjGdJ7Fsk+ZaAnp+cu8sSOdw5KBk+20lPKOV+uXJFBCBnkqvD3t0W
         RfOgcvbxk6usya7fs51MNlO3QfihPjybwL7y5rXlnXRWmOAY7ZldxZiksD57qzziDJNt
         kkojss4lEMO7cVrMef5vI+QGZw1PimnsAKpdBNwpyo/nKIM0wUQBYWT/gQjUaU4TXuPq
         PdkVH193o/doinOqWsinTus4Uol9eNE2KI2iaIw2226LpT30v6GcgxPSjENtitgydADu
         DWv/DXMUeBppQJA9mtlLTEh6//5P2iFneT1Cu5DUeXKro/e21V3YPUJ0hlkc+YxGMgzF
         h8aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="G/1EgNqi";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id h22-20020a1709070b1600b0072695cb14f9si448684ejl.0.2022.07.18.17.14.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v2 24/33] kasan: make kasan_addr_to_page static
Date: Tue, 19 Jul 2022 02:10:04 +0200
Message-Id: <a09042721e429504d3e989a99f3e90455e19be1b.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="G/1EgNqi";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As kasan_addr_to_page() is only used in report.c, rename it to
addr_to_page() and make it static.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  | 1 -
 mm/kasan/report.c | 4 ++--
 2 files changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cca49ab029f1..4fddfdb08abf 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -291,7 +291,6 @@ bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
 
-struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cd31b3b89ca1..ac526c10ebff 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -206,7 +206,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 		pr_err("(stack is not available)\n");
 }
 
-struct page *kasan_addr_to_page(const void *addr)
+static inline struct page *addr_to_page(const void *addr)
 {
 	if (virt_addr_valid(addr))
 		return virt_to_head_page(addr);
@@ -289,7 +289,7 @@ static inline bool init_task_stack_addr(const void *addr)
 
 static void print_address_description(void *addr, u8 tag)
 {
-	struct page *page = kasan_addr_to_page(addr);
+	struct page *page = addr_to_page(addr);
 	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a09042721e429504d3e989a99f3e90455e19be1b.1658189199.git.andreyknvl%40google.com.
