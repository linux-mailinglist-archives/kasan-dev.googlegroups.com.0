Return-Path: <kasan-dev+bncBAABBINXT2KQMGQEDYDV3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 71BC6549EDB
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:41 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id lv2-20020a170906bc8200b0070e0d6bcec0sf2184317ejb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151521; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yg7kUKIBdpOZj9mtqXaaa3J1ZB2Qie2wCJQEPBFKUVxVvAvUh6uyiEXs2jv2lfZ9I/
         QV1vnzlB29CkKMyBccciq+VXgGb9oQmyY6E4nSch3vGn7MWtw1lBVtmDW4nVjunKll8a
         ihM8LAqLV9iKm3N9kgBY4SebZrw1jLfKA+Ftrdl2lM8ouQChI4iOYvs8abKbtIHvVDz+
         Vj6hfAEAcgEAVCAMsqgwNDl1k9ncULe3dG7OkZnX0rW/wzJDQUd+JZeeG2us/GZGVcbD
         Gf1/FOtfQy7siH1R7R4NU6xryinxqzB1rEqEcL/vC2o8aTXdrN+fo1jMIqeMoFr3xBBS
         0i7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bBMHx6AJE7qbhQTwG8xf9Af7CrhJOwAwpAxeHUWt3kk=;
        b=nVxTlHGeBo90MJkPYqKxC8yQt+nAcdy+JbTxnaUzyQyAHIOPlEWpBSD88HT6gppkK/
         IeIyfTsoXWOogxZmkQUNQobLT6c8kII5fhqMp3xrvjQimbIJ9Ckiq6y0TxdRVNALb769
         KcRvW0tqrnjJsEYj2BTO+4zCNmmE9kqsn/CQjHjU9Uob6I8bNnp9tC2GFse83BjGNtHW
         tdbaoklLQtIAsh6N7rWUo84XWjtmSWafoxV3kfZBzX+sH7wbXK5srBXxMtdFryVq+1BE
         /3+BS3ITrpKUqxMSRzOd9SPXeIEFjo8AJSAlpXrfBonTygH28LFaUQqeIDtaydAY8Nu4
         2oog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JefL7G+u;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBMHx6AJE7qbhQTwG8xf9Af7CrhJOwAwpAxeHUWt3kk=;
        b=P67QRQJ4mmbsn1jJjAcrc2UBSKhf5N6zOcHLL8fyYZmPO/k/cCj2yOyCoCD4X8WQr5
         MLCqsqneM0D1bbV8WcC0miril33MM1vEpo0oMFrOBd+w6F7Ix/dxMEEp0L0cBLmyjJf9
         bDm6kKEBTVJ5oxw2tfmsUGko5kjRwB48liTX37FRVdi5Y7GzCTiYfwTbrAvak984yNAk
         M33K/biKzvL9Bua+muF3zZ7PWivorVYsmq81i1L9rt5JRHdiWapeiSqzMtep7vdk1hfX
         EPWNWEJwi5h/AkP6/HTHUQiTl00GgZlNBvkUpbnQKssvIKchdhCy3BVCt0/Gyumc4X0n
         GUnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBMHx6AJE7qbhQTwG8xf9Af7CrhJOwAwpAxeHUWt3kk=;
        b=F3QXKLKArimhpJguLI9IVGVG1w1+yAs/lcXjhIp8XySZxw3Xv0fq3WHtj91lEuniie
         e0Dt9dCDeSZWYOABX27TRYM6jhGAM2kMIRFv1hVVCZHw21i6YZF2K1ru6+rEdarBoI6D
         jPASxudBGdjepj9/VhpDPUqmOFOl5Uf2qdUZAC3/8zCEeB2kADPFQl6LOdjet6xs0HrZ
         WXmhP109zDwtWiLWcSDYzKVZLFy70/IxoTnOxPV/gTgWzW4cQy0N3qUcvKT6VoRWzKwC
         0Idd2Xc4vPU/TIxMMvZT2D5b8Zxx3RKSqAK3bgCm21N1jNBXNWZU9mKitcE743t3zOVq
         wxEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gLv1v6cJl7Rc+iHMp7OpLoWm+2yedtvggMUxv0S3jF+MZAf15
	6gG+R7KA9YsnJ4XTjDk191I=
X-Google-Smtp-Source: ABdhPJxt5aiIq0A1vnqU/JZCeTm6YixmWDgRF/HtNznrZ1oziP7pT+2yGo/Swukp1/att9iwzmleBQ==
X-Received: by 2002:a17:907:3f97:b0:711:d61d:df9 with SMTP id hr23-20020a1709073f9700b00711d61d0df9mr1321843ejc.644.1655151521273;
        Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:70cf:b0:6fe:d027:3c1f with SMTP id
 g15-20020a17090670cf00b006fed0273c1fls145057ejk.2.gmail; Mon, 13 Jun 2022
 13:18:40 -0700 (PDT)
X-Received: by 2002:a17:906:a10c:b0:711:ec20:69d1 with SMTP id t12-20020a170906a10c00b00711ec2069d1mr1302172ejy.718.1655151520694;
        Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151520; cv=none;
        d=google.com; s=arc-20160816;
        b=EBM7dckF1mN8Mk8zm4SUhGS3I9rTUiMP7TEW3w+NQnP06JDvpgf4hjalPUzE8rqSdA
         35P5jIdxbPrqYlqbDTIU+rQL2cdRi02zbUqpGFBlYr0SvGxHJNkLZmBknZn8qMoki8F1
         VS+taD5SZ+8RZVqjFpZ7V9ysATWpYDqKWjemqrP9f0yxmZObZvI1xiQaIxB6mg6PigtG
         8X+UV433PQ8eHw+n/hGFxdxF7rxkcsdopsWjsI/QFoidfCIqqKjRHxcIYkUJukqtqiJg
         bhm1xtMUvB3CZb04+M7q8HZyISMEkq4Mxp+eVGZiMaMFe4c1DTkUAmztlFicvsFTjAvH
         UNrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7UlP4rgYEeC4zjzJGZ6kC7jJ637whgBTqafUFs9KdFM=;
        b=H/CuBoN3okpU9jXEpa3vvw34o05pvv4POkVryBEFrypkKhqmYvBCUFbv6/g51uAIyX
         8eTDGxf+tzUGGUa1IJqJkvDd0R9KmH5M8MUbr6+ky5oP5cSy7EpCsGsfWqliJ0Vm3Ume
         Y1/q8b8m4GonSVLRP5hiFfvZ9y+GT2sPEXILpLiIFQoe4xoiccad5tHOxx9f7rdRuFkF
         pSGJXlvB5xg2J+EDKMUKBQugpOxuB/DNgYhrWKAxbuKaBZ6Mss2TeCKd6zjXkFUnEiKL
         Xe9blsd+UashLvGAxT2e1oWGxFnfOkQkhmHLEa80b6YSD7DtM4YGshh56LQh6PcJCKmn
         wjnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JefL7G+u;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id q24-20020aa7d458000000b0042d687c85d2si344326edr.0.2022.06.13.13.18.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH 21/32] kasan: simplify invalid-free reporting
Date: Mon, 13 Jun 2022 22:14:12 +0200
Message-Id: <f7f5cfc5eb8f1a1f849665641b9dd2cfb4a62c3c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JefL7G+u;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Right now, KASAN uses the kasan_report_type enum to describe report types.

As this enum only has two options, replace it with a bool variable.

Also, unify printing report header for invalid-free and other bug types
in print_error_description().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  7 +------
 mm/kasan/report.c | 16 +++++++---------
 2 files changed, 8 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8329935fbfb..f696d50b09fb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,16 +146,11 @@ static inline bool kasan_requires_meta(void)
 #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
 #define META_ROWS_AROUND_ADDR 2
 
-enum kasan_report_type {
-	KASAN_REPORT_ACCESS,
-	KASAN_REPORT_INVALID_FREE,
-};
-
 struct kasan_report_info {
-	enum kasan_report_type type;
 	void *access_addr;
 	void *first_bad_addr;
 	size_t access_size;
+	bool is_free;
 	bool is_write;
 	unsigned long ip;
 };
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f951fd39db74..7269b6249488 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -175,14 +175,12 @@ static void end_report(unsigned long *flags, void *addr)
 
 static void print_error_description(struct kasan_report_info *info)
 {
-	if (info->type == KASAN_REPORT_INVALID_FREE) {
-		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
-		       (void *)info->ip);
-		return;
-	}
+	const char *bug_type = info->is_free ?
+		"double-free or invalid-free" : kasan_get_bug_type(info);
 
-	pr_err("BUG: KASAN: %s in %pS\n",
-		kasan_get_bug_type(info), (void *)info->ip);
+	pr_err("BUG: KASAN: %s in %pS\n", bug_type, (void *)info->ip);
+	if (info->is_free)
+		return;
 	if (info->access_size)
 		pr_err("%s of size %zu at addr %px by task %s/%d\n",
 			info->is_write ? "Write" : "Read", info->access_size,
@@ -435,11 +433,11 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 
 	start_report(&flags, true);
 
-	info.type = KASAN_REPORT_INVALID_FREE;
 	info.access_addr = ptr;
 	info.first_bad_addr = kasan_reset_tag(ptr);
 	info.access_size = 0;
 	info.is_write = false;
+	info.is_free = true;
 	info.ip = ip;
 
 	print_report(&info);
@@ -468,11 +466,11 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	start_report(&irq_flags, true);
 
-	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = ptr;
 	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
 	info.access_size = size;
 	info.is_write = is_write;
+	info.is_free = false;
 	info.ip = ip;
 
 	print_report(&info);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f7f5cfc5eb8f1a1f849665641b9dd2cfb4a62c3c.1655150842.git.andreyknvl%40google.com.
