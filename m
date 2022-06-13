Return-Path: <kasan-dev+bncBAABBYVXT2KQMGQEK6WI3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A77B549EE5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:47 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id g13-20020a2eb5cd000000b00255ac505e62sf872237ljn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151587; cv=pass;
        d=google.com; s=arc-20160816;
        b=wtulnYwM1ZF5/8116qgsLTcYmIu4bca4KYqHim/GyiOf/8ZAFldyC6/AKhvaIKEI5P
         9lSRfAz+R722sgohRTRr/pq7hUgMKftMQYmmiwqiQ9DR9AAwKniZ8S8N6jtL79GRx+P4
         p9kMUSaA92TgYamuX+bM2gyyMXxFJKBrP9xcQcvhyHlxfoi711vKQY4QNeTvz5pSO0vI
         /EpCC33WKzfXMavD5EaGw3cCVi0ufzmC0qWlNcCKPKixJcsmVPu2pqkp/IYQPeWdp/bs
         lyqsH3p2tdLr/SH8rqnoXep/bqldreSw4EoWI+c6mm34dFqYQKWzKAHi0Wk+qdjfkrZf
         7j9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F3kl7K03Kd/3YTs8Dm/8B98QRZifvo24JckpxA1KlIc=;
        b=IR2ucUGAJuwroE+/W4q6GGCB8zOsprbjoH6M8B0nxDFju2EPC5KWtRTGleCO51il1t
         MLRDwPIe5tUsqbXCHPL0yD2tk9V8rA1W1CXbMdtplpDRhDIOstuPx6T5xZqCJWTwMU4c
         J1BMB8UAFQ5lZAcFSjvCXUVkJRQnc7DxgFl2QopF7lbxPuBYIVhch7MB2a3N2CrNO7Y5
         QaFIBWiLVOriC2etZXnThCYgacWqQ0nWgJaVQQIfUVJIf9qVWRV4sdVckkJZf9FJWWy4
         mobKOeFgcWkjsZSjOyHZEJa0ocdYgiGE3v0aSpM8nQgxWyagWR7+8f03jM/KDkQjn33U
         Esng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wrqv7ohO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F3kl7K03Kd/3YTs8Dm/8B98QRZifvo24JckpxA1KlIc=;
        b=GCGw4VA88xRdyTz94aj0JINJDsa3NbcSP0zKRex2Hb65KPnN9uGDvOvq01VveWFHGr
         4c7n60boZuyatp8vj1mJrNrTA99WBINjNu5i50luGHAl977yo/a3ziHwI63CDzvfhCmf
         BC0zDBTvlE4zW9x2+gG60pe58wvvGhtIqa+yBHjSeNAKdsYk0VnTcOhAJpQEpaBb1opF
         iIWHFviRmBi3cHwXRMCvXb+FbUbdnIW5KADCX+BSWG4xZ0yTYWvaqGVclgVfXfk4P/1E
         gxv/BpUhXLbcJoSG6D7HbP3GZXVfsbhXisx6G+zhUs4Sdt1ecAvPuA5yIaqm1OlEed6v
         9QnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F3kl7K03Kd/3YTs8Dm/8B98QRZifvo24JckpxA1KlIc=;
        b=kb5w6Zr43LFAsNzhHqHrBRPG1jpsNfL6fpTrMuhPALQXBZ3RGN7bgJPq53U9FGvBJN
         Larm0NO84UpNS699GvoKIqNiYUMrAJ0PBbnH53P11tEIks4tKRWX7j/no/dD+cxgFC+i
         aEB0XSCgjQ8NsOwWbTUzwdJ96ga6/KLFCTBurA7NUC+ZCkOCoV6z0FKacL6F1N/lm1Tt
         awnUJ+4OzR7MBmTC/reBnlPahnQdZdUQDLSDfC5HJ8tR6YS6kGQ0hYvmQnQLIWtcSw9W
         iiGqcGY2fou1VaqzrmIbUEzmfLNxko/CYzG23wbcOsS8S1DCQC6D5WuOxCfbAE5WEDru
         j6Hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/a24ui70Z7YndsoQwxJviybg7FX4o3woMMBjBKvlQiu9G20TDQ
	ghonIV+zwt+rwnbPGSSutGU=
X-Google-Smtp-Source: AGRyM1u3cdpSyACvcK/oIkntx+99kHJKqCmKVlQvb2iQHvstz+kQo6+xyi4LqUQp/7W275sMI0BbYA==
X-Received: by 2002:a05:6512:3b87:b0:478:ede2:64ac with SMTP id g7-20020a0565123b8700b00478ede264acmr914901lfv.241.1655151587105;
        Mon, 13 Jun 2022 13:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als188456lfa.2.gmail; Mon, 13 Jun 2022
 13:19:46 -0700 (PDT)
X-Received: by 2002:ac2:4351:0:b0:479:5d63:1471 with SMTP id o17-20020ac24351000000b004795d631471mr943731lfl.594.1655151586403;
        Mon, 13 Jun 2022 13:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151586; cv=none;
        d=google.com; s=arc-20160816;
        b=RMGFfp922h0A7BUiyKMxd2SxzVYfuedsNDDLm7d+Rt+Pr7g4XaLubpB2+FA7huxB7p
         gFBMHznegTNB23f4wSiRPDE8U7STxh/1vxvWfbQB7vDLNRp6X6f+BecL0ThZroXMGHYE
         RQihG733ugEeVbVcA22KzmTFhf8zRSyqW9npaf/o7wo8GN1jTaQ0wzeEcN0u8JDoc+IG
         X22dTVHkijy0JpnsT3NnT+jGnhK3CiNVtCvQDjJQkq6ZXcWMrUy/LwPBtBnfW2xnDezb
         0ZYUxVErPrJ3WB3Xe8JEyYpv5zOwON91bNqIHGh0LRJWKw+2knpETgHI0AL7YBWiZ4yu
         MGKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4luxyHsp81FOFiUT/6yoqfYUWRQbE1ZGpW4pjt9Mu8s=;
        b=TCgTv7KNTmUYEIEa2Hsx4OxqMGgB6yXpzangYArTZnrw0QmCHbK04D0gnjKhKF4a7Q
         g3QKpecCEbwJJgg969Dm9SqUFMqoqi/YDsLsX6zn6pyTxpWBYxoKzoRrREovzu4wrK/7
         tFBebZFwMO7JXfm/s8a+lg1MvReSbOW/gyupnno0B5mzXhoJltBcJAvC5Kk+jaCO4iqB
         UGsJHjzoLb8U5PITGE/ZFNyFi/9le/Das0ZlwEltEpzclQq0/8I5aYnSjm+gGXQjmPT/
         GT7a7krI4sAVmC8+JMFqj9OkOGMp2F+9FFDcjmbF6brp2PDeXJ2zydUOmk2Q0Ooc5fgM
         eVZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wrqv7ohO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id k6-20020a2ea266000000b0024e33a076e7si300301ljm.2.2022.06.13.13.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:19:46 -0700 (PDT)
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
Subject: [PATCH 28/32] kasan: fill in cache and object in complete_report_info
Date: Mon, 13 Jun 2022 22:14:19 +0200
Message-Id: <1e3e75cbcf4f258701b325dbad8b2a43c2633b7b.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wrqv7ohO;       spf=pass
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

Add cache and object fields to kasan_report_info and fill them in in
complete_report_info() instead of fetching them in the middle of the
report printing code.

This allows the reporting code to get access to the object information
before starting printing the report. One of the following patches uses
this information to determine the bug type with the tag-based modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  2 ++
 mm/kasan/report.c | 21 +++++++++++++--------
 2 files changed, 15 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0261d1530055..b9bd9f1656bf 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -156,6 +156,8 @@ struct kasan_report_info {
 
 	/* Filled in by the common reporting code. */
 	void *first_bad_addr;
+	struct kmem_cache *cache;
+	void *object;
 };
 
 /* Do not change the struct layout: compiler ABI. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 214ba7cb654c..a6b36eb4c33b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -281,19 +281,16 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
-static void print_address_description(void *addr, u8 tag)
+static void print_address_description(void *addr, u8 tag,
+				      struct kasan_report_info *info)
 {
 	struct page *page = addr_to_page(addr);
-	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
-	if (slab) {
-		struct kmem_cache *cache = slab->slab_cache;
-		void *object = nearest_obj(cache, slab,	addr);
-
-		describe_object(cache, object, addr, tag);
+	if (info->cache && info->object) {
+		describe_object(info->cache, info->object, addr, tag);
 		pr_err("\n");
 	}
 
@@ -400,7 +397,7 @@ static void print_report(struct kasan_report_info *info)
 	pr_err("\n");
 
 	if (addr_has_metadata(addr)) {
-		print_address_description(addr, tag);
+		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
 	} else {
 		dump_stack_lvl(KERN_ERR);
@@ -410,12 +407,20 @@ static void print_report(struct kasan_report_info *info)
 static void complete_report_info(struct kasan_report_info *info)
 {
 	void *addr = kasan_reset_tag(info->access_addr);
+	struct slab *slab;
 
 	if (info->is_free)
 		info->first_bad_addr = addr;
 	else
 		info->first_bad_addr = kasan_find_first_bad_addr(
 					info->access_addr, info->access_size);
+
+	slab = kasan_addr_to_slab(addr);
+	if (slab) {
+		info->cache = slab->slab_cache;
+		info->object = nearest_obj(info->cache, slab, addr);
+	} else
+		info->cache = info->object = NULL;
 }
 
 void kasan_report_invalid_free(void *ptr, unsigned long ip)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1e3e75cbcf4f258701b325dbad8b2a43c2633b7b.1655150842.git.andreyknvl%40google.com.
