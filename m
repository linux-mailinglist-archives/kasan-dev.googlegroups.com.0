Return-Path: <kasan-dev+bncBAABBY5XT2KQMGQEFGJ3NYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 539A5549EE6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:48 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id n5-20020a0565120ac500b0047da8df6b2csf3499193lfu.18
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151588; cv=pass;
        d=google.com; s=arc-20160816;
        b=WXUwsH9+VBsUMf7cetw5VOf/21mF/6eCl99zegATJlaxFm2mC0mebeppEPKuVC3Thl
         ukUu/jfPRwaFpiBHCMOXEnxRZzXjiSppQ8Zvgv/q+yelbOf+panuPpRTrFN7RcyQX0P9
         naLQNn1yO79MskHpzRUMLclMB245JPsfQnZWS/Hrmtkzx1nW6i8ZbATNx1wvvX7Walpr
         bLNyMgiBrfx/IhHJe5dUytqgCF8XCxDeMOck9do4z45BcY4Qh1NknOKTxbjLHZP5HOuA
         OnLohuEwHQzrNTvJxqX3KZygczDywTDgnLOaNLXBbKkgmtZ1eVpx3Yk04635SGXkvQUR
         BARg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0wAmBEYWKOiqmYbEV1+oDgPjbKABKhLd3cbLvSZET3Y=;
        b=hbyIH/1ol3bp2QhGV3+7W8RVv+PbymCH71JFehjRJ0gWMA2aZPrPq3qFfgegM9IOLz
         0Zt6h3Flwc3MQM7wj4EOs36diA8o5nFnlbBGGTXoabz+dBUkmM6aqqTOKZw46IjchWo8
         OS3rJayDqXsh67qM8uoHBxdJc0/hG6bVcHb3ieh/EFAi/DzAzdByJANfvrZlH6+wmCJ8
         0rWiLTFTzvuU5AOcURF4OU/6HMji3+HqGgMlRpa2qLjyt9ov+DYjG5wzBtXetMxwxA3h
         OgYTjs6PyOv9MMCIGKpPu1a6D9WLC1shI1no/WckEJTLwAS6zQ/hPN9sy7HGKEE4yYL2
         iC/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="CTO/MXcp";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0wAmBEYWKOiqmYbEV1+oDgPjbKABKhLd3cbLvSZET3Y=;
        b=KxTdBz4ZnpuJ30v52z/+uqjAholMjOLY9ETeP1H97PaWw2/KwkuJuQcYywRVKuXsSn
         k6vo7Uymy9NotBjupMOlWHKki8Z6KGGOPgQKIRyklLLEaMAvb5txRTabUQyYDAc3MaGt
         uE9ubKwFa7B+qHAhoOL4B70j+fG+xRMhRmNJKDq4qiIDW5c1HnvRTdMxV+map0jf7REe
         0X71/zB23nLiC060VQ5Kg8n5hXPCBHdAotb16OguJGayyexd2gr4HyvHHpvjWhCuAtFg
         9enuaY+6zBwpW6EYqSFhiLEbvlIkh6OP/zG7uU/HkCGbWt19hXEc5DottR+zdNNu5/Lo
         2vxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0wAmBEYWKOiqmYbEV1+oDgPjbKABKhLd3cbLvSZET3Y=;
        b=bvaq0Wr8V7EI3z8K0UTyAbyrjRNWayLIOsy447b0ats/q5tI8h6/iDBgGSCw6tSWAM
         /ciVtScjwQrp+u60s2SC6/8AS8iqB7fvsn9Nq5IkmH0t6gre70wofhF2l7VTYtAwWb4v
         /FmodnHj9Fs4bv+3MW5BbBhxvHAXbaoPdssbA9TRnKlYXzl0XzTeWmsGARXAPvXTZix1
         zpKza/O+fVkOHBF+lrZ1ZpbNUgiq34dpfjORZrKe/v2cjlJmNltJZOg2bnehNfHb6mZE
         99MTvOsYaginh27enl+38FHvUEQj4gAUJw8dn3+zJ365kxhbGfpGVn6K3xFxdp72YCsM
         7ylQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora932ZfZtDtDnvx+IvBGH009V+CR5O+FmlSJ7jjLo4R7PGj945LT
	iEUaSfLGbZsHBj+VkGDYeIw=
X-Google-Smtp-Source: AGRyM1vW/QJ81VvleT5PZVSDu9zZz8tJMq1JOiQqwYR3U4rEpaJ1cRt+p1+QY5rtaxQMZn5FuB3srQ==
X-Received: by 2002:a05:6512:53a:b0:479:1725:51f2 with SMTP id o26-20020a056512053a00b00479172551f2mr907666lfc.688.1655151587808;
        Mon, 13 Jun 2022 13:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls188342lfu.0.gmail; Mon, 13 Jun 2022
 13:19:47 -0700 (PDT)
X-Received: by 2002:a05:6512:b93:b0:479:1d41:c960 with SMTP id b19-20020a0565120b9300b004791d41c960mr942294lfv.78.1655151587007;
        Mon, 13 Jun 2022 13:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151587; cv=none;
        d=google.com; s=arc-20160816;
        b=JrBXQbJRVHzutxVRuw3H4jKkfE+pvtsvcSHs8+wORXHMN5khAtSU+51CaK6auU1B+W
         WFWf2aO2NXh0n8Hsh9Wu653PjVs7cMa9h3ttKYQx+oMA7Lsa5V4DcZSlzFdTQHMvYivN
         tyy6/0Dzh/0HfRTK40ePGg2L/sYO2JrQXOwdFgzMDDcb1mx1ojwUbtdEi0jrxNLHKKPC
         XwYxcuFxgNxCeQ9lK/FhFJBHatAJp7op/Xn8mrQsUJ8q7jCye+2UkpsBPWmZpjhCbzLY
         hvsWxhiYQez0p+Rc7Bt1qGZpCJk7TMXHWO2bi7xijiDU9lcVV1FsOPJzEA9SOGFlfqQW
         y1XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=itBNzX7+Qi1Y3bHVuJEJdtRTIklJZqEOcvL8dc0SsNc=;
        b=yjgUFemG+9h4A9sOImUsMBBhDSdxr0xvWgUaM5SUVQLpKqcAdkjGCkp0Vcm+8NgTYf
         FZRcGwS6Yvr69J7hKJ5e4GOSAs1rLvN8WALsU0OAACIHDyDwpDqBnm746/wg83Kl62Ot
         G97UHTM7Zzy7LtrmQujzmdTu3xswO8pMSledhfm5TCiZ54VpVkrVPjnLHiGXtu1KMAO2
         Ut1SFEE9DWP5UJXUSzLEA36VnAfwVRNKrti5B3qX2R82QrODas5X06ErkwK8lrGEs8mL
         2ICQxLGiHJj6qT4zznFAPnwz5uxa49B/iEdepcVfRVHdJrhZFBwTpC88YDltKuaKucFA
         gsJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="CTO/MXcp";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id b21-20020a0565120b9500b004793154b447si269143lfv.13.2022.06.13.13.19.46
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
Subject: [PATCH 29/32] kasan: rework function arguments in report.c
Date: Mon, 13 Jun 2022 22:14:20 +0200
Message-Id: <a3e6a3268681a28737a8dbf79eb4786ca2b28276.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="CTO/MXcp";       spf=pass
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

Pass a pointer to kasan_report_info to describe_object() and
describe_object_stacks(), instead of passing the structure's fields.

The untagged pointer and the tag are still passed as separate arguments
to some of the functions to avoid duplicating the untagging logic.

This is preparatory change for the next patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index a6b36eb4c33b..a2789d4a05dd 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -207,8 +207,8 @@ static inline struct page *addr_to_page(const void *addr)
 	return NULL;
 }
 
-static void describe_object_addr(struct kmem_cache *cache, void *object,
-				const void *addr)
+static void describe_object_addr(const void *addr, struct kmem_cache *cache,
+				 void *object)
 {
 	unsigned long access_addr = (unsigned long)addr;
 	unsigned long object_addr = (unsigned long)object;
@@ -236,33 +236,32 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object_stacks(struct kmem_cache *cache, void *object,
-					const void *addr, u8 tag)
+static void describe_object_stacks(u8 tag, struct kasan_report_info *info)
 {
 	struct kasan_track *alloc_track;
 	struct kasan_track *free_track;
 
-	alloc_track = kasan_get_alloc_track(cache, object);
+	alloc_track = kasan_get_alloc_track(info->cache, info->object);
 	if (alloc_track) {
 		print_track(alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
-	free_track = kasan_get_free_track(cache, object, tag);
+	free_track = kasan_get_free_track(info->cache, info->object, tag);
 	if (free_track) {
 		print_track(free_track, "Freed");
 		pr_err("\n");
 	}
 
-	kasan_print_aux_stacks(cache, object);
+	kasan_print_aux_stacks(info->cache, info->object);
 }
 
-static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr, u8 tag)
+static void describe_object(const void *addr, u8 tag,
+			    struct kasan_report_info *info)
 {
 	if (kasan_stack_collection_enabled())
-		describe_object_stacks(cache, object, addr, tag);
-	describe_object_addr(cache, object, addr);
+		describe_object_stacks(tag, info);
+	describe_object_addr(addr, info->cache, info->object);
 }
 
 static inline bool kernel_or_module_addr(const void *addr)
@@ -290,7 +289,7 @@ static void print_address_description(void *addr, u8 tag,
 	pr_err("\n");
 
 	if (info->cache && info->object) {
-		describe_object(info->cache, info->object, addr, tag);
+		describe_object(addr, tag, info);
 		pr_err("\n");
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3e6a3268681a28737a8dbf79eb4786ca2b28276.1655150842.git.andreyknvl%40google.com.
