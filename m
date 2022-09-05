Return-Path: <kasan-dev+bncBAABBOWL3GMAMGQE35QV4SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id A448E5ADABC
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:18 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id z11-20020a2eb52b000000b00261d940ce36sf3180996ljm.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412218; cv=pass;
        d=google.com; s=arc-20160816;
        b=dzKLd+71BVxrGvZY2yFuljmhXrJMn6EFnsO9RppLJ3xRB7M44SNjK/3hvXx9oI1oq3
         SE7kwtjLnlqoXEyCMzB4+1bkuJ0E2YbnMyXOeuy2PIltRGM5irGTuk8G/5FtAu6JP5QO
         fM7/Pt1WeIiTTxVmw/O4gzmMdH+KKm6gAz5C/McrWdmZAwHES5knWhKti5be0w2NqtUb
         6TzVx8FWVP6dEHjCNKHexlzRH27a17muoDebTPh3kA5m82163vNYPmzMyHSf951iiUV7
         s93KJLbJy5kOexaAcyrix93W/7/nzuCYWnvHQOzsJh9+55WfmcCeClSgbyHr1u8alTdT
         uYCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OqL2KdQ/utp9derTAbMhnXwJRa0ZQdZTTwZKrskIxMo=;
        b=p8+BGWDepunyl4Wnuga/RaRx0GKyz03uqtmPNYcOijeU8Y7PoptxDjg8l3CtqlTbCI
         mA6aTQJxtCJWxGchXjboodMOaQwuch4NnTkBEo5osVZpL6tuwrOVcEfJ/CT1FDGZKzGu
         MuPIrKYuKQtJOExS52oW14+OzdM++7BwP4w6RecAhgTYDaODvMkLpndYiDkXssoDJWJf
         p2q306LOBefNASPsunNxcKJi9zqySxTXh93sTzxBy6Z1LOzmmuXyGo0gBouDlkYjVz0Z
         zphes9OawhvXfFJuKuq9pNNvS7dwIOS1EhSS5ZLJYLDgUHgI3JO9iNaABlQJO2dPdYbX
         m0Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HXM9rl7H;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=OqL2KdQ/utp9derTAbMhnXwJRa0ZQdZTTwZKrskIxMo=;
        b=Quwm6pe/2VNhe2kXlh35wpVkdZQ/8i9s6zya6vf6wwQ50byxqakG+NDiK8oKRJJqMH
         9zuuAAeAW5IVIUBKrV8eT9C369QXdInhnAjr9LXyUGJDJg3yUCxoXpg8avZF/WmD6pQ1
         +5lFpLkDx+JT4j78fAaFA1HE90dK+ZF1tXPr+QjEZXkd2F7nWziIRrnqv8ArtLKgdKJG
         3QWqs+EoPyTzND6N7Yr4AUG+E9gNHOoM9HoamwPfMWc/kW+TtozN98XhRCKPO8FtqK3+
         0BJ/33LJmc+8WykTTEfERCrsjVstlNuNNbgPhqHIp+5pfbNCGTN+Gn/Oz/Xv1xWunbol
         /eLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OqL2KdQ/utp9derTAbMhnXwJRa0ZQdZTTwZKrskIxMo=;
        b=lyRbL7lbUOdRCK7VsUUgg3qEgPW4ZSFJeUN1XrGAv1ITEyHEHPQ4tSYRlvNjz/V87B
         JLsRDkq0Sp06rpQSiD3yZfbSFq0Vm+60hoaMtXROtcouOfq1HRnaemYM6H3BmS5XCSQU
         c6DBYwliMPh9C3lKq4M3Y2zwIdG59VbgxN+TQnFytZ35ltMUj8zfc5Mke35KZMknj9al
         Sj70404akMDWxuS7cGBjyPXHAME+DS1Zd1F/NdRf0l/fF9Sn23y8oS4GLVdBJbUMkqR7
         689EuepH71HPep9Rs32LFlDIfs6putu3/qnR0yt2et9bQchB/iiUniO4ZiO8sK6lY5Ol
         PiPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0+4mydRj66yE7+8R4ebmkZh7ds12vPuMcVZLBGtmYDr10iGST/
	F7qDzKVMWHioUAlGpfIHKGs=
X-Google-Smtp-Source: AA6agR69GguI6sHBKYXW5oQjddlMw+9/QI6zL0Pp5B5ycrXSb9rM8WRQWSbPvLMdB7FpeIQ3Vnh2sw==
X-Received: by 2002:a19:e00d:0:b0:492:e5a5:588b with SMTP id x13-20020a19e00d000000b00492e5a5588bmr16028015lfg.243.1662412218225;
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2016:b0:48b:2227:7787 with SMTP id
 a22-20020a056512201600b0048b22277787ls5360136lfb.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:10:17 -0700 (PDT)
X-Received: by 2002:a19:2d08:0:b0:494:62f3:fcc3 with SMTP id k8-20020a192d08000000b0049462f3fcc3mr13082118lfj.362.1662412217522;
        Mon, 05 Sep 2022 14:10:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412217; cv=none;
        d=google.com; s=arc-20160816;
        b=ElApypX/cxqG07qSZFm0V0B8wXVEW6qIrzaeltTXWcCaUp6ltiZ0EFZqT0Gu4AobPE
         cUbsgpJ4MkFBxsJqLzuy+W5/zlrj2XQpKJBYIYp7kbVFZamK5JJ3o1sCcxpqfd/LAUK1
         uaKzTAy64ZoAUxp4lWK5cAlGsUgEvTldgzPKBmtxzp0SyI2NNRKNmwZ14OnX+QNT96RM
         g9NmI62PTD4tJjIaZ/8iadJg3PBK5MEH92paVlI4SqOy67xqDiHzT9aUP8OdQHgWFPUg
         DQD8M4M3gMuRX0kjKs/nuJ4dBRV4Wea6BQgxc1OMKk2i79mqqN2OmvgXZgy/IuzP5la4
         I5qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zEfgbyod9TAfDmSVR8FRbZx2ES7CDMUEPsx9DLtb/Fc=;
        b=qy8ohwTKG2uJFcD21LlpzslvSYfvplGH6V4fcYf1Ao26OEfG6Xm6EHa9h8d4eAdJz8
         YYkvyN55Rc0aOUep/7ncIqrgg4OKXBrkYpJcMh9yrvqngHmtimHjCXOSUehrOk0eBQ8U
         IUrcgtUQUevC8aXgKC5XbWtQRmR9jP9hRn49Fn2Uy1sDQaivYSNvTOlDgeOX/XxyTwsu
         j9TfvgLwwAxUWZ0xsRS6xu41JJkOVfT62ZoEGqWo7gLZ1Vo1Aa7xGEhCfZrHARBqgSY/
         CeZ8L5k0NDyo1Q8T20qTVqd/L3x22FlcAvIbE0lPh83gUEigDcOUKDSfDYStF20j6Wi7
         g2UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HXM9rl7H;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id u20-20020a05651c131400b00261e5b01fe0si478609lja.6.2022.09.05.14.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v3 27/34] kasan: fill in cache and object in complete_report_info
Date: Mon,  5 Sep 2022 23:05:42 +0200
Message-Id: <23264572cb2cbb8f0efbb51509b6757eb3cc1fc9.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HXM9rl7H;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Add cache and object fields to kasan_report_info and fill them in in
complete_report_info() instead of fetching them in the middle of the
report printing code.

This allows the reporting code to get access to the object information
before starting printing the report. One of the following patches uses
this information to determine the bug type with the tag-based modes.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  2 ++
 mm/kasan/report.c | 21 +++++++++++++--------
 2 files changed, 15 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7e07115873d3..b8fa1e50f3d4 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -162,6 +162,8 @@ struct kasan_report_info {
 
 	/* Filled in by the common reporting code. */
 	void *first_bad_addr;
+	struct kmem_cache *cache;
+	void *object;
 };
 
 /* Do not change the struct layout: compiler ABI. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0c2e7a58095d..763de8e68887 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -287,19 +287,16 @@ static inline bool init_task_stack_addr(const void *addr)
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
 
@@ -406,7 +403,7 @@ static void print_report(struct kasan_report_info *info)
 	pr_err("\n");
 
 	if (addr_has_metadata(addr)) {
-		print_address_description(addr, tag);
+		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
 	} else {
 		dump_stack_lvl(KERN_ERR);
@@ -416,12 +413,20 @@ static void print_report(struct kasan_report_info *info)
 static void complete_report_info(struct kasan_report_info *info)
 {
 	void *addr = kasan_reset_tag(info->access_addr);
+	struct slab *slab;
 
 	if (info->type == KASAN_REPORT_ACCESS)
 		info->first_bad_addr = kasan_find_first_bad_addr(
 					info->access_addr, info->access_size);
 	else
 		info->first_bad_addr = addr;
+
+	slab = kasan_addr_to_slab(addr);
+	if (slab) {
+		info->cache = slab->slab_cache;
+		info->object = nearest_obj(info->cache, slab, addr);
+	} else
+		info->cache = info->object = NULL;
 }
 
 void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23264572cb2cbb8f0efbb51509b6757eb3cc1fc9.1662411799.git.andreyknvl%40google.com.
