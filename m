Return-Path: <kasan-dev+bncBAABB4XO26LAMGQENJZWNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id BA20C578EFF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:42 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id m10-20020a056402510a00b0043a93d807ffsf8832892edd.12
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189682; cv=pass;
        d=google.com; s=arc-20160816;
        b=KdnsYo/ozq1o3Q372vyOmHlqPg2BoS3nLwVJ+3lfXLszTnZm1JXJY2lnnm/kQWH66O
         RCVQADb8YWFk+JWHLGchbaBNCN92NIbxUhZtMcmHqNQc7O2/NwBzXj3EFzP5/bsaG1j0
         BFd1UWtdr8ql2O8BgzvfGJioUKLWOGxOvf9ImZpEGIBvnMpE59+2EUfIARwH/FU2sVEx
         Hs+3GJ2XL1m8HvvI39a0LBTJAf3d4TtGh/ZfVUEkzChNQjKkT6ovp/rQuO1fVqzcHPtA
         zp66QvnZBKaIxrM9o2qM5QD+aM9REdmvfVBbryHnELjPCjyDCCMoLRmCQu3TOU/KoSxy
         7Gtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gaPKITU1oZhZ5RfWxji1Vc783zlHgHPJc7ukcJgOvF4=;
        b=Nvf5oPnyA6rJwzQhnsS6GZjFICBljB0sMLPc++Us8cLGBfFzubyaKL7PSofdjFqK4j
         ordOPa8unToNB/dKb/I2u6BG/0MCrsvHBojCVtYY5cqIEN0smRi0j2LtI1kNKr8dJxis
         laTWkLsStzL0XoGwbsdvtJhtF6+wAy+H9AS4B7kuaRIdcUi6bEp+cCIErqlmwFW3UpyF
         95jad1JDXsrlk/okUZEJvlGgJfZR2x0KqG7P2is+fwa+/o2z+q+ObPUZYp+V6/gelFLJ
         28AOkuVVhgGe7A9YZvPUXN5BLobOOIKGS9n8Bs+Q1CFyvjtDdXF4qmYCK0wQGs53vx4W
         YjVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PsMkFHXX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gaPKITU1oZhZ5RfWxji1Vc783zlHgHPJc7ukcJgOvF4=;
        b=t1vi88tm0YBQV0/4TEbCj4cDGrpMtRYsmHBzy+5UgHtTjQv+4RWNdpY+daJTLvvAsN
         y6RZc03g+hZgoRqdGv9xo5/sNFTkXGfolRwGaY0c2LHE3/D72olvTnxjDBnU/oMy+rKW
         RbGnHFaowrR1r/yLYxU2edfbxQTjaz9LFHsxauGdBaOulURSOjGFFeq8bmSn/xCJg/W3
         BJ8grB3ZjzKvh/+f02PwyzDHj1PutFZBNlJGHQwsQhTIbcbuclSun7d8Uj/1ax12drQB
         6TyV7EklNiC391V6tBiarwUYo2B84mo/Dtq4daSZSm0/TDX8WviEQ+olwIQuYL4NEjAd
         rZSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gaPKITU1oZhZ5RfWxji1Vc783zlHgHPJc7ukcJgOvF4=;
        b=2ne7KqB+eY6/83q/U/0A5GAnkp2hUi45Cf1W6FdQbly8fCl5wSCyanPLj2XbGQLoCY
         FpunQtRBrFVrStEPtPW8WOSyVxVoM2ZmtDQKMo8Pv92xCu4FkK7bR/N8NrAdW75d/d9E
         qqL5rZ3nQv8laNTVubDBh88YyOi/sUBAFvM/RNK/cPgZHBXzPyQLP/bYsvM9MzdjCTfb
         NemAUoHQmN+Secsz9uQenJ2NQsW++94IO2/N+3w4PbuUvjvvx1DUBUHJ/wnP5nPJu05T
         3/mH1tiRu7N/2DAj5do570VkxD6QH37TNCQtcyUjvGgPQpCESewakFkMOoqdJHhWA460
         ZHgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8HRboPlB0F6pP1FxSBvWpwDuXCfCqRftMFfx7hPgfVEsKPnmWt
	1pu8Xj9qJNurK1+ZC85AUq8=
X-Google-Smtp-Source: AGRyM1svue8DME7P7Au0K5YsA1QPGEHuC2h3x5JQ/05kDkIs4kjmYbQ4Q43cOh40Ee7x6vI41DBKBg==
X-Received: by 2002:a05:6402:3284:b0:43a:7fb4:ad8d with SMTP id f4-20020a056402328400b0043a7fb4ad8dmr41383645eda.28.1658189682426;
        Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:d0e:b0:43a:6e16:5059 with SMTP id
 eb14-20020a0564020d0e00b0043a6e165059ls79630edb.2.-pod-prod-gmail; Mon, 18
 Jul 2022 17:14:41 -0700 (PDT)
X-Received: by 2002:a05:6402:2287:b0:43b:a9d:ab1 with SMTP id cw7-20020a056402228700b0043b0a9d0ab1mr39758560edb.325.1658189681793;
        Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189681; cv=none;
        d=google.com; s=arc-20160816;
        b=K/PPZQOXxWkOqTItSJg933rA+OnNWU885b4xks2Cv55DBW4jlubO23to4XYrphrSS2
         EWDSEs41yl+QyBejRu30bpqh94m9cpwrwmpxtacBq8Wnvot1QKgsVHMymaDmB/MJ9v3k
         Xi1mkaCtipEEQSllos8Vi6CdTroxbpDYNjK5XIwFw4YxYAaXmFcymlsYcywhymqyOpfT
         6B7S7KaIG2qhtMDhcig1Q8NHMJu12XtxbWzynOE2qKzGQL6YX4ebVXXoT35fiRRp2SkJ
         ljFJ+x3zMw3SqzuBKo2eujq8y5wdRG+LtI2GDAeE132brrx/jC2FNj5yvPmixdFv5bUI
         s3Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wlDL8UWCNOAUa7xc7DhMAdKP5Ju8o15uIhriUX+aQyY=;
        b=vCdmF8BS0nvdSUmIt6aIxPLY/Ma0u++VOo6/k4iLtCYpXjnKx3iV8J26rjI7y3pL4k
         350MHFvh2ZF2uGA0I2qxMlEP5gXMdjX+ShbTk2xYff/7KKgzNeXDkPURBL2E8WiYl2cv
         25XhKnN5ZTVMRo7kNOrNy88Zy9FN9/TO3atsfF6RaIZTbGunDMcsamneNYobBS3iUWRJ
         VQitN8kjyIgTkcJgXTUpCi5jGHcovpDcZubiScbgRKUWYpLriFGrfyVeL6WV3EvqY9kU
         +tYfqHTveaQeGp611VP5k9WLuTNPuN8+fddPqd5A9XeSt03NxDFDxvOp3pazTYvwiIG8
         wiBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PsMkFHXX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d10-20020a50fe8a000000b0043a99ce7f64si388038edt.0.2022.07.18.17.14.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v2 27/33] kasan: fill in cache and object in complete_report_info
Date: Tue, 19 Jul 2022 02:10:07 +0200
Message-Id: <83156bb0ec6d790b0e7ea0002b3490a70bc5c481.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=PsMkFHXX;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83156bb0ec6d790b0e7ea0002b3490a70bc5c481.1658189199.git.andreyknvl%40google.com.
