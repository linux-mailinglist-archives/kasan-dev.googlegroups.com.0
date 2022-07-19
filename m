Return-Path: <kasan-dev+bncBAABB47O26LAMGQE5ZXWYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B1D03578F01
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:43 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf4732174lfj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189683; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJx7hibt8JFCbT8PWQ4tKwTmpfkUKfGO2LOmH/3t8iELuuiwLwxdXuRQIKckh84KgT
         TUWNDt2JXBLV7yP2SVxGKNVXLr2qPWXVFFn3kaKU5MKlvp464jPhOlVG+NFDTfg3/OJ+
         32zfhsBhMDoPWzNRykwJfjhAXEFdxZzGjOWXVsHI1EILkaS+7/qvU+SZKXgxURs39+JZ
         oxk4NJlftX5c5eC4iUv2cWs185ZMYsM/FvP3ExWjLlzyj+hUddytvWRi5Phk29E3J6lq
         ttSNEJeRsejVzE68bJpXzZjz01RFVJdfBrBFzy/f47mMulogsI2Np854qJYBKIQVyNgy
         qtLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lqDGlFMlJY3w6VnIhd5RQRmvbX876wcHbdVxlZq3MqY=;
        b=N+GaVOgFWWEJRWpk3jIhl8Xs7aZhc2jC0p9qh8Tkt8diQsOKNc7ZQ/6XaNb63INwEx
         BjTqbYEnXdAEmdKKOnaR7PPdhUWSwT0HzH+78Q4KLhEDPichZpcQC4qydPRnYX1tKO9q
         OD2wPfsWV4rLJjxbVU0NOg7wUoBh4i4F8xKqaWCviDPFAbZhDPOz33qnDUoHQuCDofUs
         xO3NnRy3nOgpNndtLwAcfqPxoJjT4ZbLCrY25G17VM86AnadPaONxTe9Vp7KGUXm9Csx
         ok4dK9zCWaHYTrKYLnn42l+phIWJjGY5mFH6SPmbRu9IJlZgbA2qXXRIes1aPRWfG+0M
         ROjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="aTN/zjk7";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqDGlFMlJY3w6VnIhd5RQRmvbX876wcHbdVxlZq3MqY=;
        b=LwTawLVXT8mlCO0A17RSSYFnDI4yMVFUwl61aQx1lUUkV+IFPLOArIxCoWESQ74T1w
         tWl04a2RKUI6igpOscFbG13IsRyHhqUnAQ6uJJt0j/ocO5zbkriWZWbtkHTml1VKushf
         7eoz+pkrqkbRaO0O0uxNRhYOmei0UU5rjBEHRerz7iKy3x1CM4iTKmmW7nUOYFmYAfi0
         Uv7zg0U6/vOImNVddPszY26hN+2lXGiTUwmJQJysEaXMM6zXtMhtxNA7EMK2u/QMeXBj
         z6fLYraL6+0sVGWb25ghYBxzaCm/HErURXNjsI4YMk4qyJvS0bRG8fonPDSCwo3LPeST
         XVyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqDGlFMlJY3w6VnIhd5RQRmvbX876wcHbdVxlZq3MqY=;
        b=Hv9AurlTGuomA9gnmIj4pSphHiJMPfSy2Jvk6cbT4CjL15Ec10+8duOECa5afxGy4h
         YgbI4+tmQDaGSeFITCEvCJJOPqCO7C/a7aNbmljpzb6MvD0yqnR+8oFoj/JYVc9w63es
         MVtNNBn1dtEi2HgkaN+WHo4JrZPKKZBa/CrYkP+UQjKAI4wJ9Z15CdT7xuYQz2UjkZAo
         k19bF4bRsKhaAmKGnDf5yJERElW6DztDE0P28sui7QNJgnht6umdhmLDXntllWYK2E0j
         qPquuwFPzw67+lMAV3igMDgvI1XkHGtDXQuULErfqtGwUuxrpvq8xxFkbfPbJFip8pp7
         pP5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8uhEeRF3CtGj/6BFt6ECDr2Shzw6cni0URVFmia3VFkDAMT1bD
	ajCxd9acytDq1/CHY9RYNwo=
X-Google-Smtp-Source: AGRyM1sR93FwjbViJGfP5dn5rLVwRjQ1g+7D8EjQMN71JQGgc2lcwwP3nuRmaSozpbCcqK1lsW3+CA==
X-Received: by 2002:a05:6512:3d8b:b0:488:80d2:5960 with SMTP id k11-20020a0565123d8b00b0048880d25960mr15484745lfv.331.1658189683268;
        Mon, 18 Jul 2022 17:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:154c:b0:25d:6f75:eea with SMTP id
 y12-20020a05651c154c00b0025d6f750eeals116495ljp.8.-pod-prod-gmail; Mon, 18
 Jul 2022 17:14:42 -0700 (PDT)
X-Received: by 2002:a2e:9dd7:0:b0:25d:859f:5fa6 with SMTP id x23-20020a2e9dd7000000b0025d859f5fa6mr14563724ljj.155.1658189682617;
        Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189682; cv=none;
        d=google.com; s=arc-20160816;
        b=EyjI4f6a23GNkebV+1+6UNqDcE63AgyeFjlqy70NKsSeiJ/bV1yEn4TKCy3zzbTzKx
         jYhsVXwQ5FPKDR9Zxx0h45rn7ow7oMeqc3D5EmNwGYAsqyj2Qj+wx+th+NxLqe1wGkax
         En3x8jeJEaokJ4+9Po2qKQYLIIBCbeVWig5NKJplIkcDAVXMFV9AwTZfD/j9wHraWka7
         NeeNBq8EFJ00Z5mNbaGai5pp6LT0MeUP6bmMdoiaTvH9aVdoWDMjQneBgqXwfed2MZQ0
         Je4D3ksTV+qiOTcZZLhKNPXWezoZHfHMqNN4CkBEDzuXEHY4gj7HMUi/ht9SmQq/6M2o
         ojFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=07r2mZKCyHd2fu+4Bk2w4QXaKiSUtwJ2KOZg+LGbxK4=;
        b=P/vB0hMXnTnIblsfCcKPohJ2zqgR9vCmds4Z39K9T5ZQKA0AxwGgN2tLgC9RCYu0OB
         R0konucR3DsyimK4Bo4kxWuCtIBgmXJ+NkB7otyiDO7tC9CFNYTJRlCCHifL2qQlbxbU
         EvavaGT4rAHiPRPNOd97z6Nvn08cboGL0i8o7BxUgYlTyISx4Q4f6+0g844nEWxVe5ph
         DNnaSJjwfnU5yLIJ/TUqagL0sZT4GEhxqfYo8BoA86LDDYIK/TuyYfTfAsBi/9xkHvW6
         KNrwKS7eWP4C6e2RBw9nDLE+cnb2broJPXBmiXbWOAlkKiSTEJusXmr4zrPlQZanKyKw
         rZ6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="aTN/zjk7";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id v6-20020ac258e6000000b00489d438ad8bsi383884lfo.3.2022.07.18.17.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
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
Subject: [PATCH mm v2 28/33] kasan: rework function arguments in report.c
Date: Tue, 19 Jul 2022 02:10:08 +0200
Message-Id: <0333e02a35742ef14103440a7091b34ce437ddf3.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="aTN/zjk7";       spf=pass
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
index 763de8e68887..ec018f849992 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -213,8 +213,8 @@ static inline struct page *addr_to_page(const void *addr)
 	return NULL;
 }
 
-static void describe_object_addr(struct kmem_cache *cache, void *object,
-				const void *addr)
+static void describe_object_addr(const void *addr, struct kmem_cache *cache,
+				 void *object)
 {
 	unsigned long access_addr = (unsigned long)addr;
 	unsigned long object_addr = (unsigned long)object;
@@ -242,33 +242,32 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
@@ -296,7 +295,7 @@ static void print_address_description(void *addr, u8 tag,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0333e02a35742ef14103440a7091b34ce437ddf3.1658189199.git.andreyknvl%40google.com.
