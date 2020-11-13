Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXMLXT6QKGQE3AQ6Z6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D41F2B2811
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:03 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id b34sf3716734pgb.18
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305822; cv=pass;
        d=google.com; s=arc-20160816;
        b=nuSpVfX2UG5BZx42MFo44a0PMTTzMT8RUn/2yM9dluh0Qti9OeeIHoiU1FWSjyCOkc
         mLBPX05AP7hgV1OPfBaQpExE5JrcBa0gRVD4deMNGt7beJRVzZ5p4X6l50bSD7soqfKP
         ExssCTycKM4zLCHtLCZ5ruQMHgYMXqasvLbdb8INoknFLQYg3h0p5tZIIGkLHAtitbUj
         Rk58EV1muANqOTsWx5quH7eqQcxzI2NJc8JYT1dl8sfkOoomMtk37nBgoXF7Gx9oaR7q
         xR0G/0OUyHHjxUMtC0B0pIPw6oZ2IA+ou9f7esdk4iGhmkxFoPRuzfedug4TwB6vhe/F
         5Odw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nIMQABSGixXzgHOOG+MxoZbkpGvaTBhz7layJWXsJ4A=;
        b=DXsLR+Gz018yCsUDmIFA6xLjUrsfRnVvUGf1RAy+gy0CwoBKKkdQqOunpTQ+kQOW5D
         ffGFGteocbZkp5ZiR4F7oAU5OKV3RftKwhxPjRo5nyjmodT14Uy9nN4O7JSFdJ9QSAPo
         kmYt1UTtxlguxP/wWXBeck9F3SJIGf+KT6AW7RJ5wrxoZ5S7tHl4B+MBydOkD9zAeYfj
         T1wbS5awfxWbZikHcTDAFaZAWgU00ZxA4gt3UBZwGHjyidzM4y6iXbXr7IuN9U8usH3G
         Vh9FYSRGVgumPe0krFcOTQK44jv2STg91erVQNf1vclXtHyXRLKT8AYgIA6NJ8y3FF5h
         tLpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pUJ0TD71;
       spf=pass (google.com: domain of 33awvxwokcachukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=33AWvXwoKCacHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nIMQABSGixXzgHOOG+MxoZbkpGvaTBhz7layJWXsJ4A=;
        b=qPffMwGDp4KM6qRKxIQC8nK+UMipE/b8c8ze3WjX7ZoThJIWzZ8j1LUfgTdDYuEIdD
         vfmSXtS5mNo7fUpmLO1jEysJeO2eHxfxPAwHcZiwjWsaiEabPB/2DuoXg//P9CtbxEmd
         x3ghUE8OE1Vzmes7miyh2w8ktha998R1fVHqJnvXBgDXSBeG4zXMe+8jOEZHH12yzr/0
         HyLsBZEDaEQdsy/Roy3Dsdx6D9/1O6n6mtlKRWyYxYNn8WXR2tTRFdPnNAy2TjRy3CUP
         ujzBEB2on68/leEw8nYjrWcFaFNbt79Bg+B/ArCBPHbmyOAzq8tkq1Xn6Ade/8x5D5aB
         ZHaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nIMQABSGixXzgHOOG+MxoZbkpGvaTBhz7layJWXsJ4A=;
        b=GeIOQgBCF8Y5WXR8OeDLKTJB+j4J0FipX86pHc6iZ96Gu61mWcUWtohHMJP66GRSCi
         wKwrP5OIzFuhPaN9iEFVQorQgnEfxQ3AEUXjeoMhXWnIrXqwgsW5Gb4w2kHB7LIehf1Q
         FLHJSDIgRb1X935Yb7aVs727qUqp25wjB1TVEfRI6TT8T6sUCghkoDTUPaxtOfBF31ff
         nwiVGmE49cXPFAWW9rFw34kSSlRRCf7yi+usIdtbI+bWHITt898Qw34ma8DdHLm+IrOL
         HSBKyVgPYBQRdCO6YDkE8/RaFHG8HyMQmLZQgEKrReau9Yx8Elfu/9p3I7FsgmsBJeMl
         +iuA==
X-Gm-Message-State: AOAM531pAR08oNbAg+c6PHnna8SGyAyfB79VCX8+b51UGLgxL4nvzmP1
	NhjrdL6lq4hXsP8yC1tLYcs=
X-Google-Smtp-Source: ABdhPJyg0GLV4LzFF6zyVf9HmbuyI3Wq8CDS5Ne6ZzKs6IGgzfgKH1i/M1lHsqDXEMV9WQq3+MYt5Q==
X-Received: by 2002:a17:90a:c381:: with SMTP id h1mr5397038pjt.2.1605305821896;
        Fri, 13 Nov 2020 14:17:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:989e:: with SMTP id r30ls538951pfl.2.gmail; Fri, 13 Nov
 2020 14:17:01 -0800 (PST)
X-Received: by 2002:aa7:9699:0:b029:18a:e057:c44 with SMTP id f25-20020aa796990000b029018ae0570c44mr3809227pfk.34.1605305821393;
        Fri, 13 Nov 2020 14:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305821; cv=none;
        d=google.com; s=arc-20160816;
        b=OviDfW/8QUHbhMXJJvJDqOJ3OLr1IY+ZIyHHVUWyuGAmgJwP6No6Hxf+1Pvjrvmyxx
         Ab49MuocWZ6O3KzhiDQh85SxsMQH1cxuf+iiQ0q2SOnWU4T+2gNoQDGkQv8vibLQ7iAp
         TLOpXKhURcHz4S93Gcr9JfJKlDBTXYaLKQsX97+AUCl8mYDqHIjVzLX0EPesMAVset/9
         KRIqHeL6N+v7x7SfLGpBuI6FibrkhIq/I7jSy3awaatNnXphXV3yCUV+YXxTU0cm2GLP
         G4tZAXUzGgs65IUHM2eQ86LaT3YSxw0h/El66l3r0WLHCQeS12MHd05wnVSFwSoezXSA
         ky0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nOCTDQ2//vgboByM6FE0MupdQKKhq84DcRt/L5d/bIU=;
        b=0pIflbCpivI1Zj/Bp3HLnzgB/7u1LNSK0UVyoxekgn+fpRYTQKpb/tnSF5joh2Jtw0
         K/W3wclxBL9fk1E5lbH/+8Pt81SEIsTaqtHIqbE+s7gkyCReCRwLmQvTnt7lz3v8pTfJ
         kDu8VNskRiZHR8rnoyXj1TQQeeU/hgbUY63CVPQbcIs6xsYpfOpjO4XNIST/LViKNUkw
         9fUL0CR9lnItz3WbrjIUeuf+DYSPaCDVvqsrWVgofy3wG1uLVl8KcRi4ZW/dhsdMtj5E
         lCcpgXSgHE2RqMPFdyRzimfvzrutD+DDT3cwXWxe48RgkJ/xWrkjrV5vy+b6DxEQwDmd
         gHvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pUJ0TD71;
       spf=pass (google.com: domain of 33awvxwokcachukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=33AWvXwoKCacHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id ne10si1372897pjb.0.2020.11.13.14.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 33awvxwokcachukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s3so7029255qve.13
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c2ce:: with SMTP id
 c14mr4724618qvi.20.1605305820567; Fri, 13 Nov 2020 14:17:00 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:47 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <4bc8a39b683988a2c672a0d99df12eee1e3c85cd.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 19/42] kasan: rename print_shadow_for_address to print_memory_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pUJ0TD71;       spf=pass
 (google.com: domain of 33awvxwokcachukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=33AWvXwoKCacHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2990ca34abaf..5d5733831ad7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -252,7 +252,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -338,7 +338,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -379,7 +379,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bc8a39b683988a2c672a0d99df12eee1e3c85cd.1605305705.git.andreyknvl%40google.com.
