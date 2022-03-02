Return-Path: <kasan-dev+bncBAABBIF272IAMGQEX2NJIIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E0FD94CAA6C
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:48 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id o21-20020a05600c511500b003818c4b98b5sf709595wms.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239008; cv=pass;
        d=google.com; s=arc-20160816;
        b=HqPRZgirWyquU+aTFVhw/GqjjEYVX1RdgVRYUdrY3nbS1rtf77YDSU+FsU4d/pr89f
         2jbwqANNaEgGIjeplg0/8/fYPa9XTP8P8F3VIunm0YjsOY6gUr5M9ICJGPu58AImk207
         xt9SY/djVPhRIxRhmEdfzza9jvK/3n46fgt/d4mW0kdD/cgW7uTrM0h7+GgFyONN6yfv
         0zvdiEA1gV4iQrt+y9Cs//n2YOsLQLN9goRkz32M6Bn6wVTjNQaYikoPrhybxypRkth/
         36c0/dFtjvEicKws2xa8ynt3MZTZNYG8Pe93PaQCRi1wHcrGSiNQPswrpVqiyWVaEuVE
         q48Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Jvj3MGtZvyDYHwXt9Sm5SHOOZkO8ZauVNKaaxGqdb3c=;
        b=qHSrW3dL8XA9IGl2rodRy1Q0xhnFUEWCltmGHU8GfcJ8Hcl0wpKpQ3BvC92cgFDFG8
         +4t0hqCTIcsOFczwLg4/5B0HZxQ73SqNEQMrC+a0AErc+VMIFQjWi9CHlVeWym1+yp5H
         MLV7SZSppeQK9A2Ts+oMb2Gsc6Vr4Y9GkRK8uWAWQ4ENPAVkbSJ0m/MHMVPMld+9JHMq
         YDbJVe0E6N35MbKu6TSM8mK44J5dI//tQeEPJUJjPgnlpGDZDCsARnuJnzEW2aEYfpSu
         p3Jv1rlKUR7C4DRaOp4bvrDnD/nAfaoeWogU0Ybhh0vIsTYQIMx388vdoWuhMv3AR5vm
         h9ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CkSxgq2C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jvj3MGtZvyDYHwXt9Sm5SHOOZkO8ZauVNKaaxGqdb3c=;
        b=S0jW7zGEbi8M137ImegtvDS4+vf8P0y3u2+Xt5/8+UL0U7dLYXJyj1Bcd0BYBZ0flC
         8z8ieXNdDw/gkVUjNnA/Kp6szVUdBVOBFcGa6tYSI+vLZjzj/7BeY6uTUFOeIWrPzOK6
         jgo8U3QR9iJatp1qV3glxL/I/RBAmy/J7qirXfVdxuQTeIg06G+4tSwj2H+o6FDjzVYW
         ErwzBTcgi8ojJUBJEY13adGJEfRoRb0lZgLv0iBtajiEEZmHaD8MlRxrYGQ9ic8ntdJY
         kxq74WJROUwLeKBtcc3bHidBn8yiHID9yX1iZ0ptWvanNkj+5r4o4rIkrhDhL6OiAhyW
         Rbiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jvj3MGtZvyDYHwXt9Sm5SHOOZkO8ZauVNKaaxGqdb3c=;
        b=2DX4c9HPCRkL8+7IbRnopLqC62h62d3M/2dihSwrmYmda0+vN6wGIEdRU3lz5K0zUC
         3SXdLnsGD+27tGfwfB0bknWcGvoHDnvJ0qNv2UgQDwCNLKTKddbDbt97N+YlmG2MxY1y
         ndS/Is8SZwWe35Y1EcHk5Son7xpb7CEtnommgkajK60S7E1+PtEY+UmUGeRX6tSbWUpa
         Uq2xHCzykohaDUg5EeDcmjimGXh36lKIHFYe25A1ExITunjfyXvo5Ai1U9yhqrEdP+i5
         GKyCmGoIsvcF5ZUsn/q2VC7+CQIhKJpMOyWCuJf+wOd6SRlxATzmHpZs+bCXiQ2k9Yf0
         5tVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316itmifmgcfHzccxPeLIvKXbggKh/uM4pztVTu44zp0Hv9rCIm
	awFXfurkA8wnZfvDSOcCq64=
X-Google-Smtp-Source: ABdhPJx/+XfB0j+XweC4isA+I+kCiiAMWCiWVJwAhXmJiLyMBwttQ1j0ha8pPjVkl8KrJDjuddtjIw==
X-Received: by 2002:adf:f6cf:0:b0:1ea:974c:5872 with SMTP id y15-20020adff6cf000000b001ea974c5872mr23951545wrp.137.1646239008539;
        Wed, 02 Mar 2022 08:36:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls696124wrc.1.gmail;
 Wed, 02 Mar 2022 08:36:47 -0800 (PST)
X-Received: by 2002:a5d:5981:0:b0:1ef:8304:d9c1 with SMTP id n1-20020a5d5981000000b001ef8304d9c1mr16061189wri.43.1646239007848;
        Wed, 02 Mar 2022 08:36:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239007; cv=none;
        d=google.com; s=arc-20160816;
        b=S41hZNSrTF4QXLqi9HOkO51nAQGvZ94gw17UyYi4OjiDK18bpU/SHsgfuXqNsWO5NE
         MfLDR1NtUCKwE+LDJwRXMm5n5XD5KkPpWYfCwF9P58no5U/Yu36AqX8KdiOwBu39NSxJ
         gJtb7PXxMoAVsu+/WreglzHOmVSqj2o7MWg5YkVVUo8vHB6yvK2Nogsu9mzoh74TbRzE
         el/2kEUNbJk41aDxp8xAZX6B7TQz+i6HvmIig9a3+B0yXopnSPfLMV9FhNo9DIsGzvgQ
         GlgCyucqlgEIauv+ySZ9cBLlyDITYNfZ7zNckbj3Ks4/K0t5Izby5YRVfi409BWNa/5m
         JZ3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ReVQg90bpO6aQ9p1E17mGNBQrTUFi/5PZoBeBo27NeE=;
        b=C2JnIK7nRJB/8JtlgVA3Tfu/WhGa1aksszhnVz12oCPCv7XdeQNqnRl11Z9EoeNJKN
         E99aU4osyzXQqtPX6gpbzX3BTvWEsd624Gzvuxtj4xZj8YvtKrjwtkuqHqCkFNuzUOyH
         HccJicq6qQpKyKSHEJGNzVYGpgnfRulyf/mIkhSR/I2swPdQ1wSvJxpUZSLviFk0UuZW
         TW2srihSFPSpfGiW+z9xJrWMnEwTrQDr482jFFBTu2181RE/Bi+ygXxhAlHwoV3B4s5q
         uR3y53iKaKAYQ/vJ9na4Dytwe5ZJsHFT8FqTmrF2NI6JJJN4UQsWZtmOFvnvv9twp1Z9
         sPcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CkSxgq2C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id 8-20020a1c0208000000b0037bc4b90d17si456798wmc.3.2022.03.02.08.36.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 02/22] kasan: more line breaks in reports
Date: Wed,  2 Mar 2022 17:36:22 +0100
Message-Id: <8682c4558e533cd0f99bdb964ce2fe741f2a9212.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CkSxgq2C;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a line break after each part that describes the buggy address.
Improves readability of reports.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 607a8c2e4674..ded648c0a0e4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -250,11 +250,13 @@ static void print_address_description(void *addr, u8 tag)
 		void *object = nearest_obj(cache, slab,	addr);
 
 		describe_object(cache, object, addr, tag);
+		pr_err("\n");
 	}
 
 	if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
 		pr_err("The buggy address belongs to the variable:\n");
 		pr_err(" %pS\n", addr);
+		pr_err("\n");
 	}
 
 	if (is_vmalloc_addr(addr)) {
@@ -265,6 +267,7 @@ static void print_address_description(void *addr, u8 tag)
 			       " [%px, %px) created by:\n"
 			       " %pS\n",
 			       va->addr, va->addr + va->size, va->caller);
+			pr_err("\n");
 
 			page = vmalloc_to_page(page);
 		}
@@ -273,9 +276,11 @@ static void print_address_description(void *addr, u8 tag)
 	if (page) {
 		pr_err("The buggy address belongs to the physical page:\n");
 		dump_page(page, "kasan: bad access detected");
+		pr_err("\n");
 	}
 
 	kasan_print_address_stack_frame(addr);
+	pr_err("\n");
 }
 
 static bool meta_row_is_guilty(const void *row, const void *addr)
@@ -382,7 +387,6 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	kasan_print_tags(tag, object);
 	pr_err("\n");
 	print_address_description(object, tag);
-	pr_err("\n");
 	print_memory_metadata(object);
 	end_report(&flags, (unsigned long)object);
 }
@@ -443,7 +447,6 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
-		pr_err("\n");
 		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8682c4558e533cd0f99bdb964ce2fe741f2a9212.1646237226.git.andreyknvl%40google.com.
