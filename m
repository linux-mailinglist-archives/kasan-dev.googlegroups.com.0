Return-Path: <kasan-dev+bncBAABBIN272IAMGQEUQK7NBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDC944CAA6E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:49 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id bq19-20020a056402215300b0040f276105a4sf1317149edb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239009; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJGoRwt+/qcLUgYTUUdSTkHHeSD/5CtMZ5VVS4dLZvNAg2XG5cKEfpTn8QT6Q618/V
         +jqIyHnn9M3mX6tmQFjpNT9CZqomJimQiOoRCXxJ9X5Wgez/1Cfq8ry9SkX1dLD8/4vD
         zH7N7oTOJAE2jrxdu/dcYisyu+bq7NuE060FUnHFj9DQD4lRfwMmBiCmzK/MzU4FnTBr
         CFpt0cI5B4q3Fa6L7qeE/0YX95QsRvKFdZKYlBpSRGBCNiaKiXTihOPofib0Yks4LLPd
         osX9dsuB3QTWyDj1Avi1WglBzu1lz3bQTPl1C4fy8JjWVvUZZ3ztXVCdVYq5Cr5Gc6GM
         ouvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ICKWbw+XHJahlzkwjPsdzUW3LELsBWX3/BwiVV6ZOMI=;
        b=TYwO5nhbkNHx3LSzKNZ/TcBzN02+R/+tJ9BQqvOsGcV8U1skXcEt/U7lknEDq7+I5a
         dPqYJMXHC/m7aa58iR0J9lJDjdUmfQVj+hK68kDQk13lZI5w4jfd0LQFliY/n7iYOLQG
         qKOj0CcjaN+bD/KdS6P7wutMlPbOPwFsDAXOrO4UNblLRI0qUvKkjJdLcDkOq2lpS1nh
         n08fqe5UMXE3GofhmZyvv5andjSYNqXne3ImUWKxq38D9ttmtGRCyxGBR23tnNUz73pn
         XNyvSRnhL6mZv0dUl77nDIP6H2dXeAnRr5f7pT++HSJzS1C22EOhA2jxJoNb+v6FQOh2
         QspA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dv6ARQEL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ICKWbw+XHJahlzkwjPsdzUW3LELsBWX3/BwiVV6ZOMI=;
        b=niL39O/4Ml+tti39Huu41xpg69g7kuUndJZ1EB+NF+d3z2l3cakzFQfRu1COHuhl+P
         iDsp+DZ/25XSxBQAB2+2ilVIsiK9pUGV87nzOvstu+pn9YS3hNZyPiG+l5X6Pc6lotwb
         kPdg2A5oEw6cjYB6/rHp3LCDbYK8m7allxlGmp8/vCRsR3pHmuMR59JeI/7tQLVgKFVF
         L939HYHqh66IwKEFaUjVr6eW9tHGlNEL2P1Wiox0nrHiCxecRCz9wEsbAS/epjkjjO5H
         voo8+dDHOsODiV0eUajdG/cF7cxCBPwG+rnYRgTpJ3eMt7C4+cRM7u//1UcFTduS+lg2
         cZRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ICKWbw+XHJahlzkwjPsdzUW3LELsBWX3/BwiVV6ZOMI=;
        b=dqsRsei3vVLZONDKqK0c2xJuJY3X1YMTuclrBz9AkcwO9XJLbx4VOkUuXNA+fZ9G3r
         aJygAtsAcOxrCzKUUuYJdRWpJMDjVk3fI68xm38grfNS6L5v6KJjvT+qRI2RhFoj+xEh
         QRF6cXw7TT/TfiaLSI5fazhXBRuqVUycGRKfEqzBcGKYKDSTOpWr88kFb4kwdknTiHcO
         0cjzecpFCMHdOyIOeAqbcFfhVztjrIMZ3CuqSZ7NW1ZHTOHf/GXy0TSBe8eZ2X6ZfnHp
         5mLrWnqCEDlp9+yEgXiuX5TELJvYg+fz2en9EDKQ9INUYya+CJfLG0fp3x99fG7Ggp46
         FFug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xc487OJ449Onc4MLzeLgjbqtg70eUbGdmcPq0hZxGEwD9b6u7
	cfQ0KKfB263PhaUvymf7ZgI=
X-Google-Smtp-Source: ABdhPJy6wyOb/ZvlewfASaqysoa4MSdyYo7GZxbdpcmlO3QsmzFN7t85+NQZi4ou5ZBFDCUk+s/K/g==
X-Received: by 2002:a17:907:98a5:b0:6ce:8c66:e75e with SMTP id ju5-20020a17090798a500b006ce8c66e75emr24872341ejc.239.1646239009473;
        Wed, 02 Mar 2022 08:36:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d1cf:0:b0:403:768d:84b2 with SMTP id g15-20020aa7d1cf000000b00403768d84b2ls2642532edp.1.gmail;
 Wed, 02 Mar 2022 08:36:48 -0800 (PST)
X-Received: by 2002:a05:6402:3507:b0:413:523:5d24 with SMTP id b7-20020a056402350700b0041305235d24mr29889327edd.85.1646239008634;
        Wed, 02 Mar 2022 08:36:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239008; cv=none;
        d=google.com; s=arc-20160816;
        b=kqxANb0gT4LNEkX59FVp6T002BNKI2AE4qrJv1YLa/CcjQ0hb+xKtfeUQotjLb6jCW
         urVcYOpHUxL9BUjEhVhW6MPiyFely7Quc9gbWe+So2a23st2xQcWdoOLE5LkK3jrXVHI
         ZrlKwbs3AkIl9YjzuoJYpIT5WrbLwYAWe3C8OLZVaMqLsli0xTWTF3R9W2EOFWfUP54P
         fD1uC6Ge2eeSTuNw+6/J9Ys3pqTQYf3q/rX7wRTyfPFfE4q5pfxJgXP7ckIG1dXNSLMI
         dKZDveAuwSa7+8ZkFrqoCAlQBIOQO6x7vzWm2HeLwtvk3a6Tk+zv0ANx4TJ28afqTgql
         0fww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/PNbeFwa0AFDpaFm8soBx+srw+6LkE/5medj0Pnuzw0=;
        b=y00Edo+X2hJacjNISXPtsD0IZBrEMLa7XN2qi8p3eX2kWDW1MImK4RDnLUCFOihbIj
         T4aLaFY2EP1FQpMu5ixKnS9cBrLraKnmWq8mT9bUEpGk9r3KuEXhloSYHRLUOP8fM3vc
         nV2eaESoHFuzqVl10isVuSdndeQSw3ceE3hyIUFqTXsGh78xuvfwN4fmnT+QOjE3MhFC
         cm1K6dzeHjS4etyBh7XXe9rgokgsPTX/r1Gt3cOnVjYwH2rF+7tFF10xcDOGpgou01hn
         NoA3x/f+MTfQCVm0rT6yMIwoX5KpfhpJvZEg3bppuJSVdCAXjAH/FwRmWubuEt5Z446U
         WG1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dv6ARQEL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id et1-20020a170907294100b006ce69d31a32si1206222ejc.2.2022.03.02.08.36.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:48 -0800 (PST)
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
Subject: [PATCH mm 03/22] kasan: rearrange stack frame info in reports
Date: Wed,  2 Mar 2022 17:36:23 +0100
Message-Id: <1ee113a4c111df97d168c820b527cda77a3cac40.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dv6ARQEL;       spf=pass
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

- Move printing stack frame info before printing page info.

- Add object_is_on_stack() check to print_address_description()
  and add a corresponding WARNING to kasan_print_address_stack_frame().
  This looks more in line with the rest of the checks in this function
  and also allows to avoid complicating code logic wrt line breaks.

- Clean up comments related to get_address_stack_frame_info().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c         | 12 +++++++++---
 mm/kasan/report_generic.c | 15 ++++-----------
 2 files changed, 13 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ded648c0a0e4..d60ee8b81e2b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -259,6 +259,15 @@ static void print_address_description(void *addr, u8 tag)
 		pr_err("\n");
 	}
 
+	if (object_is_on_stack(addr)) {
+		/*
+		 * Currently, KASAN supports printing frame information only
+		 * for accesses to the task's own stack.
+		 */
+		kasan_print_address_stack_frame(addr);
+		pr_err("\n");
+	}
+
 	if (is_vmalloc_addr(addr)) {
 		struct vm_struct *va = find_vm_area(addr);
 
@@ -278,9 +287,6 @@ static void print_address_description(void *addr, u8 tag)
 		dump_page(page, "kasan: bad access detected");
 		pr_err("\n");
 	}
-
-	kasan_print_address_stack_frame(addr);
-	pr_err("\n");
 }
 
 static bool meta_row_is_guilty(const void *row, const void *addr)
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 139615ef326b..3751391ff11a 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -211,6 +211,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
 	}
 }
 
+/* Returns true only if the address is on the current task's stack. */
 static bool __must_check get_address_stack_frame_info(const void *addr,
 						      unsigned long *offset,
 						      const char **frame_descr,
@@ -224,13 +225,6 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
 
 	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
 
-	/*
-	 * NOTE: We currently only support printing frame information for
-	 * accesses to the task's own stack.
-	 */
-	if (!object_is_on_stack(addr))
-		return false;
-
 	aligned_addr = round_down((unsigned long)addr, sizeof(long));
 	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
 	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
@@ -269,14 +263,13 @@ void kasan_print_address_stack_frame(const void *addr)
 	const char *frame_descr;
 	const void *frame_pc;
 
+	if (WARN_ON(!object_is_on_stack(addr)))
+		return;
+
 	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
 					  &frame_pc))
 		return;
 
-	/*
-	 * get_address_stack_frame_info only returns true if the given addr is
-	 * on the current task's stack.
-	 */
 	pr_err("\n");
 	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
 	       addr, current->comm, task_pid_nr(current), offset);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ee113a4c111df97d168c820b527cda77a3cac40.1646237226.git.andreyknvl%40google.com.
