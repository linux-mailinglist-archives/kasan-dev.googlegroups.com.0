Return-Path: <kasan-dev+bncBDQ27FVWWUFRBL7AUHVQKGQEXQZYBLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B2A68A2B7D
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 02:39:12 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id t19sf2951124pgh.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 17:39:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567125551; cv=pass;
        d=google.com; s=arc-20160816;
        b=WJp9G8KwwqDPdBO9MsDBwokP2do0YfhDXVjBseHuJS8s3Trn5gIR3e9WzfvRF2QJUB
         1tBiuYEu+8U3CEin4CQoKLE94N6oAUiK2A5TngzgM/z4V/z4AAM6QPxZk89K5/TLni90
         JxWEAFAFa/4/C817UF9a/ooMUFQXI+SWbmOjq5BYV8VNC8hb/neG9coi5bLM2u5A/AZr
         MBkurhK9hMd6IiI2st/jRlU+KmsnxDcp/K378TtuNqowqfP9ZkfDi1PxUN831dMxHiRy
         EtVBa6us9b3XNDxtZO1wKmOzalMEE5PyxbkFiUV9WIiNy7Q/VenYySJq7KHm/IihLqWa
         v8vA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p6RTyi/RN0Ui532ZXhGoZa4fGOwnvpJRG/qaVpWWNc8=;
        b=bTrgXnvDRBIWk+KfInf1S3ErH560nHvoosTtW/yFB8fGzn0kwDVdaWvhPLnxJaL9FN
         2XZZSPTTYKOwus56FGT2jfQyAjeteTh7o5BHGOt4b4A1afv27gZz6J+UhPI9UDDLwbk7
         1BWeIz3wls4fKSo+j53yx/qcKppM3JuYreC4GajH1jZ0YK8W5z11lBTtAFJsR3tdVhvJ
         0Jj6Q5il/AztDwrPVdKIh9CH598tR7QBannKQye2qTUtbkxRkDxUon3W3UDqueAGglX3
         0bMK1kbDCY8aVfMzwetXDQ33yMPBjgWgzrcQc0X7LA+3yzerSvJW171f4vXXEQfkQZ6p
         5Y5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rC80CM3v;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p6RTyi/RN0Ui532ZXhGoZa4fGOwnvpJRG/qaVpWWNc8=;
        b=BxFMI+XcZd3LC8LmcNb6UU4XxFTtYXI0SguLZgAVdRewAMsniiPu6q2oH5iEixPqJi
         48WVMm91ue88h+XkzJT8v/uF+LFkDZwcw+HqUaAFcuQHezje6ZHRs1J1WKElx2HZHVsa
         Oy6OnvNqxrn2Iv7kKmWtKZ+pNqFBVYiMuli2zms8nSygNjw0zy8CddS59c5zJPyLieWo
         LCEe4IBb2OUeTZKbcBdsfRyQ4hon/vIMY45ol2QpkRtn2/4rqUHYbXvHfCIbTWIfdoTH
         rnfiBuI42dDi170ozTB8d3fLt/6tNGDmQw5MzWeSJ1khxdcNfCY9OxI9FoyHHBD12XkD
         skeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p6RTyi/RN0Ui532ZXhGoZa4fGOwnvpJRG/qaVpWWNc8=;
        b=KXUSoNDqlJ9yRnjweaIGutHIKWQVyO/nGjqDz9a7yM2uBan2aJTDJcOXSQkbfFibvc
         XIIFdxRBKsTa9SEhmSM/iFFn3BfHJgB++9/K5HxMoGid5FNx2fNfc8IIWlSH+CYnahDg
         gWUTVFNMCYpdaRWAFayzmAvqEbYc0kDS4D3Agc++ZRW4hKfJdmHiXzbDCawCjqSUn5E5
         CLIqeN5qnBj9kiKClpsbvZ7AJXfdtE3fK+cJqwwwgTjjVHywTt+j+08ZpRHwuylJQ9/k
         gGhJHtqIKAIgstuH0WlRL8rFxUfS8G2U6pv8B0wPPtOPo/bsU9/+s/ljSeRywRmXW//f
         /7UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTIlst6i3b6qyAEthvtpUlOvJoktevAqTK84fbVkf/sYap78R8
	8BQBT5j9O2sB55ShAlCD+B8=
X-Google-Smtp-Source: APXvYqx8aJM5gUbRYuBsIvVZsZb3yFh9E38fQaRHmV26vdJ1K9nasBkUp/EG0Qi56nnMz5Ttzcs3Bw==
X-Received: by 2002:aa7:8488:: with SMTP id u8mr15201238pfn.229.1567125551148;
        Thu, 29 Aug 2019 17:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6452:: with SMTP id s18ls919030pgv.2.gmail; Thu, 29 Aug
 2019 17:39:10 -0700 (PDT)
X-Received: by 2002:a63:460c:: with SMTP id t12mr10668834pga.69.1567125550787;
        Thu, 29 Aug 2019 17:39:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567125550; cv=none;
        d=google.com; s=arc-20160816;
        b=kj8dteyOji0o3bdB4SMKRILzJ83McCMroUfPZPBM7oqZCIUoBfeKC0nmAfErIdzban
         8plXaS2Rv28gPJtSFCWpOG/nb5TiUrRggBcywycbBJ6rt6zaIGDKFnO1xkjGBHTAiVWN
         pg2BS+0QGnEtNvwKL+GXZK0hlu6xLnRqv92NBl4tP8o5MFXI2tMYFqABR7I7k5qM2nyj
         EoACGONE2/9LV6h1pGfkYkLUWYijKBLx0Nt9G4uZ3VUOFm/K0yTeblzjFORvyKn5KdzF
         EqvgDpQNkTL8T14P/nTpQuiecL/u9fqkrPz9ByBIr2VA/nhOZIq/B6mmOxrE5jBsJo5H
         Jaew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNDV9DT7O32N2h9l7CrACdWJSzNVfR3Dv9pnUT55kOg=;
        b=0NuW1IZNwU6NuUQFaQgKzeTDZGGDuM1DbSBHy9s4f4us975pCzSnTfLMC9XQq0Zlxv
         DKcwt1B5MHG0+FWUCN0jNmsnTvWGUzF3YX8b8G3yv/PWa7RE2+8C++pKSOLkqBKqdfyh
         bIhCYkUnD8BvcZ9CgtXMiBJJ6GS6tzKmZVmmblAbntX4GMOCitxuAP8Cd5rR2Os5YTyl
         juqFV4Kp0DCz1NNhX+M227Z0txaLKvVTXtgV5Bu/c1+qw4hqqg8c70n/qSlu7aGsuaTA
         7o2bL1zQPfKxtRgmpQ0HPX5Rz8kmKWQfdqLQ28zUFN0CiKKkSwvOdtx1bJb1zn0Whmkq
         Gaxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rC80CM3v;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id q2si210160pgq.3.2019.08.29.17.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 17:39:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id a67so39069pfa.6
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 17:39:10 -0700 (PDT)
X-Received: by 2002:a63:a66:: with SMTP id z38mr11066655pgk.247.1567125550257;
        Thu, 29 Aug 2019 17:39:10 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i4sm2211255pfd.168.2019.08.29.17.39.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 17:39:09 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v5 2/5] kasan: add test for vmalloc
Date: Fri, 30 Aug 2019 10:38:18 +1000
Message-Id: <20190830003821.10737-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190830003821.10737-1-dja@axtens.net>
References: <20190830003821.10737-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=rC80CM3v;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Test kasan vmalloc support by adding a new test to the module.

Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v5: split out per Christophe Leroy
---
 lib/test_kasan.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..328d33beae36 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
 
 #include <asm/page.h>
 
@@ -748,6 +749,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -793,6 +818,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190830003821.10737-3-dja%40axtens.net.
