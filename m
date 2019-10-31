Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTOX5LWQKGQEYUACVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A4FBEACA2
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 10:39:27 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id x17sf4675489ill.7
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 02:39:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572514766; cv=pass;
        d=google.com; s=arc-20160816;
        b=fffkyZFgHwdDpAiCOKkJiTLanh6N9R0XW7Yj6Pcw0Sqqvb/oSOyXTugmGjCis5XewA
         Qd3v2ctKz/bmn7cSfmHqaiQOweXjg/rwQhOHkdLGL3mYIA9LpZT6ynucsGQwmw10vpb2
         a1aytvzepEzsO0L2ZP4GdaABs5xOwCJuEEznyJItIGn9R4Fy8JQe09vzZ3ZF5o/y8mzm
         efV/ZxYxpn+A/W/wzWuHanLkmi/91JYq5pzzBNxZq48KqeOll5YlSM4kqHLZ75tGr97L
         BJmtZA0N/hQcgNewJkO7h3dZ00CkvgoIa8FvjxKsQaXVw9mVu/MVaJUlMqN9JX1wWDks
         2cXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dv7lYF4hmHjwdNdqglHv+84FIhPSWJ7FyngXtEoLtq4=;
        b=CRDJUJu66vx0pMkr1yYMei7IL5UiVxEEDOGd5bii5fc0lze6Ge0KRJN8FmoT7Z7zwy
         XJuXCrAYGjyiJS/75YVKkz2b2XVBWUycJ+IF+XXQahn8Pqj+ghHkS/IXkOaW92KyKlNL
         V0eLUr0BfRu9eCbR5EaSq8mQKqo2wQSHKTzgorkWb8ykoykZe8YZgzC99MmvGfta+kMd
         kFgiT5cgaABS/Tdoz9sg1SleaIXJcTP4Al6j8gOBfcis0/ahL3TlXSgLZpT6HJy4kBN8
         OYAu3jwhOHaZkG45oyCkuLU+evgsNl9dGVWrI3pzjZihXhQWtSdLaKS6BOwArgYMBjXS
         Ur7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=WNnsrZjR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dv7lYF4hmHjwdNdqglHv+84FIhPSWJ7FyngXtEoLtq4=;
        b=rt1vxXaIHNo3blLckKmlVeuZ6MvaI62jnfYia0T80gXz1LmsrT2O9NlSMB7yzGsdq7
         YGEM7GAnoCInq5j0qrQBo22OmlQYZhuU29BDMuG7byhQaIX9G2HpKiMJbVVbrddM+AMs
         jX8vAJm1k0cSWSjDA4Hv253Y1y4LwaqtoZfy11xPXXhYBoxOhcAdq99PY7ZI09JTuMx+
         UKhKtCxptEPKQBsnVZUJ2M9WU2KYl6vK0sjU1xtWAMaUjlcP9IAQl+Hq7c5JIDb+jtKW
         yeJ2jlD7hQvlFOerbfOFW1yOb3+Dp7QJSB6AQ/8MwHOCrG3ztwmI4d3msg3LU7BWfqzg
         XN1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dv7lYF4hmHjwdNdqglHv+84FIhPSWJ7FyngXtEoLtq4=;
        b=rJF7G8tZ1c5Jb/Skem516rAYUMBqaGYqzTF81zN+wfoesIda+dsIOnx1yoNd8mhyHr
         WggBMoJEPo5hCJRUDDQcCHgbGas5KRpCH2LFAP56jsyzCbHPZl2K65307o2A8VYli4K2
         xrpftiVfD+tH4Fo26foIV7TfYD2U2XO8sk4md6Zl+7r3SUIzfYk43hSb7JXkHBH6otmT
         BK3atThdBhF7qhnJptpRmSARRcGHWBUEgopApQmvhvUVxwGYoTYohDXy1+I321a3GB+1
         Gmqwowy3+9lrBSPGoskrFWgq7LdC2IzgxXi5WOLPz44oj0pTi/yT8G2XNCrb5jWP/i5/
         bYoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXpD0pJxX5vIxbrJxZGn7XbTUWmRQV5LsrwIqvgVi/CsKQD99i/
	dZE9IHFsF4VSm50TgvQHPQc=
X-Google-Smtp-Source: APXvYqzoGrFkZ5rrDw+Q3DxI0IPdZpA3L/YHwkcYeXad/QZ9L1rdqRhaJCimdISlOr+T6IdoKK1qFA==
X-Received: by 2002:a05:6638:73a:: with SMTP id j26mr50991jad.116.1572514765868;
        Thu, 31 Oct 2019 02:39:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8149:: with SMTP id e70ls457078ild.7.gmail; Thu, 31 Oct
 2019 02:39:25 -0700 (PDT)
X-Received: by 2002:a92:ce4d:: with SMTP id a13mr5506886ilr.46.1572514765483;
        Thu, 31 Oct 2019 02:39:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572514765; cv=none;
        d=google.com; s=arc-20160816;
        b=e0PiHCgUMSFJ7KtpDIUV/FgQSv9UzdYnTcrnBLMa4wcl2DxL5G6p5sW8nmbu6Qed/1
         Gi0XHYD3fLBQ6uArm15ad31iICvfrKguHvuYqfJNQxQvkaqheyanRiBsR7uAk1U2tkS0
         NC7Sg5iHdOxbEesAzGEDYRUpoPGayBu6EI5hIOfT7f1hd5eKpNm7BFBxXP58kRdPJNXu
         hq1HN/Awnx+tbKi6sQ0DPnvJPQcChQVRqBkIQsFZ92kj27u5lj4Kyv9LDGXL50KBNtLP
         zvsJSvYykdotK4O/GJQM4uZ2f0+/MeUTxWT/Ugt8euzSoUJLX7GC2GFuSXO/gGue35QE
         Zexg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bVXjkvYDDmbnxsC38vuCWt+2DP5YT7XnHdrJpHAvWR8=;
        b=aqXbyGm6v5HpfRCzjfi4gwgxry5wZOUy/KvjI+Pa0UwkMfX+S88UwfXR7Rssvj4dcv
         g76xn+IwAIj8XmBMJNBKOAioD/2gLuDhkqx66L/AYPBxt6vOei4lF14LKviDdr3ZE7WT
         G1lHWa96T7c0g7mveBmRx0A6VV6S0i7p9sdHenkkrKnYHIUp8MkBMxjhD0Q3xI4nuFFd
         tbXAueIq3gYi7wZwKs2X3IfwVxk1rLTVL66NaJ9sht/avdJnyOsOVBhi5KTpaoXqF9wD
         L4jF9nlqAVgImXbvh/QN1rLWAe4S1r10QNf87X6GuAYHBtAWyYJBDNIqEyiGu8k92u63
         sojw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=WNnsrZjR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id t64si236000ill.0.2019.10.31.02.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2019 02:39:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id u9so3991080pfn.4
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2019 02:39:25 -0700 (PDT)
X-Received: by 2002:a17:90a:1f4b:: with SMTP id y11mr5863515pjy.123.1572514764668;
        Thu, 31 Oct 2019 02:39:24 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id n15sm2785042pfq.146.2019.10.31.02.39.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2019 02:39:23 -0700 (PDT)
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
Subject: [PATCH v11 2/4] kasan: add test for vmalloc
Date: Thu, 31 Oct 2019 20:39:07 +1100
Message-Id: <20191031093909.9228-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191031093909.9228-1-dja@axtens.net>
References: <20191031093909.9228-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=WNnsrZjR;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191031093909.9228-3-dja%40axtens.net.
