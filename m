Return-Path: <kasan-dev+bncBAABBSGG2CEAMGQEURIB4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 149E63E98A0
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:45 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id r16-20020a2e97100000b02901b398e1cd20sf1115301lji.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709704; cv=pass;
        d=google.com; s=arc-20160816;
        b=uQl9UiBg2lgrDg9fNXT2A+GwV3gQu9O3EDWXY55U9HAW6m9LEgOncMO7dnTWU5E+YI
         LP6zNzJBpWcSePY4iMxXZycWDryhi+KdSYr3Yj+CjbvrEtXbugiZZy3gA84qGPSeMNI9
         TIfhcLiHFwc3BB12tZrYNqWv22sO+jc0NKhrfV7jUPefNs8HtnkS+JfaNwghA7KHFiIP
         nxq6NITeSH+d6Xx5tJWAwJtBu5G2BYQa+/CHdGnOJz+i5lvA9Uqub7Oh9Fe3WdEW3EhU
         nXtwK3NhgTD68suChtQTdvTZTHqBbQL31cwu2IZu1FF7WqKtdfSWJv+VTQX+zYEJokN6
         Bupw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IbAiGYnHFmTXdCsPSepXw7NAXgwi+V4OGerHCgcsNts=;
        b=BxnXoCmaZRUOH6eCxcjwAIe61vAK11IzLq1pHVJMZhbGzK5vSl9zuC58grdTgO7hrT
         sGEb2aodYaWcbW7D4RjaFQtkpws0PRR2i9heAcziMnp9amRuQkgWqlyo/jPK1d16hg19
         fN657a/+0Q6b9xF5IaG2K5rNSklevqrT+HXrQMOvONG2ilFDrixGgZseVHGmvVc8WpnL
         7LT9du64OIQ9vufDSYtegJZp0ZdV+qZa97XtifrXcNLI7J+lxA0WNfADw+i5nqI9IJAe
         rFobw9Bm8Rz/I4gZjnIMYOgagCP9oS7J6xuzyWy0uKUn4YVlsgJ2hF8X305iWpUXeL0R
         8JIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IYrielYM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbAiGYnHFmTXdCsPSepXw7NAXgwi+V4OGerHCgcsNts=;
        b=J272QYWuKxeBFRVJFDktsDyewFpkiKrquK6NkNxIzlmdk8RK7+SxkTPtrj+qsyVJWf
         b961JDjbr/pVV0D9GPq62dwkxatK9bIJT4tyukg/rAvsZkRxSMzms/pzNSkDvYL+whrd
         amE7faPIlN22Cia7/pO3sLEUDHOV72TuZlXRxuRz4Z9LWwbVd3tu4/NHpAIDEOSgSgoa
         SRGveBM5xUT/rOC2deq2lT+X+Ro5kgdFUO76bSR3sxnbMGwNR5zu3QjvrwrMzkl0pfHI
         WCnTYXYiv98fgTKMC2z0ClJGbofYFGxygZ29jiftgPFpoJSpdvvVXKJDJotJMo4pkmpn
         pCHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbAiGYnHFmTXdCsPSepXw7NAXgwi+V4OGerHCgcsNts=;
        b=G+csDiM5aDClsfbQAj7qu0n5xF+3Up9BdNy8r7uK0PkIQwnit5cx3RLuwq92EVaVtl
         syVuYhntAtWZqU8FHok61DauyRB8KCdP4MW35kGGj8yZz2UvXMO/3FQumJQBOIk9xdkx
         G6MyIBINwtgju3rNSSB87mBXpZGKzIV9Z5eKqFLQzMQYhG5490GcPITfiCOXWsdODWPd
         4Id6UqDeUfGyjxrHrLeYfd9ntWNvW0LjSZ+4CT6PiMxNXGj5C0c1gC+2b5Y6pYUEoMkF
         SaaLvUv+0MJpHac7zTF3pHDRK14ODm/qNdimf8+RfLkXiIawe9YirdRdFRycLYxKwvu7
         W9ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MQ3pIdOXMwpVJRMCn8hfz3ZgaB1sFOlCTOHJ9leWy1vxf7GSb
	bXjmK+CLkM7S89gmdN5dmhY=
X-Google-Smtp-Source: ABdhPJyGeAN7iDUWlIMEoQIASMcYYyxy9/njzqP/ZyzheSG8+DMQv9AkkCUU0IOoatUa6bjrvYQpZg==
X-Received: by 2002:a05:651c:146:: with SMTP id c6mr153033ljd.225.1628709704584;
        Wed, 11 Aug 2021 12:21:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a167:: with SMTP id u7ls610091ljl.1.gmail; Wed, 11 Aug
 2021 12:21:43 -0700 (PDT)
X-Received: by 2002:a2e:7f1a:: with SMTP id a26mr155264ljd.183.1628709703583;
        Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709703; cv=none;
        d=google.com; s=arc-20160816;
        b=IvauIRbr6a0q6ACYVLQqX25YbOEbgdEx+LpuA3AN+Fr+Hv8ksaRh1TxhQBuC5ypKpi
         RJsYli+BcOU5nXem+AxUcg+tx0xJIqB5PDjqWxFHA1tRZ6FLw2gFRrHAD0jh10acYU/Q
         cLDqPe0Q0tLk+ua/ctV8gfoQBDnqZu7cW6coihNSXJChoAVsNLpQTxSIpZYfUWt7W2tu
         XYUcTQaMRRYCbT41LcI4S97YASTiwXwHMuwTv5sYKR61rFThRNzmgNU2T7a0drpQAfRE
         hVESmjrNW0J6cwkQDJ9SNthkmmeKqs4ZmyUpTNdEwGZ8ibW262NBKOIkRHR46au1356N
         Mzew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mDv6lThH9LBlRq+G7bShNnjHZy0fm6nN/s0ZaRwS7lU=;
        b=frbgl/lb27Gmsy26djE+ipLqMaSCl54dDivYLCWWI0OjgXtkwp1WSNBdGJsfubI7PK
         tJSzWrfGOc/mxd0Jn0Py+4g+h+ParoRvreoRvC0cQsPpe2lETEnggwuzxde9yf5hzU0v
         nr06k3n+fuF6RERIArvRz+CIlR6I8j0uNfg9RCmDnn0QBFS5poVJ8idlvvtC3NIviDHw
         1VVGckpCjDUIQQVI8BqEECM428JkgsJioMQqRp6VsfhFF5V8Bo38f0/iH9UzmKyaOoAS
         25w0w/eBNt5jUF+XJ8HdDwAtvgEBWte/uQd86OnVThBdb+dsSMjS3+2+VD4ZodIp52D1
         Doxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IYrielYM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id u9si9146lfs.9.2021.08.11.12.21.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 4/8] kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
Date: Wed, 11 Aug 2021 21:21:20 +0200
Message-Id: <408c63e4a0353633a13403aab4ff25a505e03d93.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IYrielYM;       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

The HW_TAGS mode doesn't check memmove for negative size. As a result,
the kmalloc_memmove_invalid_size test corrupts memory, which can result
in a crash.

Disable this test with HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index fd00cd35e82c..0b5698cd7d1d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -495,11 +495,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	size_t size = 64;
 	volatile size_t invalid_size = -2;
 
+	/*
+	 * Hardware tag-based mode doesn't check memmove for negative size.
+	 * As a result, this test introduces a side-effect memory corruption,
+	 * which can result in a crash.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
-
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/408c63e4a0353633a13403aab4ff25a505e03d93.1628709663.git.andreyknvl%40gmail.com.
