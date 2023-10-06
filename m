Return-Path: <kasan-dev+bncBAABBXGKQCUQMGQEN42PMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F71F7BBB9D
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:55 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5041ae34ce4sf2101107e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605534; cv=pass;
        d=google.com; s=arc-20160816;
        b=lCBlkqqpoAB88+HiYwK2u05Uypz4FwXvAPMCHxwc9ZbMY6X32V27oygV4UbPnRb2JX
         rCzEVL+22v+RB7jvs9cjSAsQUWAiYrYDUAyTdkFa3aru3N/s9eJl5S9B5pU+tkagAFUH
         AkITPLFT3ad/ILzx95VxeXahy4wwHYOMPOFK2SFCeNZse9IOEfXRECbpPDRIPlJqXLYl
         Wd3SIESY16nhafgiUcUoVjiMgytIyTF/vfQtX5wieXUsKZmfmOCEsEGGv/i74+7GoeBI
         Xqk6tc5AEnImBnO8UuEQT3pVsRvHkxVJ8EQWVXyLYvTTH0TabbC3uizx9/OxCjzHjls8
         ohSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w6La6h/Az5FePvqP0e+XD/EYDISxSRKkzb57xD2Cevk=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=Av+qy7p1o58grsfE2ZWagHU99ndUydpZ+W9Ps/pQuB+DkMERrlmc8SR8b9K9lYyNPp
         wc1kGQS0z/C1XBV0LDqdtpPrkIh3u8//ANcQ2DeycXu86VB4I0PjuWRmqCk2sbT52YAK
         iCbB3wsu33GMY5IMHKuLT32JCsdgvTgPB4eoytpRik+bubTC3zPZYx2UZWb1WtDH6zyR
         WuagZhikZgNNJro+NgbEYfsHFFx+bsP5WnUOzPX/ZCIP6bpJrrrlEPWqhtN+gLImzPYJ
         vRw7IIuPgza8u2317JrE4MJZQJV2oaRHIVjWvZ6IBRyb9EHJwWpcNIfZveHn7NGNfRIH
         +j3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sdj54eOA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605534; x=1697210334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w6La6h/Az5FePvqP0e+XD/EYDISxSRKkzb57xD2Cevk=;
        b=n3HX3TkYtQO7rqGwHKIxGzws2Pf3WOvDBpQnC7ceYP4/nkcKC55qr5cJeSbXwv+dON
         YXZN7WDYeWM7ySj/DZAQPjPdaHcgRMhP8zdJTu6bm5ZVAf/GJUzD0WXqLYiALOa6i5nn
         H5WdlYhVVbwGUpLaTSkpzd90aPnj6Pno6lRyrpEehcvCWvTsr2m4GvwW3400BUhxsMll
         RS6r5wsFgGwguq3yTYpMMKMqLJxqltckKwOIBO5kmTTGSvk/SU1T1r2Cn57jyHThxB2f
         V/rrasTKlBGguv6HNAjcqX+mTgAg7zmI1HL9CYboPj5dlKbQ/gsJy4qdRAg5Q99OK84A
         l1og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605534; x=1697210334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w6La6h/Az5FePvqP0e+XD/EYDISxSRKkzb57xD2Cevk=;
        b=nGrn/bXKZBUoisLFFyF2txBI+7w2mtiGc6HifS5vsV0uKEw0VHHh4x5vXUIfDxKI9T
         pWTsLYzsLwKATN6lwRszyYbrJQ++tT/+skO5Jhy7yIh1lmXkt9EX9R59z/jPj7/tJ7iE
         RVmTHPtPAZWbzqQecz8xXFpIMdysV5BIO2kSJOl6tD50PR0cKmYgVvXymlg1qT3lg5MI
         f/OgVfmEgns129H3a/aWctpGMIGcmRtVj5B6TcMUVwZMqpZsx4um2K0ArK04y/q3Iqtc
         ivC9SwFsZr6lxr4HsBjFCbGMDmrQ5MHDHWzFSam96dw3f/H9LSh712Mkj6seQt4+maN+
         Z/mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxHJb/FLD3H1mPg0VgZym2N+SmIfyMxbcfbGRelhi0CWkmcz2qd
	0Ty4byTSGQIbz7KEbCHuQHM=
X-Google-Smtp-Source: AGHT+IH2FkZSa90URjvlAmVpfAu9w1ty552ZcJiEYk3BY34GF+SJq9MUH3y+Cpddghb42QYf6Yr8rg==
X-Received: by 2002:a05:6512:1104:b0:4fd:d18f:2d93 with SMTP id l4-20020a056512110400b004fdd18f2d93mr9769611lfg.6.1696605533240;
        Fri, 06 Oct 2023 08:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:448:b0:500:80c9:a128 with SMTP id
 y8-20020a056512044800b0050080c9a128ls17277lfk.0.-pod-prod-03-eu; Fri, 06 Oct
 2023 08:18:51 -0700 (PDT)
X-Received: by 2002:a05:6512:3b95:b0:500:c89a:2a28 with SMTP id g21-20020a0565123b9500b00500c89a2a28mr9374640lfv.28.1696605531630;
        Fri, 06 Oct 2023 08:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605531; cv=none;
        d=google.com; s=arc-20160816;
        b=AKvwbjNgEMDVJ/2NRh7Hj8Ttu6V9VGk1TDiA0WkZsL3Xz4wMJXB3DUkaftBXq8oaHJ
         elCf11gvUGz+o0FHEs44J5eIn3wZ9rJXfNyjO4mES2ktavyL/pp0WD/NvKJkvR/I9hLF
         o99kBWbWk21Aa9rrhA5/vA1YIhWPXBXNyQyl8hLfLXAQrq1Xb0jYl/FZD7CIFYsdaBMu
         hZ6X7NNXFafkxPxZaRcopmW50cpb/moVocBVee4Gfxeh28Wf19h5ODORfuBLGAXs7UBn
         CEQzFkBLqPHpRmblS6hzRZSQZvYEzxX9wlik3yAjJOW9ZrzsDyq5T7aYK5RNqwKIqmzC
         Vp6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KpaY5zOxHzDnEKIsjBbAGIMHyxq37tXIib8836JShNo=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=QOuXVHLtmJBV8GVm7ZaLhEu/dlld9+wXYrc4oZouRaGXBaXgLRthDWFbFUrAmiWOQS
         qWJdiRsXHe4aNP7XTpLPRBF8CYi+Q/X5t+zpz6YYOEaL10XX/2wsBzxTRJ26/+FpPIo3
         8GT6rYzT7sGNn3IZwxgSDdFe4XbX4rA0BBphpT20PYEumL8Pv7lzsWolbVWCnevgr29n
         AQQ6GTmIqWs4vUlrX1kDUYo4Z5Jwf2/gQLg+PgvyGhsKjMz8gbrHat9a4jPg7l5p5KwI
         W5E4I7BZPNmKerjkqiaIa+mYV9+PtWsNLiwVltURrh2/A8Z1KXN8qlkO1+1mUhBZYD0t
         XudA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sdj54eOA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-202.mta0.migadu.com (out-202.mta0.migadu.com. [91.218.175.202])
        by gmr-mx.google.com with ESMTPS id m7-20020a056512114700b005008765a16fsi74202lfg.13.2023.10.06.08.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) client-ip=91.218.175.202;
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
Subject: [PATCH 2/5] kasan: unify printk prefixes
Date: Fri,  6 Oct 2023 17:18:43 +0200
Message-Id: <35589629806cf0840e5f01ec9d8011a7bad648df.1696605143.git.andreyknvl@google.com>
In-Reply-To: <cover.1696605143.git.andreyknvl@google.com>
References: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sdj54eOA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202
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

Unify prefixes for printk messages in mm/kasan/.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c        | 2 +-
 mm/kasan/kasan_test_module.c | 2 +-
 mm/kasan/quarantine.c        | 4 +++-
 mm/kasan/report_generic.c    | 6 +++---
 4 files changed, 8 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index b61cc6a42541..c707d6c6e019 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -5,7 +5,7 @@
  * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
  */
 
-#define pr_fmt(fmt) "kasan_test: " fmt
+#define pr_fmt(fmt) "kasan: test: " fmt
 
 #include <kunit/test.h>
 #include <linux/bitops.h>
diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
index 7be7bed456ef..8b7b3ea2c74e 100644
--- a/mm/kasan/kasan_test_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -5,7 +5,7 @@
  * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
  */
 
-#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
+#define pr_fmt(fmt) "kasan: test: " fmt
 
 #include <linux/mman.h>
 #include <linux/module.h>
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 152dca73f398..ca4529156735 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -8,6 +8,8 @@
  * Based on code by Dmitry Chernenkov.
  */
 
+#define pr_fmt(fmt) "kasan: " fmt
+
 #include <linux/gfp.h>
 #include <linux/hash.h>
 #include <linux/kernel.h>
@@ -414,7 +416,7 @@ static int __init kasan_cpu_quarantine_init(void)
 	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
 				kasan_cpu_online, kasan_cpu_offline);
 	if (ret < 0)
-		pr_err("kasan cpu quarantine register failed [%d]\n", ret);
+		pr_err("cpu quarantine register failed [%d]\n", ret);
 	return ret;
 }
 late_initcall(kasan_cpu_quarantine_init);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 51a1e8a8877f..99cbcd73cff7 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -220,7 +220,7 @@ static bool __must_check tokenize_frame_descr(const char **frame_descr,
 		const size_t tok_len = sep - *frame_descr;
 
 		if (tok_len + 1 > max_tok_len) {
-			pr_err("KASAN internal error: frame description too long: %s\n",
+			pr_err("internal error: frame description too long: %s\n",
 			       *frame_descr);
 			return false;
 		}
@@ -233,7 +233,7 @@ static bool __must_check tokenize_frame_descr(const char **frame_descr,
 	*frame_descr = sep + 1;
 
 	if (value != NULL && kstrtoul(token, 10, value)) {
-		pr_err("KASAN internal error: not a valid number: %s\n", token);
+		pr_err("internal error: not a valid number: %s\n", token);
 		return false;
 	}
 
@@ -323,7 +323,7 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
 
 	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
 	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
-		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
+		pr_err("internal error: frame has invalid marker: %lu\n",
 		       frame[0]);
 		return false;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35589629806cf0840e5f01ec9d8011a7bad648df.1696605143.git.andreyknvl%40google.com.
