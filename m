Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMHRRXUQKGQEVX2UKDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 17E6F626D8
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:09:06 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id y1sf6374343oih.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:09:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605745; cv=pass;
        d=google.com; s=arc-20160816;
        b=gwkL9/9OxO2TGitnpwPjKaNWtuDDbMw1uV7txPUXhpyJLTutnG85SK4leBPPwMl8+M
         9WocW0QJwLUQEkznOq/RARlU6NRWO5xToVFkZn4Mb6wdLtaedUxNS0iks9/y94wPDuXI
         4jppp2tKo65Y8KvPmaKMAh0jjSMIMCqdpeo9I7EZPfTUQf5681uTvl/3YR8bhH1lyuCK
         wGVg8FzhtUi7YF/8KSd9LpUYU4sKLnhrCzxv08dicZLdCil0ZXvFN6Ltlt5jEwX3LGEg
         Q7wXeBROLkKZIOlS3BPTaZ5h1jJQQAvCe/4cEynHZvkALpcvEfOkgMuRbuvof3JPvGol
         jy1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=44+ugFARnGvA0aC/7aGsniIYICo9WE7m9eEej3HghM8=;
        b=FxaCeqE6N+GFhiyurLBSJboMXOMSq55M7JzohEnE1SR9hg+tc4h+XuwXTq6mNMiAiR
         tMYXn6ioChPqJw1mE/7NeFEoTMIZwjDpsXeqCS7tzRN8Ultt4Oj/cvJ4GXRrs/bfdngq
         6TKf6kcJy6L+WAM5Irp3HJ2SU4hu0bsXtmEFIDA74SUsZn34jHwqR6J1bWHiq5vhe3I2
         18qWBzsHEdkv5tcgNBnom4+yA3iqIhns/LjpPuhPTxC/NlOIcAeL+zkda/yHgdzN4kGe
         3BykxmsOp4OV1E4D+RVvyzhQLGDzX8fT0IxlYpBOC03Fakr+6b6CVKr19tYXvh+6jDLw
         lbog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PgglRjVj;
       spf=pass (google.com: domain of 3r3gjxqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3r3gjXQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44+ugFARnGvA0aC/7aGsniIYICo9WE7m9eEej3HghM8=;
        b=e7xIdvVlfdU6Nu9BYHHmCo+OK48KJrvD6XIZ2r7gtgOQ5MtN7qevwIV9FjY0Nw2fw4
         CxMBAFSsJ0Jetn3zNcq8+jgnOeAZ9JrmnbiNxVWq18CnR8xdPMCzv5LSC165A8vqGCzO
         MgQJb4kjiy+vnypTN985WhE0CdAKVs5SJ9ZLoqJeAdZOkJt8YXDMqqlOnI1oxDclbrNt
         S5zMTihHAePVGtriUKzRH36HkORxD01iO2Lt4BaWy+P5ijB1ADCa+aAUOA+7f6idGfVV
         xUq3VhfoZaagp7xVV3t1shMDY4SRskweIjVWCBFCdK45QUxqaQxIyWhip++eRE+dKJNG
         ix0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44+ugFARnGvA0aC/7aGsniIYICo9WE7m9eEej3HghM8=;
        b=UfR9UcVIhXX4ykfoBQ7O2Z8B487LLBZDyWFS6G8Q3N9sGBF26k8qjVR/yjj6CFxThH
         R/pCWJe0ZmdT+aD59UaOxuDqhkdnRUlXFREXfDrHofFKvnFv99o+UEg1KrEIjr2I57QN
         iM1sT0SpFNXkNSTajYwBWobtrPLYhVRi7SAfEU/jtXMQBLcW/lCsZkPZgrNypUUdX1P5
         dFRMrALCuoc8pTfVNLDkzhwaoxuUVMY30ODp6ZHy36beLxX4iFKPjXxQH4EVZCqk68x5
         Yz960KY1mPS7SnyR3EERDq9/VARtrGUTbNGIx1t8pA5eAcRkkAV0DQjNWsjPGg7rg5dH
         9E/w==
X-Gm-Message-State: APjAAAVoy/HXOEpNpzjYIi6BcdTqw8bxdClDNpfJxtOrxYiV3rn9yEiY
	2wV2FgTWiobc0BsxdimQnwg=
X-Google-Smtp-Source: APXvYqwAt08K0u/RcYdluu/tt44+5UdDQ6SdRCWb6V8vB8UmA3RPPW2XdJiTVr9BD3hXVEDG/NXi1w==
X-Received: by 2002:aca:bb08:: with SMTP id l8mr9449143oif.92.1562605744924;
        Mon, 08 Jul 2019 10:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2f43:: with SMTP id h61ls1282669otb.8.gmail; Mon, 08 Jul
 2019 10:09:04 -0700 (PDT)
X-Received: by 2002:a9d:5615:: with SMTP id e21mr3543463oti.152.1562605744582;
        Mon, 08 Jul 2019 10:09:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605744; cv=none;
        d=google.com; s=arc-20160816;
        b=Id2NdQjNp7pcu2365eO+bd2N+MkpQWZAWEwYxZ/Qm7sIjg48PVG3u5agYEIL+W+ckm
         NBYS9ukSQQGbkPbECM97XeedAXnnTXiERNO23QusMQAAHcmOXmGvs9YwG/P2RQsTZWKw
         /OzW0wcyVGANQT/LFuL0/PlDgMh9r59gWQ8y12Mihp1TF6uvKAhkkP4LQxXoRpPTpCfV
         KwinTY4Y7O4DF/fyddrPuboGVctYUzH8I5+HJzDkI4dbrxp8m/Lx0Ox7dat816ndIUYw
         FJRJIoDEuU+ZZp1oXPOu5siCs7GHcB7NAJHwxkH7oAK7smjxDhaxUSfS7PC//hfiZudc
         I5FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/Bjb3ErsQTLw+YrlSLkjBcr6K+fvu3f9fORDBwR/vbU=;
        b=JNwyfDgSTmhAWhxCLAPdub45xw2Skn4EjgO2jjzCGWXgD6aZnxrv9rhiUYMXI27Y/g
         NG/11LmZqwZ8SD95zAIHJQ02VS5rC/tBvm06AgCDKrSwGv7GrCQX3BhycZANGauNAThB
         J2BcATdALt9oFqJRVjpSCvP2i4n300ur/BQZUcvkBrKkETzyJHwFNN6pMa2HC1Q+Wj4N
         XvNfsvgDtRR/0PVaPMOe40IZPq2mDqD4KSSYqvKZAOCaCzjxoMldTxdXHUhLOTtX4lBM
         JXrN5kuDNJM1B3drXTfMz8EZe2Es9WBT/z8jj0G3F6IHYbFVEENE+u8ccIZ0xaEu3Tzt
         PWuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PgglRjVj;
       spf=pass (google.com: domain of 3r3gjxqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3r3gjXQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id y188si960984oig.3.2019.07.08.10.09.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:09:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r3gjxqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u14so10189606ybu.19
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:09:04 -0700 (PDT)
X-Received: by 2002:a81:a95:: with SMTP id 143mr12306291ywk.279.1562605743974;
 Mon, 08 Jul 2019 10:09:03 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:05 +0200
In-Reply-To: <20190708170706.174189-1-elver@google.com>
Message-Id: <20190708170706.174189-4-elver@google.com>
Mime-Version: 1.0
References: <20190708170706.174189-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 3/5] lib/test_kasan: Add test for double-kzfree detection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PgglRjVj;       spf=pass
 (google.com: domain of 3r3gjxqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3r3gjXQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds a simple test that checks if double-kzfree is being detected
correctly.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 lib/test_kasan.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3c593c38eff..dda5da9f5bd4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -619,6 +619,22 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kmalloc_double_kzfree(void)
+{
+	char *ptr;
+	size_t size = 16;
+
+	pr_info("double-free (kzfree)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	kzfree(ptr);
+	kzfree(ptr);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -660,6 +676,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kmalloc_double_kzfree();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
