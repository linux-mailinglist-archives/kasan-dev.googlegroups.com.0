Return-Path: <kasan-dev+bncBDHK3V5WYIERBJUBQ2IAMGQEHMJEYEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C4CDC4ACA5E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:27:18 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id f4-20020a05651c160400b002442a0b1344sf3543508ljq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265638; cv=pass;
        d=google.com; s=arc-20160816;
        b=nbSNSH8xuHkq6ue/22OHyqSRbZuVfbpxQBFxjCtnDIAW5/d34CLHwHO9KUJ4rMkz3V
         ArHineLEDx+6J4YF2e/3lIYENR9b34ZMukydfvmRjgEhRkGBzkCycwe0+QKSJqbaIIyg
         ioWQYCAPc7eC2sjcFI+txDCugXKvXyedE7ByhDF4uYtQDUMYXgazGSroGfLHAU7/QyhU
         Melu/kczEYgpxfCLuj6T/1Rg40YrMNYOi72W5eqdg1ykTAj+Z32Lkh9+49R9TlW/ND0/
         x0fy6/OBVv2hR8+izy39Y4wW/ZffYLE9kcC0LnbRnNJjSSvCeUOUudQtdfPsveCT0i0E
         yIgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IgRSfEWRoXqAkVyUN0vuYS3XCNJjAvdSKHYCs5A+PtA=;
        b=JEpuY7ed2zOvHIukwF52wQj4dD2eg/aGd7nswQ1BhqdbTDGGi/GKLZ/ZqoVQxZkpTM
         4njFu2obo483ticA2E4awZRR2/Fdb9B5WZ5vsyLApZ5IwZAyA5Hix7cSUVK1DBTUrPlY
         zdR6r5D7TZwPebwv4+i4SrT4YnGg5IhbrInR3+O4YvLvxmVtjOe/v5ieAfZhSIoos2vz
         nh7nM1OTsbI/IGAnKgfMSvbT+v+qv4M2KhMXXEO44bpA2eobgwmYZ17nHc4Y0ctT6r3R
         fSUQP7BYleJXwb6xzsQuYWMI6YS/D/El1WYVWFwviawBMhTP+J0yasAAQzIM0lGcEAI1
         vqvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=W+jEhB6B;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IgRSfEWRoXqAkVyUN0vuYS3XCNJjAvdSKHYCs5A+PtA=;
        b=FCh+mQQtF22N6AOaDw8mCSMA0OHizEvv1rPGXyE3Sb7Klu7Y8fKhOYyQe4E8FYvsZ+
         9HFq/H0PqtApn1JkDi5/fsNIe47dgdvFJZ+KikTzZsgwaz6Vta/osJ1DyBgo6E6qYBbH
         AgGCzj15qbNXjQ6mYfyYwjfQ2nV0RQDvL2nZLu4hIAgVWO7gEHmY7cIXYijienZLty5+
         Vkp9BGGAEc9NwHkv721wv8521xhn6k+hTMYc97FEW9wI3oaQG1KUETIxLKeRoYXwznlz
         bzGCToR89Vh7pHyKB0ozwtOYjDcB33B/hP5edDnZI3SC707nZct4oltGFKDx1v6DEl8r
         XX1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IgRSfEWRoXqAkVyUN0vuYS3XCNJjAvdSKHYCs5A+PtA=;
        b=b8qA8Dyo2QM8AsX4/Z496ytCKMQXlqKtO6nk3N7eUrSP4Dsv4LiVWE4sds17urjdf1
         5t9FGdh+X6gVcpTDyzCrlqGRlQfadeqFuUyc6x7lYPjgP5dDMEjpITuXpK31uvwPNWFH
         0jhzoTq0UFboG+VmdmGSZwOAoEhN7uC0W9f5Xdsi5O5SN2mQwWMrlSfNtgYXYvfO3Xrd
         meKd7QOSlgd//23FIBQxqF3loBgpUBEPsKq8YAmE8LWXCBnBvmahBgq1ez6pfzdPIRV/
         LIkpLSnd1eHoiULpdwZkSFf1E58YYiZeq5ZOMM7D6COacANqrnneT+n9DT57eGKY7BP8
         0tcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RsefLB2SoID+Ruj5vRKGVUEwplNex2Wo3TgHbEdzfPs83zZL5
	18gQJs7kLE6bkJpuAqP4t10=
X-Google-Smtp-Source: ABdhPJwwToA0IDUex8Lflm38dljyIol4TKxZuyrqcwV/Wd73kpNwjqUpDan3KG9p6ueBJM+vcnVaWA==
X-Received: by 2002:a2e:8053:: with SMTP id p19mr700913ljg.95.1644265638263;
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a782:: with SMTP id c2ls1587826ljf.4.gmail; Mon, 07 Feb
 2022 12:27:17 -0800 (PST)
X-Received: by 2002:a2e:8756:: with SMTP id q22mr719010ljj.93.1644265637244;
        Mon, 07 Feb 2022 12:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265637; cv=none;
        d=google.com; s=arc-20160816;
        b=SUXQgtJBR+9VAjafqK7YliYICt0woT5zk+A33f2HRNMCB+lFZMOTeaDV28ZoiuIifW
         RTcH90c+ljyiRmpw8Vhzg5xNuDtYqF9N7q4Vbz/OTOWNhR8h/AiwHjqrEz3xgDRHCjay
         C3jzj5lNvcdJ8hX8I+EQtA+i909U5P3xUwHjMFw3tFJsycCFTE4S4A3rlFNVFD/UqJMr
         gOD2ZIQOoMcfasZamTKXsUqnC8vWsxbE2ce2CLlyFi94z89FUDhUkd9/PtJVbaXy1C27
         GHrueCVlnRZl5Zi9fGtPjpiIzaajvWWn/mqgTPxpnnfwjYcsuhFijMHr7WM30oFnZaBd
         phNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y0o7uOOFR/F8wdFMHcK21ektAthAmrg4gw7mo/oxzd4=;
        b=KFWNY0MTdiCyQY6hppag8StflNpdwoc4+8FCgbOAFRQUBQ7gQmhB/Lp51WVdUcRhZl
         IZ6/0jTCBtbwSiFA8m5WOCWxN916Ub9dlRM3+shKPFCjZXintWJve9suUys+lUkLA2Yg
         LzdT9t4eZCL8fY2YF0k6NzllohMDHuDT/3av/IWoMlfI8eXMTQgXgTpU7CSVrWVe+QVS
         LkanzBaY7foOBVjSEy9sl9PG8RQ0SfZHriGdO3Jil1ieKHvtQK0J7uoN628ojJLNvRO0
         SV85vWaQO1hAY09HmZ0i8YQeqcdCvZiapUDx8yg20RMahLHDp8a8gZZHiMO5//+vYI6F
         JKmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=W+jEhB6B;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id x16si514992lfr.10.2022.02.07.12.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id w14so32731865edd.10
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:27:17 -0800 (PST)
X-Received: by 2002:a05:6402:1649:: with SMTP id s9mr1266085edx.38.1644265637064;
        Mon, 07 Feb 2022 12:27:17 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id t8sm787893eji.94.2022.02.07.12.27.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 12:27:16 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v2 2/6] kunit: use NULL macros
Date: Mon,  7 Feb 2022 21:27:10 +0100
Message-Id: <20220207202714.1890024-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207202714.1890024-1-ribalda@chromium.org>
References: <20220207202714.1890024-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=W+jEhB6B;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-example-test.c | 2 ++
 lib/kunit/kunit-test.c         | 2 +-
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 4bbf37c04eba..91b1df7f59ed 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
 	KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
 	KUNIT_EXPECT_PTR_NE(test, test, NULL);
+	KUNIT_EXPECT_NULL(test, NULL);
+	KUNIT_EXPECT_NOT_NULL(test, test);
 
 	/* String assertions */
 	KUNIT_EXPECT_STREQ(test, "hi", "hi");
diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
index 555601d17f79..8e2fe083a549 100644
--- a/lib/kunit/kunit-test.c
+++ b/lib/kunit/kunit-test.c
@@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
 				     strstr(suite.log, "along with this."));
 #else
-	KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, test->log);
 #endif
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207202714.1890024-2-ribalda%40chromium.org.
