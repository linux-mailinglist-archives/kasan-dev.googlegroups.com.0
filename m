Return-Path: <kasan-dev+bncBAABBNOVY6MQMGQETOB656A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB0415EAF3D
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:08:53 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id l15-20020a05600c4f0f00b003b4bec80edbsf4469808wmq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:08:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664215733; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkLU3l6/MG5ZzI0+IP32VSMdO2eJjTguCyb9386NNh1lBYBL4MqHWkIQ5UrNhBBNk6
         10Ds48k/1FpwRFiIcOJ+lOptLTZbSAFlIWwsrotfOPjmcr0fsVFlvEk1Vo903Fe6HUFF
         1nHqYsuF14aqsVW2AbYrxryU6HDzsSHpv2YJhcDdq3RMWy1wBQ4hr+ullzYYhffGllXb
         ZOMDa//AEu9zBi+xvGJVBYezOxjfRE2I71adV+1Zh83e00JvlAgZxKcQd60l3Jp8ktll
         AMqDjizNfjq3+rRdTSNLlmtaQADmVqWuW0w0SKRlop9gnbsCd84leWHRD9jT/KuDmpSR
         zuwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4hqRDgHzvQFC18ngtu7rgpwaBXlzExy6BZGweS4sqac=;
        b=aABBnLsXJ4jALSRLUcGlAz371Y2Xy91EnVCs9mr+o1UVCCQ2R8l1xNdL7qnXG41Ikx
         LZr7XVbgKQM5SJ2WwlBuEjNe/1TrkLj+3ySAfn3ch1NwIn1cwrFR6QRNNWLS38LTDxrq
         Ja+ME7xdDWZG6fEfrXdXGkM9LfHNeZyKHGJnxaxPCn25gsBexyTy5oO4dDzp2+Lkt89y
         Hlv5Qu/iaFyhYq2ZgwVGgGHxsfthet8XPdbRi9ZBHkKT3r2IbW42HTLo4lUGwuWbTXZ/
         k8h99HQdfTcb4LmcYjujjUmm/AlejXcTc6B1ZrqIkM6bvrr9ZnHH+s09wackh9Gju/NH
         Y5kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BRXYv2H5;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=4hqRDgHzvQFC18ngtu7rgpwaBXlzExy6BZGweS4sqac=;
        b=ULuaNdsHBkUK6AJCGvNdEtP86pOBrzasm2GAZfA6R1tX5D6V5J0JqVGFafto1B3ejh
         FPHdModJV5Omg1qtm8tKc3Tr4VdLrEzPcRFK/7tuH295jiVZpXPgVTvHB0fsXg82nBs8
         IXx3XEaVloDuzJrI9VcsXF29igpf6LFTvIF3BPUPBpVvlod4odtJt/esai6upRobgn8G
         9A43EWccXtM77XkgKuzoxfU30Aezh8MopdZ5qDkFN2LGYX3DkBUrwDRVy4S1L3uCBSoY
         Sxmb1gdXJvFh0FLj/8Qq2qPVoobi2mHlr1cVpSu2n7rb7Pk8J5vnbPoPEFs+vFjNaiyL
         AByg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=4hqRDgHzvQFC18ngtu7rgpwaBXlzExy6BZGweS4sqac=;
        b=FgfifecIRH8CsI4mmWnKnBJRt+CRBMXRwkXZZeTj9oKkc4iitKK8KcYVdTd3UggcCE
         fyzf0c9hXNys/5xkOKb8zodGd6KNCqxq5gzJTsPFtpneNJdFV2HPv2PRcqxvz6CyVy/p
         2IYf8eElxBVLsMJmEwR2jqcorogMZ5sRwg+yrd2uVZubgIyg6Rg0SUhfr+g3qlH3FAno
         ePAV9gECzMAIhmb6vTNHkwJzVXJ4tw5c4Ycp8lNs4zPbqfkuGb4FSVvSSpaOUxds1m9p
         WOCmkZIgQHCgnuEf/cmmK3ukvdNJmeODW2nXPG4XaPS7nisJAYAAuOgzjYYZe0jk7HFE
         9Zag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0g27oO53bDmt0PTc731rkmuZfV8NCJcO4G+V/J6fhObNMHrGDB
	6h+BRuDCLb9UxxjjzypYtoE=
X-Google-Smtp-Source: AMsMyM77+Ejg1n2NFi8fbiqCG8nQufD/tpZCNuAXyucI+RKTpx53LbbkWLnb1wUU5HNZ4jjL/wIwhg==
X-Received: by 2002:adf:ecd2:0:b0:228:6439:a24 with SMTP id s18-20020adfecd2000000b0022864390a24mr14309928wro.401.1664215733262;
        Mon, 26 Sep 2022 11:08:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e4c:b0:3a8:3c9f:7e90 with SMTP id
 e12-20020a05600c4e4c00b003a83c9f7e90ls4040478wmq.1.-pod-canary-gmail; Mon, 26
 Sep 2022 11:08:52 -0700 (PDT)
X-Received: by 2002:a05:600c:4651:b0:3b3:3f99:4ad6 with SMTP id n17-20020a05600c465100b003b33f994ad6mr7095wmo.90.1664215732460;
        Mon, 26 Sep 2022 11:08:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664215732; cv=none;
        d=google.com; s=arc-20160816;
        b=aOl7bq1QxLQ85300c2yA0a8Wc1sZgXm+XXbcs5vSL2g52Tcf26dHvd8QW3PFbYbjCK
         IfWE099V3g1+WVdDHJxtOpasAqm1txZnlerKtWUgQMdfMNX4/sSw0qdppOuPkikNDhOG
         4N41SRtBGbIeQ9G2cAqWgpVPuEyNHoIGu2zsRYSO4k3ZiN6+v315Gg0eFJ/IDFU+w7T+
         4WF7OwfTTKSUhM178VHNtw6kEZ9hpTQ4DJ/yp3xnBsC8YUH2FkMoqC9dNMirYf0tE5nm
         b8Li72mI20VOSXAtSCAapRfE2fJOlBdT2CH1gyK+LXE3Y+C0w5KgRGDWFdFF5mOzghmR
         BN+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OEmgNjB4wCnJJ/8lBPr8SNJcQWguKZ9xXHXJI9R5iDU=;
        b=aYIdoZU08RQoti2onS+XwLSME4CoQV3/hUszVPGzeQcXN+9g/32WFfU05PuErZBqVy
         uhQw/ik9Tqd/QnPEubule6EhPXXx0PqsxdrCK5PszP11SKX2T0+h8vW9xNOeOdgXBMpk
         ZMfZoDjgYmmtFuF0hhlC2Hp6wNjyih9MboJ1iHwRCpCUIJiuzQNnDy+8HLSzfoD8oGRq
         ktXkWBlEep1UR5pcJ4Ae7HUL3eFiGzN1RpNrrqEB1lyn0xQkmUuZBnJ8xcZ727EOc3I7
         zpG0cinUFemsl9408ufAeCytE6ORjyFSlSLuY1KibrULXu2y3zKLB008F/HalXw6TCd+
         gx1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BRXYv2H5;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id ca6-20020a056000088600b0022cac19bb23si94856wrb.6.2022.09.26.11.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 11:08:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH mm v3] kasan: fix array-bounds warnings in tests
Date: Mon, 26 Sep 2022 20:08:47 +0200
Message-Id: <e94399242d32e00bba6fd0d9ec4c897f188128e8.1664215688.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BRXYv2H5;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

GCC's -Warray-bounds option detects out-of-bounds accesses to
statically-sized allocations in krealloc out-of-bounds tests.

Use OPTIMIZER_HIDE_VAR to suppress the warning.

Also change kmalloc_memmove_invalid_size to use OPTIMIZER_HIDE_VAR
instead of a volatile variable.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Add comment for added -Warray-bounds-related OPTIMIZER_HIDE_VAR.

Changes v1->v2:
- Hide ptr2 instead of size1 and size2 to be consistent with other
  uses of OPTIMIZER_HIDE_VAR in KASAN tests.
---
 mm/kasan/kasan_test.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 71cb402c404f..f50b11d84f41 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -333,6 +333,9 @@ static void krealloc_more_oob_helper(struct kunit *test,
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/* Suppress -Warray-bounds warnings. */
+	OPTIMIZER_HIDE_VAR(ptr2);
+
 	/* All offsets up to size2 must be accessible. */
 	ptr2[size1 - 1] = 'x';
 	ptr2[size1] = 'x';
@@ -365,6 +368,9 @@ static void krealloc_less_oob_helper(struct kunit *test,
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/* Suppress -Warray-bounds warnings. */
+	OPTIMIZER_HIDE_VAR(ptr2);
+
 	/* Must be accessible for all modes. */
 	ptr2[size2 - 1] = 'x';
 
@@ -578,13 +584,14 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 64;
-	volatile size_t invalid_size = size;
+	size_t invalid_size = size;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
+	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e94399242d32e00bba6fd0d9ec4c897f188128e8.1664215688.git.andreyknvl%40google.com.
