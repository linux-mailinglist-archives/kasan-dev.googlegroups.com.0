Return-Path: <kasan-dev+bncBAABBYV272IAMGQEOME3C4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A1004CAA7B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:54 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 10-20020a1c020a000000b0037fae68fcc2sf2109232wmc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239074; cv=pass;
        d=google.com; s=arc-20160816;
        b=Arphl19erCypi8TgVNKE5p/qQykUOIPjKNZZltpP6ve+qWxsDnt5rIoA9tkdfHdYDR
         BlnrNWyeBdfQdzkbtYaY86Qy+hwKgbmRT/Zi0W+Fu70YQXNWZu8CZwmH8Y6n3Rf4iRb4
         24LTLnzhfgdXxo3n8BCy6yhc9rQD7+CGJFHtgg1/nfN1CFYDRewp4ioXzDeTJ/uDUr+T
         7bO5AcPV/iDjFryIEJO69VTOkVCAMRtkh9bRHjA2E6uzr6VS+1K+ZMbwICFL8J/1ObIo
         GTBMqXHOW9Vvn1IdkSwlUGvxKZi3BtsWhIUtc7C69/IbFCXo4/k/zC1Ea3vs0oXsL2h+
         RNLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lZztR8PRdAN+WE6adHs51u6+rC3gDlVTOgEUAtRVLKA=;
        b=DMzDSBDZ85BgtCrXSrZTopjAC97bD9j+hPIXJLaxa+CgKRQUgks6OZuZDwhL6Bp3cV
         pDbRxLEU7PQxs4TvrqfyJBxm/FlEVWImz9n9DQDAohBBzR3x5zoNS+RmLgBp5s5TQZn1
         LKUOP6dpkPvlU3WKcm3eBDAved1pSxuBm1WwZqLvLzkWEUquCJPZ6jBQuDr4Ja40JEMX
         XBfwGI9hBtmINfFwjpP+y8nGaRkWQFbscrRLBwnBm6KsVtq2aPEfmiiefz+zNLKN7BYI
         uk6JR/ZkqcrnJtShrWZ4WrHMrPD9Q+sbm+ncbY4lsljAiOz83P62zaBVnMuUAqKgP7Ip
         E6CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IEetNTQJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lZztR8PRdAN+WE6adHs51u6+rC3gDlVTOgEUAtRVLKA=;
        b=s0iTcIAPvO3RT8Nk6Q28lL/di2KerW97FOQ5iPl17LGs1ZqPmM/++yPHd//aBTqDEn
         GyzgOFZiX9OCVtaiA5mqd1XJ7Om0HYEjRB/iHdg/Qo4soQ0ah3oPNEpg6m0Nfqy/BTg0
         j8zvodZlym8qUoShQjOSgJZD5Y9whvX9i0z6mtA4i4YxXnwzkrb9gHdRAMg2ezgUAza9
         BL7w+MxIxXn/RR4MAMRDO4Zy9swwl/EfqmP+zr2jIxEgHOpyq7rfa2NfqAxi0EbccDia
         vL/cEUd+pkjJL2R5uA9qOnDqr8JRs8A7GPObjA3gMAtyiCHbRacXmiD1ksfqiXudw+mU
         4gzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lZztR8PRdAN+WE6adHs51u6+rC3gDlVTOgEUAtRVLKA=;
        b=ArJg470nOCWtXghh3fehS0IAKcGLrygG5bVsEcgTzNrJJHepz5HjkhKY35FEGKI0rK
         JbdprLbH7DwzrgRWXfA+6huzBL31TWpKtAtsMrLD2+YZFGbw4Ke0WnK97CabtCf2KMud
         RKQEbf5Pv/K+49RwfQphgxe/Fn7oZlmW55NHoIxXbKxeSLURcRupuF2GkS+RhIGr40Sg
         JFYlZUOuw6GgXsWUYBdjytZaxfF9kVVEwK9VlEZwhgzT/EEj7MPCfnkU0p9jc72ZxSEu
         pswi3Wp4hpwZQ/iW5C/VRY1jYR2fIN3IxKWi2nFuycoiTjHds/HypmhqjtYrzrrS01YX
         dwxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305K3RRMZ1EBtXWmjtSID6nYY35Q9k2KgetnQEjzCpUoJCP7CFe
	391ee12NWVGLj4mrp7wt1ME=
X-Google-Smtp-Source: ABdhPJxFlHSfIN8Hd1rRTWE1WViyQhtgFP0cRXL7VfDda37Swk5ouxkeDrg40XVr8oeL0NluqFJSYw==
X-Received: by 2002:adf:a319:0:b0:1ef:7cc6:d03 with SMTP id c25-20020adfa319000000b001ef7cc60d03mr17937923wrb.411.1646239074170;
        Wed, 02 Mar 2022 08:37:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35d1:b0:37c:dec7:dbc0 with SMTP id
 r17-20020a05600c35d100b0037cdec7dbc0ls2987533wmq.3.gmail; Wed, 02 Mar 2022
 08:37:53 -0800 (PST)
X-Received: by 2002:a1c:730e:0:b0:381:103f:d6d9 with SMTP id d14-20020a1c730e000000b00381103fd6d9mr517647wmb.46.1646239073443;
        Wed, 02 Mar 2022 08:37:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239073; cv=none;
        d=google.com; s=arc-20160816;
        b=IxexYhA12Nb5iZ+AZoxusMVfk94otN43NlNFp5kOMDlZ8QlTllMd0Bj6Ema0sHebu3
         sBD1/s4ZQPF1rOi5PVde+KSgm8PhI+4GbbDsQuumkJH660d1PQulewbOaxfh+llySHQd
         Joh29sYppicVpOW46p/3E93E/2iRbwLm3oAKYSnqrIEl8c7u28cL/OUQOmuTOWC6CEGr
         UKZ7xZcu5WiLX6zHpVh4BuCOtWUomkFNXWmFAs6DajdRsjPwLTExsYSybSIS/6C6fVjA
         6S6s/ROAgC8zzr9IHZOHH+jia8D8PFMq/JVDK8tgc39PxohNTFixTa+zoJZ/Ky//0qiO
         QCiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L6CSCTWOxlFTjCUaDQCg92iZqD/oJAA5cp+h5CudQM0=;
        b=mz/krD/OjvGvdJs48m6s4qo2TDkQno+CZmhD+n4w7Lgn1YVniOxaaesYTvu2EG4q9V
         ksP1hnxMXnMCAPWi0JeGwLc/IKuEtS7gO9vXhjQBl1GtNVcrkoTJsTmwXMVq+wXb/J5H
         DseKQt21cTIcSW8TOQIwEvAGniWOJqTu9FJgzBEQszKqcJN607woMIGIK4MJ08vHVB0A
         UIrMLNIp00Ve4sGmxFNwyttsyWAhfbRRVEqTNMMKQ3nA6sCw/I/mHX32FdR2iLbXWSGw
         hVrerB9pXO4sPe9m3pYf9pJNuXSrrM7Bi1dYuwpk3aTcCw2xXAXPtkws5+w9G8UZE3mN
         mGBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IEetNTQJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id h81-20020a1c2154000000b003819dad2a19si394024wmh.2.2022.03.02.08.37.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm 08/22] kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT
Date: Wed,  2 Mar 2022 17:36:28 +0100
Message-Id: <223592d38d2a601a160a3b2b3d5a9f9090350e62.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IEetNTQJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Check the more specific CONFIG_KASAN_KUNIT_TEST config option when
defining things related to KUnit-compatible KASAN tests instead of
CONFIG_KUNIT.

Also put the kunit_kasan_status definition next to the definitons of
other KASAN-related structs.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  | 18 ++++++++----------
 mm/kasan/report.c |  2 +-
 2 files changed, 9 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4447df0d7343..cc7162a9f304 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,16 +7,6 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
-#if IS_ENABLED(CONFIG_KUNIT)
-
-/* Used in KUnit-compatible KASAN tests. */
-struct kunit_kasan_status {
-	bool report_found;
-	bool sync_fault;
-};
-
-#endif
-
 #ifdef CONFIG_KASAN_HW_TAGS
 
 #include <linux/static_key.h>
@@ -224,6 +214,14 @@ struct kasan_free_meta {
 #endif
 };
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+/* Used in KUnit-compatible KASAN tests. */
+struct kunit_kasan_status {
+	bool report_found;
+	bool sync_fault;
+};
+#endif
+
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 59db81211b8a..93543157d3e1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -356,7 +356,7 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
-#if IS_ENABLED(CONFIG_KUNIT)
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 static void update_kunit_status(bool sync)
 {
 	struct kunit *test;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/223592d38d2a601a160a3b2b3d5a9f9090350e62.1646237226.git.andreyknvl%40google.com.
