Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGPORT6QKGQE3QMD26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 38FD22A712B
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:55 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id l188sf218194pfl.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531994; cv=pass;
        d=google.com; s=arc-20160816;
        b=c3UKVc52JiJdq6QO7O+buTOoDWhMfF805/r07kzmA9IO5N/EzGdo2ACa/Ju+N5PgoZ
         DNmZ6GtnceKUnYJhj5SdQWBpSUB+yNDt7Lg8yQEi91sP1r6oKnwZN9KyCVKqFqzComkJ
         /WqRpuVdTkfdM4eqGpyasz490zl98AOVFkqPLrePdxy8l6/0gr9nLdEmw6Do6B5fYZtz
         T0OkAwo4Ve+lkq8a8J2zPmox/1cl9zdvLG4QWF4eLiIjloKD3cjqfldlcN7l9yONDzQ9
         DdTbsbG1AO35C52kmKRa7B+NL00hsSwK+jowphihvz1tzjQMTnatbuCDyJ4WzIlugmSI
         3/fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+w9WUzXNSpCQOeXLCOc6x6bjgHRilS0G+038KrjUhfw=;
        b=elUknGS0R4T1XxAtysD9aVirE0SPk12Et7/L9sXT9aQr4hior13wSpt1KHaLmC/JXW
         NZD5eLvd9OuS3BwUJUWEwgls3lG1W01fATgP1AdfPTwfymMj+MmKidtVC0rcqQb5binK
         bP4y+P5AQJ7r1CZrOc2N7+GieNkUfPgYH2O9gpwfuZO44hA4eFgYpXht6L6/ZBlIuWo5
         K7rM0plh1drxdslim0TBOOEX9L3Or/7Gd5T5I3JbjsO/8siRWPYQnpz1XPWxOxLXiJEs
         +4RPD8cXxF3kw22PXHSmrWORoD0+GmFereGW4epPWNLhvLqQBhJDYAmjDn8UhFFgaFO0
         OO2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FBI115kS;
       spf=pass (google.com: domain of 3gdejxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GDejXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+w9WUzXNSpCQOeXLCOc6x6bjgHRilS0G+038KrjUhfw=;
        b=ql70UPNcgp/pVpvR8h8qBsIEExbhdli0u/+GTCOqQSI3mfPD1GIcwRGwyB+tU1hxpj
         PwdIEJZCsCqQAaDxrw6U75FbthI+RSDILm1bGdlxJGKOqzsO/C+sOtcZiORiymMgmsk+
         lNWBmQ1ySAHXLSHsLGOAn994wii3tnUFPR4Jy2qj5VWlgWVIDgUmU3VhgHi7jUczENQz
         SFKG5HRyi92KFKU91qJU18KUfB2EYw3PZRAsAL5w0vHJTVfFGjEaKI0qg7niLPNTd0tX
         HILrmKKvy9UmNQ/ef3glpyrrew7evqUNFv8W8NryAYqsqynkPwRPdkevYHuOgh8Rem4G
         6HoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+w9WUzXNSpCQOeXLCOc6x6bjgHRilS0G+038KrjUhfw=;
        b=KHzc0e/IHAMSaRMngpGkkpIXIF/8ui4Ac8hDJmFANJUNNaPwmp4Y5wWvlW51T51Y5n
         2kmlMKGkScMTw8+MmZE+RwnuZm2J4Sop0qOQzIEV9bfEIouJ68WC7YQjDP26lWF6vkpb
         BRtBsiRQjXnOg9ksoPHvamFGiuS2axjyfUUD9EREViiIaca38KRqU6odo0BDzzj63WFM
         ez+IGBkqQuiRuvGNv7ObGMgwU+LsCscy1/7ehZ5xU2p5iQyps001w8zakhQyoY2uCbhF
         97BDeS1+I7JzADbxVl92Xo271L76rz/fMTsnH51kWFK1r4Mr0Idsuha0Qphzc6H/lBR/
         3JUg==
X-Gm-Message-State: AOAM531/Db//7bXFr+yGc/c48wYSAHFRyHCB0fNetG6qLI6L5ZiZmSVe
	DVBzIsFhHlOABLCxXu7CjGQ=
X-Google-Smtp-Source: ABdhPJyTZe3S6pxGEgVWXR12HXbo/j74yffUAy7hOHhuD1nMhSyWUsCCOIbEeo7TkvPPt1ScbYBQWw==
X-Received: by 2002:aa7:9af1:0:b029:152:6101:ad17 with SMTP id y17-20020aa79af10000b02901526101ad17mr153557pfp.25.1604531993997;
        Wed, 04 Nov 2020 15:19:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f601:: with SMTP id m1ls340575pgh.4.gmail; Wed, 04 Nov
 2020 15:19:53 -0800 (PST)
X-Received: by 2002:a62:1686:0:b029:155:3b11:b454 with SMTP id 128-20020a6216860000b02901553b11b454mr139805pfw.47.1604531993487;
        Wed, 04 Nov 2020 15:19:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531993; cv=none;
        d=google.com; s=arc-20160816;
        b=gDK2F7jr1BByZsSXitbaFQOwifzW9H23QZGQO4HNIBECDQFCp0c3QdlULaYofrPR1S
         vdfi5AaNh6CD5MqZAvcJa5jKg4vyF1Z74p0H3xDMIszYK10KoGXSy/JdfeDC5QfxpmgC
         DAHdV982I5iBSSOXha7ky565ew1yzHud28jp6Eqwv//Gg59/q2DtyBJMHQ69PUkt+Dg3
         Wqf5vld8lWXaI3pOXlL9JZIzB/Un4ySVvx1Q3bD48O2++jHxALLZ9pKcE4K/XBAwvHlG
         iImwMgN2hswyKWZvkxuFnnX10ttwIfKYU2btruXsxMli07ToJhdxVlaGGYbbSMyk5vpf
         qeJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=71dDjA4AvorvAoOL9VJG2R9YWEBiYEDCkHWbAxU+l2Y=;
        b=y7YejdV2cNwuCaSUEiavoeLeVdt0bnhDKYgWxnwwTwNtcoUiJcSAOadMywY56u9Oo+
         nGkCf1eJ8nTzVler50XypLHeXw8rGNCUrbR1fO4Ybic7b7Jkbf5vw/6wh7rzptkXU8lS
         eNwbsmnzgo6xwzZdqTNBxCffNb3qr18sbqSk/gxslO3BqSXAKyRegiPiFeET32mERi4b
         nl6RRBnYPXIdhUR848agVXdX0NiyuAaZD3HKy5oJbA21yWqGLBRb6MyDWas6pygjEjRV
         TGpTu0/FKb8yN+1j+99hH31gkmHAKb3nMC9bJ9P1u7FYoTi5m7xFt5bBqJsGlGFG58G/
         4YGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FBI115kS;
       spf=pass (google.com: domain of 3gdejxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GDejXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id x11si191600plr.2.2020.11.04.15.19.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gdejxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q19so4754qvs.5
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4512:: with SMTP id
 k18mr256501qvu.5.1604531992636; Wed, 04 Nov 2020 15:19:52 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:34 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <a2c72de4f882e748698bebc25e45f08b03ea0de2.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 19/43] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FBI115kS;       spf=pass
 (google.com: domain of 3gdejxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GDejXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d0cf61d4d70d..f9366dfd94c9 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index af9138ea54ad..2990ca34abaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index b543a1ed6078..16ed550850e9 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2c72de4f882e748698bebc25e45f08b03ea0de2.1604531793.git.andreyknvl%40google.com.
