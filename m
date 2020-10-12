Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAMBSP6AKGQEHKCXYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 86CD428C305
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:54 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id z8sf6091086lji.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535554; cv=pass;
        d=google.com; s=arc-20160816;
        b=rjouUqU9gnH77wUuAs3d15EsY8l8kd9LVBWstkYCKik2Sru/4vE93ycULGD6bI71up
         K6hjNH4kvh+Myg9eSUleFUo0vZu4UHSk7/V7TLZmxj/zGB+BKxntm1ju9afI4Yh0pBV9
         6wiVJqQcJgliosb0tZiBQDhfc7xxzsP25Dq7U4jxZpfCZwbm894ob6JNT6QK9YAkRoXi
         chWQpkre5bFG/KuJd4U6erLPG993TshCeji83ALzNgiqzL0fVyQnQ+sNMCShiDt6z03R
         hCVM5KaLrFxd+NwTxPFLtCnJGB97rvvRvXpLmzRdwhBw50B98ldzGxEUrueTHSedcoCe
         SZMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SixlMzESIdXz1sCrmpOAHH+6iUKPEzjxF/3ggkjd2fA=;
        b=HM2f8tKFYigVcPSY2SCQ3oFBAFtiYUWbktbubpRWu2eq275vOJkhPBuJIq8Prjzy0L
         HoVSHg1rWdleeRyGUG4C0Zy7shMr5vnVSfnpqgkhB3HSoaxKs9F3tQ0qYhAryBII7s7v
         kTy9+vou3NYM50sezrTJA6hvUDQO9PMT/2riOKgJInS/LElJdrpmtoudqiuVEpTethAE
         4s6akkLx+d5X8xjszgrGrcxGMhRfKZ7wqqu7PQb6taMOWFlopLWIXRwXruMGVX0jx2RY
         JyDRjhTVaUA20ef6LCxpJMVAXrIleMgVeSZFKOfvVZLD3Gf7fqYOiV86uRVaQA2rVbJy
         eP2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XY3o8GYc;
       spf=pass (google.com: domain of 3gmcexwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gMCEXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SixlMzESIdXz1sCrmpOAHH+6iUKPEzjxF/3ggkjd2fA=;
        b=bTuR+u71JDu8pamHpm2YU9l94c6hwbyjT+VodTdB/S5LhzE3aXTwOVPMcRyDaeRjbu
         4O1zjUmGETAwhgsGEvmJIx6zXhJQIB+vXVYbfMJs20/Sty1WDet55KRHvIIjdBUW95BM
         Ah+G7BpT/KWG9J4VQBHMcJ/ajYPrjXGC4CWf55oQSWGjoQgXUjDTe4mpLo9cmVDTB5Bh
         bt4ru0Z8U85q7gaXzqOeZAus5TzPs3eukowLGMsYX2tMrI1t0PZR05X6TQGJKIUQEPu9
         G8F/3pUY2vVTLSq2tE5UnjZiOU/KIT2TaS13BdI9uIdaUSDGLqfyxnZ7o56yJmhzg+xD
         eSDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SixlMzESIdXz1sCrmpOAHH+6iUKPEzjxF/3ggkjd2fA=;
        b=IBntGV1dCjNgFQs6aVyQmjhNcH7rpeMAmHCiaErSCx7mWNkiWn6mOtgeGH42fjYvqU
         wTe+V5B4u3gkeF4wG+y7Yd085lG2bGE/1O6hGXPu6/9+EzilU7vHINCoVE01PaSh1BP6
         HNgT99bfl7xiDlNd4DynlBhtTwaoifJqeMPyqUDa0WCFrzlyeII3remsgdOF1yG7JsWG
         fHeEF6xXhsprnKMig+M6qNjHOA2AVk+6g3wN8RmBTHM5voTktqBFx0VbMH8nr0N0jEGk
         wRZitAHs4MLmoRgaaELZvb/5KiB7v5HX9l90RVxm7t9ZpimEMOlHkiv7dTt/tx/m9nzR
         364Q==
X-Gm-Message-State: AOAM533JEIGqBKxlgcWdUFaU1C/LsID2A0QrWoFpcE8vPrf4t5C+IF24
	iJBCFUba0Z1ehJ0vrU5ZlDg=
X-Google-Smtp-Source: ABdhPJxTIgTVg/ves1W8HoN04rv6P+LZSYy2uVZqncw+OuMnVkH0ftGR3Xr63MtOLzD59o+4Oz/Zmw==
X-Received: by 2002:a19:c1ce:: with SMTP id r197mr9493639lff.266.1602535554066;
        Mon, 12 Oct 2020 13:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:804f:: with SMTP id p15ls3023156ljg.2.gmail; Mon, 12 Oct
 2020 13:45:53 -0700 (PDT)
X-Received: by 2002:a2e:8194:: with SMTP id e20mr11612702ljg.405.1602535553040;
        Mon, 12 Oct 2020 13:45:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535553; cv=none;
        d=google.com; s=arc-20160816;
        b=bTzdXeA4a3xFjYGf0YSyHfr74OgYKxbuXEI0E/swq220y3PTnK9mm6z89Azl0n7lpb
         8DyIRZIC2/tkRDWpFHo9jtQLlYX4v423Ng9kz0YtogYZcjBqPJhvi2sLLe9PK1FUtUDK
         ULeeVtzlydP6tzm3CVz+V6EpG0ZxEjhVPxOFGu8gOmeo+3dMKffsgspL4hRT8KjQJ/+7
         XIPI7ojNU5PXUILjZGwseuxRBAEyDPv3VlG4rQtaDz8Gny0PezjERtX3sZQHKEDrimmt
         RV5Ht5qbkNNIWeGgLTKCBjEi5fcIueFo4bNfvZa1eSWhYI3jDzn7PhwsspiGsIynrfAV
         bm2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HoLd9axH/k8QQMpteaotxwKQuIlysE8DbXq7dK1Bu7s=;
        b=f7MALnyRpH3AOV30sDUOUje2SHrpnrARooYhfCh9Vt1TKRyom5QGTEs9qkFuMqUkeM
         2GkF0kVBPOaho0fOROhsCJEPgojfKwk0cLtHn/JwFEjzphJNrGtgZgYOBbiuOX7ABGwW
         /lazFxG5SOl5h3v0/3RZOi7nw4jYiA1fwhzTz6CRhQdu+FeWnO/Y04kRbgLatSyMnsVO
         u8qYmX15fM2XaCKu68BHCqP6LCIYPRhK/Nim53goZNPM6au1EIpLVb0nMIUq8TaDltgO
         qdvYWbn1xx4MCjWcq1gQ14WesXP+KtYcIZMoCru9shZO2fGIXPfSx9cFIMWKLsRC8AQ4
         3s9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XY3o8GYc;
       spf=pass (google.com: domain of 3gmcexwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gMCEXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c20si328384lfb.7.2020.10.12.13.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gmcexwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so1610534wme.8
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:53 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6488:: with SMTP id
 y130mr12073548wmb.94.1602535552445; Mon, 12 Oct 2020 13:45:52 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:31 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <21b75a558884793bd6fe13dc1e0a263381b2cf82.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 25/40] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XY3o8GYc;       spf=pass
 (google.com: domain of 3gmcexwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gMCEXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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
index 5a69472eb132..420638225c13 100644
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
index 91b869673148..145b966f8f4d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -329,7 +329,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -340,11 +340,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
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
index 42b2b5791733..ff067071cd28 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -117,7 +117,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21b75a558884793bd6fe13dc1e0a263381b2cf82.1602535397.git.andreyknvl%40google.com.
