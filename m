Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHUT3P4QKGQEM2HUG4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D98C9244DC3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:59 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id h36sf2681952pgl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426078; cv=pass;
        d=google.com; s=arc-20160816;
        b=hTbbtVZlGmriqWoDiqDCU33OoyWQbOY2osi6aq0Ys3koPRySK/XzzERUNUI8bzg8jg
         GbzeDFbaC/Va+K9D7J3NZdVwJtTZPM1JMUO8J2l+fqeTpX5LYrm/4352z26mVf2wsEw1
         5GaKrhCoseqQURWjaL6mr8CjBNT7njiEtad5L1FQBtrl5HWyz/6U+HX3kct61BsiTrDT
         VqzvRHB690XwJJCirmpRwY0Ksrepwz1suR5F0BoUokBCWX2j7hkWjx62AxYGd/aexWPw
         wUGo6ev6zbV+aNg3Bq9izsGYc5Qpw6n4cNeEYDztBSZPyHnevCh7epkAhNQgPmcEDnth
         KLXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OV/b0JP4q9j2gxZ7KIm4eWaSZdJosXN2OoF/Rf3Fdi8=;
        b=EjN/NLTXDEoNHlWlKLUOtruI621b/F17lwNyhEjwy1yKr9+0EWAERYNGh9OJcwglxO
         6GfW0MSyVR1kzSlzE/+epyWs8NPp0fS00tsYyXjzo99rNiasGsDiEqXG9WTZda1txNNv
         7bgrgXvnOCWKKOreSV93ACw0/v05SIyJG6kBpjGOF7gNsHkOcRL8BYacmU2L7y3hJhTE
         skfQsxtNC6ciFbrQosBKjcqVX8Xvb1ZxS0ZQ7wbTnlj/maShOuCmiWIOwstJxO827mxp
         OuEDA6HM/rF6VAQi5E4md7+7Z+mPNv2pRk7ils2ZoDiUhjzO1QHNlZXulDvvplpv7Xt3
         xrNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DrFj49N6;
       spf=pass (google.com: domain of 3nck2xwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3nck2XwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OV/b0JP4q9j2gxZ7KIm4eWaSZdJosXN2OoF/Rf3Fdi8=;
        b=PqHT2zGDvr1Utsa3NoaNYRSIZc0wGp+iNGFz4CUOEeEa/jcj3Qb7W6dO0KUk3S/eYc
         UfUfAK2Fy/jekMkvQXtEgkuTvhCvfF4m5I61n73xqSTiflGelekhRaVLnne9L3K2SJUm
         pTQvOuK3URaKdnY5gXFbTBU9t2d2OuvO/2s7/QAtsNEbGLzpCb4GGUXhqVhtu/FjiJH9
         fOFv8ULq4r/PMF0s46DzEDQLbbWt8DvJjxnR8s71HBmK4vb16/R+YsmRyXc9orpvCUiL
         8s6kkSnSmks48Mr9unnrhY5VRnk6TUtmMbbchI4zv9qGsWSxqEMzx7Q+9uQhvKpFEmkj
         OBXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OV/b0JP4q9j2gxZ7KIm4eWaSZdJosXN2OoF/Rf3Fdi8=;
        b=rCM9ZFJrdG3ixO9eFBJgmQNowQZZ5zrkiH+4tSxquX+GK8bxLDMAFPRVGHvwM3hjit
         Zu2x2+l7u4Sa9J9JLD5ZNQMzXGosZORWu0vRcbweDlOYKAUxy+OopuPVblDv+EZrPu0n
         2CYNKZ7o/6FQP016BBd/Y2ULJ0Nsg4oyKLcOxTCG8BC3OWlfXlBx10H+q4M6KsFDVRsS
         1BBA2XAiZnA+cJB96jq9ckejklLYmKnwjjVQ4yymOljtLO/jU1KujABF+yf0kTOentEb
         LsWIeVjlfcAwACXcLEnitZ1KdrhqSDLEP4lNG6twHrmue/pMspfgBr9Vh8kpqBCN4DGj
         GKEw==
X-Gm-Message-State: AOAM5318NX9v54I1jfepd0Uuumme3uCiB0n8BiOt/gECfPzLb8Ooieow
	nvwbsRkCdda41hQUso4AWGY=
X-Google-Smtp-Source: ABdhPJxO5jcxmc9CGd8CDP9imArl1SH9y5STt/bybEsu9syYMHdh2LD2x3dtdyEpBLir1ht8mV4LLA==
X-Received: by 2002:a17:902:7d84:: with SMTP id a4mr2747465plm.44.1597426078587;
        Fri, 14 Aug 2020 10:27:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f158:: with SMTP id o24ls2683424pgk.4.gmail; Fri, 14 Aug
 2020 10:27:58 -0700 (PDT)
X-Received: by 2002:a62:18c9:: with SMTP id 192mr2486179pfy.23.1597426078168;
        Fri, 14 Aug 2020 10:27:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426078; cv=none;
        d=google.com; s=arc-20160816;
        b=ImJ8pk7egGf3uz+pg0Ay3Ngv6b+NWeXGp+gLb23Om9GD1VvfCMkw9J2du4n41ldm2g
         vOd6LUbDiAzpjDOpNtiAqNIf6Yx76WwBFPiMfp4IA/jUtk8TQGP8wPLYahLhB51TCzka
         4s90cHFdoaNLxWhnGJhjZ4pjIfFgeBB4AUQxBWEq6a48XhfW2brG3KNffTo2WX4Jjb/L
         ml/mWUnjNBguFMOtchg0XHarrTM1XjW+EbKHi7lNwMzHsY5SdL6G2b167mA81hoUEKg/
         YF5Rb/3CC3eCaLc/iU00uV5LNzYLSSx7Lms7FDMkdHPhjrGYdI9Su7yh2mG3u/k+MqAN
         DhtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=uzelTOrZuAbTWnllhx2uagoa2R4S00LwGFOB2texzaA=;
        b=kiFe/4EZBHVaINcXVLAHLkMVXH05gGeCdRxvQD0aX2W7KLwyvQEP2I4+T9epkxkjeV
         n+yeqE8H6hDRu7P4KDcKn26CGlrJ0QBVzFne6gt7gbBmRm6X2AeG0sdG72bf5IzU8Yrl
         qqvfbI0+inx0szdZQqr3unRBjt70hzZYPwXRNFXvIxDNEmCacRqQk0bqXBpNXwqlHy6r
         jUDHu20HgiZISmAiqEVHGOA0Uqe1EPXt1xdfdHvtQwauSOQwK8pIH2oIaMZhJpm9+DaA
         7RdTtsWkh1NM36XtaD+fn5zQNNTrSHA2jv8uURbA4YCYc59oamERntML73xAIhm3aea2
         JcXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DrFj49N6;
       spf=pass (google.com: domain of 3nck2xwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3nck2XwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id n2si585616pfo.5.2020.08.14.10.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nck2xwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id x4so6481311qvu.18
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:58 -0700 (PDT)
X-Received: by 2002:a05:6214:8a:: with SMTP id n10mr3654847qvr.13.1597426077265;
 Fri, 14 Aug 2020 10:27:57 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:56 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <82cf4f8007645f8c45e6e4847a28a743dfb9cbda.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 14/35] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DrFj49N6;       spf=pass
 (google.com: domain of 3nck2xwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3nck2XwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 15cf3e0018ae..38fa4c202e9a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -145,7 +145,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8463e35b489f..ada3cfb43764 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -334,7 +334,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -345,11 +345,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
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
index 427f4ac80cca..29d30fae9421 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -122,7 +122,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82cf4f8007645f8c45e6e4847a28a743dfb9cbda.1597425745.git.andreyknvl%40google.com.
