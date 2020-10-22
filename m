Return-Path: <kasan-dev+bncBDX4HWEMTEBRB44NY36AKGQET5KKBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D388295FB2
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:49 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id q4sf932905plr.11
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372787; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z23hwhHAKZCrjIHFWwjEx18TAQXnaq1f9MY+5XNMhAP6UTnanykkRsvrA8dCEmQwEJ
         s7fJNam0hmWeI2HP4bXmU8qkFffjOKgM+tL7B0yuIkwdrMkvJpYvjBxCZRS/ZxnjFyMS
         5RQfjLb0ElacET0xfG/XBgQsIjn6/o9ElW8WZzjobCUgddVJR491ZvkhVcnauRZLPzmx
         uEcRRglpz65cIK3ZVuO1VtfsY0mDCHhNSWpsHAwtppnhmVqpM0/c9Iq/9by2W8D8vfNE
         E0IdpwLmU4s/J2G+QvG9YdDPI5LPvcAkIa4Gh1rL42M/symo3nhyM0o3xDQSwa567j3p
         fIkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gI3GDPvVafxR12LjsuLuXxRg/j4PLx2vVCSqgbXiBqg=;
        b=CrmsI0YTpKHniGCvRwFqJC4kUnRApFIWXz3sYRMje2OEcvqLRK/PFydweEBqEPCiPX
         Tp3IGVtgyY7D5vMBS35SjJwhmi8LMJWHkQU0QipYXsXmfBZ7/ERZCRTmvtd5RHxHxKVZ
         GhQg73iR1QgqqI+96IDEUziIm4cPULXebs97jLHd2igHQ1Z1k3CYOSgtk6qn5UvfMHWn
         NYK2FKI+wIqIAWSHo2ah83YnRdNJqM4CUe2Kr4b39c+fWFARpras4r99lNotNLdk2p1z
         O2O4P4nbG0R4JaFg0eAxZBpNCV+YCPWd1xDCLhr4tkWmDJk3/ZhkJcD3CLGhf3b1RVW4
         tITg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FpiS6ya9;
       spf=pass (google.com: domain of 38oarxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38oaRXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gI3GDPvVafxR12LjsuLuXxRg/j4PLx2vVCSqgbXiBqg=;
        b=R+y1yIkSu5oBOjVQCDsHke3vEAkcRi7qrp9wZIlh+f8RXY0H2iTN03i4C2D9PxcMmP
         TTSnafPZlzzRw7Fg6gU/SOODhV2US7fH1n/2mRE9avaAEEv+szn9HlTPfFQcGg7ZzsGT
         YbyLLQtKOTKVBKmkdT6WzQmQgni0bDoEnOmc3pMyQRqhFbSFbTdorYH0awvSs2qSfwYy
         X5lZOksKsYYrOw1yatnODWdWEs9+/3u5wPJ5Y3X4K7Z1LIr6JjICoXiKXy3kKmSKDdnI
         EvO0GmJs1kd2MOK8KRZ+cWtSO/GZkwoQAhX970lSGNDZE7v0Of8DcFhCzQGLPkBBSzIm
         N2Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gI3GDPvVafxR12LjsuLuXxRg/j4PLx2vVCSqgbXiBqg=;
        b=D/zt0XlqfcT/9rtbot50gpzLH2ZSlqSj0omQNmvmEPFDBcug0tgwr9+PJlI1Zzvfcz
         bXaial9L+GosPdPpZY7Si70oR2xVFtRw88HVzYtWiuVZ2bL1U6d5xYlAHK9kdux0B2Jt
         Wgpu4W5vaHzPaSu94Jxnlw+YsBsr/z81prqJspyDyDYDnmFfYOL+WaTXSgTKp7efjMyJ
         WsnX4LlvHjQ70U4VMx+Thczpq1Sq/W7lOiAarWW4PcMhFdC+npUhmng/9Vcl7synwS+D
         H/m4ilYHf7V9Ils8AIKvub7NCgGiDxLmkfdXvcjSpzbmLZ4hCbxiyqQuJWnk4+EOQwP1
         L3EA==
X-Gm-Message-State: AOAM532Da5lT3cg/n81CiUxUt2LsSQNq3c5MCcje9ey5QSSO/ZbvbHNw
	W+zOSTAwygeHvGAd6Orj3sI=
X-Google-Smtp-Source: ABdhPJyDWKiKRgCasCyLZY+bFo6AxyRvfHVycvyLRYSORB8oHSyxHO7/LJg0JuLbEWolzC/KtDKlFA==
X-Received: by 2002:a17:902:708a:b029:d4:cf7c:6c59 with SMTP id z10-20020a170902708ab02900d4cf7c6c59mr2690298plk.52.1603372787768;
        Thu, 22 Oct 2020 06:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca16:: with SMTP id x22ls950599pjt.3.gmail; Thu, 22
 Oct 2020 06:19:47 -0700 (PDT)
X-Received: by 2002:a17:90b:f8b:: with SMTP id ft11mr2471210pjb.88.1603372787153;
        Thu, 22 Oct 2020 06:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372787; cv=none;
        d=google.com; s=arc-20160816;
        b=gsc8v9+R1pwtBTy4Qqsm5eKmxgI+xlpQ2ShXFDeTzUKB8kXu6gLedaUq//CdDpIMQn
         8HrXOIHx8+4HDp6ut/c8oszgJuSzDSow5eGHQMZMgSphDe47IK2Ek/N0YC7ERkimd3pz
         L2sAKA/QTlc04gzDdCoZSvJ6XUOIsKFtuVvKSRae8cvadzLAy2/Yo3X20f2KbmC5c/Jr
         +oOxLoV46wWVfahyC0SavX/SFslGKY6TVYTE8546uB6EHDEsOKdC3Q6jXlpPx89/1KFo
         p/ScsuDMJabe8dRt+q8qeGUycpkXu4P/7m/eBxiuDiinVBSmbXXQGxZzjc4a/3ECPAJ8
         fbug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2LAxUi3Z+b/LyEBabYwH/SVI831szHE0G1gzyusivfA=;
        b=dKUPIONvG/9Oo6SyfFBBIRHv1nboEfM1bhTFJdwbVsbyQ1oXBFZcLYAYm0fUel5Beg
         qnC7EoFp2gWQynpLf7g4xa2qMR6mOVFHV8sf4nN9E9JqYoPYIRHd/2dH0iJCxjOI0Vh1
         esGZDC69fvuRsgcoT4FpUBfpfElttbFON3EA05ppRCgfejeY0zkyWj+09oiG8DFTnfAr
         xdfYlYEfTsi/SESzC6fzVXcAP0U8KQQrX7bcBaiau4ATGkgEaPICk/ZmLjIe0N/f671m
         wsCtFGFQvgCr8QHjKQhmeA+GgCqSmJ8tGHDnwb4xvrzEQd21YitOdcqUUJikhfX8Ygr2
         bv+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FpiS6ya9;
       spf=pass (google.com: domain of 38oarxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38oaRXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id cl2si116410pjb.0.2020.10.22.06.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38oarxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id b7so989183qkh.20
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:45ed:: with SMTP id
 q13mr2255535qvu.55.1603372786206; Thu, 22 Oct 2020 06:19:46 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:01 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <b75b7fe2842e916f5e39ac5355c29ae38a2c5e0a.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 09/21] kasan: inline kasan_reset_tag for tag-based modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FpiS6ya9;       spf=pass
 (google.com: domain of 38oarxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38oaRXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Using kasan_reset_tag() currently results in a function call. As it's
called quite often from the allocator code this leads to a noticeable
slowdown. Move it to include/linux/kasan.h and turn it into a static
inline function.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
---
 include/linux/kasan.h | 5 ++++-
 mm/kasan/hw_tags.c    | 5 -----
 mm/kasan/kasan.h      | 6 ++----
 mm/kasan/sw_tags.c    | 5 -----
 4 files changed, 6 insertions(+), 15 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 93d9834b7122..6377d7d3a951 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -187,7 +187,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 void __init kasan_init_tags(void);
 
-void *kasan_reset_tag(const void *addr);
+static inline void *kasan_reset_tag(const void *addr)
+{
+	return (void *)arch_kasan_reset_tag(addr);
+}
 
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index b372421258c8..c3a0e83b5e7a 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -24,11 +24,6 @@ void __init kasan_init_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void *kasan_reset_tag(const void *addr)
-{
-	return reset_tag(addr);
-}
-
 void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
 	set_mem_tag_range(reset_tag(address),
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 456b264e5124..0ccbb3c4c519 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -246,15 +246,13 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 	return addr;
 }
 #endif
-#ifndef arch_kasan_reset_tag
-#define arch_kasan_reset_tag(addr)	((void *)(addr))
-#endif
 #ifndef arch_kasan_get_tag
 #define arch_kasan_get_tag(addr)	0
 #endif
 
+/* kasan_reset_tag() defined in include/linux/kasan.h. */
+#define reset_tag(addr)		((void *)kasan_reset_tag(addr))
 #define set_tag(addr, tag)	((void *)arch_kasan_set_tag((addr), (tag)))
-#define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
 #ifndef arch_init_tags
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 099af6dc8f7e..4db41f274702 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -67,11 +67,6 @@ u8 random_tag(void)
 	return (u8)(state % (KASAN_TAG_MAX + 1));
 }
 
-void *kasan_reset_tag(const void *addr)
-{
-	return reset_tag(addr);
-}
-
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip)
 {
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b75b7fe2842e916f5e39ac5355c29ae38a2c5e0a.1603372719.git.andreyknvl%40google.com.
