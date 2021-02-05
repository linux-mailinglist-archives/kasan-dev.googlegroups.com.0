Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLON6WAAMGQEPPM756I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id C45A1310D3B
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:26 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id y79sf6129906qka.23
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539565; cv=pass;
        d=google.com; s=arc-20160816;
        b=aFSR+I3G77zIt3URz0bV15/Iu1/gaLMTebVUqMNuvmXkZutiC3JTSB8seDncKPYOsY
         CmW4TVgn5M9rVHuRPGsUlvW+/Hx1gaR4MAmTxjpwlk7OOiFXzaKJ9YtQ9V590LwI7S2Y
         GboVglhBz73oEa1o1vIhuB2uRybnJUn/C7cJZQ3c5x4jShdMCrJ80KezywmALIJQheao
         1I8QaK52h94PZnO/XIyQqHssXk6JVQr4HjL5Onp5m7GL8im6YHupm461H+rFBfrMG0BN
         u5PC/JTZ5Hu8apOcKZnWx9PF4NBqSMouWnKdl2KbaVbe5Q7IPME8rO6K8Plt19t+hNnf
         hJ1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4gKaK+F9PUV0PoyIm/Mi555z1zuwhCifR8QGx2JxLFk=;
        b=ijZEF1Ch3/06kXa6DmelHKUBTF9jYJjeFc7x56rG7Iuh72cnUD0rS5F42BIdFRv398
         I42Xs+z21u2lAi/6JMtfmLAgmH1ptof20d98QQ5GiMAjjPsfdUQBtMjos9RjWkyX7Tir
         ZJMjDwrkcAR2hE68oxTew/sNB+XUCNTPxHktjkOd52gxyALSnHzb6a82n+0GGqlhLXQ2
         UCoWN+y9A8+sM4IGx2KtZt6Ax3yB3wSjfzJTxBidw6pq0Z0WBgX+jmrd8LCHh1Jkg2Ae
         jh4S4VELXzLghbd1iCqGD8kEGv9SgIz9xbsjMbivzIlJB2s/wnMllirRw0hi1ZcU64DT
         TgWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=syVSGwpY;
       spf=pass (google.com: domain of 3rwydyaokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rWYdYAoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4gKaK+F9PUV0PoyIm/Mi555z1zuwhCifR8QGx2JxLFk=;
        b=rv3uzXN7d9hPeg/I5+ZNV7sgGtD+KTcRxEOcljltZSK9HraX1nUFNoUQyuYjA+nvlI
         PW7yBiyJTrE3roWhxRlw1aY5V64zmcuCo/jYD6cP4tN1k6umDW2rDeIzkizRUy743UEx
         yjwUHf9v3zBuoI959edymHrwICAduy3quUTwynhC7O6is1MYOvH7+fx+sNsNDA9BFx7E
         GjLAj7xQH4oqk09lhf7Dwv/mSiSJ/m8CSj6oTu5a4IGrP/KjnIAwSkGSCWtNkXMTltt8
         MyPwGjgLrAxJxeWYquQ/7EK/IWn/dT8oTc8O+mF2H5dOMCJr9obWYx00hsZt/s7dtEfI
         v8Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4gKaK+F9PUV0PoyIm/Mi555z1zuwhCifR8QGx2JxLFk=;
        b=rFl3zo7FlydAdqnCg3IIkmzYHMvaTrAp0YxupNyzEsUj6W7QIrELTqoyIum7sXwC1g
         CwAfFrbG9xdLW2VHQwEWsQAdPnHyrmrk7/V4iHeTp0u6hy6IagnHqO8GyB1hEGOljp2g
         tk2C3XSFMpHqNFAIN1yyGVoCHBkNejRsElX6gEMGk22ammJg6/sbOPu4V3Pcu+NAYK4S
         epDrc+F6uiNWkT11oqGJSM3G4Hn5V4TO1Xw3U0SI/ZbT6JJRrrBab+aZvONdTcTgGB7G
         zCS/SRvtzj/uG2QPcHz7ihFPmmHRjFwg/wK8FGyxM0auIqNzHuc2vyysyXjBKPpcfPNs
         H3fA==
X-Gm-Message-State: AOAM531TXHVxj0AAeFWPkC0GAZEwurdm9X3tgPlqtSBsZsgiFBJ33zUE
	fSwsLn4ENjuXksdibm26os8=
X-Google-Smtp-Source: ABdhPJz5wLrRJ8NYq1Naz5F5clxHWatjCMolB2NnOnF5nCRUAIxoy5eMuQYkz7Tstw6VufD0NfFk+g==
X-Received: by 2002:ad4:40c6:: with SMTP id x6mr4804605qvp.10.1612539565824;
        Fri, 05 Feb 2021 07:39:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4cc:: with SMTP id q12ls3616381qtx.0.gmail; Fri, 05
 Feb 2021 07:39:25 -0800 (PST)
X-Received: by 2002:a05:622a:453:: with SMTP id o19mr4767429qtx.344.1612539565466;
        Fri, 05 Feb 2021 07:39:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539565; cv=none;
        d=google.com; s=arc-20160816;
        b=0s8CdAmh60RD4tEWfw1EOsQxnpFwevZsknjBNB3CwT4GQ0/C2aQZTE5/xAwklMVJ5/
         F+Q4/QAtLS52GDBqnU8c0JmJqKnFOhgF/NlUR25t8umXB/DGrRYDpOQ71CrOwDhObRgC
         nYb0FteVD2THFVSNmKNVr7D98mj2R4f84cZkd1G4027PYPGi8AqTcDPjCJodABQZ/bSj
         MD7v98Mf0yNwp3NJ9aSD3PvdFHHh8MSHsjyS594Mv8x84NN0OVSBwEoA0PREgcaOwXOg
         dfmS8sg+xjELVBDs1+QlM7oUcQdASFVM5ZdwLLWpf/b67xNv5IO2xv2v0jwFqC6xQlvE
         8JyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tljlSxhBzcxqidAVSdVdhM6oUJ+nJ3d1xitEmX2Ppf0=;
        b=X8BfZNvf66KwkdnPRuLg4HMUL3E3TlSG/EhBOxcpotKZyVnJ/RVC+/34vGMlvk9h2H
         Kv0zBDeWkCEDtQ1iY1uqYJCFbBeru9ahthe2/uLSxt93srtKV4Q/5oGU3OgKYXIgiPwz
         KE7pkb7fOnFe7uR3zU67hNUHULNLHr8K4VBY9KJGwVJvCBPxE7bLfm28w2KiBMGBApvQ
         vDDkw7dqMp3boVSCC86xTcu1gxbTwndxSlxRg7s31DzgarjOaylZVuxLldIiXOmGdEbr
         ECKCMJf3HetMXyXj+AOVE8BuevpihK5Ac4PeaDTceTAU0fQCmYnf433/PNRYLanPq6eI
         XtKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=syVSGwpY;
       spf=pass (google.com: domain of 3rwydyaokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rWYdYAoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id m8si674781qkh.4.2021.02.05.07.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rwydyaokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d8so5279857qvs.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f94a:: with SMTP id
 i10mr4890478qvo.22.1612539565151; Fri, 05 Feb 2021 07:39:25 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:04 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <97581e50e594596e0bf8dd5bb3598d5e13013f18.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 03/12] kasan: optimize large kmalloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=syVSGwpY;       spf=pass
 (google.com: domain of 3rwydyaokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rWYdYAoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

Similarly to kasan_kmalloc(), kasan_kmalloc_large() doesn't need
to unpoison the object as it as already unpoisoned by alloc_pages()
(or by ksize() for krealloc()).

This patch changes kasan_kmalloc_large() to only poison the redzone.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 20 +++++++++++++++-----
 1 file changed, 15 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 00edbc3eb32e..f2a6bae13053 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -494,7 +494,6 @@ EXPORT_SYMBOL(__kasan_kmalloc);
 void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
 {
-	struct page *page;
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
@@ -504,12 +503,23 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 	if (unlikely(ptr == NULL))
 		return NULL;
 
-	page = virt_to_page(ptr);
+	/*
+	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * alloc_pages() or by ksize() for krealloc().
+	 */
+
+	/*
+	 * The redzone has byte-level precision for the generic mode.
+	 * Partially poison the last object granule to cover the unaligned
+	 * part of the redzone.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule(ptr, size);
+
+	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(ptr + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = (unsigned long)ptr + page_size(page);
-
-	kasan_unpoison(ptr, size);
+	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_PAGE_REDZONE);
 
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/97581e50e594596e0bf8dd5bb3598d5e13013f18.1612538932.git.andreyknvl%40google.com.
