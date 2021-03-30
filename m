Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3UIRWBQMGQET4VW5EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 091BA34EC7D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 17:31:59 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id w21sf5612614lfk.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:31:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617118318; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jx2X9LBU770I+xmk+7gws3ZAI6to0//lPDvVSB6DnijqnY5bZnWkq1OQ4uqJuKqAQy
         vvHCe9MPgRFHMGkW1WZocY3fRuDeh9aqerK5gmML6S++whIL8Vge3LMea71qeQgwf6vR
         E5DqxvEQ42TRDkGZ4Y3pQYVvjiGXrmCaR45EQilTZIlGL9Li8lS2HeBZeYRU4NNI8IZD
         U2kmSKKfWfC/w633Z7EHULUYUYvTnrjN2EWI3BfEOOs0damAs8uCnP6+Rsjq3OMK/LB4
         lIfF8+9nv8Y1UI4IRvWI+M8pPE0JMLINo/g3TuxC7V1t5ba7nfU5AZxznX+UOwsZGHcl
         7zBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=j2VDq64hCmb0PdqvjEgPY+veWyNVkBbnH582VX3VFqw=;
        b=nUtWDpjp1USN1Aq5qGO9iFOCekiaEYPoViF9HaC+bxSGEGDnfixRcpuSOSb4tveeZK
         7GVoPyNIEARay5mep6+5yAkW+f1b3tbth9UGWMsMX1cXxlRb1BIMT0Hblnb1y7Vww1t+
         FNK2jbv+8RUMETlS/v6yR6vJXNKd+eaiYXhgnqtdK/kIbjM5R4mkFZ2HIMEzi9UYQzzs
         ItXUOT4WBk0Mj4mo+TTEvFjeONvVLK1fiBLSY5HUW7ugvYTYvstfNH3nuQPpsz+TE4r+
         yBz+PtpuzEkGAMq488nSwbSV5FG5Hwh7DUANeaZRELBUWY1j+7cMbnB3Tcu9CcgldYpI
         433g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTB5eRLt;
       spf=pass (google.com: domain of 3berjyaokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bERjYAoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=j2VDq64hCmb0PdqvjEgPY+veWyNVkBbnH582VX3VFqw=;
        b=nodVmgohzLKC+8prUYFI6MaVCJWmvJkr9RXW5cHJ7xfjlA7XV2IbxvTPxyPSlz+Cny
         3ZwT6///8Opo78UBsWCl+WJzhkgtpqDbhvLq9iUOw99p3WKKE7X7qwwovnCixEeHWTQF
         Y4pKr4aNbpgLTZzjZumvIQKCAoUEvtqXVu8rPgv4ubGucbfEwyvAX9g/RYys8chNyKRf
         7gIQUcfAIt9U6wckNlsAIDBqS5Z6Ped/tgsD94o2ULyryexsaQtnbY7v7Rfbh+Fm0VAK
         MNQ+pdG9yu7G7LWBOX6WziX/W3biKoKtJ0dHfzdUNyxxuW95bRxHbjFYr9xmbqPnslSZ
         rRTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j2VDq64hCmb0PdqvjEgPY+veWyNVkBbnH582VX3VFqw=;
        b=PwJzgRYWqfO0NFedQKR05r+0TWajyP1du2NUgOgZpYNLts09KBRQXF/yVT2CgobWb6
         7SO+8Z/SQkXNRbXI1C++veOBb1mAwTHXkb2jSmIZ3l117ZRmMEhQ9nA9VA+ISPeyRuP7
         os6hJPmzSWyygu7oNrijHuqmbdhKTOB1IriJL5iM3IbXbdc5+6PpkoDPLh8hC8+DYaYC
         jEt6LJs4RAs8pSE8Nu73llJHDkaHO2DVDj2lkaHA9XK/B4mCirMLQTTSVIWbz2KqcuP0
         rlLQBTZT1trtQwXbNBuQIwPzvzgtx+a2WC410FwMET/19nl7OubhZXfYMVbzCJn9DfE6
         cq5w==
X-Gm-Message-State: AOAM531xiPZ5C3n9Aw8ZDH0n5JZhN/cZJVSBZN1/+SErRpotgub667cF
	3+Z3by4VI6SeIPohG1Z5qVc=
X-Google-Smtp-Source: ABdhPJx2/HfSsHgHPIpruowzLYwJRFtOO52pIEejDICgegCvIgPP8p04VzyBkCuPJspBV6P6Q/92ZA==
X-Received: by 2002:a19:521a:: with SMTP id m26mr20514720lfb.56.1617118318627;
        Tue, 30 Mar 2021 08:31:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls5532550lfo.0.gmail; Tue, 30 Mar
 2021 08:31:57 -0700 (PDT)
X-Received: by 2002:a19:6c6:: with SMTP id 189mr20885067lfg.426.1617118317637;
        Tue, 30 Mar 2021 08:31:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617118317; cv=none;
        d=google.com; s=arc-20160816;
        b=RWyezfdZgRycX2umBCxpCv+4ZwGxnRsJz1anMes589lRVnVGLIAiUZqyqHAdekG+ox
         WyXXIaJro+3BxSBYfk29e/t7fBiGldhvOsxq8sfatJjjQt1M9q0GrEMMeuknOVQRTKts
         mqAtf0kkScHxpyfVIhfMM8pMZ0s3xWkNF7vOqoohCUpYa/gX+PA/z0Hz7ySbhoYWnkXL
         tODCruplBHDovN3EDcWNvfGCkkHZumNpI6oj01YHUgKoPSsOm1idKti4h5STyJIQGliC
         aFP9vHCshKH8dNeQXwDLeIgTEJzydXwK96f0IbtBrnpG7VdIzsH9gPnSeIrrv+zQ09hq
         /jww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=3cy7QAZwcM0qFIMC//13hJw8FRpw0MBxMbErk7zBrt4=;
        b=LmkPM6BWUqhNXiz7EDHWaof6l21ie3INVPaNzY7inS3tAJ2p6ihYSiw+ECEvc4ZbGI
         MQIJo7XPrhmAOgYB5q8g8qCBq71B6ZHmPu2OYkVGnRy8zdhU/yGZyXMhDQR2jeF/HGQI
         +n49aGhYzfZsJiUVArn54aAB11xiUQdjQjf3z7Kw4nNWqXpoYIyh7OPPtv+tJQjLxwYa
         tWcK/v5dyJHieR+PD9FW5bA6kmLYDcV3JzwFtMCpsb0urBY38p7eN1IoyQM1U336sMoX
         P7TWSBuKZ4g4yL/YXcht0GkzL5EzSbZQyvHy3KkVh9S/n4Rfaz9feEXm14XwvewCVLtZ
         GmYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTB5eRLt;
       spf=pass (google.com: domain of 3berjyaokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bERjYAoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z5si890072ljj.5.2021.03.30.08.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 08:31:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3berjyaokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id n16so10576696wro.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 08:31:57 -0700 (PDT)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:f567:b52b:fb1e:b54e])
 (user=andreyknvl job=sendgmr) by 2002:a7b:ce06:: with SMTP id
 m6mr4526147wmc.38.1617118316958; Tue, 30 Mar 2021 08:31:56 -0700 (PDT)
Date: Tue, 30 Mar 2021 17:31:54 +0200
Message-Id: <2e5e80481533e73876d5d187d1f278f9656df73a.1617118134.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH mm] mm, kasan: fix for "integrate page_alloc init with HW_TAGS"
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Sergei Trofimovich <slyfox@gentoo.org>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hTB5eRLt;       spf=pass
 (google.com: domain of 3berjyaokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bERjYAoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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

My commit "integrate page_alloc init with HW_TAGS" changed the order of
kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
to __GFP_ZERO allocations being incorrectly poisoned when page poisoning
is enabled.

Fix by restoring the initial order. Also add a warning comment.

Reported-by: Vlastimil Babka <vbabka@suse.cz>
Reported-by: Sergei Trofimovich <slyfox@gentoo.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 033bd92e8398..1fc5061f8ca1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2328,6 +2328,12 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	arch_alloc_page(page, order);
 	debug_pagealloc_map_pages(page, 1 << order);
 
+	/*
+	 * Page unpoisoning must happen before memory initialization.
+	 * Otherwise, a __GFP_ZERO allocation will not be initialized.
+	 */
+	kernel_unpoison_pages(page, 1 << order);
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_alloc_pages and kernel_init_free_pages must be
@@ -2338,7 +2344,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	if (init && !kasan_has_integrated_init())
 		kernel_init_free_pages(page, 1 << order);
 
-	kernel_unpoison_pages(page, 1 << order);
 	set_page_owner(page, order, gfp_flags);
 }
 
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2e5e80481533e73876d5d187d1f278f9656df73a.1617118134.git.andreyknvl%40google.com.
