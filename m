Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIOE3H5QKGQEFVFWDHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 04472280B04
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:30 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id u23sf35176qku.17
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593889; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZpCT1rKPvEENf2cwLyoyeYkkpqEA38xlmVdpwcTOIxhTNlHtFIbWlJlA8ehwpS5myG
         KIJDM0GKQ9PtpRhTviRcty64ea+4HbQovwLuavQ0kLL6MctrLeow/natv5qOJk4ksieH
         qzxCwWnhWf3F3BhRUqYo4AyW4a072l/u6sh9niyZaP6Vi9RkiE8o/Dg23rNY7nDGEX2/
         qU0GftNxWginmf7fhJXl74Nd84p+8RHmd49MNzCtJVx6tQd3fL3R8/FH/6dxvFTW4fjq
         2avIV/o8dk63wO4IVNH7lgMAw1J1QZ71aT/rQxLzbqVc8du3o40f5MVHp+P64S70+CNR
         0Mow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SNCwHJatvpRzaXGmd6OZhGw6VQb1QW+WCRrlqowe3Yo=;
        b=riQ8bdQF6YMGZPMN1p/EYX2KNbuEFyLcC+u+N5rx6r5SAtSUiH4URiUIPdG03M7GSb
         iWYrsMpGstk6jUIOkYEFGbbIpeORs7mqjdeYDasxRFRLiwcx+MTy5wR5IjxqWym2Ke4/
         W5dfqgCHqj33Q4vx7ws1p86D70QeU0EEjf9s8qopa21w2fh5GYjHsXr57zj/huI8Ozo/
         UcnOVRdTh6QcvucJ2vVhaoDvfT8oSQrHEXEaPkD5mXnipPXM1nrJYDTdd/TSpKDa3ZBl
         BecbxohNbLfZVLvmTiLauB02e4JbTgwJpJH9iK038st/eM7LPF0JafXR3ZUE+kW+evkm
         OmZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/BtkqqS";
       spf=pass (google.com: domain of 3igj2xwokcb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IGJ2XwoKCb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SNCwHJatvpRzaXGmd6OZhGw6VQb1QW+WCRrlqowe3Yo=;
        b=riM3d06d7w5Qg/N89FgouJrsEVZnY5SNETaAmb70Q1GgnQeUDmn19uv+jkisftw5n1
         kOxMau5Lm8rpN4dN87Il2G1RJA9pGao3NQd8aBlyFNDGddZv31s3/NvBuIbAQrT/HOsX
         b02bAeZbIa37up6Zj/TSqgxQRs8fSs5n+ofK1rJFLKuKnD1Owjbl8dXTjfyT26B/WH9T
         UfiwrV2BG45zSrzrjey4b4w6nQ8Mixv9VchQwSzaDSp/T7OA2eC9kbg2XHNHzIe6Y9WP
         buxH6ycIgNVuY7g8pOHxOaRU2kbnevC7EHWnEU2OkdAOQBnlDV/7f5dKWAMCcrYHu+2x
         S7HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SNCwHJatvpRzaXGmd6OZhGw6VQb1QW+WCRrlqowe3Yo=;
        b=jZRXfvFXK5m3kwS2iQN4YCLJtB4X+T8fq89pVeZUe+hgkDsd62i7JeEgpoC/kRrdFg
         ocMSewtla6hQ09EjfsT1EESyoy1DcdVAca5pf2SBkRB3I9iqHz3cJtNS6FwLuu1ke4HN
         Kilr1l0aF6ZJvJuwEkJ+QLo1FT0UKn9uK8wWvyS6YqrdTvZ6Z+a3lsN8OMDfoSVqihji
         IaPFFB/rmw4UcoaM4g5aRO7FMaTJmcg1OKRYqXz+gKFiQ9qHYxZTo1b1rkdlFPi8/MBr
         b+KnNeH8VBoluiqe5J8wFOgi4CAW0MRWqknEyr0K+aXs1Kc9/+FKDOV2ju+I/6z0TS2w
         LVCw==
X-Gm-Message-State: AOAM532fgPL6+vwZ+18N6zPVry3wctVknW/Nvc7HLBXJMiPEZ1Kd8Nz2
	INk/I3d9P4yAC7UyrXOvKlE=
X-Google-Smtp-Source: ABdhPJx4FwoDYwUdCLl+sNuo6jtNoenjPo/03Xy4AfB9tqjjO4hv283pp5/EUCeXGAlBmAwhtDTywA==
X-Received: by 2002:a05:620a:f89:: with SMTP id b9mr10025071qkn.75.1601593889110;
        Thu, 01 Oct 2020 16:11:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c93:: with SMTP id y19ls2669329qtv.3.gmail; Thu, 01 Oct
 2020 16:11:28 -0700 (PDT)
X-Received: by 2002:ac8:3fee:: with SMTP id v43mr10130110qtk.192.1601593888696;
        Thu, 01 Oct 2020 16:11:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593888; cv=none;
        d=google.com; s=arc-20160816;
        b=dip4BCWfbSuJnw7OJ7gLs3NGFUQQYmihZRjh0oIeC/kswvXk8dsOCa5K7sOumtQnkv
         OYtLlNCOlk1z7wLYHQfgfq9kQdC3od/vS9TzAxLoea6lMbWPWlJKDorkSShyxma9Wdo3
         /Hg8bqjuVTOdmLqLkonco1b88aoVMUVNJzWch2/VOEVzBXCzQ8BY5NCURGJr+Py+vtXm
         2d3KJLXGG6dCDfo7rGyK/lkyezn868B7nLP8xVascJH9lW8i9eCMdfIqF2ppZflHNEeV
         Gy3TQmRWpCuK/w/+iRJe7cvpAO1AmoGOL7JVxM1a9oQuUQtr/et4fLpfqdcp1BCF8O4F
         +jLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Yqrr7BPrg0ain92TsQQXnoY0LyVu+DXBA9LKavF3UYw=;
        b=L/cWVAjQo51QxyNTZmFqeDLmCv5ujDR+Tmd90EPqUkphML8HLK4lFBwDk5CkZqgQrZ
         WFkTHGSVdRDtf7zIDhqJD4VidO3zCb01wCdAXqKKY3QFVOAlHQ/EFQKg6fLn15iDOApS
         /vsQ5NVCumo598jhA8/MzLqxNsbhMwV5OhdQiUare8qSgNp6gJK58aEEqPZjKkcCxqjT
         yThGptL2ZYBi8/AD6N4CKfVMmwxx2zYLknSWJS2dz2t3aWAlSAMZQ9WYPEf6B5s4fPFF
         m3oClDIarVqG8daHVJMv0LG63/g19aHs+DYLALbkSuoa1OmHGhK17O4dqxYsYWZ2qUMa
         ZFhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/BtkqqS";
       spf=pass (google.com: domain of 3igj2xwokcb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IGJ2XwoKCb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id x13si501852qtp.0.2020.10.01.16.11.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3igj2xwokcb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id ct11so232220qvb.16
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:28 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:abc5:: with SMTP id
 k5mr10212554qvb.40.1601593888265; Thu, 01 Oct 2020 16:11:28 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:19 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <32076774a3cb7307410532deb902716411a2dc52.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 18/39] kasan: kasan_non_canonical_hook only for software modes
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
 header.i=@google.com header.s=20161025 header.b="j/BtkqqS";       spf=pass
 (google.com: domain of 3igj2xwokcb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IGJ2XwoKCb8fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 9e4d539d62f4..67aa30b45805 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -371,7 +371,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/32076774a3cb7307410532deb902716411a2dc52.1601593784.git.andreyknvl%40google.com.
