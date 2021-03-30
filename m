Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPUKRWBQMGQEYHRTBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C60234EC95
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 17:35:28 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id w2sf9918850qts.18
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617118527; cv=pass;
        d=google.com; s=arc-20160816;
        b=FJdOR3uN5bW0pBz/fviOS0+6zTwfPyH85loRVUzO/ULiPw5rrqzoDJz/N64j7lMTFz
         BM4X4AWWEOCKIXtdgKg/T0IVoGgH4pGbgAFDXZJVmFHoAoxLgQnw8/Um306n0UkFgkPV
         CfHnepkAgzT36SeZtbIbNbxqESOgxXTWIl6pqo6p3VqfEZgPlyFHEKdHAYlsUm9D4lt4
         K7NLuTcHFZ+Lo3VgrwTokXkIiESyAJe8u0bMyptfSbvqz0+P30pBoxhQOgTj6qZYkh6+
         Vfnv4zrJJHznSadjbTJNUf7U4/BICQHu2dDtzZZH7vsmSIlpbbS6YAAay7KDlQlVTBFY
         15lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=mCcA4IFT6rwj/gg1INnEuPQlqLBCI0T7jEpEnBJu/hk=;
        b=uYtgCLlhkHQtHvNrFSVrTT+mfMUEfmmGWoA2dGpD6niNNOyWg3FryAvJkG1plfx1Ni
         6QwQSLwRMLO77IfCatcqe/6Bh7T74O8aAHEAoetpz7EwkNVCYL4U6KxyuYdaoNS0YHHB
         aBUItxTTRNGT95W/n6DNaXsnQWcoEh2j4RmNZW5wG8YYc9Jg8OMrd+Pu1vmLcDyHUJ9s
         VwxYkXLQtu9p8nCyIc7NeS7pEFvvYj1ocSTq3obkqY08qNrl4dfD3ViANSztlCqY2K7u
         weY6vgulnD+CvkwCJM7/r2XbReovsM1KCo5mp2xmgTfA5sBbrcB7lzOJdcn+HEfEuwhD
         00Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TMlZyMKL;
       spf=pass (google.com: domain of 3pkvjyaokcv87kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PkVjYAoKCV87KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mCcA4IFT6rwj/gg1INnEuPQlqLBCI0T7jEpEnBJu/hk=;
        b=niGiKAbYGnmwX9v1WIfGAPojeSXePORAEy+9JmJi8akJ/rrme9HjX6FfTVj445qFM4
         1M6tV5ip5z2Df57bQdzKZmrNXW++BJuAAwR8AGtp3i2KsbiMd2yIBGHuUxszTqy3iH1k
         wrYBuaUp5tdMwrsD3d+OuP0Mxja6D++kp5H0I1g7PIV2l85PWvEV6Cko9UQ3As3Hq0pc
         BiFZx/na1Jdzzwz0VylP9XlCPO/XIM1/qG0xUvq8+E3bnh/H0/6JluOikVux7hAmz23M
         IK0KSi6OPtaX4BwBGn1Q374HelQsWVxJ0C9Rb6xftdD9n/qXcR44LotU01lEQkcy97Z1
         S/qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mCcA4IFT6rwj/gg1INnEuPQlqLBCI0T7jEpEnBJu/hk=;
        b=TCYME8XCmb+xgY+rxKew404BCmdqhP7xhOH7lokd5VOz0nyXHMPcZ2Khy4FcJEIWCk
         vEwIuGy5P6aC+ontIZbzsjSfSgZlSjvLcThUvkLEU9WYyv5GC0OzFPo2qYi1qt9smXu4
         khyC4xEl0n84Y7lzNNPgXWXzwVMpDLzl+KJcSg3Jftq2ZSqC49kA4o9UGCgigqipJhkh
         3hE4ifG1aYWlTor7R3aY5hBGl3Ro/7XVRLOmfNNtv1mt7ObgSnCTMGNOfOYTFm4PMDFe
         n3qxTq7m36b4fNHtmT43nOLJfJo3GMVWyV57yF9IGd5KrS8jKafpGImD5maFrAryw64A
         SXRQ==
X-Gm-Message-State: AOAM530CXYa7437t7ek9Sz73aKOCVM9zgL7friUEu/0kkZJLOafjdM0t
	YhxtXDG7xJYuKd0iJHtLDWE=
X-Google-Smtp-Source: ABdhPJyZqap2Ku8cPsXIOH0ER2pJVbiOifaDBDlTwx3ZSIniSnvArfevZKI06LC8e+OwPb+K75/xPA==
X-Received: by 2002:a05:620a:2116:: with SMTP id l22mr30634649qkl.377.1617118527061;
        Tue, 30 Mar 2021 08:35:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c207:: with SMTP id i7ls10611808qkm.9.gmail; Tue, 30 Mar
 2021 08:35:26 -0700 (PDT)
X-Received: by 2002:a05:620a:993:: with SMTP id x19mr30136607qkx.77.1617118526650;
        Tue, 30 Mar 2021 08:35:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617118526; cv=none;
        d=google.com; s=arc-20160816;
        b=G3H4DRM7/jDetxvENnbQQs+iYh6fQK1Gupt+seAOm2GKE4Hs6HQ2aLOeJ3vOp9XWhd
         8xNqXkZWkLIjpCfhyBE0LwRRVcQNeGY/VyIPZRH4/JwdQdjlqu7uISIByW4jaCCAxWcQ
         cplWiBrI/M/j2Wy542Fofa+fNqqFj41WCW0wDLclnX4I5+sZvKy3ZP/JAUjO40a4MXEC
         0xnU8qJybUVwO+o5a6cvodT0ead61Px/MEY2CqklOjFBVfXePFaFiMjImDuYDAFFCiIg
         ghjuUZwY2zByMrkGVs+vQMflV+tYHnjWU1MhH0x3Pqcotrny9uyOBBDhbDzwJmdzMAnJ
         4k3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=q7MsrOk2npJtSNdwNIXd9WmInrGYWhEX/by2Gk6QS24=;
        b=rSx9g3cbjkc9rtEQ8f8CkJo4bUO/bhpCZLIuXhMIYXcqt+2ukYpRKO9ono9x4lwKS7
         miX1rR5il2a3jUwNL6Ha4raKGLadNZFxDnm4FFxFl09TE0dslLNxCxtFmyGVXtSR4g/+
         uCEYZV1NN9+Rv5VaD19AOPuLjwVCR/wSlGmSMPC0R2+kGbcSnqU9OLFa78Vmq6HaVRzL
         5cZuzfy3guCJmZjN9zjcRbB9voWxi3iHTyeMtNNMfVARDa7wEc7BERT14iBH3uZbHQrQ
         xQh+y8Bfys9Ju+GzcXG2i3iQBfVXyYA6Vv1GE07qkRXOmw85aHV39f+JFEaqh38GS3Xh
         gQJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TMlZyMKL;
       spf=pass (google.com: domain of 3pkvjyaokcv87kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PkVjYAoKCV87KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r26si1142666qtf.3.2021.03.30.08.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 08:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pkvjyaokcv87kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c20so9908609qtw.9
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 08:35:26 -0700 (PDT)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:f567:b52b:fb1e:b54e])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ed2c:: with SMTP id
 u12mr31246924qvq.30.1617118526298; Tue, 30 Mar 2021 08:35:26 -0700 (PDT)
Date: Tue, 30 Mar 2021 17:35:23 +0200
Message-Id: <2dc799014d31ac13fd97bd906bad33e16376fc67.1617118501.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH] kasan: fix conflict with page poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TMlZyMKL;       spf=pass
 (google.com: domain of 3pkvjyaokcv87kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PkVjYAoKCV87KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

When page poisoning is enabled, it accesses memory that is marked as
poisoned by KASAN, which leas to false-positive KASAN reports.

Suppress the reports by adding KASAN annotations to unpoison_page()
(poison_page() already has them).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_poison.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/page_poison.c b/mm/page_poison.c
index 65cdf844c8ad..655dc5895604 100644
--- a/mm/page_poison.c
+++ b/mm/page_poison.c
@@ -77,12 +77,14 @@ static void unpoison_page(struct page *page)
 	void *addr;
 
 	addr = kmap_atomic(page);
+	kasan_disable_current();
 	/*
 	 * Page poisoning when enabled poisons each and every page
 	 * that is freed to buddy. Thus no extra check is done to
 	 * see if a page was poisoned.
 	 */
-	check_poison_mem(addr, PAGE_SIZE);
+	check_poison_mem(kasan_reset_tag(addr), PAGE_SIZE);
+	kasan_enable_current();
 	kunmap_atomic(addr);
 }
 
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2dc799014d31ac13fd97bd906bad33e16376fc67.1617118501.git.andreyknvl%40google.com.
