Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOHTVWBAMGQE3JZ4IUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D3B0C338FE8
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:56 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id x11sf9836931ljm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559096; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4u/GKGxUZYysa7LsH6vd9VQ4/NVb/7FTielu8l/MLrpS55+ezb+LOYnX+wJBiU576
         0Hns5GKkO3+hxfFUG2fQFGqGNpWI8/F1FLDLbfeEoSjLhenclJXEpVlBwzwKT9w8rub8
         pCv7IIuwbE33LhbtcoxdB3m43pUCo/QD5wepii4RvlvNsuBh1WstE00zJ+hbP927pXXg
         kYeFFv2lXwUYg2tQqZ1li0csjpgW2Lw6biGa/Q0bo6eHsj4hvDcD6Gn2pbO8q0EDCN9o
         +oyEo1C9wJ5MAozBuq79Ml/BS3Yg84Y7f71OXylWB+7NpoDM7wF7cqdzCrlhdpVuBOxc
         /yaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DhJNiGji5IlveSFSq4AaDIRXnHNz5SEhxa9pKIFxDgA=;
        b=h5yEkglUktAbhpYiDpN3th8AcPQEFWdOddIE+IdZ4s1B//Af/4y2SFeOKUcymy1TSZ
         +HjQboM5rKOtFvV8nVNP0q6vmJo6VbC+Mwd7UXmG3d7nQU0YAGh4olOWh1ONg4r7XvjC
         Yb2ycDkRu9tDllZwfU1lUMxrq2W+vocxx+v+nhiQc4c2UQ/f95L+/LWjenvxLpryKO0N
         ifdVfp13Zv07SRrYbetW5LJBYMKabwI4hYLVZfORjILJ9vnZ/zM7PgJPl/EcAcfyGFOS
         MaHDY5urtADopYzAdYNp4eWwQNjJqZxDnJITse3Un5+V7tdS883VHgcghkhFxhQfj9YB
         tcEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jCrEWQlY;
       spf=pass (google.com: domain of 3tnllyaokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tnlLYAoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DhJNiGji5IlveSFSq4AaDIRXnHNz5SEhxa9pKIFxDgA=;
        b=cETVQDEKiOuMWFpmFXs9G1C0wrlAGMXMUJ9p/499g+ITignIOwG150pT21v2h5I06o
         IizX5KOF1ESxBqjMQNGtDUDwSUw+JwZwlucgJJ+3W30VebSwp+J5acWBR4Y6f/e4UjP3
         FhEKgY5SsuUM/eLqDctcUXPwHsPCSaZo9nK/DbcYD+R+70/83/i9HEXcoP6k+lfqTOCD
         B/ycoCMcJkAFjE0R+4Fh4dkGOlVcMw/bsmQzQGTHg6lU6oZJJa3SABqnPYxqzhtEaA1i
         9BAOVIfUpiu40247lvly/CdhilppOKj9TRZ7pMOjon4exQBUvqZemjY0uxXZMHcg2AT5
         SQeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DhJNiGji5IlveSFSq4AaDIRXnHNz5SEhxa9pKIFxDgA=;
        b=NNEE3oLW7Gb1dp8dDT+OvbDDfaiDZKp4HqRwhxpfUMgJ1/cSZ6aHiSR65L0LygGNVR
         OD76MqshUUrBStEMnquxTUNIWYoRQvTCRzDA7w0pLEb+7JJuug17ETvrDKGg7fAOj59M
         sr0WLb/oOzEagVkwNdLCu5rQovlsKvLt+G9jiP2deDr1S3WW/u+wXLo0TZnpupUeI+/T
         HMEa5TEhSsoxfYU9B9pgiSYns2mf/P/sanugDVUXPcczt3efcsfCDSpP/LXY3IlgKZEm
         T/jpUvVNLH3YRjvmVnYj/rfO7uTMf1DeZ8gGh51+zj6fZJTBLsH0CaWGwWgFprBJVSXl
         rWfw==
X-Gm-Message-State: AOAM532c2h6Qv4DQ9cLtMnznOVIF1ejAjE0E1yfpqxWWcKlxQG1hgc4S
	7aL887+Mr1y1XVX9lR6l9Go=
X-Google-Smtp-Source: ABdhPJwpBVwWneIMwTjHdWSsjVjQ0ZkZpidI4nbw6JNX+7s+kWFhNEvQEKE19G8Ad+4/TSotZoflYw==
X-Received: by 2002:ac2:48ab:: with SMTP id u11mr5377852lfg.79.1615559096451;
        Fri, 12 Mar 2021 06:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:: with SMTP id b17ls1972217ljf.7.gmail; Fri, 12 Mar
 2021 06:24:55 -0800 (PST)
X-Received: by 2002:a2e:6f11:: with SMTP id k17mr2517596ljc.231.1615559095451;
        Fri, 12 Mar 2021 06:24:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559095; cv=none;
        d=google.com; s=arc-20160816;
        b=CiROrU3eRzVlkNNWuzuCGUO6lnJd8FJVFUUT/55kAQD95E7n4H2oavdDkE9rs9pEZ+
         IdHt3YWCZCiWTI+/lw5DND5r414zwq+VE+7JzdQW/GAlhYXNO5RMVSFnSPTPprKRXSvA
         155kz+BKIIxFbVKBuVsvpBU5t3a6jVxLkJoiCE7otskuiXcSV7v21nSe885WxbECmHvv
         r6Aj4UfY3H8QLhLTlRY9C7/JtA0YOOehdcazyGgi4T6NSBUmmJsPYZ0/a4cuGTUiCF5N
         sEB+m6psE3dkhP9pDAwujhiCX7OGJhzwehb5C7ihnr12BwTRnKysUMUV8zuCc6XXJi67
         sR2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=AADxbeoNuphnMvdgMWHUkUamhVrmAjoCfQWWs7Kvkug=;
        b=txmDq4Hz+CefIGY36tqSTKcS63jG+J1hxtCjJWxfDleaC+3UPbk8hMjrzgdt029usQ
         FFmdkdhTCYswTAs09j4aXaPQHOtg19dA4um5+b9vMbqbD5GlpxiWJBoWVmkNTI7mN40F
         pjxUsaEzDhRGa6SVAbLVymSDLT9VLV6NC5rF5T+gUBS9WDPYcRI6Jl/vOm56Gd76BIrb
         OWg5GH2r3QZ5slpn7uhdolVqsPyYRMBWCKpnl9/s9X3O3RRMJTcf4SXe4KcsxbP9D1Kv
         DBTsnKjABBp9HQU3n49Fw1QSDU6UZBMCmhZTrZ+W3AUEi1Ss30fFML4C5JZpmZHEpp6t
         fBiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jCrEWQlY;
       spf=pass (google.com: domain of 3tnllyaokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tnlLYAoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 63si217060lfg.9.2021.03.12.06.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tnllyaokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n22so2104648wmo.7
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:55 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4688:: with SMTP id
 u8mr14154024wrq.39.1615559094829; Fri, 12 Mar 2021 06:24:54 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:31 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <ee2caf4c138cc1fd239822c2abefd5af6c057744.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 08/11] kasan: docs: update HW_TAGS implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jCrEWQlY;       spf=pass
 (google.com: domain of 3tnllyaokcd8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tnlLYAoKCd8BOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

Update the "Implementation details" section for HW_TAGS KASAN:

- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5873d80cc1fd..2744ae6347c6 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -270,35 +270,35 @@ memory.
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Hardware tag-based KASAN is similar to the software mode in concept, but uses
+Hardware tag-based KASAN is similar to the software mode in concept but uses
 hardware memory tagging support instead of compiler instrumentation and
 shadow memory.
 
 Hardware tag-based KASAN is currently only implemented for arm64 architecture
 and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
-Instruction Set Architecture, and Top Byte Ignore (TBI).
+Instruction Set Architecture and Top Byte Ignore (TBI).
 
 Special arm64 instructions are used to assign memory tags for each allocation.
 Same tags are assigned to pointers to those allocations. On every memory
-access, hardware makes sure that tag of the memory that is being accessed is
-equal to tag of the pointer that is used to access this memory. In case of a
-tag mismatch a fault is generated and a report is printed.
+access, hardware makes sure that the tag of the memory that is being accessed is
+equal to the tag of the pointer that is used to access this memory. In case of a
+tag mismatch, a fault is generated, and a report is printed.
 
 Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
-pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of
-kmem_cache_alloc/kmalloc and page_alloc memory.
+Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
+memory.
 
-If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
-won't be enabled. In this case all boot parameters are ignored.
+If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
+will not be enabled. In this case, all KASAN boot parameters are ignored.
 
-Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
-enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
+Note that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
+enabled. Even when ``kasan.mode=off`` is provided or when the hardware does not
 support MTE (but supports TBI).
 
-Hardware tag-based KASAN only reports the first found bug. After that MTE tag
+Hardware tag-based KASAN only reports the first found bug. After that, MTE tag
 checking gets disabled.
 
 Shadow memory
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ee2caf4c138cc1fd239822c2abefd5af6c057744.1615559068.git.andreyknvl%40google.com.
