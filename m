Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV5EVT6QKGQEO4L3SCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 115CA2AE338
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:12 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id a10sf5271761ljj.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046871; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIVrNqlD9v9xyL7/AXRLpaABlxyztbbfiMupwQ9y7wlg44FTDZ64MVWB3xOVJZl+Z3
         OZ8e2GEzyGXzCsml69e9COw8w5BSBKKctk5WANcRIZQYVhlvfVfN/SwBVgTQ74wviXuJ
         PNctTdJqaWopoETfYUKIgjJilewC0W0crBINdXqLy/QMUfgg+4m+qsTll6/JivrbpEDu
         gyX4UuHutyqmG+eeV/o54r3LQSf7H7nu+Ic+LF2MyGJkFSvB0U2PKlCdwL2hom3hzOOM
         /BKblsSPOlhvfVWlwg3hqZNl8edg+zrvqE9HeD7HMjILrBsP6Vig0OuADed4yc91ry44
         raqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8ClRGbwICiZT/2qWFRY2BMAFy+L8PPggWzOw1OLG8E0=;
        b=M73vwfLYSNMAx4iVI5O82aV88tG/tVQ0DeZKEzWijhUsC0PMPRw7d2qZBdCsXLMawE
         2Od+o3/bxEy2EnWUkZNl1mH+/iBBapuGXaT3FnvJ8H+v9fV7Oh4+iwYnVHjj47buTfAW
         +FanMKobz/nxgp7dg3JL0vhtX5DirZl4qaztlXjnh6hhh4wXRhly02tbbO5XRSXC3iQ6
         /BnOKskj41p98hiLA0mVF/I7GV2RyQwdeSiGxTW5ycCzJAWPcM/bN7dVeXwv5Sv/vAhr
         wj+xklefD6j2BPcnXJie4cnj0hgQOOXBPqBeKVAglRPnB7ZoXyvkaWIhxCEBbiK+qRMM
         c3tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wL8k50M1;
       spf=pass (google.com: domain of 3vhkrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VhKrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ClRGbwICiZT/2qWFRY2BMAFy+L8PPggWzOw1OLG8E0=;
        b=m74IZ73izWPoYMuCCzbg4I0/OJz5vy4a5tjuPDI+AArwo0+XW4t31HuJH7AtCU3/bS
         SCf+u71+mVJJ2LVL8YvWGjr2y6+YceAkTNWOY98aAU5PkYnehOOXtt3dXBe6MopbDwV+
         eKses+Dz9w3j2C4uJbPZvPx65EdUur7OXGL3s6b82qW3/32TZ5J5jmUwYIE/OYiFYfaH
         cDaa8kmlViqTWH0iLE9RK+XjZUqo979FlkvNCjG+hByxl2PXQaCGxSmUeV01ZnCUlkfO
         hiouVljcXi5EEcsiI6hltRSED0QQLyHGoY+W7gypBSGlxELMHFjReFWj0WZWf7VFGAWd
         DjzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8ClRGbwICiZT/2qWFRY2BMAFy+L8PPggWzOw1OLG8E0=;
        b=P3pJURogaEvFs0IZ2gs6Y4h2UMzpGeNKuVZ1BxVaxedm4hecuzdo4MVICNY259VNjc
         vz49cGejt0b355leFNfQcapLv4WcG5zlSK0ozj+3HF12bC/s5R+mywz1frKZIBTSlRjc
         L7h7UvuFOz5wi2/fT+SJHP5fKv2vLmui9MWbNU5oBTwHTPn3coADHd1ZNgdErS0sbuLX
         IP29gDiSQjRITy4WF6DV/Mh/Jqct6r8ceAgHf7E6IIWF2Im6IbITPQkZSkY3MrsH3t3l
         l+VnwVejucvoDiNsVjR2kXU3MbhF5vBcYqHhRdYdwOjagPJB8ZYG94oY9ntRei/otnJe
         r9nQ==
X-Gm-Message-State: AOAM533C5ATyY+IDNCTp7vQhyEiPGp1qkb3+RzZwe7d48l/k9yboraJz
	xRJ8bf5nSxPZTZ+scwG9xXM=
X-Google-Smtp-Source: ABdhPJzMhCs4x4FdZYb7XmpJg8zb6IPxvcc5PK8bWTyeZbtYjPvoBr+BC1y61DHnRKJw/d0iexJyag==
X-Received: by 2002:ac2:5446:: with SMTP id d6mr1643920lfn.271.1605046871659;
        Tue, 10 Nov 2020 14:21:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls1295149lfn.0.gmail; Tue, 10 Nov
 2020 14:21:10 -0800 (PST)
X-Received: by 2002:a19:4a0a:: with SMTP id x10mr4016776lfa.565.1605046870777;
        Tue, 10 Nov 2020 14:21:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046870; cv=none;
        d=google.com; s=arc-20160816;
        b=LJy5Z//NYx7AkflA0PxDaSYBPU+4k6vRL2PNb/djNwV1JAGz7e4+8exK7ATwEw7iHf
         zmWn5T0TL1Gb2kQfQyMtC/09GwDNIDPvjQqRhG1zM2IGf1siZUNJk1tz30JS2P4kKIwM
         snDUXSzlOhZHkXifdDxJHKnui819g+c5Rf43htXpJtsDx9OHf1DvX8SE1aur1naqAvcz
         DOcZiTySB7p0A35aFP9b9wXbecBbMxvVDcudM9DtYdmxWqEDNspiu5wntdh1Bg6sWboA
         L29bJM21/16FqFfIwJIWv4EtIECgncYL1lmAQG8mD5e4wwmDwwd0tkqYQJRf8NPz5L+f
         SACw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MgiGs2FK0RQ4JNcJFnsxjsC4BWa7qeyNid6Uf5IWwBE=;
        b=GZcTJYW7CyrpXJR6q0HVvoukrGkfYsggXjP4K3lANJCl82Y2Ct1n0XdMGd31x3q2fB
         9nsYsdNpuTu5wD8C3JWRyfMsXRpKHWcfacQ8bAjZ06G4HaXsypk3THFz3uiuFkSHiNaY
         V08cWTgi+YuUTiqXMS3ulVfaKAEo/SVfrzPjRExJ2ez7Nwc1KAUdFBhDcpAQYcPrDNKc
         t9jmY7Au+cJFXvbEhIDn+S4qjedzwY0Jzc56Iwh/aRXY3IYiGQJS1Top1+AtQAVNjutO
         QOeRPPBCi4QXVwYb7/5CN/TL+Zl3+l2GV0atcVAtAzigFeyyPaGSKSMRo26qakLXvq0p
         sneA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wL8k50M1;
       spf=pass (google.com: domain of 3vhkrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VhKrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id o185si3978lfa.12.2020.11.10.14.21.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vhkrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q15so6192978wrw.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:210a:: with SMTP id
 u10mr304573wml.98.1605046870141; Tue, 10 Nov 2020 14:21:10 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:21 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <dd492a97ed68200b1d7e2dce55ed9a7790525396.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 17/20] kasan: clarify comment in __kasan_kfree_large
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wL8k50M1;       spf=pass
 (google.com: domain of 3vhkrxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VhKrXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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

Currently it says that the memory gets poisoned by page_alloc code.
Clarify this by mentioning the specific callback that poisons the
memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 40ff3ce07a76..4360292ad7f3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -436,5 +436,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by page_alloc. */
+	/* The object will be poisoned by kasan_free_pages(). */
 }
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd492a97ed68200b1d7e2dce55ed9a7790525396.1605046662.git.andreyknvl%40google.com.
