Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCWE3H5QKGQE7QE2FTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 389FB280AF5
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:08 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id 135sf72319pfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593867; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4HTJYRP9hS2oLFEINm3wXcDUUP0kxjU3oymr1gc4+IqdpqDzOJF8abtE0MsWPheW4
         06iSzHXnP435wkTtvTmyEkz8/ChylmHQruLhZdDSUNerN2JG+kDQJvzB/dxqAQXCQi6A
         S75D9ltO7LrV4NudXO6d+GLeO6byxb4cYmGsK6467uNIlh7kF6lbFnUkM0mB7Bfho6kc
         SmvHRGtPI0VZpsmWQRI5115Wj3mClC3/hH++mxCpLFUpdbPlKJ6RcESQE8PNC6SNwf1N
         BWwhXxVpTA5UrErwTOqfTCYWImY0sQxu+Uewrz/Y3WUQQlLmoBKAtgt52nHw0/LoXyCW
         urpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ifzqqYC0FenMIRcmcEbXr0mKRzGqbvPHp7bsojDaRd0=;
        b=Dy7N8jwAb/Sor+vtChjDioxNU7PI9pjtWgkv1T5Ip+KXkc8vBnHVdeTVjg9hsk9jEK
         VC0G2rPVCz/gks7g9K2XeZ7ttH6GIK8UOicJYKlg7Fd2aSKT2YA0hXVAfI70YjQ7DM6h
         vw8f/bI8zpSzav+hoIkBsisVcDAdzqOfb0PvYKyLVByGNN6pvdI6ExzBG9Ke05RTGydF
         rbwNx7py7VvTP9n8Akp2lp0ghI9x7SSHTzF7y7GUhjOsTWbRkz0IQRMAxvIEanQtgirx
         fmPRr97MWMjjP9Z4CIuZq6JbZEfz6DuocnXxrdx+xr1rQgW0TNPkqPo1ATJBo1NdRBg/
         ZNwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GDXGGeur;
       spf=pass (google.com: domain of 3cwj2xwokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CWJ2XwoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ifzqqYC0FenMIRcmcEbXr0mKRzGqbvPHp7bsojDaRd0=;
        b=Ms6lHdXxGnm0Pp0be8Vbr+N5HHsdk4ln9QcYGtkkUeVpyn3SdrGq+V/JoktKSGAv/q
         QdOKTMva6eQMlYwdu5UjEU5x3Irtzc6mXaPg4FC2IuJZjTor973DHd9bQbZQMz+bu0lF
         2Yyk9/nToQuPNdvn2EfbX6bDB3ZXJBDa3nM5bozFASnMJQnIoE15cmJIYiZYtZuwz9oe
         Vr9BfTqdL3uqUPMjiNHgNavtSvivzzc8aMWbbyohZB9Gzf//Gg80FAZkmZrDXybeD+QC
         Ttu+reyvC+gS8mvw5LGMJFtfBEZSrERtNvuz2bd4GtPiwhdfuFIZLIJnSUlsBX+ixdqn
         WMdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ifzqqYC0FenMIRcmcEbXr0mKRzGqbvPHp7bsojDaRd0=;
        b=rf3Xp478XbmuSmasuXzlT0RMM9dn8RLWnR5QBvQ+GFvgijHqb6sqeaSK5suc5w6EE1
         z44pNOTYobz8g3OBalKyfthYyQjLFiqVO51xOFUtwaTqDpNuP74TFgv2ocEal56Ti+as
         ScCGMULAVaRp+uJySL8NCIFYFB+wuLq1CHRzUAle7DjecxIIvYUK7umSCviooooMkzFX
         DF5rXhtWhjPhdlCWSplsq9Zpy3bPEGOLKRfv4/UuW8KMyQwS+glJFGkXqFqQ890XIsIj
         jjqzw8wU0bRcNDYUFD8FDmYlZMnkCFHeNzFz5q4acwTAA0XNCJLYCfWLI0j6SJ3q3+eH
         r5nw==
X-Gm-Message-State: AOAM532JH25wo9NFfo3VoBmsGHh6B/c8CGAfQhj1bcC4OfMIITxEBR5R
	xbhKExuSS3byxCBXi60IqKg=
X-Google-Smtp-Source: ABdhPJxikoaCPZb9MifKR9py4yIaauhn3CiCUSwaACULdKu5dQSrl6eP63u3v2KmhphC+vzCMn84Ag==
X-Received: by 2002:a17:90b:3197:: with SMTP id hc23mr2031464pjb.78.1601593866931;
        Thu, 01 Oct 2020 16:11:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc89:: with SMTP id x9ls3027137pjr.1.canary-gmail;
 Thu, 01 Oct 2020 16:11:06 -0700 (PDT)
X-Received: by 2002:a17:90b:4c0d:: with SMTP id na13mr2302833pjb.102.1601593866354;
        Thu, 01 Oct 2020 16:11:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593866; cv=none;
        d=google.com; s=arc-20160816;
        b=kPpBUk9I8De7lXh0AhJU6tzvBeXmqlc8ykAFv6a/T1SNjXBEMQXUHB4eo8kn6H+xTf
         K85NouPCeWJebQ2E53xZvkLq+fzy/E0GUNwiEQS2lEdvcuZiRgperb/75GbE4FDLr49N
         0G0mcYsXbG4EfIGwL/MknNS8MG9mRsMN9HwL/3T3XblQ7+8BeGryVU6DAIqOFSxQ9uwK
         mDutalIIBIkKvHQgoY9GA8T/QvQQTci2jqoq1NdRJcAM26O6mfILZBTSQmqhVUrp36Cz
         t6Uk5UwGYyGFRriG5+PIudLaUtXQ7fkAOA8tkMktZJGciujLzBLiwMTPIj3t8Qh9KtRa
         j1Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=h4ahnVj97FiAecn9nKUYbRmxkWBQXwitOEnqIvzOE3A=;
        b=SLOk819iAmJs7PEyhYPHJJfFhb3sQSXCo3+mmnQFKmf8cLl7oG4w+cPgID73uvLPV/
         ftn36Ui7C17IzXkRRwMR8xRzYHlZ4ew14FIkkCOJisIRjsmHICDs0uhq9V5jXzx2ZiV+
         Mx121qUdJNwOb39VTgw7lK6PuMHuks1KXOeJkcfL3P3zDrmS3JQTiso960wlxlNn9/D5
         oioX0Cxv3pFy0M4ozdQKRNbjVkpDAfl4XxMh/x1hZwUbvZNcbSEbBOuowT1SqX22ExTS
         nNQRU5qxRNhgQVdA46Wz2erW+YiUNhndKGjGDpXWEsyWNsNYGGn9VDpHQSaB3VhF+tpw
         zZFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GDXGGeur;
       spf=pass (google.com: domain of 3cwj2xwokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CWJ2XwoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id f8si58903pfj.2.2020.10.01.16.11.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cwj2xwokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id r9so531453ybd.20
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:06 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5b:f03:: with SMTP id
 x3mr14383469ybr.137.1601593865465; Thu, 01 Oct 2020 16:11:05 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:10 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <559c0a35aa6de0a7a2e915c73da260e35bad5809.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 09/39] kasan: define KASAN_GRANULE_PAGE
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
 header.i=@google.com header.s=20161025 header.b=GDXGGeur;       spf=pass
 (google.com: domain of 3cwj2xwokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CWJ2XwoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  1 +
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 12 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..26b2663b3a42 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c31e2c739301..1865bb92d47a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,7 @@
 
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
+#define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index ca0cc4c31454..1fadd4930d54 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_GRANULE_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_GRANULE_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_GRANULE_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_GRANULE_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/559c0a35aa6de0a7a2e915c73da260e35bad5809.1601593784.git.andreyknvl%40google.com.
