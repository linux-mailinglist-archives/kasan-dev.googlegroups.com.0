Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSED5P2QKGQEQNXIOQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 76CB41CF93C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 17:33:29 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id t17sf2237028vsp.23
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:33:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589297608; cv=pass;
        d=google.com; s=arc-20160816;
        b=a6VBAxwG/IoG1i3mGYE68HX5jfdkyu/r4ccpwQvFAmxWdfF+3/yTFtV3sfJTM5nvfc
         ihcVVhBuhSxOmkx9MRYO5U+3q1VHHPmm/qhEaUp6bvcCIgK1HkHHnxk7f9OgCOaG0WEN
         k0rmn0Do5Q4IadIPcqXPighFCX/T59tKki6QkUZhZqwPQBfSHz8/w/0bj9dlibZPzPWE
         UP+otyi0ufXaYAsVLLRUL0y6JWHax0vJ7PkRB9KvPOV0wOcmtCSlURCQM6yumiSbwIHo
         3pwkDKCX883JcKqamp6ZMLwY5XDk59jHwDZgCNUhsLSV1YF6wLx+Is72CWwMfB3crggw
         Y6aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=q7pdmmcuIFO9bAlCNEOAyHcYCtcJvvgkLL8VZt4JrAk=;
        b=ppePoT59JiOvJPd1O8Tf2FN/0YHfC0hyTFPP8ciVHOuFQ+iiyBDdY4H1y68dM2VZN6
         1rRHX63+M4AnZuwhOMwYMl607lSby9eTdfJO/c89gvXYH2rPVIyaO1dl1SBc5heunMNX
         nbd1UmH8VWvq9bS5czqE/g7kXw+cU7+cSfXl+HLm5Pwa3Jh1r3t5dBooZy0jsUV10PyI
         KDbJL7XA9iJKjJ6szmLKnA6p1j179wU35GxL4pa4JLtpHHmoppKnnv+9RhLQS4tOvcCK
         bDvUBx5I2pnklTshIZymg6l3EsMoM6t8LM5v0H7+yNTlSuDKXJ85LDJOIfdyXqWYw+iT
         /i9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wBMVtnmp;
       spf=pass (google.com: domain of 3x8g6xgokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3x8G6XgoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q7pdmmcuIFO9bAlCNEOAyHcYCtcJvvgkLL8VZt4JrAk=;
        b=IlyZqqP8xXv246HE0yMaZi4SV9bl0KY6XJ1KKwP9C4d1H2qE763TBPGhXKl7jJmD/Q
         MmQKXMYARLXzhfwudYSCFJW2XZ5uU7TqcV0kLSWofpc4juPFqRbFrbhPl0CsmPq1u7eZ
         0XXq963igCeenxLNfNKITj+DUuFDMrSqqNEwCDxfYMpIxD/RBRaEjrlApz8wVJh+OgCa
         WR5V94uPV/VZB/siZFlq1VNX0/UVxryC0o8DgSdap2aB5yGgInM6N+Uf7tjXUIAjqd2/
         yyY97ww+5bAXbm3C/T0VC3dwacVMIsBYRKFVkzkYw96w1jVylehHAHzy3RMtypO48KRe
         qMzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q7pdmmcuIFO9bAlCNEOAyHcYCtcJvvgkLL8VZt4JrAk=;
        b=etd9Q9VaA5rmjGiNZdx0q369MFIwGDrcGmXa7kKTWv+mIDlkGtLDm58/F2TFCnEGIT
         e+p5aOohDPQYO3UugNJMTHr8Pn5iHQD5C5+EZY88RMqMAhL3Oa2+O1apPfm4R8ROGTIT
         dABn/gPw8Ahv+wUBHHt0nWDjJqcg3zy5TeHbed+rT7Vy+pFp1NXmgwwnznbPV4n5PFuy
         1FwBw+KBcxfSte6yOod3n8YPHTwYvOyEP8igqOMM19OqSFpVUHEE1gUlDsW0l7h54Ss/
         UdoWL532PslVdXD+GTWInnPiCQNrtzN5AOM7L4uHSKK/WGCwXvxCC4L+N8QsRQaC3V5A
         jE5A==
X-Gm-Message-State: AGi0PuY8XVL6RY9KTJi73/Qco39FW2bSstqX2q8OBlrlSX9no6dC4snO
	Rergqa2RCMmK1SjSgHkXjEc=
X-Google-Smtp-Source: APiQypJkIIN9cmch8ocNNnxSO+LwaFA9ELFanUOrdFe/SyQXdzQpDXvNGayxxUl+UFyxPZd9SUd9tw==
X-Received: by 2002:a67:b91a:: with SMTP id q26mr16846876vsn.118.1589297608277;
        Tue, 12 May 2020 08:33:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:80cf:: with SMTP id b198ls73200vsd.3.gmail; Tue, 12 May
 2020 08:33:27 -0700 (PDT)
X-Received: by 2002:a05:6102:3d2:: with SMTP id n18mr17291849vsq.157.1589297607828;
        Tue, 12 May 2020 08:33:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589297607; cv=none;
        d=google.com; s=arc-20160816;
        b=b5rvS1ZK+A/1stwM/inIkkHe5NlP7v7DRYJDEljT7Xg2IyJEX3n3I8ylrdxuGOOYfw
         RVtftv6N/7FOVcP7Ju+KYaLxNRjdYubgv2CGN8eOde+qp+MwDWmmdPjS/ErRWjuFjIbE
         +WKdlWwZo/A0Xp+FHWnPYpP3wLpqBKIMN/OsthMrFd8FWUxu1uXu1oE2V1Tw5HFOm90F
         A2LHB9kOihShBAiaWNlup8dFEdqsE01fqyg08TnQE4SswmQMCDCIoCHRw/vDtM0VYL82
         51OBUKrXOTZPZKFFNY7iemUV9wEIeGxZ8tLr0c6bYBCdUKww5JfaTN7OpS/wnjXtM2lS
         5fJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZV8IIs+LNNWl9Sq9YiRd+Sff9ry91f64w9KGyz/EsLo=;
        b=vwO81eTecxLcCLzrZOBLOB+ccbga+2RAKgDC43JC16BU5bpN/MXLWCP+nVstRkNfpS
         I5CRzCrd32K5b15hOxaAkZY0CJY8XUfFC48t72dRlaNvzumq9rjh2awSy26vFswqDrX/
         x2QNfI2EeyOfam/buJpoXXxGhEC60g+BCItPzX8t4kgXbC18EsgdQlyQ2J42K5lUW84q
         X3qXXwZf8Z6bbaZLxnTVT1u0KN+LZ1GH0W8edc6JxLvLFXcqSifHjr/VHlhvBosxybWz
         1OMCqpZFybsTh1F0UC6PvQKfW9r9egm5BFie+JD31ojHr6YSp5RmER7vnzmlTsYKfiTo
         gECg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wBMVtnmp;
       spf=pass (google.com: domain of 3x8g6xgokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3x8G6XgoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id y77si683138vky.0.2020.05.12.08.33.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 08:33:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x8g6xgokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k186so4932401ybc.19
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 08:33:27 -0700 (PDT)
X-Received: by 2002:a5b:2ca:: with SMTP id h10mr28140141ybp.37.1589297607322;
 Tue, 12 May 2020 08:33:27 -0700 (PDT)
Date: Tue, 12 May 2020 17:33:20 +0200
In-Reply-To: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
Message-Id: <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.26.2.645.ge9eca65c58-goog
Subject: [PATCH 2/3] kasan: move kasan_report() into report.c
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Leon Romanovsky <leonro@mellanox.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Leon Romanovsky <leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wBMVtnmp;       spf=pass
 (google.com: domain of 3x8g6xgokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3x8G6XgoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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

The kasan_report() functions belongs to report.c, as it's a common
functions that does error reporting.

Reported-by: Leon Romanovsky <leon@kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 19 -------------------
 mm/kasan/report.c | 22 ++++++++++++++++++++--
 2 files changed, 20 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2906358e42f0..757d4074fe28 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -33,7 +33,6 @@
 #include <linux/types.h>
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
-#include <linux/uaccess.h>
 
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
@@ -613,24 +612,6 @@ void kasan_free_shadow(const struct vm_struct *vm)
 }
 #endif
 
-extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
-extern bool report_enabled(void);
-
-bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
-{
-	unsigned long flags = user_access_save();
-	bool ret = false;
-
-	if (likely(report_enabled())) {
-		__kasan_report(addr, size, is_write, ip);
-		ret = true;
-	}
-
-	user_access_restore(flags);
-
-	return ret;
-}
-
 #ifdef CONFIG_MEMORY_HOTPLUG
 static bool shadow_mapped(unsigned long addr)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 80f23c9da6b0..51ec45407a0b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -29,6 +29,7 @@
 #include <linux/kasan.h>
 #include <linux/module.h>
 #include <linux/sched/task_stack.h>
+#include <linux/uaccess.h>
 
 #include <asm/sections.h>
 
@@ -454,7 +455,7 @@ static void print_shadow_for_address(const void *addr)
 	}
 }
 
-bool report_enabled(void)
+static bool report_enabled(void)
 {
 	if (current->kasan_depth)
 		return false;
@@ -479,7 +480,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags);
 }
 
-void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
+static void __kasan_report(unsigned long addr, size_t size, bool is_write,
+				unsigned long ip)
 {
 	struct kasan_access_info info;
 	void *tagged_addr;
@@ -518,6 +520,22 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	end_report(&flags);
 }
 
+bool kasan_report(unsigned long addr, size_t size, bool is_write,
+			unsigned long ip)
+{
+	unsigned long flags = user_access_save();
+	bool ret = false;
+
+	if (likely(report_enabled())) {
+		__kasan_report(addr, size, is_write, ip);
+		ret = true;
+	}
+
+	user_access_restore(flags);
+
+	return ret;
+}
+
 #ifdef CONFIG_KASAN_INLINE
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
-- 
2.26.2.645.ge9eca65c58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl%40google.com.
