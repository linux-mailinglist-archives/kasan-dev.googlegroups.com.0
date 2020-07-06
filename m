Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMHNRT4AKGQENK34N7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id ACFEF215999
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 16:35:29 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id x1sf9254676uar.4
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 07:35:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594046128; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQ3AVq05p8zT8AevlBeZy57H5jo834KKp3B3pzgZ4fFAw9h8K1d3mP14Ep1udXC8j2
         K4XgPTolKLpawcHnROf7G/tg4z9bDbs7WYxGGF3AN6rSIa1KqXRtoOntZGDWm+UYV8NP
         2svjHJeRE2BQdsQNaKLlWvwquhgbrh7XhMwsIiVgPIeN2ZVXxUZQcJMMRvsjSRbLBYrJ
         6PGKfQtuDWrjcFEP7JejzQI0tQoD2jh7fcB4DFzh1rHEjdZyhXXn3mIGMH9IzV+0sxPQ
         4qvMvJ+qv2Ur+Xy07s932cq+Z7oAnuZyiamtL7uq+KlDlGHbolomy2l8W/0o+gb5pEOe
         wYBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pBR+ybceDFh0gQzaJ+MswlAADlyem6wDeZcAJKOXPBE=;
        b=CQEbH3bSvgfnoCa0TZDl8mp4whSrG1VN1LC1ZRbO3gH7DINQXciKIeolB5A+F+JbyE
         hM//J5pt7pgi7YuC1K3uOYyKOGpAU3ZUPiA3DN/MT/Kd8r/HTM4bxcIgVQPbvOSWbx6o
         vJiAfUYH2GdEjUjBxy22z2XN+/IaoXdzWrwAkB+oinqWSJf7mxlomfqdR/Oe9zMoO8uL
         bjdBU85pwC8HgUcp/ZfWI5jiF0WqZWUR5naxcY+8BDz8xLP1IHpR8udGbjVmFT5UNF+X
         6YrY1t3TnPzt1YvikYBCMmTQtZZR9cXvLo6zBTWSWSz3+2c/onAhhXqUqo6/FpC2wYnM
         PboA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBR+ybceDFh0gQzaJ+MswlAADlyem6wDeZcAJKOXPBE=;
        b=QwvePXWghgdj0GkGYoMJsyH/ADSu4pX2dFO/BY3wrUGLUkCU3AdEUEUYyUxCSZTy6u
         dD19LUFqD1Q+7NcCnUkrfX4TdteDsood4Ap59quNvo/GbX+rl5iYPYu4/4sk7HMvD2Cj
         E3O/yvFpfEyp/ehNp2QP315EU60wHW+loYTmPMJ+pjQY7kqS/sgc6rkJim70eUeyPP4q
         UrBxlhM3KXNFSY5mTw81EOnY6x3VOt7v4V4sj+9sjxmipQqY0GyyRLRLhpenZ9UrmFbR
         mCMWWtHSuReOdmkDWoonsbsrKBmSAvHN0z6kRlgnCx8YyTMXzSfKTwvVzScREV8WMfcD
         oKKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pBR+ybceDFh0gQzaJ+MswlAADlyem6wDeZcAJKOXPBE=;
        b=W7BmFkguXhcfTZ5O0oLzpxZuNdqUCGzqjKQIIeZIGo0QAUYCS/MeBlljHgn535v3nc
         B/TALCXLqL/zqBEUm8VQ9n+85peh60WZqKGrJbwvR7JAowKjpH6fw584Gwp1lCXguskX
         94JGfjc+qrrzQCEKb4O0wWFqqFLWqtaE5Xj7N+Gj2S3uWpla6H7D4QsrFddgSq7dtZZx
         KT5eVao9j9uKIjL5hzgkKo3mBxM61ySxhAlNuqOkiFRzu0E1s65FdZ+/qjn2MpHaYk63
         ePGohu2ovlFzPAwnNXhJ0DiwTQhUXy9esbP3m0c4XHRwBrNIVMCpInQ+pBOivAzM9SA8
         pkGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SehYGJ5luKeLrRjtHi5zjmE7PnGp7XPnbSn+t+Jh2EPSYRKNP
	g70a1/NdnAYEMmT8CKw5hi4=
X-Google-Smtp-Source: ABdhPJyYmfRWUXcCLmap5O+vdvGeT0kkW38HjhCOmEf7Ehzf1+c1w8/EoM5OBoC/tfB4EA/z3/umAw==
X-Received: by 2002:a1f:24cc:: with SMTP id k195mr4397137vkk.61.1594046128704;
        Mon, 06 Jul 2020 07:35:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7241:: with SMTP id n62ls737355vsc.2.gmail; Mon, 06 Jul
 2020 07:35:28 -0700 (PDT)
X-Received: by 2002:a67:3258:: with SMTP id y85mr692863vsy.157.1594046128265;
        Mon, 06 Jul 2020 07:35:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594046128; cv=none;
        d=google.com; s=arc-20160816;
        b=Dbe6CVIGgrFjrdkif5sMbCrJUDHQvSFNqeJq5mBHrvORpI7xDjr+1U+VmlTTevma9d
         9MrdBdK1cg5fWQiqLbRn9eLlpPaZR9EzUSFwJ4+WSOGOYyz7gEkrzuhltSn1jn771M8B
         /7o+WGmDYrll5MrOxaUlDXBK9yqyjLZ4W04NY1TND/FVCjtMfhZTJZlkKoJq4t/mWAh5
         6MVGBxmK1rE4o7W3gEKzYkbeCJ9s7qMl9oocNri2iSaV6fS2hdi0m0ANGQHDe/2YhgGB
         bbekM70d7T65l3B54hAtK4j7Cb1hQWwSGFtJdxr/6eS8Pe/ngpmeD4nruqtTC7Oob70E
         N1lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=juuuzWiVUoAE4H/EUqgFoqXZx0LCYrzuGO0PErBCDTI=;
        b=SfIUIzr+ArjszXxdhX2h0amlcJGm4WYI1RQOnJR2WprQaI5rFRyjVYvZY6OxAIwZuO
         eiX4GN7E4u854XuJK1K84PkXGf+S6T5bzYrE58jv0aiGC+wa4P4rE4PQitgJIO8f7tGT
         cr6R7dOxY6M3porCKP5wz24USlpTWbo9j1fQUkKmrzOzlnPzl1Hss8r+T9WlsRYc7WG7
         q668BxXIv6wj3pCxS39j4A1C6CBSaitC5SPT+rE2jN1nOv7C4qD+iaLLMn9Xv+H4+Gv5
         7jhv1yLuoNGk5Zw/Vk7SYoSoosccI1OOvHmPGIrXjp0ysk0BCU3y34UvW0waSmcnmtJL
         cHFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t26si822246uap.0.2020.07.06.07.35.28
        for <kasan-dev@googlegroups.com>;
        Mon, 06 Jul 2020 07:35:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A7A7630E;
	Mon,  6 Jul 2020 07:35:27 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 709E53F71E;
	Mon,  6 Jul 2020 07:35:26 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: vincenzo.frascino@arm.com,
	mark.rutland@arm.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH] kasan: Remove kasan_unpoison_stack_above_sp_to()
Date: Mon,  6 Jul 2020 15:35:05 +0100
Message-Id: <20200706143505.23299-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
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

The function kasan_unpoison_stack_above_sp_to() is defined in kasan code
but never used. The function was introduced as part of the commit:

   commit 9f7d416c36124667 ("kprobes: Unpoison stack in jprobe_return() for KASAN")

... where it was necessary because x86's jprobe_return() would leave
stale shadow on the stack, and was an oddity in that regard.

Since then, jprobes were removed entirely, and as of commit:

  commit 80006dbee674f9fa ("kprobes/x86: Remove jprobe implementation")

... there have been no callers of this function.

Remove the declaration and the implementation.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  2 --
 mm/kasan/common.c     | 15 ---------------
 2 files changed, 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 82522e996c76..0ebf2fab8567 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -38,7 +38,6 @@ extern void kasan_disable_current(void);
 void kasan_unpoison_shadow(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
-void kasan_unpoison_stack_above_sp_to(const void *watermark);
 
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
@@ -101,7 +100,6 @@ void kasan_restore_multi_shot(bool enabled);
 static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
-static inline void kasan_unpoison_stack_above_sp_to(const void *watermark) {}
 
 static inline void kasan_enable_current(void) {}
 static inline void kasan_disable_current(void) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 757d4074fe28..6339179badb2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -180,21 +180,6 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	kasan_unpoison_shadow(base, watermark - base);
 }
 
-/*
- * Clear all poison for the region between the current SP and a provided
- * watermark value, as is sometimes required prior to hand-crafted asm function
- * returns in the middle of functions.
- */
-void kasan_unpoison_stack_above_sp_to(const void *watermark)
-{
-	const void *sp = __builtin_frame_address(0);
-	size_t size = watermark - sp;
-
-	if (WARN_ON(sp > watermark))
-		return;
-	kasan_unpoison_shadow(sp, size);
-}
-
 void kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706143505.23299-1-vincenzo.frascino%40arm.com.
