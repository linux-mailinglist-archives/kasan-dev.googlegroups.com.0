Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4MNY36AKGQEWCXGOQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D7C49295FB1
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:46 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id s4sf855537pgk.17
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372785; cv=pass;
        d=google.com; s=arc-20160816;
        b=luYS8jU0qNl7HgyVxWKUuM9MC4moOm44YCTeL9Z+vLvr1bfp5veTSIuP79c9BZRHV5
         2Qoyl057ej2EVovj5RpUzU1q0Yb56vvjKvOWgWm1Hd432JsiAFmk0q+DPZYyaklFL5Eg
         K5zMR6Sq8O0YGjMEdW0Cn+mGfH6fxh0IRIgDyx0DlBg0OBzcJvt1841jESkhYcgJxgdU
         XNPpf5o/CTneedlX7NBMN0ZljS52jdJNtPvCCVyduyFBIFV0STujNNyUP8DGyB+2DZYR
         PCnztuwEKg06P19EaWiAZSwtS5a2ws5LI2txDAkXLkckH3Aem5Ea1u4cFQLOCzGeLdWT
         aHeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tVVFpVpffJOPeqJY7GVjtqg7Ya0iRjl3rjulkBARtXk=;
        b=mDlNnj+70dXWHA/IO51m/TPSu6QzP8mvJpHEy3eJbwAwgKD23YXEuCB8+x271o0+BL
         l5dW5/EQtuWNrB91btawg2cumPLCRW8/IOmt9O1uoczNV9JfocWo6EEnIFY4x/jiZPFC
         3VGlCdXbzXuDtBZi4RSwmZ9k+RPb4qvpDRD0s95CqF6/9SZBPb4okRVZZFKRTVBJ8ExA
         sVcmHZIbqEKtt7v5XvqLx7EkqNDU2uorI9ERP5YBAayIYDhw3JRuRcWW9YA+L43qF4PO
         Nxnp89I3kvGVGsAMq53YU16Sj4NqP1SBZJq1IlTArkbogEPtMztIUt7FFGP7vnU6ZJiF
         y/Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KYdK90La;
       spf=pass (google.com: domain of 38iarxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38IaRXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tVVFpVpffJOPeqJY7GVjtqg7Ya0iRjl3rjulkBARtXk=;
        b=q6ebE9JF/Z3BxjJtHGk81qLmyakb5IcnAlBlzRHtYvuqdAprfU/UndNwheVkwyn/TV
         MT/9s8GEZZda5wV7/LqH2OktNF5PKj5QbZ7+qbw8T8CnQnIABzP01OOH5lQ8YQOSqBJ0
         Z2cpUU8eVJC/baKMagjKl6GW17tvGFKU62uztmWX4nu4xnF8Uuxg/6oph+SLWjcre49H
         6n+eOzhcMTX3UKxiSUUi6pGj0S4nN3USWCX5tcMrLF7lJLhChpwXDgIbrXDfHEp+y2M+
         JbaLCiLbOCcZN7Rr2Z2d4EwBuy7D2/iymB7qxavuAUsIQbY7r0nCB6HpEWMcjY2qUlAn
         707A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tVVFpVpffJOPeqJY7GVjtqg7Ya0iRjl3rjulkBARtXk=;
        b=CraYkK+NLNMtx4Qug0cYf/1GecGuNZbBo3OtIjuQGL5pWZl61M5lx4MWokU52cgsVS
         eIAOkzXJeP6OWAMmQ5V/fI3dAsD8xpi1q1SC8eoqOixmACxPk9icPchaeUTKlgXhNpZ7
         /CM+d3FcLlwwshsGMB+iP+3gPJ+lw5wTJp413La2GQfB8U+ANuboDXcGkC//dvgiL4/p
         Qe/IdncgWhd7uXvfIw0KhIfFf8iRHFldD1H3M3oTzzSoMX6JIWaczKkrQqJ+lrD+KKBx
         ekUkzjic+pTDFaFoKQ0AkdqRKamidRQFY15ttDb1dZ6dzwFeE9lcxvkmlphA/Yjnevy3
         EYqQ==
X-Gm-Message-State: AOAM5334PQ1QqPTf9pVkkoGSQbB+vANtMoAquZCwPkkgyXRxBXwM+ZIv
	K5YzOJ5w04VZAGJ1dImUon4=
X-Google-Smtp-Source: ABdhPJyPanTbizmjrHfIZEgEYfAeLXXgDvji+x6Qr8VNJvJUzN9Om9yl3uWCTIJlV2WUCoi5fMZXsQ==
X-Received: by 2002:a63:fb48:: with SMTP id w8mr2191376pgj.218.1603372785565;
        Thu, 22 Oct 2020 06:19:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:86d4:: with SMTP id h20ls743659pfo.7.gmail; Thu, 22 Oct
 2020 06:19:45 -0700 (PDT)
X-Received: by 2002:a63:165b:: with SMTP id 27mr2164910pgw.197.1603372785042;
        Thu, 22 Oct 2020 06:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372785; cv=none;
        d=google.com; s=arc-20160816;
        b=NKEC5wsKov2ozceS4m7bA7z5p8ElD9F0BtTU9jPEaDpV5mZcdMeTuheBW7aIpGp/aT
         zJRjX1z5AgOeEANWBnhk5mx1CNzb2t6lnkCbklgtTbNTGMjabNz3MxbbKO/ae59cIqp9
         mLQwk6fdDC7KhKTEusRQ3ixqp1oNxP00N/B+lkZIUWcHLnacYzh5ynhZMiXCGDsnNI79
         YCEDFBE0XkLVtInEyPMOLULLCmqWNRZ74Sj47sh7qcko/Zv5jGAlINQwn5LQuYurHkxB
         yMsI7ykoP6J1poxOBnAAp2mWXnm1KD8Oj1JROOhtho5KQyGfOnTxLS9COZ4d3qZvkknl
         rsMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9DI5u3KafPzj5V3i+niAdO1uhXW2it0RjumucIpkaOw=;
        b=lk1whM9Y5Shf6+b8fBNq7HN1jEPohK4EdB96qWhC4w3YIqGlV70eKcZbqsr/aR09TF
         roT+cl0JztL+bn9muOf1C0Uvc2Hj43Wpi21YtYNlVdHX9kygP3JJYGeY0bxzNc8Qs7El
         FuPEbisfFXkHMYo245/krvfU++tPv+3snVPZbNnOpmWXEfpt3ioBCQm/NcaEeXAc7Rjl
         bq77GMzN13BbVziwiTmeZcscSUxRURyDEids9BodBRwK3MIvIn5NkqIODEXSXs8vN/kw
         YJvOQNM42ZocoU3GRpq4xoOem/4BD9pMgPkC87TN0CgPxbMUKPzVrBDRap0NRKjNBvA2
         RA4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KYdK90La;
       spf=pass (google.com: domain of 38iarxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38IaRXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id u192si121574pfc.6.2020.10.22.06.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38iarxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id z9so989334qvo.20
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:44 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b5e1:: with SMTP id
 o33mr516199qvf.17.1603372784151; Thu, 22 Oct 2020 06:19:44 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:00 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <84dc684519c5de460c58b85f0351c4f9ab57e897.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 08/21] kasan: remove __kasan_unpoison_stack
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
 header.i=@google.com header.s=20161025 header.b=KYdK90La;       spf=pass
 (google.com: domain of 38iarxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38IaRXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

There's no need for __kasan_unpoison_stack() helper, as it's only
currently used in a single place. Removing it also removes undeed
arithmetic.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50
---
 mm/kasan/common.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a3e67d49b893..9008fc6b0810 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -59,18 +59,12 @@ void kasan_disable_current(void)
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #if CONFIG_KASAN_STACK
-static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
-{
-	void *base = task_stack_page(task);
-	size_t size = sp - base;
-
-	kasan_unpoison_memory(base, size);
-}
-
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
-	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
+	void *base = task_stack_page(task);
+
+	kasan_unpoison_memory(base, THREAD_SIZE);
 }
 
 /* Unpoison the stack for the current task beyond a watermark sp value. */
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/84dc684519c5de460c58b85f0351c4f9ab57e897.1603372719.git.andreyknvl%40google.com.
