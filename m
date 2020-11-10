Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPFEVT6QKGQETHSI2SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FAE82AE326
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:45 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id z19sf81606lfg.11
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046844; cv=pass;
        d=google.com; s=arc-20160816;
        b=HILiotxFtUcaGONf3ptwHzo80LLtF2KMN3AQ9DaO9yP45Z+JME+wn4A662lRTTbLNS
         W9irWcY+w8TzRxKESAzVSnR/an4Wo3SRS09QWPlg5VtpyIPPgldYmRAM3iP+M9so33cL
         f5H/SV/Sv6pJ5H48uMWdbpiyR6x5IXai+O49F8hGuBLEdFMTT8O3IRnyzSe18J0RJHOt
         KhPgvrDD4lp3SnGFWTskjL/r9knbgERq66OHhT4eJW9CAT2xh4kLuDRrZk7ORtmG1GFV
         FQn641hvJrtQhYPlyc6q4t3XFaslq1PDDk7gZ39X/KW6DfuczdLEtkPKquqcFkcYYw12
         ZEdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VHSmxM6tLi64fsrLmoDuW06/C2l3cd7V45pAG5XlC14=;
        b=utARqUytJetyz6OwB7oSCtXXqyfXn6sPfl5ZLQ79UOKTY7IGLQSyVjVn7TkkNuHK2K
         p6HOF0tXJcguMM/iNqwQi25RoUzx4HmMwiNYUFEdI462HMQfALDNez2N0tCoJJsoQFCd
         4KOyUJYebq1d7UHbh56Ej8E1urWAMMfsJkKddFNAAu/u+rERhzvTCs+9KLlJlBQ745vS
         KZ9/8sueY12c09ZPcvp4SyqqK+mgkv8ylEMPbTfMyu3h4NMN5kwUhcbPYX4w0JyQfJYu
         daOjXbbXVqWa4QsuHNrlxPXt3AQe83IvwIbNgc3q1djfb3OcCRDHa8PirTZHqnhUC77U
         HgLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ljjlpu85;
       spf=pass (google.com: domain of 3oxkrxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OxKrXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VHSmxM6tLi64fsrLmoDuW06/C2l3cd7V45pAG5XlC14=;
        b=githr8BujfRr0PnrMrbP+d6h+l8oAsuMA5LacAFKafYTdn8SbT3WiL7/7U/sEd09Og
         rmZI/ij74TkTtOTIljOe1rdT+AkYBfsJgEcekf64qrEK3vr8zjl3iNH3DYiB5pZj3WrB
         GtbnLc6lcC/S9YkSzbKGL9wiZ0x8vBHtDjIpvbqKM0mSZJYS44iib/bK8WesnKbc8qbV
         Q1bcs+6RTj0GNmPngj0j/9xQNGfb+MNR9YIYlXn7K+5KNNkaZAPYNKWZPRfD2w+KhRvR
         p2zctNyHrGQSSU9BU3pYTNA6aoXSO4K+cS60TC4cMt5AtkmJmuIPS3j8kKPBhxONav85
         Kk5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VHSmxM6tLi64fsrLmoDuW06/C2l3cd7V45pAG5XlC14=;
        b=FnTg0XQWVqE0WfMP8d5BUs9udzUCfwAJ6Y1osSebUCBXeaJifFsTDXbVQxhKISWY0P
         rzy/bz6Hhfeyhptlm1FllkDuIiMP8HJyTwY/zlSPmOK4VnLUqFeoFoXvTFAaOGPPx7Kb
         QJ2luIBkAIL1wdzjVbI6/cv78hACD7GHDaGGQgOqX4T7jKjfJaQGpMEvbl8BUa6L/eoB
         ALQuyJv2BV+//VBpETZEgzvUP7qDAfnaG3qO4QYUz429A+bA9EM+r70p+nzS6Mp94JVy
         j2abenAj3wC0cpClP1+HlbSDCqJVJUYmOQhJc4ohGOn3i3AEe8PRSlnLMW2IkhTIMYHm
         bZsQ==
X-Gm-Message-State: AOAM533L/N3eJs/kScl8tIQQYAEwl4zdsLtnXwPYpC06/ZwgaQiGJsNA
	LrvK08jUh5F142OhN8qowIA=
X-Google-Smtp-Source: ABdhPJzmqsNCGC/VXXqPxcPfFGjQVB+Gyd9OZ8sAXdpuylk9XI8HiuWBlmVVRqbWccF/4GNvYBBJAA==
X-Received: by 2002:a2e:984e:: with SMTP id e14mr9808074ljj.110.1605046844720;
        Tue, 10 Nov 2020 14:20:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls1306066lfg.3.gmail; Tue, 10
 Nov 2020 14:20:43 -0800 (PST)
X-Received: by 2002:a19:913:: with SMTP id 19mr8964442lfj.147.1605046843849;
        Tue, 10 Nov 2020 14:20:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046843; cv=none;
        d=google.com; s=arc-20160816;
        b=VjZR2J93nwewh4ks+V/bdK2t7aY6crrtvPWVjqLKIQnOtMuIXPSOSpN8QbRfV5bpll
         QE75+Qw8qANKAwdKrRAd/BkkY3/nSyWA69Ovf1mROt7VZdcJfDiCmeWZ7nkONuByv4W4
         76iRMqJHOk/ALRskhSMVxFWsR0Cw07GB9NOdx9ImL3VAfxCBo5vGT7AXA1yw+x9tPPUS
         EQRW9s2zzPgKOOwiBg0X2bHiRnDdjQ/hTPjRRT0euupZB/xLlIMy4AFu7BMA8jRt5nBS
         yu4XtpS+DAMBgEySzCPKP3FJRsbfRqi2bl988ajTLTI4UfsO2mu5/wydTIePGbN32iVh
         ZMbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gyGUZGx6qFH2jkAU5L1Nk+VZLXl2e4B3h6WrDO5AJuc=;
        b=lg4iqAza7+gwL8YnRAWEtzEvBUSKbxYyzvpuREIkHXONYm1yKolpqSU3e9tYrmGg4/
         HlXuhuyzreuKsqWMqnit/KrCGf0L3kaa/Fk/q+ntukZQkly21+sA86sGnl9H3lK119GN
         xl2RPAwzak+3Q7q3KgIGJU2TcjAKQYE9uQaPTdA9n2pA8U4wDRUzzihx5nEnwRK5r1yS
         FSwqa8z0V23MU9i3z7ipl8VSadxybce5o3uFBGzj6lfLy3R6wAMyvayf2qZ2e1xnJNTL
         LvW6MuMBDxFKSTlbrJNCr9QIAjsz0uVypHCCQ32xm25VI7h0xR+JVcWuBHy03cRKOo3l
         lj4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ljjlpu85;
       spf=pass (google.com: domain of 3oxkrxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OxKrXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z23si7106ljm.6.2020.11.10.14.20.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oxkrxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y1so1868388wma.5
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:630b:: with SMTP id
 i11mr5840517wru.404.1605046843285; Tue, 10 Nov 2020 14:20:43 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:10 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <462c375f39ba8c4c105b3a9bf3b5db17f3720159.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 06/20] kasan: remove __kasan_unpoison_stack
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
 header.i=@google.com header.s=20161025 header.b=ljjlpu85;       spf=pass
 (google.com: domain of 3oxkrxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OxKrXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
currently used in a single place. Removing it also removes unneeded
arithmetic.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/462c375f39ba8c4c105b3a9bf3b5db17f3720159.1605046662.git.andreyknvl%40google.com.
