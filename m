Return-Path: <kasan-dev+bncBCCMH5WKTMGRB74SYWWQMGQEIAUO46I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E26783AFF4
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 18:31:44 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2cf2fd27e1csf3723831fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 09:31:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706117504; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCw5iLA9JRIZdUXI7S9WN5x8frXbPHVIDNNhyjm9vkLo0FSCbpgQNI83oi56DRcPA9
         FMAzvkMYrh3hrRctcJ8w4/9mL9l6mxZoipj8dbN4bIAFfNT5osTb/YEzpK+AciXFV6jz
         j7PFcpZSxdFVGAMGBulaXYdUE9vpkOreW92dZ0FpsCOEqRm+UYinkq5BGnehmiOfe9qe
         kMKQ+QegQxt449qyxOlhtYgCZIl8iSpbujw4RoC21EWkqhNRkp1EgOIt5Nuv0qHJ9G1j
         FTd3sM6mFsi/5lwkBc7/9ik53fWMzMkekUKi0W+5SLHO+blgV9ozhFs7Y+hkvtmgBOQ/
         qN4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=8aD6pF6tXCJJW1TGe8tpOCtM9tfgBLEE/MMniSiZBIQ=;
        fh=Kqo3G5+KDeAKSSAN0QOehLq4Vu7JLa5YA3bSMHyGhM0=;
        b=hyI3lrk1DXIXabhcl5IGDBamEGa3SAXOflsG38Ya45tVlFcFbAbrIi6Xbag/RzUCPU
         VDWe9uX9FqGpYeAXr2hjpvc19IFZvaMOTq0+sq6EG9/tFkMaKUiVNquUsNUCEbE+fz1a
         8/oaRqbsuTWRQ9bDGNWZZKJ7IGT/iKSOvZkHoO2L3HxQ4THgSNTHR/hlQ+QJfAMTNPjR
         i1s5k+LtATGjWGULUml3hg//r1gZyiwUuZ0fq+b7X7PChq1w4fvXsdXyBQj6lzECouIM
         6CrY6SZFPPxsQGGUdy8IZyjxtDkfmu7AcxEQTXc4Ra4xy2/EgAxtY1bBNbIE2YUHjMiF
         iWlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AZ/pFhQD";
       spf=pass (google.com: domain of 3femxzqykcqkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fEmxZQYKCQkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706117504; x=1706722304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8aD6pF6tXCJJW1TGe8tpOCtM9tfgBLEE/MMniSiZBIQ=;
        b=IaSwXkVM7GZ7xL7ULwHX7OZhh2ecLVlH67auVXgzClQBuHgfLJB5UcJZUdwUT0w9II
         kV5ABOJSVrQJNLe41kaQUBPmFQMngmRTyJMAGsCth6PBRB8exU+eeYYfAeV6nD4gW4hF
         cEeAX53jMXIcmb/ZufDDiFB7iML16nSf7qdVsflraUqv5QeyXzAOlkRi1RPKCG59VUCk
         1Wo0wDbGMuD+XE6WG5tDbsaBFtux0z8+2WBuryK9Oal1UBaN8uqcb91Pv88niZQx1cx6
         p8bdigtyXndXheIwBrhXv3PIy1qWB6w/aX540F6Pr/jdyDOM/MeJlio4XoNGl/7rz3hb
         Z/xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706117504; x=1706722304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8aD6pF6tXCJJW1TGe8tpOCtM9tfgBLEE/MMniSiZBIQ=;
        b=IEfnT2DbDb280I0+l4k0AEPzYNo93ciWIkXGVIf6NzD/hwNq8qoHHczDYy7AO6gu6G
         ezdyRChbJeYnlWlq0uZE5S9AzW66tfB+dDn0rd2nmRWA87g8WRDF8WDObcFx2t6C9jkK
         orTo+rpMcVnKcPe3jScPNeiW2LP2M33u/Mi+igQxPVckyNOcJp2WH5luptyKMIWyNpzn
         1bTpqn2+L224dQdh0iWhjL0oeRpRjpg5negvBcUGXtJAqtnJVCiQXFXXAcsRwHorEiG7
         GQSyDztBCLXoA2GueS1mMHoEUgP++k3CJ2cOeTUKW06/LfVJJjN7T0D3lFMXE5AcXgLg
         V9JQ==
X-Gm-Message-State: AOJu0YzQXPxYGgu35O9O4Qdv0NHgNhLq6kq2KyLMOrooAMqDXTkUrpNY
	gccYZau9RdFUeCvU0oalZjc2W0+qH2ba0VYMP/CWOgiMJ15lhBve
X-Google-Smtp-Source: AGHT+IHD04nJmz1BGlO8Ctb2dOSEUpc8TTteyVBHow7KHmvxoneKMU+0XQNlgcusJXrG9J93+/8flQ==
X-Received: by 2002:a05:651c:19aa:b0:2cd:fb10:f9b8 with SMTP id bx42-20020a05651c19aa00b002cdfb10f9b8mr1443685ljb.23.1706117503473;
        Wed, 24 Jan 2024 09:31:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a06:b0:2cd:b310:f5af with SMTP id
 by6-20020a05651c1a0600b002cdb310f5afls272399ljb.1.-pod-prod-04-eu; Wed, 24
 Jan 2024 09:31:41 -0800 (PST)
X-Received: by 2002:a2e:9d88:0:b0:2cf:1cc3:fa5e with SMTP id c8-20020a2e9d88000000b002cf1cc3fa5emr1037204ljj.63.1706117501544;
        Wed, 24 Jan 2024 09:31:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706117501; cv=none;
        d=google.com; s=arc-20160816;
        b=gVUBVMTsBj3c2y4Jj7L3WOx278yBhszTFmiyU7bqP3oRgIkinbuODkO6KbK5s6MuA0
         fxBZQD8QF0Z/gKSypibasvSk4IklKV4WPaCAWYlwJUXGHQjD8hr5sQu52jXVif1alaMB
         gWdcCSBbEYXqyvikPAMVYccrfSp8kjLeBA3XC6deeaj7uei3beoPC4grJAAFbWKFjBp+
         Fn42Jcpq974saXjeKhLksNb9PdJmj+nvMb/ZREiJgGhNHMUJ+z4H41gWDuhGMJpixfLz
         dELE4Z8+zZoBITWtOjJN2f9JU2uqQQI4ATp2jz8vTqdutYiIDKLBDI9kWq5ngaTsfJ2u
         AtEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=kMQl+PaRJqmy3cHaG1IzDq8AzN3RMVuSbCxHhfx+H/0=;
        fh=Kqo3G5+KDeAKSSAN0QOehLq4Vu7JLa5YA3bSMHyGhM0=;
        b=S8ce7tyP095knSLL1AlnxZecEZnkQ4H1AKLKOQz99nbrgTGH6eNSK7jdxPT2U5W2u/
         Ejl1QSSROxuRmHyCPjQ8yIqtvKMymbmLrTMuT9ShwyU/F51l6Pz+rzqdK253bDswZLy2
         Ztm9HcgLt/K9xl/jZ3sm/GR1cPZ7ouJq7eUgJUvIhy6b9kjgYy2th7JTiag7C8/u+VEV
         TxV4w6KkzCEDTI1gRfauN3QDT+z5hN2CGNAFrmtj9nwlqMKfVVTcA6ihRsvk/DvTfZ8k
         6nhiCs7EznpTVrYMhOcPXkHjylohSLxd5orUPAigCTAs23VE7FWf6lqQPGhxc2jPEHFT
         xsRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="AZ/pFhQD";
       spf=pass (google.com: domain of 3femxzqykcqkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fEmxZQYKCQkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id i20-20020a2e8654000000b002cf1e5e1c4asi9975ljj.1.2024.01.24.09.31.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 09:31:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3femxzqykcqkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5597d3e0aa3so3387626a12.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 09:31:41 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:ca56:4222:6893:5055])
 (user=glider job=sendgmr) by 2002:a05:6402:2491:b0:559:6fa1:bbec with SMTP id
 q17-20020a056402249100b005596fa1bbecmr26136eda.6.1706117500691; Wed, 24 Jan
 2024 09:31:40 -0800 (PST)
Date: Wed, 24 Jan 2024 18:31:34 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240124173134.1165747-1-glider@google.com>
Subject: [PATCH v2] mm: kmsan: remove runtime checks from kmsan_unpoison_memory()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="AZ/pFhQD";       spf=pass
 (google.com: domain of 3femxzqykcqkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fEmxZQYKCQkpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Similarly to what's been done in commit ff444efbbb9be ("kmsan: allow
using __msan_instrument_asm_store() inside runtime"), it should be safe
to call kmsan_unpoison_memory() from within the runtime, as it does not
allocate memory or take locks. Remove the redundant runtime checks.

This should fix false positives seen with CONFIG_DEBUG_LIST=y when
the non-instrumented lib/stackdepot.c failed to unpoison the memory
chunks later checked by the instrumented lib/list_debug.c

Also replace the implementation of kmsan_unpoison_entry_regs() with
a call to kmsan_unpoison_memory().

Signed-off-by: Alexander Potapenko <glider@google.com>
Tested-by: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 mm/kmsan/hooks.c | 36 +++++++++++++-----------------------
 1 file changed, 13 insertions(+), 23 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692a..0b09daa188ef6 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -359,6 +359,12 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 }
 
 /* Functions from kmsan-checks.h follow. */
+
+/*
+ * To create an origin, kmsan_poison_memory() unwinds the stacks and stores it
+ * into the stack depot. This may cause deadlocks if done from within KMSAN
+ * runtime, therefore we bail out if kmsan_in_runtime().
+ */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
 	if (!kmsan_enabled || kmsan_in_runtime())
@@ -371,47 +377,31 @@ void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 }
 EXPORT_SYMBOL(kmsan_poison_memory);
 
+/*
+ * Unlike kmsan_poison_memory(), this function can be used from within KMSAN
+ * runtime, because it does not trigger allocations or call instrumented code.
+ */
 void kmsan_unpoison_memory(const void *address, size_t size)
 {
 	unsigned long ua_flags;
 
-	if (!kmsan_enabled || kmsan_in_runtime())
+	if (!kmsan_enabled)
 		return;
 
 	ua_flags = user_access_save();
-	kmsan_enter_runtime();
 	/* The users may want to poison/unpoison random memory. */
 	kmsan_internal_unpoison_memory((void *)address, size,
 				       KMSAN_POISON_NOCHECK);
-	kmsan_leave_runtime();
 	user_access_restore(ua_flags);
 }
 EXPORT_SYMBOL(kmsan_unpoison_memory);
 
 /*
- * Version of kmsan_unpoison_memory() that can be called from within the KMSAN
- * runtime.
- *
- * Non-instrumented IRQ entry functions receive struct pt_regs from assembly
- * code. Those regs need to be unpoisoned, otherwise using them will result in
- * false positives.
- * Using kmsan_unpoison_memory() is not an option in entry code, because the
- * return value of in_task() is inconsistent - as a result, certain calls to
- * kmsan_unpoison_memory() are ignored. kmsan_unpoison_entry_regs() ensures that
- * the registers are unpoisoned even if kmsan_in_runtime() is true in the early
- * entry code.
+ * Version of kmsan_unpoison_memory() called from IRQ entry functions.
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
 {
-	unsigned long ua_flags;
-
-	if (!kmsan_enabled)
-		return;
-
-	ua_flags = user_access_save();
-	kmsan_internal_unpoison_memory((void *)regs, sizeof(*regs),
-				       KMSAN_POISON_NOCHECK);
-	user_access_restore(ua_flags);
+	kmsan_unpoison_memory((void *)regs, sizeof(*regs));
 }
 
 void kmsan_check_memory(const void *addr, size_t size)
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240124173134.1165747-1-glider%40google.com.
