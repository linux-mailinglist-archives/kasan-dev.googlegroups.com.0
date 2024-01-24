Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4P3YSWQMGQET7HU3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AA1383AE90
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 17:42:27 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-5ffee6fcdc1sf53386147b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 08:42:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706114546; cv=pass;
        d=google.com; s=arc-20160816;
        b=rwgqEK8bs+iJF82Sky2I1bxNEI5AYow9NcTnIY3kr7UvgK833JhwE/5B//D83HFAlj
         k2ikuSw5WJORd644qCDMlMqtXtMkr0+bCW8Nr31kri+zqAjxqo1cW2yHaGLhcWHgROkL
         MylXVsq6zswVbi7g25X5O7prDhUOSgfb+ozWI+LGdPJcWhxPKBHWpEkFQ0KNJBywE3lR
         mzGvlbq+WT+15Z59kUlSVDRSNRo1K64fZrNraALsCJaSq3AU3KbqmM4Smnq738kPjyHs
         B1UNVb3zw4WqD5fS1+4WBO+k5114lMY+tMs7Kkk21YFOqKKL7EwfROKrH4OE+Q3di2qA
         SGKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=Q2a4rdagje8UJeHKJckVlNfa/Th15mJL7l86yKC/GuY=;
        fh=Kqo3G5+KDeAKSSAN0QOehLq4Vu7JLa5YA3bSMHyGhM0=;
        b=e/J3JXrq7OzuSj6eW+nXtmQBbBwKrXN0usvR4hwk1+1Of7whF+KBN0n2KdFJVzUmo7
         mS2aFQioIbV1u6kDdJIwI1OtHKC3OjjdWXeiXGrxzzzlAuyKRCNSwPOaP/CNkmH17Bx4
         Pr7OmJznhVzmJ8MJuSvv7sav/heNYqvCjyFlT+yMnnIUP7ZfFQXplptJAOrxpmUxANtu
         HPdSaKhUQdpJCBY223GGMsBqFUaeaTivJFrrKtegMw8KaLIaqyUIOW0xt01eGJzJt1M3
         kW7EhuxxJKmuIAOp9QKiiWBYEXTm5KydHqWItzqMQ7TPiRz9qW9svFpj3NJpTW4M8x4g
         9nSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IM6rZ9VP;
       spf=pass (google.com: domain of 38d2xzqykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38D2xZQYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706114546; x=1706719346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q2a4rdagje8UJeHKJckVlNfa/Th15mJL7l86yKC/GuY=;
        b=qD+kpB9hGh9pGYBUQIaT2dOPgXbFUejAy2y6XCsfsq+Ml7YjzIVoiwhTt/LDrMpMZW
         9Yn6oEl6cHD9Li8MIsJ7m2Yt/u8XoVPS2Sh2n/boRz8zPSCcG1ZQE7MB8PiCT20omXvw
         3ZujJrZXkvwWyqoKVIE9cISSqM/PEYhZB0cUDhiOrzstuwppQlhmmKqvp4zXrbLjDRjP
         9mHxX1Xinpk4m7c7CjtruRlH/3ocqmtbUXoIQK1MZCnrLQMpUYyKd+7nuOGtnciqf77o
         h2LIsKPDhI5giEd40IS2QlPajRkiC3+mUALh7AuEltvWMRXTA8pI9l47ogp/4jtL7U+4
         hH1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706114546; x=1706719346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Q2a4rdagje8UJeHKJckVlNfa/Th15mJL7l86yKC/GuY=;
        b=q5h173rcLGV0KH2HWxq41/cUx2ZSm/kryzZWqfuLzY7IJkQFFNyTIW0yn0w5Nz7krz
         Tby/CoxsjiPzll8Xo3vHtfv5YMJ5bxhxHF9Z0IfPabWU3oEeF5qWdglOhboroSA0q5hg
         b0/BkNg2MO/jDPIEb5mQyNzkf9YiGyoU0DBtP57LiJUiW/RU+HLOES5w1ekosJMoUIqS
         RKHIu7VfD95R4evsOZAEEz0gapGhZBjuYAM8IscsmEAa5fyZmusxr/DNjtVMez+7N+xz
         +YAySDUFC+41TAGQzOU6qvQ6UeKthjaY4+d0guHvvddyummuQnqR5pROt1WbbZ11svYA
         iO+Q==
X-Gm-Message-State: AOJu0YzZIIKAkD8X92yneLtGCgwMUtpEkuuTxBesJW6ZmQ+LjaesnFPB
	hYL5BlKUbr4YIoujovGAzpi+AX07l2gKA8NkIWlQXYEEisFBa6GW
X-Google-Smtp-Source: AGHT+IGRwZXgP/3oeZtgQkS0CNxFlsUcS5Qdva74vaBo8/FGqc0DueZFeT3OBqHQoRzlfp1gaWh0OQ==
X-Received: by 2002:a25:2e4e:0:b0:dc2:50e0:2be6 with SMTP id b14-20020a252e4e000000b00dc250e02be6mr910679ybn.2.1706114545602;
        Wed, 24 Jan 2024 08:42:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d6d3:0:b0:dc2:252d:7373 with SMTP id n202-20020a25d6d3000000b00dc2252d7373ls1771203ybg.2.-pod-prod-04-us;
 Wed, 24 Jan 2024 08:42:25 -0800 (PST)
X-Received: by 2002:a0d:d68e:0:b0:5ff:6552:8f57 with SMTP id y136-20020a0dd68e000000b005ff65528f57mr1060696ywd.39.1706114544802;
        Wed, 24 Jan 2024 08:42:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706114544; cv=none;
        d=google.com; s=arc-20160816;
        b=bfgtkDfpt+zpmGz+6W4+pCxTyRbW4xO7c09lTAOrx1RYAI0e7KRueHL/XP7czc+hT0
         fvOpGAyQTrhJV+SuMkahjve9qVfpaBsS+m1A/80y8L9fn/5PRwui8ArjVF/IRWbmcx/V
         BHQcbN7lJngHwMWXpLmzQ//RNx2NLC6HhducuLdRQO9OGS59wSfYxb47nLlqugrAdy8j
         6i51DTSywDecDu+rl3oV00JKLKNKT8q4YhA1p15DLHqCs+N2lPua2RjCAeV+fG2Ew8xx
         5CE30+MsLroJWIf+MbTUPjzcEogsh1brK/Ky9qgd4Bp768p2XGuoNbIFvMkUeljAP3Bj
         m9KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=m7Y5l6OToLybSucRHht2qJXpk8kuciDNbQY5osmgoqQ=;
        fh=Kqo3G5+KDeAKSSAN0QOehLq4Vu7JLa5YA3bSMHyGhM0=;
        b=cyPTHvdKoRhOnAlnK9oNy4sQRFiettMs5yJnkFborar3gggQf52bnUxxs8uryXlTDm
         2x07ybqX/eoTT8pH0LE/439UzlYe8QB5Oia7E/H2RgP21eg0qJgKT+aCX+P9JpUmmzan
         SKHj8hyChApHUsNYMkrTcCwoEm0uYxPxOhVUveknfP6eFdzr861HulVpSQFn8F/Na2AG
         Nlm2XBk82GAcT9fkYCaV6S1VAqEgne3ak9sL949eR1x8AT+Md0IWFVIQTQhP+58dwYKE
         wrvz5ajSLdyCar9ppgIXe/sNn8zehU/U+G4+CSEA2TeAXa64NAeKtfJfzBQxY3n8VW1G
         6g1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IM6rZ9VP;
       spf=pass (google.com: domain of 38d2xzqykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38D2xZQYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id r4-20020a0de804000000b005ff5d5ae22bsi13239ywe.4.2024.01.24.08.42.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 08:42:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 38d2xzqykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5ffc7ce3343so56957707b3.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 08:42:24 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:ca56:4222:6893:5055])
 (user=glider job=sendgmr) by 2002:a0d:d708:0:b0:5d4:263e:c819 with SMTP id
 z8-20020a0dd708000000b005d4263ec819mr360803ywd.8.1706114544464; Wed, 24 Jan
 2024 08:42:24 -0800 (PST)
Date: Wed, 24 Jan 2024 17:42:11 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240124164211.1141742-1-glider@google.com>
Subject: [PATCH] mm: kmsan: remove runtime checks from kmsan_unpoison_memory()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IM6rZ9VP;       spf=pass
 (google.com: domain of 38d2xzqykcwujolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38D2xZQYKCWUJOLGHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--glider.bounces.google.com;
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
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 mm/kmsan/hooks.c | 36 +++++++++++++-----------------------
 1 file changed, 13 insertions(+), 23 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692a..8a990cbf6d670 100644
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
+	kmsan_unpoison_memory((void *)regs, sizeof(*regs);
 }
 
 void kmsan_check_memory(const void *addr, size_t size)
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240124164211.1141742-1-glider%40google.com.
