Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOG4QD6QKGQEYGRZEVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 069172A2F08
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:14 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id f10sf8274270qtv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333113; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkxrjYFjH2JlrHLHihb0L3tVwjkaU6rk/PKfdsWxiIfKqwKxBTfA7BAHeBlHWgvIeE
         o2AoGQfu5gqpC9pDXJx+7lhpODlxNavizupPD9JF9dtC+XMTJqSn+K+I0kr0Hfi06NST
         F3vL6RENI2ZD3brGD0mE5BpnaY4Bqu8EaSBoDVQQWTCZc3msU3Nq47pNlo+10Vlkmh2/
         ly5oEbRDKDQ4uqgCwy5QU8aHihkl9wi1+YjSojPIIDNL222QQ3FDLbhpTC0i1u/kWsCp
         LK+5qF6gZ8HX0wFkE9sraw0rBeX0BtCpZWSBLB5w9X6qdd8wHRNqQl9zX6Dm+u/Ytk3q
         Ud9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Oa6WogWdPdxX6SAA2vob82oaDsn0IZeM7ZGDUutBY8I=;
        b=bohHVJtjFcRSDPrtd86TmZejGINeZ1CZpjTqGfwmSdwrApbzxW7vKLC7Kr8UFaPuwK
         SWr//ZXnwQyGaznBhLDAT8rQ3a4YNPL5KbuDP9ei67TngbP4m7mVRp3cakPxH3iQXZT8
         x6ul2aELXGtdvQkyUjfHuU9VY3nsutQU+xvjb6I/PM37s0aocGCfz+PudI5v0udTiMUp
         ZSC9t1k+NuGF77OasytUOL6MxyQM5JwjubGJCpjpGdFF0iV4NmW93xu8xs1GcMDSSjfA
         mJnmmCvMvywRxgWntK+xd0VPBhqbVJxmAbfe/2jK61RH1+aKyv7T/QV0PAl6gx8qOfWW
         iTEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FdmK0iW0;
       spf=pass (google.com: domain of 3ny6gxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ny6gXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Oa6WogWdPdxX6SAA2vob82oaDsn0IZeM7ZGDUutBY8I=;
        b=RYk1ku8tXhsL4olJu+xBaeZh2WaeFgWd3WdvnRrphFxHQAmDlof3/SxtiGtoVPxTbE
         LLGY6FUvnHR944fNJjRofgk9vpeOY0pc158IaWBpvsQ+pQEun1+E9cQ4H5doI4FiQv5q
         DyQAZv6JbQGlO+igH6yTfSnhU4a0AwXUYi/JP709laWmqRIXxjjcp3B3BPGxaepHAweo
         E3hllvdFl6TuMrJAzD+iIPZIQIst0EpiGsABHTcJ/yXWP+eEQ4u4OiVFOFb5wI4m6bbk
         Xg4Wj4/8ms72hIqa5Zrf6oWNrM4gajrwEFUr8HNTRoYlEjVZPq6+ZOTKMrJKJwBljHOn
         +FKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oa6WogWdPdxX6SAA2vob82oaDsn0IZeM7ZGDUutBY8I=;
        b=phUjk1BInyiDJxC2ygyx7PdHMMNpDDc5NUu0lMgOoPJN7RS7xP92K5qTQyMCV2CKQS
         N6B2aMWcWQFQ0dBIsj5X/EPpWRuNXvWkDqPF/QzgUwyJZPz8H7YEIwcwW0FvntKLF0B4
         8yeOa44W7pzeqkqh0DEsTZvBgOf3wAq5i/btpCsQDxbREvN3Z4XPIvCqbhluiz9tPzA4
         HUpMU0n9xvhocy80zrpmx0xVmtEFVcbUzVuJVsQec28XXAYiiWdBYtMIf6YfeGhTkHTr
         m8WS+TGIhymprb0aOoObhOY/Kc0OwrtMbtScK+8xjRJwtvo1yk5oR6hcwp4Ye2rRyfrG
         Q8NQ==
X-Gm-Message-State: AOAM5306yL26yav+KeSPBSSKRmpzMWJx0ftAxQormRi768vX14krd7hT
	rDK17LHe/MHmhrjLinlII+g=
X-Google-Smtp-Source: ABdhPJwbwZehFu45dSNt3r8cb1G4YMPfFsRtT18B6Gn23BtgtT/bu8Y7/vYMXkjukCLjx862F3FtGw==
X-Received: by 2002:a37:9942:: with SMTP id b63mr16380981qke.85.1604333113102;
        Mon, 02 Nov 2020 08:05:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:65d0:: with SMTP id t16ls2346652qto.4.gmail; Mon, 02 Nov
 2020 08:05:12 -0800 (PST)
X-Received: by 2002:aed:3b2a:: with SMTP id p39mr14384526qte.211.1604333112241;
        Mon, 02 Nov 2020 08:05:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333112; cv=none;
        d=google.com; s=arc-20160816;
        b=tMZh9asMdXHXojL3DV83I1nC2RxwLoc2tpc3hOpXn9AZDM9AvQmjZj+9FkyoafSucQ
         310pF6UywSOnYyRoXlQmXxM6JuBR971fAj86KCsaZUc8HNKhE6xG0QmUGP/49+7wSxAQ
         cjQG13FV8iwdx5VSGIqZKfix9FGfH06GZ1m0maFtkywS6a/AL/JaxZhilx4eltU5jVlc
         scXp0QFEVYTlxyO8+7EwB+TGHMYaOvP7T78EBBoFQo2087n+GGBD0eKBpmYfTkM/kpso
         SMnLuf6ARX1UUaA2w82H5b+FKtqdt2JJcxdhYoD530c78yJbq6TSQsv9x2MX5ZNu6jL2
         qTEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=U0LE84ypp0h1o7gemXVydYKKDJF3np3HPozWD08S0mo=;
        b=Dv+5HftOUTOfood4SYKi4Ior5HJCB9WTAH0yQdu8+XFLswHx/LoP0jZsh/i8RLeRZp
         Z9JQX60f5wZlY1ItInfqtyTlhQxF3Qsqbz8OOJb3w6liw9+h7UmUmpzxHWALU6V2U9RZ
         4TKUZOMi6tRF6vaRDQ08ExrI7qtd3OjSbk83sZpYhF6P6GFp+PhI16b/Vcq33PDLtFpy
         Q/rApGMqEu+PpOwIJ8Yqpp5lqJGguNijKoWT68/4o2ew/RUCA23gkNtoxTGsE8nBECNP
         tqXeOBur71mOCCCzqUp+JOU6Nkg0wvOfu4wAvp/KXCMUTd0RTNDhJ43FL0yb2oMIQ0fG
         bmag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FdmK0iW0;
       spf=pass (google.com: domain of 3ny6gxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ny6gXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id x21si797290qtx.1.2020.11.02.08.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ny6gxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q14so3482857qki.23
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:12 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fb47:: with SMTP id
 b7mr19151839qvq.25.1604333111911; Mon, 02 Nov 2020 08:05:11 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:59 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <bf5551a8f45509562a862aa49561603a0e065064.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 19/41] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FdmK0iW0;       spf=pass
 (google.com: domain of 3ny6gxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ny6gXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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
index fc9e4250a098..d8f54efb2899 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf5551a8f45509562a862aa49561603a0e065064.1604333009.git.andreyknvl%40google.com.
