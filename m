Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5UI6WBQMGQEFSZJLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4B38363E01
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 10:51:02 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id n11-20020a1c400b0000b02901339d16b8d7sf1311443wma.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 01:51:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618822262; cv=pass;
        d=google.com; s=arc-20160816;
        b=qxEc/lcWO2RKy17P3n2Ok5ZXlSA7U+U3Dp9r+uvjDKUR27LTrZEJiA3EPp2j76CASU
         xyzeFGPvNnB/ch7mZ5eO8idIiEIVTfMsxHU6JPYkB2jccZy/3DfymNEw7zJ7WMEiq6XK
         4HDMo68H+WgCq7Oi+7s1ls09GnttkOHcalBZv8jabPVwHYf0oaY+5Jemos/fjECOtksi
         VlWOy+gwqS8D2Za6xGRGKigZQpaDjxFHM8ML9AbE0THWaPHgl5GesiO3ANydw1omjIif
         xi++PHe7qCo1VgTe7i1ZrQBLZuR4ea21CXWY4NBjvPDHY/NjfIMJKYSDdfdi0rHXq9pC
         mxHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=amMWdFihsckcBKhV7MOeLbBtFYYxNjrKs/y39f220hA=;
        b=XnVo9ol5kNnJnfPHvwkp8aaPNU00r6Y3twfCZwezi0GiYeBLjqMhy0lzmwHGXE6vBh
         VVj2t8T9yvdVO6Z79WJQUWsugSPd/jsmuZaAe3jKqlk8y+EIrfH/4qD8rEu8nzYMVM6e
         wnTw3qw20yEvZ7mG0aMDMsjzB74MG9lWw6Safgj23bqP03asaCmLXimfYH7Vvxkb4+yE
         KXfKU8fnBb8qOj7m9dfPMWHtK+jBsKLG5NPZcc9ug4hlh0QhYW7vgPPX/90onu/Vbikd
         GZPMJSo03LKc0uuZPUGagCDQL1Bu0pzeRW6+ti8h7J2IZGqmY0tE/oulg1LktUaWpRJG
         0Pbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i3pEmtzl;
       spf=pass (google.com: domain of 3dur9yaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3dUR9YAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=amMWdFihsckcBKhV7MOeLbBtFYYxNjrKs/y39f220hA=;
        b=qS6iYp6BwSTkFtf4sH0/iR3i32zGe6xycvLQQuPaqJuAKK6Gz8578Enghk+OgLI3bW
         oa3yQgi6mEyiT47xRdSo6ukEszw7AG5pv0WmTqj0WnS7z6IOsaLdM6ZFsCY8K9c1lwdJ
         AMO+tKt2d/h/xJvSqafsOT8KXlbGwcwPgDVXTuonlssbiI1QKNiylHIjZv/J2YUsGsye
         jYxKV/JbIYXMCHTPTZa6dCYAFEOsIGerqiY/0lbadnhtkW729ab54tzNW67ScIyrfJyA
         6TojT1Eq8fpTpNHE4lAPS/cN6MEvBMP68+vKp1A7fdigA1ZrEzg0YSrHv1AAMuVNb8ku
         gyCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=amMWdFihsckcBKhV7MOeLbBtFYYxNjrKs/y39f220hA=;
        b=ZMQP/nS9OAd6Szq0BRHF9elvdGPxk5QitwA66XrPM9oNaAtzEYXTfo9kqMXyPRb6bv
         rfAokGAF9aQgZOToy4CCDngTOAZYNH214rwxbRVh+V1NaNAeBfXVU+InpYUBv7TH8NVX
         H59DWL51rws2uKiQqdo7/gO5457yzQsmhmhiWLQ/yTdmMh1DRFDJacUfVvJoKSi1OLns
         05/uzCge0dsyLOMi/hRWK/tvpwp2D++miqcpWyqYZqU7JD3uWmjOirrelYXzzSsLZnnf
         7azfYlB3ut3j9QqFZv8HTGjPEMez7u0WHUtcCZIqRhHsiK27XsIldpzlQuuVqSCC/DJd
         Y09Q==
X-Gm-Message-State: AOAM530sQfUTVY0mtK5+ptF2kEevgNoihTi6gObut4r5FdwHrNcHplRg
	SZtKIFEJJONVIblVB0KLLaU=
X-Google-Smtp-Source: ABdhPJxgYkP+biMarpDdqRiMbEuGjqkTY8G40ssTdyj+EtOg4yqJA4gwE3SBQJsWwkwx+0HvWY9eEg==
X-Received: by 2002:a5d:424a:: with SMTP id s10mr13664233wrr.70.1618822262741;
        Mon, 19 Apr 2021 01:51:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1287:: with SMTP id f7ls6647285wrx.3.gmail; Mon, 19
 Apr 2021 01:51:01 -0700 (PDT)
X-Received: by 2002:adf:fd90:: with SMTP id d16mr12981760wrr.96.1618822261795;
        Mon, 19 Apr 2021 01:51:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618822261; cv=none;
        d=google.com; s=arc-20160816;
        b=DrTuJAUYIQ/VeJKewwcY7nLzbUpJKbQm2Z3eQydXMeJalN62d8bYX2g9FMsjG7j5sL
         iGnCcznk9DqO3X5TbSB4INfZgjMKqgh/+sSXmrGJIFZcMLzFSSyFQFKSj2620fp1pTyG
         juXcgIEElH0+aoUsvyHovZzftyB4/3n9JiJacHRRoklauQQmlRlvy97+8F36aK4vtKEj
         I11ZBHqABCM28bXwPF8f1OxakWhv16IN/uL12pLjgOarmIMz8SSnqtoAI0gHFDjq4jQo
         CnY1+5qufCACp9n4R31xD6wdmwYVt6HtAwJwkt8tmbnyVWj8Am4XUcYaqAZtUE9iiJ2H
         KK+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=p3g1jw5/hGDj5wABho0AViDXSgtC45K4NGeFzanUCY4=;
        b=Q0OF8BTqZWoYJ4nJk4IJjZ/uM7ogWcpjto0ETa9y6PUeZILOMQMMMKuoD87gdQpCgp
         KcgcHqxkvftcegnFDcfI1dvK3oQZYpxBHMYYnA1iSx1YNTSbU/v01Y4TkjjdmYT9lyC3
         i482A9nCDr8UBH72ar8ekZMMrBLPEpkxz8qH38RuydLMWe32RN53vrQEIn00gmvJsv+g
         6stpiwSyWIxQv+mDCqfoqSsLixk92HCeWQPRAvuS2Jy+5YbMLumORCHhc3CePoDH+AAP
         yiljsxacxaQym0GDwGIbuZ7hOjS/fpW8Ddckm/iw/YrDj10s4Mf/iujAJJrfAH1bgkQO
         DXyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i3pEmtzl;
       spf=pass (google.com: domain of 3dur9yaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3dUR9YAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e17si1071880wrx.1.2021.04.19.01.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 01:51:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dur9yaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l6-20020a1c25060000b029010ee60ad0fcso4394127wml.9
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 01:51:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:92f8:c03b:1448:ada5])
 (user=elver job=sendgmr) by 2002:a1c:4d0e:: with SMTP id o14mr20041525wmh.141.1618822261465;
 Mon, 19 Apr 2021 01:51:01 -0700 (PDT)
Date: Mon, 19 Apr 2021 10:50:27 +0200
In-Reply-To: <20210419085027.761150-1-elver@google.com>
Message-Id: <20210419085027.761150-4-elver@google.com>
Mime-Version: 1.0
References: <20210419085027.761150-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH 3/3] kfence: use power-efficient work queue to run delayed work
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i3pEmtzl;       spf=pass
 (google.com: domain of 3dur9yaukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3dUR9YAUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the power-efficient work queue, to avoid the pathological case where
we keep pinning ourselves on the same possibly idle CPU on systems that
want to be power-efficient [1].
[1] https://lwn.net/Articles/731052/

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 73e7b621fb36..7e20cd9690a2 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -642,7 +642,8 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
 #endif
-	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));
+	queue_delayed_work(system_power_efficient_wq, &kfence_timer,
+			   msecs_to_jiffies(kfence_sample_interval));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
 
@@ -671,7 +672,7 @@ void __init kfence_init(void)
 	}
 
 	WRITE_ONCE(kfence_enabled, true);
-	schedule_delayed_work(&kfence_timer, 0);
+	queue_delayed_work(system_power_efficient_wq, &kfence_timer, 0);
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419085027.761150-4-elver%40google.com.
