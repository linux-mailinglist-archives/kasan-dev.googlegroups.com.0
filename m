Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBEBSP6AKGQE2TO3W2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id AC2F428C306
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:56 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id n16sf7138125edw.19
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535556; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPxzmtFt30JIp6fZ2lG1oDh9L9cfcBTgOQnx9jDjDADL2BnhV+8JZkmKY9wP/lM8HB
         sAycYUXWuB9bwrAlTOjoracV1XTHdjVV0kGkK/KY2Xmyy8aT0oGCQoWtvagnKdL5XUml
         v6IfU55+13Yr03pj7Qlcw501YuzppOAPpiAoyv7IJuipxhEmLe4vPVxgg7OpurJFm9wp
         Gd18IvrUpr0lq8IrjpClQWRK20v319FFBkJlm8HqdwsEmqpFg0tsdrz9VCbG0sDFFNSA
         hxryuEQogS4XDHhhnuxhldkK3Fz67MQNCAq7yBGluIepFT4D8rHGDhC4ABkEpkboi62O
         8ZIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xKAQeJRQyFXbB+hsMLMreo0Yj1vQDmGwmxE11MDgDBg=;
        b=pmwZ7Y3NYNAQnQn8s/qs51H/5TklHHOmi/Qz97dwCWwQJbFdZtApkCmXQfbZDV0ZaF
         hztdVhINJQu7ZHwShhOWxckle5GCA5OpHQNETYSfX1UbJUktpdB7i0W30ABa/pkG+bvO
         E1QwG5rAQ791m4SC4auQ12+ePq0thJFdbjwd2oKktCtgNlOsj1syw+Ii8tPzrezgw8v6
         3bJ+orGxzCLPA/uVvbv0B+9ImuDExeyzbq302mZ0rumD0SwfGjPw6OYdypnX8P+XaG1q
         dtSbsY/oLxzEccMw7mMl3OHjRg3cSkJIIUkrBWioPyg79ylHryxX/8zEST5JNaVH0iXf
         Je/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LMXIiTVU;
       spf=pass (google.com: domain of 3g8cexwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3g8CEXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xKAQeJRQyFXbB+hsMLMreo0Yj1vQDmGwmxE11MDgDBg=;
        b=niSEl2HN2K2kx4mdUKsvRfMsgRYibPm7vzW5HXtI23XZWFjkT4E+yAywMxFe0mYtju
         3PZicsBe6+/zttTlNgjjYkny7NuX9JLxNlcO/5YHlyA2Rs63jXbDWJzuoWHlqN2iDLvy
         TN0EjvKSDeAQ3qSEQvU8hFvHxhNlEUOC8hHYialXVyYKY17x02nON1xkcKYom23XKbj+
         87EYa8kiwxAnAunqvENwDXatdCNukGE9EV57JO+rL/VXJKiQ+kVjR4VV9ILzrMeD2dPx
         bYfdBhxC7huZ6EQMMbYgB+jWqAGB4lbns+DTrZ0n4cXiRtNUyh0N9vHPiMSM8SK+39AO
         Q9+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xKAQeJRQyFXbB+hsMLMreo0Yj1vQDmGwmxE11MDgDBg=;
        b=teUZAY+Ri8op07xZB+UvvJsB14GzrBPsXbeIz0t+v6xL6tNoJk3yQ3DvRPrezzC0US
         TV+Q+GBnOb/0xwq85bT4yQ51o/vz7V8RlgphDBD1R9dHT1P59EY5vOZFtW5CHnHnm2Mq
         VxXrIP6Xe8xLDB5JgFJkbbMf9QbmaH14w3WzzJYXiZJMhhl0B+WI5OQCQS7E8TCUH9h0
         Tm5McS4WY+XIkg+ivbcq1uEHrbfTPuspncQwBLEryuX47WiunzlUBfmRlrNGbgwtpBYX
         A/oUT3PQNcZLl/i8mu3vMD8Xrc3WAIOd1grU37KsDZXIZomOt3oKgn9uLU25CBztkzRB
         AjSw==
X-Gm-Message-State: AOAM532f9OZwDi0VOhtHP7Rv2LfmHemFsGXxbWmsX4AVN3hkhsgI/ic9
	ec/EyRh9jzP9dmM7pVMwMfA=
X-Google-Smtp-Source: ABdhPJy8g+XQ7WOLSV+oYoDfM83x/yYCNvhSwQ32729j2knr8K3zU/99xqpFKUlJtwb/BQf9vCxXZQ==
X-Received: by 2002:a17:906:441:: with SMTP id e1mr28398460eja.396.1602535556377;
        Mon, 12 Oct 2020 13:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4904:: with SMTP id b4ls2348447ejq.9.gmail; Mon, 12
 Oct 2020 13:45:55 -0700 (PDT)
X-Received: by 2002:a17:906:d159:: with SMTP id br25mr31175205ejb.155.1602535555496;
        Mon, 12 Oct 2020 13:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535555; cv=none;
        d=google.com; s=arc-20160816;
        b=W1KM8Ymm22oGZgdk8UIVV1TzeEsAUwTialp6XxTQ7XPvHa+pQ1Lj7srPVH3tfkQ2YZ
         NJUnEB4POzyRpbBrw7m4zuEXDT+yyErHVv1YWUG3TyGBwThiZdqVdQ6W8ezaq9/G965r
         9mRR0l+OkAixyDhd593VbQauufQzf0VqsJqKIA+Rl7oB+J4UDx0mBXaR0WnSPrz4XKku
         MeIUyUnTGgRBTdf7YikM/8Ob2V6SBuGroi/dHK0TtQBQhT618WXxOGMeuJXRPLAUSDxb
         v1vs8+d0/WH6+81j0+8bIcYnkUbuk2SOlECMo4GEQhAmkIS2781yzj+jnwT0zCFPH6Jd
         qt9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S/2LUWRyeXcI4N86DAnzB0X2oSlP65kDJMRv67ks5r0=;
        b=dxG6E1sylsaswDKlh494kFcg2a5X7DBY3Lotc0lodREhW9YasO+Qtn29JeOplZl8EF
         gZhHpB1Q3ZCfsVFGwYcarIOFXrn2C3Dyd/lsICTi/jmeD3yPAuv9nLT7TQrjsixgRLsn
         tqNqPJotCKMsfL4DIzlUadDKaoppn5xf3y8zUxwVI633wPo6CBpoXDt1sZQ8vpcOe3m9
         jQR848/uEziiangugBOZ3gkrzpk81hg1sVH6VjpVCgNQRxnwJxjGsG1PGgpF+ExTb23B
         o44mg9YmTENt8yIMTU7gjONk4/v3gMHhfY8M4gcI5i9sZpwfLz8nKwCw/EvmSkoH5q0B
         JYnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LMXIiTVU;
       spf=pass (google.com: domain of 3g8cexwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3g8CEXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u13si267285edb.0.2020.10.12.13.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g8cexwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id i1so1713029wrb.18
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:55 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bb84:: with SMTP id
 l126mr13064242wmf.159.1602535555003; Mon, 12 Oct 2020 13:45:55 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:32 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <f939797ef5a3991d6d32eea46c847b5d42be5c1d.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 26/40] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b=LMXIiTVU;       spf=pass
 (google.com: domain of 3g8cexwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3g8CEXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 145b966f8f4d..9e4d539d62f4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -250,7 +250,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -311,7 +311,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -347,7 +347,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f939797ef5a3991d6d32eea46c847b5d42be5c1d.1602535397.git.andreyknvl%40google.com.
