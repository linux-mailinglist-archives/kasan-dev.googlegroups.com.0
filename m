Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTG6QT5QKGQE325KAIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E72A26AF59
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:00 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id w7sf1722170wrp.2
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204620; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZGI89W6qd8X980wL6owNychTJQcHB6cu94LIx9BGI/wedVsubue+mNHVvQONmlndPr
         tiCaIv72MsQq8jjJhP622V49UFiqBXY+8h/iH89Ox5Pv5kSIyZN3vPjnumvioNWgQlkB
         Q2gXFS6tQ8BwDE2zTktNHJeHAfvP7nDaWkzCRInjUvKTI0jvS3oHca/xl5UzUvKP2W2O
         JmdwO22Sr/6KtapcwzhaZgdyFnyroh/mTG8t4KUffTYt2bVcvwUSV8+J2ijN/EirELhD
         sbq2nLS624s2VjXZB9zXVonQV3QPy70LGn9uCsC0KFCsdcMQDMVOljvRkUVdTNy3vOAn
         mkQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Sy2x7icgqdGUxdB5QtTTfwUBg7nQ3CwzEBjhXk7i6Mk=;
        b=qrpHP7eUDNMf7GSdqGFQCNfv+jjW/WLJcnX/b+cVa0QM/FczTEfxoJVCk9v5VzqZ20
         daZQg7jMbbVITwfrsbIEjgkHVkB+DDw9NHtbDZTUf8xd4paB0YkWD6WtJjNeRv+9gTTJ
         0CXrWu+TfYrpqFXQVjif39xYOqqLiII/H66ACDGUxHtYVK1C3sZoHp3nv69Q6jAIRu4H
         wId6jCjIgyrqYuRMAwNwjYrp2hCqkJzuRhr/YsZ68s4f31bGOu8Ylf2oXQEd0O7zVbEC
         SfYpo8E4nm3zx0viw8n31z/7VVRr1ENse4LDh26Mv2TXzdIqLQX3khG8LbA4ZJ1DgoE4
         tkyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pe/gphJl";
       spf=pass (google.com: domain of 3sy9hxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Sy9hXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Sy2x7icgqdGUxdB5QtTTfwUBg7nQ3CwzEBjhXk7i6Mk=;
        b=d1Y2uytCQ1NTRUZdjIfHmAdOQc9Tm3+tvCtDc0rIJM5cY+bIae6eaTf40Z9HHstuoX
         mYaoNyAzmQMyKseAoL4+gZ1QJ64bm1Ujgvi6b3Qj7SpNqkbbOzRp6yI++5pp8K0PfxAz
         0G6ywVCgoF8w1VQer14hlAfkQPXNovWcXNFNlR3eebTs1gOR3V3AwXsOvmvhyJpi61Og
         erZivSkdyJTGkvZWEt0j2Y/FAk032sc6YJXcoPDaBZP9a9mHhLX53/0xlJNMaZCYC3oa
         r4nwcEmPb79LiF0dpsEVWQtywZbVE9KskH1z8DuxkOqdkO56VekwJjT82FKS+YCaQKnU
         ogig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sy2x7icgqdGUxdB5QtTTfwUBg7nQ3CwzEBjhXk7i6Mk=;
        b=DBck5TIHe6yW8bqYSBwi+ak+D7gQ7hfDsfWKO4bJCMLCGAEV5bogoO58R0pxm/JZTC
         oRaNZKHVtjNQ4ZqeJnArl727sq/On6SZyViecVga0GLGTc9KqVtg5kE7l+2bsCkSIOEb
         SQwFY0tudTEAehcwYarV+YC0VgC4HBVysyK6qmR7D1ay0RalPqi8gOuKn67vMq0054dE
         QwaHyxNVE1G3CJOv78kJ7KKaFarX0R+wpmzdIwq8cIYw82PrKngsb8OZ/d+SN3h71i+N
         8LrdAjBTdOrrqy4NQTDMGogetbJqVjpYDyQwWWCSSJVTJZHfcOXzuB+9+iaBcecMUUDF
         PnbA==
X-Gm-Message-State: AOAM5329jwavXHszqL5/7HYl1tF7odTH/25IP/lQgM6ykZo+BUG4CBqE
	a/orB3hGHN4Ocii0wf/q698=
X-Google-Smtp-Source: ABdhPJzwiLrYGDqrtm3NxiUBecAyzdT8+8O0aA+qz2A5kPgHUODZShnjjLO4qKJ5uUfjXjFIfmsLwg==
X-Received: by 2002:adf:dccc:: with SMTP id x12mr24196205wrm.241.1600204620383;
        Tue, 15 Sep 2020 14:17:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls339437wrx.3.gmail; Tue, 15 Sep
 2020 14:16:59 -0700 (PDT)
X-Received: by 2002:adf:f290:: with SMTP id k16mr24873652wro.124.1600204619683;
        Tue, 15 Sep 2020 14:16:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204619; cv=none;
        d=google.com; s=arc-20160816;
        b=yvRPc5xtzFE4Cf19U/+/CWTm/DN0Vwtb9z1sK6hIa+NQuD7y+BaY8CDRdRbYhPPBsJ
         n1CoBCkQFS/2HPC0HfucnnQ1xwDDJQ972o7aB6PKSENZpgCFaJcKz9vs4lexrmy9YltT
         zbJATbrS+Bh+d2MEzOvNcVcTWtn0RrmISPedHKWauHUVqAc9YEPTyUXaDUB8M7HSHEnU
         YVH89Czc8HcHmlOR7H7SmOFlwkppDsYWvZwcnTK7mA9xVb9mGl7s3z9rTKbIRhIk2Xf1
         mrnnfLQwjHmk9sB24jzETzz4nwZH7ReRmY2gwpzJmo9UPLoL8hVO91KKTjPJLLC6ewCi
         uPQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LA/JoGm8S/g3KI3imjTGafEDoL5GY8vPZ9zGXBZ3JZQ=;
        b=QJqamNpECa+4njSS1354V5WlpF7Y60Fan5iagLhOfsM8IuNS/0iRWTghWvm43PR+Bx
         K9iYctjMA4XH0FRWPGwtzVrhkolV78nOHw3NdAc0JFHMR5yjZEJ7JJxZsYE3L/7D1KdI
         6j/0d3hzNkn2nua9ku9iEQ8Xin4YW4gJu3035+0UlUebpEIr9tfSvVfKa7QSJ/ORkDnf
         2DcR63fgOrig4jvUmDlYLzWg18kW6X6KiAXQdAEx5at/reOqm3mjLSrNdMYwuEblSspZ
         tzfEdJde9gjryYmDujyXFFF/YHHcdAalX4bUlgqhw/6a7ae5idXO51qGk7AE+1BLHq5k
         qO1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pe/gphJl";
       spf=pass (google.com: domain of 3sy9hxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Sy9hXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id g5si49782wmi.3.2020.09.15.14.16.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sy9hxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id md9so1826113ejb.8
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:59 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:aa7:d30b:: with SMTP id
 p11mr24645433edq.80.1600204619159; Tue, 15 Sep 2020 14:16:59 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:57 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <edf6404ca39b224c93ed2b3b27a2b94dfc62fd7d.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 15/37] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b="pe/gphJl";       spf=pass
 (google.com: domain of 3sy9hxwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Sy9hXwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ada3cfb43764..8ad1ced1607d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -255,7 +255,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -316,7 +316,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -352,7 +352,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/edf6404ca39b224c93ed2b3b27a2b94dfc62fd7d.1600204505.git.andreyknvl%40google.com.
