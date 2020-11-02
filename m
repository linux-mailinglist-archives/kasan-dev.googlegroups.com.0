Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTG4QD6QKGQE6STLE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 245902A2F13
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:33 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id t4sf6302338edv.7
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333133; cv=pass;
        d=google.com; s=arc-20160816;
        b=M90VjcSAoOcirpePdZZatojPkweM6DI6fLe5+l3Z4y0TY23H16PuOdHNaL5P4bsCTR
         0+LwTCiKz1M4fUDP8UnH+9SB/Cm4wlwUF0CkZuyLHVV7NnK5Jxb17kdfvppTBsZ+1Q0k
         Vi557rYriiEcjfHA9+qc3jenKmOI2YxFUkFeFoMT4jZgqXovsX0grfAXeb2L8ZAn8k0F
         zvv6+sDCkZTDlYqOUHg3Q2fizCkPmwPBRuAWwrVyfNeiRAPRgqspE7R2dZV4BapdekNx
         xnLz7meh790FGaQH9hmr5GRAdYB3lnGalPt5tOAFhcEG9NahuHWml4aOc0W1k/XX4hNG
         AHiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=coWgbHWBlMR+qmX9hr/DsDJEWcTPnLC/BsTl9YeJKp4=;
        b=e0SIQ5tzaE4nD79n4XxDQTGiblqU5B/+IZjTL8VOgnKo2BI945p2IAmDytAIaBDF9J
         w+QAmfk/35dfVQc2aK+zsdoxwdHx394mMM6zB3Ls3npZe0KxCsN2LsfVtGQtivT9p2HK
         0WjKvmLMAItOTqVg5pbPz/t6Ppu4NmOuP0iIbiGX55eRIbpiyKRTIcUlbf415GtV9xUi
         W+6qhlUmt1X5qqMiT7uZa7Y3euwkT7oQqzULlbVnJdJ9foLapidZj4ZKeojpoLFseUyr
         US5KXrLOj8HibYcjAQQYCgDNyLxep85tqFqEIwGxOWbmoxLd6lc7bZ4r/p2FSv45oGGC
         A6SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="jW4TR/kD";
       spf=pass (google.com: domain of 3sy6gxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Sy6gXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=coWgbHWBlMR+qmX9hr/DsDJEWcTPnLC/BsTl9YeJKp4=;
        b=KQBMbwHSbOMEfayI+N3fyR/tyosIhKaPzhJ/eacw6QI+CSdw4jHQfoJ8CYVn4bC+/N
         XAuhORPg0bdFZUpsHDmPl5esMC7+THEuX3ehQW4d61kTpeIOswAK9nkl7sHeHH50hC3Y
         SDGT6Nmx5dDdvoBtvillwrs/l/NBc9stVVTooPcT9OWfpCBcxetukB9AuETwgQu3b7Kr
         SJnLyTe0Ff3jw+FA1kBtTW6o8/vqFkJBoX6FlgR/1bTepDqjTgHYHRLi0tYKrGPap7FM
         z3deyHOC7l5noz4QiaLluL5nvdQxnRg+qC5nh0Y4oCD/Qj3GRQKqq5OhDbqyaMlf9AvX
         OBEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=coWgbHWBlMR+qmX9hr/DsDJEWcTPnLC/BsTl9YeJKp4=;
        b=k5LYfyekEFgvM6xYGYTTi3XhgisyUZv9D7+XMdFHkaag+4+8VyFmOlxRncY7VjgNr4
         BIAsFVmhYF+f2ppHr4vOiYysffmOB9HcWbA/CmZ421wgaEmIUJMDUbDRfF2kfSVmDeXK
         qku/Er7ZiJ5tMVkUBo8a9e6hWHWQIVB7lOoS7MvvmADMIv65zdcTaXq7CwWqVrjss1Dm
         OHR9FHhx8+sMR1mUnhVsyVyUiJDUHZhlD2lc2bVGtzN3PNOfmbnQnJTVc2/8k0Dq0MaX
         E7th9Ke3cWR4rksyOTPZmeFvs00Us9Te11at8F2jyelIOR7jkDKStO/1Co6KLSwcFb6L
         ND3w==
X-Gm-Message-State: AOAM533VPk+efVHXjchmny9dcXvajgcgYpSDQ2lPFIqNepImCFY1310H
	a7svVW50w4yZuBv4cwi1qFE=
X-Google-Smtp-Source: ABdhPJxUnwCqWCL2iEOVYj40++V+X9N9aZ6PzPdT3TlNhSKH4z+y+tJ0AlYjgM+3xc3L1pT4+cqSug==
X-Received: by 2002:a17:906:2e8e:: with SMTP id o14mr5876971eji.324.1604333132845;
        Mon, 02 Nov 2020 08:05:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:38d0:: with SMTP id r16ls7218137ejd.2.gmail; Mon, 02
 Nov 2020 08:05:31 -0800 (PST)
X-Received: by 2002:a17:907:2667:: with SMTP id ci7mr11129632ejc.282.1604333131845;
        Mon, 02 Nov 2020 08:05:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333131; cv=none;
        d=google.com; s=arc-20160816;
        b=mxNsZh4/us9TzFbCV73KA0gteGVv88RNu6cBI3Ctpxt1dikf/6Zb8tullAprtEqE5O
         3XL7O8UxJ2gt1LYBCSeIg5XMgp/FjQbwRO8zS/Whp36rtj4aDYs+jPzRrVdXopGmB8Xn
         +bzUTuDi2q1Qro+SOyQH9HecKCLaqmMNGsdowCd8Xci9+QM8YwGQhxJNvZokQTZ5XZPT
         ABLg4/SHG4HfVE1vXB/Or++O+658MoOsmaGQOs5fQ1ni10zvAidySib+o6POIfTbsj0X
         N5p6Ydcsk2eyEym0yKmhAIjURl+03B8Yg+jGTcvKpQYbbuWz52W4i4hg6+wPMaOeGy29
         KMNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=96T+1f9i/jCV3zB6gHtRoH9MAYIWASsGc4o7euuXITQ=;
        b=paOQd7KzQ9BOcMBDwO2nzGYxfzHpBTWJtqe+WXvIr0Ykhxx5T8NqE9mi7F6G5/uPdH
         8F92cpnhHfSe/rwV4Qp9SiksQPzlYijd6iE++Cxx8IsVz2ZIvFeRMaD7dVDzN1vAcgcy
         wT7xo69c1uxXp/82rEdf0wSNIkQmJjzea3zsgImxHMBQBq8CryxCalnRGkdA/hKzTxKP
         +m0NJltK/NJKGzJY6OIR8UgBnPQOOsSibMpp0SNjBHYsk50YChKTwccrh8VxbWcaC4iP
         fEqd1SEe9laN1RYPGoDwirLAA8+IDDisgIAjq6cH8ryE+HPMOlm/bnl+hNt/77BNRtfy
         520A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="jW4TR/kD";
       spf=pass (google.com: domain of 3sy6gxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Sy6gXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g4si332768edt.2.2020.11.02.08.05.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sy6gxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s85so2025375wme.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3d54:: with SMTP id
 k81mr19445547wma.144.1604333131167; Mon, 02 Nov 2020 08:05:31 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:07 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <ad03e58d10744e418b4a457a4ca9e1d088394b46.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 27/41] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b="jW4TR/kD";       spf=pass
 (google.com: domain of 3sy6gxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Sy6gXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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
index 2990ca34abaf..5d5733831ad7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -252,7 +252,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -338,7 +338,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -379,7 +379,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad03e58d10744e418b4a457a4ca9e1d088394b46.1604333009.git.andreyknvl%40google.com.
