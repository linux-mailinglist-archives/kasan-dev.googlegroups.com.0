Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK5AVT6QKGQETVBVXMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 318472AE2C7
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:57 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id e16sf10390710pgm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046316; cv=pass;
        d=google.com; s=arc-20160816;
        b=FDrtlF0PtF/oAymFiy1/MTjLv+hFfVnjTcLb7GAPgeNBd7pFz1dzYX6xqfrWShJ9Gn
         M7XtimaDQRSQ/XdWZUUqqk/RZz0ixWzWReH52BEzab84P3rOvU+rQGKXe3v62JAyiDig
         1I5Mc60TzSXzN4ZfoX5jTehtxMAzDCkrQeeHKrRvKlnRqPKxB9ugYmHc5sXSU4Akr5Np
         nWHmpmlsvCgaEwEoPbrWbJoV2BeXAEgDaNcoeNIbF0ONjc8934fCYqbzgBrNJlBdoL6p
         LeSzb3+FkYUmOzjDEETz3SE6zOAEmPNPU3XH43JiFO6geG9HMxWPpVQNcPP+yU4AchXw
         Qr0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7jbMwrk3I3z9OV2dUm7FVnEwTzyybX42TtwaX/9n2XY=;
        b=riSkqnNBWW6hDQ2ZUgRqF2Ui1/jFarMO667CqjfkRUvI1f/d/hR65QVsHsdj2+8GqS
         hmlH35/z9hsn3Yp+y753nvrz98AcTX7rcrsIRQFrp01CNsXIqUWe4YEGIekqqDwXbmQg
         HxVp6qo3LCB6aMO3aPe/ysswUqHXU6Px+784UCU4pgjerygPClUSfywTIch0FNT7mNvR
         PcT8vs8xR0/ZiAd/JR7258GNGt5ldGTJFC4Z+rGmzmuSs+k1kY82ZS4J5gpDScPukmWc
         4Pt1ZcXXV3kmfS+i4hb2wuLqbaIfA9r5z4jywnroEYOlFJVYUjuLq5+qc0WgT9ZVpfIE
         Jb2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZFYWnks;
       spf=pass (google.com: domain of 3khcrxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3KhCrXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7jbMwrk3I3z9OV2dUm7FVnEwTzyybX42TtwaX/9n2XY=;
        b=n4KSbJ4ALTCpM79Whhue//SoDAO/RFY+Y8wZxCed8i7Ro1hEd4W20sxcgHWpO1F0yW
         CzLnKPa/i8x1j8vDbo/HOQRnDygFeKCudyEEgitlJIb56QU1ucLr1OcqBpXEggh50h/Z
         cymlp1ysUDfV1AnVwFYMpumeUPm7EkxYSh+FGbvkE4gV9GWXBiR8ezxl1oyvImq9Ajyw
         OlleIU2rnH9VWmCgnMIRRz+GcGsOlODrwrYOpm4tQXO0blvJLuhuXfa3EuXIbK/S2HrY
         QkN1BKfKLZx/Tteo3TcRYTeWYBtRLNfagPzy7KSHhZUfjTaNS03c6RZCc1BgvYjL2fJa
         08nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jbMwrk3I3z9OV2dUm7FVnEwTzyybX42TtwaX/9n2XY=;
        b=sWg23A2xqj/cMpBo9EpYKexrqELdtSW122RTP8OCHzCVqY/jj+kACYoHoTQ6a9fktB
         oQt3CphMXgoDlMOUluGPl5izTdrzITRdIb246+1armW0oF/i1Ioog6AWngwYXWHISIEz
         KC8Y45h0vxocPQMDlmgMV3jEDZKKICPiCmbpBTwvWdXPMFmLk0Qq4gqXLa28F3ROQuFq
         rV503k2VUIUZh7mtvFOIi8m9RFMVK/Rlt7lOWA5WNWgVTlJHByXD9FhriSYzGV75yETh
         XQuhBOXsuoqK3bHAIsF1aRQGqPfGmOwVKDwIPWdaHD1GdQK2YyPkPGlv9QEsQ1KPuK4x
         /9/A==
X-Gm-Message-State: AOAM532b+FJi+VIYQxAbPPavwv9LAvyDOA7P5eNhrTokmdJLaCLDjgEV
	C2sW9hMO4T9FTbQ1OU268WQ=
X-Google-Smtp-Source: ABdhPJwA0JcV61IHlscMlKfX13j5pR69rx1oU2HtH7LPkjcL0JlJHeYe4/1Y9hi6wSLClKQc9bcfhw==
X-Received: by 2002:a65:55ce:: with SMTP id k14mr18814288pgs.65.1605046315908;
        Tue, 10 Nov 2020 14:11:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd46:: with SMTP id b6ls5835748plx.10.gmail; Tue, 10
 Nov 2020 14:11:55 -0800 (PST)
X-Received: by 2002:a17:90b:2204:: with SMTP id kw4mr270286pjb.153.1605046315301;
        Tue, 10 Nov 2020 14:11:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046315; cv=none;
        d=google.com; s=arc-20160816;
        b=RlNgxZ7Lhz7RROfkvEnS2hhyaYD9LECEUoaorswKh2Je0sSNg4ULcULhkr4OaJ8zty
         xoJs1zp2AXeJHYn6g2My974PkWudmfmZcsjtawkzWJWqvi+G1vwEahtthSv9O+I10vC4
         T347TFKpIV437hcuqhSTgv/w/TtwV7QJOYRyHOp1HhX6sJgjske2SctypBmC5HIlIbeT
         cLTrVTX+7KnX1o9jcPRcti7tgRaHi1gjR8iDjDunh1D8shoaaLnZK6j0yC5X6SoVOWmZ
         IA0V/dZMOoSGf9jC49su+Uv5HKLkEZ+UY0D8vvFf3RSNNc7/Q190VOfwOVGj8QqXeB/3
         zC8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=F7/1KPTvjV1FWBHoCg0P+/y9T50JI9o61TdT17vNWe8=;
        b=Eau+a5vv7JNdgT51o+V8QRB8z3ArpwN1YclNRNLGaX7x7N+x5bqxh8/mKYYYvuelUZ
         a35b0cUTXyaO2oKrB1+JYdO9+BLFY10QCZ2iM02owp0i4J93PSruKfloXFcfEHm7O7p5
         QQcO80WC1IAuqr+sjNzZB2Sf253nDXzC+n8uMvG/h4pzRLZmoWww/Ok42UFgcHQ4ftig
         kuR4mPqpClgkVtTeu68XF8HXk815uQUwJefuym0sDPmHHUadyr6jMVxVk8YZv3qVA+WY
         2hzMz/D6HXzN+zJMxYHJ7HEEA66KwLltOaPw+oFAOjRV/4sqZAoWEhD26S2aP1MRo2PV
         iIQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZFYWnks;
       spf=pass (google.com: domain of 3khcrxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3KhCrXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id z12si8236pjf.3.2020.11.10.14.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3khcrxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q6so37500qvr.21
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4514:: with SMTP id
 k20mr21206364qvu.1.1605046314408; Tue, 10 Nov 2020 14:11:54 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:17 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <47785f5259ba9ed493d2ac94ec7c2492fa5c1f14.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 20/44] kasan: rename print_shadow_for_address to print_memory_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oZFYWnks;       spf=pass
 (google.com: domain of 3khcrxwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3KhCrXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47785f5259ba9ed493d2ac94ec7c2492fa5c1f14.1605046192.git.andreyknvl%40google.com.
