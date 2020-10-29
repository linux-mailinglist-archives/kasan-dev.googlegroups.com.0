Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEFP5T6AKGQENO3SR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 723B929F501
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:12 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id s25sf301109wmj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999632; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmadD9yBHXVtawVrDaCdT/FwACQbpHibbPeExN/qgaWi5R097QEAsnLIJgcWX1EdOK
         jD7fVGxeriyzOxpqZ2TpdQb3Q8GRodf+lvQdvu1KWlBBSPPpSp3aj+9+Ln5hce7eVf+8
         WrCp5qdViKAQ8UcFOYPLzOMxHkYoxrbNKpG21p/gkbE89DlWGuwULb08uim3c8CvsdTi
         R4LGH0z3GiFRbZH0k1JrNkvMIDWdIUW7sVglYW2EMn85IaJDmsPq0Eniq9ZMgG5M/DK7
         EWaxKLuvzJKr59tlK1GMp5tE7u7nv1xZ+8fmAFXDfaQ9VA2vV4MsYqTSjxcMquI/SFCq
         otKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=u/kpSC7/gUcZYU0BlsGgcvxIGGyBxHLklNs4/+NkJUc=;
        b=s0rCCn21Lgf4p9o1S/is3o3LGiF3Lf0/go4Vds/524t7a1BLierpdW8H1P0WYwGX+D
         MAXySAdnLajrTctJwt/d6ciSKm08OzGIHjxiR5ZEHEBNeXVm602FUF74iCSw41CKrpWM
         oje/j7WRO1BgE48hZ6ESq9VxOz4z3BvncLreJSBlpF7TJhhswqkq6hRK2svNfZtvVkMW
         u1rZctH3yU3uJowa1cYdYhT546Cmuym6ass3hc9vkV3MYpvUTc7loDCivKqyHdZjjCuu
         13nfaiUuPbkciMqLaUvylIGupgGBuaHq8MEkmRdv3GrmoFnLmMB53+P6NBwbfUPX4XyJ
         M+RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tJOGLhLJ;
       spf=pass (google.com: domain of 3jhebxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhebXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u/kpSC7/gUcZYU0BlsGgcvxIGGyBxHLklNs4/+NkJUc=;
        b=n0fID0+VtQSIpFpme+SpDakgBzTQOcTL/7D5R/QGSnH5QqbDbhEmaDqB+AoW+E1PIJ
         Z7+5HI4DJg36DpK+RFO1PvBN/winU2SDcpcv4mAAMW2fdxgAnORq8/hns0mOrA53Of77
         JZr9eA6CrjVigLIVKxi0L7zX2wvCTt3dv0sOsPBItachkbbfnkA0uz05aJz60MmlGECf
         R2DOt49eUu92kWE2cnGXjFBmBIvOldpu6FVTA2QGb8euMXBMhWnkUpqE9xRNGYy/AJ+t
         W0U/1h0ieGKC1BIQkXzEuzssiU5ngNxp1ljEk7ZAK7cbgfyJ+dOgcjxyNJwuuAPj+Gik
         VpBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u/kpSC7/gUcZYU0BlsGgcvxIGGyBxHLklNs4/+NkJUc=;
        b=qFw37/NmU7NT7/90I5/jpovr+eh6ASEA2toj08e0waEhh6VagsixEexEfs/panC6Uv
         1yWueRqlAXJRIro3JOuWOFtkcIwIHXt7PFLS9BhgDGyQOux2EVV/Ns4DuKM/vCV04cAi
         J8ae8rB2BIDcblZ+CCH+89Q7qhlKnvRzHHWSXvNm+2bJjAL5lFz+zTtQiSW+TSjKcUKt
         dfLbl8qOfzUGOmhr35/iGbJR+bsBTde+LyjL0tvVfs1OAZi6N2a3SFTgRvuToacAMsmv
         aMv6qEv8vAsXXayWZ3S6WNl/ar26/3EVHOd8p5lS56QT17nKIhMAg6l1BYaJTc2l6H8r
         Wx6g==
X-Gm-Message-State: AOAM532u3UflFnFmNZFbvXR1Ug/QBUiy/8xz2sNKfX45cGNvpIJS7i2f
	WFX9W3FoT3FkldPOGVLRo7Y=
X-Google-Smtp-Source: ABdhPJzon/PQqbd6PbVjQLGhX9/avIh4AX8LRid2f9diIQ6t5sUPmXcQHXrWX8kgyRZliWL4mOeAEg==
X-Received: by 2002:a05:600c:28b:: with SMTP id 11mr799927wmk.144.1603999632194;
        Thu, 29 Oct 2020 12:27:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a544:: with SMTP id j4ls2598582wrb.3.gmail; Thu, 29 Oct
 2020 12:27:11 -0700 (PDT)
X-Received: by 2002:adf:fe89:: with SMTP id l9mr7707906wrr.264.1603999631359;
        Thu, 29 Oct 2020 12:27:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999631; cv=none;
        d=google.com; s=arc-20160816;
        b=EWNE2plhNrgpS5R9UWH7RumBUgoBQ69GkJI0vAjFPXDasgwNQRvJHtkRkDaTv5ADe1
         Laqzp/ypxPKZ5gWUbcgQ6yjje1eZ89b8l0dC0daoHL3dBE13MxwA8zgnNoAmczkrPUCf
         OCrhy4q93nOU8UHZBTz4qi/3s73hBR2JMAApIOouo36XpsSgnfi7EEYywPPHX9NIpbDF
         zvRnnphWH+ZXmhNC54QfAO6aJ1s1SjxwtmFi2nLjzt6wm//nIcirdEP5oTFuUMQ/TavU
         SXqxfpS4x30d3Ashy/v26ZHcgljrftYZ9b5usDfU2Du4W/oTpDw3r4PDPuNXcm2ITcKW
         u/SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=96T+1f9i/jCV3zB6gHtRoH9MAYIWASsGc4o7euuXITQ=;
        b=UuyqtdUghzuZ/A1DkezrFGZ+aWL8bnxUFyKPCbRXPC3Nf4apR8PS3QtkUzBgQuOjJD
         GlTe6nDQ5i1dr/SXnvwo7jz2OwwkHkRnYCx9yH+DI8BlGoXnFE1PEk1nhddOmbUlhkB3
         SgtI/sXVqv0Ia/n1rFA0ylU5nOvmu1wUruFlBPDVv8ONChPdN3dQ62/318KA/sdPJyvy
         8oQzQnViwIgGrkLrkyZZfwus8tZ+0xPSgxnUUf7PJvN+DvM+u0SwAFMN3KPLgtUET+EP
         QsTnLdPGiL98rqQW0ulopIoCHYQClk60u2DCT+mkUTZVqcyXyEjx3vGUd3pEznadOmz7
         x0qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tJOGLhLJ;
       spf=pass (google.com: domain of 3jhebxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhebXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 14si82882wmf.4.2020.10.29.12.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jhebxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 11so571636wrc.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:11 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2246:: with SMTP id
 a6mr723387wmm.135.1603999630912; Thu, 29 Oct 2020 12:27:10 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:47 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <29aedfa17e38384b43560d89742b1c9f61b3d0ca.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 26/40] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b=tJOGLhLJ;       spf=pass
 (google.com: domain of 3jhebxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhebXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29aedfa17e38384b43560d89742b1c9f61b3d0ca.1603999489.git.andreyknvl%40google.com.
