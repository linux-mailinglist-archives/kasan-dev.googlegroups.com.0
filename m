Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5OFWT5QKGQE6MJADFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id DCFF5277BD8
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:33 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id c3sf395347eds.6
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987893; cv=pass;
        d=google.com; s=arc-20160816;
        b=btamEMa8CW7NCfUeTW/PMTMw4VIbl20FXiYM4we7vp5U30xYaOBMJwaQzYF6JxJ1Pb
         OyNd7gUIT7d/JR+ecHfw2RcUIenc9ll49tJnK9i/cyJT7wuTMBiBdk5xxVPnj6MfvJNK
         CTv/xx3NQ74C9aEqBkEv28iwBdy3hXs+Ct69XMoZKCdH8MK8X7LS+Fnk6BVoc0kUgmD9
         a0YmgIL1fhE1oltgMzLaPwcw19l0iKpMAaxwBKmon0vXyx7OWXqGtO1aSGPJhhODsFnb
         mMtYt+a26CgQl+YF4Skeyxaq4d5cf0h6RRL0aOGpPIDmY82VdywQuwH+BZyx4Wdqjpvp
         1d6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GVfVa3NMvo28iix0JGHCtzOqSKhfC3ZXK5iBYu4/wPg=;
        b=mxPeqhg0+bDfwSgu1OG92QPpdgSzefGfJFhhn1b2ZaTMavaLC6ohBTi87JMoDwNphL
         4VetQBaFmGE9DLuRxhdl5wnFBUwIpRFSDERPR5hORgT0uWS+CNd0rQrp1ef38WGh7Mgp
         HqWPs1Ou3jSDtMP9+fnowJisKXWSduucGfmD2sf5g5+6/+KOYebejTOHpngOGnnzqkSM
         4v2gVSUg9jWguZgvQ2bWiTzh/mSpwNxATUOxnr6Vz1h2LygpVlwcB0OT2Fq916lJ7BsW
         5WaY8VhUKXF1/IUHbcE9VPVE7qrAKNi2FLbseCgq6FOdu8xfU1CcGjrlpy1+mgTW8Rt1
         S56Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gw9zXNxH;
       spf=pass (google.com: domain of 39cjtxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39CJtXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GVfVa3NMvo28iix0JGHCtzOqSKhfC3ZXK5iBYu4/wPg=;
        b=K0htLBnxqGX0mWb3CrjswxFzWhpCaNDVJqtYDMv8UnW06qjBpbMBLy1Fory/O1nEW6
         35ptqZGJq+qcfnLzZWtDoKAapyKiv6U0hAHMFX++XcTigG6liwX5tnRCDeIlI1epdyy2
         WXm/BNiNJuSXtOgY/mOGewgshpeQflFU600Tl9nbUe66c0jggjs0UOiOuHMcGEJ/biBl
         mxbZBFiZXj2r4ldQ1UXUqdBt/kHcTmtqOlsUkXpXr32zrkmWCMsPeX6Mic7DzVQZcQb3
         Om5Swqs1y82b/QDYLnexVfSPBdxE2nHJMt5I/lLo8+AgPlRFLY1hwvKP6Xcz+GZrcsxk
         DgkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GVfVa3NMvo28iix0JGHCtzOqSKhfC3ZXK5iBYu4/wPg=;
        b=bnTdOmLdlp/q72enNWZ1CthZLFUa2q5tZFRf3SZiqpI45+WdH3kgPpen89IRYvWxqj
         UAT5TeyDx5hWNa0fN8t2kXlTLtHk51SMQhm+EaALJ1OsWbcA7SF0fSgnawZ9JkxKazcF
         mHN8MXBhu47wFBIzICdSaZHHOdu6HfEjJMvEc9sOL5Jcezb56ECv/zwB8Sq+DlfEXZjN
         eo50ynsNxOoWCdDcvWnqK4WzNmL5UUdWVgzfTXo6uh86bEKK02drr1GSXmnG12lfO+Dp
         Aulloy69Es/dxCv/NKZ+eS/Proi5lVtIdO7Lb9Tu813fQQ9e/p5CvKF3dpcKgJj9GQE+
         jGtA==
X-Gm-Message-State: AOAM532+5ByMmLyHHHqtx9i0j0iw9aTGeXac3xX11sGcL3WNXF2p3TDl
	3/8sWua1SVwi4VhFtHgoXDk=
X-Google-Smtp-Source: ABdhPJzS30FzjrwG98LcTjsh9Aoumr0pNz0nNyOIee2qYgRferL7zFgu61T1e+3Dgka6ey124rdjUQ==
X-Received: by 2002:a17:906:8687:: with SMTP id g7mr878532ejx.129.1600987893671;
        Thu, 24 Sep 2020 15:51:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:71da:: with SMTP id i26ls256059ejk.6.gmail; Thu, 24
 Sep 2020 15:51:32 -0700 (PDT)
X-Received: by 2002:a17:906:95cf:: with SMTP id n15mr937982ejy.14.1600987892688;
        Thu, 24 Sep 2020 15:51:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987892; cv=none;
        d=google.com; s=arc-20160816;
        b=RnK2H8ifiOaLzjxwPMwqyS0G/VQ4wBUPGT6hav7DF0tm8b4Jx4zoNR07uiy4vuW01r
         R6WDfYX4IXCOTtfPlCz8wvurcuhyysOc/eLf1c9hQOo+XujwPhViZMhIbCueByCMyl+n
         mDFD9QvDt6xdcm8iKqvm5U6zbcXbpQcF2/zUUKp0KI74joaG1ET+z1B/xYxiWeF/shxr
         rMUnWoe/lkDNC+SR8rceSUdOGg/5lGeqTz1Rs6k09xD6VUsr4xsAXqzdnIHZkQe2OirZ
         KRjCWnPukJZWzsAIj8+q80CP7dslQQznHLF2UmZyVpulwjFCc2cVsqusl0xJA7ODYbKO
         mP0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BftCDXbWjL9wnLQzbXlcogs3AIdXjMmm0RTraZ8+u5E=;
        b=CtbSSOWfsAM+pPfPzL6764r9Xi0zEauWYHCKGDt+DWv2K3gPFwYd/2bVG5ML1UQ7Ab
         NtDMpWd796gGS8RcerUUjWYVA2dp7tWXpgM/uyctn6uWTTFjiMDi61DmkoXAD5rrlsZY
         LBwDJNwtMhbWTL9EXJMDrwEM+qLmTtKFOuOyQDIfOnXYK2lYb1hcExbq9jlTS6iosW8q
         NCkHg4kGCazUwAztXdqqEwEIB9A8rjV1uQPAS8mlEmSyJHh1/7f6QZzNFhy6hNBTDouR
         hQkiQgxhQbd3k8JykwkUZCfsrr/K2g7hlyNCHQnOuZJ7K/z4tBtASaulmdOaiJQHnwz+
         R1RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gw9zXNxH;
       spf=pass (google.com: domain of 39cjtxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39CJtXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id t16si18055edc.0.2020.09.24.15.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39cjtxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id l1so389338edv.14
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:32 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:1c1b:: with SMTP id
 ck27mr1066322edb.12.1600987892214; Thu, 24 Sep 2020 15:51:32 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:24 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <8580d4945df57614053084eee8f318edb64712d3.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 17/39] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b=Gw9zXNxH;       spf=pass
 (google.com: domain of 39cjtxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39CJtXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8580d4945df57614053084eee8f318edb64712d3.1600987622.git.andreyknvl%40google.com.
