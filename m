Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4WFWT5QKGQEPXJN7KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 1481B277BD4
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:31 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id d9sf282713wrv.16
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987890; cv=pass;
        d=google.com; s=arc-20160816;
        b=Up2t8M3IvsOMfGa3Ysqhk3bdJhu52uF+BlBs/sjK3Y0V64aDufnwaIccEEsNFEu/z1
         1mrHBNSXCKZ9vNTen75DBTdOEnFlQVCe9dPL38qLAj4Xvi5UhIDpMA5QY4cHdZxDZSLr
         HfCf8DEmip9mP5JW+LQRpIbmeZGTPHxRRv8t85wwKIJD+3g19gHAQRSqXJx7eGFYWWHu
         OEANxNsGxyq09b1MOsrkvuOkFhdtBTiSmsmZTF8bae1+LH7UaHRjiTgNDIqeQNX3XeSA
         c7hjINzzY5YF7bf4BaP0YXM4MwVWMZ/5UHQtRNRzzHS1LZyCH9wVuWPXI4xtw30J/6qX
         EGAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+klU4olnHKLMG8G7B1yVupxiXwgEwdVvXjD/UASQJTE=;
        b=oew9rs5wChY8BwVJJ7OwwD9BUNy7pQw8WgoQOh8U4+9CQx2M6XQch63XcLEqZYlNiE
         JJbfzlsQob5Tmo3H3SZJwdOEPoZZHFgl81eh+M04/cbDgF6/M+8N9jAIAEIKrKCHrlSt
         aPmdz7QBGjFs6RUKY7Z42WFOw2kDiE5sS7pOHaUC7WUZGos9xJWtQEepU02qj7TXa15X
         21erUfwqRX5A9oZFxpXNvs4JByFisQtU7mO8ovIR/c+yGx2LaJYHcxw4nOwMA7RiS4VI
         JTB5koAbwbxozPwFpTsVLXl9dahuEOy0BOesjeyjJMVPAbU9XYpNHpekfnqgjz8oJCEo
         iSfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pSVeZJ+M;
       spf=pass (google.com: domain of 38sjtxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38SJtXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+klU4olnHKLMG8G7B1yVupxiXwgEwdVvXjD/UASQJTE=;
        b=qeK/ii7U8Lg3a6jQBMPe82zJqhClAkbZ+FoR5wr9qTi9nvTh4P4wacTZ+sgDi21caH
         fY4bhFE5ctPijrxZbFH1cHgk09gusY7yjkg+WEbz8MN53I+86zQcqpemre+Ie+QCe7c5
         gjmpnUBNFcGB/MLj6dG3xqSNeL0O/hKNzmWV9tkIKj+KoWKSck/3ICEBuvts/thmGjag
         Ich+kplfDeg5ET6hqruqfE0HvGsKjMUhMCsDdB87AuG/7JNNNZdsGrMH0mscCpY5/GN7
         YUeI2k5mhemjLZ23fwAQMMDSZELa5Lnil14XavbSZa+digRe97pGL5JVL1oSmTStWhPJ
         lv5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+klU4olnHKLMG8G7B1yVupxiXwgEwdVvXjD/UASQJTE=;
        b=ct8O7q83U1TIBYz9rf1MukrfWHV5Ig4RA8NVySOtmnBeccYHMFBhVA7JS4dJz4nc1O
         W2nqBEQGJSYlC9LpxLkUKzGAE0h+13to5Ffb6joGxt/IGsoGsOHDEDPy8kXbxjtAZEM9
         LrSf0CspS7EOF5waUAd0E2FW4GLRPC81qizhIdNpvRS8q2QYRJl0i/WlXgmbRb2FPEwy
         hWoza1o8Btkans9jGYc0TU8bBhJvJIHLohi6/jspjhGISfSoIlXGK8LDYBNgw5CMw7cd
         IbScWPVgisMrCu6LEBG9Njq2UXLnXkNmiAm5yilUxWgjAoPDpGf8OUqVmYXhz4x6D8+S
         QI8Q==
X-Gm-Message-State: AOAM532XlKzYJysklkjgUINJhDRP9ulE4SY8n5fjvkMpQEhklqxwa1aD
	7ETQre8fk7l/wwkuoFLeDq8=
X-Google-Smtp-Source: ABdhPJx+fA7QhQuyGpdYPc5xUFlbQ5bg5Wqbaf/a09t8Qife3wlBJ8YZbHGJ45+f3ihA3++onRsWcw==
X-Received: by 2002:a1c:4885:: with SMTP id v127mr878729wma.129.1600987890830;
        Thu, 24 Sep 2020 15:51:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls226838wmo.0.canary-gmail;
 Thu, 24 Sep 2020 15:51:30 -0700 (PDT)
X-Received: by 2002:a1c:ed09:: with SMTP id l9mr836991wmh.89.1600987890078;
        Thu, 24 Sep 2020 15:51:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987890; cv=none;
        d=google.com; s=arc-20160816;
        b=yzann3yQvg8AkyKZ6ZbOjIuSgqcFQ3aDmqNExcz3eI1T1aoNRWDUlckrxXIn8zxkhH
         QjnC4FxIyNuP0FI1S6ivu1ViDFCcoKTUEoUViW+aI+6RsNPcAhB63QAqZgoIO0qGAxwz
         yjTjP036zoU9Rh6Ox3xza0zolIcmu1THXogyQCYhy89UznNau0QFeRpF7MJTaXl7ouqo
         VA35k3yGEuGThlbdUjtNQSS76cQa0id/LDhWwD2UUZv9uoOwoAlyfoZgrLIWOdnV7YC+
         KZWkN1YTsW2V3DcekamGm4pQ0Vf+Df3SM449rqq6Q4JqOAtyFAjB7+6v9f0MNycXfF9s
         1gaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hIFfthxFzKDNttx6Iwa15uG/YA2TsOtV5/OtZQz4D6k=;
        b=a9nFH8n/mH9GO8JGqiLeZrxu23BW+b0chdVoI/iwXu+IJXaXC6PcFRcoBx8/LdY5+h
         8XHgDbEtdGau1N6GamuvP/ii9KI8/Kpq7eQYLPVFG7b91REC3KHOP8rmbyOtSVw58Mw8
         eZA9mWBiUgjZRahjBb18fQDS/b0XWzgATW4FhtpYwJ4cwMyp3gX2tRUSaYvb9ncX+TKb
         6uT0Pn6stj7vsFiOHdHDsbeE36T6CQC/QgQCYke7gvKEXoxSyOC2BeLg2XPGXWIoicls
         5WAFrwXt7z6evWoElC2YtHGAYn8gruoRGJcTCBgFKLOFL0NwrOPDg0Y05oK00W6kkqPt
         kumg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pSVeZJ+M;
       spf=pass (google.com: domain of 38sjtxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38SJtXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z11si29513wrp.4.2020.09.24.15.51.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38sjtxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id a10so273679wrw.22
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:30 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:60cc:: with SMTP id
 x12mr1196294wrt.84.1600987889651; Thu, 24 Sep 2020 15:51:29 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:23 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <fd0103571c825317241bfdc43ef19766fd370e4f.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 16/39] kasan: rename addr_has_shadow to addr_has_metadata
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
 header.i=@google.com header.s=20161025 header.b=pSVeZJ+M;       spf=pass
 (google.com: domain of 38sjtxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=38SJtXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8dfacc0f73ea..0bf669fad345 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 91b869673148..145b966f8f4d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -329,7 +329,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -340,11 +340,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 42b2b5791733..ff067071cd28 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -117,7 +117,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd0103571c825317241bfdc43ef19766fd370e4f.1600987622.git.andreyknvl%40google.com.
