Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSO4QD6QKGQEQUEA3UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 64CCA2A2F0F
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:30 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id u207sf3504689wmu.4
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333130; cv=pass;
        d=google.com; s=arc-20160816;
        b=O2Up7v6YK7kIYVE2V1A2ymkCqr/nB9Ku+kEKKPutrGIGdHz3k2YatXHQrfo1I9MRm+
         vWi9HfD0e/23Eo0HUWPwnXWxULnsTmt/xr0Kpzo8wRA7iMF4e9Dz79ExNg6gPzI5cNW0
         V/gmH4wntk/XygHpuSmFeqlOy4jlE2/yYChkZ9v2iEfBPX0n9A/f2VVBsGmcBQalLZ7p
         HoUkXkQGSaAb/M3dOzV84tlSh8vASqcuq4tb4MEvoecIU7FLcDAuflL/mYieQcDQFWyC
         /bb9vFoZOvfHwJP1QK66geDoF4ehmU2LcDv9zSbrezdx9Hrc5Gapchb9+NkcQyUG+EhI
         GmdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nujQingmeK1GentHI+jwALjfga6FiGPChqp2BtGan6Y=;
        b=VU8dSdKfx2Wv+F+xLkEDgSdEIustrzbflJI/qYtH0x9lsW3ZdMcDaWD66eDUzIXfLZ
         hVdMOBPGlydrTKo9JMeaDGmfK+6iMIYfocKmdhQ/pyDeD2SVU6sit+/vTaUiiNXre+W1
         YcTx7P/HseIU5HpLE3cjaDsXCIcFNFkMWQon0yqcSowCZcM07cgxvyGuMNm0U6vBVeFF
         pAHkDmxHFJT+En4LefbVVjdxSONwfQDrfAH8wo6ilHzMkUI7FB4g3ARBKpCAM/vQAuq+
         lSexN3LAUTk4G/ahu3I+FdfapIIt5wesZV6eqkhScXwdhj9AOjHSY0csn8lCLAoua6Ii
         ToYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v6ir8TXD;
       spf=pass (google.com: domain of 3sc6gxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SC6gXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nujQingmeK1GentHI+jwALjfga6FiGPChqp2BtGan6Y=;
        b=LWqYD8y4+LnQVTI6XQo3hJmfaSYVAF/zUBFocKlgyBo+1PgCAC8CVhgsLuD0KJKffs
         C8vCnty/PNWV0zb/cbs8jYw2XFFH9I2/jzL5cb997qCZWgnBDmupH7y4snSGhnWpuqDd
         Oc0NKM3oOqb3W7hsw9JHxC7ceYbIL3Z8NNng83fjjZ/ZMcxqfo/odMylavG2llG3Q3H2
         Wu/hnp0FEPLTv1ZB5W3z+hrZby3/JFRQivclN6NTuM+YPpyeC4j6fdwXR0wI+03fu5aF
         z5DVdlSjp5wJDlN8qkNcWtun8+h/G5H7APeZiUj81/cEULPwvjPT37iJDzLfUASf6NG5
         O0pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nujQingmeK1GentHI+jwALjfga6FiGPChqp2BtGan6Y=;
        b=H4RByoTzzOLF3gCF1gSkdPzp24eG26Kt4hfZMBowz9Fon0aZ7CiIG9PuuN635amT+A
         nLqRGY0dpGHpDIZGLKuZXWoWHd4LMKuQBrylSM1gWcoCdnEhjtziyAQTrpTLKPgTa4Jv
         icK8EyMzSA1drsMsUny+6OVH2Mpg9eHGndLQ0H06H0U/g/Vj3sxLDk4wqopPoXRts1+u
         W+uayN/gnU0PJSjqs7mIcXZz3h8KTKiY/UN9d8rjtDVEuPLTnnawo8HfX9OcYycS1GTp
         cy7w7/OX4EEep+52Lw1DCUq45xpnyj9FRSv6MG1jUOtioYHQsXW7nmDkMcEnyNqbLvOo
         RqRg==
X-Gm-Message-State: AOAM532ua76o7zTK3p9ld7JXwTczzXhefo6BPQ29f5FIIJeZPKBxu4yL
	lO1I0eyVBDbw9JErIfZprr4=
X-Google-Smtp-Source: ABdhPJwSw+AU5VwjiJCILcwP26ejfEIhuCNc3buuUxBnrEFaG5coqXwTQbcPyMvLnesvYpVcjBJmLA==
X-Received: by 2002:a5d:4f07:: with SMTP id c7mr22058729wru.296.1604333130153;
        Mon, 02 Nov 2020 08:05:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f7c4:: with SMTP id a4ls8875821wrq.1.gmail; Mon, 02 Nov
 2020 08:05:29 -0800 (PST)
X-Received: by 2002:adf:fa8a:: with SMTP id h10mr20820843wrr.336.1604333129354;
        Mon, 02 Nov 2020 08:05:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333129; cv=none;
        d=google.com; s=arc-20160816;
        b=dCd8CBBl0ejIx09zCUQZrI+EHG3miT41LjJS21hCk6cNwTL5gPxo6m3CgKLVPZ4WSf
         KWxsWAC0xwzWczis3IDuQ4ptzaS2p8x0wDnLM4m76vmbWUPRekP53bFU+Q3oyKurUhQQ
         RKwa3HvxVPGNW0k7TDl9WOozxufXOH8GL0E8WkUezb8de2Gouo0FYSqQ8qtlNenVeSr3
         DatBCQTjKKTH2yAnkZeX4sBrw1oJ42oY3dsn85+BGurqpv8kDo6tWPdnnE9mFAhOfinA
         DtlIavSmBY8F+Qd4Jlnh5sHf/eJA3CbBaITM6s0lxEe0seRiIPlSt1DZTVaLE1S40wiS
         qoKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sVRidbcAWerSUwt2ci/DUHKn4WqZtHdaAQApmenAD58=;
        b=NSDwP/yEnDrm2wu7FIbSXXKjx94t6bxiX8c2rBY7Xw9G2VGD+S2PHQ9lqehr+Olk7H
         3+KwaOGKUG99oUtdWkUQJs1MskQfuJ6FxxqcInekzZX/Eu64f16Qt86FribFY1fTSmFH
         Cu2OIOrQSWUtqDV0sClFMhXDrw/o4l9CULUmtO/nICfbs1bHr6cndDonRL+AO0+JsfNB
         T/Z1vIOIWuYJ04O8TfmYYXgk09b39l63rsRCCpF7PoHLOWQH6B684UULTYH6L+h0lZ2y
         gLxd9UGnW8dLHhHQR7hT2Cqmq5g1wh1sN7TR7rVeD+VV92JkYBMWIipr1rUqdfL6k/I1
         LaZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v6ir8TXD;
       spf=pass (google.com: domain of 3sc6gxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SC6gXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o4si379074wrx.4.2020.11.02.08.05.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sc6gxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y187so721667wmy.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:1109:: with SMTP id
 z9mr19417964wrw.388.1604333128982; Mon, 02 Nov 2020 08:05:28 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:06 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <fa10232c2a15097fdb6d8ace41ce3232a4d59536.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 26/41] kasan: rename addr_has_shadow to addr_has_metadata
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
 header.i=@google.com header.s=20161025 header.b=v6ir8TXD;       spf=pass
 (google.com: domain of 3sc6gxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SC6gXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 54fc3fac9779..ce335009aad0 100644
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
index af9138ea54ad..2990ca34abaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
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
index b543a1ed6078..16ed550850e9 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fa10232c2a15097fdb6d8ace41ce3232a4d59536.1604333009.git.andreyknvl%40google.com.
