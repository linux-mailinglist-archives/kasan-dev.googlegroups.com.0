Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVFAVT6QKGQE6YPBTPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AA622AE2E0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:36 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id k1sf4861339wrg.12
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046356; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgK2ftCpzpgZCFGb/wDK1CI7UMPMd+8O3XtxmCd2S5S33VYgvfkolC6qAPDsU7e6Xx
         orDtxbVHsQpyn71mfe7F1nXGyW6B+s5rbPbc9ZppUaq/jqZTKi8nTO7GUW+XK2rO13jE
         wtVshlzfBF0O/K+K943cLAbGx6R8s2rwyqYGma+EEZWxgv72Jq1I29gYKy4007jewoFO
         FTpe9iU+u5g3YI2CKAptJ/mdLmRTR2BSONIk3k/aGSzXeaUGsHXPilt63V50WQYBN4Au
         e+rSgvgcK1GvfVKbKTpsHXw0h+SfuoNqJIbPqSG0YJSbmR16TxypbG1s+WsbJ9F/UJAU
         9jIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5HaxN7fTJv+TyNStam+ORlnv8ewivVAiUXO/gyAPrF8=;
        b=Axtf/oXJ6ot5yeOrAZde0C5dKi1haOFQh+uB54gq7hIUA29E/OYJ/SOVOOI0DRtNw4
         sC3HMWjdV02GylUnoyWTExrBOID4rrxN5njPHb9kdgPzFX+MsHlUxV8Vuk8J3F+ADIdQ
         p65CgdcbddpHvjNU3yTJQDl1iKYrl2oZw1DxxG6UlqFfb5n+MFmK2vBuwC3dF4lprImH
         GrRwGzsmQs1f/1FfFNqkxKlh+c32I72RPJFb+/InjQLzqfEOYX4WBMg5HLTpxQx6NRtK
         zSkKuFep/6QJY3Vbcgb0ZAqk4zsV3C2yZOoPIt3dXdBbmeD5f2Tfh3502UfW6ifCO1jF
         WwsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YvQ5Un7K;
       spf=pass (google.com: domain of 3uhcrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UhCrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5HaxN7fTJv+TyNStam+ORlnv8ewivVAiUXO/gyAPrF8=;
        b=ghUFfuzWB45si+VqabfG8pHM3IWlJcvRM8XO4I4ZIIonT2FNzgUp9DOmQ0hM/QOi7G
         yzVTte4MY8wVJsfDpgqsHJzjZQfXYvKaq5Npj81GSUuI8gFSl2NblDHAUTJpEiHxgKYp
         ZeFD9+Ygtmi6wiaRYQPgzjVtn45s1UIDdSSXlPghqFeLvE+58ifqOT2tlw/LA7NjKKk3
         Gj9ayZjadZR6SaQ09iP3AcnjrdchN5SbS3uA6uGfy5p94Ugrc8q6xuOL+A3pJnqfWzFG
         Nxl4zNBcNDQBpb4/gZpRW66o7c9ekje7gukQpLpwuqjOroJBVVSutl615/+emJEAoDdi
         NK+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5HaxN7fTJv+TyNStam+ORlnv8ewivVAiUXO/gyAPrF8=;
        b=GwrqZAl/efHAYmkdCUrsATHUWa4OTNE5zF8LNTDPqq3BC4t30nkOwfbYN1WX8dmpl7
         Jp8B6ASxe8onSQkqkwtVJv8hPWaRiqErdioa8ZKShVb5PZHyHp9FwSJCb/sGvxf+ocgf
         dGni/YP6885C6tlieQ0Q2kqgIUxKyOiLcOfCxXdB6bQDXHNxXyECTLcXIjDg7HYfXw2H
         a1IC9gfBheMT7MEw/hGiFfRyh7Yu+exCglzYF5xvU3g3KYnTXnF2H6KNbaXeA7d1xwyL
         DKDgDnUcpNrBImGRAUa5nNUBg+5H3UsikyLinApH8SGa/im4zNuQB1KhEOOFRsvTOI1Y
         AGcA==
X-Gm-Message-State: AOAM5309hCp4FRyG0qtZDXhoHrb+pT4+B9qFpPPiUYeRHYWhyUzTSxjg
	2HV6C4hCucJ/TgnEcyQR8gg=
X-Google-Smtp-Source: ABdhPJzqsDEb8d60TkxOJ29P3AGP4/rC5UDfBZC5qA/1KPEDywEuxh+hH48zXnMEPHaaxcN/NtKKDQ==
X-Received: by 2002:a5d:4ac1:: with SMTP id y1mr26955064wrs.27.1605046356215;
        Tue, 10 Nov 2020 14:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls212851wma.3.gmail; Tue, 10 Nov
 2020 14:12:35 -0800 (PST)
X-Received: by 2002:a7b:c848:: with SMTP id c8mr271157wml.86.1605046355363;
        Tue, 10 Nov 2020 14:12:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046355; cv=none;
        d=google.com; s=arc-20160816;
        b=Z2r+ICQ6QgI3pD42qI/SBG8gjX1rf8tLa6orPnspNeZMmAtoOswtOPpcRlUe2NSs3w
         wTQHYBhvHioXDyhV+2OvZ5F7OuGBpnxNFNj+suPGy1QtVl/wqyykFUKTtDV9DRoRL+zW
         PPV7phepNiC9DswjB6N29U3urBwLfksxa1ZxQko42vj3iWyJ7Fuu8VFw+RvfR2oOFZSo
         RbARz6sVypfN8BITECZJnXsBabjdosHH84c0Vvc8hV7kn3Tj8b6Uj5k8HsYxBhP7IcVo
         2HIvDR68z4R+tKRdNJUfwEGy/ooO1JklVRsuioRaawLaVRZBcKIdMneqE+sf3qizBNp1
         fotg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7C8N6r4JJ4qY+cHK/gFnwxLkHzjgeTe7+92TE+0jPPs=;
        b=kpqd+Pa29i68SIGb20sZ0fFvHEflsh2vg5/jxyNN5oOuBKS1+OZWdCRq90AocfiQ0w
         QU3kOcwip5xv0hGceRVZQ1ajOEsYsD4jPt9ctkiFtfeI70UnkNRJ6ePi4q4wNIZC/7Ht
         GEjukzfIgFOCsvlGBV3Ct2Jg9NRfFODIJGcm13nCKoryhEzeRjYzs6Bv/PNf4FT8/9bi
         TJ7kbg2UaVpKY1uGDx1zAyMc2xOKLG7RiMbOtykDMS9H9GMN/A+LyM0y3ubW43XXXPom
         1Q35V3KskN5OBD17Nmw48XedjPEfuLdgzOLgaNQCFlptHSmHhnvoXyukkUQKQe3GkCph
         V9JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YvQ5Un7K;
       spf=pass (google.com: domain of 3uhcrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UhCrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id t9si128685wmt.4.2020.11.10.14.12.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uhcrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x16so6160043wrg.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:634c:: with SMTP id
 b12mr10670704wrw.130.1605046354872; Tue, 10 Nov 2020 14:12:34 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:34 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <096906ff06c532bbd0e9bda53bcba2ba0a1da873.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 37/44] kasan, x86, s390: update undef CONFIG_KASAN
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YvQ5Un7K;       spf=pass
 (google.com: domain of 3uhcrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UhCrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index d9a631c5973c..901ea5ebec22 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/096906ff06c532bbd0e9bda53bcba2ba0a1da873.1605046192.git.andreyknvl%40google.com.
