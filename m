Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSNN6D6QKGQEB7XBB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id E57402C1541
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:42 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id n8sf6910799plp.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162121; cv=pass;
        d=google.com; s=arc-20160816;
        b=V7eBSwUeIsWqzZ8GyfYhkT6hnhXreFze10YaAFC726mFZRXAu9AmB6zjhhL6efSGrz
         bUzmR7/B6Za3ot2UkuMNrYlaHLO6/8mtWGYMwRdWkfISaiM4Mx6zByEpEWw5o6w5SR4v
         lsuiFhUU7BFeBxmecsnHT+vHi8v+pumjWvrgCOiyCbO6+kS1m7EM7a0L/0WjVrtI3idF
         MedNeG6seFiVhuulMYUk6t0pL6IfYGBm59V5x6VQ5gI/ZMIGlflC9V7Dskw4WEW02OIL
         ECdOvxuGnw+xmPETk1Ub6xnhC9aNZZpIbclTReEyWtGx0Z1oR1Aj5T7eIqJHeTghA4b/
         VZVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gXmGMrtgr9m+slgKcWZPWoJdWeeVpz66ha3+22eamUw=;
        b=bEmuurGSc9iaWosZHEuFmn5TN6Y/lcqeeHEDNAgmEGBApLnYgQPaKTS2KMGdvZ0pKM
         /hAYOvl9icYrIhq1eTfmiGx73ve3BqwjdJVs2rgJYjlQPN6TUE5ua+j6x25GiNM2y4Eg
         /AkLClG5GjN8fGhS93bsDGuYB3Amdzo8ukUQDaXXQAoS1zCfoVFU44u51uLCOzt03n9x
         nkHXZYY/btmNB345JKay8U7wcFgxvTHnBkiEkyTYCqdLz27zwTAronrB5jre8ICjZZrx
         aOswyFTJfPq5nInXvQcb2cMNlAlt8i38WZyPBGAty+igBYjIlhlbmP+gAcPCAqqrWOKm
         07vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mI2C/t82";
       spf=pass (google.com: domain of 3yba8xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3yBa8XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gXmGMrtgr9m+slgKcWZPWoJdWeeVpz66ha3+22eamUw=;
        b=Zo3EAK6tDmS0LoFwEuSriTvTjQwR1VcP2ie3orBgERY4ducQ+Uzm6ghVYWqTJUL0Z0
         GSqVAfyYtbWTXiJD+SmB709mexekffPyVgyuIW/43CxMuAn09Xv5GxfLr/27XnZM/yQo
         TRUwDZidBl0Vn8A72bRZeRYaB4RetonOMDnf7b3oRj81jo1kIUV2wzTiGOvCL7M9q5zm
         jD8DdQKsjuBVZKORyT+e+Ukzae2/vl5U4n85i07Xeu3UYSw9M1DgPukqv34XY6N3RGFx
         DqaSUjT1enCCqWAdMIfwT2UGVBApikv5pgPa5usYhjRJa5Kt0Wz2dk/vw2Xp7VVsO/Wb
         vLbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gXmGMrtgr9m+slgKcWZPWoJdWeeVpz66ha3+22eamUw=;
        b=mUD9R0PxvnU2x3qjj70tL0KodChh9mg8U/W7QPQraAYvLcxd0bkatBgXlzoVodUZGp
         fiTKtUfvxNZu5kLtAiCFIGBN4J1ZHHE9/6yj7OG0N3P45OiSW5HxfA7TAIi5nz6DkhiU
         zQVcWFr+WDAnHDjMARzI9a00R57GbQ3nONTG8ZEHDf4EBoxBV40o0PPNpcCKV/RO/hAL
         S+s00Ju4pREQvhKyHb7bj6i8BmwQNPNGgbz/uyBX92RZzPmf8NyJSro8DJIAdmPwgFiu
         hh5pEqyJFxVuhNNBgzevx5HUym3DrtsRvCzy9KTyAyVsPg1ktrBbDXdZWUdAbTNRxhfr
         Yllw==
X-Gm-Message-State: AOAM533GnG1DhmnlGCSq/MHXm95M0wGbQBQ982keSoyvQXp6PlLd5gkp
	dh6udMMPcptOCHPFqAp01ws=
X-Google-Smtp-Source: ABdhPJw249yAhMHFnTWBhOHCiVTE3mTDUwJcbCY8ab6+HFAlpnz8RPp3zrZSLTv/J/WeC6Uoxc8INQ==
X-Received: by 2002:aa7:8c16:0:b029:196:33d2:721f with SMTP id c22-20020aa78c160000b029019633d2721fmr999346pfd.70.1606162121668;
        Mon, 23 Nov 2020 12:08:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:de41:: with SMTP id y1ls1372517pgi.9.gmail; Mon, 23 Nov
 2020 12:08:41 -0800 (PST)
X-Received: by 2002:a63:5864:: with SMTP id i36mr972299pgm.68.1606162121025;
        Mon, 23 Nov 2020 12:08:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162121; cv=none;
        d=google.com; s=arc-20160816;
        b=yE2PG3M/uBm+4zz1/NiD9tpCYDHdRd4n3NeFOhkU9fl1y/Kgqilz0pqemSV4CX4aKL
         QXtGOS9OxNkHI2po4LTls57IDauIkSLDkpEafO4QGpJhdqmJsVdXyJfVWTC9Kqs9BP0h
         FfirdZeFNFxCrvlJa8klHIyVC/j4+Jpw+f0igIPOXoLSU4iV3P6oLMF7SPMjoQugU4LM
         o3r7HyoVFCKwZVHSU31pSxzrTHa2636corqCdUGfq2PIsvU5OTzE1WIjPnyIS7RbSxf1
         Iq8PP+u5+SCzdlc/Glfu+/JEme4Gg8njpVD2tNT5kcM9I9MZDxdShk9Idbh6n6hP2haF
         /B2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MuLqLrZstENUkSlaOHjVDBkv2H0uielvFk/0yXzNfks=;
        b=wBiJuPFWUpmR4r+G/zaao54ayXfXeOZCsQYJfMsjGeQ06SHzAONNbila6ZfzF+bamN
         h57+o532/ZM4utFE7ZxpZzWlZQaRB4CIdJG3iZ2XeTitwWToqIw0tNJXYu/j+V8RGhtP
         N/lPEczeJDQ9lVdRXnfgt5AOFdwIIeT1DM8M/IJdIwkQTu99xOvq2SlVrG0auLs0JyDF
         EZSlxwRntMVq1c7LGVSKBh0Ahu7/DrP6PLkPniAAXaXXSr7XTxna0G7wJPQsY7BCxgwT
         k5fQ+3+IIFYsEjeR1VxIufzdOANr2xxbsCiZ/AV6Hf98QJgF84x6JvF/FIY5yPXBQmiM
         ezrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mI2C/t82";
       spf=pass (google.com: domain of 3yba8xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3yBa8XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 80si869950pga.5.2020.11.23.12.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yba8xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q6so13672358qvr.21
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4051:: with SMTP id
 r17mr1061834qvp.39.1606162120173; Mon, 23 Nov 2020 12:08:40 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:33 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <8329391cfe14b5cffd3decf3b5c535b6ce21eef6.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 09/42] kasan: define KASAN_MEMORY_PER_SHADOW_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mI2C/t82";       spf=pass
 (google.com: domain of 3yba8xwokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3yBa8XwoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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

Define KASAN_MEMORY_PER_SHADOW_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT),
which is the same as (KASAN_GRANULE_SIZE * PAGE_SIZE) for software modes
that use shadow memory, and use it across KASAN code to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  2 ++
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 13 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..bc0ad208b3a7 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) ||
+	    WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) ||
+	    WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 53b095f56f28..eec88bf28c64 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -8,6 +8,8 @@
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
+#define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
+
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
 #define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4264bfbdca1a..80522d2c447b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -174,7 +174,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -445,22 +445,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_MEMORY_PER_SHADOW_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_MEMORY_PER_SHADOW_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_MEMORY_PER_SHADOW_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8329391cfe14b5cffd3decf3b5c535b6ce21eef6.1606161801.git.andreyknvl%40google.com.
