Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIUNXT6QKGQE4ROMCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DC2152B2838
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:18 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id r15sf4662735wrn.15
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306018; cv=pass;
        d=google.com; s=arc-20160816;
        b=ya9hK7+7cNMI5Jf1r6/YzWcFqf/yKV92bvL5HHpXpPcqJdF8DM7tOvcpFwHR2PbRRz
         v05PQkF6mbmhvrydb4N86XXWRmwqslnBpwKZ9OHYx8pjPjwF5Q8RMCfp3Es2+Os4Mbpt
         yzovtFujEkxBtLIZeYsRzatLCThzvEEOWd1rHVRMbUSybC/U9A66lw3dzLoYNgDgKvhs
         A0jgsZ1kbmbRPXlUzQ8ZrGhj/2q+RT2y+EzmdFmwCZwnXSnWGreaCG7MLBMco4NopEBJ
         y1FZgRxBsHaaQaF+HvFXyzXce/8zwaFYVdoBFn8+q9fSWJDNojA/deDVqaRRXDzi4QsB
         0s5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=laNnVLOxGyX7/V+BKEZPgs0u7n4K7C7xUPJOc9yrrW0=;
        b=AolfaGNTA+haxNyObGxtaiJa7csoxLVnzpbsFDtrNOpgyaRlGHVvTZqiEsTGkqZeFB
         ofTEwujs2F1AARBQBIk/FiF3kmWN9AodDbSutgkJ7vMTgq20EZgJbzwLJGoDzlUI69Si
         W24UsVbwMsfa26zeiqnc+qKhWIke+esvzbEx3+6kwxlMeC2hxUKbIEL/LcvRIvOUZwkz
         uVva5PJtYM/lpPdO/HqKzQGtfnagKn4v9GKRhaders1Jrk9Gr8JAwEcNX645GWTOEWUM
         Z75Wg7Kg+bx+y9G5hSvwya4oidy6mOFhSGJR+PEO9UrGV8xkO6ERFZvo+nbx/Nbx3h+w
         AgWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sv8Z/Kpl";
       spf=pass (google.com: domain of 3oqavxwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQavXwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=laNnVLOxGyX7/V+BKEZPgs0u7n4K7C7xUPJOc9yrrW0=;
        b=VBZ1coTUco+0aGMzqo5R46bILAn42idokrcVHztyI3tSCvGr6vdp6uVafmS+VMNG64
         HLHXNuGdRI55Hwc/F4dIZaKTmLcSNLKrJs8jDuBW4rSkOAQFPP/7DRHO/jSMuuzTkGIO
         E1gPL6RYPiDaigZmt96hns+/Te05tUxLWe595BvHv7OXS3Li4/RLEIdce4mvMCACWCeX
         Qm9nUr/pHPgyS/w54UyeObs6jB138XQM2l+q8o7PFBkdnmoS3I0LryfD6R+vUjSRF8JV
         iBWAn40TrHjE9NsNw+eIKkHMZdqDwSqECKwVDKOi5vXCWzlaIxypjhHz9uiz2ys0lREU
         /nwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=laNnVLOxGyX7/V+BKEZPgs0u7n4K7C7xUPJOc9yrrW0=;
        b=fPdiDuNDo9Sx4rXgqwwCSgCFpJ6oB3B76DekP7aF/wN+jrUCXdMsxHDB3NRomikpn3
         fcOEX2r7TZ4qaFTLqJpM7X1Nure8joltdvWQd3cQER9IblTJvRuPIgHAkiMWvNsOTJwl
         cbJCKIHQXCDh6yDgh8mggHpExcBdk3G7bW4YE7FF/RD/jC3k0dPBCU0GbaSDqN55swtO
         eFPGGbpc4RIZvVVjdh1C0JSJ4MpdczOs5UFWglYKY6apVcjoiSzPu+q3B+qFUrPAsuII
         wIXm6ZH06Fsr3Nlp72ToHKShsjUnMGTCLBGrOWLHU3fnlZWJMKFxgiMebsJwRMu0HrAm
         ZJaQ==
X-Gm-Message-State: AOAM533MkRSx2nF25zukF16ymug7fctBE/U7f0FYXS3ga4SLBafEwvrx
	NGehkVuzL5XeQDECH5n5IIo=
X-Google-Smtp-Source: ABdhPJydB12r4brrwK3btEPNh55h8Iz/CbIszdp1j7/G1H+IfP9rreyFDT/hbKGNQBKMqBqIp53xIw==
X-Received: by 2002:a5d:474d:: with SMTP id o13mr6385904wrs.178.1605306018650;
        Fri, 13 Nov 2020 14:20:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls7245618wrn.3.gmail; Fri, 13 Nov
 2020 14:20:17 -0800 (PST)
X-Received: by 2002:a5d:488b:: with SMTP id g11mr6434141wrq.210.1605306017855;
        Fri, 13 Nov 2020 14:20:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306017; cv=none;
        d=google.com; s=arc-20160816;
        b=IMv46ZzBC7gJSiAMyISw0Lh/BwQOb6KF72pZfh+2YOi43h4H8tDJgU2yv4AUPjBLjA
         MtcaFmv/yPUhouB9hw5INBeTlhEYwMhvLS2R4qZnAnlVbTSpLUOz3LLKvmqcbmUXblyC
         ClI5Z2GfT7VyjZx+QcsO42p26oDURs+/xudQj1K//SFI6FzB3PwRYM1Kr5IVnAnLPT0l
         36vvHxaYZaPsfqpp0TZ+TreIi7bT/XsTfm8jJx4+RAHXaBIu9HgKn68t89VPeXXdvQbi
         Nb7Y2ENjSxEtUOHaFaudfD5npV/RAnGz6NZ3jQ0evS9mE8YbjSt8niV0eD/Pm40ldH5o
         YNYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yJWxegPyzZmdx3tmzwd/mzW6YwRRuhTO52iQtSKYSdE=;
        b=K95Ai1/XppmHYFZZNK+2dUwppJGkpRmHgZ9wCDX5EtWPmBxUNgowJjYmls3OPvY0od
         2asrcazCedHN92tTCGTs3zm5GdZ49882dg7Ali0ZYyzARepW11qw2vLdBMhi6a5iYsd2
         wZM9FPAwNg+LS4OpydYRaBur/U/zJ8X7rKM29Pf8Ky1SdF/8tt3q9p0XC9PoX0/0I95O
         8sBIbiEv2V2HcDrIYLCu6piHRabfvnJYynCVklceZjwKt7l4AloBszYbVmAQdtS3wvYz
         TZWhg2HOLEAb15k5KHOv1McwJmKGniv9lEcNzIOv6CmwiV/q6N23t9Ah4vzYQxO02UaS
         XyPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sv8Z/Kpl";
       spf=pass (google.com: domain of 3oqavxwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQavXwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i1si349739wml.2.2020.11.13.14.20.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oqavxwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h9so3561776wmf.8
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:658b:: with SMTP id
 z133mr4378653wmb.1.1605306017372; Fri, 13 Nov 2020 14:20:17 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:51 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <0eeeec8ecbf877e526ea43808e40e9062550217b.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 01/19] kasan: simplify quarantine_put call site
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
 header.i=@google.com header.s=20161025 header.b="sv8Z/Kpl";       spf=pass
 (google.com: domain of 3oqavxwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oQavXwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 998aede4d172..e11fac2ee30c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -317,7 +317,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 64560cc71191..13c511e85d5f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -216,12 +216,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0eeeec8ecbf877e526ea43808e40e9062550217b.1605305978.git.andreyknvl%40google.com.
