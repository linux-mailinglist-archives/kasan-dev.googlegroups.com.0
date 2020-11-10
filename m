Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJVAVT6QKGQE7NOQNIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99D702AE2C3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:51 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id r18sf65996lff.18
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046311; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJtOYTOldhlkXVl869ba+01thu4GJv3P3/Xl0TDZyKjguZxIEtMeDeBNkiPV5UdA//
         0yHasGrqVODN0zGFClnYEaSFEldIdh+WkyiGRyBeRcpIqEfcV5A7ghrv6xA79xhqlG21
         MYgLXN9ady9OCihTzAvM6szerfp2jUhVSAcZL1o7UW+Nf1/CLACyOKZ82szWb5lxU/yJ
         843XyjPAEEKFtf9i8Td9bzBBproJXoY5ip77EERjTGLSJZLQrFKKnoG0JOIW3Inbq4PK
         GXcR2ssEiq+FxbrO8AyT06iYaqwsEr+mCYLGjmMdK/agQMx56iErCD10MMx1JAg1zmJU
         pqGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Ro0H/8LcUmoCUqZMM0+uwlTONehve9akWbg9dGBloaw=;
        b=RYRhWjTWKeemp0JaM5dcWoC+xanCR77NPZNyR5VRW2ymM8vPMHdLjCZHHZu7WRDRC0
         +JMzwldF9e+SeuUxWyj7hXP+wSQ9yDMJ/2pRfZfiGPrUuN+HudzDjtRHpNn43TMrelN0
         GsSvmyVUpXXXLyf4BTz1zfjnmqyiFh/4gHb8gZoPYaS9edeqaKqsJ1Mxl98cKuIXohFz
         mrrv6MhV7++KPJOxbtfQwh0vV1EOoLBw9W8a8hqveMHzO+MEL4iwF5Yz6kLTIiYP4sKj
         roj4gDZvtHrCuU6aHff99+WAIzUJ0+qfCL4M82yV1PGVswnuY1GXYhv6EjSYhAcjy+oY
         4Ejw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i5hBOh9R;
       spf=pass (google.com: domain of 3jrcrxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JRCrXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ro0H/8LcUmoCUqZMM0+uwlTONehve9akWbg9dGBloaw=;
        b=fBVvvr35FZdPP57ewuq5iyZ+KkLJznJaMNQcxhSns7QpY62Yw92hhQNTzSnR7kR+SD
         jeQQtCJ7smR7Mx6dImPMom1c7ddS/LhuSrFgFlMfIdayrGV0SmCKxwkDNnNl1flYbB58
         aDHNES8gViPXI92upcCGmXnteZ+nYg6xjpY0kvasj9DSr9bKpQIGvftebz+wkTYpGsli
         AAQEarUk5q6I+sUdmp3KtRReMHHBVkHO9hZ7vjcaj/zkVtdCw0WeBv5lsR1qHXsPh4Oe
         58f8sA07Qtb66/YaWolLREwj4SIQm/KaDmk2Qf9Eu8fX4RySlHkuQBLvnQXpJ5r6xUpj
         DHbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ro0H/8LcUmoCUqZMM0+uwlTONehve9akWbg9dGBloaw=;
        b=pUavh8sa41/+9QBvDtGKO5O7SiPKg7YEVH64Ma+hifqRhci+ej909KKGAl58Jctgb+
         tIyfvXVCRGOuu5b6sr3nBRpbuGuXhnGua9HxB6jDNKpTk7/Qr8+ZYWjYdHw45mD/xygf
         XenCC8oWuYx9HD+El+AK6+SGZpbYXQPVe+BvNFMfCo6j7dMHNzBc1rsfbQtxhAzDztZa
         iPXj8uaSNquvCawXD85HLpEOKKXeNEG2xHntTYY3pRzdzk2QfCngREMXYNKttwAh/TFQ
         inkNKr9HrmwjQr4mlAVNkQ7z1zMccUER42cxBc27L+6hJfiJGXPp+uJ2dSu77dr+6z/r
         Rw5w==
X-Gm-Message-State: AOAM532FwSDxLcLKyqCA0dZNDqt6pP57dZZ/9v1szaHWRFez5OaLQhrY
	NmsOCa4QY1y2wuvpF69ORrE=
X-Google-Smtp-Source: ABdhPJzJGDNg2URY9/Jmb8erQxFN0juWNTuZnTEm3wctR3l/fE6a1uG4RpOwGnfbUrpgepmQILlj/w==
X-Received: by 2002:ac2:5c01:: with SMTP id r1mr9167504lfp.436.1605046311195;
        Tue, 10 Nov 2020 14:11:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:818d:: with SMTP id e13ls2407498ljg.5.gmail; Tue, 10 Nov
 2020 14:11:50 -0800 (PST)
X-Received: by 2002:a2e:9b56:: with SMTP id o22mr3508197ljj.349.1605046310152;
        Tue, 10 Nov 2020 14:11:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046310; cv=none;
        d=google.com; s=arc-20160816;
        b=eIsMWXpybnG5mKIvfxqh+Yh9zAPR30/WkvHBrhGnoTQkFjGoG5L2Lc8hY7EyQ5aP5u
         TQjvCLzbDmGf6fQH8X/ehr3LpTJGeJ078e91x8sw6+7L7W5b1uvIu7/El2+HJtf5+MR3
         u82LZchj7LD+2WJEcsGzv+UfLEm4aylpXLchy564HSXtKbBCst7cw5C1PMwH9GmL2se6
         maTcOWJp9oGRj8NxGMW4CHq/B+VEkqLV7alH2qLlSztxlqMI9ckBuDLSxXh0abLyypPv
         +YWTuf3v2pZNKPAfMeTAY5J3+pr2xcD+O7dxrtWjhC6qYmXWyefbaQc2TDmsJE+HLs/E
         P62g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=maJnPTI34+iFP5D0D1ra1sKb6Wkh8ktrMcPMtIoOl2Q=;
        b=s712a691A0F4fnxqF1EPBbLzeLxDwJoLf6/7MvSWv+kEpFqPjjUvfpUFjmYWAUFR5N
         vSvtAqU/wsF8+Mbw2FYtDnMV0+AMrKEeuHNLOPKTOvOCbL0rEFDf5eSs11775VmHnAcg
         Qsy3HHO1/z3YaYUb3LFX1dvnGwCSiEFhzzhKxIkrlxl2cofOTUdwdjH/wvoHRIuV5mqb
         RNtPmsGD5oW9hDo8DLfALe5KmAcww2ds35yCx8K/VlgogP3fh1jMuUXXt0e7OIblEIKK
         53UtIra5iNoz9IYZpCB2dZ15/6cFE2x8liygUEAWsU/63zspUYDBvbmGDtK9w6ACg5AC
         JPzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i5hBOh9R;
       spf=pass (google.com: domain of 3jrcrxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JRCrXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 20si2561lfd.10.2020.11.10.14.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jrcrxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a130so1670505wmf.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f7c7:: with SMTP id
 a7mr7030672wrq.347.1605046309488; Tue, 10 Nov 2020 14:11:49 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:15 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <8b8345f75fa75638328d684b826b1118e2649e30.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 18/44] kasan, arm64: rename kasan_init_tags and mark as __init
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
 header.i=@google.com header.s=20161025 header.b=i5hBOh9R;       spf=pass
 (google.com: domain of 3jrcrxwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JRCrXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

Rename kasan_init_tags() to kasan_init_sw_tags() as the upcoming hardware
tag-based KASAN mode will have its own initialization routine.
Also similarly to kasan_init() mark kasan_init_tags() as __init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I99aa2f7115d38a34ed85b329dadab6c7d6952416
---
 arch/arm64/kernel/setup.c  | 2 +-
 arch/arm64/mm/kasan_init.c | 2 +-
 include/linux/kasan.h      | 4 ++--
 mm/kasan/sw_tags.c         | 2 +-
 4 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 133257ffd859..bb79b09f73c8 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -358,7 +358,7 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	smp_build_mpidr_hash();
 
 	/* Init percpu seeds for random tags after cpus are set up. */
-	kasan_init_tags();
+	kasan_init_sw_tags();
 
 #ifdef CONFIG_ARM64_SW_TTBR0_PAN
 	/*
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index e35ce04beed1..d8e66c78440e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -283,7 +283,7 @@ void __init kasan_init(void)
 	kasan_init_shadow();
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
-	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
 #endif
 }
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 979d598e1c30..1d6ec3325163 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -191,7 +191,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-void kasan_init_tags(void);
+void __init kasan_init_sw_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
@@ -200,7 +200,7 @@ bool kasan_report(unsigned long addr, size_t size,
 
 #else /* CONFIG_KASAN_SW_TAGS */
 
-static inline void kasan_init_tags(void) { }
+static inline void kasan_init_sw_tags(void) { }
 
 static inline void *kasan_reset_tag(const void *addr)
 {
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index d25f8641b7cd..b09a2c06abad 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -35,7 +35,7 @@
 
 static DEFINE_PER_CPU(u32, prng_state);
 
-void kasan_init_tags(void)
+void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8b8345f75fa75638328d684b826b1118e2649e30.1605046192.git.andreyknvl%40google.com.
