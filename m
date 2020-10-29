Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH5P5T6AKGQEZIRXPZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3E4529F50F
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:27 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id e29sf664330lfb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999647; cv=pass;
        d=google.com; s=arc-20160816;
        b=cDvKOUP2EwncGTxMq+P2IY1HXo1zNFzyf9XCG0Wz2SZvIkK+1blO0i0F31RY9+2ysq
         pcSv1bBU6WhE6AGgIO41VkiI8HaiOcm7Cn3MBRdmYPVp0g7ywEC+s5zPn4nbvSH5qQSV
         eoCsAX8hmYdy0rjzKpwBCmf1wI6rSXNBn/LzmyudSu5IYM7xe/Rp2YqvVZxgRgQDcxYc
         7kfraThsQQhbAY1sHwhEz+eU5LMj5nWQxRV02R/hcTme2uLCO9+2L02UCwiv9VIEMHXE
         V4BqVZGvA8PkKL39NFaOArYFxJSyyDZ7b/4uO4Hsu2nju06vmIKsmdmw/n8w+KgJuD8f
         Q9wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=b9Mu0zgBUP6uQn9FYsdr0qQlbjNe5mAtk+Ypg7pDYVw=;
        b=qptamWPvZgcekb9Bsijko2gT1JVR+MkvE7yUUqtrq7ErO1a9MDsFF/nNwzrxEQTF4p
         BitavUha6cyUtlQCad6mHCwMk10jIR/G3ThvaDaNaHEOysM8/VD+Z6Nnz6G1YiBcze5P
         MtyDMCry72doWr1FcTOjKm/vjYCUNQKuB/9x41O8IradUeJqE255AHA2XXefCotTwmEb
         yGT5XDwj2x7VCFZqezGBgbO3p517IY3yNrmOBkoYDX6wKZDCfZ6FoxKRiR7rBZ/Mr19u
         PVObB22Iku6bZ81Ss7jw/hWOqBM+UNbz85MMVYCQdxOt6suU0Me5AzCgFBhSo+wUBs/f
         MV7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qQoHRGYT;
       spf=pass (google.com: domain of 3nrebxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nRebXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b9Mu0zgBUP6uQn9FYsdr0qQlbjNe5mAtk+Ypg7pDYVw=;
        b=T3l/lI3OBONqoRnd78R8Ooc5pflNgZ60VsENWH/g0GK51BhNezjFDg/eyPGhqefXPm
         IC7RdzNmNpWFwLN3MvpOxnxwnrH2k+bJxmipfA9eq89ojd8yZhhXeQoDb+eJYFNtZsZe
         Lxona97205ukWZN0CsIYBXsPewRR91vckKixEU+k3QGyCDrToq4brNKLEv6Ti7/vfnd1
         w/w39Ql7zwYaztvv463EBgwTREOk26EGLYBP8CMsWchk5FbohekYJ4fUs3Mw+FchUbjL
         fqyGCpVdrogimUSXIUlNCyk1ARQAFZmsmEsgmArasCafKPJanMKTnbGnFcidUZLVM0eo
         Wrqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b9Mu0zgBUP6uQn9FYsdr0qQlbjNe5mAtk+Ypg7pDYVw=;
        b=YwPQ8awI0Kz+r5Tt/bxssa+pW21unUWT3ywwOKNsGk4Q00N4E1T0VuGINW0+VEqRXI
         5/WJ3U3ySNv1l9reTodlvkr0UgXhagbux9jXUGtnQAKX/hWQ75RM0yIRYkS1ewgHeCYV
         iZ/e5L1GKZqrWl4LeYPCVhdTkEPidZ8Kgp6wekXGE2UVGY9/u143+LZvZLHF/lY52kGR
         fI0FuROa5oclLzZ8aJaTiNcKYu5qaaV41ys2etcy/aI8k4mFUKzzgklgTMopRg1RCTTB
         JIqlLPyrcemZeMBWHapgqsUSuV0Y1k/0A4Q4dhSr1931lo0zkGir5oRctOfsKQhDxQFd
         2FJQ==
X-Gm-Message-State: AOAM531BtcKN0KnZTDrgq4ZPxs6on1C32Rguhbnqdu0/XAyyHQKWth31
	jSBDHt5UKpHhYoyiSYwnISw=
X-Google-Smtp-Source: ABdhPJwQAolpMW5UTRZ+LAN/PD2ep5ldtXtSztX6cMtO68C/G+GuuqaER0DydhYGD/SQuFCwcdLTpA==
X-Received: by 2002:a05:6512:3b6:: with SMTP id v22mr2068041lfp.536.1603999647300;
        Thu, 29 Oct 2020 12:27:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f48:: with SMTP id v8ls749503ljk.9.gmail; Thu, 29 Oct
 2020 12:27:26 -0700 (PDT)
X-Received: by 2002:a2e:6816:: with SMTP id c22mr2754367lja.200.1603999646114;
        Thu, 29 Oct 2020 12:27:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999646; cv=none;
        d=google.com; s=arc-20160816;
        b=YfzN3AdHe+RbiYALxzqQiWYkOP00++SOrZqC7/CdVBWIlto9U5YbWy/L0qW/PC0VhN
         nsWE86HoWVK8ensryPfrJdJTN0V/hoEJRz/NulSru5K4XT7zKlxoSphYcEAZdM7lPUNi
         BR6hA7AZZWV9oOR1RmC/anJsi5vLxGgUCyXIx6BYDlhD0S3dmeOuvLD6P2C6rlAmPKbQ
         qZoQY6vowNElRWnOJA14f+tGxIPUhbvGT/P4RKV9dzmkJB2ACJvsUkr7LFdEvNJe9Rkr
         uD/MqLEGHEBsBjM0IHjN6ebTMBZFfOD/kAU3Zo6g0+bQ+jVHLQ+/PjJET2w5GdluSrfk
         BjQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mhlSkARMRob3d2hNT3T2VG0Irjtu7J9HetujXqVGCGY=;
        b=B94cQoHZ9M7rL6sFBd6ddBk7eO/vRJICeytiCGhxrDLSIVu4moSIIQEKmQ2Ifo/BtA
         5iMMAc6lRy4Sq8/fpjMfQvO4UJ4/Z5aQ+2AP17Cw24TURZO+eTIFc4en7dAsG2TpIPv+
         GKh2puKyZvPlJipqsVB1NhMJVgRIDXYJvSjpuxT2W9Zvd4sfu5glKSxk9yQnUFSSWzV6
         XDrhudHNCTVwswfa8SsA5CiREyauuRSDBbhhnh/zJAQv0B9HSIgbejU3cfqiCx9zWkbk
         SzCgfBOZMK4m5AjpPHE7t4664rAlRvvANj30Ws4OqDiQni+yYb3c8u57a+fP1WtZY5Jh
         TduA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qQoHRGYT;
       spf=pass (google.com: domain of 3nrebxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nRebXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w28si116047lfq.3.2020.10.29.12.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nrebxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j15so1679104wrd.16
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:26 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:5a06:: with SMTP id
 o6mr749019wmb.181.1603999645776; Thu, 29 Oct 2020 12:27:25 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:53 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <1baff3a8f85c510057fb58e9628d670c224df8ff.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 32/40] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=qQoHRGYT;       spf=pass
 (google.com: domain of 3nrebxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nRebXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0c1cb0737418..a4554b19022d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1baff3a8f85c510057fb58e9628d670c224df8ff.1603999489.git.andreyknvl%40google.com.
