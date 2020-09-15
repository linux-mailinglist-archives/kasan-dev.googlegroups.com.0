Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3W6QT5QKGQE7V4IWHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7126026AF68
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:34 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id t8sf122587wmj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204654; cv=pass;
        d=google.com; s=arc-20160816;
        b=qtldh/PobmDt/FHIQJ3SHnksbiojrKUpoENqsmKppOVK5YQuvHj5VqWnyu7TaVqVBe
         QLGvabYSS6TDe6mpvbJIg2iLmJ1El8YHRK0uqyuWGMdjIhO2jH91fm493WWCu1/WQ6OS
         h2d1eW0PB+9jc7HqV7+NG6Is4cSfCVkZxCt8z5SHsQeHe/PGKUTAsnP7QBiMCHFitF45
         MkS3KnoUZjHi6EZJeiM8PPdR05BM2TtNJRCAOOtEH9KzldpYt80TnEnWfC4t4IRHzcET
         DBZyaug0NNnWj2BJwC0WcOYqHUoX95sTm530FNVFMxZ7Niz6M6mKWiZJlZZubX8UOaS0
         6jlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OvXk3sZz5p6yqcfuz8xlCY38rPvJWIhDBiQu1VJYE3M=;
        b=Z8NiSPrKjpEeJ4t7/w2VznTlDNkd25c9jYkrf+1RwIRoZxQdcbZyddwY2o9cdmDYbR
         1opLc7NM213q4FWIBCtZX0g0dMqWJPnI+1z92as20cbqwYAEpWnvNysotfwLVLgChK4S
         cfQn6yPkOEXENHmeyUiKnH4uBxxiycEK8i+nFCrlsx9w0e1mYAM6tZLbwKWftPFXcFP2
         viJPtwtPq3NK1Izo7urEnKe45gzPFILW8jI4n0sDmzQcL+PzaqfEJXNMUCmhX6hQB9R3
         /BvkIcHp2lQG9AFaTbvmz1Yx0mU2/uj26NOZ1cKbhpC6VuWY2wV2UDWFaZVWxJoNj27S
         4tLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ejaRrNgw;
       spf=pass (google.com: domain of 3bs9hxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3bS9hXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OvXk3sZz5p6yqcfuz8xlCY38rPvJWIhDBiQu1VJYE3M=;
        b=IoJujmLZqHmzc29bSeVbg1thLg8ECLgQtyj5bad8VtDIPS58hLNDbCk1tipc6NrE1N
         ew6rjK/J9lSU00f0czEwsgrC68JXLA7eTbyA74kNMeM6nC34IWXpq0vfqRxLz4sf1zOS
         fvcAvwE0vjsTTubRgl5FlVfrwt2DgO+S5bkpfiM/fXR2E9A1YG55KSuiGYEvyZKkfXYB
         BQRBTPpVrcMjO7/8TFQhNmWJ/3G+PdN0s2BXrT0rVSRppibyp6lvN/6OJDUX8IEM3OXV
         dVBWEzP4FT/VpiPbADr6cxsjCFxCOG70CY31clBrqlO+y37F04ulboQ0plvmufoA/84R
         sdvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OvXk3sZz5p6yqcfuz8xlCY38rPvJWIhDBiQu1VJYE3M=;
        b=h5sRAdX2CSEF8X/9O06A4B7AlklgjJk9GZeue4euNCASuJZFzJOBoFNLQVb1za0VmB
         hIDndJzdKNG0PHaVO2cTcykU1aiDQJ+7yrC51Fw8Cu/b6MTYMwMqH0AU4SJFqbB7IOun
         dhhOjPqZmT1pjBpPNBXdXVEDItIpKyYYGuJiKMKjlMKaBYCZttJEgyxgZ+/3clOHzvqg
         WVqhiV4LazQgfhNL5M+3fRVyXuZivDYVLe4Va4jinAxfhVM6tWiBbUeo66EFgfRfJlJW
         A9ID/W5VrMDq8tPdsOVhYM0tqqHlDNYTcYqE3OdTYToGFLTLgne/vDIUtwCxislYzwRq
         0edw==
X-Gm-Message-State: AOAM533O7xO02p4RqdEubREaWoITiKsySW5cOUQccxf1GSngT44+Klhw
	NBZmaV4XzAYwpyzMRHdteEo=
X-Google-Smtp-Source: ABdhPJx/1JRtA/AWqrRcOhOxi3vAPewthW4uvJ3ufohonP6El8aRh8XQ2Z9xRLmj72qudXaPNINgUQ==
X-Received: by 2002:a5d:4081:: with SMTP id o1mr24054030wrp.338.1600204654211;
        Tue, 15 Sep 2020 14:17:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls352243wrm.1.gmail; Tue, 15 Sep
 2020 14:17:33 -0700 (PDT)
X-Received: by 2002:adf:ec92:: with SMTP id z18mr25032652wrn.53.1600204653539;
        Tue, 15 Sep 2020 14:17:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204653; cv=none;
        d=google.com; s=arc-20160816;
        b=gukqs7+FlgRRpt8uT8bZlKMjq+g0fnX07ByJqXiZ2ya3EfiYRint+j20ERM/zOi1AM
         p/JpWrUITWMDXMps18oKcaJ8k7b1JMcWJRZwHKFO/u1uRNwyN8Trnup832at5vRVwLKv
         STKONsI72Y7zRzqF2Kd621IFgBarVvd6rojDASRDZQKynnU8mu+L6QuPVAIrssGndJE/
         sU5F+KjDaAVTTobetJlnrWM19EJmMO5ITQDtEsI9rXkbTuZ7sfTQLtfWbjtdlmmecoZa
         hXt32ZpdhgOIgJIDjr8sK45WaC528TMWv7eW/JfcUHX3DTbjP9B6N75ToE7nbgW2TXa0
         Hf4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TX70ilGdAcdyg1YBqmaSz5QEacCDiTB+zVlfonsPQRU=;
        b=A2Qre3GbV5nZh3cjQQ7uK8ZG/kHUbpyMs+4a6mAo+ENZhLGC4DnQgPRGx4YRDjWVKj
         WcZJzs9vXt48A+/xComGpnS3v7urJSuAkkTCGEwLTO0h1/SuK4+aNc0T4lcE6hsX2O5C
         eurZe0psPVj/vrBjTiCa0M62gB0CbXibIbs++UI7qhuk75ZrYv1+GUTYz2WLJWkQC0iG
         WPHAqPb+eGAUbXTM1yC6fqtKsc2TEztDcGAXT1LTEJP6gXlbe3yVG9AGXCb0Cv+PmySb
         Ch6XmvR0V6qpy0eF290jgRrgV0q/77PP5tJApS43sCtbInKeS+3PISM27sRuVeeTyB6A
         sXPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ejaRrNgw;
       spf=pass (google.com: domain of 3bs9hxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3bS9hXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id g5si49816wmi.3.2020.09.15.14.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bs9hxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id li24so1839280ejb.6
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:33 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:4902:: with SMTP id
 b2mr21685991ejq.208.1600204653213; Tue, 15 Sep 2020 14:17:33 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:11 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <0845668a82ddd3eeb3f652712597ffd056f97504.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 29/37] arm64: kasan: Align allocations for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=ejaRrNgw;       spf=pass
 (google.com: domain of 3bs9hxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3bS9hXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN uses the memory tagging approach, which requires
all allocations to be aligned to the memory granule size. Align the
allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
CONFIG_KASAN_HW_TAGS is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I51ebd3f9645e6330e5a92973bf7c86b62d632c2b
---
 arch/arm64/include/asm/cache.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index a4d1b5f771f6..acf6a5097cce 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-helpers.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -50,6 +51,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0845668a82ddd3eeb3f652712597ffd056f97504.1600204505.git.andreyknvl%40google.com.
