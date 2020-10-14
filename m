Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTWGTX6AKGQE54IUKPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id F324B28E7FF
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:45:02 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id u18sf220753ljj.14
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:45:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708302; cv=pass;
        d=google.com; s=arc-20160816;
        b=NAMQ/kKRWGBFtN/olEO2JZiUeyMxdDWEIvV3RhgJ6qIfVh/1ioMAA+0X/Bj1Cp5oCG
         SDISffkOFHx2RTnRZgGsxquSIAcccca26xmwlm/UQIhAAODSXLfHRlnEuxLrETQ1hAcR
         DDbiuUVopy8/MWnH1bDaX8s5H6X7i5mVO9CZKEuADR0p+S9z510M6AxDUtbQTyBi8XpW
         bVH9l5erMJ5vtxAQg2CY6A4iSPfHWs75+dsIivkl+398/gALWxZwUEnWy2p7WxCOXZCr
         mFp+R/8nesLzCP+agDk09QY42ydFHzFqsqNcOA80fcQIZD6YrKG1H3+PjnDzM8jfl3ug
         Ci4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GioMeWHrOcKp9nnXEfAkREWXAMbYsjiFWABKFCytldQ=;
        b=pkWUP9kNBGPVLwz6uFIoOPPWpABWT8UMEr541LBXcuyBMrqcsm6wk2uSGZh65C0jLH
         mHcAhnplqvCdqQwFL9hPeGZOqtffNOd719CfYXZRrUM8Oz6wJUwUIY3i2SOHdozs4lPz
         VeZYLqOasHWDOYwLdb2DA3LP68lcG0IxmP/NVMz7fyksxBbOr72z2BYPWGZN0vdHEOqR
         M2wiie0Y7/rpYz94B9XV1nqe9sAaRXSaFKkDZJKK06thFEY6X6X7B6/53dK1YFQPseKX
         sb98Uf8KIRAJMFeQR2zJKRjxc6hD1N+bn8HUFCutigTVyZY4nK8mqbocE4xZng/RKjC+
         nKLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XvQbYOsI;
       spf=pass (google.com: domain of 3tgohxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TGOHXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GioMeWHrOcKp9nnXEfAkREWXAMbYsjiFWABKFCytldQ=;
        b=q2PwPOnu3z3zA6Lld/TF1E6MTahmA80jkAlwlJirH3xrRMhzTXiEpnqX1acBRbEKQh
         lnVREsyfO2KLiFu6GdjBZuO7FFydegubGi5UowGNcS4V33tBWkTZkU1AHvjJK9LKkbpQ
         vzRDywyjwfwCKoS1P3zFrHhtDGM7IihjlzMYz0YlQfdkFX5+Utzq781UpXNcBemDihoe
         lziS3KNOiFsO9SWKzztQv5G5IOnX6nJQlIvCky+BGhaqsx0pd/xkDwzENuj1UXe94zMG
         dX48+7dBbqzK150NGFPIOIfxmXq2EphgWhagOnB65rUP7F4Nu4kkRrGCP2dK+aCQxznw
         gSgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GioMeWHrOcKp9nnXEfAkREWXAMbYsjiFWABKFCytldQ=;
        b=BeOY9xDJBzh0NI7RMTmjc2S/PJ0uyPzLVeqaISMmOxe8FZB7X33oAdFgn78a0ndOLQ
         QBOY6O7gP0bf+YaUrimbhfVHqQnbrBbtFCV5PfIqIvzYqbVmkuWdqjYVO7w1uQAN9Gvy
         vRXx7XcUK8NttjFYVvqJbTcPVZ0Zg7htBmRlqghFcBb9cWDTYIRP+qhXEPRcwF5cOVxJ
         Ee0W8fLRB7YUn+sE72Agm0UL3niz62mQRkf0VuniNqOnG8nDk0TfiLWGONzMRT/mIyHC
         xbPBIok/wb0hartvlY7WzsTBy40grdjSb266BeewIDlm7NtPeec7oepIzVJ0odaxIsgw
         4bug==
X-Gm-Message-State: AOAM530wQw0lVJumkS2fVlAPk/Y4Nr0RvoVRO6opNqc/iLlj3UhDvjvW
	FJCiWFTmuDh3wxu8HH3JE9E=
X-Google-Smtp-Source: ABdhPJzi43c4DlgTb5uPfZcUwaNVJvVrHZFLh1EswGjzbY/alW12g2w1A8ui9oOhZ6pUPtjXiOa9RQ==
X-Received: by 2002:a2e:99ca:: with SMTP id l10mr301ljj.218.1602708302497;
        Wed, 14 Oct 2020 13:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls146103ljn.9.gmail; Wed, 14 Oct
 2020 13:45:01 -0700 (PDT)
X-Received: by 2002:a2e:7815:: with SMTP id t21mr153457ljc.217.1602708301448;
        Wed, 14 Oct 2020 13:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708301; cv=none;
        d=google.com; s=arc-20160816;
        b=BXhpcPkzY8bklk/d3uWhXJkQL8FaRWjJjFyXpsDL4BBy6kYvt8VNtRb9PlPPpI39K9
         86kHkKzje7HKuHmt9ElX6jjhBdrcKh0A0hY82GTRBy9U5325cFvmxiVs0nf9Tu6ynbjW
         kVkGeucntokNobasUAb/pSpbNCxofMaZR/E5wAUiHggwg6xI2GMeMgo8Ia+G9UGKdKYI
         Kc01qku8dtP4g2UtqKTsjykvjdhZUG68bhf997hFZ8odx7/ulzSxaO+U8tAwOL1Eb444
         6oez4leDyQrjqTMopOSDH9EPLQTu51zj1558zxbYwqNsr5w5F30hWDX/Q2v3sxGfwfQH
         eKew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=y/nVmKw0+obzUSPYrpDLElf69GpBMgys1Kxk8lAQxBs=;
        b=b+igAVuNZtJkfFAxiU56ze1QBBXos33Sr2jRP0AGEQ6rFgbcbHD/9z7aLwihMdpc9A
         iOnF4PYfnUIokM/3gUK+3dYh/Tbw1FrdAUpPrh+Mv0RXOULnENtzUZ2q0r9nCmvZfegQ
         uDFiJI26zRbs2ZmCTtt1cH5QNgSNl/5IYjs+tVIAtQq2rSmdGyWvgJ8pEEIF+MO1pBFC
         VNaPryqSOAuWAzO7Pb3WeYjT4uIZ8UQNqBYaEoUDuDgZXwf0vMrBcYh2XeAjaMqvQGmk
         Nzj4H+16j5TB0RfoP4FVJv1VN7zHEi+XuMCLY4j5qvitRVlm7j1dcLlNOFAT1mUfLW1Z
         hZng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XvQbYOsI;
       spf=pass (google.com: domain of 3tgohxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TGOHXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id d18si10335lfb.9.2020.10.14.13.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tgohxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m14so413396wmi.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:45:01 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c181:: with SMTP id
 y1mr616036wmi.58.1602708300850; Wed, 14 Oct 2020 13:45:00 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:35 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <001de82050c77c5b49aab8ce2adcc7ed7d93e7ad.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 7/8] arm64: kasan: Add system_supports_tags helper
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XvQbYOsI;       spf=pass
 (google.com: domain of 3tgohxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TGOHXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

Add a helper that exposes information about whether the system supports
memory tagging to be called in generic code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ib4b56a42c57c6293df29a0cdfee334c3ca7bdab4
---
 arch/arm64/include/asm/memory.h | 1 +
 mm/kasan/kasan.h                | 4 ++++
 2 files changed, 5 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index b5d6b824c21c..6d2b7c54780e 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -232,6 +232,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
+#define arch_system_supports_tags()		system_supports_mte()
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e5b8367a07f2..47d6074c7958 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -257,6 +257,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_system_supports_tags
+#define arch_system_supports_tags() (false)
+#endif
 #ifndef arch_init_tags
 #define arch_init_tags(max_tag)
 #endif
@@ -270,6 +273,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
+#define system_supports_tags()			arch_system_supports_tags()
 #define init_tags(max_tag)			arch_init_tags(max_tag)
 #define get_random_tag()			arch_get_random_tag()
 #define get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/001de82050c77c5b49aab8ce2adcc7ed7d93e7ad.1602708025.git.andreyknvl%40google.com.
