Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7ENY36AKGQEIYOM73Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C56E295FB6
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:58 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id u4sf864993pgg.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372797; cv=pass;
        d=google.com; s=arc-20160816;
        b=BEm6VGH/IOn8DaJl8zO4Wp6549v3fz2LPKrwy30bNdGpB0GSSLxiOQwbHvja8HKASB
         isI0AoVhJlz4uyo/IA/0xvRYteR3YPlTuLRLmDI+TEHXkxLuo3QOOUZLjUX+XNx6kA/9
         oEYfR3g+RcF2gHJhi7DwvrVYwtPXkPXLXLshVnxf2cvN85gocbc93IJ38PAt/jNY8UiY
         P4cI6hnVhpNYvKyuIhkDjJDKX5vjJwFNEDyHIUGWA5luoxS9BusMABvOdtHSFSydzkLe
         tVhK6wsTjPEv1zXet/PCVnesJna/76JGrAPArCymupbV8RomqdALOI3rkUj1JtBKGJSp
         dhzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=y0Z0kZQCJ2VJUXBNZa6XOiJS+qCAR7gEdaOQWooPfgM=;
        b=ThzXNRwLsbAE5haZXQE1LMxGStOPay0NTxBd5zCDIGq0vd4UyUQ34KVqCqaWUIGwtO
         MTrF4xSptAUMaxuISxbzshHnEvdQLrFs6tvo04LAnT+JUfyMbw0Gm3OlEQMKhFZEgg9q
         YX6nycrG142k39UwW2KJvOqmv8DJj1lZcUXiS0oxilTC/evokoe+56L6m4XKP4B4nymL
         re4Cgv0iq4kagZ439Ty4DlaZafOHlYYTDCgiodVzuRnkqhW1U550bdE3ll+oGTysHJYm
         KnM+NzjdolidiZv68iDwPglgZZQd7y3YoE7y+bd4TlmBihkh4xu0dzqtK2d+mFBgxJlx
         XZIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hyg/yHWH";
       spf=pass (google.com: domain of 3-4arxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-4aRXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y0Z0kZQCJ2VJUXBNZa6XOiJS+qCAR7gEdaOQWooPfgM=;
        b=FSK5cE7CVzFASbdpabIB86/5kZukB8nvVE4Exv7KZT9n2jNvIp+LH9ooqNe3kwPNbM
         RI6qEGaxlhsCt/J7tIq3bGG/KaKp8A9/zdgKNHkA7OuJCMZiF+eHhH0SW8Z489/SfcFT
         VykmZg3Oulg7YSpZGqwtvizbsofMVueWZHr9JwiE6foxD5e6JEvrzzlt22UBSJhYxu9D
         BE/G7q+zVXkQdfpVxObx78nf7qtkBypHOTKWyiuNoxC6euTLlzkvl7qtJlKqMHC47Afz
         Zp8sOo8NIPFuQL5CZIXnedPeRAuXslg105/C+B431Pq8l9pNnqc9QTxv7QbItRG65T+E
         JxBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y0Z0kZQCJ2VJUXBNZa6XOiJS+qCAR7gEdaOQWooPfgM=;
        b=HpCOIhEC5FfmNjQGbXBN6dqx5SyqnIGYbXXhp1xexZRksU+tiBQ0zzEy28TrdW61JF
         JisLhbIGR3U9t14S+T/q+P7pebLwy//ARdbI/m8S9jJy9+odDWTDT2eR4SlPvKOQ+lsJ
         1juLlj/gMkdpeC9nLmR6IrKyHcqg+Qstn6XCQViVTpovQIakHVd9qgpmuLL2Ei0GNPM+
         XFOjoSACHL3z9/rA6YD9qCea0sbhU3DsypLqi2npm3wDUcyNxHZrylLnapmchAQowAXE
         PPvugxFTVTmDsXKRp/Fs/5eRpWNcvIizpsjqo/DVu4hUGvTc9DmpS/zZp+0m8mlVssR2
         ryZA==
X-Gm-Message-State: AOAM530uzHxB2+KH/4yKhbkLY0PRqoq3KupvjamqwI2J7YQs4UG69pbl
	4gddX/wcmXjju3lKcgpCIW4=
X-Google-Smtp-Source: ABdhPJzX/xdocpe+8h2UCtDOGM4YjYlIW1ssTbIMhCutrUR6RdF4wc/zHTrTUGJ47fVXELl12tkaLA==
X-Received: by 2002:a62:53c1:0:b029:156:438e:2d6c with SMTP id h184-20020a6253c10000b0290156438e2d6cmr2543934pfb.37.1603372797123;
        Thu, 22 Oct 2020 06:19:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:483:: with SMTP id 125ls749253pfe.6.gmail; Thu, 22 Oct
 2020 06:19:56 -0700 (PDT)
X-Received: by 2002:a05:6a00:1504:b029:15d:4a76:5633 with SMTP id q4-20020a056a001504b029015d4a765633mr2663723pfu.17.1603372796548;
        Thu, 22 Oct 2020 06:19:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372796; cv=none;
        d=google.com; s=arc-20160816;
        b=jYJrsJn7earPg5Cl6saqUxULKUqZtfVyqnZEr43fLBsR3dzac5YWlhfXiopdX4viD1
         zLAVldC08YrT8HDBKPumbUjESYBllGLn2JT+FcM2WKdyaJXK23D9EGM3UCSuBG++0O9t
         ZadmX8FKE90z1arSHUu0suftLTK4rYqF6kMcd10ymzLRwsAe0v8JYyFQ3paltkKAfJpo
         Wu+EYi+A/2brNuD7xyvTCsNIVl/6PjRNCDVcckO4KbVVrDo5qiUAo+9pxZNigTS5ZJr9
         VxqSyfoh0/l1qiM5Fr8XX75xep3xkgujasOHC9CzSrWwuEduImVSlZeH0Maa0KrMX940
         IvBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZoFNxYTX2w5xrKhT+4kOLYASUdfUPOoAnADKxtZ91BU=;
        b=BEJ33ALy0xkS2/f3WTOWtbrbxeLcjEwduiTfgQOBCzePT3wPE8/QmVKzZRdikYfvxb
         c00XinRy2cnh00RJ9xZGr28n3RjhuiyHt+VMy7L55RrBBRkaSavTKi3qBn3JzuP/20gt
         hWpW8rB9yTwbgdf1jaKdGjjhjTYfPBsb5NA0YplAmBh5mP0TuhMFKcWlZ6UGohOltmFe
         +pYCd1LOO8QeE9RfpcKfUAFFYS19mMQSr2hGXkJ2f4fzf8rGdyWd5tZwAZNVXi4pnku+
         30nM9RQ44eJeYVTnstNRyH1IpEzsXTLMUIXUv9cPMGG4Kp+GO1LZjYY1T0Y78YLQflrs
         +vTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hyg/yHWH";
       spf=pass (google.com: domain of 3-4arxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-4aRXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id h24si115625plr.0.2020.10.22.06.19.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-4arxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id j20so462494qkl.7
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:56 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1267:: with SMTP id
 r7mr2283039qvv.50.1603372795643; Thu, 22 Oct 2020 06:19:55 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:05 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <ae2caac58051ea4182c0278a1c1e4a945c3a1529.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 13/21] arm64: kasan: Add cpu_supports_tags helper
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="hyg/yHWH";       spf=pass
 (google.com: domain of 3-4arxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-4aRXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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

Add an arm64 helper called cpu_supports_mte() that exposes information
about whether the CPU supports memory tagging and that can be called
during early boot (unlike system_supports_mte()).

Use that helper to implement a generic cpu_supports_tags() helper, that
will be used by hardware tag-based KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ib4b56a42c57c6293df29a0cdfee334c3ca7bdab4
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  6 ++++++
 arch/arm64/kernel/mte.c            | 20 ++++++++++++++++++++
 mm/kasan/kasan.h                   |  4 ++++
 4 files changed, 31 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index b5d6b824c21c..f496abfcf7f5 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -232,6 +232,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
+#define arch_cpu_supports_tags()		cpu_supports_mte()
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index a4c61b926d4a..4c3f2c6b4fe6 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -9,6 +9,7 @@
 
 #ifndef __ASSEMBLY__
 
+#include <linux/init.h>
 #include <linux/types.h>
 
 /*
@@ -30,6 +31,7 @@ u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
 void mte_init_tags(u64 max_tag);
+bool __init cpu_supports_mte(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -54,6 +56,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 static inline void mte_init_tags(u64 max_tag)
 {
 }
+static inline bool cpu_supports_mte(void)
+{
+	return false;
+}
 
 #endif /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index ca8206b7f9a6..8fcd17408515 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -134,6 +134,26 @@ void mte_init_tags(u64 max_tag)
 	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
 }
 
+/*
+ * This function can be used during early boot to determine whether the CPU
+ * supports MTE. The alternative that must be used after boot is completed is
+ * system_supports_mte(), but it only works after the cpufeature framework
+ * learns about MTE.
+ */
+bool __init cpu_supports_mte(void)
+{
+	u64 pfr1;
+	u32 val;
+
+	if (!IS_ENABLED(CONFIG_ARM64_MTE))
+		return false;
+
+	pfr1 = read_cpuid(ID_AA64PFR1_EL1);
+	val = cpuid_feature_extract_unsigned_field(pfr1, ID_AA64PFR1_MTE_SHIFT);
+
+	return val >= ID_AA64PFR1_MTE;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index da08b2533d73..f7ae0c23f023 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -240,6 +240,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define set_tag(addr, tag)	((void *)arch_kasan_set_tag((addr), (tag)))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_cpu_supports_tags
+#define arch_cpu_supports_tags() (false)
+#endif
 #ifndef arch_init_tags
 #define arch_init_tags(max_tag)
 #endif
@@ -253,6 +256,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
+#define cpu_supports_tags()			arch_cpu_supports_tags()
 #define init_tags(max_tag)			arch_init_tags(max_tag)
 #define get_random_tag()			arch_get_random_tag()
 #define get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae2caac58051ea4182c0278a1c1e4a945c3a1529.1603372719.git.andreyknvl%40google.com.
