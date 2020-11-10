Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJFAVT6QKGQESKWXO3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0823F2AE2C2
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:49 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id 2sf31216ejv.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046308; cv=pass;
        d=google.com; s=arc-20160816;
        b=M0XbCAdjd4dT0kiEnu87rplVre2ykwnxFtk7L1l84Wf0hYxcw/sYCCgluVjW0vGQcs
         9xG6FgoVCbN+VXqcQPjv9duIeJQDubnsBOnYm//ITcb3k1KGYvvzpzqZvUBDAg7hq1Uy
         Mb/fZjxumAcLU5i1qPIDhb4YMc3jkxtdkSOzooQuMsTVpng8BMjNcvKOX9zF0KKLH+8r
         nCXvOObYdJ4jpWkHr4k9vxKz46q7ZUrbPZufVyIya71VmaVOxt7FqMS+sA7WXNzZ38AK
         T3YSjIrzWNvE7z193SZsKr/JWwDsCm50dOsiimjBbTcsJ4mo24s8u/2074np1pVtnbb0
         UiWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zXWcyNohbxa3L2Mba7YkfREazZgmGJZohm1YabuOcJk=;
        b=tE88BfaRa1Ii/ekk3bnh/OUjXkD+3p5SkgjMAJCaNbnZH3trzGFgyXoerolUxfIKHo
         Kz/P53gkKkYz2wht5Ry/CB0QM0xgDUAaKsnm+FAPce9C1+XKVy7yGHOANreMuTeXEZf2
         arEqnLta15qMZtiv6CgQfn+9UJkz1bfE1czWIy9VFYc0xUCiJdKYSgEH8zUGdhiu4eFs
         CJJsN8c6C7ZvnarxWVVRbpnzGmmva/jC/CfPyKYctB1Ht0icaltBC+XfyzVOHRV20j3q
         WKK/R+nOkcvVX3i2nQRsGdUri6UF+x5feWkGSIkKbwV93mHTSDNXRoHSm2iu9fwtD46b
         ye1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IQSSQ/5E";
       spf=pass (google.com: domain of 3ixcrxwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IxCrXwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zXWcyNohbxa3L2Mba7YkfREazZgmGJZohm1YabuOcJk=;
        b=fw67lKOm/rA8p60AwUn0SW7n4KKIDdK5UUCLXae6E/yDpma/JfFpy7V2tRCSErwJCW
         0lFa1d9f0KmEEVaIJ8ml6/yEsS5nuTcPysySl0zXu0Wbh0Kw6IPB1F+4Aq5X0Zkpx6mj
         YAw7nw2qp02lOvhLPeumA2e9eONg5eSu6ziCVbgo71QNDRX5GfgyweMfu/An8/o4XFwC
         FJaavPNRmHFLRJndCyQKyCbt2mdv+SX8DVjipbjKPixd5mtg8XyEKBfmASD+miM1oao6
         PC9yUdaAhdVGIiHvrkDaXydV0rP2jIRXPI/vpWxT1q5ENfrqVrEwJWHqDR1qrTyBm9in
         7+IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zXWcyNohbxa3L2Mba7YkfREazZgmGJZohm1YabuOcJk=;
        b=h1iH/AIFEk5aCWQ8vpjwQZGyJ4YWW06OcHDJs9RhEfI9IDlTip+W0NbBrikaNvvXyG
         MFKjvAfJhQDP3x7lVelAQJaBgcWDjxw/qCzbxJg1dmgyJDhNn/pChQJRl+ukZXTUTCSD
         vSM20Nfs6/3S6MfKkNqDMinhrA7HAsPsiJzF4DW7/l8qbtidlawL5DZWs/V6YQvxfihL
         zVzA9BHdCBuF+5L/PPlO46uZnWsS5ULjD+qJ/lLkTEdk2QzWQofH8hptkMEnXJAo7vz6
         gg3h4ByYIj2YpUL7fhuIDvSS/HOYmMAyeSOERTCUeaENrVNnypBrD+9cRXRwawPTGq5X
         45Lg==
X-Gm-Message-State: AOAM530J7Ox7UDAbXgYYNIe7pccA6sbaDzTE/Kz6joLwrnAaVZlUln2h
	KyTKiBBmEQqQTAtnb0B4OmY=
X-Google-Smtp-Source: ABdhPJxj2jrj0ONWrcSIs7B0zWCwCny72qYEf5IunajGHQIFJE6JeiOiDBONVAhB2iuVu8VBB/wVbA==
X-Received: by 2002:a17:906:bc46:: with SMTP id s6mr21864776ejv.456.1605046308753;
        Tue, 10 Nov 2020 14:11:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:245b:: with SMTP id a27ls6862008ejb.8.gmail; Tue, 10
 Nov 2020 14:11:47 -0800 (PST)
X-Received: by 2002:a17:906:3bcf:: with SMTP id v15mr22918300ejf.244.1605046307438;
        Tue, 10 Nov 2020 14:11:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046307; cv=none;
        d=google.com; s=arc-20160816;
        b=kbcYNZfbWozgeHGN5znSMK3/XiZOoc2lWhX4nQ7IWjjxwgy4r1N/1rfiMEunOYpG5d
         wUXGwVbI6QJCpzMwusVeyKtfTeI/vt8gjesSdwWMRjRnDR2cbLdgVM/8clytAkMKGAA+
         GxjQdv66L79gTy1AODOWLUDRQ0vjo2aWFyAsUoVVHOgbpXuyskQB3cnhcUdnTjWclcWX
         rYDyGTWDYnYB6Xnfnz3O1xU+TIMQbaU3GErYclkwPWw6/q0Qu4Wel0HYVijRnz0n85h4
         IYiqTz/z2yntLDhJTfp6m7laRSPKQnmS4KmW7gHQ7vJtftmmkY5IW2mFS9hsZkPj/nnc
         igJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IoTt6hT7gjXNpuAqI7B1fpPr1ifOz5U3TNuE4drki+I=;
        b=mHkyZmkvBeYY1VqRCMlHGrtOiHv/uqodrxU9KoWAxkFK9jFIxtXzDMIQcSRH4+mhHR
         us0iRwXdNNs2h1R0uHlf3NTXEcQ87+keEm5h2YR3Awc4BantjcWBztBe/5eS8eT017Ny
         7fHMr8lphrlweZPnBvnw9lbDo8vwMlWsOPbMA+kvAXyt+Ir9lrGXxPnjJ8Flj5Cc5KLK
         eQH7H0xdxgmck25XHgsAwUMN0YAwa9rXEJ4JBe/Qx5SCf0rgja5CkL4wIKXXz8v+Rh+w
         j9qVGAqpjENvu+uMEGkhcj8VYk/h1w6PmlF3ZD4W9D5m1KJBbomnajNCBF+Bpl4HKbL9
         oDTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IQSSQ/5E";
       spf=pass (google.com: domain of 3ixcrxwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IxCrXwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c11si5199edn.0.2020.11.10.14.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ixcrxwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r15so1104963wrn.15
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7219:: with SMTP id
 n25mr232465wmc.61.1605046307132; Tue, 10 Nov 2020 14:11:47 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:14 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 17/44] kasan, arm64: move initialization message
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
 header.i=@google.com header.s=20161025 header.b="IQSSQ/5E";       spf=pass
 (google.com: domain of 3ixcrxwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IxCrXwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
while the generic mode only requires kasan_init(). Move the
initialization message for tag-based mode into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
doesn't use any printing functions; tag-based mode should use "kasan:"
instead of KBUILD_MODNAME (which stands for file name).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
---
 arch/arm64/include/asm/kasan.h |  9 +++------
 arch/arm64/mm/kasan_init.c     | 13 +++++--------
 mm/kasan/generic.c             |  2 --
 mm/kasan/sw_tags.c             |  4 +++-
 4 files changed, 11 insertions(+), 17 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index f7ea70d02cab..0aaf9044cd6a 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -12,14 +12,10 @@
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
-#ifdef CONFIG_KASAN
-void kasan_init(void);
-#else
-static inline void kasan_init(void) { }
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+void kasan_init(void);
+
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
  * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
@@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
+static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 5172799f831f..e35ce04beed1 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
-#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
-
-static inline void __init kasan_init_shadow(void) { }
-
-static inline void __init kasan_init_depth(void) { }
-
-#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index e1af3b6c53b8..adb254df1b1d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b2638c2cd58a..d25f8641b7cd 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl%40google.com.
