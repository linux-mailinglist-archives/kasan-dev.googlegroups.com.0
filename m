Return-Path: <kasan-dev+bncBCMMDDFSWYCBB4UD2G6QMGQEE3TIIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC03A394DD
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:16:51 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2fc1eabf4f7sf9377948a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866610; cv=pass;
        d=google.com; s=arc-20240605;
        b=d0an51FsWD3IUsGrfTJVe5Aou03oA7AaFlVEl9zOYqHKWBbtzOv29LJA32K+gimlRu
         SeZbNXs+CIZYGvcKlDply+rRYqzhftljS3eOyKyyZNfq0NSXqyYCnB5PfmjBTVLUxFMC
         0UZLxMjNO+ykDfeSWnSXk7uh9lqecvsd2nz8h7e0Wt8CNoDlLtdXs/RMuIaCNnipP9JT
         KPw5M5uK3ACRQ9p9A4ZNwgJI51oyqq3JRYOfUy4OdMOT90eXr2msKznEVKXnryvzD0Tc
         /IGJM8OBsgG2D+/sKYmEaNS8K9oiWmOKknI+yAbndMBuPIWsYbv7OMGU3SLoSIm2woYW
         meSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HoTnx7d7PmbTuCD5M9vffqW+HuelG+1BxcZe6tmHzWE=;
        fh=emB76e/Rthu/pLTWPebjwpr9//OuSFEYTMf2eccyKI0=;
        b=WCUr+7xGMe7RtU3dU6mEHaeA2y0FC1Sdv7v3X2qr1KV2OOusTLSrwh9nlk+iqDTxt/
         U7dDMzoyOIQRGRewFVhWCG3DTCF5wDJim0YHNg8l+lCMXdKokEaDJZ4WuW0psXKdp1v4
         tpUI5lGTgceeNrU6GoZEguCGLfsxNjbnt0ZUVOvzqz4d2p4/nyDLeOIn8tPP+4ijlLP1
         w14iE3AUd1fyU0gbYL+3Tpd19EuT4T7nxbXfU6r1cCO2Q0leCNIap4zUv7CpkhQRlv2u
         XIGD9pVvPEbGEpaChC8fqf/EWBkrO9l+fj49ta7z8xSbp91zFiR+wymd5yAij0levX3L
         E6rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MAaDckFL;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866610; x=1740471410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HoTnx7d7PmbTuCD5M9vffqW+HuelG+1BxcZe6tmHzWE=;
        b=DTcYJSda7fKCbo/HnZbRza/eqrbp/5ZGRq6u2KQGgcOyqKMrKXarsWV2wZNiWPDlWg
         lC9A4FuPXPjepBeAO9k9I38u3fdNRWmV5975Z2DF8nUzvJDBrcO0Yez4P5fltYZV97fN
         C0pun2jMO+dlUsAe4G7/PIdVLrlXMQqh9dvmBi7+fZ0Nk3AIGC+wxX4/5IPzt9Ib/pOS
         1NGnNvym3opcQweIBydFXAOSrlwzlwsJBkN0DQ4Clnmxb3vwvLN2mQHH3+ClLNoEqSkb
         gwAvLqIv8tRhFpOZ6J9OToumL35lIDYMHYa4994JxOGqMwxUVF02t0omaKjX1YCVpNND
         tDmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866610; x=1740471410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HoTnx7d7PmbTuCD5M9vffqW+HuelG+1BxcZe6tmHzWE=;
        b=vK1Aotye+ayM0wF0cSd7wrO7BR9sz/X9ZWAyjX8O1E06z2P8eb6wg9lM3OF+z+juAN
         IwlH1Uwl1FXRbHGd28BDZ8oyrpTwOUjGr3PbGey/Wtk3pM4X9fBIKr6RbUxnHHScHQnq
         iIYS77LBM8cilt6zr9/uEDolWRMfNBYYQmiQE7doigCtC/NgdK60pR8SpIfERkO/isJV
         FmywWfUoMof3pXtIRvAGIp+iMOKK6hrdqeRpiVlyZ5EmL+wCgX9RLQ36ojOkzGvnRJ5P
         EoKJ2Ud2M+W/Ldxge5izlYziEzBKTDZU0FSolIRRFR5okHQi3ZsgsLwExbF1DjFeEK9g
         V75w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzYOlApKWu3DbbDDbdwGJvL7/ApO30SBAwgyTareeuEUzvM5LhWfEtmzMux+79al+MW/U25Q==@lfdr.de
X-Gm-Message-State: AOJu0YzYHJj3a6tmlUyj8kbVNCmcz5NutTCR27IDHz5MyqFvqCk6P9ZO
	4SKw0CSHUEo0Z5LGaXIlvmgW800p/OSPylxI7eLOFuZgxqRJZkhH
X-Google-Smtp-Source: AGHT+IHiSzXALri0MfGRwQUbyhNIySVKP5m9rdvAD6FeeRiW4mkqpiKfdFPIlm6oHn8caMhZxZd1LQ==
X-Received: by 2002:a17:90b:4b0c:b0:2ee:ed1c:e451 with SMTP id 98e67ed59e1d1-2fc40f21e60mr20481456a91.15.1739866610338;
        Tue, 18 Feb 2025 00:16:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGFq3+48zKhyaJ757JJje5ZnMNgW7NGiehgoD4v0zsm5w==
Received: by 2002:a17:90a:df18:b0:2ee:126e:2f50 with SMTP id
 98e67ed59e1d1-2fc0d727883ls1445945a91.2.-pod-prod-05-us; Tue, 18 Feb 2025
 00:16:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWm0fqQa3uYoqZ3H6tMUCl+bO7NIpK+zjX1/sl9IFC1uBISaJr1Ek2K5tPduJZcxlUSMs25Kb3J628=@googlegroups.com
X-Received: by 2002:a17:90b:3904:b0:2ee:f440:53ed with SMTP id 98e67ed59e1d1-2fc4116bc55mr18010948a91.31.1739866609186;
        Tue, 18 Feb 2025 00:16:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866609; cv=none;
        d=google.com; s=arc-20240605;
        b=PjkMZRem2IdYyawNsehSk30S7izFtGGkzlVAt8/k8aKzWF/ZgLZO4EdOt11EaHWs50
         qvGML3/sHfb2EGtPKVNm6oUdLpkfxCxDAq0u/ZxMRhphuGYXpA/WL/RbIX/MdbQ0M11H
         /OQJwR8yE6+iq9YVI8HuRaJ88+MtKuNfHxjMQmknvkG/rFubEX+yH4O5BgLRuU/P/2Sa
         li71VrOycukmun9zeQsytztX6gxruGb5SOSU6G2Ml4lS9h18eaV82ejiaMpbT6uj8Kcs
         ZNjkuMPpRfVGPEdkyGeAwS9NTR2Rsrgur18tM2L0zmn4HI2P7NBRIWPQsJ15f19WQUPg
         D2rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1TTuXLxMopwWeFVdGnLcIPjRaZ96xctO0Nm3rLViPCA=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=io/iVjb3mkYGT9SZLqhr0VHAnbukujO2+vBfL27KvqhVNUeRTfLr58TP53e6guIG81
         X4pB4NXwp2dzfvLvAacisthlYa7Ho6hcmcwo/ywrZFlaaL6GATF2SFi/lCpBcYcSU7WF
         re0JG267Bd2aI2uoOIBC7NVG28dnoH8s8XMyNKnfjovWl5pZM5pWcd7upananis2H9Ua
         fdlpwyjpdSzk22EOeJuE+ga5IXuSjew3FnJbPjLA4d4R6KpmpwwTA11LEvZrdODOimPE
         w4D4NlW6R5qUBmuqttr0ADxH2N5GeNcJGZIqh4R71O8GIG3Yfw1K5TfsCNKOVXkiRCa3
         fX2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MAaDckFL;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa5cf2c57si1473296a91.1.2025.02.18.00.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:16:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: sTZHx5vaRxuO3V9h8YCgRQ==
X-CSE-MsgGUID: F+X7J+AIRmW9yPfpTNU9tw==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150001"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150001"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:48 -0800
X-CSE-ConnectionGUID: M5Fwk1/OT62LIgJLo5m/Ew==
X-CSE-MsgGUID: 5TZpocIhS3iT+cIhiLsT0g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247387"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:28 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 02/14] kasan: sw_tags: Check kasan_flag_enabled at runtime
Date: Tue, 18 Feb 2025 09:15:18 +0100
Message-ID: <b1a6cd99e98bf85adc9bdf063f359c136c1a5e78.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MAaDckFL;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

From: Samuel Holland <samuel.holland@sifive.com>

On RISC-V, the ISA extension required to dereference tagged pointers is
optional, and the interface to enable pointer masking requires firmware
support. Therefore, we must detect at runtime if sw_tags is usable on a
given machine. Reuse the logic from hw_tags to dynamically enable KASAN.

This commit makes no functional change to the KASAN_HW_TAGS code path.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 include/linux/kasan-enabled.h | 15 +++++----------
 mm/kasan/hw_tags.c            | 10 ----------
 mm/kasan/tags.c               | 10 ++++++++++
 3 files changed, 15 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..648bda9495b7 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,7 +4,7 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
@@ -13,23 +13,18 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
-{
-	return kasan_enabled();
-}
-
-#else /* CONFIG_KASAN_HW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
 {
 	return IS_ENABLED(CONFIG_KASAN);
 }
 
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_hw_tags_enabled(void)
 {
-	return false;
+	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
 }
 
-#endif /* CONFIG_KASAN_HW_TAGS */
-
 #endif /* LINUX_KASAN_ENABLED_H */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..7f82af13b6a6 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -259,9 +252,6 @@ void __init kasan_init_hw_tags(void)
 
 	kasan_init_tags();
 
-	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index d65d48b85f90..c111d98961ed 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -32,6 +32,13 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized by kasan_init_tags().
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
@@ -92,6 +99,9 @@ void __init kasan_init_tags(void)
 		if (WARN_ON(!stack_ring.entries))
 			static_branch_disable(&kasan_flag_stacktrace);
 	}
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
 }
 
 static void save_stack_info(struct kmem_cache *cache, void *object,
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b1a6cd99e98bf85adc9bdf063f359c136c1a5e78.1739866028.git.maciej.wieczor-retman%40intel.com.
