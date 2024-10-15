Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBMUNW64AMGQEV3P3GMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C8E899DB9F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:43 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4603b89d3f3sf73145571cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956082; cv=pass;
        d=google.com; s=arc-20240605;
        b=F/JvleDzZUH1TN5sRRQdGxeeedm0s5E3yW3us6vQG6/vA1X0EmjDcOmv5c8CIYnhnn
         6oliHoAe64nNwZPtv0Tm+S2lI6mVaxnnjyZU3Y48MBYUk3mPVCQKL5BdJTHCW1JvTrGv
         C9IpeoN79UcMAyQfANpKr0buGPFFCVfnzWRIW5MLm8Z1NxD3XZ+DcEp0CqWUxtxTg9mK
         Vce4VOuE5/+dBcxYbQBDTFhIlu0VcJmjOqpYzDp+lWWtnNloUELjWU+1qqxRoaAAfEyH
         ZRbawFf1vgKqonq+27+JL+va4havF82aNXQOwgJHkZbUIEew2orjho7IMaRLMccKapUE
         80ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=IwaRRLDcgawWyTwgc7+lz02HVuQADB8rFdaVf5+9Z4E=;
        fh=c6vpauFLKfXiE/jDWxsBHmxyzm2AC9/9DeAJjzlljRc=;
        b=aPGnILT6/0l6yxNPIXn8AMGg7H7+5bvVY7XJReyI2CFuYa1UNOrsXhCviiKvN/jSAi
         fF495VkL97CaGNmtcGpVEIQHdlgW5y/vyKsDsTIEOdW9Kf8nMmWpZT3jcqHqkcTKqnEm
         xkvN245pcqpjtglwCrkWnZ/X/PMHEkSoVpEc48I+DI7Q8V2AtoIrR3TVXQuaR1BHiWM7
         bNh6s1+tRqFo3X1SYa6T5mOTeEgGmmnPXFfOO97wOI6Ar/WAq4MFN0QLPgpFEyuYcjQY
         GiVg7wkMfWzdXJ1ebOn65ST/k2GRBEuZR9C7SFmoCTzhbCn987XfITODDKLuJRqQQK/w
         pzKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nCgxDhfJ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956082; x=1729560882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IwaRRLDcgawWyTwgc7+lz02HVuQADB8rFdaVf5+9Z4E=;
        b=HhCIc8HWiywqz7PWfLMIm5StFycZIZOAbqhS6CkSnE/qBoukI5LLd+2r9bGnIbNWoK
         sYaiazNgE3CEzeFNmyWY7vL8iaVITU/ZP6k8vD9OzximD220YgAgB9ACSU8Vu/F2IZv9
         6I1fO815LpjaxQt2puqfDlto4hNU4k4DIIyVdDjJitsuM17oEYkjGQfQdVBIpqwu2Djq
         uG8y0/0VgNcih0nGlRtLMx3eJ7Dncq6DUBUnqZNI9BugcuzESc9Q/OpjNtuPGTrsNdkX
         z6ymekywdTATm8IrGjCGPpwnGxhS2YwF60ejE/L1BlSAPm68cQTJ0CWOgrChl/TfAaXT
         zmaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956082; x=1729560882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=IwaRRLDcgawWyTwgc7+lz02HVuQADB8rFdaVf5+9Z4E=;
        b=mmG5Ak1X9lrKW1OVk94Y7vsup1KXOqxVirV7ZtiNx7XzaMdse0QURk2P5acWF8A/lb
         +mVwmGXPKoKP/MJhk7fMDYx1ORQVnjhlt2/9fV86hjnCj/9qsGfF79YA6pT2AyRNVnzn
         2QwZOVbw+ELvoHTtywdlkU7D/MEe69xFu8anYiO7nEPe0kXJ2U4jHwLfj5vE0sZYJNP1
         GmIvRaU5cACx0xm3+5ABEKJQt8fXliBMJJL1BPKv8VMQbs/zm5F64OkEJumFNG/G11qB
         UDT8ERSmC0k/QzZMF2DT/DoJ42a6NfleAn4UQeTHz6O1NVLYVBikrL6K5HHnpG9CvrWH
         izyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956082; x=1729560882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IwaRRLDcgawWyTwgc7+lz02HVuQADB8rFdaVf5+9Z4E=;
        b=Z1O8jPX/nGc3Gjr/1o8yN8K+E8IrwyJYv9dvkULRwsXen1fPybEVrqtG61PwISaIjg
         b3mKtTRQBpTsZ5e0Bx1CnrKcjyW/0WbD7JWTPXP4CJrqHU/DcHV5+rvoJKVfpPKLc9fz
         ZInZbuGYHQfjtRK+Pcxueci3bF9I7bhq//8NELQgSPZ0/nPpKW8xS/jCyEBhOrDadNaB
         ICXC0RUnWCV3r7GEa3D/4Gknzb6qqE76Fal5q1UlSk5h8CsLscEZBhkIi/GiUmY6nVrb
         t7bw9Hj8JsS3IVSXofUNwUAPthf4nblDVWiFQtNsTLjHt7vBkeU6+nuEcy1RPyl96rBf
         R87Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnT1ayzYJfuTU7yoQiIZWbAgLA2CViWl0bbzaHVYzdOejvGepPOPf9bRzM9kyT9uCWdrlpZg==@lfdr.de
X-Gm-Message-State: AOJu0YzZHqhTGKwYRpCweuAX8/B9iSxHn158MfnGbTvWkrj3fRkvFnYH
	0/s7cU04LFH5uOIWaUeVdcuTwS4JXWGqWJcv7PzaonAAZScoZi0G
X-Google-Smtp-Source: AGHT+IE2ocOzPR6WwS9u2wx7NIrZpa0j0Mh5M9FQBO/OSvSp9yC/PkiaJr/zdDvUlIVxfeeNYWlfMQ==
X-Received: by 2002:a05:622a:1b22:b0:458:5bb4:7751 with SMTP id d75a77b69052e-4604bbb4380mr236570271cf.13.1728956082185;
        Mon, 14 Oct 2024 18:34:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a95:b0:45e:f111:4db with SMTP id
 d75a77b69052e-4603fb34732ls81036591cf.0.-pod-prod-08-us; Mon, 14 Oct 2024
 18:34:41 -0700 (PDT)
X-Received: by 2002:a05:622a:229a:b0:453:15b5:26b9 with SMTP id d75a77b69052e-4604bc54438mr207428381cf.52.1728956081407;
        Mon, 14 Oct 2024 18:34:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956081; cv=none;
        d=google.com; s=arc-20240605;
        b=CV/XaRGXs/kK2v43TpVmpYOIYi3O0FEDTW8385hq2Va8pJEHX2hQw4BS9tIFfrDbDc
         kbwERvxLIERazICV5HflusT1Rz4LTsLoYJocQRYvd6sBISTXOB7c2xZJoowrR2UV6NWI
         NB4fOYgK6G+bIBPC3pgiuwfkRvHZi8FZWuN6MF/uiQT8vxiIXY1cOsyW61Ni3FkuQ1yq
         jGZWJPmHGUT+3f6s59q2MG6x4Q2E9H+raq8KgNcIiKJ5cwlOYkO9/xkdzNdpt8jkLdqg
         H5rdBiihfN3zmWd3RL5TSW1nLVlnFAPlo+76UAIjs6VIX+9I/e7Z+pzEgdXBuJ8MMBVl
         5Bjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vbK+DyWhNFTOskVhv1fyi/tJ2PP4Ej6g6TRuPbyIjZc=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=TjsScZxwkvbHIj0+zqF3rBOzh7xUBG0KxyOy1MbNsjQAjrMgepcESEE2n9qFW28YFx
         fHSUXi2WTq3wh5HuSR2w2zkciMund8Y7KswdEe9cprk7xK+nqvdFluZcFlkGTLcBv4GK
         zip2k0NqtVw93wDOZk3fLZGu3xGVn+ckO3+NX+ktYKEWvM8jlUkytTsAFOYSHQbCCeQJ
         rmLJqinr6QuXOS3Mj+eGRh279LOqGsjcqMm8RZBuG7nZ9bGCrTaupCHvio7eyoP5tjnT
         XKiwJjIUJ3K4APFsNDC0inaS1BMBXvgkn6PMwlrWYi4aLzZqkwLIdSElmM1GSYpTPeJj
         /e5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nCgxDhfJ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4607af286dfsi163521cf.2.2024.10.14.18.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-71e70c32cd7so717786b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:41 -0700 (PDT)
X-Received: by 2002:a05:6a00:189d:b0:71e:768b:700a with SMTP id d2e1a72fcca58-71e768b7107mr1328450b3a.23.1728956080395;
        Mon, 14 Oct 2024 18:34:40 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:39 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 11/13] book3s64/radix: Refactoring common kfence related functions
Date: Tue, 15 Oct 2024 07:03:34 +0530
Message-ID: <a0ebddc6250441d7750c9f94f7d1fc64db406b20.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nCgxDhfJ;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42a
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Both radix and hash on book3s requires to detect if kfence
early init is enabled or not. Hash needs to disable kfence
if early init is not enabled because with kfence the linear map is
mapped using PAGE_SIZE rather than 16M mapping.
We don't support multiple page sizes for slb entry used for kernel
linear map in book3s64.

This patch refactors out the common functions required to detect kfence
early init is enabled or not.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h        |  8 ++++++--
 arch/powerpc/mm/book3s64/pgtable.c       | 13 +++++++++++++
 arch/powerpc/mm/book3s64/radix_pgtable.c | 12 ------------
 arch/powerpc/mm/init-common.c            |  1 +
 4 files changed, 20 insertions(+), 14 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index fab124ada1c7..1f7cab58ab2c 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -15,7 +15,7 @@
 #define ARCH_FUNC_PREFIX "."
 #endif
 
-#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
 extern bool kfence_disabled;
 
 static inline void disable_kfence(void)
@@ -27,7 +27,11 @@ static inline bool arch_kfence_init_pool(void)
 {
 	return !kfence_disabled;
 }
-#endif
+
+static inline bool kfence_early_init_enabled(void)
+{
+	return IS_ENABLED(CONFIG_KFENCE) && kfence_early_init;
+}
 
 #ifdef CONFIG_PPC64
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
diff --git a/arch/powerpc/mm/book3s64/pgtable.c b/arch/powerpc/mm/book3s64/pgtable.c
index 5a4a75369043..374542528080 100644
--- a/arch/powerpc/mm/book3s64/pgtable.c
+++ b/arch/powerpc/mm/book3s64/pgtable.c
@@ -37,6 +37,19 @@ EXPORT_SYMBOL(__pmd_frag_nr);
 unsigned long __pmd_frag_size_shift;
 EXPORT_SYMBOL(__pmd_frag_size_shift);
 
+#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
+static int __init parse_kfence_early_init(char *arg)
+{
+	int val;
+
+	if (get_option(&arg, &val))
+		kfence_early_init = !!val;
+	return 0;
+}
+early_param("kfence.sample_interval", parse_kfence_early_init);
+#endif
+
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
 /*
  * This is called when relaxing access to a hugepage. It's also called in the page
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index b0d927009af8..311e2112d782 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -363,18 +363,6 @@ static int __meminit create_physical_mapping(unsigned long start,
 }
 
 #ifdef CONFIG_KFENCE
-static bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
-
-static int __init parse_kfence_early_init(char *arg)
-{
-	int val;
-
-	if (get_option(&arg, &val))
-		kfence_early_init = !!val;
-	return 0;
-}
-early_param("kfence.sample_interval", parse_kfence_early_init);
-
 static inline phys_addr_t alloc_kfence_pool(void)
 {
 	phys_addr_t kfence_pool;
diff --git a/arch/powerpc/mm/init-common.c b/arch/powerpc/mm/init-common.c
index 2978fcbe307e..745097554bea 100644
--- a/arch/powerpc/mm/init-common.c
+++ b/arch/powerpc/mm/init-common.c
@@ -33,6 +33,7 @@ bool disable_kuep = !IS_ENABLED(CONFIG_PPC_KUEP);
 bool disable_kuap = !IS_ENABLED(CONFIG_PPC_KUAP);
 #ifdef CONFIG_KFENCE
 bool __ro_after_init kfence_disabled;
+bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
 #endif
 
 static int __init parse_nosmep(char *p)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0ebddc6250441d7750c9f94f7d1fc64db406b20.1728954719.git.ritesh.list%40gmail.com.
