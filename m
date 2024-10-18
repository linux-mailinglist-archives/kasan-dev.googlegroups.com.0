Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBYVWZK4AMGQEFFNORZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D819A44B2
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:16 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2885c643f6bsf3677467fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272674; cv=pass;
        d=google.com; s=arc-20240605;
        b=fF0Ep3UDwCyaWT5W+JCPFxHkAGoqDh77hFInLSgvfDlkaxzPbXEoyxgDUKkdMqt+6e
         P7uEVWWfegmHA1I8UASQKt6aeTG1TyCOf13KhrHYGiHkoSqcGiMjXaAN8v9PWOVWqsuf
         9OKVALTgrDsbWWkMb+Y09ujd6dg4fGWS/+ZtriAIJ+MZXsyF5/pMYKa1LjcjmGSt7xRO
         hXhYjKB+wYLtO3c7p7JSUdFs78uqzHs2kpOXge2/75BdhgyJ9u/38JYuc7LuPyLwKsvc
         KSN+drWH3BG+O1h+53LMyJbgSeAr197F8zSvPvU1YGqfj6A7NXIcHY5E4A4GZFTssATY
         GJAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KdmlLQtu3XP1DMplzwyLAPBMor+uCeJKnkBH25bk13s=;
        fh=cJSCzlFERhFv3G9TWVCz6N6KQOO/h4azjA1ufnRkTpQ=;
        b=SqTSNxyqMInEfTUp5OQelsiocf2QzMqCrBnQBRS7cEku3VLjXw68znp3XDRDdDgg8F
         DzGo93/SRZbc33zhJ1rCPYcoPNGublW6kmxaPD623bHMGs3KB+sU6F3Rm6yGTbofLoNr
         cdZWAzLede+w8h5d9fDwQ7kMhhPM52PkU7YJ7RyoLVScYL7VADhxd0Bd6a+xzY+SfaU/
         /YRXvE7mPtGI8BGRXn52Imo8BcPClkOGWWGy1GjQM2dJQzqyEY/kMlbqilCpLBaDwhTh
         jtmt//mo2Rgmqf+GfHL+wGOl8JCcFcCo0+PYEe2/B5T4BxuVU+NPGtxGA/31egkbv4pX
         oBrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bxd3P7IY;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272674; x=1729877474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KdmlLQtu3XP1DMplzwyLAPBMor+uCeJKnkBH25bk13s=;
        b=caxYSQLQewa2Xf4Ne4zY6RYy3Hg8RT8ulRYZvuKs3VGMXTvUD4FFAHI1EYmbeJOyhD
         g1fr9bRsyDllbtiAalKpN77mk8g2oC8qbGaTS7oyNy9rFHOUsZE5DWC7/asMYuax/B75
         cJyPvUZEsXthGV27q8aA8QFrCmds0PurcHoscfDwHeIcCvtVtiLK/hFank8pe3QYtgOV
         sQTtKIdoW17JCCLkURMkkLfjO5nA32z+YhTXXhm6pDDtK+3ZXijdEASV2XoMhKNe9OQw
         1l0RNw00nJXOW85CacZNFGW4wIE6fX+1sntHImQLkfr5pvUMtLLpghg6BzfWxzMSgzZ0
         NU3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272674; x=1729877474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KdmlLQtu3XP1DMplzwyLAPBMor+uCeJKnkBH25bk13s=;
        b=bc+KyilChV9nc9UEbFVrEAI97une/JIppShMKGoOprrujvS4KgG2WzzZPCPFL1b5HQ
         vaEfLjSslXash9hTnF+BjSvnftzkD1kypa18o0ueE2pdOAs0siZ2Sd5RSz7j3LDW/SKe
         0AWqtweTUETseBfFfOQMBmCNmTzd7OyEcBcBEufDponvA80Ef+2GtBKT1nS0aGMYd64u
         d7L/4EjwuuEsUcBm2bGaZGvM+WSFOkyY8M7O+0ksXR5JU2zS8nEKVM6PcmLCM9BB3V+G
         lUlXjqBHIrgql1YvFGl/niMqBooPJOTTJKiY1SgrY+YmNhr5CXEZ1U0Yb02SfQ4TlccD
         vdiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272674; x=1729877474;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KdmlLQtu3XP1DMplzwyLAPBMor+uCeJKnkBH25bk13s=;
        b=b4DQBIfFjhMpl+21j2mBRZuUC9WzisGz6856RkdebuUVpcMQfsv1WfG2ipNVm7IlTL
         cGvAHqxd8j9bnT4IgRRdAp5kGy0jlQnN1jVJW9VlWC+bQS0YdkY8y7L2cM3aB+F+Aijm
         f4sc+H04ZI+s5DA6v1p7ME098wDpoJHDu6yaQkpQ2KqfHMfj+7dSEiClcA+A6obkhCIB
         8xDSPsL4Yk+ItsvbFsCtQBpXeYR+ieZPvLqddiR0srWGr62OdjlrYLadG73teBL0vicg
         tZzKfHN10ueEIuMAaz54T7NbKFl/tY+iTW6zql8UGEHCFsoTu2eke6p816PPIaO3hzzn
         gprg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBxFjdBUxtZ4gHKPAkcWTvK6TT+YEXZERXnX+hwUSEw7NeGb27tC5ltz7699BEekg9bFf0EQ==@lfdr.de
X-Gm-Message-State: AOJu0YxMy2ZFTuE/50LKSX4bdd7uFDw0ldSQfjqNXdFhhIFGfJzPUZea
	krwkboB7iVXPTrE81JgVDwC1VRDeo6A4YDzNXHJHQne93L5Vsk7K
X-Google-Smtp-Source: AGHT+IGZJKD0dDO/T4/peKiqaAnq/dCbgxWc69EWeg51TOvvLyGqN0XtTqVwcathx2O9gmIlHbA3pA==
X-Received: by 2002:a05:6870:9627:b0:27c:475c:ab2c with SMTP id 586e51a60fabf-2892c56ce14mr3048802fac.43.1729272674306;
        Fri, 18 Oct 2024 10:31:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d0a:b0:277:ea6e:3749 with SMTP id
 586e51a60fabf-2890cd0db1bls1875295fac.2.-pod-prod-09-us; Fri, 18 Oct 2024
 10:31:13 -0700 (PDT)
X-Received: by 2002:a05:6808:2f14:b0:3e6:8ae:7b85 with SMTP id 5614622812f47-3e608ae7c3cmr425277b6e.6.1729272673314;
        Fri, 18 Oct 2024 10:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272673; cv=none;
        d=google.com; s=arc-20240605;
        b=JPJj6dYPCimfWNUKR//ueCoukP0J3T/RfWbZQ2tnYf6Lfpbju8w7WwbQ73YEUHf0/k
         qLrZqBCNqOAp303hCQsMuijcPycbiPbgD5k5nsM97pW4PWF+cdI4T211YL7Hqzc9PhPB
         4TN+PSfbCACzeF0wTXeY2faLeeNMtKvWUA8D3e2q7tHUIo4LtTqjPW4oGfbt1PiTrMCz
         TUjnXqfgVUl6UFEDpBf6vCNsk78MxEsiei3+gjzbNkrJZ5eznHFULJxwD2oQO9Iygl+6
         RdNeVGqf5t3HYjqN0rBO/6rSagQ48NNwwNCZSv+VQx58hU7ykAd8ng9BX9wpO/e+wbrn
         SxvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=maqsHecWoRrqy0atrv0EioRwOZB99TyG0W2HP4lfnAU=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=aayRU0sY3w4D7Zap4uZTEUEjKiGgeePhzN533shVY351JzJ0zLwcO7OYPYrohFJSSs
         tBN7swJ/O+OmVSYIgwS1qiSkjGm1cE3gsKJZSYOxvvPkSp4mI9C9XAo2i4zPMiV+ry78
         LDUg+3RJ5GV8lxedR3TVM+XQqfqR52s864z0cfzrn8DTiyWJe16hSh3OwuEneSfT1UCm
         tFCB6RWDCTYfXVsbGFisF3hgAyPw1i02icZKxMxyLp55vb44Ry1bEmOjVqViuQmS6hoj
         hIZpwqbt+EL6Y3dK74RH5l6oyxb3Pdr+hSLbJwKoCXJwkcH0a6I+5Xpvy9tDjT1VJcwW
         9DlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bxd3P7IY;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e6029cb669si86485b6e.2.2024.10.18.10.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-7ea9739647bso1651310a12.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:31:13 -0700 (PDT)
X-Received: by 2002:a05:6a20:43a0:b0:1d9:a90:8879 with SMTP id adf61e73a8af0-1d92c502994mr4770966637.21.1729272672394;
        Fri, 18 Oct 2024 10:31:12 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.31.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:31:11 -0700 (PDT)
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
Subject: [PATCH v3 10/12] book3s64/radix: Refactoring common kfence related functions
Date: Fri, 18 Oct 2024 22:59:51 +0530
Message-ID: <f4a787224fbe5bb787158ace579780c0257f6602.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Bxd3P7IY;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52d
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
index f4d8d3c40e5c..1563a8c28feb 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4a787224fbe5bb787158ace579780c0257f6602.1729271995.git.ritesh.list%40gmail.com.
