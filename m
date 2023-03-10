Return-Path: <kasan-dev+bncBAABBK4BV6QAMGQEMA5L73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 76DE36B55DB
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:43:40 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id p36-20020a056402502400b004bb926a3d54sf9714984eda.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:43:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491820; cv=pass;
        d=google.com; s=arc-20160816;
        b=wo+YQZtjDNsQj01yuAmI/w/CgdOm2rZorbq5mkaBScw5Rs3bxP5fnpqlWb2xwJrlaW
         OBRryOJDB6oOg/vZdH8s3CJbM7S4Hx+p3GejlLD01w2dB3zufTdrSeKb4nUBSCQu4qV8
         Xaa4h3AdOoW7ZugJ0ig+uZBxOVbq1Jbr1LqHdh1cdJDluRsdhzRD+C0fdOgH2/sEFRlf
         v793ahaEurgI7LHGTbsW0Z9J6PREVBM05mwnmRIVG7n36txjfxFVjj8H/t1VAFZevOiQ
         In/Ot3HOa5Klj/L4mhG7upfew/gL81Jt0Va+yagbzLL6Jiz+DDANcCMUy9FMf9J/pvnr
         J9CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RybAr2xGSRfscX68F/l9NJ5ArUlE9c36EhR0caHZwg4=;
        b=suxovgyf2mC8eV34nBl4chHIbQAsDmmTK0sIQDPKAsiJZGOaSUbhKmJKLw2Dls+bHD
         usl1WVWdFZrt7pgpt1ZtT0ivf7NtTPHNj5D2dTC8BMMeqn0ykio6HULFFr2rbio5FLux
         JzitqOmN5qb1VDBBQbGZC06pZL0TjsDmEI3IGDjyGByjcF4CS9ReBXjs84e52Y6rYKW+
         TDV73LLEXznlGGVIuQTSLnmAst4Zk2lwGpFQ997Jj/ym8ax1EMfNBRBihoNvHfwrI9nx
         Y2rAbNNJHrdc8DD9t9B6ICuO7rATCpnbEi4Nt0XCbYoeuqlGGnB78sfM32wgc6SYUnd0
         rt0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=URqlLtgK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::2e as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RybAr2xGSRfscX68F/l9NJ5ArUlE9c36EhR0caHZwg4=;
        b=rDoVNIAUKai7x0Vj46fDEgVA8AJU/bcKKXKa2pz1Hc9JGMcr0GPDdAQJ0rPyGBxj+2
         tdYFGCZ5M3EOaaJqyOmA9BUQZe0VU8Uo0AAOnXj1xp2OZyZ3jBGfsSNxj0cmZOSmGz8w
         DL2Z0gzD7qdkkGwEMgQe0f+cSManqm1ZHaGSIrujBzFvW0hf1xVfUHWOVWeP/O/+TP8g
         zEs3s6NghI3V47dLCSKWdG/qeXPnWmBqWwQhSWqQv/3gF8WPLcYDjpTTEiPJMmtIKOm5
         m8kcBY1c3XeQUju23zealz5Sug49/MMbVlUrRDBB8ThZKb1YvQqVyRm6iq5ELN1lt6YA
         Unjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RybAr2xGSRfscX68F/l9NJ5ArUlE9c36EhR0caHZwg4=;
        b=CE6rcZjIszoBzD4QL7ZHDQ920XKtFY1wRcc3N6C+IP0WqlgAI+BGkSOj2b89Xd2cbW
         TeBQckO8u3n36WjFJ7j+2+tuXR+826lAF1gojQs39C3fwP4wFLj09eE/AHPxu9ZhXlz1
         jHXcVXgtdn/8L5f0u+T3EISN4nTg+2crD3hkIi9xeRLC+go/G0mZ/Ah4MDBflvgqnmW3
         5jQZt9SpACv5Ho0xk3QNJWHm+h8l6cpfaQawS5zeffalqgH7wk8rXPk+Qa8bQQGqOAxc
         81fitB9ZnEmYFAMsi0slvHZBhIOYuQlJ2V5Vi+YtlMDT/QhmjFbF4F8Ny/oTvgIG6eZQ
         ItyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWSUTUhFW/btzerytxUjNMLbqybHsv+q2dNywBoY1SpKLc9rJWs
	Ss89KFRk4J8fVqDkAjEyOjk=
X-Google-Smtp-Source: AK7set+lwqBspH75C2hMTjabvRrk93B74H0LmmVSZmhxOc8sLzJrasTsqtU4VkZy5Db/zVIxeUjmXw==
X-Received: by 2002:a17:906:9488:b0:88d:7af6:25de with SMTP id t8-20020a170906948800b0088d7af625demr12858870ejx.12.1678491820000;
        Fri, 10 Mar 2023 15:43:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4304:b0:4ac:b59b:6e28 with SMTP id
 m4-20020a056402430400b004acb59b6e28ls2971240edc.2.-pod-prod-gmail; Fri, 10
 Mar 2023 15:43:39 -0800 (PST)
X-Received: by 2002:a05:6402:205c:b0:4cf:350e:344c with SMTP id bc28-20020a056402205c00b004cf350e344cmr23721783edb.28.1678491819065;
        Fri, 10 Mar 2023 15:43:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491819; cv=none;
        d=google.com; s=arc-20160816;
        b=Ju+0EthXvBenbmBNIAlQlinEx8yH+EfKMAk6NqZ/mt2lN8xL/OLI9fTSHW03+tF6z9
         hTRsLmu3I5OHMl47R8Sc03sZ50+Tc0FX5iKjRaDjlZRccKG35O1E1d9Oh2mUqawqeUsB
         /m3rc2A/r+0LdmHNJeNTyA5yKFEZt8TojQZTfDboH7iguDKZgV7H80zHVzPEqH4V3vBN
         GCJdQtEmioh5el2oyJtGhkmLjzCjNCcZnydnIQSlj7BJGBqZl90sAI5QV9pnwz/sn9Ap
         dyRugvtXx1hh/qJ6HMGl0s13Z/UY+iU44SqihJoEDBmzmuCiKGQFPUqJdjWp/cKGBPhX
         ohig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5f47haFm6GLuf5I4IFtda8n0nMYkg8PQuTGiJh6Xcxk=;
        b=b7BbIemWN/tn4pacFrhff2zvB4bk5Y3LztqoWHwzWI7P8nKlKX6IPY15NMzyQN49NF
         c1uiwkHkuPaSxg/3ILNaG1qKfPh5yBAGOO62w16ZR9t17hacRLxe4OPsAZpPK4Fd8GRm
         Ftrp9ZkAdaCTQZel4ZmGKrMEFe3SS+xYvoCeCmE5EFWwkNiWgiq1sdqIIbCoegfUU14E
         GUW27V0+UaMRm6kCb1Qb0VPz4CAo+Yk2VnLD+Gi1KJTS573wtSLVtbR6Bh9rGWy5vi3D
         ike1Ks9WT0IpFaecvYcMlkYdVQa27baktoPZ6YRJ99DMFnZK8In+JcRGmrD74e1pIHwl
         CM/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=URqlLtgK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::2e as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-46.mta1.migadu.com (out-46.mta1.migadu.com. [2001:41d0:203:375::2e])
        by gmr-mx.google.com with ESMTPS id i1-20020a05640242c100b004bc501f1c76si68986edc.1.2023.03.10.15.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Mar 2023 15:43:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::2e as permitted sender) client-ip=2001:41d0:203:375::2e;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/5] arm64: mte: Rename TCO routines
Date: Sat, 11 Mar 2023 00:43:31 +0100
Message-Id: <a48e7adce1248c0f9603a457776d59daa0ef734b.1678491668.git.andreyknvl@google.com>
In-Reply-To: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=URqlLtgK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::2e as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

The TCO related routines are used in uaccess methods and
load_unaligned_zeropad() but are unrelated to both even if the naming
suggest otherwise.

Improve the readability of the code moving the away from uaccess.h and
pre-pending them with "mte".

Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/mte-kasan.h      | 81 +++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h            | 12 ----
 arch/arm64/include/asm/uaccess.h        | 66 +++-----------------
 arch/arm64/include/asm/word-at-a-time.h |  4 +-
 4 files changed, 93 insertions(+), 70 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 9f79425fc65a..cc9e74876e9a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -13,8 +13,73 @@
 
 #include <linux/types.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return static_branch_unlikely(&mte_async_or_asymm_mode);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return false;
+}
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_ARM64_MTE
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
+static inline void __mte_disable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+static inline void __mte_enable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
+static inline void __mte_disable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		__mte_disable_tco();
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		__mte_enable_tco();
+}
+
 /*
  * These functions are meant to be only used from KASAN runtime through
  * the arch_*() interface defined in asm/memory.h.
@@ -138,6 +203,22 @@ void mte_enable_kernel_asymm(void);
 
 #else /* CONFIG_ARM64_MTE */
 
+static inline void __mte_disable_tco(void)
+{
+}
+
+static inline void __mte_enable_tco(void)
+{
+}
+
+static inline void __mte_disable_tco_async(void)
+{
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+}
+
 static inline u8 mte_get_ptr_tag(void *ptr)
 {
 	return 0xFF;
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 20dd06d70af5..c028afb1cd0b 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -178,14 +178,6 @@ static inline void mte_disable_tco_entry(struct task_struct *task)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-/* Whether the MTE asynchronous mode is enabled. */
-DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
-
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return static_branch_unlikely(&mte_async_or_asymm_mode);
-}
-
 void mte_check_tfsr_el1(void);
 
 static inline void mte_check_tfsr_entry(void)
@@ -212,10 +204,6 @@ static inline void mte_check_tfsr_exit(void)
 	mte_check_tfsr_el1();
 }
 #else
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return false;
-}
 static inline void mte_check_tfsr_el1(void)
 {
 }
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 5c7b2f9d5913..057ec1882326 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -136,55 +136,9 @@ static inline void __uaccess_enable_hw_pan(void)
 			CONFIG_ARM64_PAN));
 }
 
-/*
- * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
- * affects EL0 and TCF affects EL1 irrespective of which TTBR is
- * used.
- * The kernel accesses TTBR0 usually with LDTR/STTR instructions
- * when UAO is available, so these would act as EL0 accesses using
- * TCF0.
- * However futex.h code uses exclusives which would be executed as
- * EL1, this can potentially cause a tag check fault even if the
- * user disables TCF0.
- *
- * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
- * and reset it in uaccess_disable().
- *
- * The Tag check override (TCO) bit disables temporarily the tag checking
- * preventing the issue.
- */
-static inline void __uaccess_disable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-static inline void __uaccess_enable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-/*
- * These functions disable tag checking only if in MTE async mode
- * since the sync mode generates exceptions synchronously and the
- * nofault or load_unaligned_zeropad can handle them.
- */
-static inline void __uaccess_disable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		 __uaccess_disable_tco();
-}
-
-static inline void __uaccess_enable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		__uaccess_enable_tco();
-}
-
 static inline void uaccess_disable_privileged(void)
 {
-	__uaccess_disable_tco();
+	__mte_disable_tco();
 
 	if (uaccess_ttbr0_disable())
 		return;
@@ -194,7 +148,7 @@ static inline void uaccess_disable_privileged(void)
 
 static inline void uaccess_enable_privileged(void)
 {
-	__uaccess_enable_tco();
+	__mte_enable_tco();
 
 	if (uaccess_ttbr0_enable())
 		return;
@@ -302,8 +256,8 @@ do {									\
 #define get_user	__get_user
 
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async() and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() and
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __get_kernel_nofault(dst, src, type, err_label)			\
@@ -312,10 +266,10 @@ do {									\
 	__typeof__(src) __gkn_src = (src);				\
 	int __gkn_err = 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_get_mem("ldr", *((type *)(__gkn_dst)),			\
 		      (__force type *)(__gkn_src), __gkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__gkn_err))					\
 		goto err_label;						\
@@ -388,8 +342,8 @@ do {									\
 #define put_user	__put_user
 
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async() and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() and
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __put_kernel_nofault(dst, src, type, err_label)			\
@@ -398,10 +352,10 @@ do {									\
 	__typeof__(src) __pkn_src = (src);				\
 	int __pkn_err = 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_put_mem("str", *((type *)(__pkn_src)),			\
 		      (__force type *)(__pkn_dst), __pkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__pkn_err))					\
 		goto err_label;						\
diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/asm/word-at-a-time.h
index 1c8e4f2490bf..f3b151ed0d7a 100644
--- a/arch/arm64/include/asm/word-at-a-time.h
+++ b/arch/arm64/include/asm/word-at-a-time.h
@@ -55,7 +55,7 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 {
 	unsigned long ret;
 
-	__uaccess_enable_tco_async();
+	__mte_enable_tco_async();
 
 	/* Load word from unaligned pointer addr */
 	asm(
@@ -65,7 +65,7 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 	: "=&r" (ret)
 	: "r" (addr), "Q" (*(unsigned long *)addr));
 
-	__uaccess_disable_tco_async();
+	__mte_disable_tco_async();
 
 	return ret;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a48e7adce1248c0f9603a457776d59daa0ef734b.1678491668.git.andreyknvl%40google.com.
