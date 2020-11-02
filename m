Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEG4QD6QKGQEGI55HUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id A51792A2EF2
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:33 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id c196sf14798232ybf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333072; cv=pass;
        d=google.com; s=arc-20160816;
        b=qub0T8W6yDZxOYN8a3wP2e6VWSG2JJJ2IrIk3zb2JZf+JckoMmXvqzMDC923MpUO5d
         wx/en9xes+16l7xIb7gzWSJ5OMP/9v1JYwF6bycn4fvfjm5st6TdC+kHhnlEWRdbT/Ew
         5xZQfP7mW2+R3u0ixtTTHBZp0BD/TwryKECCWwrPGNBhaTJqiFeslV6Z+6c7Qw8Qw4av
         jqVX/z1tndmwLxsAxL+GbSnuUJoKQrOifwahwtGoBqH5cQNAJ0qFjjAESoa+TbVUd1dn
         SG2iussvabruYx18zPwOdM1bzW6xgReqawMBoI+CaZwN4k0ytbMkSjulzpjSXPHRRgC9
         g1/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+qsWzZO5YPh89owQi2JRmW0GjAeUhXgqeV6CSf6ybhU=;
        b=H7tgMe/XXmCPWSjtfcD8d9CLmDoK4qSRC7uQexvmb0vCnR7LxB8oe/SjA7ge+758eR
         nHJWPgY0yTl5lGkYwVEbbsKAvU27XFjq+bpmrhCUPh1JtdHioKaITpwWV+dIflN4LgtN
         BFRkI9AQR+NcHS7pwKPZJQmKVmvX0HTnfjsi9mIljmz31dcXzEHED1rP84TL6H4K3uZ+
         Sv7dxwLeBgKenRwg6JaEt9pXN+7K2y4VRdj/Do0hFjydU+AsSDe/EygidMDYI59CsgCW
         J2mEpwP2b+nY7eX8fiTEW6eoleUFxkD9OuzqEH61JRJ4wPj22kr+mnX8yIJkJp8uIP8w
         lYzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PJ6EtMCW;
       spf=pass (google.com: domain of 3dy6gxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Dy6gXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+qsWzZO5YPh89owQi2JRmW0GjAeUhXgqeV6CSf6ybhU=;
        b=HuMpK7kfLOcuTB09N0i98ryOZTMGnJea0/0qabNS72NdFcBTnrmWeaXl5pwOWm48VR
         mzY0/Y85RttMicDlL8+eNTgr70+bZOeFdMB/Jh1kBq22LHR+mkSI18adRTs+TMTf4VPT
         PNxhlnLJgLOaaa8XqiEizLulZgibm6xIBQxLPx4m2I1PJYzIOj1VBDqNicP6JIhZfjJt
         B3m9YIhk3Pj8WTq94P7gDtcZBhKe2r4uZCUhLcpQHvZkxm2Ck6WtPEBbcHpIjl3Hk74H
         66F0T4ozOXeprdJ7QbUMOedpXTSfU8QwgXWoGv831htsYm73uQsIsv4LEbAPAexHUqi1
         wXZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qsWzZO5YPh89owQi2JRmW0GjAeUhXgqeV6CSf6ybhU=;
        b=oQnnOzxe7LG6mvHuM+tUaCJ5vr3ZhTg3H0NxIhHsBRCL265SXBOkFmT6a5R+i1URqz
         ZFZGiG42qiWxucj74/UubOnnzu1msWbWozXt5U9UcMiENNArQ3Cgb1/+RHeMfGTv28L8
         NKRowL90vnHhMe3Iw8HuZHiQmGZNwdix7R8x7TnOc3X/5lluqFLuRZZ8qTWgK0DrlXoL
         hGzah4aJA0IoPBnrlzfs4gcaLacQrGps9HL3GyerNo1m/bQA9HVzUetiT7HdnURsB7jN
         eYDzL6CYs6AJri6/twLoTWHoIgjuHzC/UHkOxLbXH7GLchWXaxJsLt4A+j5x1IfFqXmR
         vLjw==
X-Gm-Message-State: AOAM532kA5YZM51/nOn7uCPI1PT2wOEUhoVRQaAbzPLWunsVHSAQvM52
	k9hB5xvRBcCk7Mr4jjDslzU=
X-Google-Smtp-Source: ABdhPJwngeoMsmt9ZVM3GOdC+rVY4rFKNDo+pou7LAv1FX4cDXrLzOYxyUc3OJ5PhKC7fdBVl+Ppng==
X-Received: by 2002:a25:2d5e:: with SMTP id s30mr21135222ybe.61.1604333072562;
        Mon, 02 Nov 2020 08:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a0b:: with SMTP id q11ls6867269ybq.8.gmail; Mon, 02 Nov
 2020 08:04:32 -0800 (PST)
X-Received: by 2002:a25:4cc7:: with SMTP id z190mr21972848yba.405.1604333072054;
        Mon, 02 Nov 2020 08:04:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333072; cv=none;
        d=google.com; s=arc-20160816;
        b=q5UApAtblCKTxCej8wmqKRZ205ZU/iWGBjsJORPjWYHTkQyvvrCzqzCVXhoFqC0Zn0
         CY0Bp2B9A6WJ8MeqRW4RT1j38QcMgbl0yrr6+cX7D31vHI33P9m+mOXjfXoH0aOkbjUo
         bd9n/4LFcxQeq/yWxALntVPIIPNMbUVI+226EAVn9DWFzElanK5hqYftbwwbDoPB6xr7
         vOLS9XZJRdu3esjq6dimVWO8vFuoLg9FFUiMdbPkSGxHxtLNThgc3eaVZcKsI+5BQyqX
         4ILjwnsHALWzUVWskX5NMSeZAVYkssmU5g15i3Vt13pjGD9BQBIvulSaSlLwqikFG88j
         igAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iKiZmQLw/RkryeoFhlFWSKbY6lm99BwbnzE2uZJZe40=;
        b=0HtCPHtzng0+haNx4lM5zxTH5LFXC+PGwSssqj40iueW0tBrGTjKB07S2dcLAZ367S
         5DH/yRhcCN2dqHVD0oUn8KT304NGj720RZMF/2pOHyTcYkN/2Yf8/j63oGOKxwAI7yL0
         NQxovpwTSiLk8dknxlMDS6+ZuiPMBmn54aRVdDDUip9FC0qQxGMRQCFFAk1HqVTQHEP2
         yNHDBgJbjDSS65hS4kVqzlz7PsEIlcT7sWLBy6CvEb2hEfwje0f/tdSmhBJy58GkOLME
         z30yqFgaSEImziXgoSz7ZL/thrcvGdHZEtl4pimssIF4OMjNsT5bZDRcAqH1Jw4L9FSW
         QYKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PJ6EtMCW;
       spf=pass (google.com: domain of 3dy6gxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Dy6gXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id t12si996561ybp.2.2020.11.02.08.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dy6gxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id v134so8958227qka.19
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a166:: with SMTP id
 d93mr22483453qva.22.1604333071649; Mon, 02 Nov 2020 08:04:31 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:42 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <ba603a59698d146e81afcead5de66cd053eaafd7.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 02/41] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=PJ6EtMCW;       spf=pass
 (google.com: domain of 3dy6gxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Dy6gXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Provide helper functions to manipulate allocation and pointer tags for
kernel addresses.

Low-level helper functions (mte_assign_*, written in assembly) operate
tag values from the [0x0, 0xF] range. High-level helper functions
(mte_get/set_*) use the [0xF0, 0xFF] range to preserve compatibility
with normal kernel pointers that have 0xFF in their top byte.

MTE_GRANULE_SIZE and related definitions are moved to mte-def.h header
that doesn't have any dependencies and is safe to include into any
low-level header.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I1b5230254f90dc21a913447cb17f07fea7944ece
---
 arch/arm64/include/asm/esr.h       |  1 +
 arch/arm64/include/asm/mte-def.h   | 15 ++++++++
 arch/arm64/include/asm/mte-kasan.h | 56 ++++++++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h       | 20 +++++++----
 arch/arm64/kernel/mte.c            | 48 +++++++++++++++++++++++++
 arch/arm64/lib/mte.S               | 16 +++++++++
 6 files changed, 150 insertions(+), 6 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-def.h
 create mode 100644 arch/arm64/include/asm/mte-kasan.h

diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
index 22c81f1edda2..971c20ddfed4 100644
--- a/arch/arm64/include/asm/esr.h
+++ b/arch/arm64/include/asm/esr.h
@@ -105,6 +105,7 @@
 #define ESR_ELx_FSC		(0x3F)
 #define ESR_ELx_FSC_TYPE	(0x3C)
 #define ESR_ELx_FSC_EXTABT	(0x10)
+#define ESR_ELx_FSC_MTE		(0x11)
 #define ESR_ELx_FSC_SERROR	(0x11)
 #define ESR_ELx_FSC_ACCESS	(0x08)
 #define ESR_ELx_FSC_FAULT	(0x04)
diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
new file mode 100644
index 000000000000..8401ac5840c7
--- /dev/null
+++ b/arch/arm64/include/asm/mte-def.h
@@ -0,0 +1,15 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_DEF_H
+#define __ASM_MTE_DEF_H
+
+#define MTE_GRANULE_SIZE	UL(16)
+#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
+#define MTE_TAG_SHIFT		56
+#define MTE_TAG_SIZE		4
+#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
+#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
+
+#endif /* __ASM_MTE_DEF_H  */
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
new file mode 100644
index 000000000000..3a70fb1807fd
--- /dev/null
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -0,0 +1,56 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_KASAN_H
+#define __ASM_MTE_KASAN_H
+
+#include <asm/mte-def.h>
+
+#ifndef __ASSEMBLY__
+
+#include <linux/types.h>
+
+/*
+ * The functions below are meant to be used only for the
+ * KASAN_HW_TAGS interface defined in asm/memory.h.
+ */
+#ifdef CONFIG_ARM64_MTE
+
+static inline u8 mte_get_ptr_tag(void *ptr)
+{
+	/* Note: The format of KASAN tags is 0xF<x> */
+	u8 tag = 0xF0 | (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
+
+	return tag;
+}
+
+u8 mte_get_mem_tag(void *addr);
+u8 mte_get_random_tag(void);
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+
+#else /* CONFIG_ARM64_MTE */
+
+static inline u8 mte_get_ptr_tag(void *ptr)
+{
+	return 0xFF;
+}
+
+static inline u8 mte_get_mem_tag(void *addr)
+{
+	return 0xFF;
+}
+static inline u8 mte_get_random_tag(void)
+{
+	return 0xFF;
+}
+static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	return addr;
+}
+
+#endif /* CONFIG_ARM64_MTE */
+
+#endif /* __ASSEMBLY__ */
+
+#endif /* __ASM_MTE_KASAN_H  */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 1c99fcadb58c..cf1cd181dcb2 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -5,14 +5,16 @@
 #ifndef __ASM_MTE_H
 #define __ASM_MTE_H
 
-#define MTE_GRANULE_SIZE	UL(16)
-#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
-#define MTE_TAG_SHIFT		56
-#define MTE_TAG_SIZE		4
+#include <asm/compiler.h>
+#include <asm/mte-def.h>
+
+#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
 
 #ifndef __ASSEMBLY__
 
+#include <linux/bitfield.h>
 #include <linux/page-flags.h>
+#include <linux/types.h>
 
 #include <asm/pgtable-types.h>
 
@@ -45,7 +47,9 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-#else
+void mte_assign_mem_tag_range(void *addr, size_t size);
+
+#else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
 #define PG_mte_tagged	0
@@ -80,7 +84,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 	return -EIO;
 }
 
-#endif
+static inline void mte_assign_mem_tag_range(void *addr, size_t size)
+{
+}
+
+#endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 52a0638ed967..8f99c65837fd 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -13,10 +13,13 @@
 #include <linux/swap.h>
 #include <linux/swapops.h>
 #include <linux/thread_info.h>
+#include <linux/types.h>
 #include <linux/uio.h>
 
+#include <asm/barrier.h>
 #include <asm/cpufeature.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
@@ -72,6 +75,51 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+u8 mte_get_mem_tag(void *addr)
+{
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm(__MTE_PREAMBLE "ldg %0, [%0]"
+	    : "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+u8 mte_get_random_tag(void)
+{
+	void *addr;
+
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm(__MTE_PREAMBLE "irg %0, %0"
+	    : "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	void *ptr = addr;
+
+	if ((!system_supports_mte()) || (size == 0))
+		return addr;
+
+	/* Make sure that size is MTE granule aligned. */
+	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
+
+	/* Make sure that the address is MTE granule aligned. */
+	WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
+
+	tag = 0xF0 | tag;
+	ptr = (void *)__tag_set(ptr, tag);
+
+	mte_assign_mem_tag_range(ptr, size);
+
+	return ptr;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 03ca6d8b8670..ede1ea65428c 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,3 +149,19 @@ SYM_FUNC_START(mte_restore_page_tags)
 
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag
+ *   x0 - source pointer
+ *   x1 - size
+ *
+ * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+ * size must be non-zero and MTE_GRANULE_SIZE aligned.
+ */
+SYM_FUNC_START(mte_assign_mem_tag_range)
+1:	stg	x0, [x0]
+	add	x0, x0, #MTE_GRANULE_SIZE
+	subs	x1, x1, #MTE_GRANULE_SIZE
+	b.gt	1b
+	ret
+SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba603a59698d146e81afcead5de66cd053eaafd7.1604333009.git.andreyknvl%40google.com.
