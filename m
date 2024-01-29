Return-Path: <kasan-dev+bncBAABBXGY32WQMGQE2IQO6HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FDFE840754
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:10 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3638219eb79sf481845ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536029; cv=pass;
        d=google.com; s=arc-20160816;
        b=GHc1Ekc+0fs4tg5/xSvoQnRI4eohlGRLzWPIweGKNXk/QE/u7omDzHHC8TyQ/UVmXF
         ruzIGpwxksPUP8BncHhSV5DEWpapCJH5P8U12CYnUairu+COmb0UBoW40UoUa5EOfHO1
         Knv1YKSxKO5CkWNLDcIObAXwAhHQZPqAo4VrKJrv9h1iMRmblFZgiECzABiUfYuppZbl
         7JzmKG3vKLjYmVMVCWw9H4I5Gnk3WI6RVL8/79i/BVPTaYVxlT70MgIyQfctXAfHG3Pp
         2DKTrWFV82uZOYEOao3AAG8rtwTDpw5eqNUK4d7Z1Ud62N/BsY6lLOvbwQkB0/7JkIF3
         VSBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gV0J0/aO2Ua3YhGcKK2ns6V2iqi8OcJhIYKKLhbJWLc=;
        fh=Sd8hkMd3XUJ1lo7CezFFQtIAtPJ7NIMTiny/1zEEwko=;
        b=SD1Ef3zvZN/1BbIFIZrBCiu456dojiBhzsh2lA258VR3VRChtNv1l5gvE5eOdfbSzv
         TtdpYw7fevuVP3bxxMZQ35ukF7orhNbx6vN/ZHCi4d7Ru/lhq8vusWwJmtW9r4TWSYtL
         3W/hZY2mpai3aCztfh2WgHKNr+IV6WKmo/lEBfn+4k3moPXcvoIlepSvGcsU6svazgLX
         fRC7un8B3cs0pTYaaPOCyNakuGqGWQaIdt1Zt9zpyieNTF8a40bF4b3nH+IyjV4qRrpp
         yBWBV6G95GTv2IFbiMiURb2ynBdZECLxJTtO38Qy+1EBzYSyna23wfkKyW6ftEk22Ulr
         hShg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536029; x=1707140829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gV0J0/aO2Ua3YhGcKK2ns6V2iqi8OcJhIYKKLhbJWLc=;
        b=C4/3IHLRR7HVZj0OMK/pD0V9KnoegfdHNa0M5cAFpW9V8BhlZm4UB5uLQYGIuLRODj
         XPoOinNQY321efpJV/ps1BPsuWnDJ3rgvm7CV3cAXwjPVE61X9wPSN4uy8vpoHl+bQWm
         Cuu2m8aNBqxse/7/3Hq9KezShcY694ZEjyJZqr7Gjd8DA/si1Y/Z1x2OZef4iIvo2A3c
         R36CI7D71+7JM4Y+W/KEnmvqcuchNd462Ij5PF8fvQ0enB0UX6mV6Snuz3/WQRr5cfSX
         wp1L+m+UbObTe4c/Nt4gwKH/MplqXehdhg2XxJcrYFRtGvwnGAzL/CofdZIYJdTkASXq
         mnmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536029; x=1707140829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gV0J0/aO2Ua3YhGcKK2ns6V2iqi8OcJhIYKKLhbJWLc=;
        b=T4rL+CH96HtmE6w6GEnH2UeaaFR1SYo1tV2ImE1u6SM9KrJzhgQQ7sQwg3V/jz0vMv
         Nv/FlBVcJx5YzmRfiZ5o9MavMQvYZY0H95KrwTw//g+NfI86kIMlLPCMaDS+cFl+gi9j
         J8lO6ryK1A4krOxVpXKWhqhOc+WhWbbMZnuHBMwv7b/R1tQvvbEpz+oD7652absqrPdy
         9dDqZVXb/7P0lJY2nUYjhJmfRro/+QqWoBXY4JX8rbUr0PtXH1qhZEjZmfy+2wq2W2Xv
         hJb54CCDY1bfbnxL54pu6FSAUhzLVReVvHmCj3chIoxsYLJE+qcGT9QNjVNdsrjXls0N
         75Yw==
X-Gm-Message-State: AOJu0Yx89/Qu9uzFD+EFsNCDVYAJJaMIYPumONB8kbhNWyxefsQXRdDh
	6iXQBQ4N4Ye2ffA+QTp00ijbZtic9VWCoWpGMNaoq9pkTK6bdNuk
X-Google-Smtp-Source: AGHT+IFGvYak/cPD1p1UftuG2EKcD7krSFGhmCwlh+6qIBKlC0GeW3IecpJ0Xpq0bd/m6uuAKyHX/A==
X-Received: by 2002:a92:2807:0:b0:363:7de5:c85b with SMTP id l7-20020a922807000000b003637de5c85bmr188516ilf.18.1706536028859;
        Mon, 29 Jan 2024 05:47:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3d85:b0:210:d75d:5796 with SMTP id
 lm5-20020a0568703d8500b00210d75d5796ls1100126oab.2.-pod-prod-05-us; Mon, 29
 Jan 2024 05:47:07 -0800 (PST)
X-Received: by 2002:a05:6358:524b:b0:176:569f:8921 with SMTP id c11-20020a056358524b00b00176569f8921mr6406651rwa.56.1706536027703;
        Mon, 29 Jan 2024 05:47:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536027; cv=none;
        d=google.com; s=arc-20160816;
        b=PIfMcJuOK8ucDoLwapfaxk6h/8SluFqsSNs+5vyM3QCfbZLqfPeA87dan9DqOQi+xc
         h3omArg9/4HYo+/MT0Xt7htXLOX9hftPVCtvAdF8mY3VLyAljF8hfBRJMDovDYt7dTX9
         YjI+6fa5SG13YDn9IweIRIIlzjuYHrvoyNuj3wTwQXOAwiAQb4DLUyoVJ+5JSIlLXkVy
         2kcH+g0JKyUG7rUKmtQbTAQXhy+QpWWZ/T8Q2X9dm4PHX3gRuGFkRHRIPRh908P1UfI0
         2TrEiNnLIQNr/9mSdURFZ0+cJyfFtgmHdHSWrS8Ac8IJxHofgs39Ygcqbg+EpVMMAHlg
         nR9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=sZk81MB3F0fi4jLe+8qRvJk+fTfX2FXMCLP2DK+rkzY=;
        fh=Sd8hkMd3XUJ1lo7CezFFQtIAtPJ7NIMTiny/1zEEwko=;
        b=IndY+lUwFQvk7hkBHzcnR3tcH8axWwgh8IrwGlq4bR9Z2rbTDXnJaAWFVX4dlq49JT
         yjv6maoZxu41/opGJJNDjDCVNAhE9SMO3h5s4F63AvYTNcX0cDX27LNFJ7B9HC0DNEy2
         uDeEqgk9F/DsiRdGHgqbL2wPi23eZ8Qalv6ER1fZ0ZJCVYxVL2k5JLsBGSA7aweWUPee
         UrJyiiH0kxt7s6SzIG1/MBYUHMVToEhwwZdoXKPoNPAvpfymBWGcW3nZA4hIfpZnjC8L
         VCjw+nKPtI/BlTVy0tFTK4P3AqxjKW/9DLNPJsrwA0Iwst6H5k8wVvpYEsSvuyJ+1XzY
         BmUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCX9tKbvf+Ki+lcLzWsiIabpATZbTB3YJU3DMB1LWrt7hIrjobM47tzFMC1WBjLfacXy5kImxAcbvRR9mA2+oe+R5YbUJGrs340+nA==
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id x18-20020a056a00189200b006dbdb227dd5si527635pfh.0.2024.01.29.05.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:07 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.163.48])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4TNqN02YmzzbcRg;
	Mon, 29 Jan 2024 21:46:40 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id B5DC218007A;
	Mon, 29 Jan 2024 21:47:05 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:47:03 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 5/6] arm64: support copy_mc_[user]_highpage()
Date: Mon, 29 Jan 2024 21:46:51 +0800
Message-ID: <20240129134652.4004931-6-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240129134652.4004931-1-tongtiangen@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

Currently, many scenarios that can tolerate memory errors when copying page
have been supported in the kernel[1][2][3], all of which are implemented by
copy_mc_[user]_highpage(). arm64 should also support this mechanism.

Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
__HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.

Add new helper copy_mc_page() which provide a page copy implementation with
machine check safe. The copy_mc_page() in copy_mc_page.S is largely borrows
from copy_page() in copy_page.S and the main difference is copy_mc_page()
add extable entry to every load/store insn to support machine check safe.

Add new extable type EX_TYPE_COPY_MC_PAGE_ERR_ZERO which used in
copy_mc_page().

[1]a873dfe1032a ("mm, hwpoison: try to recover from copy-on write faults")
[2]5f2500b93cc9 ("mm/khugepaged: recover from poisoned anonymous memory")
[3]6b970599e807 ("mm: hwpoison: support recovery from ksm_might_need_to_copy()")

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/include/asm/asm-extable.h | 15 ++++++
 arch/arm64/include/asm/assembler.h   |  4 ++
 arch/arm64/include/asm/mte.h         |  5 ++
 arch/arm64/include/asm/page.h        | 10 ++++
 arch/arm64/lib/Makefile              |  2 +
 arch/arm64/lib/copy_mc_page.S        | 78 ++++++++++++++++++++++++++++
 arch/arm64/lib/mte.S                 | 27 ++++++++++
 arch/arm64/mm/copypage.c             | 66 ++++++++++++++++++++---
 arch/arm64/mm/extable.c              |  7 +--
 include/linux/highmem.h              |  8 +++
 10 files changed, 213 insertions(+), 9 deletions(-)
 create mode 100644 arch/arm64/lib/copy_mc_page.S

diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/asm/asm-extable.h
index 980d1dd8e1a3..819044fefbe7 100644
--- a/arch/arm64/include/asm/asm-extable.h
+++ b/arch/arm64/include/asm/asm-extable.h
@@ -10,6 +10,7 @@
 #define EX_TYPE_UACCESS_ERR_ZERO	2
 #define EX_TYPE_KACCESS_ERR_ZERO	3
 #define EX_TYPE_LOAD_UNALIGNED_ZEROPAD	4
+#define EX_TYPE_COPY_MC_PAGE_ERR_ZERO	5
 
 /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
 #define EX_DATA_REG_ERR_SHIFT	0
@@ -51,6 +52,16 @@
 #define _ASM_EXTABLE_UACCESS(insn, fixup)				\
 	_ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
 
+#define _ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, err, zero)	\
+	__ASM_EXTABLE_RAW(insn, fixup, 					\
+			  EX_TYPE_COPY_MC_PAGE_ERR_ZERO,		\
+			  (						\
+			    EX_DATA_REG(ERR, err) |			\
+			    EX_DATA_REG(ZERO, zero)			\
+			  ))
+
+#define _ASM_EXTABLE_COPY_MC_PAGE(insn, fixup)				\
+	_ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, wzr, wzr)
 /*
  * Create an exception table entry for uaccess `insn`, which will branch to `fixup`
  * when an unhandled fault is taken.
@@ -59,6 +70,10 @@
 	_ASM_EXTABLE_UACCESS(\insn, \fixup)
 	.endm
 
+	.macro          _asm_extable_copy_mc_page, insn, fixup
+	_ASM_EXTABLE_COPY_MC_PAGE(\insn, \fixup)
+	.endm
+
 /*
  * Create an exception table entry for `insn` if `fixup` is provided. Otherwise
  * do nothing.
diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
index 513787e43329..e1d8ce155878 100644
--- a/arch/arm64/include/asm/assembler.h
+++ b/arch/arm64/include/asm/assembler.h
@@ -154,6 +154,10 @@ lr	.req	x30		// link register
 #define CPU_LE(code...) code
 #endif
 
+#define CPY_MC(l, x...)		\
+9999:   x;			\
+	_asm_extable_copy_mc_page    9999b, l
+
 /*
  * Define a macro that constructs a 64-bit value by concatenating two
  * 32-bit registers. Note that on big endian systems the order of the
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 91fbd5c8a391..9cdded082dd4 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -92,6 +92,7 @@ static inline bool try_page_mte_tagging(struct page *page)
 void mte_zero_clear_page_tags(void *addr);
 void mte_sync_tags(pte_t pte, unsigned int nr_pages);
 void mte_copy_page_tags(void *kto, const void *kfrom);
+int mte_copy_mc_page_tags(void *kto, const void *kfrom);
 void mte_thread_init_user(void);
 void mte_thread_switch(struct task_struct *next);
 void mte_cpu_setup(void);
@@ -128,6 +129,10 @@ static inline void mte_sync_tags(pte_t pte, unsigned int nr_pages)
 static inline void mte_copy_page_tags(void *kto, const void *kfrom)
 {
 }
+static inline int mte_copy_mc_page_tags(void *kto, const void *kfrom)
+{
+	return 0;
+}
 static inline void mte_thread_init_user(void)
 {
 }
diff --git a/arch/arm64/include/asm/page.h b/arch/arm64/include/asm/page.h
index 2312e6ee595f..304cc86b8a10 100644
--- a/arch/arm64/include/asm/page.h
+++ b/arch/arm64/include/asm/page.h
@@ -29,6 +29,16 @@ void copy_user_highpage(struct page *to, struct page *from,
 void copy_highpage(struct page *to, struct page *from);
 #define __HAVE_ARCH_COPY_HIGHPAGE
 
+#ifdef CONFIG_ARCH_HAS_COPY_MC
+int copy_mc_page(void *to, const void *from);
+int copy_mc_highpage(struct page *to, struct page *from);
+#define __HAVE_ARCH_COPY_MC_HIGHPAGE
+
+int copy_mc_user_highpage(struct page *to, struct page *from,
+		unsigned long vaddr, struct vm_area_struct *vma);
+#define __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
+#endif
+
 struct folio *vma_alloc_zeroed_movable_folio(struct vm_area_struct *vma,
 						unsigned long vaddr);
 #define vma_alloc_zeroed_movable_folio vma_alloc_zeroed_movable_folio
diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
index 29490be2546b..a2fd865b816d 100644
--- a/arch/arm64/lib/Makefile
+++ b/arch/arm64/lib/Makefile
@@ -15,6 +15,8 @@ endif
 
 lib-$(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) += uaccess_flushcache.o
 
+lib-$(CONFIG_ARCH_HAS_COPY_MC) += copy_mc_page.o
+
 obj-$(CONFIG_CRC32) += crc32.o
 
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page.S
new file mode 100644
index 000000000000..524534d26d86
--- /dev/null
+++ b/arch/arm64/lib/copy_mc_page.S
@@ -0,0 +1,78 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (C) 2012 ARM Ltd.
+ */
+
+#include <linux/linkage.h>
+#include <linux/const.h>
+#include <asm/assembler.h>
+#include <asm/page.h>
+#include <asm/cpufeature.h>
+#include <asm/alternative.h>
+#include <asm/asm-extable.h>
+
+/*
+ * Copy a page from src to dest (both are page aligned) with machine check
+ *
+ * Parameters:
+ *	x0 - dest
+ *	x1 - src
+ * Returns:
+ * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
+ *	     while copying.
+ */
+SYM_FUNC_START(__pi_copy_mc_page)
+CPY_MC(9998f, ldp	x2, x3, [x1])
+CPY_MC(9998f, ldp	x4, x5, [x1, #16])
+CPY_MC(9998f, ldp	x6, x7, [x1, #32])
+CPY_MC(9998f, ldp	x8, x9, [x1, #48])
+CPY_MC(9998f, ldp	x10, x11, [x1, #64])
+CPY_MC(9998f, ldp	x12, x13, [x1, #80])
+CPY_MC(9998f, ldp	x14, x15, [x1, #96])
+CPY_MC(9998f, ldp	x16, x17, [x1, #112])
+
+	add	x0, x0, #256
+	add	x1, x1, #128
+1:
+	tst	x0, #(PAGE_SIZE - 1)
+
+CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
+CPY_MC(9998f, ldp	x2, x3, [x1])
+CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
+CPY_MC(9998f, ldp	x4, x5, [x1, #16])
+CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
+CPY_MC(9998f, ldp	x6, x7, [x1, #32])
+CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
+CPY_MC(9998f, ldp	x8, x9, [x1, #48])
+CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
+CPY_MC(9998f, ldp	x10, x11, [x1, #64])
+CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
+CPY_MC(9998f, ldp	x12, x13, [x1, #80])
+CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
+CPY_MC(9998f, ldp	x14, x15, [x1, #96])
+CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
+CPY_MC(9998f, ldp	x16, x17, [x1, #112])
+
+	add	x0, x0, #128
+	add	x1, x1, #128
+
+	b.ne	1b
+
+CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
+CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
+CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
+CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
+CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
+CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
+CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
+CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
+
+	mov x0, #0
+	ret
+
+9998:	mov x0, #-EFAULT
+	ret
+
+SYM_FUNC_END(__pi_copy_mc_page)
+SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
+EXPORT_SYMBOL(copy_mc_page)
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 5018ac03b6bf..2b748e83f6cf 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -80,6 +80,33 @@ SYM_FUNC_START(mte_copy_page_tags)
 	ret
 SYM_FUNC_END(mte_copy_page_tags)
 
+/*
+ * Copy the tags from the source page to the destination one wiht machine check safe
+ *   x0 - address of the destination page
+ *   x1 - address of the source page
+ * Returns:
+ *   x0 - Return 0 if copy success, or
+ *        -EFAULT if anything goes wrong while copying.
+ */
+SYM_FUNC_START(mte_copy_mc_page_tags)
+	mov	x2, x0
+	mov	x3, x1
+	multitag_transfer_size x5, x6
+1:
+CPY_MC(2f, ldgm	x4, [x3])
+CPY_MC(2f, stgm	x4, [x2])
+	add	x2, x2, x5
+	add	x3, x3, x5
+	tst	x2, #(PAGE_SIZE - 1)
+	b.ne	1b
+
+	mov x0, #0
+	ret
+
+2:	mov x0, #-EFAULT
+	ret
+SYM_FUNC_END(mte_copy_mc_page_tags)
+
 /*
  * Read tags from a user buffer (one tag per byte) and set the corresponding
  * tags at the given kernel address. Used by PTRACE_POKEMTETAGS.
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index a7bb20055ce0..9765e40cde6c 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -14,6 +14,25 @@
 #include <asm/cpufeature.h>
 #include <asm/mte.h>
 
+static int do_mte(struct page *to, struct page *from, void *kto, void *kfrom, bool mc)
+{
+	int ret = 0;
+
+	if (system_supports_mte() && page_mte_tagged(from)) {
+		/* It's a new page, shouldn't have been tagged yet */
+		WARN_ON_ONCE(!try_page_mte_tagging(to));
+		if (mc)
+			ret = mte_copy_mc_page_tags(kto, kfrom);
+		else
+			mte_copy_page_tags(kto, kfrom);
+
+		if (!ret)
+			set_page_mte_tagged(to);
+	}
+
+	return ret;
+}
+
 void copy_highpage(struct page *to, struct page *from)
 {
 	void *kto = page_address(to);
@@ -24,12 +43,7 @@ void copy_highpage(struct page *to, struct page *from)
 	if (kasan_hw_tags_enabled())
 		page_kasan_tag_reset(to);
 
-	if (system_supports_mte() && page_mte_tagged(from)) {
-		/* It's a new page, shouldn't have been tagged yet */
-		WARN_ON_ONCE(!try_page_mte_tagging(to));
-		mte_copy_page_tags(kto, kfrom);
-		set_page_mte_tagged(to);
-	}
+	do_mte(to, from, kto, kfrom, false);
 }
 EXPORT_SYMBOL(copy_highpage);
 
@@ -40,3 +54,43 @@ void copy_user_highpage(struct page *to, struct page *from,
 	flush_dcache_page(to);
 }
 EXPORT_SYMBOL_GPL(copy_user_highpage);
+
+#ifdef CONFIG_ARCH_HAS_COPY_MC
+/*
+ * Return -EFAULT if anything goes wrong while copying page or mte.
+ */
+int copy_mc_highpage(struct page *to, struct page *from)
+{
+	void *kto = page_address(to);
+	void *kfrom = page_address(from);
+	int ret;
+
+	ret = copy_mc_page(kto, kfrom);
+	if (ret)
+		return -EFAULT;
+
+	if (kasan_hw_tags_enabled())
+		page_kasan_tag_reset(to);
+
+	ret = do_mte(to, from, kto, kfrom, true);
+	if (ret)
+		return -EFAULT;
+
+	return 0;
+}
+EXPORT_SYMBOL(copy_mc_highpage);
+
+int copy_mc_user_highpage(struct page *to, struct page *from,
+			unsigned long vaddr, struct vm_area_struct *vma)
+{
+	int ret;
+
+	ret = copy_mc_highpage(to, from);
+
+	if (!ret)
+		flush_dcache_page(to);
+
+	return ret;
+}
+EXPORT_SYMBOL_GPL(copy_mc_user_highpage);
+#endif
diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
index 28ec35e3d210..bdc81518d207 100644
--- a/arch/arm64/mm/extable.c
+++ b/arch/arm64/mm/extable.c
@@ -16,7 +16,7 @@ get_ex_fixup(const struct exception_table_entry *ex)
 	return ((unsigned long)&ex->fixup + ex->fixup);
 }
 
-static bool ex_handler_uaccess_err_zero(const struct exception_table_entry *ex,
+static bool ex_handler_fixup_err_zero(const struct exception_table_entry *ex,
 					struct pt_regs *regs)
 {
 	int reg_err = FIELD_GET(EX_DATA_REG_ERR, ex->data);
@@ -69,7 +69,7 @@ bool fixup_exception(struct pt_regs *regs)
 		return ex_handler_bpf(ex, regs);
 	case EX_TYPE_UACCESS_ERR_ZERO:
 	case EX_TYPE_KACCESS_ERR_ZERO:
-		return ex_handler_uaccess_err_zero(ex, regs);
+		return ex_handler_fixup_err_zero(ex, regs);
 	case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
 		return ex_handler_load_unaligned_zeropad(ex, regs);
 	}
@@ -87,7 +87,8 @@ bool fixup_exception_mc(struct pt_regs *regs)
 
 	switch (ex->type) {
 	case EX_TYPE_UACCESS_ERR_ZERO:
-		return ex_handler_uaccess_err_zero(ex, regs);
+	case EX_TYPE_COPY_MC_PAGE_ERR_ZERO:
+		return ex_handler_fixup_err_zero(ex, regs);
 	}
 
 	return false;
diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index c5ca1a1fc4f5..a42470ca42f2 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -332,6 +332,7 @@ static inline void copy_highpage(struct page *to, struct page *from)
 #endif
 
 #ifdef copy_mc_to_kernel
+#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
 /*
  * If architecture supports machine check exception handling, define the
  * #MC versions of copy_user_highpage and copy_highpage. They copy a memory
@@ -354,7 +355,9 @@ static inline int copy_mc_user_highpage(struct page *to, struct page *from,
 
 	return ret ? -EFAULT : 0;
 }
+#endif
 
+#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
 static inline int copy_mc_highpage(struct page *to, struct page *from)
 {
 	unsigned long ret;
@@ -370,20 +373,25 @@ static inline int copy_mc_highpage(struct page *to, struct page *from)
 
 	return ret ? -EFAULT : 0;
 }
+#endif
 #else
+#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
 static inline int copy_mc_user_highpage(struct page *to, struct page *from,
 					unsigned long vaddr, struct vm_area_struct *vma)
 {
 	copy_user_highpage(to, from, vaddr, vma);
 	return 0;
 }
+#endif
 
+#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
 static inline int copy_mc_highpage(struct page *to, struct page *from)
 {
 	copy_highpage(to, from);
 	return 0;
 }
 #endif
+#endif
 
 static inline void memcpy_page(struct page *dst_page, size_t dst_off,
 			       struct page *src_page, size_t src_off,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-6-tongtiangen%40huawei.com.
