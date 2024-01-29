Return-Path: <kasan-dev+bncBAABBV6Y32WQMGQEQAUOMQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA9F3840751
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:04 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3637aa8a40dsf5448065ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536023; cv=pass;
        d=google.com; s=arc-20160816;
        b=gj2qhNv2m1yodgcUQ3WV3k7tT4JSGOLajd2i/rhECz4BdP24Ed4vaS2e4qzQI4jyzl
         uCk1EpfJDquzLVsNniRvuQxR9H8XwWr4PAMfkuPPy8Qk5XZs0thbx2IEv+aMVW2cqndA
         6/B58Rw8WNqFJsjo36v1eAlOax8//RQCddaoYbVcX4OwY4LG2i4Vmp8VJOfWVh5nkuWn
         EdtGxU0oBH7//4VLry3HjycWSs+c9BFkV9yMlLkr4H2KPy9QznCLPcYjqa2d4+UX2O9L
         ZGzDMNrHMtbCkDBp05gpKOCSpB3Lk6dnk2H/fe5o3QsQxirTerIJo35AYBlxGQKO8osE
         5fpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=cqeCogovK7gD8z4Y5UGodXe4JDX8Mf2e6ToqNOVyoP4=;
        fh=aljRTGteZBhLwyP87MXio5g7ySkxaOapQhKDab3QWEA=;
        b=JPtMJkYz2saRJSFtHJ9VrRydINVWsertKJm0Cf8LpiELtNL0AmBsoHCf+PFMluNKzd
         jLcaeteqshxK05K56owai7oCMz3mDpTOV2QekLrbOvnjQ/pBmF3xgYafX/w2Dgvdo8Bu
         PvV4Jyv1axv5nsP4lpAvNpINXXzkrLC33mKqUhr72nFpMyrOPmnJ/10EGnF57gHcYH2Z
         2vUr9KtP6RwIxh1TKjg3B+ccNdxX5jRd2TPajP99Ve0arAsxwO7pfiLVhs0Pc5rJ12Qp
         cd3TbSRQtY0yYlsl+mjn1jYOyiBi8pZsPSZQOsFCEFMu8I1Q4fmox1AXo3tykU/q9Nc4
         BGgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536023; x=1707140823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cqeCogovK7gD8z4Y5UGodXe4JDX8Mf2e6ToqNOVyoP4=;
        b=ArS4slvLj6hsqlSiV04c3TWpZQQLHjopMroVNd1m8V9tMsLJoWboDYh2D3LksaS0/0
         z8OvJ7UDyUqKB81NwsWGdXjjJ2owP9p2tnT5jyNiOFjL8fDw3c/7RWmj3B4Q1PXMgwWt
         CwzGKucDdsnDOMafpH0RuH2y72uPuDEJd17tk9EiwvPLdHKgNKLPkwQJ5VLGFpfAz6RI
         riZtSZafoePvQNpl8NLxVK3ZeDUwe8CUYVqNTuVdwev9M7mqYRaU65GPAYpn8M/MLmf1
         NVoV1l8C1U9gvUEu64goXTaFU+1/6Tnf37BbavHyxYw68qiPYVf8oi+r+qt7JSmVdGd8
         C1qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536023; x=1707140823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cqeCogovK7gD8z4Y5UGodXe4JDX8Mf2e6ToqNOVyoP4=;
        b=hM/UWSLC1FRZ32pn5Bxj/HJ3w25l51o5oyyYOVMWjmZPU1UUrrawseCSFlHrcv+ffr
         AJpvvKIUgx3K3JB5L48wlQbP7VrpwXETzteQbLA1L4YG3ly5eLz8gilNan0LX8VX4vfD
         iQdDDfouMxSPesf2yth6XpDk69j7Eo86ntBfF2/UuVrVAT1Wr7j4dnthW5MJM/RLun7w
         OBuE99R1sTPw3FtNdHn1W5Ma+NOaE62Ew+Wag+rzdp1phf3pD5i//frv+Uv+T9FvbgPb
         r80WBb/u2XLwEKdATJoQxgV2gPgsI5c/5iIwFyAexdYnHb3iAqHk50J2aY0fRmvU/VoP
         ii8w==
X-Gm-Message-State: AOJu0Yx6e2o48HtCe9gTHCmqzSWlTsWhkMTI0Ds/CWnUA/VqzIcqm2IU
	5+iYqt0auk2Vo5R3pLGe3iLXJwovqOAwJgvGkrlu+ZRzaH/RA/SZyB8=
X-Google-Smtp-Source: AGHT+IG3NJp77tww20JM8o5UZw/aG88jfU6Y9B7HL3DBtTu6SalYSNPKfOE/r7Xjrq2VVFdaXiD/qw==
X-Received: by 2002:a05:6e02:1845:b0:362:cfd7:37a2 with SMTP id b5-20020a056e02184500b00362cfd737a2mr6316517ilv.31.1706536023519;
        Mon, 29 Jan 2024 05:47:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3520:b0:363:846b:1129 with SMTP id
 bu32-20020a056e02352000b00363846b1129ls179451ilb.0.-pod-prod-04-us; Mon, 29
 Jan 2024 05:47:02 -0800 (PST)
X-Received: by 2002:a92:ce52:0:b0:363:7777:658f with SMTP id a18-20020a92ce52000000b003637777658fmr4433631ilr.11.1706536022742;
        Mon, 29 Jan 2024 05:47:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536022; cv=none;
        d=google.com; s=arc-20160816;
        b=vIe7E6jLX1drojuuP14WPGE3i/DEhunrEuw0mltPQEx3BYqXlyv2O9ilIgY/fi+m4q
         zHWaA6ak67nGlQXfmWd7kTPbgrkRmsmPrTjIyavCbtL6t4iSdEdODn7bTyyQ8/yN6871
         HiIdD+zCSGin+3GkuuP6JxSjdvYLC7yz9WLGhh3pA5N2ZHZTxsNqIL0N43ugHuBi72NR
         RNHrTSfDFG+lbzFboW/Vff7Dq5IFTgCCttpQwlfTpLPNA/6M+v7WgyD2bF/zyDfrVqLH
         RgWHF/NXhSSGgMw/vkqkEi9hv7VC8sYwm5S9WmQOnWqGSCJnhgA5MkDK59lsVitCtZib
         6pEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Sze+W7/VXzN9lUi+wiYHH7plMoEL8Mu63vaCr1k3jh4=;
        fh=aljRTGteZBhLwyP87MXio5g7ySkxaOapQhKDab3QWEA=;
        b=vYHt4DU4601zF+5y3zvNuSDhD7mCc8OhwSA2VJICYWLdHnqq7KlWzwrDDjONSDBh5P
         szQx8rbwYVh8X3Tcu9/pq+jUTzYU6eLu4QELISs0P/WxgCOYuqPIYldzWJ+c/o5+Wq7k
         YTv++iLwtXgA84Y+iOPFEjtWVg31gyxC3K/NdOAIrjx9GpITZaUoEXkxb0jRfBZCUSl2
         rWWP5DEDYiT7scvB0NREfno3weGyyKpC0/axrQL++Yhvxum7EtwekAO4fzXjkq3Z+rgm
         PppSPdUzva4ja9ls1pScx2oIjcM4J/Yiqs3+9ncVk6JGpomh+5f6n4JZfkZkdTdSrSBZ
         bvag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCUvrmKabKPOD/z52Su3XWB53yQ9gRkaO/469Sz6htLWUM0uS6fsX6lw5HY3jTwolLcC0h/JpdVzJs2gR8LdwjyY1SLCE5YbLUUMTQ==
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id h9-20020a926c09000000b00361a8692358si532536ilc.2.2024.01.29.05.47.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:02 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.163.48])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4TNqMF3pN7zNkcY;
	Mon, 29 Jan 2024 21:46:01 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id DA46B18005E;
	Mon, 29 Jan 2024 21:46:59 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:46:57 +0800
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
Subject: [PATCH v10 2/6] arm64: add support for machine check error safe
Date: Mon, 29 Jan 2024 21:46:48 +0800
Message-ID: <20240129134652.4004931-3-tongtiangen@huawei.com>
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
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as
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

For the arm64 kernel, when it processes hardware memory errors for
synchronize notifications(do_sea()), if the errors is consumed within the
kernel, the current processing is panic. However, it is not optimal.

Take uaccess for example, if the uaccess operation fails due to memory
error, only the user process will be affected. Killing the user process and
isolating the corrupt page is a better choice.

This patch only enable machine error check framework and adds an exception
fixup before the kernel panic in do_sea().

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/Kconfig               |  1 +
 arch/arm64/include/asm/extable.h |  1 +
 arch/arm64/mm/extable.c          | 16 ++++++++++++++++
 arch/arm64/mm/fault.c            | 29 ++++++++++++++++++++++++++++-
 4 files changed, 46 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index aa7c1d435139..2cc34b5e7abb 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -20,6 +20,7 @@ config ARM64
 	select ARCH_ENABLE_SPLIT_PMD_PTLOCK if PGTABLE_LEVELS > 2
 	select ARCH_ENABLE_THP_MIGRATION if TRANSPARENT_HUGEPAGE
 	select ARCH_HAS_CACHE_LINE_SIZE
+	select ARCH_HAS_COPY_MC if ACPI_APEI_GHES
 	select ARCH_HAS_CURRENT_STACK_POINTER
 	select ARCH_HAS_DEBUG_VIRTUAL
 	select ARCH_HAS_DEBUG_VM_PGTABLE
diff --git a/arch/arm64/include/asm/extable.h b/arch/arm64/include/asm/extable.h
index 72b0e71cc3de..f80ebd0addfd 100644
--- a/arch/arm64/include/asm/extable.h
+++ b/arch/arm64/include/asm/extable.h
@@ -46,4 +46,5 @@ bool ex_handler_bpf(const struct exception_table_entry *ex,
 #endif /* !CONFIG_BPF_JIT */
 
 bool fixup_exception(struct pt_regs *regs);
+bool fixup_exception_mc(struct pt_regs *regs);
 #endif
diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
index 228d681a8715..478e639f8680 100644
--- a/arch/arm64/mm/extable.c
+++ b/arch/arm64/mm/extable.c
@@ -76,3 +76,19 @@ bool fixup_exception(struct pt_regs *regs)
 
 	BUG();
 }
+
+bool fixup_exception_mc(struct pt_regs *regs)
+{
+	const struct exception_table_entry *ex;
+
+	ex = search_exception_tables(instruction_pointer(regs));
+	if (!ex)
+		return false;
+
+	/*
+	 * This is not complete, More Machine check safe extable type can
+	 * be processed here.
+	 */
+
+	return false;
+}
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 55f6455a8284..312932dc100b 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -730,6 +730,31 @@ static int do_bad(unsigned long far, unsigned long esr, struct pt_regs *regs)
 	return 1; /* "fault" */
 }
 
+static bool arm64_do_kernel_sea(unsigned long addr, unsigned int esr,
+				     struct pt_regs *regs, int sig, int code)
+{
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
+		return false;
+
+	if (user_mode(regs))
+		return false;
+
+	if (apei_claim_sea(regs) < 0)
+		return false;
+
+	if (!fixup_exception_mc(regs))
+		return false;
+
+	if (current->flags & PF_KTHREAD)
+		return true;
+
+	set_thread_esr(0, esr);
+	arm64_force_sig_fault(sig, code, addr,
+		"Uncorrected memory error on access to user memory\n");
+
+	return true;
+}
+
 static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *regs)
 {
 	const struct fault_info *inf;
@@ -755,7 +780,9 @@ static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *regs)
 		 */
 		siaddr  = untagged_addr(far);
 	}
-	arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
+
+	if (!arm64_do_kernel_sea(siaddr, esr, regs, inf->sig, inf->code))
+		arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
 
 	return 0;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-3-tongtiangen%40huawei.com.
