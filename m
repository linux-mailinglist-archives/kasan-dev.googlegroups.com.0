Return-Path: <kasan-dev+bncBAABBQGHSKBQMGQECWHQ6LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C2F6E35047E
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:30:57 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y16sf1721565pfm.11
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208256; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqgaJgS8BwzGtEOutPko4RsmASjcVngyvkQdQZ175J2LOev30jPZK+55fLfgV6nKG2
         UeP35nTAjwrewRVX57exsxnacbd347k5ZQ1BsOkw0axWON+CyTBRABRa5v03uMj4AaVQ
         Gtb17gYuk/kZ7tdcccDLrbydvHquqS9bjTsYMov6VdMhe7zNWmZ4qu39mfpfXkKuXWR4
         vr+BGSxbk2tk0b9xoWETxSfBWHzRQOtdRw6vfh00lggvBeME53+/qz+ZNMoLK+dCUQwH
         DXzll5tM68Hx7Sa/irdTaBfEPoCiKWvk7EaIzZx0PFCFdqeY9gMjH74hmolOg9PfwnMS
         IiiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Hm5dDbuw3DQFJ3Ul6ZN5X8EtIWx6/5WaS9fpPi4RVvY=;
        b=0O3JFahzwetJ5B80BV1SfEumX7sDq6YU+pDpkUx1LPjb68lI5usiCcuR9TbE1lcc84
         Po+BpGgUe6exqAcxrUCmMrpdge7Tmz4pDHI+a6+kDHzYkrx6sWnqVZVKRY+iC/SkLBio
         DFgBZNhdWJEgjSvn2Eewk6zuKmNqXNgywwGs01krQe9ySu8OAh1MMyHKT3g2C+qqkXkd
         Fe4sXKgD6yO6g0J4KxbrNEst1VpuNmlKGJ6cIjh6eqXbYKw8ER2dpz+KBnCBYXC58VCT
         w8+TLiL2jhkLtNiOYP+0M6umUJGFulfWGT+bY9Mbh+dB88+Msp3ECmLCkgYfU10UZmzW
         pOmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=DfLjKNIt;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hm5dDbuw3DQFJ3Ul6ZN5X8EtIWx6/5WaS9fpPi4RVvY=;
        b=dBEZz8+Cj6CF+IbpxW+ZSU1H2DpHlgIw7TSYohrREQtrCo7zo/Ic+fFVKwZ9mx//+y
         CNFYh4IQp7Vor54vF+JhOn+p0sW0BG+O9R+05jbA+J+lzHOFAVlU4Ns1r3vNInOT7MEv
         xVqAc0E/+2qqfei1y2OP6Ktz/l4zVlwqQ4IgeeaviJ6SnGnfkncXAo/uGG9HmcxjLFyc
         MnVrUvdXvtfQ4hP0N1jVycr/dlkF+W1tpYGQ0FIF+dgztGPnnKFjcxS32oYzBJYdSz00
         GcJJyHt87lFHnEzHnwLAskINTEfIm+XkEspN3VJBBGSxzO+rXfJw+lD4tzxj7ocv8qwW
         oVng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hm5dDbuw3DQFJ3Ul6ZN5X8EtIWx6/5WaS9fpPi4RVvY=;
        b=WlsMDxhCBZgPgz7/BIszDGxSz2bRUt188I/sEI1MeeTfhuf67mZ3n0hJdQ5vMFjgBa
         Sy4IdExkZTigVsEKVL117BDzp6LJxLVtn3uiKLP76a/6qPnzxA+z6tnzQROx1EJpfNw4
         R2+3gwPwgNH25w/rvN6ZqP147H/4XpMlaTLN8sNhZRgMbpyyYFGd7NCaVS9aUlhlt2N8
         mu9hEAbHlN4V23E5AA/StiKeh6CY2ITluQygzNFxC0IeUZGMWCCwSHRUG9kbpPfRS0Ug
         5sNJKbuAf2j5EXm1Ak8kF+eC78MSXbWFfMRmfMQonkT5QTjwRmpFmaeiJzeltVSwTijD
         bbWA==
X-Gm-Message-State: AOAM532b6YddSYZTGitCqjZy6HSEmQzwYwjROSIP9CjAwGVtREzNPaQH
	8xsD/j1NivgkxOB7n0f6Ics=
X-Google-Smtp-Source: ABdhPJwpoA7BoUdeA+X39a1FB5eMj5rYKOvxYx+fqqQZ7Sm619oQUAfXuNfXk8VFU5sTk0SXqhkC1Q==
X-Received: by 2002:a63:ea01:: with SMTP id c1mr4131331pgi.236.1617208256230;
        Wed, 31 Mar 2021 09:30:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c595:: with SMTP id p21ls1362361plx.6.gmail; Wed, 31
 Mar 2021 09:30:55 -0700 (PDT)
X-Received: by 2002:a17:90a:2e81:: with SMTP id r1mr4252623pjd.58.1617208255511;
        Wed, 31 Mar 2021 09:30:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208255; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8LZbk6vcPUhuffWis8r7q79VxJZ57xz+KQ71bQ1XCRbBzrgTHyoIbzWUGEgamK+eG
         abmPAZkdk2C0W5OKWuypms+QTq7WmtMwSQffIBQWd7bbn0pvAK5mrdaABhgMnCmdyuMm
         7IEnsdV+uMymIj2wKnJDgj7/FM+4SPpO2yzXtqCCHLJrekxfEYcFtjhkEQhzDwV7+iNu
         9kj8dQHxlq0d7AMItHKgtc1TWquAvBQ7uldjnYuVCj8BpNqpolBJ0BdPEoygvOE02EaD
         fSfcv9zGadJhj+PXJ2aTF51jlLyDhaV2jjt/Q3Ae+Ku+yMpSsp/NMTbU/huITbpCAdQa
         NwDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UzLPat+zCVCHsOzci+jiquCA0flgNJrwkrnYFtrMHnY=;
        b=JX/hZbVCfyMOtRYCYJAtyxW8uhMfPDndabPp3R7kYtGlCvYrevb6c95XNGW4G94XgQ
         b+KN9vyKz/BdSBBX1U9NznIFnsi/uVq6IClYTgy9Thuk+lGicr7EJfJAcLHr54bwkhdW
         OxwBrlJJOs8Ol50llQsZRfSyoMyWxkUYyEqsBn4+HrPiMBAP1CFv/gZixetrSE4NlQDh
         K3nYHSCNSWmOt7m4qatk5df9Qz8SXYqyr6cmmeGc0sbSSrdH/ttkXRYvTKiNw36Avhi6
         CY51tn5Zdd9sJJp/J1rf2W6zD8mEt3oM5ewm9VvNsgAPEfpkZ9UwBlt2Bh+1dFculcaZ
         d84A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=DfLjKNIt;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id f7si169297pjs.1.2021.03.31.09.30.54
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:30:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCXnaW3o2RgL7x6AA--.1430S2;
	Thu, 01 Apr 2021 00:30:48 +0800 (CST)
Date: Thu, 1 Apr 2021 00:25:51 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt 
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin 
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey 
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, " 
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov 
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko 
 <andrii@kernel.org>, Song Liu  <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend  <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson  <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2 2/9] riscv: Mark some global variables __ro_after_init
Message-ID: <20210401002551.0ddbacf9@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCXnaW3o2RgL7x6AA--.1430S2
X-Coremail-Antispam: 1UD129KBjvJXoWxuryfJFW7urW3urWftw4kCrg_yoW5Kw1rpF
	WUGF1DWrWrZanrKayayrykury7Jrn8Ww13ta12ka4rCa1UXry5X395Z3ZrZr1YqFWkWF1S
	ka45Gw1jka1UXa7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkGb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUXVWUAwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	WxJVW8Jr1lIxAIcVCF04k26cxKx2IYs7xG6r4j6FyUMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jndbbUUU
	UU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=DfLjKNIt;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

All of these are never modified after init, so they can be
__ro_after_init.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/kernel/sbi.c  | 8 ++++----
 arch/riscv/kernel/smp.c  | 4 ++--
 arch/riscv/kernel/time.c | 2 +-
 arch/riscv/kernel/vdso.c | 4 ++--
 arch/riscv/mm/init.c     | 6 +++---
 5 files changed, 12 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/kernel/sbi.c b/arch/riscv/kernel/sbi.c
index d3bf756321a5..cbd94a72eaa7 100644
--- a/arch/riscv/kernel/sbi.c
+++ b/arch/riscv/kernel/sbi.c
@@ -11,14 +11,14 @@
 #include <asm/smp.h>
 
 /* default SBI version is 0.1 */
-unsigned long sbi_spec_version = SBI_SPEC_VERSION_DEFAULT;
+unsigned long sbi_spec_version __ro_after_init = SBI_SPEC_VERSION_DEFAULT;
 EXPORT_SYMBOL(sbi_spec_version);
 
-static void (*__sbi_set_timer)(uint64_t stime);
-static int (*__sbi_send_ipi)(const unsigned long *hart_mask);
+static void (*__sbi_set_timer)(uint64_t stime) __ro_after_init;
+static int (*__sbi_send_ipi)(const unsigned long *hart_mask) __ro_after_init;
 static int (*__sbi_rfence)(int fid, const unsigned long *hart_mask,
 			   unsigned long start, unsigned long size,
-			   unsigned long arg4, unsigned long arg5);
+			   unsigned long arg4, unsigned long arg5) __ro_after_init;
 
 struct sbiret sbi_ecall(int ext, int fid, unsigned long arg0,
 			unsigned long arg1, unsigned long arg2,
diff --git a/arch/riscv/kernel/smp.c b/arch/riscv/kernel/smp.c
index ea028d9e0d24..504284d49135 100644
--- a/arch/riscv/kernel/smp.c
+++ b/arch/riscv/kernel/smp.c
@@ -30,7 +30,7 @@ enum ipi_message_type {
 	IPI_MAX
 };
 
-unsigned long __cpuid_to_hartid_map[NR_CPUS] = {
+unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
 	[0 ... NR_CPUS-1] = INVALID_HARTID
 };
 
@@ -85,7 +85,7 @@ static void ipi_stop(void)
 		wait_for_interrupt();
 }
 
-static struct riscv_ipi_ops *ipi_ops;
+static struct riscv_ipi_ops *ipi_ops __ro_after_init;
 
 void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
 {
diff --git a/arch/riscv/kernel/time.c b/arch/riscv/kernel/time.c
index 1b432264f7ef..8217b0f67c6c 100644
--- a/arch/riscv/kernel/time.c
+++ b/arch/riscv/kernel/time.c
@@ -11,7 +11,7 @@
 #include <asm/processor.h>
 #include <asm/timex.h>
 
-unsigned long riscv_timebase;
+unsigned long riscv_timebase __ro_after_init;
 EXPORT_SYMBOL_GPL(riscv_timebase);
 
 void __init time_init(void)
diff --git a/arch/riscv/kernel/vdso.c b/arch/riscv/kernel/vdso.c
index 3f1d35e7c98a..25a3b8849599 100644
--- a/arch/riscv/kernel/vdso.c
+++ b/arch/riscv/kernel/vdso.c
@@ -20,8 +20,8 @@
 
 extern char vdso_start[], vdso_end[];
 
-static unsigned int vdso_pages;
-static struct page **vdso_pagelist;
+static unsigned int vdso_pages __ro_after_init;
+static struct page **vdso_pagelist __ro_after_init;
 
 /*
  * The vDSO data page.
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 76bf2de8aa59..719ec72ef069 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -149,11 +149,11 @@ void __init setup_bootmem(void)
 }
 
 #ifdef CONFIG_MMU
-static struct pt_alloc_ops pt_ops;
+static struct pt_alloc_ops pt_ops __ro_after_init;
 
-unsigned long va_pa_offset;
+unsigned long va_pa_offset __ro_after_init;
 EXPORT_SYMBOL(va_pa_offset);
-unsigned long pfn_base;
+unsigned long pfn_base __ro_after_init;
 EXPORT_SYMBOL(pfn_base);
 
 pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002551.0ddbacf9%40xhacker.
