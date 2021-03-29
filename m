Return-Path: <kasan-dev+bncBAABBLNYRCBQMGQES77ZZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3434D34D70A
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:27:58 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id c17sf1649553ybs.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:27:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042477; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Rl6NwQxgnpNUxmDITb7XitfAlu1YKHrRAfMDDE5aIXmydT+E2Pr2JozuiEMllh9o8
         UAiV/PwmMmCwUya4oz4uxaH7DSqDIZcL2gX/USA6H0fQZuJIeU6XsQ/4NS9z1flVBqJG
         tSmzT77wSsJTI/xtenh//bn5BOTcfXsNbvRNSxKfrTYl/Fac4oCiQzKkUOpvXtrbvJoL
         T4wiIHrMh7Co+7BFNzILI9iq6AsHA9XcYYtcW9MtVU8Zb8FMfslACWg4SAhygXnlNmHg
         GurNgsSTZWfRQJoaI9MsntwMNoMx8FloQxUbpDpSYE2EUu0cAgwSagF7t/EUXQPBPQ8n
         PRiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Y80OPUB+ExP/uw0k5v3K0V6sRamN3TQ2R+fWBrorBLA=;
        b=kFCjPGtKqyU/wzwR66V46Ck3fNHs0Co2Hb/g5yZTYoSGPKcmAh7Rvi3xWGhpmHQ6Il
         fX8o4pxme4FQmJMcdWEUSf2DyJ+/XpC3oNL9EofAUm9Me8lxJtRoKl5zLELCC0cuE7v9
         sSnACGsvoGm1aGaJ+AqgRfJPqooUvDFMOTjFB2hwQyQws69qIUxGVqKnPlgPF2E37Twp
         wS+G5Lgx3lUCBh5cV3lkmjaiNdHOhgvh/Ogm/AdyWYl27CwyM0onyA2ajw0bSqu/ykm8
         7OBbkKxwLFb+pihR3m+cIR13E49t8j7WRlUXc+TyvuExRqom3yqOo+oT1XdiSbU4wUsD
         4mGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=sRYiMMm9;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y80OPUB+ExP/uw0k5v3K0V6sRamN3TQ2R+fWBrorBLA=;
        b=DtGY8IGEVL+jncdjo+6Vc2H0mVn8OjQN7swCD4qObYBS5QRy0n6HGwveyWN7LHyqVg
         XRVUPdniqzEgh+oXSicHWvIIlSU6/eJqUvyttDEYQQnKe9Xj0xT6Q1UzEs85sXcEkUkG
         FogiSKeoHRv+SzXm96391qYmjbfLYzpxy+9ULd2b5z4V2qMf6ok2WE4vggx8bdRFbhzT
         f4G1idaDzJv6JevggZaLehng91O2YReA9F/rfgsW/Tr1IurF0pXswT9XrkczkO1T3oEt
         PBeHoCDVaF1VF0PwaIYZuU0F6J9mUactFcXDnms7SDy8BrBYNLxLUK4PgBdhP0LiOfkt
         0H4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y80OPUB+ExP/uw0k5v3K0V6sRamN3TQ2R+fWBrorBLA=;
        b=opqrKCuv7/4AXU+r1dCXKlos1oRNzsY+BFycgPi+uhep3/AmnV+HQlXu+OyfQfC3YC
         oNcr2kS1R+qhe8O9zwO2OnRtwmw23rGKU8rc4sD1vnT3mqq+tQ7cRK+wMwtfG1a/KR7f
         yeUO1FpZjdLKecC3jOKPOpb6KZsWwGXyuGfnB839nKyDj/nPiDVQdtAbYVfrHpGCtyEd
         +ALlfg4MNpSDzYdQmCDnUByOSpdSnYE00houzNI5ECOQlokQF926axwKgrwFXncXD9nZ
         ieZ5C/JF0AHWqodJ0YjeX8YYYy6/wd8nL/Ez5UTsmc/NbUGdKEIYnUDVWis0yig/ZZX1
         aHEw==
X-Gm-Message-State: AOAM532D2A+JrCSygroS3OO+FxGgLWDlqk/42OncQM5picLJq9+Mu3rQ
	b2rYILBriHHO/Xudz7/IFwA=
X-Google-Smtp-Source: ABdhPJxyB2Wb+6H50OKfTisUmdP+5vblR/cnv2v7siVi8BOodxL/z/2MaSoVoynqEwQEqo/yAodu4g==
X-Received: by 2002:a25:5381:: with SMTP id h123mr38584475ybb.416.1617042477331;
        Mon, 29 Mar 2021 11:27:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d306:: with SMTP id e6ls8622012ybf.11.gmail; Mon, 29 Mar
 2021 11:27:56 -0700 (PDT)
X-Received: by 2002:a25:61c5:: with SMTP id v188mr5874933ybb.423.1617042476903;
        Mon, 29 Mar 2021 11:27:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042476; cv=none;
        d=google.com; s=arc-20160816;
        b=EuozJGUspPcU/+OenD5v49J6Eujpah3/N0rce1ZTwCm4yrYApNptAFqGQ8vDoaBC6I
         XRFgGmb3lqW9E+q75mFBICrAdbWoReqrDjjj9Be7m8weX2ArRLyH+BRHEo07676EFPKz
         TN9DOrTNnwICwHzMKzvBfE+gTK6bm0L5oBPxGh3a4GNvfIyU8JHjDBkmFEjoe7cZkqsv
         +P65a/0QSJ8dI0/RVaz8EeEIQuQ8Ew+yDVxQiC8vfsZMl33CHc1LDTwURKpYZI2Q/0WL
         9s9LmJfiZ6T6Jeortt6WoUnO+Tla9l3ViwYmC1p8aSYK5IlkarmDIkBJ2hshGS842fH6
         LvLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UzLPat+zCVCHsOzci+jiquCA0flgNJrwkrnYFtrMHnY=;
        b=KJuK+txxXGOPYWNdNvvmrGKd+83r82qxymC1IltIexh9+Q2QGV8ZZhb6iIUwqXrhWZ
         QjIX+XFRq4Zwf8XYeN5v0fnu1xWTy3t6ZF+wBTG2e1wv6rQ09u6g7ztOYYPzPPo9h++Z
         zJd23JQK0+mhktC/EHLzWtxkAgbxRd3GtRXR/m4ivWTwcHVnFxorBg3ccXIoZJZnO/iy
         akAqYRknmhhVHEMJ8y2vTBmTCjl6TAtCke9EtMUHvGtDQzwQRkxeWZjzB8cQ1Ou4Zj5E
         q2WyaEdh5+Lltva3XQfnjI/C1VjM9AU0W6So+V0UY/4U0wILlA3XaZqYIL0JVImGm/gp
         MJoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=sRYiMMm9;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id n16si734001ybd.1.2021.03.29.11.27.54
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:27:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDX3EgjHGJgqfNpAA--.35364S2;
	Tue, 30 Mar 2021 02:27:47 +0800 (CST)
Date: Tue, 30 Mar 2021 02:22:51 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, "
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH 2/9] riscv: Mark some global variables __ro_after_init
Message-ID: <20210330022251.6e0f61cc@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDX3EgjHGJgqfNpAA--.35364S2
X-Coremail-Antispam: 1UD129KBjvJXoWxuryfJFW7urW3urWftw4kCrg_yoW5Kw1rpF
	WUGF1DWrWrZanrKayayrykury7Jrn8Ww13ta12ka4rCa1UXry5X395Z3ZrZr1YqFWkWF1S
	ka45Gw1jka1UXa7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkCb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjc
	xK6I8E87Iv6xkF7I0E14v26F4UJVW0owAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUAVWUtwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	WxJVW8Jr1lIxAIcVCF04k26cxKx2IYs7xG6r4j6FyUMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxU2AwIDU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=sRYiMMm9;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022251.6e0f61cc%40xhacker.
