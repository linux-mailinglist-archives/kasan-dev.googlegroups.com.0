Return-Path: <kasan-dev+bncBDB3VRFH7QKRBTF3ZPDAMGQEXZCQAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E8AC6B971BC
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:32 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-42571c700d2sf61618075ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649805; cv=pass;
        d=google.com; s=arc-20240605;
        b=ILlrs8D3StPPCNJJm0T3ASILKM8WSHGRWp0sORmvBmLnZFS5JTjheJ3BZ/RGO13Yw/
         0Ywu8jiCoMojf+cacQZsISnyluqAfbbmXQwc1Y0OdtnsUn5zD/cnLIpvhTi141DddXez
         U+cGYbTS/GFSbOlCwBkhAd+eHjj+064aMk5vEtnxQs9JryWFxG7ez3yRAC1LqGoHGq8P
         NHcGwe/vWwFfPkStfI6lo6N8tFyQhc/Y2fS5uvG+mCMKDfM9JTGJ8iYyApA8aWqqjfFy
         tYu/wx88/csxdAxWyU/0pea5DaQu6ZE4xqHvkm2cUkkxBcbFW25ffobU4GNfxOUOqmAR
         Ommw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q4cz1ntxy+4l3opPKG88IGKHv6QWtgcECdmtLlkqLRA=;
        fh=4JIFU8ZU5T4D2ji7hNWnEYJmjkuYDnc1ArwN+m0lSFQ=;
        b=ZtNtszNfDoHiGQSb9UlpmxsSTw3c9vZlB/FGW/aiIdxbqQs59Y1TTIJLJ8Oxfq46sF
         EJvBT3y4aY9Sy+mLR0FNchMyXKgueW0dDGfP4XqUxWdLaum2uagUV1MUc4tNV415Wfuk
         iWfCoAB6Ji0ybZ1lYJEBt7PozA9gfloeOxteUokJbnw7GCkJQmArDxXT7IRUsqR/343v
         Y1NDl7LGYRGvLJ3vUNMTGbRGRPGmUYR2NcPDyfabULYZy5dLmksLxuj9pQXTtZ51eSYT
         e2jNtjG1pIDMzYp32YFvvMhchrFRce+cNTzaBuxWHDbJI7k9JCl9HEWCWsGEx/ay3QoB
         AuOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649805; x=1759254605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q4cz1ntxy+4l3opPKG88IGKHv6QWtgcECdmtLlkqLRA=;
        b=DzI+LOcRGGnlEqSt0avscuu3pBjuLdFVj0bVFuFhXYLbWQ0398VV/8wYTPxbpbpKVL
         t6lYOJ5IlemJQRb4Gbyuhu3dxzoX3jYqgoa8AWEHU74sZ4F2tr3kFxrDjNxNmmG7qGfi
         pwP5PRU310w+2c3BAD8Pn4RRkzlPmHH+e/eNt+N3ZLmePiOfmpFfpku9mCgoT2WX3pnm
         lS0CwcfEzYEKQa7YEjS8ODKbYBL1/9sqAq9jibNcAAOXV8m8jezh7v6n9GGo+EJRh1AC
         3pAiUd96Zgn30HlyK/7meKMJNtDYKlIu7lAWGkBahE4ruS+HjBUiUAy6NuIgPRdgBtIp
         KnWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649805; x=1759254605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q4cz1ntxy+4l3opPKG88IGKHv6QWtgcECdmtLlkqLRA=;
        b=K69pOxdH5SVztJQIyj+TnwRvl/SgLYnlqQZXJ4XiZy/neyWzz2xr/0juIgtnio34JO
         b8cJgXYNMhV8vursVXoT/4R3JtCc6MwFR/hYskgY44eSaWy6rvsz65Vb6zZcANoqRxvv
         8JINz7kum3StqPaIK6UwQBwUkfrC/juTWBtL/J+cBRp00DLQkrrJFK9su5G5UH2zr98u
         /0q2NarZSdCoweRcHVSctGj61pUng6MJ9Co21Y1kRs0hqqZSp81v3lOIRYv6vhMYrubR
         VGhpGleBAiD6pMOou4Oklv7iVTHj4j2Qdo/5jJuut9ypDQorWnOhrURANj5KPnmVyrBU
         ikcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2MkcnBgJ7tKhZtzAdbr45FDl79HfFENFwVfr6+37O+yugUUel2RSQF/mGOI1FZJTjRXiyrw==@lfdr.de
X-Gm-Message-State: AOJu0YzUc+2EyCq3u1AlUDiDkCGM/SNTqGvnA3WV4jOzmMXXIA0bxqa0
	dUaOlndo4UApuCOg7X00hgyv/UdsXdJHrdokIh8idZ6kqhC1xpuO0kII
X-Google-Smtp-Source: AGHT+IGebduuqFxB6Q0Q08HX/ZSNt5cU7ycLprvODFPqYOf5Temq5ZBqZu76smjTFCnVo6QgpLhLug==
X-Received: by 2002:a05:6e02:1888:b0:424:805a:be8c with SMTP id e9e14a558f8ab-42581e0f828mr54012515ab.8.1758649805222;
        Tue, 23 Sep 2025 10:50:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd46ImsayhacvyGrtCPcv4E8q9DkgIJv1ZzYBwCNNqEgHw==
Received: by 2002:a05:6e02:3712:b0:424:6b1:5287 with SMTP id
 e9e14a558f8ab-4244e0396a6ls93189855ab.2.-pod-prod-01-us; Tue, 23 Sep 2025
 10:50:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUl2ajusLsq36ot5ZIrJkDGzJIJic53Q8mtEI3BVZyQlQ8AhS2aflPDUHyEhECdv/80Qx4S5zPhQOw=@googlegroups.com
X-Received: by 2002:a05:6e02:1a6c:b0:425:39b:a7d3 with SMTP id e9e14a558f8ab-42581df7528mr52151165ab.1.1758649804302;
        Tue, 23 Sep 2025 10:50:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649804; cv=none;
        d=google.com; s=arc-20240605;
        b=AxvWQ30HGZ1jOm+YUALDc+FOS6+rVWx/3J/Gzr5UiUkqj1/XB0vhvO9JzQ5CLxpeHq
         /PiBpHN+bA0oTivxWDBdExcz8Mw3/rFIoyCLZKPusz281xjNF1RuPamoDOx+hKJ3QBE2
         N1yNf2lwYJ96zrHZByk+8V1bfZaix7NaK1tcAcC+5VDu0HJqObc2CmB8pq8dRe6dQq7+
         FjusHg6EiKwEuAjeBIQVhjBf/6i9Fr5xI95E4adwoCcgSHdwIeYckDHotxIDyeEt2DxM
         baVguTImOpGPSnlrOxzslMPX0rMndjeuyuscY/rH9KouC7DtWMz3vH+Ym203rMBungmn
         vaxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=J6JbDICqugtb9qT9yEa3DWWYK2mJcztKgaMSZgbVh4w=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=ZArsgqHxBSsYx8+aOc1jC+KTzRir4pKhf5oECBwB2KwGPsRw1yhbgofdt6Hrx4lNgp
         zFD3owa/myCqChDexYCiokJsYRQd9glG+HOc9gdLwQBx3aiOLx4ZNfMcuUxdRQxL+oSc
         FZYDhfZQ33fGRHECAJhjU+L4SfTCcTjE+DOcoRIKZ3n32Nc4yFbGDnQEbAy5D1FfCYTb
         lUX92MOEHseEgDTSrBwrBdN3snXD+zhPdbs//Z/Gy5hBM2BM/h7A/mEoOamlui7frdmu
         Tu4WghtcJSWli3d8CH4pkK/JF+/8jOnTiFrme2lHCnJ4ohkQQjmF8DZ9Co6igXTi1QvB
         RbqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-4244adb1a88si7010465ab.4.2025.09.23.10.50.04
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 66942497;
	Tue, 23 Sep 2025 10:49:55 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 2F2973F5A1;
	Tue, 23 Sep 2025 10:49:59 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 12/16] kvm/arm64: make alternative callbacks safe
Date: Tue, 23 Sep 2025 18:48:59 +0100
Message-ID: <20250923174903.76283-13-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Alternative callback functions are regular functions, which means they
or any function they call could get patched or instrumented
by alternatives or other parts of the kernel.
Given that applying alternatives does not guarantee a consistent state
while patching, only once done, and handles cache maintenance manually,
it could lead to nasty corruptions and execution of bogus code.

Make the KVM alternative callbacks safe by marking them `noinstr` and
`__always_inline`'ing their helpers.
This is possible thanks to previous commits making `aarch64_insn_...`
functions used in the callbacks safe to inline.

`kvm_update_va_mask()` is already marked as `__init`, which has its own
text section conflicting with the `noinstr` one.
Instead, use `__no_instr_section(".noinstr.text")` to add
all the function attributes added by `noinstr`, without the section
conflict.
This can be an issue, as kprobes seems to only block the text sections,
not based on function attributes.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
This is missing `kvm_patch_vector_branch()`, which could receive the same
treatment, but the `WARN_ON_ONCE` in the early-exit check would make it
call into instrumentable code.
I do not currently know if this `WARN` can safely be removed or if it
has some importance.
---
 arch/arm64/kvm/va_layout.c | 12 +++++++-----
 1 file changed, 7 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/kvm/va_layout.c b/arch/arm64/kvm/va_layout.c
index 91b22a014610..3ebb7e0074f6 100644
--- a/arch/arm64/kvm/va_layout.c
+++ b/arch/arm64/kvm/va_layout.c
@@ -109,7 +109,7 @@ __init void kvm_apply_hyp_relocations(void)
 	}
 }
 
-static u32 compute_instruction(int n, u32 rd, u32 rn)
+static __always_inline u32 compute_instruction(int n, u32 rd, u32 rn)
 {
 	u32 insn = AARCH64_BREAK_FAULT;
 
@@ -151,6 +151,7 @@ static u32 compute_instruction(int n, u32 rd, u32 rn)
 	return insn;
 }
 
+__noinstr_section(".init.text")
 void __init kvm_update_va_mask(struct alt_instr *alt,
 			       __le32 *origptr, __le32 *updptr, int nr_inst)
 {
@@ -241,7 +242,8 @@ void kvm_patch_vector_branch(struct alt_instr *alt,
 	*updptr++ = cpu_to_le32(insn);
 }
 
-static void generate_mov_q(u64 val, __le32 *origptr, __le32 *updptr, int nr_inst)
+static __always_inline void generate_mov_q(u64 val, __le32 *origptr,
+				 __le32 *updptr, int nr_inst)
 {
 	u32 insn, oinsn, rd;
 
@@ -284,15 +286,15 @@ static void generate_mov_q(u64 val, __le32 *origptr, __le32 *updptr, int nr_inst
 	*updptr++ = cpu_to_le32(insn);
 }
 
-void kvm_get_kimage_voffset(struct alt_instr *alt,
+noinstr void kvm_get_kimage_voffset(struct alt_instr *alt,
 			    __le32 *origptr, __le32 *updptr, int nr_inst)
 {
 	generate_mov_q(kimage_voffset, origptr, updptr, nr_inst);
 }
 
-void kvm_compute_final_ctr_el0(struct alt_instr *alt,
+noinstr void kvm_compute_final_ctr_el0(struct alt_instr *alt,
 			       __le32 *origptr, __le32 *updptr, int nr_inst)
 {
-	generate_mov_q(read_sanitised_ftr_reg(SYS_CTR_EL0),
+	generate_mov_q(arm64_ftr_reg_ctrel0.sys_val,
 		       origptr, updptr, nr_inst);
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-13-ada.coupriediaz%40arm.com.
