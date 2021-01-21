Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDH7UWAAMGQEY2GTGXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C79612FEB71
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:20:13 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id t17sf1234979pgu.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:20:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611235212; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2sN9jpRpC00NM3UD3Mgow7f8AOPS9FAaJctoFQmRq73sBvG49oKzn2mJ8bdS7jUXq
         czSgujjg8svQiDA6OH83xq/hA8mxq2czwN/6whuC6jALcAQX9wuZLj6YUet2dfcydLqB
         FQlbzP3qLMFboJJf6lAMrIWnDnh8/Bwyp/YwOHRUkmIHD30K+3grficnry7mdIbxCiZC
         EFlI4kxQLpshtazqKk6Jx6goZl4UYVVwrj2eVZx5KMdvzRbwuNOMJa5TK9bSyDv1wjG2
         +5uEoyapjGmG3ovi7t5M7/ix+Iv3TZDWQM7sriQ4MWFkqbvbB6/fpCLGodVHzVLdHKfl
         PYRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ryhNsj/vR9Ysxa8uv0x60pAaKtx7IP+Wv5ewOwZcLFU=;
        b=KrFrl5GHdrgzWQiKywZgwPHN38f7IWK3CCQv7LvPe9kxCmQ5L9AfJxAbH9HnTK1lre
         r2iCvLalXwbIXr0NifwrPN88v30jWCfjugGXET3NqPTZwxKwO7JnQdlFRo5NV5omlOOC
         iPIAfmmfUOf6tBGFMS+mJfqBXHd4pAaiB+80Zpr4jnwhUp1wiy001EszDMyvsatzt71m
         zCMbdyKQp6Ygew9VfsY68Knjp1z8Nm/etwOV4u8+cQjJUyncTY9R6lV4d8ap4yWv8+ny
         FVuEyRr/eidVGaUWC8yzdXtM4IO/Q7Q8wfRb7Ys71ybujbJMxGVp+y8mX0KAv7I/dhm+
         pOpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ryhNsj/vR9Ysxa8uv0x60pAaKtx7IP+Wv5ewOwZcLFU=;
        b=abqjNHGiQklfvv42vN9c2sQrBzQ+yHOOtAk42J5kt8WBAypMvTH3BGsltnScTf7qrd
         AkH+V/bVMR2q3W1rggGdNj7XgE93fCAwAHg2Hj35BmP89tEQ/EyAKXViNbfrQDtHmLlQ
         vm+AYSZpBIaVGZ//+6Tw2ZVponvOA9Eqb4esOfb0+5ZF3YUQw6hXY+llTMhpZXaYj5sj
         zEo7flzjCnkRu+wgQjAe3pJyeb8/gphteQUkOZrcAx09MejVvz5PZnpnVE0dHy2pbWkV
         JDHgFXTv/BzLqHvYGEifn+9b1fPYtt6EZ++Z6oaZo96blgyJafVTWeWcLW1j0b9Cq4rV
         irTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ryhNsj/vR9Ysxa8uv0x60pAaKtx7IP+Wv5ewOwZcLFU=;
        b=YgAcdLj6hVRu5M48/zijvRfxIaBK4DrOEijIeORkanzaD/LJLPErJhkPkVHnSADfSD
         hl3BlrHd/bCl95q34ql5glwk+ZB5sLcU0974aimKuzV2e+zJXNsS5TMO9oSJ3xKq0oWn
         vt+gHOEm+QfF1LUkfoKaxWCwra4yXoXf+Wr0CiCWi7UZnobKdwMriqxXzJ+Uz0CtNZXE
         YEDHaip4xT1K8glSTgDK+gBpJ3//9Gkj26YKOmlnrP/+6/f+GKPKEGRlKAAwhMVEv4GS
         a4u9dfgwr04fh7h2FzuhY8i/lBytxW6tDtIjsdZfIR3OUCeJ4nLgi3WUrbbZ4TBuPyZv
         w78Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319uCvmAyNIX3MkP7DBvIOaVIMm13fgjbeEZ7GfzUmlTGInPnVJ
	vp5X54M8diaMSlhgGlqQjQM=
X-Google-Smtp-Source: ABdhPJxblNn0TPQ2hqjq8cr0f9LI4quH3s8o/K71F5PMPv75xQsQuMMQRaFUE/tk1ToNZtiw6XV4KQ==
X-Received: by 2002:a17:902:7487:b029:de:1d8c:51ed with SMTP id h7-20020a1709027487b02900de1d8c51edmr14903069pll.35.1611235212492;
        Thu, 21 Jan 2021 05:20:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls1187573pll.0.gmail; Thu, 21
 Jan 2021 05:20:12 -0800 (PST)
X-Received: by 2002:a17:90b:602:: with SMTP id gb2mr11752892pjb.170.1611235211951;
        Thu, 21 Jan 2021 05:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611235211; cv=none;
        d=google.com; s=arc-20160816;
        b=rky3ow4HaZhFxvS5QbyGjpXukZOxmzluqpM5+E70o8NaNtDhl5nbxB7Ovj5rYmRbzC
         mGBUqZ6VI3/PucS8TkLGGvv83za+xopxg+lENU1uUXBFpizUyqhSp8Sqi7uciPykmdZG
         Z2IC3vVsNpLbqlbuYe2wZ0R2mbkUOfrN38aGXQ6xJyoDv1M3dxIY/0w7BfSm3d9J9djF
         lPomtvE+w+Vv7GwwzE4dIvunnrhocPAs2dzMn61Q/xzzp6oD2Da3XQhiPSlMu+5ij66G
         U1OBtwpXy4nE0Z0hlJym+bsQGAN9akzvagAA/B5DEBPMpk7Xe8ZWRAhwt0aZoZ7m5zZs
         zVKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=45GXurV1eRDagOLDQE4RuUjVb+SQr8jZfH5MAGhmkwg=;
        b=hodiyeWGBFuO25Gpj5zO74ZM9uU55fzGYYA1S/fkDKbP3WoCHvMeYT/4utulkYthXu
         T4dZhPFzFePFbcmZKRrFnVD+ek1ICSW4mGSdSpF1RC2vYaIfo9lFJDFWp6PxJgKEyYzg
         lr6b9VQX+t7JGUnmmfnyupsL9aKH5kuaLQ5weJVgUjHKgfBBM49ADpX+u1AZ9bDr4usW
         BDpdfxrZGIV5cD8G8TxnymAbySn4Q8pvoRfCaRYs2ta5am/e1JoE49/aRLbIP0hHzPZV
         9cEBVk/Ja/PBQ0uTzPU6J1RodL83kx2Tp3I6sFnsnUDiGI9zqpd9TCp6fm/eHUzoGrNs
         NOKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r142si275952pfr.0.2021.01.21.05.20.11
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 05:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DC54A11D4;
	Thu, 21 Jan 2021 05:20:10 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 705D73F68F;
	Thu, 21 Jan 2021 05:20:09 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH v2 1/2] arm64: Fix kernel address detection of __is_lm_address()
Date: Thu, 21 Jan 2021 13:19:55 +0000
Message-Id: <20210121131956.23246-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121131956.23246-1-vincenzo.frascino@arm.com>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Currently, the __is_lm_address() check just masks out the top 12 bits
of the address, but if they are 0, it still yields a true result.
This has as a side effect that virt_addr_valid() returns true even for
invalid virtual addresses (e.g. 0x0).

Fix the detection checking that it's actually a kernel address starting
at PAGE_OFFSET.

Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..e04ac898ffe4 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -249,7 +249,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 /*
  * The linear kernel range starts at the bottom of the virtual address space.
  */
-#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
+#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
 
 #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
 #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121131956.23246-2-vincenzo.frascino%40arm.com.
