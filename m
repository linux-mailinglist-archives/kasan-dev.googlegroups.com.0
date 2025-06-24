Return-Path: <kasan-dev+bncBDTMJ55N44FBB2WA5LBAMGQEC2SXJIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DB3DAE65A5
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 14:56:12 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-32b3f6114cfsf22655041fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 05:56:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750769772; cv=pass;
        d=google.com; s=arc-20240605;
        b=SzcZvG+feGCGgCkZ94ndZvaHbxgcDZIZJwLzzRkrDAfLD7cCXdQvbysFtu2vUgE6q/
         xGoIUL0Bt1NtHXCOBehcG9K01z31SA4l63c9URVaTRo8E2ySF1djRTmHuuND1IK8NW4k
         zEpbndyX0h8dd0ItEVkCtd0d+5yzIHRnMKcoow4BXJPb0ituECisffIdR5vDkcaaWlnX
         8mf62u8x1GoRssKQQ0ITr92OM86uO4xPDWsXR+tflWr3B4B9ms3u6H3P7vXlbxn+Ssha
         8wB5O2tASarhODVChlG5qCoAkgOF4huWJO61aeCpjzyE4U4jh8v7ZVdtxw3T93DfuGfP
         tfBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=UxW3vbNeLEi8AEbLEUAkuGmzvBRmL4lwLzwpKCOQUts=;
        fh=MJTyZ9gSqy21YI881DeTjVl4daC0Z1JAVTAXGzzetD8=;
        b=MRmdrBig61n/TAZCKqJy+GUWPYHQLQEFz6ofycC9mDSeP5DLt474N5QWijQdbIai8+
         RwtnOOlyuLo6W47o+k0fmUBrJWV2QqTtTinCv6017685XfTl6B5muxAG4KdwVfKRs9Mx
         bEbpe/LQ+Mya3sVx/NdrZEVyCwC4iCtYNDB0i0W9l7Uye4d+azExOgpsPy5PLF4NWv9t
         zG5RFZuvwJBMwAA/qUvg/ikk/WIYN/uTlNRk46Tb3ncJ/W2fefrqB6swENwOSdrNEpBK
         H3+TK9jMs8KBTDg/aX30i8S/SjCT6h6BMw04Yy5x8CDKIB7ON8Kb+LxdO3cEmJSNDhBU
         4uqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750769772; x=1751374572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UxW3vbNeLEi8AEbLEUAkuGmzvBRmL4lwLzwpKCOQUts=;
        b=T2QdRHSmjBfnl0kLr2bxCIYdyezQt5O0DKQ7Eg9hI/pKnhUiXK7wsWTNrJMzVy+0Ah
         EWQ2rD9xtql91Kl5nHfFGZhfKlr9njtrVmllj2ZUPhf/YfaD/V8isZT+30+PbxRUxex4
         4JEfNxs8cfCelAwyBf+gLvJjepDDiRQAJwX4U+Y4l8bg8eynOY0t938cHp9YrzIGMMFj
         VNdHGS+JTYFhd9VR24O9AR7wVrnb/jBSjjbsxODyVbFe8VSP90Zl2E4Zo8/iO3F8rk36
         rBRTRnNDwn2Ir8sgieu+yhJXFEdp8YFb1oIZdNmj8FZe3daDjw6XoMqZyvYTpeN8AScc
         levg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750769772; x=1751374572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UxW3vbNeLEi8AEbLEUAkuGmzvBRmL4lwLzwpKCOQUts=;
        b=NK4WBAV5U6tUn2DEuhK5RQIYa30yC9pusELpI2YRC0iXrsgWeTFEKMIFqwV4nx4Z9l
         s+c78ukGWWFySAQxW2d9qEb6LE6cPT6qpbNMmc/wCCi1LvpXKTInlbklD2U4BvWzvdAa
         mlkUC3tSKPWXxJLxGaidbMB4/d0KR00gpqIv8JzWmFvuONGFrW1NCf5y4DjVI8t7w5vM
         WqUqKj/gajz8ACqXLJMY0yNwOfliSXp7Af5gEW8lJraWw3q6MfzsDmObaQbH76+O1MKL
         zg6Rb1CAIywdzkrtKiR9u3pApLGo5+7F/bQmzwYIdC166HBhI96DOWzeq0wek/aqc7XQ
         e0bA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZ1tS5PhGAaJvJ8fqjhZTekJVTNUZ48q+txi97wWOg4IqkqC3MWFWISjiKg9XqIXFjzkO5Sw==@lfdr.de
X-Gm-Message-State: AOJu0YxFRBmW01tirPYO9PJ9dtL+q56Tf5UfeMNH0noSU9J20yxjk63B
	usiCZ4pqCppLPiqn8IUr0D7Y0eG8sifa/AftdmqIidEmsRif5ihvFkNp
X-Google-Smtp-Source: AGHT+IHJmaARTuQBgsylfTwLXVWW8fG0WcHZsCJMoGzbt4HY8q02TiEqTI3bdyM7fcL86uG0l4CDmQ==
X-Received: by 2002:a05:651c:324d:b0:32a:6e77:3e57 with SMTP id 38308e7fff4ca-32b992d4869mr43114961fa.21.1750769771470;
        Tue, 24 Jun 2025 05:56:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfEVYPIYsyNhowYCRpRnWtGwZ4APRxpJ1P8mZIoMpSk+w==
Received: by 2002:a2e:a9a9:0:b0:32a:e3cf:797f with SMTP id 38308e7fff4ca-32b896dcba7ls15161601fa.1.-pod-prod-07-eu;
 Tue, 24 Jun 2025 05:56:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWU3KONs+dP4DB8A1TQma1fLRbQ8BYRQsK11pToKUk0L9Px6eN1Zy/KNo+9coVba9tiAUo+bBT/Bxw=@googlegroups.com
X-Received: by 2002:a05:6512:1153:b0:553:a4a8:b860 with SMTP id 2adb3069b0e04-553e3af3b66mr5084363e87.0.1750769768603;
        Tue, 24 Jun 2025 05:56:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750769768; cv=none;
        d=google.com; s=arc-20240605;
        b=T0oi9XCdvnn+C14x67ZSUeU9XEdl+g4UUnfzI2SJPngLxEEaRQ3dlbcZah2FQgOQCa
         dQ5scqEcyMg47cM/A9BAKr+D4HbhEkkBBaOHl0m/gvZP8SpWdJ1pLeHAeVKdjdZiOuXr
         zHywYekflHBjIyX3yTIzrXZq4XGqCKxccu6kG6QJ6eItlP2mw8tmjya5bjnQ/xwH4PlU
         5VHVqhDMm5L6/Jh9hWU+YMWHSlVKH7v9bex2PK7ROPP7/7uoSd/My3tQmGif0UhMUz3w
         FwvoKp2GISUxDgSMrAHhtWfjVlfk9IofRjI14Rg+8Or6L+He44LA7ZMBPbDLRklWIkcg
         Gb7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from;
        bh=Wd5pQO4TMLiiStgKcNv1qG91igXzuOqB+CW/7l3oonI=;
        fh=T17YInYm58WvR7RoTo8L+tjIwak7KYvRELNS7tUcEqY=;
        b=YsuJ3YYYCs1xCVTvie/BiajHnp9xDL4+tWY9P0bKBb4UVtj/BP8UUtvqtgrtugBWlj
         8VmVDfbMXIr+T+tgMbGVK45t9orSbiODV15yOKLg+LG8QHjYXFPLRBohDpK9MtyqCRFB
         i6J2oP8HMo/X1JROf+mS6h0TgCzEfHfUUpo48J+iJgXPutb6cY0AdIk5fxs2eOaDRdkD
         cvIYq+4Lb7cXybDxx+PjljPdNmd2M+zctrEhAi69Qir6HhSxTWaN0wCKc1UZCTrRns7o
         ipMY0ddqh3zntjQQm0eNaNfq3e5rrBSMXNg0lCy5pPe55AktMGGKaENsTKVNVXVCWJHD
         gd0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ej1-f50.google.com (mail-ej1-f50.google.com. [209.85.218.50])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e41b10a4si344011e87.6.2025.06.24.05.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Jun 2025 05:56:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as permitted sender) client-ip=209.85.218.50;
Received: by mail-ej1-f50.google.com with SMTP id a640c23a62f3a-ae0a420431bso192862366b.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Jun 2025 05:56:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW2hGnA0BiqPPz/+HdM4Uw5eDf2cOXPaBm9g1Io03jQvuHQOViTlh0dv036ThbernIFEwimKDm0GVk=@googlegroups.com
X-Gm-Gg: ASbGncuX4T2KHqoBMQVyzGG7kfUN5Z0pU98VyZNhsE+ZD+Gn4C6QDMG2HkKtg3ICnvL
	0bjO8GcqXw5kgxdtVkGVQl26NlNwJwidO4hJnkPx8AqirKp2FQgKeuiHFv/4EtBMPUr/u5mnhQ9
	CQ/cSao85nrq1X+mVNBSxut/hCcrF4VH/8kdU6ZMFsQgU9IOKvYKLJgaWd4TcycAGV5a2tErx19
	uipjlGNWk86sR0bdQwVRLCahnITCrRSK8UkcV0VvpCZaZKJjnwBTrwXpsmlzXZgOmgx3gTwF5dy
	BiEvyY8nxEJgDvrAdJlzcxnOCEJGiO77SvxTN8VmnyYZVMWAT6WE
X-Received: by 2002:a17:907:1c95:b0:adb:449c:7621 with SMTP id a640c23a62f3a-ae057c0f672mr1747686066b.29.1750769767663;
        Tue, 24 Jun 2025 05:56:07 -0700 (PDT)
Received: from localhost ([2a03:2880:30ff:3::])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae053ee4e32sm887089266b.57.2025.06.24.05.56.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jun 2025 05:56:07 -0700 (PDT)
From: Breno Leitao <leitao@debian.org>
Date: Tue, 24 Jun 2025 05:55:53 -0700
Subject: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime stack
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
X-B4-Tracking: v=1; b=H4sIAFigWmgC/x3MUQqAIBAFwKss7ztBV+rDq0SE1VZLZKEQQXT3o
 DnAPCiSVQoCPchyadEjIZCrCOMa0yJGJwQCW65tw97EvPdbLDEZP7jJsZWR7YyKcGaZ9f6vtnv
 fD9I++rpbAAAA
X-Change-ID: 20250623-arm_kasan-3b1d120ec20f
To: Catalin Marinas <catalin.marinas@arm.com>, 
 Will Deacon <will@kernel.org>
Cc: usamaarif642@gmail.com, Ard Biesheuvel <ardb@kernel.org>, 
 rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
 linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
 linux-kernel@vger.kernel.org, kernel-team@meta.com, 
 Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-dd21f
X-Developer-Signature: v=1; a=openpgp-sha256; l=1774; i=leitao@debian.org;
 h=from:subject:message-id; bh=cuqvs4eld47kMpQxlX4a66Aj/+sUNQEviegQV4TglH0=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBoWqBmoaEGY0Co/p8xMQtpfpmgTuCHGkMlV+q1t
 BKsgyWtbl+JAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaFqgZgAKCRA1o5Of/Hh3
 bdsaEACmyscWIr3t0MIMFNGraHzVh9hvWTV6na3q1m1afnri47yEjl/+kME4vBNnvroir2ynG0o
 Y43r5iaBwxaB+URpN5iCHcqktnhCX+w9qeN5okvTo5geVnjQrgFpSugkrStqVd3XUXJZWecP1H5
 sVhm16coRcXJSbz6rOjRtVwqNzBpxQ/fYZgOl9II7k+0zFaozXqkQ29462BozXBcp5R/eFu4Qo8
 qNQUC8tsSoqRnpM6vDagP2r5evpSs0bLwTVOjGCBE4zKepqG/4j9RHr2McXgcvb5VNVZI1OlG1j
 BFLL1ktHmWDk6ZrupaSsyzAh3OX/5cdUV8T5aBmfwm5/sJyjEwfgIfXVX9M7Hp+O7rylnmmlxg7
 CcSVzlO17MxtNxxMnSEVLNl41jg6F8fLfeAp6CG0g/N3B0bkzhvdGY6MfuxTSluItEWXtvngiNC
 1VFdvFY5DmwguLAjouudsLTWjc2wOqPcbykPU1VKnXsWnBcJHk4YkyPKhSD2Qc7ekZw6R/vwzVR
 7PGD67q7uND0Cw0I2De5hyNwzlVZwGoDqpdcOF4B9aUF6K3isQGWvvCub/2UXA4WmErmJAeb8Z/
 XikwCGchi6d+NARnAxUtFoPQU+7bhUk2tkfoZFui0qvjOKWPmW4D+lOYzBANctlEbPhz6Y4iAl9
 1cEzMc/LXEis8Sg==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.218.50 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
with KASAN tags reset to avoid false positives.

This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
EFI stack allocation, which internally calls kasan_reset_tag()

The changes ensure EFI runtime stacks are properly sanitized for KASAN
while maintaining functional consistency.

Link: https://lore.kernel.org/all/aFVVEgD0236LdrL6@gmail.com/ [1]
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 arch/arm64/kernel/efi.c | 9 ++++++---
 1 file changed, 6 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
index 3857fd7ee8d46..d2af881a48290 100644
--- a/arch/arm64/kernel/efi.c
+++ b/arch/arm64/kernel/efi.c
@@ -15,6 +15,7 @@
 
 #include <asm/efi.h>
 #include <asm/stacktrace.h>
+#include <asm/vmap_stack.h>
 
 static bool region_is_misaligned(const efi_memory_desc_t *md)
 {
@@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
 	if (!efi_enabled(EFI_RUNTIME_SERVICES))
 		return 0;
 
-	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
-			   NUMA_NO_NODE, &&l);
-l:	if (!p) {
+	if (!IS_ENABLED(CONFIG_VMAP_STACK))
+		return -ENOMEM;
+
+	p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
+	if (!p) {
 		pr_warn("Failed to allocate EFI runtime stack\n");
 		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
 		return -ENOMEM;

---
base-commit: a3e9ee4ad433efad9c172d5fcf63ff39b61c902f
change-id: 20250623-arm_kasan-3b1d120ec20f

Best regards,
--  
Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250624-arm_kasan-v1-1-21e80eab3d70%40debian.org.
