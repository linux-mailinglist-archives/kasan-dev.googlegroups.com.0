Return-Path: <kasan-dev+bncBCMIFTP47IJBBBURX63AMGQE3E4TLFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D2BB96372C
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:00 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2700d53e6c0sf188693fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893319; cv=pass;
        d=google.com; s=arc-20240605;
        b=ER16B4sCeJTN+d1AAmXPmpymEVKvxhMS9HqddSU1GYWqfZxCvDIKWh+ievCPeueWU5
         ZmqeaPx89iewHZtXgfUIusmMMFUWsCqfQRaFLiKZDwD2qIxyFXWbvXJY0gJDJ/my1O9h
         7aXYmhlKF8X5G7R16mkJrAOb1DSsJv7gtg2wSEI6bL6pH0jhIpONy3oq3O2UqGznwMCo
         urJ/gtVcrw3YcOcC9b/S9aQh3wm3DKHqt6RyNV5X5VUpFneRoIEZf74SV5XyaKAVY64V
         tNH9q3KpdRYPpEGS13IMmVBhscVIRC7D4tVeuMYmQQilkv2UAM2tM6hElqVWr9vvfhq0
         txuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DnzZvAP9fkPE3JVY1g2JJ39xYLhjqiTMoRLgvDYwFkE=;
        fh=2yUj7Jv3LAQ0s7wdOBvy0OyVvk8ugRPQdeL9A7uGFfE=;
        b=ahSaNsRCigSucUzQgGuBOY7xnEjUMiiClXogEY2pM6wtttOCi3RE6GP04TQ/XQKAhf
         U7n1jfab2KT3Q5Dg2dYW6KG/2QbxSvkZ45TKp2kOY4S+Gd7G4wFqldXW5jhVgHrUHb0j
         IGN4Ez6mulVlq2WdCdmdvrFAcekkdciI/zUM6cYkRxaKENF5jPXzVpw8aU1WVzYqSvjy
         c2SATe0D2QXUIZRk0NVNDwD8Y0b605DNZFMb0X1BAPC6h2EqT+ZpwUCe1YF60wk8MtaD
         58dOFo6b2j8ENCstDwUMMo8igDU6eY8H4q0P9CUW2TqVXwj+HAR2E1Q7MGld8x+mmf1i
         t+xA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=eAlMaHl0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893319; x=1725498119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DnzZvAP9fkPE3JVY1g2JJ39xYLhjqiTMoRLgvDYwFkE=;
        b=uxlgzW48/7/gtPWN2JFt7o+SKcdRVpho2DqdHnsM1p5rAstfgRDbabNIlUYy4B1GQg
         2tOaT/ijt4NO92ju9up358KRwIaRMmV/jL3XkfQg6Mch/qPEGLJYR8zkgAU8lvp20eJo
         UEnqXuZJgCtsx+B9WGjRQGZjTsyl69qpJSL5xTQAUf14jFbqF2YjPSkqNgDruqPwC6qb
         HXNKg8JEWh1XAlAJ7eSE9xRpSiyORN3xo1alA+sRkpJxGO56Moa4NLGe9mfkTIFcwL1N
         5O11u0f2oslOACSfiFPf8VR3eJbQsODMAadklCbvXA2wLc+BshE3WVbiL2JXo9yExX+l
         cFnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893319; x=1725498119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DnzZvAP9fkPE3JVY1g2JJ39xYLhjqiTMoRLgvDYwFkE=;
        b=paptmaPPjy5zhipXghdudL2fn9le6Q42Ord8ZnHQNPDvjJs7FDT86DNHOArOSs8Ig2
         xI9k2VFrXI92O7J5ehz4DYKzVqNw1rCAn1fN23LtJhI5cjXi/Zd2S6NJeGoQ4k+ItmAI
         Eh6cviRpUx+KIHRf8aZnYgYGZyWtTI2sGhth62oXA9RlgLzBYk1kIX71LozSguYqV67M
         /XxoTvMghh/CEoYpNM0VuWiona0p06F3kNyKG0FW6PDCxdxqkLEVw7RicNXpQO0ywW6S
         nF7NM3BzhqKWW6eWvyMeMSiPr8KxqFVDtYJFMAFO4uEqdD6lOB9ESS27JGAqf16rh1zC
         kIcg==
X-Forwarded-Encrypted: i=2; AJvYcCW5dm5eJoUCCMeTxGSYN3BfX0nIA9Ui84h06iSzL3EQEpQ2/D5X04+qp2HXtJ7nB/Le2/OYuw==@lfdr.de
X-Gm-Message-State: AOJu0YyPaA4lUwfA0LE83vH1zqosGnPzhZVX1Y+YG6TNlJ5Fi0BKIORx
	AeDR9OMbtRwbNaoCyO8Z32LfnRLw2uytt2haSn7JmnibWQUWhDqg
X-Google-Smtp-Source: AGHT+IHusBY5dCwT3eEStveLRuach+0UESGZUSb8MSDNZqskBuj3cei/wuKRb3v/ZLpcPWy3hMsavA==
X-Received: by 2002:a05:6870:8a26:b0:270:b0a:cc0d with SMTP id 586e51a60fabf-2779006e272mr1659039fac.10.1724893318949;
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:758c:b0:254:6df2:bea5 with SMTP id
 586e51a60fabf-2778f0b1dc9ls669720fac.0.-pod-prod-03-us; Wed, 28 Aug 2024
 18:01:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXc9JYTvfpKegOVwRFOvYbleOBfKrBaoA0f8oJh+ANS+ANjOqe3eKUZc4hDAcV0S0zmVvS5gRrlwNA=@googlegroups.com
X-Received: by 2002:a05:6808:1285:b0:3da:e246:36f9 with SMTP id 5614622812f47-3df05e5e7b9mr1124243b6e.31.1724893318263;
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893318; cv=none;
        d=google.com; s=arc-20160816;
        b=xLxsAvLw6ukTXMjaT+PyVKC31lxVbEW/lETlOKf/fr5Ws327seAuTizzVdjLiJkhRo
         MeB8FOIhq5D6ycYtIBXiEfMeDIq0nbG1BFTqUzuOYSxBSuEwxzKe0KmlaEM8zXymT/FC
         pFAP+9NuxIl63K95et4JUcA10KJRrwT7ZK3e5AUsKOO/7hPojEtyDMcPlnhjEfBZi9bS
         l47Vv/26xZPdgViKTCMV4mvbhg7Jd1+1govV7FgJHNb91RS31+3pS731YJMEZCQrHVnt
         XSfkqxYSnnJ6/f00sCfxZBwkh9C6V6ovag/d5znyhloGnF8jssYVUse+FHXFGHtSM8W9
         Sb5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZG+HhHQwJZyYDPSqWXytdNleBw1x1orMvGaUGC5rVdM=;
        fh=PMavlanyS6W+m5wKxpU69/tFXLDPspRnx5K1k7EqJhw=;
        b=t/PC+ib654kCl9/yJ+2dhBt2Vvxow6PgHu7nZGptRLWHYvPJodccPr3yBS6kxRpvkf
         Z1yaYPb2dFNsRkFlmOxGBl+7SWgzDfST0aRK2o9yeSbdDNFKYnq8qo2GCfD1bcytxUWv
         QfO3ntcbDbjZS5F8DDNNIaqEeyRXweby5Fp3GXR09LD17Cj/DepjZe18sf0NjVVWf9rM
         eBz8QdjspBdpiGl2dJcgOi80+o9Yyz8KLhKfpg4krU7ncoE0dacC17UNE3BaXwGI6BtV
         2Lv0zwH893dDd8R/7/H1BRi/Fp3OmQY/LkcPqATRdrrDi5EF509uDLRd/LJgM5AVwC09
         XOKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=eAlMaHl0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-846a9da40a9si2799241.1.2024.08.28.18.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7cb3db0932cso48490a12.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVyFnhqqkls2p3ej8JxLz1lshRGmoZtHI01xhfZQccF9xSuT5CDp6FA/NxmRc3zbzXY7PMqEuvbU4=@googlegroups.com
X-Received: by 2002:a05:6a21:460c:b0:1c4:d05c:a967 with SMTP id adf61e73a8af0-1cce10fdc89mr1209674637.51.1724893317164;
        Wed, 28 Aug 2024 18:01:57 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.01.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:01:56 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v4 02/10] riscv: Add ISA extension parsing for pointer masking
Date: Wed, 28 Aug 2024 18:01:24 -0700
Message-ID: <20240829010151.2813377-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=eAlMaHl0;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

The RISC-V Pointer Masking specification defines three extensions:
Smmpm, Smnpm, and Ssnpm. Add support for parsing each of them. The
specific extension which provides pointer masking support to userspace
(Supm) depends on the kernel's privilege mode, so provide a macro to
abstract this selection.

Smmpm implies the existence of the mseccfg CSR. As it is the only user
of this CSR so far, there is no need for an Xlinuxmseccfg extension.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v3)

Changes in v3:
 - Rebase on riscv/for-next (ISA extension list conflicts)
 - Remove RISCV_ISA_EXT_SxPM, which was not used anywhere

Changes in v2:
 - Provide macros for the extension affecting the kernel and userspace

 arch/riscv/include/asm/hwcap.h | 5 +++++
 arch/riscv/kernel/cpufeature.c | 3 +++
 2 files changed, 8 insertions(+)

diff --git a/arch/riscv/include/asm/hwcap.h b/arch/riscv/include/asm/hwcap.h
index 5a0bd27fd11a..aff21c6fc9b6 100644
--- a/arch/riscv/include/asm/hwcap.h
+++ b/arch/riscv/include/asm/hwcap.h
@@ -92,6 +92,9 @@
 #define RISCV_ISA_EXT_ZCF		83
 #define RISCV_ISA_EXT_ZCMOP		84
 #define RISCV_ISA_EXT_ZAWRS		85
+#define RISCV_ISA_EXT_SMMPM		86
+#define RISCV_ISA_EXT_SMNPM		87
+#define RISCV_ISA_EXT_SSNPM		88
 
 #define RISCV_ISA_EXT_XLINUXENVCFG	127
 
@@ -100,8 +103,10 @@
 
 #ifdef CONFIG_RISCV_M_MODE
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SMAIA
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SMNPM
 #else
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SSAIA
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SSNPM
 #endif
 
 #endif /* _ASM_RISCV_HWCAP_H */
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index b3b9735cb19a..ba3dc16e14dc 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -377,9 +377,12 @@ const struct riscv_isa_ext_data riscv_isa_ext[] = {
 	__RISCV_ISA_EXT_BUNDLE(zvksg, riscv_zvksg_bundled_exts),
 	__RISCV_ISA_EXT_DATA(zvkt, RISCV_ISA_EXT_ZVKT),
 	__RISCV_ISA_EXT_DATA(smaia, RISCV_ISA_EXT_SMAIA),
+	__RISCV_ISA_EXT_DATA(smmpm, RISCV_ISA_EXT_SMMPM),
+	__RISCV_ISA_EXT_SUPERSET(smnpm, RISCV_ISA_EXT_SMNPM, riscv_xlinuxenvcfg_exts),
 	__RISCV_ISA_EXT_DATA(smstateen, RISCV_ISA_EXT_SMSTATEEN),
 	__RISCV_ISA_EXT_DATA(ssaia, RISCV_ISA_EXT_SSAIA),
 	__RISCV_ISA_EXT_DATA(sscofpmf, RISCV_ISA_EXT_SSCOFPMF),
+	__RISCV_ISA_EXT_SUPERSET(ssnpm, RISCV_ISA_EXT_SSNPM, riscv_xlinuxenvcfg_exts),
 	__RISCV_ISA_EXT_DATA(sstc, RISCV_ISA_EXT_SSTC),
 	__RISCV_ISA_EXT_DATA(svinval, RISCV_ISA_EXT_SVINVAL),
 	__RISCV_ISA_EXT_DATA(svnapot, RISCV_ISA_EXT_SVNAPOT),
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-3-samuel.holland%40sifive.com.
