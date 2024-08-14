Return-Path: <kasan-dev+bncBCMIFTP47IJBB5GO6G2QMGQEUADDG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D968951648
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:45 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e0bb206570asf11264028276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623284; cv=pass;
        d=google.com; s=arc-20160816;
        b=q874FNcZvx+vlkvBjkWmPhgyL88Siqa7aOuFPWGM5mowcnQMYvNCZ9wcqx+dFg2UuB
         1Y7uWlsz2Lv2z4xKyiFw7qbZRNk97fTw7xmxeUAOj2OtyBTkE7QPLQ+df+aWkrTVJU5b
         K6gis0nCP1ckcDh0CKO478RXYQGAP1b5hqUbXeKOdorSlb5XsRj4OrcBQi6+KQrtMewj
         wcTm68mX3eEnNByWth1bef9pCJDyLbVmHibnXkd6NHbUc+hLHTXlBhatv9tf+K7KzKd5
         RGveIrf5qSU7MCRn5o/Fv33vDCxkUz3U30B6gqeE+4ZTPrVJLN1viDGYeN3tZSFl1WHz
         NX9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Q6qeS8v3nNF5JP3/0QMUp7YwGcM/W5CjbcF04tosy1Q=;
        fh=GajdZx7qKTwIpIMh1idVX6Hx/FccPAqtMj3jwr1JGj0=;
        b=rjJXG+Z48uANqbcgt4HVsRDSq7jvwmvfUjXi8t3wCkHpB9ynB24eJTx1jHIVAiRI04
         E2yJ2dXu+PZ2eNUEygPSXXnjQFbOuqzrRQzCeYFfp0GoAzgxXgLPzr88N75I5P0l50kv
         9Gc4tHvnuQofL9AkxUN/ZMwdLFi9sgG34swTf9jSLV9au2+IfmW2gagIEiHjqBAwIwnf
         AqsIftUURz/ABIIk4bzDPsk3rLMUXKhNu2+vB3kNT08FWR/iaYTJGHaSz8/kpRBdepor
         +IRwhNCEYgB73l/8BjpfBrJhoWJyBEWngODlx9DvQF9J4IBPCyGSyxRnfedZHIou9COY
         E/TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mbUV9WQ9;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623284; x=1724228084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Q6qeS8v3nNF5JP3/0QMUp7YwGcM/W5CjbcF04tosy1Q=;
        b=dsCaHKlNSLbnGi8OGeRO/faJQJUCBke8/QIAztRTMHQttoYqxTL1FJViYNNNbI2tOF
         hdgNO14ARQrHmqwqbK8Fxav4cmWfU+Pn/p0yaOQ6HW0dzcKsW+U1PhjoV12AH2Z4F6e3
         o2u99C8LRX2sTJ43AwB8+I/3zB2cbVnLylDNGv6tphDYQ++XWm6erZgpLsf2lUoLrUKX
         Ge7y8xNUvHiya3pU7UcxZPPuNsYQdIKIlm4+oJi5lXXq24trqlnYLyo5cqgoGkN3TQC7
         2QGNgx0Amix5Wy0KOeT5ofLSVG/SyH8c1nGo/WBN1gJWfV6/Igm2wLWiYWFCoeqOgWO1
         wSEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623284; x=1724228084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q6qeS8v3nNF5JP3/0QMUp7YwGcM/W5CjbcF04tosy1Q=;
        b=tWQmydkEPyK4TGmhDk+swcYCmCDXfNDC0HWui+uV6kUkbv7YbzhkGhDLNj1FBxKNQF
         KCY4BwTVeyrpTOF89tsT4OWCTRkApW7lu2066hiEOXIqU18FNJxUvL2aV5w1rzhRmI+Z
         Bnm4gC/hv4m2UXf7vYXEE3UwuHYSJkplTmuOnHEPfydEt83w5rPbLtrRsIA8aYg9h5/s
         yn2a3gJXSNUlKKQ3FT9IHvqti+yRXWwkRXURO8ejRZZNOisOFM/9s3l7H0y3AwZdi2te
         FzVcwPCTWA4U1UMr0i7oC81qLxhv+2dWa6Dw0hC9Qu8hZtnpT6Duzjz8F6ES1Fv5cKHa
         2KiA==
X-Forwarded-Encrypted: i=2; AJvYcCXHHUDiGcgoirC8q5dVz34BOzCEyW/nasCx2BEfh77P3w+OBTigsJoLAAfEDTIp6TZNp9Xx4tzSE3a/lHcCKXsqazflkJKRDA==
X-Gm-Message-State: AOJu0YwOiKiKPvB9AXUsmt/vHvfDfiCtzV+XXhWuAS76/+KBmaGmHpMW
	8B8/wSysyra0NBKZaGy6fgng7rjmusM4VtCe6jvFDYoK68d9qLpv
X-Google-Smtp-Source: AGHT+IFAQJEls8+4HMbGkJlns0QZk0CEewjxnirotbiDLdC1z+mKHdINaL/l+WqcEbdTcQRtew5A8g==
X-Received: by 2002:a05:6902:1184:b0:e0e:7fa2:329d with SMTP id 3f1490d57ef6-e1155ae419fmr2328258276.32.1723623284327;
        Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1895:b0:e0b:ba20:7f79 with SMTP id
 3f1490d57ef6-e0e97710f9cls1965304276.2.-pod-prod-05-us; Wed, 14 Aug 2024
 01:14:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW42uX/GEAmL1NcrXzIdKktxW2XDZvNLn1/ElBzCejmnAISyzGEnWgWOAFVGSeotawMLpCMGcRSp4dvgUJ3kIDh2SliC6SaryNI4Q==
X-Received: by 2002:a05:6902:2190:b0:e03:50ec:5e57 with SMTP id 3f1490d57ef6-e1155aac994mr2085917276.15.1723623283554;
        Wed, 14 Aug 2024 01:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623283; cv=none;
        d=google.com; s=arc-20160816;
        b=qmdt1iXHc+lZb+9FuzI5q1CHEBqOXvNaL71mnBhp95io4/jjL9pdQakRewKjUBH9fu
         1ko8vkNs5EtYyNPHiiAYWwB32kHx/9sUOU2lE0aZoS4dC7bk7K5yYY7Ql/vYRhCvOl1L
         8N3tSJMLkTXk3Ii+KCrackhbO5g59x+5TrPHAlB5HlOPT3Av0+lBK+3SOr6gNE2AhPIl
         7eKJu0gpD3S4XLJXBEDPtMkerrgDlgH3juCstJN2wCbGmJ/TSqprUL33iG+Kdilvg+p9
         qZbtxjfTyqmNcHKcnu52AHFLvMtRKrpfQCnY8KhNmKmat6CeRFYWoqiTBirzedkZarM1
         ArrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MEQw5iaWeTmNPlPoMjn14hYPwuqLggUjPikbJBTJ9LE=;
        fh=0Wea5+D3kGaqA5J0pARORWVfH45JsWNQMh+L0r3+jQ8=;
        b=xGOiU8cmmfyqD3mRZwMbwsH6TFKvhfIbfL1cw8sr4L9U/Qk2w/ILmSBa0NQAEnP8jk
         MEFVRwySCEc1Lb1BE7TdpPZNXtP3fyzj11xMepDn+7jR6WDqXA8/k3mrEic2+CkBfHPq
         GYQOhqRLzzfkSfbQmaVLZGE0hoEanuvMJIFnBIguNFrlXAFg80ndl/UamSidqelmiWSt
         lW7G2w01uniWdb/5hXi5Drc239RHO3cDSOirV1p/oKu+PGOjfDnli1pzZWhGXCsi0xJE
         mY6ZfUSFQGMN1mlPUi6WFPChDdE47K7zBMGy+KrLD+VKK0d001NeyKpcumIGLWY/0Iv5
         qDWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mbUV9WQ9;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1158f9f31asi50531276.0.2024.08.14.01.14.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1fd70ba6a15so49194015ad.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdkOqlXwkpaI513pe5aWtYjGi4gTK/jCHIi9H4RbueSLADNHrLKi32KwZDyamLl6v57DJRU/8eliah55SwjAt+F2UVHL8o6NuO4w==
X-Received: by 2002:a17:902:c402:b0:201:e49e:aae9 with SMTP id d9443c01a7336-201e49eda06mr363875ad.44.1723623282655;
        Wed, 14 Aug 2024 01:14:42 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:42 -0700 (PDT)
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
Subject: [PATCH v3 02/10] riscv: Add ISA extension parsing for pointer masking
Date: Wed, 14 Aug 2024 01:13:29 -0700
Message-ID: <20240814081437.956855-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=mbUV9WQ9;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-3-samuel.holland%40sifive.com.
