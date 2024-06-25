Return-Path: <kasan-dev+bncBCMIFTP47IJBBFHE5SZQMGQEV4N7VZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 037A79172F2
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:42 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-dff1bcbc104sf10621110276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349781; cv=pass;
        d=google.com; s=arc-20160816;
        b=pMfPABMZTLt89mTcJxXY3RWWZVGcnPvSAeg1TcR9wyNIC6Wb08IreSuyyLa+RbaoQH
         f+L/9fJqHPjU2p7IhAkq7cpApJlxe0j6vHwdNav63+xgpCHzJ9ZxHWCM+hqd86jFs9fR
         NT4AbBCKMiLZB6BCXSoINdU4OHjrorvANr0v5QVo5nB2kv5owZOswie3PdrQiTXZNk1Q
         15MbfK9Gx0GKoFFmupR7kzCjh22hDiG3Bm5vPsxg9uzDI4Fnvl3BvDKQOqAWEihlwn68
         xb6QY7amRCv6fav0Iw88a64pAmSs/z2vT9ktp4b/MB5nv1+qcBexFV7Ue2bdzRFPz3om
         TsYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=L9wK2v91jmaxlr5tW8A7zEgYVT6BNeNMjsMSye3vJfg=;
        fh=xLPUN4S3OnunROlL5s5e1CBXxFFEvOcl1KLewx8mPrI=;
        b=G7cYSLE+gvwikNbI6zBs0hjAYUqrz6gUoY3jo98KPpEVmS6bzTuKvMwthXIIHaEYQI
         oZea5H2J6B0dv86V9wTs9LVaI7HHzoAh1WPzHhCPI81L8GDDZJ2X5Vh2selaCOQIcxZ6
         f6PwCEdCloVzJ2nKr8s/+JhGPrE+3mQEE/V9KmofVZU6eiex58iEflaNAYKm4JfMC/Nh
         1yJJe48QPpqdIj6Kxz7M7gBhqUjce+8COXQIzct6xVKwhrvrWTk2oYrNOXp/qlWp5/bA
         HTo37fvmAwCRdssjyBFlo+vE8qhqyh5WAWOMKSmmcTpewwiEssIXZyvDh4V/1F+VrSkb
         scfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=cmnXluzS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349781; x=1719954581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=L9wK2v91jmaxlr5tW8A7zEgYVT6BNeNMjsMSye3vJfg=;
        b=L0gA5fjQL8jCts1FLLuCTbuQFhwWWX+ZWHFKzv/X/cy9RlrzMbfl+XMFTgvw+eyvAV
         iGu49JZbyVk01iNwbKNupHP1M3qSdZ/tz5MzXEZOXx58aBcaBCjK33MvJoHxoIu3m76c
         RSOuzzt04NVvx+RntRVSRAIbXD4gTxjlMwsxsTONlEfjfAE+Wb/+ymWfbwRGRfYeGsjO
         mzFEGLTPpCD5Rs23AbQFC76UgFElUwtW3B5UFxAlSuBW/7XiM8CvGOEJt9cj9mxAzA1Y
         eXrGYIWhIg+dB5eKsZYt7C8hqgS95i4S+vinoovqwnsUz00T6ofoXSlybNmUC7DIXu1n
         2JQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349781; x=1719954581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L9wK2v91jmaxlr5tW8A7zEgYVT6BNeNMjsMSye3vJfg=;
        b=sX/7rfSLJXAn13J83DunkphdVEYSWB0aOKyN3KlGqAQpj1MGZeXh7wqYrKsHJVTqRG
         chM3kfY964wAylrNEaa/vBXDSxlS4eii3XKuHdqZ2SisYu6Zds3ExABHZsSorezRUepg
         V4EfpBRxB2CKtSWTmWuyjDtflTghoyZ6FCYisqaM+wNVSS5TK2v45v4mC0ZFFafu3Pez
         PzPxWa16ILx3iksoEr0gsDLhmh1m7fgE9rSglYlLCTw/PKg14X7TXB/MbKSXJmLm53rj
         kbkzvat0Gx9ux/Wr/L8kWH6YucqGQD0zt8jBWTEKVXSNuhtfRhQB6zBrhDNXvuNbLG4J
         nz0w==
X-Forwarded-Encrypted: i=2; AJvYcCVMjTt/oeFJuhrodAj6cD+Oz9VThXjwFXEPUweZiL/nJpJsUmdpY3tV0lrShlqVxFnSxUsX1Q3gCkdCnubXZA3OeNfg8JUAqw==
X-Gm-Message-State: AOJu0YwJfQVapa+j0aQyWlfyHFy2h+cydSJpgjVgfKnjIOB3dVXAcKGr
	IJDBhhher4gERqmrQTGcjCf5ROr/FOl4Ty6jp+Xqp2zeS6vatgt0
X-Google-Smtp-Source: AGHT+IFnobsO27hGQsyor1s7CN8KjRt/0pKHYxRiwKT5JfSd8BT9YdOGXHP13QnrD+Myqncv8DXndA==
X-Received: by 2002:a25:d84b:0:b0:e03:2220:5bbf with SMTP id 3f1490d57ef6-e0322205cbdmr3485290276.50.1719349780677;
        Tue, 25 Jun 2024 14:09:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1895:b0:e02:c978:fc29 with SMTP id
 3f1490d57ef6-e02d0a8b410ls8525509276.0.-pod-prod-01-us; Tue, 25 Jun 2024
 14:09:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtnLsr4BOA32ugGNHbP4aoY2bsuXTbeJh/ukjLwxAJ5jpKPE8/8Tgy4d2R25hB16QQjZjeKW2oW/i5S2SS22XBttne4hcGpEcD2w==
X-Received: by 2002:a0d:e847:0:b0:63c:aa2:829d with SMTP id 00721157ae682-6429d082528mr86834627b3.44.1719349779980;
        Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349779; cv=none;
        d=google.com; s=arc-20160816;
        b=oQTmwRfgn049B4EuSOWFJyzlIiG8BlT99fq3M7uKS8MUrLtRgttsyzYcPJxf71BI/M
         drQ23PdSPOM+f668vw48oiMUs4BkbSBMSSjht0cB+B4FVXMnaROtdXiRCfbRUNtGmkKK
         lMbdyPcLyk5eKCEsOURVXzr6914ebu33vB5BJNDOYNeB6EeNXePXFMpz4s57QtHRzRHq
         ehHrHN2AVm3t8OcPDrXApuyKe+FOl6UhTvi69XdtQTvSwe3fFXklmLKS1DMAXDzxC7Gk
         7zkh1laAbeVOo6u9WMiLYjAjcIkg0kVKgKZZYb4m2r6hCof3MI0GHAN/6pUEbsq2uHpl
         R62Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/UOSPToUyaRaOvApUAfkaCWvJhdcwWzca8vHMvSzGJQ=;
        fh=FXjauFrUg84tvHVt695s8j9FkvnDWtejFfsNUxfap4M=;
        b=AOK507DgkbAe3MSpqUhRzU2a/kK6HqBuYQrKjx5d940foM+B/JWnn9TdvUQaU6/QGL
         18rJBfHHVF+PXUTe/l0BsczUdA9UemGVAUNqzICNzxebGUbjATIeIV/Rum3zGW5ppspA
         gD5qp8BD8Cwz77Dzw4dYRy7LRMgxEvEaUY9nkQomm3xIo9Ov1TqUl5c2G1yjmXxorPM0
         TvlVRF4a4dw7gJAZFBVCoTBvTcsNbKbiwrEX+Dc6hrDWwz96w0NE96vo5bzgba7vVkPo
         JEpAJSax1SHrQlDwfJHHaSNP8T8s9LukMjg0lCS1iPK5QsqQ+Zr+9MLR/aqTyArHzNsE
         ee0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=cmnXluzS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-647a9947e26si527787b3.0.2024.06.25.14.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1f47f07aceaso47067745ad.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXhAL2JZYWgPnQC/ga/kKrBUJtXFgPNYjTiXtuQ5jQjttxu1yvZu/sk8sXV2Krd3wcWKa7JluP9uevzq7vjk5vF3+iO3uMHyZii/A==
X-Received: by 2002:a17:902:ecc8:b0:1f9:fc92:1b65 with SMTP id d9443c01a7336-1fa158d0cc8mr98348615ad.9.1719349779134;
        Tue, 25 Jun 2024 14:09:39 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:38 -0700 (PDT)
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
Subject: [PATCH v2 02/10] riscv: Add ISA extension parsing for pointer masking
Date: Tue, 25 Jun 2024 14:09:13 -0700
Message-ID: <20240625210933.1620802-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=cmnXluzS;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
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
Smmpm, Smnpm, and Ssnpm. Add support for parsing each of them. Which
of these three extensions provide pointer masking support in the kernel
(SxPM) and in userspace (SUPM) depends on the kernel's privilege mode,
so provide macros to abstract this selection.

Smmpm implies the existence of the mseccfg CSR. As it is the only user
of this CSR so far, there is no need for an Xlinuxmseccfg extension.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Provide macros for the extension affecting the kernel and userspace

 arch/riscv/include/asm/hwcap.h | 7 +++++++
 arch/riscv/kernel/cpufeature.c | 3 +++
 2 files changed, 10 insertions(+)

diff --git a/arch/riscv/include/asm/hwcap.h b/arch/riscv/include/asm/hwcap.h
index f64d4e98e67c..5291e08fe026 100644
--- a/arch/riscv/include/asm/hwcap.h
+++ b/arch/riscv/include/asm/hwcap.h
@@ -86,6 +86,9 @@
 #define RISCV_ISA_EXT_ZVE64X		77
 #define RISCV_ISA_EXT_ZVE64F		78
 #define RISCV_ISA_EXT_ZVE64D		79
+#define RISCV_ISA_EXT_SMMPM		80
+#define RISCV_ISA_EXT_SMNPM		81
+#define RISCV_ISA_EXT_SSNPM		82
 
 #define RISCV_ISA_EXT_XLINUXENVCFG	127
 
@@ -94,8 +97,12 @@
 
 #ifdef CONFIG_RISCV_M_MODE
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SMAIA
+#define RISCV_ISA_EXT_SxPM		RISCV_ISA_EXT_SMMPM
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SMNPM
 #else
 #define RISCV_ISA_EXT_SxAIA		RISCV_ISA_EXT_SSAIA
+#define RISCV_ISA_EXT_SxPM		RISCV_ISA_EXT_SMNPM
+#define RISCV_ISA_EXT_SUPM		RISCV_ISA_EXT_SSNPM
 #endif
 
 #endif /* _ASM_RISCV_HWCAP_H */
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index d3e3a865b874..b22087244856 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -339,9 +339,12 @@ const struct riscv_isa_ext_data riscv_isa_ext[] = {
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-3-samuel.holland%40sifive.com.
