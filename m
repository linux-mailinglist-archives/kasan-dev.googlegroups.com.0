Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYUM43BQMGQEXPFHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B29FB09741
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2d9ea524aa6sf1682622fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=DSYKubQkjTvsfgOP1QGQG84txqm2QT7ou+fnQNRMmAiLSGjx+pAKxnR0Y0Ky+JuaHh
         b5Tq4wmyQYFWPatmPuAUsdU8ivjZBg4fDFiQxXpSvX83lCcK3vU9rJ1TsHfy4W0YMvEY
         UruYroX5XFHhlC87xNvdJY68KwuWAyURTkt/v2Mc8gDcWXNsIcbQ7aVaWQTrIt1QW/rK
         QiTeoP6x4LLrmq9hGqlmn81ZggAW8QOslxU2kGUpHgSwf9edu0jTFJCMo4/GSRFcqjto
         j0KkUX617DXlzuVOSkNF5dDaNhaj2NpyTW6W927/h/tuqjDqbaI4o5FhyPTNntLZ9Usf
         Ftqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=QJFzRFWIGEQ+Y3vaPIwF838ZylrXZMgTK6QmBZggMtU=;
        fh=hC8NW7rKj/Og8VpSarJX3MsDqBKHbmy8qObT69L0Tno=;
        b=lpogMjgwrSpneWr68Kdfs/f40VknHR4ie21KFva98pjfoCX62Ae4/u/8ZaC/jv+4Lj
         gJk3DfUUsnsRnaY/zB5NA0UGNf/7bd6m/oOOjWEXdtS9ccaUgJLD/KCRnH4ozfWgpgII
         cQkIKS2HOBHMu0STxbn3hrieTRqVCXGd22s+I5VfXv18lrxVA8AETovjaglYk5zAmkF6
         cbk6BBkvs1izZ/7GzE961FPjAwn/cumrVEz6oSbTzBkrFGZUfk7tKY6e/DyxyU/hetJT
         K9QRuSjroiBJKkRYrryBn4YLcSAQ8nS+edp24/z3JQMcePu6lZMvYawpMXgymRNko1nW
         z6+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="NS7X/XTw";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QJFzRFWIGEQ+Y3vaPIwF838ZylrXZMgTK6QmBZggMtU=;
        b=Q28VgWB/SrZ+4zD2Mp6Lsfhm6KdeV8UxUyHk8C+AzaMFzxikXzFM9ywYX+RviUIImt
         MCKmHmRYm/ynD1SzkAEiN0F1O+xB3LJdxH5sn/N2qTNY/SJq7thOixbcUXFTYSWWg3Qy
         t5B21yMr8rfJWqqZwavUZ6grOBxIjkVhu4EdZxm3oAL7+LSxk6KiKuhJCHxPGPo1Hscy
         qyo6RELUPj0PDRtWtXSyMTdRmOB5m+zM+R6GR5sDt+o4UzJYs3M4yR64KlTfohPhuso/
         j95pqAoff/e2WG+RqBa6gFn64iOjWHK/zI+plEHUQuiMAg/2yKMJXqCaZH3JjvEBTIj+
         GNTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QJFzRFWIGEQ+Y3vaPIwF838ZylrXZMgTK6QmBZggMtU=;
        b=X3hWshYRdnj+F0D48wcrrXJF27q6IYZlOBDhFBgeXCXeHj7T+l7QHJIzc+fuww6MAe
         8fCPuFVB5v0B7CHN7bWEqRDGaOPa6xrYNs1eXAHfuCSeq8NMdQ+znJaisiMDsHcW0AbS
         cALAoMnPZJ+93SjY5tEZzQFraITvl6u+7sjAstLY6nRBgYXr0mR5mAEMXAoeo/+vWJb8
         lJY7PCUS5U1s9BxwmFqzpcJk9Fq36OdFtp9jc3Q/l5VMeBgoYbipnKz+uH3DnLHyfLlE
         biuatOVa0vRH3TOcejwCfoTjaDCNTBUcCDJuLHlQwL6hXU3Kx9+DI4Tn+qSszPgwIFes
         8yQQ==
X-Forwarded-Encrypted: i=2; AJvYcCXuVJMhj1+qjmDYtwSZgKxCEFSHPnuVseAHTgfDT/wHm20ot9Pdq4Rzal+CELUf7snphtfg/A==@lfdr.de
X-Gm-Message-State: AOJu0YxHbEl2o0AbV/MaWCMepjt+ht2ar9AkHhHQNO1wTEp3s+m7fubE
	UYwV9byJITPdmG7uP+gArmCr/Umoe/YNAF9av8NyZMSvMt8LJy8wA5Gg
X-Google-Smtp-Source: AGHT+IHQahI57MP/hsl2pLSXX84gweIc91aYX4w1FoZs9fDZpr4GjqAe1W+IFuJOjqsOmcdjAMvCxg==
X-Received: by 2002:a05:6870:6123:b0:2ff:8f89:950d with SMTP id 586e51a60fabf-2ffb2293ca9mr5951737fac.11.1752794723076;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfwe/Mn4WcGRI0bAe7az78ecm4VQ62/qWGI8zbE+2+6QQ==
Received: by 2002:a05:6870:8804:b0:2ea:72d5:87e8 with SMTP id
 586e51a60fabf-2ffca971e44ls1011290fac.1.-pod-prod-08-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvpvsRltoGPSXZA07zfw/uVqgKaZcZ+pvPyTk4zvZdlf0LAiIa6VVE5sM1kBLCI9WV49k5FfTgt38=@googlegroups.com
X-Received: by 2002:a05:6830:90a:b0:73e:5950:1743 with SMTP id 46e09a7af769-73e66002e26mr6270656a34.4.1752794722351;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=EAPVowGRM8945Px3TAgV3JPyQGxxtEa7ZBA6MUA3qsWggUU87lJcR7SrDITP5Ab0/c
         QjM8OwxGPrugSzaI/lHucA2x6X8YlUjO5Ll1hOFdHoAFF3QE+eEtcSTv8G7f0adMLKt+
         c6+wFNSXfmKDjDXMwi4uD2xn7d9sFI2t6eLzPlziYFRDhi85cgVLZ8J18mnfvqHfSQCr
         dkAMPyKTp95liR6Ymnor+agGmBZU/HpLcH8eT2wYSKe7iSNvwElCeXVFhEYbdtn2b/Wc
         KKhZhVyr6PECiGjiqdE4IgMGKSf3ohhnOEgJYsslm/W4sOw0dfvVFjz42WOTpvgUnFv4
         aOHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OlTZo2YHN4mUSlk4pxkhvoD5faV7hXNmgVvajUQvWZ4=;
        fh=xzJyufx6tmrwYcQohFn00ZyubPILn2skWwrVK0gFCeE=;
        b=fbz3LWEgQ/8weq0O/wA3CRPAZztq3GtKN7whCk6yOPyp55cytuPG/JYZRCqeQpefG6
         uFUzWkMYmUAip8RIs0NDLO3OBwv47d6AU4Rbv5IWk/e/CSvM/0XV3Op3g9bdrdqBPcDx
         HogPbxmomdeutN1ERvy6UhlfsCt8S4ZTkxktfovnEcIp5UrZ5duWK03hII4Fh+qHIfpY
         ethvb1IwNpg1J/5J362g3tMGDZen0ufUXcLbTVX3gXErJ6fG+QFBZOcHtdwJiCj50r2D
         vOijF8BoFPz5CSDyDOQHEddRprOcX7jWdP913u1lXW74PSeTx4vchGCTW30O1pZnjud2
         0H8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="NS7X/XTw";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73e83bacc25si18410a34.5.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6880161406;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 80E8FC19421;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 06/13] arm64: Handle KCOV __init vs inline mismatches
Date: Thu, 17 Jul 2025 16:25:11 -0700
Message-Id: <20250717232519.2984886-6-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1393; i=kees@kernel.org; h=from:subject; bh=snrRkduazq+CuYpLqIIgLSyyFGO/4xQDvfJjkALfmd4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbdEzXlcsa9p/3vH4wcBunn0Xzgqe/i2/fPcJtzdM2 +dtv7RXoKOUhUGMi0FWTJElyM49zsXjbXu4+1xFmDmsTCBDGLg4BWAiJpcZ/meVLTv9o6vkxY3d a25FeUnp7579w2v1S82fR+ZrWufbpk9lZHhUJ9F5q+Oy06z3YoGri0MTin/7rdDVqX0tLvSAqbR 2Lx8A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="NS7X/XTw";       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we
have to handle differences in how GCC's inline optimizations get
resolved. For arm64 this requires forcing one function to be inline
with __always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Jonathan Cameron <Jonathan.Cameron@huawei.com>
Cc: Gavin Shan <gshan@redhat.com>
Cc: "Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>
Cc: James Morse <james.morse@arm.com>
Cc: Oza Pawandeep <quic_poza@quicinc.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: <linux-arm-kernel@lists.infradead.org>
---
 arch/arm64/include/asm/acpi.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/acpi.h b/arch/arm64/include/asm/acpi.h
index a407f9cd549e..c07a58b96329 100644
--- a/arch/arm64/include/asm/acpi.h
+++ b/arch/arm64/include/asm/acpi.h
@@ -150,7 +150,7 @@ acpi_set_mailbox_entry(int cpu, struct acpi_madt_generic_interrupt *processor)
 {}
 #endif
 
-static inline const char *acpi_get_enable_method(int cpu)
+static __always_inline const char *acpi_get_enable_method(int cpu)
 {
 	if (acpi_psci_present())
 		return "psci";
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-6-kees%40kernel.org.
