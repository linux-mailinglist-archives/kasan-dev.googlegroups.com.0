Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C751B09742
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2e8e969090asf1481000fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=fATEVtffPz3uguMWiVQlrrtLz5Fusf5hncmnqtdvYaYePd4BefZ48Vqk1BTk8TdqCl
         DjTt2c8eepaULlYX46GKj39szqGS4RdplvPkZdAa1SidtbGQcgqYKXCsDfRoXF89fMBd
         bQ3Bx1YDom7k9RCU4OSiYHIAWT9n1xYHkoVSzrkZ+t4T1Bmb4Sie7iY4cAJHLfdWnOPR
         zl4gAhpGxQxgg3/Thk/7Ok4ISLx+BAOksVRkwm/s8skMzyaCyZRey3Vtk6k3Dsv7qVbf
         uIWjxocXvIymWq7rccX0kOJbh0n7ntYzOo6cjTXtvjRDnsFLbjPw6+6/HcGHCJFYEJ1D
         tVTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=CHixn839/4dalsWrltAnEZ2TBOWepx8LRmK1lfngT3Y=;
        fh=FgTdMC3Vyqst98ovlUGvdglvoQa+eRjlWstc5iMy78M=;
        b=J7PvpEAbqwfX9YxyEe48jgZqBUVrWILrgNT8ESsajbAbgvZIEGNoarZ68EoUeNU4GI
         WCj8wn8LvNv8t2b7A592djEMaaJK+fpB8QhwJ0ZMsGFwL3JRJmsA+9dj87HPceSGKakR
         +9V7d1zFMTcJK+kNTjmOamUu5xjIuKCbZlXlC8pFykdy4gbvYXOjByBIvpMkI5r9Wde6
         znEV7VNPCcOCLhT/K6ZYghCM7cLjW99g1kmZAmw+4UDy+0fRLhMSwjOVpjEfaazmM1Tj
         osSZ9yxLnZQw5BaWKAQVqAcY/MvAiXwnIXqfNiNDZkyLBeoutVEL76nZCnxoJP1Q/cPJ
         PqrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NteDUBwa;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CHixn839/4dalsWrltAnEZ2TBOWepx8LRmK1lfngT3Y=;
        b=k/9Imb/tQzcVu4JxrcDyWTDxrZ2V7fprXho8XDFQjrUXadNOsfv16Ie2+W4kkR7TWt
         8y+Apa25cKyv+7LbHeCl4bVY+rOYIcM2Dxfvuj2uliKF7atPfoCgAALl93hW2/URN8yX
         3df7/fbJNDZMOEICH3H5xlP/ljHRj/6erayqhCgA7fM3zhqIEThRQNUw4JSI+mKU/Md0
         HmlYSzRTW8pptkU9A4wrFw4pYj5Dru5bD69uf0gakIhVYX0MhERxHL1YXVhGRh3v42Ds
         BPp4k2u9c2B3hvp/gZQ4WfRYngnp6fysLR3ldmcFdonV2BoXH8H82EzUZOt0U5LTLLMO
         jjtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CHixn839/4dalsWrltAnEZ2TBOWepx8LRmK1lfngT3Y=;
        b=Rb4rXRI1tcy89YLCdJZyHUhq1NehCifIPgJSsePmexrr7t4U9z/rownGdDWjqnNNe1
         IDNFTwRFZh8u0dtynnKmigQv+fgi3LQenG8T/t+pwY88gI3EaUfc3l0VTCbbj4K6N5H7
         uafPPbHZDCt97hRGe1GiMjE81bDQCDMACgaO2F4BrWUa8b3gLBiQx9fHybYsNcKy29ky
         mpq8D/DMRafYQX/7icVWTxUfCevmpfvM+fwu+YZDfVMirX6Sd0Mg5p5IyVbrqPjMhvIn
         HXBF3yMmqD7zXgSvx34m+LBVCCxPOz/fwBg/chcA1FXpkda+ImBp7zxfakD0yb/jqIpI
         3Gxg==
X-Forwarded-Encrypted: i=2; AJvYcCWdS4tfMZjlqOwOlMfuNRE5qxXtL2jqnF7gggKYxotSRM5C2cutp3fhf6XgtzvjC19OgdLdcA==@lfdr.de
X-Gm-Message-State: AOJu0YypjsMJXVV9B2zT63SrONLDRTlKbrc9AOSNF/OnW8l6gi5lZsFT
	WLPvB9/Iy3MQTcX4TsMlnG5hg+souM1UVmC1bsB0Sgu1QtCL7XLtrIFY
X-Google-Smtp-Source: AGHT+IHEjUP/hqNGMvMaIrC2ptDKp7rNm9FYrKqb1pstkG/pmu0/6bm8/+VgJUsSYa3QA2q/9HaEug==
X-Received: by 2002:a05:6871:220c:b0:2ff:9ecc:9af8 with SMTP id 586e51a60fabf-2ffd1f1b447mr2806529fac.21.1752794723474;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgd0uFsZ20HgJ6Dp2aMXjT4nhnXM/KzUxHDW3++Q496Q==
Received: by 2002:a05:6870:e38c:b0:2ea:7154:1841 with SMTP id
 586e51a60fabf-2ffca9826a3ls1195116fac.2.-pod-prod-03-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV66njET+95eHA2ePaJiSIg+VU/SFzJJAYHKDYExx9KzFnrnZV5LHhxhhrb1n7AGCLPM07m0owSZIw=@googlegroups.com
X-Received: by 2002:a05:6871:e584:b0:2ff:8e96:85ac with SMTP id 586e51a60fabf-2ffd0631e0dmr3825269fac.10.1752794722774;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=aStJOPx9NZqDYT91+ysCDoqs4PV2Gwi8QQH5L3a/L89O7bhIFcSbJu8sD4+2li7S5b
         X33GCIZLHVpea4m7kpl1bp3PRt4h7juH2lLVqgVxl4gjFNlDJyYHPTmVx0qtZlrfpZLW
         iU7zy6ETw5BlP9s5mKu3J05cdCJkVNV4izR4OHZnpor5tqLDM3lA38p6zPnlP5Y81MxB
         GFuiGcBeWURonn9RI2lXGuHTdhGbaQr/dV3trnLEr/UsBG3CWcgtNK5lvZUnRyeaBGCd
         8kHczQiIYJJm2MLGBI13U3qINIiiFCSN0kZP8nNrF9Rthu6joAtUZ+FFSJnRz+O1XmZ5
         F/mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=M709jLRtc2XgE706Ixh8CoyF/CdRnneMUqovlV8ji3k=;
        fh=6IfsBdTHXiGXJhUQGRPEi8EbiYIAgma1Vzd6MRblN30=;
        b=MNIgFl12khdThpHKJvhBFVs+kES8jgA6iCpT+fcmfnj93ZLXT06RliZR6VZ8b/CtaH
         rCFtkVVWY5m8HGqsIVHd9kl/lfdENlRFJgKzkKp6Qgs+zl8XdUrKi5t571eViNmA86x0
         o/mIHFOgNRUgafUZuQARH2cPqiXglgiAAO3kL0oiFiSSn2wYzvQUYf43HR6wKWin8Tu0
         ne5AR6y94bccEheqU169Ydfces1cHifTItrX1dMQIpEZUCoL29+TrXAnh+hRJnHt3r3X
         pbW0ryCq1Yb+aFCtWZ5Sc4UuMnPTZZEnEYU5YchvBbiqkq5z7Fpp+5ReZABv10eIFxyx
         d7Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NteDUBwa;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30101acfe39si13242fac.2.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5618645D4E;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9DBF8C2BCB1;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	linux-mips@vger.kernel.org,
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
	linux-arm-kernel@lists.infradead.org,
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
Subject: [PATCH v3 09/13] mips: Handle KCOV __init vs inline mismatch
Date: Thu, 17 Jul 2025 16:25:14 -0700
Message-Id: <20250717232519.2984886-9-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1054; i=kees@kernel.org; h=from:subject; bh=2ug/lH8nh3wdYXaBdZPOL2AvIMcZUPQ6EhDC2jpITSk=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbTEaTpwT/CqkP/gFhCj/XO54+7qYREShYs8l04cXr l6frm7XUcrCIMbFICumyBJk5x7n4vG2Pdx9riLMHFYmkCEMXJwCMBEtE4b/Xqd+XFyVnrjymfWn 4Kf1C05k68rFv26yrf/i2iH18eJ2SUaGV0lMd+enHioMXSjkm7z02hWe6SLiP1bPKvlVrXb+1vx GFgA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NteDUBwa;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
resolved. For mips this requires adding the __init annotation on
init_mips_clocksource().

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
Cc: <linux-mips@vger.kernel.org>
---
 arch/mips/include/asm/time.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/mips/include/asm/time.h b/arch/mips/include/asm/time.h
index e855a3611d92..5e7193b759f3 100644
--- a/arch/mips/include/asm/time.h
+++ b/arch/mips/include/asm/time.h
@@ -55,7 +55,7 @@ static inline int mips_clockevent_init(void)
  */
 extern int init_r4k_clocksource(void);
 
-static inline int init_mips_clocksource(void)
+static inline __init int init_mips_clocksource(void)
 {
 #ifdef CONFIG_CSRC_R4K
 	return init_r4k_clocksource();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-9-kees%40kernel.org.
