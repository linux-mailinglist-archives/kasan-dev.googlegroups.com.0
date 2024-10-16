Return-Path: <kasan-dev+bncBCMIFTP47IJBBZ6DYC4AMGQEUD46JHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AEC59A13C5
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:26 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7eaac1e95ffsf174758a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110504; cv=pass;
        d=google.com; s=arc-20240605;
        b=kbMwsgvmoAcCyJBqVBjFL7kxrOntEVFtxSiGaa/iAWsS+Kle6+jsCLPcJewkIWkntG
         ekOW2daVkW1xA7BCUJyWUgk+TV6BJUI1AROXQx5T9KdCjVlUOCmJiwB/OXiO8U8Se/hN
         0dmhTexJi5h76yboWIKUSEx7vGCyGg+nUattlD2PvyohI90sYWXlTyzeI+RJBksgUFgY
         nCCV+szy3zSzrCqHvvZ5tguAF2yMmsl3mZ7XSGW3J5JWjinl/k+0uD/UR2gB2EvSm6a8
         cCTWY2pK3tfWV6s5zFYrYZh2GRd2T70cALZ2CNx5fT2PFCw2UE/9EyQgT0BZsfZhUwqW
         pDYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=J4EiL7oJiAe4SaMp+ghGzTnBn188K/Wm58jHDe2uk9k=;
        fh=snvcXuXvl/qnsK/KNoghz9oIzC4beH+2THwXRKIx8EQ=;
        b=khb6pkLAkktG4xm6IyLzC/x39741TTSClGwELnA3KfkRJ3W4+i2m5PnoaW9YZ9M6jO
         grIHzaK3cRqtSV7W77WGXtfc8KXt6qNaDcq6fO/SiKj46KN1M3YdRKEzBBMfNJRtpBV3
         5C7I/mDWpkvB6d6iY0Ap+SFbfTiM3FpNYOyOkTi5hLrWYGRMr7oJCBkMGMiMVbU8pegk
         bA7PKdxt+iZCMM5K0WqvEagLRpZ8kM3tWhCYslKuuRcqWvPxOU2FLjOJuu38J6TE+hg7
         dyHrj1artkS9upEPKNrEjqwzODVa/DYBzX8UYWAjn10TQz9x2B1aK1NWne4EBoTZLBoy
         18HQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Za4SJqxd;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110504; x=1729715304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J4EiL7oJiAe4SaMp+ghGzTnBn188K/Wm58jHDe2uk9k=;
        b=D/xG9pBcgPK+aacO83MTV1F7QtivejP85T2Ay2GPPD9NpObyOPZjBpLQR0hd3CDrfC
         tna39/SX3HRwLh0hpRTlLABLKuMKp6UIR5BOButH2n9o3psjY8qxLuMPzbsAusg2RUYB
         kYanv1IgfTfqCFc66nBtcO+Xrw8ncXmUnc4v+X7SR2FV1dtU2+Fug61CMoABIpsjz/WZ
         CF+teol1zmv+iAvTRvuyJM5fBub70uEpwf7C87gp4ut0wKFJoOboIMDxCJHn16ylnH93
         qak02OwhbjqeRfBnEk1G5RzLFqKI5oqW7ZRHse/jme3Eo7VwVAE0Or+CVGlSZWyIDGGy
         IQog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110504; x=1729715304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J4EiL7oJiAe4SaMp+ghGzTnBn188K/Wm58jHDe2uk9k=;
        b=w7gnwjwqdBl7o5Xk/uc9rwIOuX87HElASz4QqTy1f9g4fKpOZ5Gb5fzxWSvsHReZop
         kJ05aYlD/fTp4GKXl6RdRjrDMp3lm1RNwhsC/9PpRolhBgj6Vwq+HBXPHbI70Wnog9Ts
         T74rVScjztpyRSiSFh/qx18HfaCGRoyzBCMcPRu8LrLxHt847xJHmdJ4rDRU4x/dsU51
         8OqRCle48tUdXqaGt7U1K77v+NeERIUm3S6QLUAl1maqBG5zf1KX86j7gpPSkAtavg+Y
         RsW2n+wLycfb2g8aVDJEWzKVtrAq9q6X3nZcGdENEew8hP42g9b/1Q2EIffPXyXGMAjl
         cZ6g==
X-Forwarded-Encrypted: i=2; AJvYcCVP3Q1q16T0OS69v+/SX6VqUg9r9tPKNdCNnH4U+IY7sd8NpAKrTHO9qxy38KUkT51agDA2/g==@lfdr.de
X-Gm-Message-State: AOJu0YxIQpu4xiuv275GJpWwxQgv3Jnwo8g9CvrXUc0dFM7uAlkomKse
	0XqFbj9JIneGU8kzm/SoS2XH2iDRhBQGVQ9LkAQUOg/n7Mf6Ceew
X-Google-Smtp-Source: AGHT+IHekqf8S/cYnyFwfPnl8gSjHAKFx2A/ETG/j/52BZnlXBRfv20unE7HX9WNiC5IfHFlzIaDdw==
X-Received: by 2002:a05:6a21:4a4c:b0:1d9:b78:2dd6 with SMTP id adf61e73a8af0-1d90b782e82mr5150552637.46.1729110504169;
        Wed, 16 Oct 2024 13:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c89:b0:71e:7647:8d74 with SMTP id
 d2e1a72fcca58-71e8f8872d9ls207182b3a.0.-pod-prod-09-us; Wed, 16 Oct 2024
 13:28:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUW0ZHudz1rby9ktXP9o/Z9zCf+Hu8wWwxFRJ/n8pY/fvXhUUc2Sw6C/Tv0nNnl5Vs9Bw8SlskFPVM=@googlegroups.com
X-Received: by 2002:a17:902:e80c:b0:20b:7e0d:8f with SMTP id d9443c01a7336-20d27e46a2fmr74975325ad.3.1729110502991;
        Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110502; cv=none;
        d=google.com; s=arc-20240605;
        b=U7xE7idkpzRoTCbWnCg8j+l+/9E2dbLEOQ2MHxmli/2DM7fgIcfXjvNhhV74bVdbN/
         Mq1x7ivmme1iXYsdwlnZmeoU7FuONP92KyOLLGuxWxJNzt6ltPFfhckfnUZRhPjRmBhr
         qe941Jnc5is3b6l6nZgpHK6qPhPNpfr77HdSUvrfkkvwJdfXf3Vfe05AuIxqJ0cjnHEQ
         YPu3+4g1vOTyakUHyCiNOgVqnfkusvZIUm6TImV50TefAAF1Qviu0T7zCV9B/TUCqfcp
         JjVd9fD4nogJC99oRH6oPzZDltyjJ5SI5MQ9H7UStfNECdJofASzB/nxxa1rbwY7dDRu
         Xvug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q8L9RcsXGBuOOIJkGyl0uzoPHSEP08/B/TxdDRrdDog=;
        fh=9vmeiVA5aK29Q/19aKGoP+FglSdoLP5fA6rIF/s0wvQ=;
        b=Yttp0Y8iG+D2Iq8Xt4PWvViadMWc8fghvI2v+VeIvNuVs1r42Jig0ksLYxWQnTqBYo
         99e7DhuU0gQy90czA+3yrpUzo1TB97u4kATBvVVWDONnsF8ASNBOZy8layW8wAXp4TsK
         ZeixkbFiYLgAqRvL/67zKjRo1yoiFFytNzrJbdxWIesyOQi5qEXLY6Sw9IUF9EQvMl3q
         EvyY24QkYHrsTzU7aBDnImsrbcUrV5zdJ+I3nfNfl0q2imDXKOlDEycSCPXsak86nCFO
         rZRukXSxD12pTTUR6MM3AGDKzfdGOfK7kK35P/BO+aYEIavKyGLOukA2b9iT+wqS5gsC
         EMig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Za4SJqxd;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20d180946c7si1892015ad.10.2024.10.16.13.28.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2e18293a5efso155483a91.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUKpJE6FoVIkoAhOZnghrhjdmubiMJZetru1drb/TpN2x/h6FlyOZbEK2m2CCldMM1yqaQUBkXnVzs=@googlegroups.com
X-Received: by 2002:a17:90b:2313:b0:2e2:cf5c:8ee3 with SMTP id 98e67ed59e1d1-2e3ab7fe655mr6587578a91.10.1729110502579;
        Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:22 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 03/10] riscv: Add CSR definitions for pointer masking
Date: Wed, 16 Oct 2024 13:27:44 -0700
Message-ID: <20241016202814.4061541-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Za4SJqxd;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Pointer masking is controlled via a two-bit PMM field, which appears in
various CSRs depending on which extensions are implemented. Smmpm adds
the field to mseccfg; Smnpm adds the field to menvcfg; Ssnpm adds the
field to senvcfg. If the H extension is implemented, Ssnpm also defines
henvcfg.PMM and hstatus.HUPMM.

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v3)

Changes in v3:
 - Use shifts instead of large numbers in ENVCFG_PMM* macro definitions

Changes in v2:
 - Use the correct name for the hstatus.HUPMM field

 arch/riscv/include/asm/csr.h | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
index 25966995da04..fe5d4eb9adea 100644
--- a/arch/riscv/include/asm/csr.h
+++ b/arch/riscv/include/asm/csr.h
@@ -119,6 +119,10 @@
 
 /* HSTATUS flags */
 #ifdef CONFIG_64BIT
+#define HSTATUS_HUPMM		_AC(0x3000000000000, UL)
+#define HSTATUS_HUPMM_PMLEN_0	_AC(0x0000000000000, UL)
+#define HSTATUS_HUPMM_PMLEN_7	_AC(0x2000000000000, UL)
+#define HSTATUS_HUPMM_PMLEN_16	_AC(0x3000000000000, UL)
 #define HSTATUS_VSXL		_AC(0x300000000, UL)
 #define HSTATUS_VSXL_SHIFT	32
 #endif
@@ -195,6 +199,10 @@
 /* xENVCFG flags */
 #define ENVCFG_STCE			(_AC(1, ULL) << 63)
 #define ENVCFG_PBMTE			(_AC(1, ULL) << 62)
+#define ENVCFG_PMM			(_AC(0x3, ULL) << 32)
+#define ENVCFG_PMM_PMLEN_0		(_AC(0x0, ULL) << 32)
+#define ENVCFG_PMM_PMLEN_7		(_AC(0x2, ULL) << 32)
+#define ENVCFG_PMM_PMLEN_16		(_AC(0x3, ULL) << 32)
 #define ENVCFG_CBZE			(_AC(1, UL) << 7)
 #define ENVCFG_CBCFE			(_AC(1, UL) << 6)
 #define ENVCFG_CBIE_SHIFT		4
@@ -216,6 +224,12 @@
 #define SMSTATEEN0_SSTATEEN0_SHIFT	63
 #define SMSTATEEN0_SSTATEEN0		(_ULL(1) << SMSTATEEN0_SSTATEEN0_SHIFT)
 
+/* mseccfg bits */
+#define MSECCFG_PMM			ENVCFG_PMM
+#define MSECCFG_PMM_PMLEN_0		ENVCFG_PMM_PMLEN_0
+#define MSECCFG_PMM_PMLEN_7		ENVCFG_PMM_PMLEN_7
+#define MSECCFG_PMM_PMLEN_16		ENVCFG_PMM_PMLEN_16
+
 /* symbolic CSR names: */
 #define CSR_CYCLE		0xc00
 #define CSR_TIME		0xc01
@@ -382,6 +396,8 @@
 #define CSR_MIP			0x344
 #define CSR_PMPCFG0		0x3a0
 #define CSR_PMPADDR0		0x3b0
+#define CSR_MSECCFG		0x747
+#define CSR_MSECCFGH		0x757
 #define CSR_MVENDORID		0xf11
 #define CSR_MARCHID		0xf12
 #define CSR_MIMPID		0xf13
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-4-samuel.holland%40sifive.com.
