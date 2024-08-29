Return-Path: <kasan-dev+bncBCMIFTP47IJBBCERX63AMGQEQO4DFRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 89E1496372F
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:01 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-268a986afb6sf203602fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893320; cv=pass;
        d=google.com; s=arc-20240605;
        b=lekpz90WstWDo8AjMGOMDpTPiB7HOHbyiDKwJ8ARjV9X2Kg+52aO5UgtfrTzMlS2O+
         r5D8gOowfqA4T3Tf2DZHqMUbNwTWERIr/DV1sh4AS41nHW1hm+pxtundgPXIzPo6o8I7
         FIYcUp2lxVi4qcfHl4EhcvSvaYNgPlxGe+PhofCBP35KCmaMGPf3ab2+j/ye5bUlaO3X
         rbdIhSiB3fAqRRENFXdB2/1nu1g9p9bc+oyr/cWzqs3o3kPcXJpfGCTxu3zHtxmDfebN
         K0LMZK36Pgf3WtuC6jUm/W37pcBVVDgOJQff1RPaYY9ueNJP7rceYuu8DlvrMxOI21ei
         2bKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wG2/ffKuWNH6ggiOl1GrGWKciXU3DhGaLSc6Icx7k2c=;
        fh=NV+nkbIo4nynC7RwVl/rnQ8BTzaFVjA9El/xNu1R58Q=;
        b=JTkSiPCpXOdJQJfjIlAblvSVLbR4h64AAS3iJqTGHQlfexLK0ZnmoU6jHVhPdUGoBN
         iT1PImAgRaONibNW4j/SuDZ1L/vQhcpi8Kz4W3ncprfcq0Bu9UUY3RZDGVGb4oxBpZpK
         gyHMmew7K0iLeZhP6s6P6fQVn/jEugrDg6lT6l1L9TThX2EdzWJZJ+NIpchd3NEx0ENG
         RiOaT6/jLqTquyoCW2k7U4Fn+uMgm+nyuHkSY5fFgTjNrm5LG5W7Zel24blhDch3Xb6g
         mQ+3npUjRnUEq3PXNHPkAZCNpiClbTW9kL/EAzeS6rzDDgSCv7RgHRVJPFmjVXOiddFI
         VQBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=VnS2cM52;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893320; x=1725498120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wG2/ffKuWNH6ggiOl1GrGWKciXU3DhGaLSc6Icx7k2c=;
        b=pCrS4Ww4V6dij2ZZIH1H2whjJ6VuysLn2TFyw3s00N9wWd1NMjKsxtV5nfzQzdJm8I
         GcnhsKoXjtgdXJduJcxgynLSLBdnFjdDmaJlLCAjpklkXL9V0QL0Ofrra2cCYyKExaQE
         7erWDJHL1/80BWxPfVEVyKjPTQe14i19zKCF9WGdoKFEE5LkUiB6Epd4jBOhfHXieKwM
         mIrVVwPCOatF3dDSmBLbkzVZ+yHCGAoLMpq0623UsxlB72EqlHlGDiIL1bGuw+xRZ6ok
         quqislTpk/SEnGcahGWGdQZF8QhA4evA4V1ftyAEzCW2/JbvZoC3zhJPaKe7kmbu0v+c
         Zu9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893320; x=1725498120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wG2/ffKuWNH6ggiOl1GrGWKciXU3DhGaLSc6Icx7k2c=;
        b=JBe2bK1Dj8k6gm9qzv9S6962hh0ixnQJ/f7NLt0XTm59ld0jbkzeJUxtuJwSNepaQO
         l9nVssMf0OD5/8wsWuIFZThZuQ75bbBPPBEa3Ng3zt70OxfHSzvVWcm2aSZAmF3G/NQk
         cy5g3Kfsam61C50tt4hIYx5Nn8mRPSM3Qi/I5D9BX31Gp8ys1wFRlynCKn+Pkc2GdQWd
         D0rclpLxU6tZdwEGjqAXCyXCXj6VzHfQn21zyC8WwZb+dkiIdq7SVlft3AsVLWBAdHCZ
         gC6vh57/+rPWOMwY3SXQ+Dg4GExRi0CXTG4/IyL7hDBIQJICfava0W2PRO/tdZFcp2V4
         gpPw==
X-Forwarded-Encrypted: i=2; AJvYcCU0yM4afYHfBVr9lc0AK7PWJfe1uzXZbfPcOfsobkeHj8SO+XcCdUtI2NY/DdxOwp7Ybdk1KA==@lfdr.de
X-Gm-Message-State: AOJu0Yypn6vmw2Je5kKElT3B9ftfw51LwgCkI571POnXmzaox7Tjsera
	7aIXPblI3X54v25bpYOgM0UC56wrPpVCsSsyIFx14LtKaS9toHLQ
X-Google-Smtp-Source: AGHT+IEpoQ83eb0Krn4eFobOk3t8ssoB5EcWo9EpZrOh6PlMcyr07wtMIY5tBIMLAgsvvTPmww44rA==
X-Received: by 2002:a05:6870:200b:b0:25d:8238:1c3c with SMTP id 586e51a60fabf-2779010118emr1476234fac.18.1724893320323;
        Wed, 28 Aug 2024 18:02:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ff91:b0:25e:160c:c90 with SMTP id
 586e51a60fabf-2778f53fcbals740743fac.2.-pod-prod-08-us; Wed, 28 Aug 2024
 18:01:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+JUDtDBCjPJlB6/e05ncWZjM7jpTAiLPJ3yU2YIfw5Km93zyCtai+DiDPDtZCcH+Cg8hVhbR6LLA=@googlegroups.com
X-Received: by 2002:a05:6870:4210:b0:268:9f88:18ef with SMTP id 586e51a60fabf-277900f7ae7mr1764852fac.13.1724893319602;
        Wed, 28 Aug 2024 18:01:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893319; cv=none;
        d=google.com; s=arc-20160816;
        b=ptASelr7tblattJJjFF/0NoqPMGE0mKDxN12GU3xvYezSStuW5F5xmZKz4y0zcZMZx
         imuBfuMGvv4vDKRuM7sJxT0kALawhPtjdX9Z6wugwL1XZhiooiPSEVNj6czivmCdvaie
         yO1A0CxKZ5xm1wHAJ9KoirIHdN2nvlrSD0O0YKXv4GNWPLBWt34jVdxe6qtWmc1vqOsK
         aNkP0D74tVrA5CSJuZpQzIFO/fJfc4x1q2QNZ/ct52HLUwZr9dJnhdySngeeEEIKEXzI
         58KQHTJCH0MHLp+FmvlSU6Dh3j340JBWjCeSheZCz9ubhy4FCS7mJ3mmw30EDjzorXTh
         5VoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LvnGAjQNY6ccaQDDneANEaSxBsVmyy75aYzWJepO5sk=;
        fh=eD7BPWcHDeD+/TBGuKwTPgBsME1sdbxNa3KR6526U54=;
        b=xHnEDVzPXHQiSTw6buyGNNzxHOWqMTrepfWP5zWRwr3lUpiUrx7hARRrQAl0NIsEoi
         x4hHAe4LGED3diX0Gf0SvKioX1FUaEV6gpVJpZrWDkZn0e1/5ErK+RrHit/EpYQEi7eT
         HWZi6wqj8I5mCTWEq1fAwnyhXMaiQ0XWjWelBzscHwfDOX+9zd/nxkoj/sQL5EORWuOL
         7gNuS2mt3wFEiWPHVYwzrdLK/cxNDa16DkAd8z3fcSKXJhFbTTWzCOLwrIFA05mVQuuy
         0VQWi6pZgvPvJvORGb8do3qId4+ESyjDkhK/70BAIYbWvFLLuwyXmaGj9vSAk9BtVS3N
         b8vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=VnS2cM52;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27799f915adsi3991fac.2.2024.08.28.18.01.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:01:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-7141e20e31cso108724b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:01:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUwT1mGNVTh3ugORS1jsgyK5DHDEXUT5ZbXZnarhvbR6vZBrw/CLBYhJbJGxY6w+gdriEM5cnuvmQ=@googlegroups.com
X-Received: by 2002:a05:6a21:3949:b0:1c8:92ed:7c5a with SMTP id adf61e73a8af0-1cce1011e48mr1298963637.22.1724893318753;
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.01.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:01:58 -0700 (PDT)
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
Subject: [PATCH v4 03/10] riscv: Add CSR definitions for pointer masking
Date: Wed, 28 Aug 2024 18:01:25 -0700
Message-ID: <20240829010151.2813377-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=VnS2cM52;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-4-samuel.holland%40sifive.com.
