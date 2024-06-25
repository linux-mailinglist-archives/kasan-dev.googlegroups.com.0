Return-Path: <kasan-dev+bncBCMIFTP47IJBBFXE5SZQMGQEUCRMDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 070DF9172F4
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:44 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6b4f87eb2e1sf91775486d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349783; cv=pass;
        d=google.com; s=arc-20160816;
        b=m8PimxRS9UIUaQRnbhf5S0b7Shw70Batpg9Vc3LukgQO75ZgNbU15YmsVgECVdYmTy
         nWWJSB8W+ShwDqdhKe4GMf1QLxqP81ildEqNoYWCm0y6ahIU6Jax1Dj5Y9YtPlVgo5qd
         wNuqQO99iFAY+4rXpaBhWHgkL23qKH8fhgg0zNXj1NeKSp/J9q0pNuLwx3u4AQcnV7DT
         iqgy7eBMPlUswVemtt7yfdFlYZpcVnyQbz8jd9MPJmOI/Jwf29srG34CDMtHGPC7Z7eb
         PEgNxrcF71klcMF/UfwVlp1Igcy0+7kcEGGedTdQDvcFc391orG0iGAAGsf7pS68WhEk
         UNuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ootJNgEnGefN6i7cJDFDY/qQkO/Jd/p5Y3Q5udxtlWU=;
        fh=Izs8wg6iqD9/apZjNGDVCNoXkuqCJdaXF+EWdrNAQDc=;
        b=uWDrWsj1RbjwEcCJE9CRtfw51I8cwuVZItT5N64N1idwmQ+lN7VsWH3Sbm8UJheRzZ
         rGNc3xQ5lhUvCphM1fl89+sbBQ23JrlG1Sy7HlS5bqEMeLVcv2MPL0XRu4lKJbH+jrMh
         ky7iNr95xm0AHVentxfl39Sfy5jufkfQ+4bi0kT+1ozGWIgbe+V8aCPOtCkwx++JNznC
         3yh2T+Gtwu4mdLAnyTU2hrZ93NkZ8S6QgmhHN//VH7IDbCIVbEcN1K8fcJo/mdTngoE4
         WSbLfG1+gpKq2mkji6jCLyREzmxYLOMoLL8xruoM+sQEufBh9WNYtRIS0bf5aKDCATyv
         gzlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=CrFELqxZ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349783; x=1719954583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ootJNgEnGefN6i7cJDFDY/qQkO/Jd/p5Y3Q5udxtlWU=;
        b=jQ/BGsgf8dQ3szk0d8s4unDREGdLjdKc/hyV/B19krAHvzhPagS9wd+pPynWnFSJOV
         4XIKd+krc4nBtcjV1cBmg/60+W4IAh1HP0kIS5z7OYFwkVNgj11ibgNd8yb62vC17DIL
         mNeb5g3oNSCDm3AdZEbM+5PHV3sU43xwrCDXc7RdihKc2qOk3AR/K6UATtftQtGmz3dp
         f7bUQUGQo9WosAfAcydSr79GTpEa/cQwA6UxHq/6CmgRuORfUhZ+xQUawAOQ2wJi59i7
         RdCzCNPqf4NPQdfVv+V0VvuSO//W2nY5umePVD982OMlKqsX28jhL+0liMEkucvg4EUO
         vCTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349783; x=1719954583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ootJNgEnGefN6i7cJDFDY/qQkO/Jd/p5Y3Q5udxtlWU=;
        b=ZGRtD1l8vAu922zU31k/yoIrAUHo2wA0jE7veKJEXj99aU2IQDAXzy6mfjVhWSvXcQ
         S4uChSTVe6TEN4JbYCaU4faqnivOUkMKAT0s+O+7AA941WwAwcRHXv7zqNdkr8353N0/
         vIunOsIhakEKJjTipHIQmHc5+gxRyUD/lYA+Epq33rSr3hgdGrt2Pkd1FpFScCI7KLHT
         Cj5IUb+hJkjl2y2XdowJqFfAgkohbaMEyiIG9w97c2GlpEg+Kbki82p8zxjW6zPgZkMK
         u8C9BubbumHhMG6Tg/8C8QtnvlUzCo8Q1+DKFmnozMRY6YC1veoQ3RNulUxlsEb+TtMT
         YmOQ==
X-Forwarded-Encrypted: i=2; AJvYcCVt7TNWkbS4qcbuy+//WSh6FrRrCvsWoz+dfl93dORahHdRSMDbA3jXlunEGsCPzZ5CL99ziAmHryF7VrkIuJZV6zlYw2Ddjw==
X-Gm-Message-State: AOJu0Yw8a3RNeYsYvA6yJXXYUS8Ui56pp5qqKzAtkWh3d6Gr6AmxFHph
	O+REk2sSNrJo9jiaaYTqhYsSauDYvdzevmL1TT1n62epX/Hd6vyK
X-Google-Smtp-Source: AGHT+IEKvyDJZp+VEziZezLHqaTktdWXAl5ploOaUOOHs0iq8ShQcbRP085tw8JwdOJSXeZqI+FzeQ==
X-Received: by 2002:ad4:4102:0:b0:6b5:413a:3f96 with SMTP id 6a1803df08f44-6b5413a4007mr81505076d6.10.1719349782855;
        Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5508:b0:6b5:577:fbee with SMTP id
 6a1803df08f44-6b5102e41bdls78275656d6.1.-pod-prod-06-us; Tue, 25 Jun 2024
 14:09:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRaE+zD5KKC7LkiqWNtrUgn7Xi4q3qOUuTu2gJVFNn7yvzdmJAzSPasDOZ3CUDX0L6fUW1Nyis7Z7gQZsQB+ci/o3PyVibaemekg==
X-Received: by 2002:a05:6214:212d:b0:6b5:4249:7b4 with SMTP id 6a1803df08f44-6b5424911femr120236446d6.0.1719349782128;
        Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349782; cv=none;
        d=google.com; s=arc-20160816;
        b=vEoRg/NTsRHcKx1BkHfZEH4YcfmfQA2AKNh4gQl7Q9ihfOLyQnmV1BoTFOWyP8689h
         CmIZ+H+wlejobYaCC/7MTp4GytnWI2sbBhMf+UlmeirOFAhrjKFgJyrH/OxZZxwzhZxx
         IpAZypuvxw+WDoXTEQk4R2uYM7nJPOW84h83oWPELkH6vv2ThUrwDBA2BGwLKzdEuJ+X
         Ma0R58Fv9NQU3OKg4jm180N7SblHNfSjW9y9F9qgcXMnGQysn46RvlAWJMObdYT6xlpd
         itRsb+Lyz+zXEiqUG2JYHv86M4lZ++p7a2gpPfW9PAHa1K9bshSMdKJwKlI056fOb0Tq
         12+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FrGWvMN3Ht8MgkCDub4Kzj37NN41tMPLHr9Zd0plWWo=;
        fh=XXb2JOR/N3fmrTaIg20ZdX2lX3UGY617UwVjFjzOwjI=;
        b=tF6V/ZI86ybS/cIt8CmVlkhwCrqyhk9HbRj5ZAJ/ThmsHJ6q4buiI0TooWWdwGW3M/
         xeWythkJdnDtHEpAbo6WtwwccAxTwgyXA6UOsk5zhQCJ7mOxEzSrGZmm1uki/OSMlNPW
         XV9VA1z8Dv7vv61wMCG8nXxJKwF0g1wXOPp4ncRQiHZlpMYUw/CLI1MnkuWG6LQ0rq9S
         YtSdmh0drp6Uqyx9i9Un/vcFXouMoMDkTSNoavhe4bTQcSArO+P84Ziz1w7iX8VVTr5e
         GduAu7wZt5OHykPgkdwHgpVuq0fHU2jaRGhiPSZiRdT/fmw+ftVJWhXc/mBlahAA2fbo
         Zs5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=CrFELqxZ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b51edbf5cesi6608326d6.5.2024.06.25.14.09.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1f9aeb96b93so42237505ad.3
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGfXOqUPl0NGUWDvzqvEaIoJJ4SZMpdpAu/VJ2On++N+92dqvgZdPYEcdLQhLJLBXd1Bz+3Xv40O+1Oe8JKWUhFwRVZMj+7Mhg0g==
X-Received: by 2002:a17:903:41c6:b0:1f7:35e0:5af4 with SMTP id d9443c01a7336-1fa23dce235mr106984915ad.30.1719349781063;
        Tue, 25 Jun 2024 14:09:41 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:40 -0700 (PDT)
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
Subject: [PATCH v2 03/10] riscv: Add CSR definitions for pointer masking
Date: Tue, 25 Jun 2024 14:09:14 -0700
Message-ID: <20240625210933.1620802-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=CrFELqxZ;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Pointer masking is controlled via a two-bit PMM field, which appears in
various CSRs depending on which extensions are implemented. Smmpm adds
the field to mseccfg; Smnpm adds the field to menvcfg; Ssnpm adds the
field to senvcfg. If the H extension is implemented, Ssnpm also defines
henvcfg.PMM and hstatus.HUPMM.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Use the correct name for the hstatus.HUPMM field

 arch/riscv/include/asm/csr.h | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
index 25966995da04..5c0c0d574f63 100644
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
+#define ENVCFG_PMM			_AC(0x300000000, ULL)
+#define ENVCFG_PMM_PMLEN_0		_AC(0x000000000, ULL)
+#define ENVCFG_PMM_PMLEN_7		_AC(0x200000000, ULL)
+#define ENVCFG_PMM_PMLEN_16		_AC(0x300000000, ULL)
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-4-samuel.holland%40sifive.com.
