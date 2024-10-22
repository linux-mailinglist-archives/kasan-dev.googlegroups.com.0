Return-Path: <kasan-dev+bncBCMIFTP47IJBBA4O3S4AMGQE6XAB23I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 77B5F9A95D2
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:35 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2e2bd9a523bsf5368010a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562372; cv=pass;
        d=google.com; s=arc-20240605;
        b=dxhDxL7StSinJOWarwm4Uy0OZrLV4sDtfSapNBjJsucv64zVlouh6fBb+Pm5WGhOn/
         3X8wyaktx0QHqKG+eN5luCG9hgC32OoI/w7L0U2goYGFjDP4FU1AzHPxWKYSOI/yeZ6r
         JLW9JA3zufjmZog8R/EMwOdubaFa6+CeCPOHXeMmPrp4dK0/yBoBru7/+fHmdadXHyRM
         Rdz6vbJ9k+SGMkWv1hU4C8KNvoZ+qbQ9rkz1YpTi6Qd7hUiD/AbBeNBu1BUkt43/eRh7
         uFQdTfpHxiGkpRAA8axRIw6ZEXm7K0zO07GWaOU7/q7qBYBM8jwX51lr9/ZAxjMBPHKq
         5uug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=YUOCnJ2GE227KsXph1zlP+LslGBuHE+zk5ztdNoZI5E=;
        fh=kIlokOb/7hahKayvscuBaKz7MPY1GYxkPgn7tJJG8gE=;
        b=LdJx2qXnZ6K7Is2i26GCRwUg30LNb3FhBtBZvQJHiGRSh5MqSJRx3LWS4x301s9l9t
         C1Ev54A+2RsHQR8vTNWzb3X9Zjs+dQdvInJsUn8qYnTFmDlBdtdvlGjPdd8bEed0pU8a
         5lETbV7RBrYAN2tscsLzk/e6tYF+JwRycDYF222vb8QwHbOAol4hzSDM1WUhA1w88Rph
         ulvHPaIV2Ec1Dkitlbh29Z6uBSFNmN/852oBrfc6m8KKqtWlZc5UM25MuVcROovR7PBQ
         q9Jc1hSIKC1QAv0An8P3+DkDdFgxqlX+Q3LDSLS0INuvQQf+BJqVXWBuHqEANYMB/JhN
         BV/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=nmnDfMID;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562372; x=1730167172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YUOCnJ2GE227KsXph1zlP+LslGBuHE+zk5ztdNoZI5E=;
        b=peNhBG0/rftavSoFFL/Hp8NIg5Whfm4dBwhJE6ECE36UgQqK9+p6HDoTBdliPCIOxm
         4QapATLoXHAKJROdfDskCUkIyYsn6rWQhSdtYSHKaqQMyeX7+NAXVC/8A6ZCJkDO3Cmj
         KEEpmDzjU1SyOWhoy0+EHEoJs3GsuVgHrtRrGCpHiPv3c0qm4pEqlRoNSYd1csHcrCIR
         Rhis1ZX9+DNf+FVZLIFyOWZOHC0Ofm4bVoUTxtRfEbRvGJ+KbAh2jHyh8SKxvmNyWYxB
         9tTxSb55kgfrKeb06GF0ivvcXKki32bp3owVP/NyWDE9jNfkZSxvG9/nGyCpaAk/dzZf
         ukVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562372; x=1730167172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YUOCnJ2GE227KsXph1zlP+LslGBuHE+zk5ztdNoZI5E=;
        b=q9LZin1t4p2+1jVub4UF0/BqBjxygpB1w7oXJp5I1q6wCCYJMMdEufRfTA3dRFw525
         FGGo+rLKRWSvpknOJzwNLjGXOJ9PE6CaB1dEzzAgbchMbsACuPsO1P19gBaJKt+UdDxJ
         jQGqJRoM1ZIBuPyB0rbdf04lRRYQvOUn23NkWM5tGyF91mU5bbED2It1d0JbNVOCqeQY
         VlhQQeJgtBtQbGfha6EeB5qpPOo1tyc52n0YoxPSMvOR3CFfzXgNLPnU2jodTa/uzUZ6
         LlA0qSYfvh9w6EFUVtCiba5SdIFLxs1tI4OvSRfUG0H5R41jW7HehbhE/LlO/XQwl3Xw
         yTqg==
X-Forwarded-Encrypted: i=2; AJvYcCWaLslqoiYhuidIC+GUVLr2NIGavDWXN1UVkqQc2P0s09ExnPLIsyAAV9ayRlU6LALRHlPkCw==@lfdr.de
X-Gm-Message-State: AOJu0Yzl1WA/NyVvgS+BrflVza7+an76+C9swKcgxjBGWYNQc6jWqK7+
	LB4WjiG8FJVUr9shanlVPkozTOLhlZ1o6SQE5scAtFSm++iD4qww
X-Google-Smtp-Source: AGHT+IEp32vDT2rsjGR4qLRWs/bTmug2UsDVnTNQP/ouMghA6oJ9FSS3QGbJaKeWlK7ZK9tcsK4r4A==
X-Received: by 2002:a17:90a:cf8b:b0:2e2:8f4b:b4b2 with SMTP id 98e67ed59e1d1-2e5616e83b8mr14488234a91.27.1729562372171;
        Mon, 21 Oct 2024 18:59:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e843:b0:206:ba3c:2b96 with SMTP id
 d9443c01a7336-20d47b11d9dls9755835ad.1.-pod-prod-07-us; Mon, 21 Oct 2024
 18:59:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqzRKAnImchMusuriVx0IWzBRhO1rjpxw25EE6K4T7GVKL+T0GdXrH2U10N+qnANX7VL8BFYvSuPE=@googlegroups.com
X-Received: by 2002:a17:903:2283:b0:20c:6f6f:afe5 with SMTP id d9443c01a7336-20e5a9324b2mr195527155ad.50.1729562370975;
        Mon, 21 Oct 2024 18:59:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562370; cv=none;
        d=google.com; s=arc-20240605;
        b=fecCCFS7BxSSLfey7Ap6RxS/LqxnNSujNSip//+f3eAoFVWv4PSN7I0iXJWwbkYerw
         Q44qInbJY1BT1Wimhz1hSxM95gmJw9jIcLffYioKF5mxZOoULMX55OIOghpZphkYju1I
         H6UsnEISdXoxip9acfR9jDDK7bNQeG5piJMKDdcJ03gBdd29RQgP5t+Pu7QcE53kq/sk
         STKnbzABE1JXpsrzxTEkkyPw5CfERy6C9cHDIDe7qCpvHMwCPxxHUyeMgb4ZzkXp0/Di
         9DS5K//pqU9gl/ftW7AAvPAtsScqkxeGcpQ9HFaTJAEYWZJ3LFR3t60/Vm8VXuV4qaje
         umBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bo8mvyzhNAGog51IrcbhLjSHRzC25xwCT3do7aV0R5s=;
        fh=q+OdzQ7+ijFXms/hzA/vCA8Kgj7rlLRAXfKFWGQM2yA=;
        b=AISB/oQD8vteUWll/Th6ggHFAaHartsd90v/zntjW1EcdPvVfsvb/LAMIJsJ16SUvp
         OsStZCRUJ3F76OYx1qmYlNu+/2R5ddxEUwPh/Swk4bZ0O04EoDDYrp2uvIdXl5oPhvBe
         Y6ymP5bPJSfRXkIhVEaUnyikSSn5aRXJXXB/INxYFBhym5i2sfWMnnvHhf3RYc+K3TxM
         wuYfzDjVDUesKLyu2DL5gxOrC88Td9TOOrprEuETqdhUwvMR1fNOOEjSnAgtNAEn2trz
         yur0rQAZQNfNckBiczKEhAcq0rXMX6xMo+/vTovTEfXWdrdDMWT/Y0mS71YP4j0kLyiz
         E6oQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=nmnDfMID;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20e7ef03386si1973375ad.3.2024.10.21.18.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-7eae96e6624so1323590a12.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXCyHAidugRelNfIbfdfQZlTCFsRcxU8pB4lcbfhycFp12Qn2bjNxKOAz1ZOnbVEMU8IkxjAIM+fBE=@googlegroups.com
X-Received: by 2002:a05:6a20:b40b:b0:1d9:b78:2dd3 with SMTP id adf61e73a8af0-1d92c5100b6mr19225561637.26.1729562370603;
        Mon, 21 Oct 2024 18:59:30 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:29 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	=?UTF-8?q?Cl=C3=A9ment=20L=C3=A9ger?= <cleger@rivosinc.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 8/9] riscv: Add SBI Firmware Features extension definitions
Date: Mon, 21 Oct 2024 18:57:16 -0700
Message-ID: <20241022015913.3524425-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=nmnDfMID;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

From: Cl=C3=A9ment L=C3=A9ger <cleger@rivosinc.com>

Add necessary SBI definitions to use the FWFT extension.

[Samuel: Add SBI_FWFT_POINTER_MASKING_PMLEN]

Signed-off-by: Cl=C3=A9ment L=C3=A9ger <cleger@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - New patch for v2

 arch/riscv/include/asm/sbi.h | 28 ++++++++++++++++++++++++++++
 1 file changed, 28 insertions(+)

diff --git a/arch/riscv/include/asm/sbi.h b/arch/riscv/include/asm/sbi.h
index 98f631b051db..4a35c6ffe49f 100644
--- a/arch/riscv/include/asm/sbi.h
+++ b/arch/riscv/include/asm/sbi.h
@@ -34,6 +34,7 @@ enum sbi_ext_id {
 	SBI_EXT_PMU =3D 0x504D55,
 	SBI_EXT_DBCN =3D 0x4442434E,
 	SBI_EXT_STA =3D 0x535441,
+	SBI_EXT_FWFT =3D 0x46574654,
=20
 	/* Experimentals extensions must lie within this range */
 	SBI_EXT_EXPERIMENTAL_START =3D 0x08000000,
@@ -281,6 +282,33 @@ struct sbi_sta_struct {
=20
 #define SBI_SHMEM_DISABLE		-1
=20
+/* SBI function IDs for FW feature extension */
+#define SBI_EXT_FWFT_SET		0x0
+#define SBI_EXT_FWFT_GET		0x1
+
+enum sbi_fwft_feature_t {
+	SBI_FWFT_MISALIGNED_EXC_DELEG		=3D 0x0,
+	SBI_FWFT_LANDING_PAD			=3D 0x1,
+	SBI_FWFT_SHADOW_STACK			=3D 0x2,
+	SBI_FWFT_DOUBLE_TRAP			=3D 0x3,
+	SBI_FWFT_PTE_AD_HW_UPDATING		=3D 0x4,
+	SBI_FWFT_POINTER_MASKING_PMLEN		=3D 0x5,
+	SBI_FWFT_LOCAL_RESERVED_START		=3D 0x6,
+	SBI_FWFT_LOCAL_RESERVED_END		=3D 0x3fffffff,
+	SBI_FWFT_LOCAL_PLATFORM_START		=3D 0x40000000,
+	SBI_FWFT_LOCAL_PLATFORM_END		=3D 0x7fffffff,
+
+	SBI_FWFT_GLOBAL_RESERVED_START		=3D 0x80000000,
+	SBI_FWFT_GLOBAL_RESERVED_END		=3D 0xbfffffff,
+	SBI_FWFT_GLOBAL_PLATFORM_START		=3D 0xc0000000,
+	SBI_FWFT_GLOBAL_PLATFORM_END		=3D 0xffffffff,
+};
+
+#define SBI_FWFT_GLOBAL_FEATURE_BIT		(1 << 31)
+#define SBI_FWFT_PLATFORM_FEATURE_BIT		(1 << 30)
+
+#define SBI_FWFT_SET_FLAG_LOCK			(1 << 0)
+
 /* SBI spec version fields */
 #define SBI_SPEC_VERSION_DEFAULT	0x1
 #define SBI_SPEC_VERSION_MAJOR_SHIFT	24
--=20
2.45.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20241022015913.3524425-9-samuel.holland%40sifive.com.
