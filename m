Return-Path: <kasan-dev+bncBCMIFTP47IJBBOMV5CXQMGQEPTJKQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 03A048806FD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:23 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5a46ad3f0f1sf5282257eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885562; cv=pass;
        d=google.com; s=arc-20160816;
        b=JQZXn4WkW4GMMpKXwwMui2CLbuNrooO4YlZGZxkvZ7XYOFqzPmjwRcbfyiq7GagL7F
         i+Oaynp2glDHbpH5wVx4y4T+abQvhpMLqk+FSXHTYG55JoRjllKfn1+k0CzqUnYxd5OT
         t6URuVVcqPNa6XWf2mWnxPx9QRCVsnAWvW1N9QDn5IuBVt/FUITv8NXfq2f2SgBpj3O7
         qEGo4jclpx8Jt5EeNdSKbi8xVov/sBXGml8txafdrdYRrTJPklAJp5KnnDtEk3hW2NZZ
         tSpr49t5ejLSK+TrpnIvyzsczNZN+EVaX209W5PddEXn2j2adcSswTNA99v8K1/VypVe
         Nfng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZVMC4ec40qTx84JEfIOt5H+yRp7K6hVZJ+JR/p7Y8h4=;
        fh=pcxqYkss3JU70VDYUmxaP+lePVSqHcwAXyjYal4Ns5k=;
        b=Kuh3MVznp7B7AJDgRjkQFutDQheE1Glnp2soCNngWQJ1jc193B1z4i1cmtEXjy8kD8
         WvvRMadO8Ac5mjmJY09J9NxnA0dxAJTQujjbwWzImy+Gst+RaMtymglpmbMsagUmCj5U
         aBRKewQ+ZCNJaJkqQT6/N06cHmcKXjesApeaGoUQQ6H5xKkFKVy3/6JcRush565qZCeA
         p2MYX6S2Q/tZ7y7sMluG1UtWnO1WJFZXBheonTIpnjkIcAYOxScRyrhwwH5K9hK2cal0
         xYlSjiZ08Nc0sm1n5wfduCX6c9sAd3xhWYxwK+la7rUZTgin22vHP6GXc3Qq2zGf+TGF
         aYLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=aLFWOd07;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885562; x=1711490362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZVMC4ec40qTx84JEfIOt5H+yRp7K6hVZJ+JR/p7Y8h4=;
        b=FMUhoBR7uxBZZwklPCGDlxMlajP5YpgmxcsK2oefPM/wmkh/Id2njqFHra/mUnDsc1
         b2GHtfzwzlWLyWjgkv7pLxSUhTbRQ7DOeS5F2BIcH8sKQ17ozvVLMhtmK8fdissJWwfV
         YHeS4RvauQvnmT/Oc8CZ0USl4Ql8UQN238+Nl0VCj2RfA+nsHOGkkQ3Z9Vb9zDTwm9Ll
         KrQrDBuhhI9+yADXq2Vqx1Xv0c4I0QTd45eDeyVtb8Az7d8Zd40V10+jOcSVmWsTE1Ta
         mN1obkpU1YReg3/6/cIc5swUn4m6P1lc5Jo6r5xK7a8ktpMW9Eod9Nf2YYEoe3LM/qMy
         OWqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885562; x=1711490362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZVMC4ec40qTx84JEfIOt5H+yRp7K6hVZJ+JR/p7Y8h4=;
        b=F0DaQOalmVM7ptxtcCiHAYNUxPnNGNKJ2HpkgCpFBSZWlb3iWVIzNb/xNaFrfxiBlX
         Sg+Apj94aJiLsm5gO4lFGOgatTTdMhGml4LCkjDfwgNv8nADTl/VlHoFYKpvnmRp3eLh
         BUhjsPv4tNLVL0EpIoM/NdM45l9fJ9bSJfMYID4+S+jOU1kEBkORXh/Lc79ev0nOKBMq
         FNkmByddxjRocxOXO6v6Ksbwi7kKzsF5JsPteFcJvXmd1+0Y7crrPMsCp/Xq6SsokP4U
         INPFelT7LKzB6pNxgre10JI+dHgAm12xfeMjIWzcBP+dcEgD2LAksKIHbZD/+wZVIWDI
         mCSQ==
X-Forwarded-Encrypted: i=2; AJvYcCVef4jKWDGXABzhgv17clfYstBsS75ibrf2sujvPHqLNCDdrbULLHh75n1a6FVIhnZYfJJcibZ5YnQ6iMICHLRKGLZICZVXaw==
X-Gm-Message-State: AOJu0YwJ9rmEuIpASity68MNHooJGBGlDALSBwqg6weGl6mM/9wx8WaI
	FUend/ZYgfv1u2+ez8bR+YZLoJ5yNoa+5ICTGtlKV9VUUv9GSovB
X-Google-Smtp-Source: AGHT+IFVx77kXCARMfOemGYBoLsMp9iRoTiS1xkQdKQlj+A2oynraDZlX1lxYiw0v7qeNp8gKqj8aA==
X-Received: by 2002:a4a:9255:0:b0:5a4:6af7:5504 with SMTP id g21-20020a4a9255000000b005a46af75504mr12172746ooh.0.1710885561918;
        Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:929c:0:b0:5a1:e060:cd29 with SMTP id i28-20020a4a929c000000b005a1e060cd29ls5131000ooh.2.-pod-prod-01-us;
 Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8PwGwoENPQ7EaGpX+FMI4w0hKmBC76MyO6V0QOkS8hLa1bb55lkS5mmfAW+lKQ/Qitf14FNQ5iyv+YW2uXhs5A9jnoklpm0s1Jw==
X-Received: by 2002:a9d:6a8a:0:b0:6e4:fa76:9eb with SMTP id l10-20020a9d6a8a000000b006e4fa7609ebmr18537353otq.11.1710885561008;
        Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885560; cv=none;
        d=google.com; s=arc-20160816;
        b=zQ+lb4X4sCWHrXDTLcpmT+5yCE/SQxM8bngFJ/Hb7qTHDIx5eto1EUu5j4fI1Qctch
         Uj17UAZEK3WnKV6SeUQQuTqZNyaEtkfsk+wBLDgbnfTWWlRqYfnj4Pl++eq5/u3ecQds
         UxBJH+pNQ6f8+uqGyeo1j5ATnlsyfDLq2sKmSYDS4tJ6LhZcPpLBZUH1nGfzSW/40j0p
         DkGeImteDoltFzsK0GmWCGwlYPclGN8pz6G0UvULIJCS1G74O9qX+nEj+iKW04zvI6xr
         hh18YxBGPYaiqsGU3LWx6/nDpqA3s/QQlvuKWfjusIUnghmgk05bIm950ia1Napitbt7
         iB5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hw7AaJXdckjCcYy8ru8KTiHIANuUIN3Ni5CiYoljsMY=;
        fh=ASYjYghPG3mN4yeHHGGjrLjpwM9O4rZAnudBgmnN9fY=;
        b=WBqs4hIHRizOB2Jt+iOYDdFtn44Fcqzn3BwQ8xP1dwK5ZIdjQWM8cUUWGdweMbwodx
         3lFdugXtfaR2u7Ac5rwkEUoAFporZvyoBE2bQKDTzo6cSSCh1gICgPkQqH25/AgGHLfn
         CGxJU1CJ71mTsTdkJwwnNMk4ClhcqXg76AGRmH8TaJHbTxZ2qDpnJvyxNuZFdx7Vh4yj
         BV42baiLCTplyBqWgTylL9t/c2JfZrkHO5plmhsQIMvyF6zHwN9CJplTM8lhTKd5dowj
         TNeKwlX7zRajZ5p77ReQw8F85eK7ZElXsKEj7pgBHlM5LfUMzSH9lxBphXw9d9G1iOuC
         d19A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=aLFWOd07;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id o10-20020a9d404a000000b006e6857def18si491526oti.3.2024.03.19.14.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6e6aa5c5a6fso5822679b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVkPMTTlwD7TDYAiRC4di6ILzvRrJquaxXv4TLza6rGaGs2kFCnaKWrKiMUeGNmvPIIITJEQMUjwWY+cHMpVZvJFr5dr3iwpuXLAQ==
X-Received: by 2002:a05:6a00:1701:b0:6e7:8047:96f0 with SMTP id h1-20020a056a00170100b006e7804796f0mr796041pfc.28.1710885560589;
        Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:20 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrew Jones <ajones@ventanamicro.com>,
	Greentime Hu <greentime.hu@sifive.com>
Subject: [RFC PATCH 3/9] riscv: Add CSR definitions for pointer masking
Date: Tue, 19 Mar 2024 14:58:29 -0700
Message-ID: <20240319215915.832127-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=aLFWOd07;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
various CSRs depending on which extensions are implemented. Smmpm
defines the field in mseccfg; Smnpm defines the field in menvcfg; Ssnpm
defines the field in senvcfg and (if present) henvcfg and hstatus.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/csr.h | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
index 2468c55933cd..1d5a6d73482c 100644
--- a/arch/riscv/include/asm/csr.h
+++ b/arch/riscv/include/asm/csr.h
@@ -119,6 +119,10 @@
 
 /* HSTATUS flags */
 #ifdef CONFIG_64BIT
+#define HSTATUS_PMM		_AC(0x3000000000000, UL)
+#define HSTATUS_PMM_PMLEN_0	_AC(0x0000000000000, UL)
+#define HSTATUS_PMM_PMLEN_7	_AC(0x2000000000000, UL)
+#define HSTATUS_PMM_PMLEN_16	_AC(0x3000000000000, UL)
 #define HSTATUS_VSXL		_AC(0x300000000, UL)
 #define HSTATUS_VSXL_SHIFT	32
 #endif
@@ -194,6 +198,10 @@
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
@@ -215,6 +223,12 @@
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
@@ -381,6 +395,8 @@
 #define CSR_MIP			0x344
 #define CSR_PMPCFG0		0x3a0
 #define CSR_PMPADDR0		0x3b0
+#define CSR_MSECCFG		0x747
+#define CSR_MSECCFGH		0x757
 #define CSR_MVENDORID		0xf11
 #define CSR_MARCHID		0xf12
 #define CSR_MIMPID		0xf13
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-4-samuel.holland%40sifive.com.
