Return-Path: <kasan-dev+bncBCMIFTP47IJBBAMO3S4AMGQEMJFPKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D2CE39A95D0
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:34 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6cbf76b01desf79808846d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562370; cv=pass;
        d=google.com; s=arc-20240605;
        b=E9DU/SuZ5Gq2YBQUznU+lSDPRVSFTdDS0pmBtlXTufl7DepjHCEsoBpdpcRMnByjEW
         W1YX4OkB4bEe4OZ+IMTAbaaB0ePk9dgK/M06I6Vh5zIGPMjHhQAyPyU86/6h1KWNvnDR
         aeltj4WitQlO2L+MY8Bf7HTEQQzdWoaQ0kzk4gnkAaMAdmgqhpiHV2UiUc1gA15eJxEV
         sOxZqs6eNTKphQ3pqYB+fzey958iVICRtSHWEQElJd13GRo7YrBShyGTTZAsje1gsV9L
         9bZQXvrir+jAFAJcxToeL6L0Gqbswc3MinFbANR9gT/dAiTmYn/DPZhb+f18HwPLFeiZ
         SvLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3a0qSVav7312dpoy+lMG76WTtDsTxH/w+EBZxSIZ9ic=;
        fh=zztr2Zl75wBbLOspgqV8uT/IuShfBugsO1up/J7PND8=;
        b=CamAF1oOKcZHCR3Vv7IG9X1RPgnOy+0FlthAO4ttgbznfvDLVNxuV5e7g/caChj6LA
         xaUFn9DhlUpm+taI8oysey0p1D9c8eORqOQsIC7Au6h02+hHR9lqcQJPz1IdNtvAZsEB
         JGRnb3StUgShFAONIUAJ4Kx3qZiJd8tlydI/fggnly6eNFSCpn1qYxoatw1ftN3fGQJ/
         /SoGC+ahryEZ1OmRsqE/RNi2nfSM/3GiK1oM9aMe4zEXJ+vTE8NmJF2qqoH2jxzOmXTq
         s97bVNzeZ3o2OHgr6+aiW2gS6TdyRtsyj7PNXk48/Q3CdmnXOJQ4l6cM72u2S7EViybh
         wqgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=E56FiEN7;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562370; x=1730167170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3a0qSVav7312dpoy+lMG76WTtDsTxH/w+EBZxSIZ9ic=;
        b=i4b8Bl/qnjBBqmBcDn+e+606f+Iih9z6E7s1MEI3Ny5eAZJqcEdU4TnAa/igS9Dovm
         GQGXsp9e7gn4aWwWRVz+fRGA6jAhSRxY8ztX6GZel/YkU0kDgk3XNIj+LjCy+9HHNmRn
         4x4c/dRR48esryJYlDoNfx7bq0WAmc0KxOTjCs1jKMwyePYDbbszOUMgSTWNmV6D4Y9j
         haQYCfGFDQOTQYqJu72aoVKZzNuDHPR1qlEehhp35XFohXWv823DCwUb5GeOIra1MT60
         9ZUIBkO0lJmzoau+I5sjJrbNJkSkICRFv2Se+qmxRFyjB1VetSX1mWkkCcIC0v1/2zca
         Tv8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562370; x=1730167170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3a0qSVav7312dpoy+lMG76WTtDsTxH/w+EBZxSIZ9ic=;
        b=tzplQ3+qGAgtzVgFJ6M6gc6i6x79plepIc4B3qhd2q6qOq4iCb0dzFIUPsAR1Be/B4
         +GOOMrXTRzPaY2Pn7bU3x+kVc27z+I1hem7JKYwRlhsqklvoyItN5f2gVoyDTB/6gRoV
         O3wdk9rYyFoflDCwaaDiGCVyTv9yQlhXUPkpMr0+VKzPtQizusDSq0O110GDzrxYPIEO
         CC3n0U/PSfezPrXvCd4V2fKUU1tqDVff9UivaHtfNBqG/NysgJSvDCooPqEES0a5H8qX
         GSunbW0OmZJgyJ5lJ3E5XNfAZSVBKtHnmyounvlrWxYTWo1FqprY/l3IkL+OYH8cdH0h
         +bAw==
X-Forwarded-Encrypted: i=2; AJvYcCWKBvq/WTiZ8W30pQY8DRYSeVUFVDyMu2nStvNSiivyjAzzaJ7abIplf4ExGapi0v7Kn42aJQ==@lfdr.de
X-Gm-Message-State: AOJu0YzoIWQQ00+NRdDUvUbv/wA6lxkfqe9ROZyreoJbmho530CDjWLS
	n7LyNj/pSGqXDdYalG/Ziknpk5s3qfTzB53GGoyb9Lliom80sXbT
X-Google-Smtp-Source: AGHT+IE12K9XJbO9QBPTM48RNPNVEi0uzOXBFtLn2An/aWtFn6SUyRxBkguRwc29IND3HnV4DpiPmg==
X-Received: by 2002:a0c:ef91:0:b0:6cd:f1c7:7254 with SMTP id 6a1803df08f44-6cdf1c774demr137977366d6.34.1729562370031;
        Mon, 21 Oct 2024 18:59:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2628:b0:6cb:fae8:5fd8 with SMTP id
 6a1803df08f44-6cc36d8fc9fls108422376d6.0.-pod-prod-04-us; Mon, 21 Oct 2024
 18:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbWRnFc46BH7os+aFZDtH5os3/mSIHE7D29W8zCiGZ/yP9/57mgEqFHa0GmJgw0RbUFX+oGk5pog4=@googlegroups.com
X-Received: by 2002:a05:6214:5f10:b0:6cb:e662:c59a with SMTP id 6a1803df08f44-6cde14bddeemr232071766d6.11.1729562369245;
        Mon, 21 Oct 2024 18:59:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562369; cv=none;
        d=google.com; s=arc-20240605;
        b=F+znt/DbOjKtpJEr1VUVMdBlDAow+NGbgNx6W0f8V1RpRLM0Ji7EFe3ICJ7FglHT9Y
         ksr+wRSDEh2nh21GhbGpNCfY5VhPF0xNc9RgXdx0nqBVjRBvA5KrJNu4eTYEp0O2S+HU
         wczF6zJ3AWQWV2Zl8hrpqDlN+zvA0JJmsMHNhvT7G91p6r1aFzlpj8NEz9Mx0aidzSGd
         Izn0vQOQi83fMrcLWLETmY1WnmxCKfaN+0Pn+qtVDDbV/MlJvRjeeE2UVAoJROcb9uF2
         qjrBOiNiSKchx6jvEutibO+vNN9Xzfuo0N4Y0WyXZp7euGR83VJMjXcr9OYnSLT6ohFe
         8+5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=559wueV0PG6xFm1m5EmJll56/fKSQJhn2CptHQFJIX4=;
        fh=q5rZriHolp4YXS2sNbSpB7O0TuXv2Fo1UfMhGaOQuzo=;
        b=GIwbirefV4ZIfV+EHc/uz3z+fFV0LyXgxoCf0A2OS6twdc8VjbBMOEO7HQmWz+tccJ
         1v/nGFkvmBJmxB61rhMHk6uikDVFGF0D4bPdD+IFLH5qzJhDGsxY5FRb1fovaGKTYJfa
         3+iA3WYM/HegJhl/IPRD53FtTlPev1pYg7yZ1+xH8JrBnORWV8RJg/XZoalKoTv18Z+G
         TYeOgo0yvXyF+cTO+wjcaqsq2hNF52+PXF6vIAeS88SVyrBF2BtNNl5D3GR0nGq9bDnS
         22Ik1PshErjSoExOht8N5Xa6ALfXffvUtqdzMjsLLiWDhcJQU2oqjqlm22JOvdv3+wBA
         DCDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=E56FiEN7;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x36.google.com (mail-oa1-x36.google.com. [2001:4860:4864:20::36])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ce009b6042si1645086d6.4.2024.10.21.18.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::36 as permitted sender) client-ip=2001:4860:4864:20::36;
Received: by mail-oa1-x36.google.com with SMTP id 586e51a60fabf-2872134c806so1562409fac.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVXn3H5Yqg9OibOGdqCOkTt5+HlAxO3yjTrmqqTrU7DKXisMQpLERii4IdZIEKmUO308fcWixy3i40=@googlegroups.com
X-Received: by 2002:a05:6870:95aa:b0:277:a43a:dac2 with SMTP id 586e51a60fabf-2892c2df34amr10113787fac.17.1729562368580;
        Mon, 21 Oct 2024 18:59:28 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:28 -0700 (PDT)
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
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 7/9] riscv: Align the sv39 linear map to 16 GiB
Date: Mon, 21 Oct 2024 18:57:15 -0700
Message-ID: <20241022015913.3524425-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=E56FiEN7;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2001:4860:4864:20::36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

The KASAN implementation on RISC-V requires the shadow memory for the
vmemmap and linear map regions to be aligned to a PMD boundary (1 GiB).
For KASAN_GENERIC (KASAN_SHADOW_SCALE_SHIFT == 3), this enforces 8 GiB
alignment for the memory regions themselves. KASAN_SW_TAGS uses 16-byte
granules (KASAN_SHADOW_SCALE_SHIFT == 4), so now the memory regions must
be aligned to a 16 GiB boundary.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v1)

 Documentation/arch/riscv/vm-layout.rst | 10 +++++-----
 arch/riscv/include/asm/page.h          |  2 +-
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/riscv/vm-layout.rst b/Documentation/arch/riscv/vm-layout.rst
index eabec99b5852..c0778c421b34 100644
--- a/Documentation/arch/riscv/vm-layout.rst
+++ b/Documentation/arch/riscv/vm-layout.rst
@@ -47,11 +47,11 @@ RISC-V Linux Kernel SV39
                                                               | Kernel-space virtual memory, shared between all processes:
   ____________________________________________________________|___________________________________________________________
                     |            |                  |         |
-   ffffffc4fea00000 | -236    GB | ffffffc4feffffff |    6 MB | fixmap
-   ffffffc4ff000000 | -236    GB | ffffffc4ffffffff |   16 MB | PCI io
-   ffffffc500000000 | -236    GB | ffffffc5ffffffff |    4 GB | vmemmap
-   ffffffc600000000 | -232    GB | ffffffd5ffffffff |   64 GB | vmalloc/ioremap space
-   ffffffd600000000 | -168    GB | fffffff5ffffffff |  128 GB | direct mapping of all physical memory
+   ffffffc2fea00000 | -244    GB | ffffffc2feffffff |    6 MB | fixmap
+   ffffffc2ff000000 | -244    GB | ffffffc2ffffffff |   16 MB | PCI io
+   ffffffc300000000 | -244    GB | ffffffc3ffffffff |    4 GB | vmemmap
+   ffffffc400000000 | -240    GB | ffffffd3ffffffff |   64 GB | vmalloc/ioremap space
+   ffffffd400000000 | -176    GB | fffffff3ffffffff |  128 GB | direct mapping of all physical memory
                     |            |                  |         |
    fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
   __________________|____________|__________________|_________|____________________________________________________________
diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 32d308a3355f..6e2f79cf77c5 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -37,7 +37,7 @@
  * define the PAGE_OFFSET value for SV48 and SV39.
  */
 #define PAGE_OFFSET_L4		_AC(0xffffaf8000000000, UL)
-#define PAGE_OFFSET_L3		_AC(0xffffffd600000000, UL)
+#define PAGE_OFFSET_L3		_AC(0xffffffd400000000, UL)
 #else
 #define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
 #endif /* CONFIG_64BIT */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-8-samuel.holland%40sifive.com.
