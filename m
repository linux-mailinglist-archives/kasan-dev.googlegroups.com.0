Return-Path: <kasan-dev+bncBCMIFTP47IJBB5OO6G2QMGQEIZTO24Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id F0AC2951649
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:46 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-81f81da0972sf864413539f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623285; cv=pass;
        d=google.com; s=arc-20160816;
        b=u17V8IgWm+olg/GrHzcR/HeRBu47iUv6KGcviYc1qWNc+WjhAtzSu8oKICOzdOvboU
         ez8ZqDkDP8B6bYEHE/JCJ8TCH0wlkJjesO1xImHbf3AkXb5WR5Ugap3kd39KYsoLqQBC
         sgjmvDM6jEQrjHEtV+baWKCPzsrtdW0mJMbvi1WXydquB6Lb3fK6PeguCjXCrfpX4QNK
         8I3z2oDAdall1mLpyneQLJixdkLJIeTx6DEdKOpL9TYsqUwoAcPs8GZb6+0WiwbIiJqS
         7HJz6War7goKJvhMm7zikLN/0fm8En32Y7rcuIKKUUEVBog2vVosVXigo7anb9D3WiMw
         QzEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=crmABM7tJk9UdPq+PY4WRP+m/aLppfOxDZ2DpHg0Xxk=;
        fh=y2V6ESn15OtQ+aLWqrWjn5u4qT1gB1oid9FRFP5/2ds=;
        b=fYc7mGDiwEDgt/7TH6AzC18a993tKxYMDbLd1fyA99CfCnMq3i2zwJLTyviGrJW9QT
         QHOd2Qcr3+OFZ6DXy/HfZi3qmioInCDszpq1mEmpnMVXKRSfB8dpVUgbsd/1w1FUxxAy
         dZX0xGMioF+TsaXU54ndGT9qld3VvdmK6Cp8HAEmskPWyrossPD/aVuC20cYrSvbkoXe
         B0l0lYTlnKABzCPmibKW6Vl5kU/tkonUEFwuhtOcY3MFUP6+VaF0LdAs7O8tQBxJW6pC
         8HwLOiVLHxzkWlUkq92vFwhqq8u5D4ScNQ8p/y69dOOA3JgJPN3tsyWyJ0LXqrI3jsVT
         QYhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=im+LF83q;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623285; x=1724228085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=crmABM7tJk9UdPq+PY4WRP+m/aLppfOxDZ2DpHg0Xxk=;
        b=I2pdBe0Uq077nXqWnsS52KhsHJ1vuFfHiL/sq3W+aqrWqdO9Zam5ef4VQDgo+uvC/z
         VVvINKKGQpFkdzh+Q+nAPYdh9glp+IY4uRV0xqLWEV6FkZWcLjo6LUnJy5kF0Ccu3JXc
         4NngvaraYTjBCgmNM8MhtziZQgQmv885sHcpckJvob9ycR3vlPL4xa4vC67drwYldzSF
         RkiZ4efRRu9Cxgn4qqfNIw3M/xUA3KlumCHUk7NcH7sBYz6xD5DolMQzU0ZloVTkNgTW
         VbEEcgiljup02+Jfa2JYoRSQbnjtVFjckmPFptMOtRGLZvZZeuVpDkNUew2zN3TU29MF
         co6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623285; x=1724228085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=crmABM7tJk9UdPq+PY4WRP+m/aLppfOxDZ2DpHg0Xxk=;
        b=pTAj9G9BAv9EzaJ+52Rit9hmW+5Fd8QW2Pe/xtg0DUEa7W7Stmcj/lZWddbXddV5rH
         yqGKu4pHUtsdFXkyXbuOAcbpFXw3jPpEvCxjWln9c8L0XDCm26owYP4oJsOf6M8axzr2
         MV4WnICxOATeMZSlR668vuLWknI+LboiFnVBQM3iSQQk9ulaFqDNkxoF22GAUYj7/bww
         OoE6brk36ctH8XASfsh2p5MdNzFRtjKgva+YjdEvuTmjcTGo8+41lGh0nNW71DVmx+tZ
         MqaWT5QJ3J2zF2rcu808uuj8LwzSe78bFTHN0rJVo8YcsKVemLyY8bGVEiM92+FwAAbR
         /xLw==
X-Forwarded-Encrypted: i=2; AJvYcCWotBffstwyoGG6uP4CkLqzoIBNn/lcIoHeqseiB1mdLcxe/2S5mj+J0wCZiu/G3VyhRjBprtGMgdbZlZOQDFkDeoC1wrqw8A==
X-Gm-Message-State: AOJu0YzntxzXQIf379LXtpK+6qZU2NvUsBV4iWbSt7q6T1CH8Ukoi4jt
	egy0NJLUfZbb5/BzxxbMgbbTcdiglfW3dPrBpe/mcvWNbAAQNk6z
X-Google-Smtp-Source: AGHT+IFNMPO/NU7uYhun9EMeEz/6LUOJlp2an2O6f6Rl4jXfGGkNRCev3uMKWgBR8xgLdUisVUiA/A==
X-Received: by 2002:a05:6602:3f8a:b0:7fa:a253:a1cc with SMTP id ca18e2360f4ac-824dacd4d16mr207291539f.3.1723623285650;
        Wed, 14 Aug 2024 01:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dc07:0:b0:39b:2cee:3ae8 with SMTP id e9e14a558f8ab-39b5c98126als37411765ab.1.-pod-prod-06-us;
 Wed, 14 Aug 2024 01:14:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdlTROwZ0XjH3LBUSq3sGIVBwtQZfQuqEDmgKHLqo6eCAJ0cv4m9kXAD+sAPYZUKhCx81ardzwGlqxYD0MKXzsUWTNwC4geMS5VQ==
X-Received: by 2002:a05:6e02:1d8a:b0:39b:36e4:7486 with SMTP id e9e14a558f8ab-39d12447458mr23265015ab.2.1723623284789;
        Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623284; cv=none;
        d=google.com; s=arc-20160816;
        b=n1whoIBD8B2oAHo6lRc/LPSGEB+bFd5kdtkl/MnWWowkv0e6qGvAoT8pWGke2l2NCL
         LDWp+8YMoJRyVMW+G7MZUnt/E1xnTq4SfAsNf231GmvCbttrh6/Iokx8nLJLO0Ag4HnZ
         +VDyh3h+2xttnoVEtbR2Zza9yTRoNyHQmZb0ZxaFx+K7s7Xn77/8Szq8M+tUWad1uW8Y
         E3GQSOWGVVdyFwdHubIggcN2ICBfJJErTBPGPX2onfpPvVkI02r73RLISmxmLE4H70kk
         /2Rjj6gT/yF99pi+ODj+5Zgulv9IMlJZmRaLyYcAjPeYLpJkt/4DXSRidDgRWC1t9kgn
         HVgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZSgZOujLUXDH9o1etb/5haehfTStX4t+faWX1F0nYt8=;
        fh=Po5couR2ke3aSI1LBTPtYBa+jnp9LR7aShpkMEVcc3U=;
        b=eJCjzIHoei2aQIg0vjtm2Ax2ZuFDUVpp8fmOtGCqPq/1jxJe3l64g5u8WhPKWx5N5M
         YMLRDJtXRRUT6TDGM6X+994j9rPuLXdjSV0d5fxl8PcONXv2VqaST5ZR2UnCEUevPE0+
         UOLioEsG5U6xE6dfgLugZUXfQF9luFp/1Fn2HTTt0FS43CFOH5uecj4JxErjw2a8zik4
         HzT2m1WBE3XCQFk0kkowk1eHdBVHlPhxuwVDkfOzjDenWUtHWaU885TFJSauDPAXqciw
         uQDm0EAkohGh74hbp+zDMe3EBBKgWAy3KpzeMCYwmNrFVqHeF3r1Ix2GGhe028VAvUpd
         m+/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=im+LF83q;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7c6979ee720si134888a12.2.2024.08.14.01.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1fc65329979so58091625ad.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+FYLFkgtCC3E59T2/m+uhVID/Xxu72GhIPxblu5hXFsotFVHeVPuoziq8S2uce6o761DJiIDXqvSZD1tAJDTXuoCR7Q2d4W5cYw==
X-Received: by 2002:a17:902:ecd1:b0:201:de37:349d with SMTP id d9443c01a7336-201de373639mr4868195ad.54.1723623284293;
        Wed, 14 Aug 2024 01:14:44 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:43 -0700 (PDT)
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
Subject: [PATCH v3 03/10] riscv: Add CSR definitions for pointer masking
Date: Wed, 14 Aug 2024 01:13:30 -0700
Message-ID: <20240814081437.956855-4-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=im+LF83q;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-4-samuel.holland%40sifive.com.
