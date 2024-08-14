Return-Path: <kasan-dev+bncBCMIFTP47IJBB7OO6G2QMGQEGLHTOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id DDAED95164F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:55 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2cb5847ff53sf7735132a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623294; cv=pass;
        d=google.com; s=arc-20160816;
        b=MN4HuXBjyYmXFHKtW/+0p9qfGrsMftWvD5q3BWEjG1CYMhW0M7S2Un4W/rQS1hGVHn
         z777NGAuNINWXn69zVDfTcc2Ogj4Ln5DSc/Aw457yxrzg9o3qTWXK4FVXSRm82AgmCHh
         iLQSgzUJv1/F1PHQfUQmZWc2x0DSfuzTGwiW2KqIhjSDNbmv8/4ZKALHQyRbVJrap8Or
         TNOE1Q+nqIhODpLabpiFoeTE7pSsNQ5VmVYzdlIuXvsdw2Vm8xyyxwUulgaHof2cxeV/
         btr6+bEf8nx5YwR3nPcr+EpbbnH185+5tzzK5TjgY+7bnJORXHRoLAqtKk2PuGGLyvgU
         Gm4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=QuNNjaPuVbJPTFu/1VB03ZWru+hc8U0YgMS+ubomyUY=;
        fh=UAbCFxQYnqkjB0E2KF1eF+hW8Tsl48CD2GSKvnK0bw8=;
        b=Zg14qB2wjqeskBDkurWDufC450x/iQ2NNwmd29RHDCqZwsBYkQRXc7bCdyq8lqesby
         eFriY0qR/MmrzfgAoYCYo4GQm1Fqm8AdV4fE4dBEbQVN8vUjDQnDnsBH60Y34X2zaf5U
         7o+ewrLeDRsoXKinbxKSI+ougdMZn82owr7Y9wlR+xVrenwzoEibKX0SnGGmEuC+O4j1
         y/OAi/HgBTbdd9kEhlLFbNQjL6Hhpvznol/oF7wYKYgZLKS7utxGc6/l62Of9y85hRDv
         zVAeroBN/bJSmeeEKY3053PiJ4xqaIqd9C2gVDgqOVmvj9EiXlOBiz7KnZonffN6Oyr5
         isFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dFMs7zqc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623294; x=1724228094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QuNNjaPuVbJPTFu/1VB03ZWru+hc8U0YgMS+ubomyUY=;
        b=SS+vm0C9n339IhPo1x0TichNrnxaGsRpg/zB2DLXyUIxPhvRsrJkYnr8Qc4Uow64uO
         Zz6bd2v1tR1KAlrQ+RB0snJyycLso/EtORQHI9UHfIu4mgpE9SA5Ezk4GgMwEVrikBZe
         nCR1Lb8BNOL3pSPxPZsXwwDvABx82fYrmlcn/jmoKGZ5TQsMazwwP0sbsYYVNCurU6g1
         SSMF7A4UWXr/+F9BYwNLKunLDF9Fk37dDw0E1hOdXiQTq4q3VbrFfM5dZnWkZ6RI82by
         nocy8Q9MjyzWRKEkZE5j/ynCAz5RPtSdY/+ZEHQSnd5onrK/iz3VX1sSDy/iuDarcQCs
         V9EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623294; x=1724228094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QuNNjaPuVbJPTFu/1VB03ZWru+hc8U0YgMS+ubomyUY=;
        b=ojxxdjMwtNqgR2GLFnB5UMDScvaBDTCCxTPw2KOE4gXRoYIjo/04im2y7yye1nGDiv
         v1s6Dq9L2SFi2XY2P97GMiotwbwrVOaZEi5QBQPjATNSZwy/ubgnpAM0t+7bfztPV1zZ
         g8IzqDz4l5QAbZm+nzVSqnf4rKP/csL5FCO3RNZ2sxYQ3yi8CRAgqp0xxhupP0dSyVvs
         +EBJzMVSTZQILyn2lSEMDI3BCqFaUTfRQkAWmkNrFtUivOigLMWQOCJ70tUHP2vpc14W
         f3w6nzwvFyC4mZGVvMPLweI7LS0k4tRiOv6HVVn3yJMjFH0z6njeJmnH6FK9Ra1eC67l
         CVqw==
X-Forwarded-Encrypted: i=2; AJvYcCXEDQm2oOP4heNu+WXXhsDAZE2mr2Pw78kEl1EiH7xoHwK5U/S6frALzu3+8ypO+iiFefASmNz+UAJUkaiNQ0iDgaz1kkjl6A==
X-Gm-Message-State: AOJu0YyJHclxKlQrnn5HFbLJyS8oGMIpUS7CygGopTPD5WlZoSz5wVvY
	jZFrsO6k1+Ebi4qr8q5kvCelEHobUJebO9YWcKJIGHNvSjMyKGyQ
X-Google-Smtp-Source: AGHT+IHryjz2eQ7/OV2bsiW2kJpXsz8gynJJ3qlmkz99EROrcb3EeMnhDhnV76pQ+BndCNEAko820Q==
X-Received: by 2002:a17:90a:7c49:b0:2c8:3f5:37d2 with SMTP id 98e67ed59e1d1-2d3aaabd136mr2262658a91.20.1723623294094;
        Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3904:b0:2cb:6018:fd46 with SMTP id
 98e67ed59e1d1-2d1bbb84648ls3954137a91.1.-pod-prod-08-us; Wed, 14 Aug 2024
 01:14:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbakVxlroaW4Rg2ObKYj3R+24/cyoVhKtyEgdO/mnLZx2aiG//uYwkDaPu2UNAlMMqCSfO1fTe9yKzfXvhLyCP6Swp1uXEoJ7X3w==
X-Received: by 2002:a17:90b:1811:b0:2c9:7849:4e28 with SMTP id 98e67ed59e1d1-2d3aab43815mr2421091a91.27.1723623292975;
        Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623292; cv=none;
        d=google.com; s=arc-20240605;
        b=JDtVbA2atyzzebHNcECnvez5DSIZCHBH/7FYHL2/+M+Hr9gjGC4ETxuXpKgmkLzzYb
         tvstNeDiLxGZrG9pCz7ZU58BQhVyZjm6YyZOzCk2TmXrAfl6+lg2eugmYnf7sw44WAqn
         rFFUwLj35MgPWKnvFSchVtkdcrJI2I11OGsbDGIBy+6o0RVfBH1cYn7Z8bz3ub2xr7hV
         muFzLuWzgGOUYBbIwayw2hIInTelc/bh4az6eFfCFbt4TDggOKVpFJ986mjk+u69p1Ei
         uAUi2vUaeA7fnYunvqkEqBpI1ec42PFbi88dqiXjqAFAdsCbdvO4JvCXfuOhp2ZdYwqj
         wIRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fidSIArz80o0wKmWpcFbdk3lLWLuSUf3Uv0hxlg4FbY=;
        fh=Q+sI1HTFgBwwMYtdzhlcjYNHi8NVX5GRTMv9GbCufrY=;
        b=e+jKRNjwbAeRNYyu85KJ1U+2gVFLAxQQRMjpaXRhXWTYYz1+8m254tSDaMPqetfgha
         F3/N2Bqj53SWuMOR+Dz9yARF8gvbf7JmHoBCAv8O2Sby2Yafp3bQYkOueoTomKa2gE/M
         8r1h0tTDNG6kOW5yKL+1fHJjp6trwnM3ePYMloIlKBeHWWCCHImEXhAEJgleHEy7fElq
         Er3yXhTStsRTQajFqnHah0v3Zx1soiceiSSFupLItaNO+E/kmOaXJZHWG2L+7c0FS3yC
         jJywoYW7iMNXY4gXwRVhbclHSBKgROhyjAke5xLTgZohpOZirayz4sOKJ0ZNLcq8+tAv
         ud7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dFMs7zqc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d396a949f8si297759a91.0.2024.08.14.01.14.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1fc5296e214so61110585ad.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaTuWAo8OjXYzBIJCPBxzXIxMqrZZMyEK4vixq/mDLN+zbnHURMqwt65zNUSp6yx66phF4mmsnXc+FjAEBPMXzk7v4K+JFzJZ8jw==
X-Received: by 2002:a17:902:ea12:b0:1fc:a869:7fb7 with SMTP id d9443c01a7336-201d64c5c41mr29498095ad.54.1723623292590;
        Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
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
Subject: [PATCH v3 08/10] riscv: hwprobe: Export the Supm ISA extension
Date: Wed, 14 Aug 2024 01:13:35 -0700
Message-ID: <20240814081437.956855-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=dFMs7zqc;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Supm is a virtual ISA extension defined in the RISC-V Pointer Masking
specification, which indicates that pointer masking is available in
U-mode. It can be provided by either Smnpm or Ssnpm, depending on which
mode the kernel runs in. Userspace should not care about this
distinction, so export Supm instead of either underlying extension.

Hide the extension if the kernel was compiled without support for the
pointer masking prctl() interface.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v2)

Changes in v2:
 - New patch for v2

 Documentation/arch/riscv/hwprobe.rst  | 3 +++
 arch/riscv/include/uapi/asm/hwprobe.h | 1 +
 arch/riscv/kernel/sys_hwprobe.c       | 3 +++
 3 files changed, 7 insertions(+)

diff --git a/Documentation/arch/riscv/hwprobe.rst b/Documentation/arch/riscv/hwprobe.rst
index 3db60a0911df..a6d725b9d138 100644
--- a/Documentation/arch/riscv/hwprobe.rst
+++ b/Documentation/arch/riscv/hwprobe.rst
@@ -239,6 +239,9 @@ The following keys are defined:
        ratified in commit 98918c844281 ("Merge pull request #1217 from
        riscv/zawrs") of riscv-isa-manual.
 
+  * :c:macro:`RISCV_HWPROBE_EXT_SUPM`: The Supm extension is supported as
+       defined in version 1.0.0-rc2 of the RISC-V Pointer Masking manual.
+
 * :c:macro:`RISCV_HWPROBE_KEY_CPUPERF_0`: A bitmask that contains performance
   information about the selected set of processors.
 
diff --git a/arch/riscv/include/uapi/asm/hwprobe.h b/arch/riscv/include/uapi/asm/hwprobe.h
index b706c8e47b02..6fdaefa62e14 100644
--- a/arch/riscv/include/uapi/asm/hwprobe.h
+++ b/arch/riscv/include/uapi/asm/hwprobe.h
@@ -72,6 +72,7 @@ struct riscv_hwprobe {
 #define		RISCV_HWPROBE_EXT_ZCF		(1ULL << 46)
 #define		RISCV_HWPROBE_EXT_ZCMOP		(1ULL << 47)
 #define		RISCV_HWPROBE_EXT_ZAWRS		(1ULL << 48)
+#define		RISCV_HWPROBE_EXT_SUPM		(1ULL << 49)
 #define RISCV_HWPROBE_KEY_CPUPERF_0	5
 #define		RISCV_HWPROBE_MISALIGNED_UNKNOWN	(0 << 0)
 #define		RISCV_HWPROBE_MISALIGNED_EMULATED	(1 << 0)
diff --git a/arch/riscv/kernel/sys_hwprobe.c b/arch/riscv/kernel/sys_hwprobe.c
index 8d1b5c35d2a7..b6497dc0e7f1 100644
--- a/arch/riscv/kernel/sys_hwprobe.c
+++ b/arch/riscv/kernel/sys_hwprobe.c
@@ -150,6 +150,9 @@ static void hwprobe_isa_ext0(struct riscv_hwprobe *pair,
 			EXT_KEY(ZFH);
 			EXT_KEY(ZFHMIN);
 		}
+
+		if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
+			EXT_KEY(SUPM);
 #undef EXT_KEY
 	}
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-9-samuel.holland%40sifive.com.
