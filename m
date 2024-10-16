Return-Path: <kasan-dev+bncBCMIFTP47IJBB4GDYC4AMGQEEQHDRWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A1589A13CE
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:34 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e28ef71f0d8sf458417276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110513; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hcv/b1/NtXf/sdtg+9sX27uPO9bGU9i0XHEHJSflgCc0KjijUhk9n1DTFXHRm4DaHG
         O/H3z6lZUDLXuiyS2BYSTHrtpy7BHx4PkUxytj4gvWjYOjSJ6Dyo2UwHOl/pDbAHr0v4
         PAcA39XsG3fXUjvLngkxK7hSxZvNTWlji98xj4/hFRqTAhHSmHSQFd5VpvX0t6Lze2Vd
         FDX//lvJpgbBLmrHZ6l6wEBzZxTmlsF3S9DYTF4YqaWuoPPOJX9ClqrwXMuKBsEMcZV4
         SxnGpNutaPk0bSvv1w2D6hq/DFbsHi2vP2Vr07uRrkRGHIrLgxAPOg6JLMDDBmYN55Ff
         mV/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7heVFh5OXwqwvj9bLaP+vIp2lWhQXLWjLzveIAhTCAY=;
        fh=+cu2zgLMiJ7LmLMyuryEA4ITaNSGFy4o5GPTCFVWVAQ=;
        b=QxuX4ey88SaYgugjNjSE0hJPs5XwnIGpJZE42YQHP7HbKccZCTlkPA4PycbQM9lSRM
         fmhAla0Ns52bu64/5piO5ppmI3m50Eao3Y6j/yrpZ3BBVd2QcUwld8py/WQPRgUj9AF2
         vRNgK4wFBJDgi9omcvHsK8G06+7ohtY14AnDfNdNDMhxPCsMWIR3rddAMZ9+UeVLGPOa
         vdSJj/vFcwPOIwHS3JtjXhw2rX7r9gv9jqjV/GHA/OeOvkzIZhu6EeNMNfEQdZ2Ng28k
         mx/kuzFW+RnOGj9Fi0yJV7fce5Zcw5olnWVF0cMxUU96gTTYGvbcpwD+KR5IhADxUKk1
         Atrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=DWOQx7LW;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110513; x=1729715313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7heVFh5OXwqwvj9bLaP+vIp2lWhQXLWjLzveIAhTCAY=;
        b=OCUqQ5FP3YMMu/D4CbXML+QlIBtphYkSJWlahFP3dyHzNRU8Hkg3GgRh4mNx+FBu/W
         zMFhrBzIcRB81fIGbK/rNKt59LXhpwGGBeJPYKsGJ21HawW8Vob7wS8FbB9Fzt2AD1iy
         CIH0wQ9vNsvU+fEu60FuneL798lRNquA2z6Ni0YU7ewwYC6Sz0W4F8hH54ZBOVCA/JVQ
         cW1mvBArwpjyN/8pvQceZPdV4b2Q1jN9HBCxmLqtHUj4SJqeQXAb/LqKo0CDlcUcLiXa
         9BC2WsiOcxmbDTBozAiUaZlNcLi8UrWER0EvIJINxyUif5jGcX3Jzcp+0FN1xygk7Rci
         ZAmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110513; x=1729715313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7heVFh5OXwqwvj9bLaP+vIp2lWhQXLWjLzveIAhTCAY=;
        b=ENJqXexoiz7TsHr/aSpfW1DlYWaORtqvWbBUb8umVh1J0onqO0QgIu/JqNO6sO7AYF
         vkLycTAfAX0kWEbG7LwbXq33WiRYK6ogvPmP9jKE/X1ifDfaTGsCxh3yWH086sYd6Y1G
         ZekMxkaNTta/wUAcgtHqn2xHTiFLoMY4JMFl5KhTumwUeMgv2Lhq+j6i8Mi9o4X8x5uE
         43tgkSmlK7VsO6NMaloqZpOIxdEJQqms24koACFf1UpddPr6RGJ5IhpBaPLg96qx7wfl
         houAdvNojCFfcHx2b3LT5ObYbIeYwNGsuQykYDN/RnaFDrGRKLRPtCN8Hw5nVAo2MfWv
         OxBw==
X-Forwarded-Encrypted: i=2; AJvYcCVyjNI+Qu3k7bKfH6zCFOE7cwZF0Jy7at2JRig0m4w+pI/x2QOIAI5PghwsgM1aFVhq1mdscg==@lfdr.de
X-Gm-Message-State: AOJu0YyijGFXg0Yoe5wOXjj9j1+zc2IXanCkI9K05PZ8h4IeZ8aOVc+u
	x92bNikam8X8/C+WnATFK5LjCTPhdwXaQ/hbSrGiLc3CEGt7rWVY
X-Google-Smtp-Source: AGHT+IHo1eS/fI4CMYJJZrMRbxuKP2nYZs7olNP1i+lJbUu2wRrTbJj95T5Iak3I8e0ye8vl3HxTGw==
X-Received: by 2002:a05:6902:2490:b0:e29:2d9d:7b93 with SMTP id 3f1490d57ef6-e2931dcd933mr12984187276.41.1729110512976;
        Wed, 16 Oct 2024 13:28:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:120c:b0:e28:ee2b:34fe with SMTP id
 3f1490d57ef6-e2b9ce231eals137896276.2.-pod-prod-04-us; Wed, 16 Oct 2024
 13:28:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWu89UxVlI3uhleQoLUoV2/eew1ws4hapvkLtf2tAr9GewyCSNzS4ItUGfxz9hzCmdF+jfphTQPCVw=@googlegroups.com
X-Received: by 2002:a05:690c:4588:b0:6b1:1476:d3c5 with SMTP id 00721157ae682-6e36413fbd5mr146762167b3.12.1729110512189;
        Wed, 16 Oct 2024 13:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110512; cv=none;
        d=google.com; s=arc-20240605;
        b=XMu2QHbKrnEJc9ffsP2Mb/9BXsDW7kVaFwCb6WqVsOxqUOReCu4fE6aXTsdePvBYFn
         OD/ASuUniRB2k2ZTNi+uW/zx10pHafjDY9gI8iEp9wswxF22h4QRiGJ7kOi8bddRDW/K
         udngnmnv9nwsSIvl24tevrOCyJwMoa3JdXLJ/bNuZgT5tPJoiDqfE8DG+w38k4cepMj7
         gFaHKIW5B/tXNiGn2sq1bI3ZAKnHn5AWj7aFJKcyAgX7oiMCbEF6giid8HLUhf0MSnKL
         2WcBom/9akzXpZxJd6K75D25VQN2Env25qonCqrUCWMelnedfNMKF0gyUKJh0KCPzIqH
         ss4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yDDaRB4PMyQ9/gql9k5VOFo/XTjSV8DD59ducmwypkQ=;
        fh=cEItKllQXk38fIKvda0sLM3zIMqaCiB5Fk0rPXNVCCc=;
        b=Q5ZsWnHSLxfuXg2fHo5SJQkm8ASwOIbBpp3CeCvrYvwBSeleKoXR4nI3J9QMCtZjBu
         bk6z7kPHoF7VcqOZCFGFEyf6WbpfJ7GZho0Hhrba1xhZhfOV8aLGBKFxXST5bBwivEt9
         dQllv0p/LTbUj4wo9tLpiCwujKYKUBM4u3YUnxO2/rhVqZ5WUdesWeS0wS62Xmob4DNu
         Jpd8PjODOKWl0SCdknQblUeFvplyajzFmdpLOziE1rx81l5YM8Fk+Z+/DdjDFmX+1vDr
         Yk9MpGLwq0ERQ26pNX0sR4jf06yCQ6P8pPaCRhoxzGAlPHsJYQjckeEiqSdfj/szNBMD
         /jKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=DWOQx7LW;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc229fc8b4si1702776d6.6.2024.10.16.13.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2e2dc61bc41so164852a91.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWnaQuUTlIZItlnYxxWn8BS9OAGuid5pkCf90ym11CGfK/+FpWkIHa6g4yoWAKMdFdH00D0zn6LhgA=@googlegroups.com
X-Received: by 2002:a17:90a:644e:b0:2e2:ba35:3574 with SMTP id 98e67ed59e1d1-2e3152ca49bmr21323024a91.11.1729110511688;
        Wed, 16 Oct 2024 13:28:31 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:31 -0700 (PDT)
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
Subject: [PATCH v5 08/10] riscv: hwprobe: Export the Supm ISA extension
Date: Wed, 16 Oct 2024 13:27:49 -0700
Message-ID: <20241016202814.4061541-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=DWOQx7LW;       spf=pass
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

Supm is a virtual ISA extension defined in the RISC-V Pointer Masking
specification, which indicates that pointer masking is available in
U-mode. It can be provided by either Smnpm or Ssnpm, depending on which
mode the kernel runs in. Userspace should not care about this
distinction, so export Supm instead of either underlying extension.

Hide the extension if the kernel was compiled without support for the
pointer masking prctl() interface.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Update pointer masking spec version to 1.0 in hwprobe documentation

Changes in v2:
 - New patch for v2

 Documentation/arch/riscv/hwprobe.rst  | 3 +++
 arch/riscv/include/uapi/asm/hwprobe.h | 1 +
 arch/riscv/kernel/sys_hwprobe.c       | 3 +++
 3 files changed, 7 insertions(+)

diff --git a/Documentation/arch/riscv/hwprobe.rst b/Documentation/arch/riscv/hwprobe.rst
index 85b709257918..b9aec2e5bbd4 100644
--- a/Documentation/arch/riscv/hwprobe.rst
+++ b/Documentation/arch/riscv/hwprobe.rst
@@ -239,6 +239,9 @@ The following keys are defined:
        ratified in commit 98918c844281 ("Merge pull request #1217 from
        riscv/zawrs") of riscv-isa-manual.
 
+  * :c:macro:`RISCV_HWPROBE_EXT_SUPM`: The Supm extension is supported as
+       defined in version 1.0 of the RISC-V Pointer Masking extensions.
+
 * :c:macro:`RISCV_HWPROBE_KEY_CPUPERF_0`: Deprecated.  Returns similar values to
      :c:macro:`RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF`, but the key was
      mistakenly classified as a bitmask rather than a value.
diff --git a/arch/riscv/include/uapi/asm/hwprobe.h b/arch/riscv/include/uapi/asm/hwprobe.h
index 1e153cda57db..868ff41b93d6 100644
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
index cea0ca2bf2a2..0ac78e9f7c94 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-9-samuel.holland%40sifive.com.
