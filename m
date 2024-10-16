Return-Path: <kasan-dev+bncBCMIFTP47IJBB3ODYC4AMGQEBWWM2BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B19D9A13CA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:31 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7db8197d431sf263635a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110510; cv=pass;
        d=google.com; s=arc-20240605;
        b=NXiivD/gUFAShC2hDdWPCH/e/Yffu55/GN/fjvL5aBZyfl6KCIKcvs7EOYXR2VPbpk
         cuFosDaRXrn2NwAq2mBu+6Q2yM+R6G3Bnalo5LZji9s7gXfDRYtPp6Lrk0lkX9r96S+e
         1CiMb9n6hDbqKQmvzdcCT5n6gwNWPLXi7rQ+VuXP7JgCLL/jakqZ90OeTP/yAFcTL7Xn
         ywMIRocGvACqNxDwoZB3oNeXE3F9DaEegFJ/c/wcKPzwAXzf8Pss77UYqZ79+XuDo4WH
         IHoGqpsEZvI4DwIXNJ8dc8sew3JOcMG2aRoxGt1P0z/AccOi0EtugmDYxx7jSU4lobwC
         QNfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jrq6BTyzoUc4Xz1MXX1LI82QtNkYMq5AkI4BwTeVRpw=;
        fh=/oOsovMFgsOcOWii4H07BO2rs6R1sriLo05kVy4sb/Q=;
        b=CqU3o2E5yWP1dEP68hvPWy2YJh+Xh+QEbaLFidk8Xth7hmH7UhnX0ZMvnsaWwFFQor
         KG7xI1ex1mkIgy6ua9bbxGnUhibK7gJAyQBVaoWBki+DDTd3HK9jbxZApO+MlC/7u6lE
         sWsLBHREJJJhDCjPuNzjarBpnJOmjHNWRS6jwZVkgVGJLAU4yBmv8lNnFoRF5kvI2TAw
         jGXJ0NqTzHL00r/l3ckCdzO1dg+E23C++KciyXWLijCmP0Q6eo2P2ngdfdZD4TANghq3
         BeEVCiOUO6J/YfH9CXrqzoSXcUjp+vHmrHptZ0mxYmo3lDKdZTTuQT0yj/NnOK4WJAIl
         Y1oQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ZzmgS6Ob;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110510; x=1729715310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jrq6BTyzoUc4Xz1MXX1LI82QtNkYMq5AkI4BwTeVRpw=;
        b=WHqa0TRayg0xsTScLV6ANXsQvZMNtuvAULCO60ObYvjYi8BO/+8bBczkXdSIh6j2Cb
         RgaGfwWHj9jvwfvd4l3W02XhrBaE9gqbVMECRijstDpmcwu+fVbo7i65487DxeUTMBYx
         sYfPZ+rRjkj3qxkqfhn1RoPQPF5ef2HhWFdzjpx6/2HsioXzdXpWRpQXcINZwUNBCTyg
         tnwIgXhj0DqmUl/FFWd3AbUzEuymDuVBUfYdgnOMwk9mQ5nLO2/slruNtbfxFoU8wJj5
         4LzT/McEbdrcirDueGRWy0CmglZc9afTg7IjrltYwIGxxi6eFpGKzYqEqv4CjC/pQHoX
         uXfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110510; x=1729715310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jrq6BTyzoUc4Xz1MXX1LI82QtNkYMq5AkI4BwTeVRpw=;
        b=Hv7NEhEkPsW9YvHPD1rjHxIVYrA3GGkJ7o/M+NbNpSp3FQDq8uoJRtbvDp/BVWL04g
         WlJbXRccjF6cxkQRln3+oX9DFir0v8FZJ6Fjg+HGjPQDRPUYyUkHqlEtOxdrn56jjY6N
         m+njevmaNBdhNNGZeFrIcAnK7TfB0BhmVZuV9WEKJJgGPRXXTxvwlBW9xgg82i4+KBOj
         H/e3ERATcf1cZgtzQYxhjSoF8L/Iryyic77Y1xV7RJ4Mm2EQBTpVii2EJlAYRxqQNMIh
         +ORlUHY2nhqUnfw176/a7Q+05So0yDJ5eOuBaOSXJPKf258GYZ3Ow81hMCZoXCkbDfQ6
         Xi4A==
X-Forwarded-Encrypted: i=2; AJvYcCWyAoCldJ1vMuOjOsHDau+4Fn7awuhexcc5I6j2L3nwOiSUxIrFwDC4r2GhuawB3QmHrpNoSg==@lfdr.de
X-Gm-Message-State: AOJu0Yy3eNH1+BM00v0ULLlufpgmQwpWUwEnm582oPqxoHMob8FjTYhC
	ILRaYixm2KNFg3v9TLBuYTA8w0goeRhEYg7l7mfxnuHAsdJamP1B
X-Google-Smtp-Source: AGHT+IGQNv4bBl3BWaWifTLSqYpSd1mRzSjUsuxbcBGBsGpcygVcV3CX55TWNQq0i7Bbn8olLIXUaQ==
X-Received: by 2002:a17:903:990:b0:20c:8907:902 with SMTP id d9443c01a7336-20cbb2a0b87mr274192565ad.49.1729110509744;
        Wed, 16 Oct 2024 13:28:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dace:b0:1eb:1517:836a with SMTP id
 d9443c01a7336-20d47924d8els2115005ad.0.-pod-prod-06-us; Wed, 16 Oct 2024
 13:28:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyGZSR2tviHVTTu7eoC7xhlzqPoTVAkVLb0Al8G+eiLVDL0iz+V9+MtvPfbhY2X8QL4EzTexxH8uI=@googlegroups.com
X-Received: by 2002:a05:6a20:3a98:b0:1d8:efa2:89b0 with SMTP id adf61e73a8af0-1d8efa28bbemr9026661637.4.1729110508488;
        Wed, 16 Oct 2024 13:28:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110508; cv=none;
        d=google.com; s=arc-20240605;
        b=AMAx4ttMLhImw6WDI5brym5FUcANkqTHiaBpDflYwEryK3npDn4vd3zE3dyUAKKT8R
         JkkAuVbF7uZmX0FsIs0CzVdhb/aQpHwesrvRAJEdplKEZRTXX1Jw32tt7HSbr4+jXH0P
         0dMC/enMgsDsyNlAHlv40xSF+SMmX3s+PY2MZXADiQ+kB8t1cGxH29feSmqAPrltIjh7
         ipUbHQrd0yluQnfCOAjyKvkoU5Pif5Pj//81MAwmYR6pQF01ehDAcRnMjlnHCqi7efxf
         bbLobsqbwUc1vTviI0q2vxrzE9SLUa1zauTDPxhIkpXtfirQqmBgat1QkxcbprfF7DDp
         IaDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1uGi1aMTi7US+D+u4yTVB4/InTmfvX6ggJnfvqiu44I=;
        fh=U+Ucy7qXb1B3YVstAVmDU/UqgTw+6FxWcbjSrOopWIU=;
        b=aAuvgFT8WsWW7hny0q+MZ7G/bDiVS0E4LhngLWv1ZLizTLSPziOPVj9k5bYqJy066x
         McmDCw8TjYI5immQeBiJAiKHABLikf5cE4ohhmFXiy+OSCxmXP1Xhtw7SwYDBKcLAIWY
         0c1pZ2GY3J/37D9k6JWkpoMAPV+Cu2tTKI4ds69FzI7q+eNtnPRIsy+jj6N6pHl0s3Si
         7hYXbeBaDxlpGArbOdBD9EKd5fohMbbT/DdU9urq7eK62MEHjaSFPnmvO/p+tMYRN80t
         U0kqSZkIBdexGl5rj/SmbNOTQ5RxZoaB8W/ygvqaJ65H2MNqs2Oouko5Gnsoh9huzY5N
         2u3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ZzmgS6Ob;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ea9c7a6e76si205581a12.5.2024.10.16.13.28.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-20caea61132so1818515ad.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6qXec2RwkhxB5IpOiaX8mkQYi8lFrwXSNU0AfTLk9rVTJQFhubsrhfRurQT2Uq+fg2/9R/ItjWWU=@googlegroups.com
X-Received: by 2002:a17:90b:104d:b0:2cb:5aaf:c12e with SMTP id 98e67ed59e1d1-2e315371d8emr21626897a91.37.1729110508003;
        Wed, 16 Oct 2024 13:28:28 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:27 -0700 (PDT)
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
Subject: [PATCH v5 06/10] riscv: Allow ptrace control of the tagged address ABI
Date: Wed, 16 Oct 2024 13:27:47 -0700
Message-ID: <20241016202814.4061541-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=ZzmgS6Ob;       spf=pass
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

This allows a tracer to control the ABI of the tracee, as on arm64.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v1)

 arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
 include/uapi/linux/elf.h   |  1 +
 2 files changed, 43 insertions(+)

diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
index 92731ff8c79a..ea67e9fb7a58 100644
--- a/arch/riscv/kernel/ptrace.c
+++ b/arch/riscv/kernel/ptrace.c
@@ -28,6 +28,9 @@ enum riscv_regset {
 #ifdef CONFIG_RISCV_ISA_V
 	REGSET_V,
 #endif
+#ifdef CONFIG_RISCV_ISA_SUPM
+	REGSET_TAGGED_ADDR_CTRL,
+#endif
 };
 
 static int riscv_gpr_get(struct task_struct *target,
@@ -152,6 +155,35 @@ static int riscv_vr_set(struct task_struct *target,
 }
 #endif
 
+#ifdef CONFIG_RISCV_ISA_SUPM
+static int tagged_addr_ctrl_get(struct task_struct *target,
+				const struct user_regset *regset,
+				struct membuf to)
+{
+	long ctrl = get_tagged_addr_ctrl(target);
+
+	if (IS_ERR_VALUE(ctrl))
+		return ctrl;
+
+	return membuf_write(&to, &ctrl, sizeof(ctrl));
+}
+
+static int tagged_addr_ctrl_set(struct task_struct *target,
+				const struct user_regset *regset,
+				unsigned int pos, unsigned int count,
+				const void *kbuf, const void __user *ubuf)
+{
+	int ret;
+	long ctrl;
+
+	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
+	if (ret)
+		return ret;
+
+	return set_tagged_addr_ctrl(target, ctrl);
+}
+#endif
+
 static const struct user_regset riscv_user_regset[] = {
 	[REGSET_X] = {
 		.core_note_type = NT_PRSTATUS,
@@ -182,6 +214,16 @@ static const struct user_regset riscv_user_regset[] = {
 		.set = riscv_vr_set,
 	},
 #endif
+#ifdef CONFIG_RISCV_ISA_SUPM
+	[REGSET_TAGGED_ADDR_CTRL] = {
+		.core_note_type = NT_RISCV_TAGGED_ADDR_CTRL,
+		.n = 1,
+		.size = sizeof(long),
+		.align = sizeof(long),
+		.regset_get = tagged_addr_ctrl_get,
+		.set = tagged_addr_ctrl_set,
+	},
+#endif
 };
 
 static const struct user_regset_view riscv_user_native_view = {
diff --git a/include/uapi/linux/elf.h b/include/uapi/linux/elf.h
index b9935988da5c..a920cf8934dc 100644
--- a/include/uapi/linux/elf.h
+++ b/include/uapi/linux/elf.h
@@ -450,6 +450,7 @@ typedef struct elf64_shdr {
 #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
 #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
 #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
+#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
 #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
 #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
 #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-7-samuel.holland%40sifive.com.
