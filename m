Return-Path: <kasan-dev+bncBCMIFTP47IJBB6WO6G2QMGQE4NI4LZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id AEB7795164C
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:51 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6b7678caf7dsf21085566d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623290; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjalLPk+XVO1AlhLuKnh0HBzJmraJzDel8vSC2K9Xs3aEVZl1sxhrplhFaFPiPkXvl
         oKj13Lsyl3pBumX3sE+NygjPo2UzSXFi08qul3tDN1N1IWACY0r85e2K5nho/rXxxz5L
         SDhEVXdAJkIuXZxiU6JJsuq7JELK457nb4Mxp1awb5tUXfimQ+xnBaWcPajpjCikP+1U
         yT+JnnchsSY3eU/33BApEEIBCc8YB2uKhgISszGGnXOGYC1CLl7G85o9U/5k9qbHjR7z
         RpVaQ0A9ayhMWEzzoYeMEeSaCoGKHfYq1Xg2VJ/Ws4W/sYCgpwkW88T1xYADDAEPcVcx
         d3Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HaDpFGK9ePW/k4IcpaxiYx91C7eaWUHFdQlpkyVynn0=;
        fh=7LnaLq18/21MeL238Fly8JjhJtbX3RFa3HzNyCozw9w=;
        b=NZs4Xr8HQpbv+P8F9cCkcKw66h9txDv/Hbp9YNCLZ4y2puesryzatz6msjReF8eP0Q
         qshy+veYNOrqFHhXZfAQJuPxCmcORESWzU2oFV2QCEwviGSJW/hFtHGMZyM+tYLB28ma
         8ZsFlGVk4Oi7sf+DtW7bsfw/V63Uvtm+GsKm3rsUlR0HgiGkYsXqMfDPiaRDOWDwhXt1
         B+J6l8KzqSLNk0Ed3CdM1Q1cbT7BlRapWW+uHOULwJ7tfEfKddaleUO3QVZd7otCTYVl
         cmE7aK09wR4kWE9lgeZaSyvbh+JNffyn//YunGmLXp65H2Qxg1Z/aPp4j7Obcbxciuli
         9rrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=k6bATkf2;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623290; x=1724228090; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HaDpFGK9ePW/k4IcpaxiYx91C7eaWUHFdQlpkyVynn0=;
        b=hO5lfx44/RJrZiJxL7qH7rhmTOGAaD1lUi6wUd1b5qbYrhcpZ8XaDHv2u6HOMTgt+0
         9LgIPxYIj46VPOoJnDB4KpVLTXoAa31sEYF2fvd5LZCiWeIDuqE0sVnNebQ4QFN3oMri
         BTgn4d8muz/EnrGSZPUUcv+6hG4AGURATT/AOS6vQ2Hc+2WhWKZjXlBeNl0dSm5mPOp7
         xKWU2KEK4kNCl2t2Sa7h/wt8RwPE5e7rq9tfC30dphWsYfhE8XjCS73gfPJwNsdp/06w
         hiWJmoBRY1GBXmWe/duqY5HIYSQ3h3hcuHpLz2FTVfUp8lnc/67DCQA/HInGWOX4AakG
         I9LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623290; x=1724228090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HaDpFGK9ePW/k4IcpaxiYx91C7eaWUHFdQlpkyVynn0=;
        b=mY+JDaSX87RNDUwgobCx2UOFu3biv8tSrJFlk6B71DDDvsxciq4TcdNcpuKIfXjZj5
         hPVcgFMhsZWF2zlFArPya2pS+n0VMZl11urwC6MCrgpw7tVJPQCkVdJaaurqa4evUDm7
         HWFivh6m9XB1LqzaApxlQbzehXnE7hMRTBK+syyP5y7FA8fqhvt7iHOSZ8z1/U5fPC2/
         GoE6loIAr5dotMHhNFIXW55b9fWnr6q/cvdY7hGFFNorTyxvpMJu9m4JTX+jYbaJcAUF
         zmq3sUjnELS20chMfoyaT22h4skHNkZLn8xeiZs+lNBgblpS0BGM7Ue+C+xAilONtc/I
         BAMQ==
X-Forwarded-Encrypted: i=2; AJvYcCWnEELHzDSz6E7lXvrj/rYPF9hxDQ+9wPxFHLjdfTX3hid2H7NsOFQsIuMr0vtONiYRWDRTxvkZA2qzpwdCYqUAqNBIPxzfaw==
X-Gm-Message-State: AOJu0Ywy8BdcUHr4PvZ4BMS7K/A26I1EioJtwA+OWmELPT33u/N+jFT7
	q98/yq5NmDH91MKCfk1Q5524lLBNg3H93Adk+CzXV6VWNx/8UpoI
X-Google-Smtp-Source: AGHT+IEg/pcruEKsCGzejhzZhtZ0S/ymxcF4ji5CwUOf4eaI6ZyqkdeIOgX2hQrjJGdXzwZikkJkPw==
X-Received: by 2002:a05:6214:250a:b0:6bd:738c:844b with SMTP id 6a1803df08f44-6bf5d22c2a9mr13054126d6.7.1723623290423;
        Wed, 14 Aug 2024 01:14:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aae:0:b0:6b7:9a07:4191 with SMTP id 6a1803df08f44-6bc845d4e1cls115563016d6.2.-pod-prod-01-us;
 Wed, 14 Aug 2024 01:14:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWznHKZGGcy9VNe1GU/syLf2Q09FvFx9n5lTclJE2yxr55WwKFMxWw8c4KbUFc93YFKSeANnHQjQqQg0sjehE3Fa8QHHnKy0Chlag==
X-Received: by 2002:a05:6102:d8b:b0:493:e66f:6bac with SMTP id ada2fe7eead31-49759926c50mr2245193137.11.1723623289811;
        Wed, 14 Aug 2024 01:14:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623289; cv=none;
        d=google.com; s=arc-20160816;
        b=uKxyQQEJ8srBOgq2MXYOvBSSuhF84NqYVzEiCVP6qinHfPJJOPeQwD34uh0m+5aeqe
         IUSFW7lP7a8qVYAqpzv82VKiqi7v7PY3SjPWwnm3PhgnqAVSECwlPcKDrElksmtiop8X
         Ujyx6yOAWtGoNs5xjVYTcgKgZtzp+R8R2jQI73EsEuWXXAdAtQYOpmOk8jdB1YQ8mpW8
         BEVzT+PMoIqapEbN1k1mIWdmlg5PxuDxUgp+9TSVo23yGb3HyEhfemO9wJ0fOkzUbw1a
         +CWsLNPIVGbWfdyq3wJ930/oiXqi3lqToBbnujdf1dArAJ47Ddu8C0BFVUNWIJ7UCHFr
         0Y4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+2DzaTFaQhCi8x+b8lScKZdT6wqGghcdZfo+S0TqwgI=;
        fh=Mtq6NDgsfoWWTwV3wORhq5Dc9NFXfCBCeBwxAEZG3wQ=;
        b=D0wVd9TeFXVyP926iDZFxibqrj6wOdEaLjm5VIuyA5NWAJ45kr+WrzcT8c8zWZUM1i
         y+0c+oFc8o/OQ4A3LgvkWvYe3PGyM70drSon4pw7imXq7IHhXCd8B53TcOA20eflCAw6
         atynQ6iNqLgCWS4OYhXtUhKskMT8sJQXfWyipFPc2DOEvgnHREoNBiqkjzpUvnIRnSRD
         FUSFTS2coqFDxvbWExeXl2rBKybOKdGyb9Ltf6Rc3Yff/Hzh0yidL46kRXSq2Z6qKJFG
         jbNjK86CZHpmfDbTiNLPR2Wai96m4vONmwqFj2tUriYY+X7EZOPDXNfKeeVlBQ0yFGQX
         FE6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=k6bATkf2;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e01cc9si36649985a.4.2024.08.14.01.14.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1fc692abba4so54360405ad.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJgCCEg9/uFfocqTU5/pAEIlMUmVlY/jqkcVGPN6+XyKPRcxDQ7W1SqFYXkkF66WfWa0Cat9ispiH1BIkFztQUX7GN7MXZEdQR8w==
X-Received: by 2002:a17:903:244e:b0:1fd:93d2:fb67 with SMTP id d9443c01a7336-201d6520249mr20828995ad.52.1723623289265;
        Wed, 14 Aug 2024 01:14:49 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
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
Subject: [PATCH v3 06/10] riscv: Allow ptrace control of the tagged address ABI
Date: Wed, 14 Aug 2024 01:13:33 -0700
Message-ID: <20240814081437.956855-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=k6bATkf2;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
index b54b313bcf07..9a32532d7264 100644
--- a/include/uapi/linux/elf.h
+++ b/include/uapi/linux/elf.h
@@ -448,6 +448,7 @@ typedef struct elf64_shdr {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-7-samuel.holland%40sifive.com.
