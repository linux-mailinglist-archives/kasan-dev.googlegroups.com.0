Return-Path: <kasan-dev+bncBCMIFTP47IJBBDMRX63AMGQEUWNCHKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CD47963732
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:06 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-27795dffb33sf149426fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893325; cv=pass;
        d=google.com; s=arc-20240605;
        b=ivlPC2cf1QJab6PpcvvxdlpchnFlENLbD+ijuULT0aLJOmlpup5k7AsgXQ8zOhsQWr
         vTQq27yRu3a9cOMfmlzsH5mdRPPPG6jaV/o2Bq0b+/TiXALgAO5LE4/9zqVuzfbgJ+BH
         VsXb+dfv5gbkndUTvcT+P+LGRwhSkhI06ps7ZPNn/rYA2j+LfIDZ+OxRZ+lg3AbSgCjq
         meT//hJMVSQZvJpUbAuBLfGku+TCSc/i/aYizv43MT2ao5KeeAICEyaR7HspSbTyFE2R
         GyDU+TW0YA0CXksVAgTbQqZ1EeZDbRsP70FOfPhhE5i7IC9Iy44oVM85EpIgyEQ/Azo6
         M1hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=f5sWITHSS41uOHUp/fn91GzOvsvqOMBbSsJAlVhm1qY=;
        fh=hS7cujRd4q1BaEL4sJrVcYJ2FcCx0Vm5e+0b0sa9Pmg=;
        b=KNxUT62/RU2pclUThtdePwd7KRVeiHZarDFXT8pDpPG8PfPX3JQ37GGUr7l1Acj20+
         k+amLxOgK8RmtoKGX8kYgmTYwScQquQTtkt6A3gjFuqOPQ4qvT1EFj8Rv4iWrJY42Qvn
         3fk+G1GKs6hu0XovMst1y2OZeqXylRBJ0jpGGgDvagnU7ID0zo+P7smhKZjHZKQFEvkr
         7RzX+OzohggfmW26jMHbca6CSwrnF5j2GJSV0GLWBSr+BIkzzVptmWAODs1QeVaJX34a
         /Dsedjz4zuHO4511zpUV/d8PahgB9UTQ3E1xjdjt07nngeVRdlqu0wMFeFUyEp+Kn8K1
         SNFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=JPEmM1sF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893325; x=1725498125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=f5sWITHSS41uOHUp/fn91GzOvsvqOMBbSsJAlVhm1qY=;
        b=McC74tIm6R8/4HJszzp5aYmyAZ6hpk9QnBKkQlyErbauVbAI8EP9sd7dvU5gjuSngt
         sr2DvNgBX6QwfRs/DQRf3wqAzRh9KhPpxopPTg2XsWhnwVD3UlWpJp4WiVj1GwPAdQlz
         5UJ1auAeDmejXz8qBwoKYhUbvSdkRWSh08DkxPBS9ZwtzTYx1p0sTUm89a6/uhZm0MbZ
         OY3bw5h5oEr/S/gie9EnG32Po3L3Pla3J0lvSMHMnFhdjEg3BenYE2bYZxFQOQ2Fn0b+
         Ie/26syJJJ+BkneJ0PQJyIpkeD9lQYJjsRUv5VP7kqXVAJuIaRzYj1Fv8PONV5P7YTdO
         LHdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893325; x=1725498125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f5sWITHSS41uOHUp/fn91GzOvsvqOMBbSsJAlVhm1qY=;
        b=uAm7pNN2XMNC2juHgBiCDZYbBqM/0ouTrkv31lR8aiQUn764PlCNXkqtaz5bPtizDW
         VgXubZE/zRJZkuhhrx78qYeIXZnUxfxE9iDZM/KEuRqnUTRKK61ye8yknN7C3zLjJo1z
         xfBIo71JFrIWgewU0VFQSSbOzRyuWs/AyMfpjZSnUFcf1F9KrB+17OQQ2haQ50LVzuvJ
         peenPv1aQVr6iYfR+crJynfKa1ZCt6y1mQRW5aZSCFlx0dr6dzGjx4rpjlwOoZP3iYHX
         LAdHqwOKpCDrFDjjX4Ct9ph7ef9XgKbHAh6FtYAhNgmERfbHfArGPlSV9DpjI5caT+zk
         nx1w==
X-Forwarded-Encrypted: i=2; AJvYcCVwbv2N+lFPZKFrtnzSfewBc7NuC3VtDEClz2px4JApiRmMau2svtMxB37++zIcMZYSVvcQBg==@lfdr.de
X-Gm-Message-State: AOJu0YyESPgCHvLXo77OfWnx3WBl9MDX7jK4ZGbNandkn8XqF/TTi0jJ
	7mSZttPys7AtOT/qBtOiCHUim5Pp0KUd/5SQqPDUBBBhGdAjCKp5
X-Google-Smtp-Source: AGHT+IGa4QbSL3WeMN6cVd1f78QlOqeDVwETOxJISbzporPJjRRrFKc8uBRX+77j4nfIArYzw7dCJQ==
X-Received: by 2002:a05:687c:2c4d:b0:260:f01e:a3f5 with SMTP id 586e51a60fabf-2779013e14fmr1365515fac.23.1724893325435;
        Wed, 28 Aug 2024 18:02:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a583:b0:25e:1ff1:3bb7 with SMTP id
 586e51a60fabf-2778f0a207els693995fac.0.-pod-prod-02-us; Wed, 28 Aug 2024
 18:02:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8r17onyI2N+Ki1ScIXiAhKa/xvYtLZ4+kNwXq4AVD/9GQNOyMx5eNaq1NinYGKchK+UPeUN6/jfE=@googlegroups.com
X-Received: by 2002:a05:6870:164b:b0:25e:24b:e65b with SMTP id 586e51a60fabf-2779031e583mr1573646fac.42.1724893324670;
        Wed, 28 Aug 2024 18:02:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893324; cv=none;
        d=google.com; s=arc-20160816;
        b=ZYDxf37T1hXqi9OSvfnXlgo87HdKK/+9QQZaotyc4hNB31t+gHCRXgULIpMKryGBvZ
         iJJNcxPe3nhFahryA7kyMV25enEE595eS/mN9IhYNs9t5g2hDYNTYJv9BUzSr7VIOppp
         vFbl7XXAfXqTtxRj9vEIKCJtRcBJgl0cFFEMizyKj4HFCZiUtrgkh5nZ7uM1Hbe90q6S
         0jGmYT45C0S7q8c76hZVj91ubAaHI/BX4hu5qw/z+hcPRb69YNfpXogfUUCl5i0QskLa
         WV8MeClgNUYu8ITUCwHAIipL+mqMODKsemYYMGla5VezQa9NlF1BEG2iL2BYz3T7twyN
         JVQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+2DzaTFaQhCi8x+b8lScKZdT6wqGghcdZfo+S0TqwgI=;
        fh=UkkLWsvMq0K2z8w/VJBd9ZiBaEd3moGW5s4G5Gt5tuE=;
        b=baaiJKEvU2KzlP34FDJx51E+nJi3OhIaYzwo4oA0I2iI1i8Nj1MqhygoOTdQRX0jnL
         IJ2NdfPXLTfaIoo8GMHX35HBMXoPJS5pvugR/2jPb5XibcxaIjLiR0ADuasFpqeTtryJ
         AVTsprba1j97El0ionb9UqOEibhlJUQL0UkZPZOdpkd8NrrGOKlgLOwPP1Hb5m+/sOw3
         F+O1vJIBCy6I/2GhZomJKRoQ0xttfTeYCnhoQ3ug+U2cpKbBKzsYcu0p7GqWYr/JG60l
         ht5kuKNnkuiJJGjyGTe+KRrS84ABedTzd4Z1m7XA1pOTzhsaqdezutxFDJeu6+onaCod
         NZhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=JPEmM1sF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-715e55b0c74si7390b3a.2.2024.08.28.18.02.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-71430e7eaf8so114346b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXB74foAwd6RJNEbCOLeKUY1J942fZX8QS+es1wmafuvKHD+3YrR++4J17Q5l0Xhws09goZhblHRjA=@googlegroups.com
X-Received: by 2002:a05:6a20:9c89:b0:1c3:a63a:cef2 with SMTP id adf61e73a8af0-1cce10161e3mr1027463637.28.1724893323584;
        Wed, 28 Aug 2024 18:02:03 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:03 -0700 (PDT)
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
Subject: [PATCH v4 06/10] riscv: Allow ptrace control of the tagged address ABI
Date: Wed, 28 Aug 2024 18:01:28 -0700
Message-ID: <20240829010151.2813377-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=JPEmM1sF;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-7-samuel.holland%40sifive.com.
