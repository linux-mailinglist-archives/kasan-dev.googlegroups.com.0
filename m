Return-Path: <kasan-dev+bncBCMIFTP47IJBBQEV5CXQMGQE2DF477A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FEAB880704
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:30 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-29ff65bbd63sf280153a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885569; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqN6xjR5wZqUPKcwKSYBc7VcSgLZy3qbSmN5ZWPSeTeJr8xJ3w68dq0ZrCMzF90HiQ
         z3q7AlvW8KTurXpqoDQ0nBINOIFb08GI7UyTV3ZM4dl2LGqdtkPzZGYdqhecHomkMLNl
         tai9Ex3Gmp1O8nu5LzsHcS04Mdz65QBV0Vq+NSbsq1bMZzFjT9XrgfI70E2Tt1IhucaF
         fhCTC43C5OhufjOLmL4+ySWMeTOZ88V+Wy76Mo7NrsufPEL25B+hSeXbxMylU1Vcuv1Q
         xjqXs4Tci8pMdGWegZbOVGx7UkrpN+QIz5joDbGo6TO234ozFwSa2xU7RmWuvVu1+5C/
         KNdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=79iC6Mt9DzCF4FBUxT7AHO7XNqYpSTAzKtDL+djwkuE=;
        fh=902vFGxFiG2pdAsJv+EzU/io2N2ZzYJRzw/Buiqy2T0=;
        b=Z0TXZeqCw5Q1CmwqHiYydD4zqXKMW28QrytJjKqSK3SphmBJ5T5LoxV+ZqIV1LbKeD
         +MFsYJl545T8ptq2Uq1kL92fdJSqgjIxpI8hWAgUsVqgYnlkI6ma++KccFDHxMHUXSnr
         +VoWc9s/2YG9BPisgmb7Mz6GJMZf/A4qbYkKiiy+NrQLWOGYz1qEzLzMtwATRLKn0e4B
         DDLlCwtDDsRgIebvkGQm3a+vs+te8bffcdqFd1XnFKyQ0A1Q6NyfUiZgfEJcqysZgjG/
         8s10+Ub0CC0hyX3ZVwnKQUlWOIQpZ4I16huR+3UUw+U8yDYvF0Eon92vWU8LplUkDtHK
         u8HA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=S06YnVWB;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885569; x=1711490369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=79iC6Mt9DzCF4FBUxT7AHO7XNqYpSTAzKtDL+djwkuE=;
        b=KjqQ5BnDdn8DsWObyKhXJhCh7YAz4VqajyJMWOq4oRzw6QuMt3cGme0xSohjTyTeMO
         Blv015E0+MWcwQGh2eSgNNFtn996ym6rcWvRHYKWcqUkJR1LcXyeYEM3OjGXNA/2nLbs
         Tl7dlRlWL5eh3V0DhgiEVwN0iXhahLxhpQPG8+Eb4IZPa2rnoSkUtDOg9A3YwgBdJQ10
         LYtBgISnHPPt+8Su3ENf3vSvi4jcXAGb+U3BE/G0CqDch6gQQaKbCNO40N5ZDY0mx7Yd
         HOMKzqLniP+GFliH5S+PC6kOjXlGcnI6qhJ9PtfSQUbJEcF+Vx4W5vMnMXYWDbzNZNrS
         oqhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885569; x=1711490369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=79iC6Mt9DzCF4FBUxT7AHO7XNqYpSTAzKtDL+djwkuE=;
        b=xPAsaT3qrGmv6qmW9d/ByXajeTUaXkTa2MVQxrOh9Jae3vxeb48ySrC6fvlkxkr5WF
         xoQdMDOqL5ALDq979FOxc5f3LRBO28dCx2ECcWDT4eephwdT1ZI2M3Ne1ZAyudlPUQS3
         f+UxmUQx002vpA+ml9TIdzq1SfhmF6NAMBt4ghqMa0AoRelpfOL6R8AWutsCUF4nAOm7
         4ysZyu2Rf0xB9zf28Z51zT5nVVdH/Yz3FG0EEKyJ/f2xXvSn4TxjdRrxYQYSS6FTDulC
         G+Q45tqhyehbo/YExqVDcC2b6qgPeaE1DaEe44UUdPTjGNUShu/+u21d9J53GUT/rJG4
         BW7Q==
X-Forwarded-Encrypted: i=2; AJvYcCW9OeidggwxnkbbbzJxRvmcF6lD05418CTvFhts7CvjRYcIpj2GHXD9q1F5ZhUNpDpqCMUztc5zwAoRlmkEP35rPwAESsqz3g==
X-Gm-Message-State: AOJu0YzgMTPzd7cpDdhyeqOsv4tUi3BYJAOSIiPqdRl7r/qvhr2WYCQw
	FRewWXfHpg28bcNU2DjfQrsWJLxVmxKlcIXy2ssrSN3+c1Osl6rE
X-Google-Smtp-Source: AGHT+IEfaHM2iLJjWg7UqTHZcpFvwupCkpYc/XiKY1ss0fhbrhjA73CSB+j9WDSGd3V/I4/Dpy1YpA==
X-Received: by 2002:a17:90a:ea8e:b0:29e:c3d:c3fc with SMTP id h14-20020a17090aea8e00b0029e0c3dc3fcmr9495866pjz.18.1710885568890;
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e887:b0:1dd:96df:9ee with SMTP id
 w7-20020a170902e88700b001dd96df09eels4639636plg.0.-pod-prod-05-us; Tue, 19
 Mar 2024 14:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWsAMCtaYNAxWW85tig1QvMpQfL2dWqdey8Oaizj2d9vzqJFBUuaf5600GfWiB+D3wofh1s0vZedUCbjVtXrNyR+8aaecPZnvjyw==
X-Received: by 2002:a17:902:b784:b0:1dd:9250:2d26 with SMTP id e4-20020a170902b78400b001dd92502d26mr14694100pls.47.1710885567394;
        Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885567; cv=none;
        d=google.com; s=arc-20160816;
        b=0YM0ktz0nUGBib3rK1StkDAvxC0pasRtz3AZefoFj/R6//Gqd8HTT27I61NbbZk69Q
         JlzHwpZTGp6+UjDI6kqaJfxNOvKox0YM1DbCUodNYghkBzXFMxDccCoe+TVQkDBwenQ7
         fDPbI0fvjLzJF84lwKVGRZVZ/RrPLIMvMCEpgiYUqrH0VSFRSOk2wSWZ07iZKjWhwCzU
         aABmaTEbt8oNoJbz51DoLHUsaP+GxzEemtHbI1ohbHZ3FQQd+zFUkT6lNcFvWW481JXz
         JZF1BXuNR7+Fc7Gq2wMNSbvbHUScgVodCikNtXN+B4f+krUPYxQ4hWSk0p8MuhiETv2I
         MpTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5y8ITBc9KMnXCgtx77FHcE1LkP6cPCkee9IZD/0lAIU=;
        fh=nK9qh1IAlTmwjyDR7mOQiMpj+ropOSJcRh/Z7e9/ixE=;
        b=WsiTPvCokH9oAQp/EwguyMT8yXbjV1Gb0BH/grnP28IsseHEZcg3PeH4IYFHQeyvdB
         Uy0SwB02duhRuxz0eJC9Yej+1u7OohxWrYBhg7ZQ4nXWiG0eqohAbQvoVBs/RvnEs/IE
         t4kSjvx9j7ovkMozQgxv038spmfuoIc3AI6ce48CKYvBjOI/OVy6d5V+TQ/sX77szS4u
         lG+9di5HnavFh61v3YQtf3B8Fz3Nr2HC8ehHY5fViRfMfl4SbjwENWsgo7Uy9Lqwe05S
         8lTV6mlCgIwnBiUz6iSYWzEvkXpACihSoICv2pV32bYQknokEQVOX3JePDGtJThgSNMr
         x5KA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=S06YnVWB;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id q13-20020a170902dacd00b001dd61b4ef8esi721065plx.12.2024.03.19.14.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6e740fff1d8so1199360b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUdZ8eP9lPhX5IGvCu9JHWkP2WZ/w3cu27XFjyyEmADX90RGDkejkp/YK7Nf6gBS6gyGBroyJ3Ld2Ju2sPPaRSBEJvXZqzO6OF0bA==
X-Received: by 2002:a05:6a20:3942:b0:1a3:2f9e:b0da with SMTP id r2-20020a056a20394200b001a32f9eb0damr14091704pzg.23.1710885567124;
        Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:26 -0700 (PDT)
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
	Alejandro Colomar <alx@kernel.org>,
	Oleg Nesterov <oleg@redhat.com>,
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: [RFC PATCH 8/9] riscv: Allow ptrace control of the tagged address ABI
Date: Tue, 19 Mar 2024 14:58:34 -0700
Message-ID: <20240319215915.832127-9-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=S06YnVWB;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

This allows a tracer to control the ABI of the tracee, as on arm64.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
 include/uapi/linux/elf.h   |  1 +
 2 files changed, 43 insertions(+)

diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
index e8515aa9d80b..3d414db2118b 100644
--- a/arch/riscv/kernel/ptrace.c
+++ b/arch/riscv/kernel/ptrace.c
@@ -28,6 +28,9 @@ enum riscv_regset {
 #ifdef CONFIG_RISCV_ISA_V
 	REGSET_V,
 #endif
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	REGSET_TAGGED_ADDR_CTRL,
+#endif
 };
 
 static int riscv_gpr_get(struct task_struct *target,
@@ -152,6 +155,35 @@ static int riscv_vr_set(struct task_struct *target,
 }
 #endif
 
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
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
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
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
index 9417309b7230..90806024fed6 100644
--- a/include/uapi/linux/elf.h
+++ b/include/uapi/linux/elf.h
@@ -447,6 +447,7 @@ typedef struct elf64_shdr {
 #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
 #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
 #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
+#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
 #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
 #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
 #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-9-samuel.holland%40sifive.com.
