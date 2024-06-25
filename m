Return-Path: <kasan-dev+bncBCMIFTP47IJBBG7E5SZQMGQEGWCYSNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C8939172F8
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:49 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3762171acdfsf94241985ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349788; cv=pass;
        d=google.com; s=arc-20160816;
        b=A/bErjboGghwcT7lp0sr0lrJsbWid1Rg8o0dARCB5pFL/KTogwxCghquxYFTaENgrK
         9qOmD1FCyV2FJKsHwJlDn7B433m4Ke+XVzOQsLi2PUc2R/upITOx2zTMWU9MMKJ1bsmT
         rDSJ2mNtIZP+x2qzhADAgdjfTD2Ru+pv226AkirCVehWN22z5hoGaJ2SU+axKFxQTLd5
         RAmeRlZYJWVCWPK7fW0cL6RdSGwThmT0DLWYubMfYJ1wa9mhKo50FX8c+8M82gPhmfYC
         fjJjIfO6tzRA5No0od2XJ6+sX8Tr6loffG3el86hbdeNHZ47BzC3U127NdLQH6hgCdno
         +u9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XV1u+KRrJAwmPFV18U7NN5rX0dwvSXXvNfHuJw6AaGM=;
        fh=k8N3vtA+AZNNcHr4ByFRCch8jZwvm6j0NHVKFuIVXE0=;
        b=Fc/9Wra8XqxhMRzV8awKUB/+11Qybg2/6w7hnDRaLl3yzoPeBvAw/3Iwn2L+nSFQRL
         EnAQZp+NOrVEHnXAtsKpK6NDDtvvGZKLKpoXZf4goGKfq41TGUHK8JdPrJ4nJR7mQwAL
         sWjAv3Pd2oubLZkx1omAaFkRZLOlkh7ethBWyDeDlPRB9h8o19YR1CNyzvXs0X+Rqrd+
         /kSuoGQGjLTVuLst0iwWB1FPOep9K480mkotdmQ8J24L2mNRNCcpB6ARQ4d4Aqa2Z2NZ
         YAsvxyC0oOVzWdjc3mm2kIVV3MB+YtS6RvuL5ef0oq4y+uSgl89dNHhj/EjOZyHCfgF1
         Fx/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=HXYg9gZ6;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349788; x=1719954588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XV1u+KRrJAwmPFV18U7NN5rX0dwvSXXvNfHuJw6AaGM=;
        b=Vlxzy3PvAQiUfCPt7/Zanv3x9h8UnjmP7tR1r4FeJynHLdp+b2gn2NxMJS5YHTdUcf
         dZbYX9muhA5ZPthtMhXI067+OivLgtLKyQ+UkENiR5bLV8ggOZH5h7jERiiy7r3cTCVz
         mQHCeOPGB+MpPG3bdo8q+QHilukMZUdtBJi3ZLNny1U62HnDl0fARcrMzaf5+QwKkbti
         LZnX+igF3WBcXiJKkt60TAhXB3+yzYf/OARHCpdkyE6KnbeAZfYbaxDHRzdHfmkbMm4C
         PQ7wTtZr71nnceGSB/RTp1N61umfsjmowRvg+Dx8K13CtKyUyMor7OVOQapLbUahY3K0
         4L8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349788; x=1719954588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XV1u+KRrJAwmPFV18U7NN5rX0dwvSXXvNfHuJw6AaGM=;
        b=dr5hR3DcbIfUZwHShsJ1qWrmU3SzzaDfmKY9gSwhB5u5yx8DAk9JaUzHXgSnDg9Q+G
         JkHGTQK2DpCPuyIvhiGcFPl3rnNCIYKUwaFLZwyyDVh3RewFZI7FcRJQc4zYqu7mMbEC
         lXg4PwaRI8VJFlhKj/elWSS8nTZn8MTeCSvvZXN9qbxF++EBGKPrIia5atYp/P1yHLw9
         KdCOMXWWITTtRQ/mrpclQLRV3A9m6/hZl/n9a58yeNgj4DAl20fHbZc0KxkGpm/lUM5R
         bBi5Y4mUH0qXp1y7Yhjgy1lP/MmA6AiwRhwIZjLcVkLcvXdz/sawVQ1LVqCI7y+asn5U
         seuQ==
X-Forwarded-Encrypted: i=2; AJvYcCVfjFocrFjWIIZiND+nWf2fagRyQ5PsNcoZQsyYkjtxf8FAYHB5WGcXqOV7eCgV57veLAa8iWEwGBgnnQb+ggbz5NHr4RyCiA==
X-Gm-Message-State: AOJu0Yz5zn7Iajgj9IHlWNKbfAzIKkIFRvWwh2U27xQpO4CH2rwnDIXd
	x2amA6DmL5wfIwOJCIHfljvKrKIVb2hKdYdjnxbiyItDu6kgvSyC
X-Google-Smtp-Source: AGHT+IExwrjNrJIJ9FXw5/Jge/WIikE1PqDnRegGVmGKu+m1p+HxT285BO33ZeMU1aotXsZZ1hlBkw==
X-Received: by 2002:a05:6e02:194a:b0:376:2202:a82f with SMTP id e9e14a558f8ab-3763f6de1f2mr113301735ab.28.1719349787863;
        Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2199:b0:376:24de:8a87 with SMTP id
 e9e14a558f8ab-376269257abls49471865ab.0.-pod-prod-09-us; Tue, 25 Jun 2024
 14:09:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjJyKX8vJdFhd/efXhh3BHyoQQzcGEK2tjmAIV/dxtUdKB49fLLJ2EKoXC/cSEkUbVhbIuB+UdlRutaSNrSuBVYydSbtcr8xSjRQ==
X-Received: by 2002:a05:6602:160a:b0:7eb:7e0c:d186 with SMTP id ca18e2360f4ac-7f3a7535decmr1059864939f.16.1719349787111;
        Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349787; cv=none;
        d=google.com; s=arc-20160816;
        b=br5drVmdmP8s9wr6ys4DJOqUkFF8RTo9z2UMRwyDRo/JcFlEVxoHTQ4gFt184K7D8h
         9NeBY05+CF2774/NUBc331z5SgaTLMg8hcFh4blMCdYqSw5ufjf4bbaEYP3LRlj1Fr3T
         ZeMR+dIrmcBl1TiSZpoDJ0UYi92g97uwflYD2vmXa6FdIFkjs+dtp+0gH61cpxSTUrA7
         RZPFu3IH0icOpA5kkP/mr6ftN3eE1KyeFMdP3QFHI7DVShD5SSBOfhqto/wJkvkj2ITE
         8GejisH65Cv2hTsQUU3C3umGhoGtuVrTzkUF5GZldnB+MHfiy8ULFL7rxVvfJqv453EE
         HgSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TcVNJ1c0k9nGflpMj97RQ79v8JL+NQUn2VhiWagHpuA=;
        fh=ZfALoxqMpLRYDoi+S/6PV1VS6KAlZdhm/yOVQYNYfrc=;
        b=iKvnYy8800sfzMKgnclih4qMj2mTEGKPxQihM3XHRiQyK66wJFXdLc7nsxK3T8v107
         oE4W6zi6kSGTB2OIhhi/IiLfqiaTgzSDtZFbI1kV9GifYRWPpYxfKJeW+MjGcNQ/8aZ0
         6CCoX6nKv7aPEwwIQfu9OaCZ/fNYg0cYszb2+3T/q+eZYpQeykoScbdt27IFLrUkHdP3
         x66ErC2y5sL//WQyxEGC4lBL8ECzb1IyNF59yaCrRpgiOerSfFKOQhch2CVBg41cofHf
         t6KHvcmF9yDOwtmrqVabsYeIHCCmX7v6xVDa2Zn9NpcTKiyZWU2JpjyGNbJc6ReaNVmL
         TLPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=HXYg9gZ6;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f39202e398si75224139f.2.2024.06.25.14.09.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1fa0f143b85so26524765ad.3
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIjVbbUINRA7huSsIftpgMjfG3jznqSapaG6n/b5nSeYayl9AcBYWOHiYH3ochD7ZyIDvppSDgkA8Nz2xLcU4iCD+v80Ep483rSg==
X-Received: by 2002:a17:903:2291:b0:1f8:5a64:b466 with SMTP id d9443c01a7336-1fa23eceaedmr107096065ad.21.1719349786391;
        Tue, 25 Jun 2024 14:09:46 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:46 -0700 (PDT)
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
Subject: [PATCH v2 06/10] riscv: Allow ptrace control of the tagged address ABI
Date: Tue, 25 Jun 2024 14:09:17 -0700
Message-ID: <20240625210933.1620802-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=HXYg9gZ6;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

(no changes since v1)

 arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
 include/uapi/linux/elf.h   |  1 +
 2 files changed, 43 insertions(+)

diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
index 92731ff8c79a..f8ceecc562fe 100644
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-7-samuel.holland%40sifive.com.
