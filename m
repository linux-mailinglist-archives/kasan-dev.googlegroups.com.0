Return-Path: <kasan-dev+bncBCMIFTP47IJBBPEV5CXQMGQES7RKJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BCF8880700
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:26 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-29de02b98casf5080747a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885565; cv=pass;
        d=google.com; s=arc-20160816;
        b=ghT6BFEmmJsHqp414n7YlxMYO+DbFOhbJhUbB8Pg++d1Dml8Sfd8MT6sxYTfD5/+fD
         7wc+KZ3Ixeam4/o3wZyYE37sQUKgXg/3fEqFPU+H7JLSBcLS50WNk4bCG3u+4pCjSBT2
         ptI4HFJT7TXdEkug4Z7ENGgKJq5gTrKjLVVOYF/D6ZIAvYPk6dfUQBQv2h9g9ufj0BHH
         Y2lHs5GSwCpl4IerqnWtakSsj+koZinrQOL538TWS04Ehd2R6rwmgikjzGRJa8t850CD
         xtGF+rAt4slBT6Yzz3ad/fftO15F1LHFmBP93bdmZ+jR8VjwDJ5DG5vibw432ND6bczy
         ktdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+yTkvt4IgH5fZIiNwPIH7KyXs86dfpNw6YV6H6CFAGY=;
        fh=GXbupbMIHwgCn/g4RjmbzYwGVffCzpxINlgvggXxVbM=;
        b=hofsTwuc06JYXdsxthBI5lBXZDK119Msh81PIg/95RxoZvu3QRjIO/SzQlO/5pJeKE
         O2REMUZjhXMEAzQFswApMFYXviqY+2wsIamk1H4KUOK0t31CS2BLSlHn5xq7QazDuE1l
         rP6S12MGFwgkp56VTgA+4gLqZFyULqavS910bUaemXdHhleboIvccwayy+1smrfDJXZm
         An2XWUY89Gy75omdarB2DjgH9I9RexFquDc3XBJFkRXHFnU5e/ttmh2S5yoBpPa2fWei
         X7/kaGp1M2eyJw3Ke2bqwInd3uX9StvIO+l0IYXvdy1nMHiFptQ8jChMojg21ZgPlhjL
         85fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Nf7xpfrw;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885565; x=1711490365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+yTkvt4IgH5fZIiNwPIH7KyXs86dfpNw6YV6H6CFAGY=;
        b=rl/7sFKK7iCexjbDBnzIO8sfU6QT2FMJWUILRonR5qQ5OwxGNyudX9ON8cBm+InjJE
         e5R3UpmndfMpUAp15jtUTsYIKHABXMlqtfHRrNoN4XKunzrXUTfsh1lqBrd1PZ4cNoBh
         MX3PgJbVsWEeItCr/Blj8bGEFtY6/qXbPAUjJx+61QwUcvMT6JDqGPeHFlT2cOJTNGNJ
         3FxmWmeCsOOdZopwZKr3w+Jg++d13NWc7q7EGOPKcZOlNx/k00lAkF7aGd1yCdB40hpt
         b8HVs4/Us+e4y0q+w+blM/8p3XJwcMVjE/7nOl+Ml5PWbJQQxQ6LdPXn3F/DGaYTiPD4
         HKag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885565; x=1711490365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+yTkvt4IgH5fZIiNwPIH7KyXs86dfpNw6YV6H6CFAGY=;
        b=wHX9qHZs+/IoZctzzlnz22zC2CzoKUUmJL+TKwcsd/fZMwu59Ku/sw8r0C4GNcjaG0
         n/YdHp8ujBC91kexFtG9CcnAt3PEiKjMibrgLymdOh4m8K69e9/sEgfnXUSfTojvig8Q
         gB/viQmcIlNP5UKcsI0ToSnAQKqhGGb8DwpieR2tH0t6N/OFdBsRdT4wWHp3O0m4vsmf
         Uayhw9g26zPLSrsebhw/+nS0kSEEXMegVgbIqXeFa48V45VgwD5jo/jg57VoTjBj/0rP
         Iw7f5EX0KcncS7OK1dr1YcUq0MMi/WTBSDydnl1SOgi8vnkPFrYlnCZVgrN6zEdU0xhd
         elOg==
X-Forwarded-Encrypted: i=2; AJvYcCVBqDXvFht29CK0mbu7eJrQqfyeXhUe++LLeWBqufZjQCLzDnmvSiT+JAYDETJCRk/VT8pPuPFBuYVgqbwearfGSZMIVtDgPw==
X-Gm-Message-State: AOJu0YyaODGsLSOrFnSroS+b2GqwfY53m/K7uGfNECoMO5cH9CBis0R9
	gRj6m9W7fYN3zMVPSMtbIR0Ypk/krB8bDyTgmbLSuX0htDUODm8E
X-Google-Smtp-Source: AGHT+IFQKraaq166/ZY0F+VxN1CT30nSnVoEPEC3SCvJXxUW18/5GOsnKLOtvy5BrTseJs/DHUBTGg==
X-Received: by 2002:a17:90a:c7cb:b0:29f:6753:ca66 with SMTP id gf11-20020a17090ac7cb00b0029f6753ca66mr3623792pjb.41.1710885564666;
        Tue, 19 Mar 2024 14:59:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b47:b0:29f:e622:2770 with SMTP id
 ot7-20020a17090b3b4700b0029fe6222770ls403339pjb.0.-pod-prod-08-us; Tue, 19
 Mar 2024 14:59:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXoRL4Tc2dK1Oek+Q/lbD+jkhaxvPJzqdyCo9WaZw0gbdrhrxny98QeTH6j2tze++Ed0EOtJ43YAeAcaLUDcLd7duKSHuLfO3wlA==
X-Received: by 2002:a17:90b:84:b0:29c:7646:113 with SMTP id bb4-20020a17090b008400b0029c76460113mr3575579pjb.22.1710885563541;
        Tue, 19 Mar 2024 14:59:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885563; cv=none;
        d=google.com; s=arc-20160816;
        b=JZBfocPfGfAQt3W7szNtKyIvgOwG1lsQRGnmaQyxIRUAFIfLcUPxvF593+DGvTSeCT
         lhNOrQppUEwPlFpQTQ6a1LjmkoIHLGtkcPc+1XplSSPOBItIy/GUTcUjkeym9q/kJow3
         750CcoKT7q3umLI9GYFFtSCgq9+H+7sUXDnINQv4Ntt6B2tKWrxO6tuku/YLsGYIo2JP
         TQoDjbE/HYlwOn7W99bt7KFBCyEhOkE8YMNNEsGeWmeNYdGVviMMVwPYCZkIdWhp1Uks
         fMSamh2YRVwR6+ranFQ/sNBF/Do70UwmzaIWpiYFdFje2T8MSShvby3ugCG5JTb0cbA+
         F+5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dz0gWVnpXPU7ElrUaImwHtbiCroEAM5Xe/I2DTavV7g=;
        fh=v4ghdL0jxXubhycoqiNFfuAAKaTSkTOCoygbvFUasIk=;
        b=k4uFqVfBoL4KKM4hzGZD4ylomB76fJCeCkp/B11ZUe0ru6JkWCHRE1yT8JTzQziaaa
         IPdhjMeBuHYHeEw8vg2DZGF5E/4S2lBx+q23BVBwtNCWjRj5ZIBGAec51Fp8N1VuW+pa
         UYawhU0VyOvnGZOXmLXGi+Y/hKVAbolWCRR5xquA4E2Ovj70zeDPvZ47jAlCzukJpUZO
         33eSmAEtmn7kY50AcdGfW2ZaxHztJjCJLX1Hd0deBa3v50quUWIUe6V8ftWBYkYxN05q
         RwljpzaVQEiAKmGs4jFolqIBOSNRZ/5cOhxYNBy5NGm9eErRJOpqyxX12EJnQprjLfon
         DTcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Nf7xpfrw;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id b6-20020a17090a9bc600b0029be51c3687si138502pjw.0.2024.03.19.14.59.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6e6b729669bso5497914b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4DguGa+Ll+95bSewwAoZ98WWp6mNBzRKTKelYzuvXw7od2z8O1f5XWjq0oLTnqMKX/6YYI0ezZ/0607vaTYzUATlyKbyjZU4XWA==
X-Received: by 2002:a05:6a00:1482:b0:6e7:2379:dd18 with SMTP id v2-20020a056a00148200b006e72379dd18mr4524923pfu.0.1710885563216;
        Tue, 19 Mar 2024 14:59:23 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
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
	Andrew Jones <ajones@ventanamicro.com>,
	Guo Ren <guoren@kernel.org>,
	Heiko Stuebner <heiko@sntech.de>,
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: [RFC PATCH 5/9] riscv: Split per-CPU and per-thread envcfg bits
Date: Tue, 19 Mar 2024 14:58:31 -0700
Message-ID: <20240319215915.832127-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Nf7xpfrw;       spf=pass
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

Some envcfg bits need to be controlled on a per-thread basis, such as
the pointer masking mode. However, the envcfg CSR value cannot simply be
stored in struct thread_struct, because some hardware may implement a
different subset of envcfg CSR bits is across CPUs. As a result, we need
to combine the per-CPU and per-thread bits whenever we switch threads.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/cpufeature.h |  2 ++
 arch/riscv/include/asm/processor.h  |  1 +
 arch/riscv/include/asm/switch_to.h  | 12 ++++++++++++
 arch/riscv/kernel/cpufeature.c      |  4 +++-
 4 files changed, 18 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
index 0bd11862b760..b1ad8d0b4599 100644
--- a/arch/riscv/include/asm/cpufeature.h
+++ b/arch/riscv/include/asm/cpufeature.h
@@ -33,6 +33,8 @@ DECLARE_PER_CPU(long, misaligned_access_speed);
 /* Per-cpu ISA extensions. */
 extern struct riscv_isainfo hart_isa[NR_CPUS];
 
+DECLARE_PER_CPU(unsigned long, riscv_cpu_envcfg);
+
 void riscv_user_isa_enable(void);
 
 #ifdef CONFIG_RISCV_MISALIGNED
diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
index a8509cc31ab2..06b87402a4d8 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -118,6 +118,7 @@ struct thread_struct {
 	unsigned long s[12];	/* s[0]: frame pointer */
 	struct __riscv_d_ext_state fstate;
 	unsigned long bad_cause;
+	unsigned long envcfg;
 	u32 riscv_v_flags;
 	u32 vstate_ctrl;
 	struct __riscv_v_ext_state vstate;
diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
index 7efdb0584d47..256a354a5c4a 100644
--- a/arch/riscv/include/asm/switch_to.h
+++ b/arch/riscv/include/asm/switch_to.h
@@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { return false; }
 #define __switch_to_fpu(__prev, __next) do { } while (0)
 #endif
 
+static inline void sync_envcfg(struct task_struct *task)
+{
+	csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task->thread.envcfg);
+}
+
+static inline void __switch_to_envcfg(struct task_struct *next)
+{
+	if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_ISA_EXT_XLINUXENVCFG))
+		sync_envcfg(next);
+}
+
 extern struct task_struct *__switch_to(struct task_struct *,
 				       struct task_struct *);
 
@@ -80,6 +91,7 @@ do {							\
 		__switch_to_fpu(__prev, __next);	\
 	if (has_vector())					\
 		__switch_to_vector(__prev, __next);	\
+	__switch_to_envcfg(__next);			\
 	((last) = __switch_to(__prev, __next));		\
 } while (0)
 
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index d1846aab1f78..32aaaf41f8a8 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -44,6 +44,8 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
 /* Per-cpu ISA extensions. */
 struct riscv_isainfo hart_isa[NR_CPUS];
 
+DEFINE_PER_CPU(unsigned long, riscv_cpu_envcfg);
+
 /* Performance information */
 DEFINE_PER_CPU(long, misaligned_access_speed);
 
@@ -978,7 +980,7 @@ arch_initcall(check_unaligned_access_all_cpus);
 void riscv_user_isa_enable(void)
 {
 	if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_ISA_EXT_ZICBOZ))
-		csr_set(CSR_ENVCFG, ENVCFG_CBZE);
+		this_cpu_or(riscv_cpu_envcfg, ENVCFG_CBZE);
 }
 
 #ifdef CONFIG_RISCV_ALTERNATIVE
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-6-samuel.holland%40sifive.com.
