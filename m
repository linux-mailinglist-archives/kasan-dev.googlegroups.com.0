Return-Path: <kasan-dev+bncBDAOJ6534YNBBLUC2TCAMGQEKGNI74Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 91A4EB1DD8F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 21:40:31 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-459dfbece11sf7229515e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 12:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754595631; cv=pass;
        d=google.com; s=arc-20240605;
        b=aeDF8QRUp/KdwK3k14FLzYxYPnFEDDw69o/YQ6MJmTRYoo3uz1/LM0GasM1OevfSj8
         /JDlydINgv59SeYX7aTknCGY/EpRbFDbeJOyAWS5CBgowRkgM2PFoX3e7dWoH4h7E9bp
         wraXjGuk+3xghXjq8PCFQr8H8cuJOLB1K94JGo+f0KINPjCilkNSVW2dIi515B78laQS
         hs3pX5vttmvMBDfkUnmdMbG6Ii1BekDV4LC8/WTc8VwR3RNRovIUs6AqDQps6G9ISoYG
         fTKEHVQGwA/aUMWj/4Eciq7CrlNe8Wrjyw51XMixBY031Qzv91yyPgRoRya6jU4DySPF
         tRCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PO4yKLCLJ4NZBR+E5PMnzz2y1a3TZ2QJkVoWim9+jfM=;
        fh=PKVY81XsnfAcsTlafgXNExfIP2xtcktUjQgii8yoaas=;
        b=VeCok2qnDFYqqaivh0/hbpFOzcy8fbmm1VNB1tVrVwPgUp785ZKp2bubaUUV4c/lBN
         TO5dF9wsw4O8srHqLJzx3eSTTsahk7eU59YF3Ia2ERsxY/xzN3/ANG6McwzAcHzOy44L
         jPm/vIUSMR8LG8wCnVwt7NGaxuJQgfIJ01julpGOMUHx0QAUjS5j9997e7M6qpRDpmN4
         tJ6x9p97inWCQPfdsf305qIsxI2b0q6kBS4ak5Iktv1Ogz9MNe3qbLfyrIoOUiRDRHzv
         s4B0FRmKeoehsbJFvdaJ9O0do7WXUoIquAs5BcQ/50Cc2HqeFFhaK7gBZ9tXAc031MOE
         dpww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kWjRi3ow;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754595631; x=1755200431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PO4yKLCLJ4NZBR+E5PMnzz2y1a3TZ2QJkVoWim9+jfM=;
        b=RwewzXUqTC311KIsgMK1aOxdrmhQ94uTaBqbp99FQHUjnIY/VxhMKbYkIjqhFHQdvL
         EvH3CSAc9wClvlEn1U9xLtChQsycCkzG6HJQRZiIhe6+yyrHKa5EHVzAMlFbjMsZvVeF
         ARYmghfYZJzLP8pS8CyhPk5BOAICxfeGlSQLJhieZZcEueCiaN7ybuGno+30ohQqxVmk
         cNS51nX/FKLgQXg09LXm4In/RPtAgZSOz1z5JEiz+IwWzRCB27kyle2BkMS/rv4Y+sIm
         XVpKYhQ7SGXKO3NY7M8hzP6+SPtbqqx81BiKB0CAGemg5uD21MRoWEY5KsFwaq/fwift
         V2Zg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754595631; x=1755200431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=PO4yKLCLJ4NZBR+E5PMnzz2y1a3TZ2QJkVoWim9+jfM=;
        b=Ar1Lh5JrgS+SbezjkTcGE71OYPze/WaGJdtil2PlPslQwlGlp0hjvVSlWk6Oigyi4b
         hD/97ocFzBNcGVfXJcAllofm5R711oa1O8r2EC9TWnVzs62oM+C55uulewaEMGgUuFO0
         oJksKlXxcbr+pE/uZER/9mGq5b9+Q2V3YoW1SdpqA9IuOuDwnHdISPM1PufwD4AtegLx
         OUY4LJNniKHmuLq5CRui806JOvEQkKOAIzS1fiuJMycHYJQ6BAjR4jNjZzHnhugSejay
         tiwO5o8x7FgndP4bgu19yHAlRUDhXAx0udyJmLVKNfEq3r8Cduhiarxh+dpAmL92/xG2
         lmxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754595631; x=1755200431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PO4yKLCLJ4NZBR+E5PMnzz2y1a3TZ2QJkVoWim9+jfM=;
        b=VNT8aGaBEayP9HFtsKS9aa6iE+AX6b3ZGkR11Erh5jJPZvDJhpcdRDSyc6ncKhCNAA
         Ez2WzeFb2V5XWnOirFfG7o6DAYlcllpUNG7wkPkFNC4h0aaXJFtBLMImGDifVtRFWff7
         nSTE75PjtCM5PtSeK2dsRBdUNjlxGQf3vaDvGbgX9gEForP37UyqHF1NJxmwYdTrp+a6
         rB2jW2T+nxp/kkJJl3m7V7cjnyXnMUmvWIQvYOmQghjdLXHpY4dTZh0QDoylpSwucSvZ
         kF9cF7N4VOlpskt/8ZZmf8oHsKvLiRBECDNUnDKsaKzQoceHScv1ZL7SDvC9K9++AN7U
         t2cg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSTAM5ctI5RloJRFvLC6kSLSTz8/rTTnnLsOzJhzsIMQ4P72KGPrGfA86mz97aC3oI6P3fMA==@lfdr.de
X-Gm-Message-State: AOJu0Yywr9aZCe8XCKtLWxzPJvD/OUXFGTArO1EjwBzhMsrqDWzFlhQF
	v/xfWtBFUwfvHdqp2/dYdp1MqK6DDloSqhNi5JNxLPvED8E1+B9JudR6
X-Google-Smtp-Source: AGHT+IGEu1vTiomC02ewY/EJXukKeYhb7uQeGEqOOoZ2mWWtSc6xxkHbLdDKTNk/cBo9gmhmAmgq8A==
X-Received: by 2002:a05:600c:4509:b0:456:496:2100 with SMTP id 5b1f17b1804b1-459f4f2bac3mr1797695e9.31.1754595630933;
        Thu, 07 Aug 2025 12:40:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrO69+AxZ6gY7Qg5Z3XeIP+9FO19c4/FH2dJuIJ2kTog==
Received: by 2002:a05:600c:4f49:b0:459:e65c:2213 with SMTP id
 5b1f17b1804b1-459edcf9db2ls8531055e9.1.-pod-prod-03-eu; Thu, 07 Aug 2025
 12:40:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLGNqhbnbjrlSWK71K7aGNMyAkVF4C/6ELtRWOsDJhjAVrK5A2jicNrZmCL2/LTntzQJzV4KkgkrI=@googlegroups.com
X-Received: by 2002:a05:600c:4449:b0:459:dfde:332e with SMTP id 5b1f17b1804b1-459f4f1447cmr1590335e9.29.1754595627801;
        Thu, 07 Aug 2025 12:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754595627; cv=none;
        d=google.com; s=arc-20240605;
        b=OjFJp/gdfL71DZ2faTZ7kB375Sh8BsWVeT3Q+lzbGVkM8jEGlsjO7ryW+/f7hfN9Gm
         NYeejPiATqH40UDEuCMrJAvgcj99nv47QqFRT52brREfpAfgZ2Un+NfbomGPd3/EXNbP
         xax9gUravGuDmhbjq2QXdfcQv3BoUDQma4nxm4DWiZnvBaw/IeI2xIDqd3m8AWWN8MHX
         50HWHxoIyNZ022d/+gF4vJc6cXlibMIG7mtfo8XAVVAw63FJK0GPEiMhTCI9uMZJqor5
         LcHOH/0KlKS2M2+iK8U0MB8o6HK7NDvmBbgzR0OMkGjZb5xawOvtOa/xeFYBrY6p81Hp
         nAkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sNdBwl8v2OqAa3v0ByxYoV2FZHtZfSuaaApNKvSqvMU=;
        fh=KZL+2S1oxvi92Da4E/Yq7pxCy6OeZHwdrYo8AI9pE8U=;
        b=OKWmrmN/h+L+b5WO1BZmd06iDQkUshY8OV8NzY8LQCOdHiuEhSGod55+TeeR9DZJOc
         wbA4Hgy6lnpJYQUfMVd0TBEQrZl7aKEyp70eAWEgO13iYSHcO0tu6yfV4/cYIkuqtbIu
         41ae3mK0Tnc1Fsk5LNEj2FfEYpXzv27JjE3znoFVzrMqFgpoPZA3/cCXuH5PGpwufEq8
         9LKhdmrW6nTu9/GvqNjd7nA03tt6Dn5WVeRq2e5VpY5mf6SdM/b+6GkjRpQgHodwuAnR
         FUmK9SMhWFl2fkGWRgSWMhgvL/y03k8WLk/oM4/EReNJdth2dDwPfw3OJvAonTr29yvR
         tXyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kWjRi3ow;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c4791easi502588f8f.6.2025.08.07.12.40.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 12:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-55cb8ab1010so1104015e87.1
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 12:40:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV6cuGXiw3qaNTDtHYSu3Kj88CZQOa2QxHLRyZlhgDMhjc7WM+KJ4KtfAAOlZclW5JZZNxcJL3PL1U=@googlegroups.com
X-Gm-Gg: ASbGnct4gp0LlwgK/0JSRgbRXtGV8/oSxhomD1yq5dRpuRg4D7+d2w9+4qqZBflWphm
	wnNYgW7LPvIVwYcThBk0Tf6ai0hQOCONBnln0d7XjA8Gm/musxlDIJ+rljsTfsmyeJ6RC2hN67d
	gU1Eqwt/YezmHry7Eo1Nwqi+LD/cqbe6E7IcylpLpgCc6isvWktRoto7vQh4v6xfzE8RMOpKqDb
	vpAfgInLMIdPuU36Py3VtxhlQ8cHXht8oSuMGMcjcRf5sNhFe3EzMzqCEivet5vjpDmQipNq+eL
	ozVGwqx8MPQ0hCE9qLbF1JQCRppNoTFt5hQHRVjRrWi4RrcRH3M+h+VTYGbGOLROqU/jGJ1En9W
	o+suvgdoTXs8CfVCwNsPJu/Bl5bMxQXT0oW4aplf1OA8hqjFJkCA7o2WSoUNq79kGc9mmVA==
X-Received: by 2002:ac2:4e14:0:b0:55b:8f46:80ed with SMTP id 2adb3069b0e04-55cc00e3a66mr10263e87.21.1754595627098;
        Thu, 07 Aug 2025 12:40:27 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88c98c2asm2793570e87.77.2025.08.07.12.40.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 12:40:26 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	bhe@redhat.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	davidgow@google.co,
	glider@google.com,
	dvyukov@google.com
Cc: alex@ghiti.fr,
	agordeev@linux.ibm.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com,
	Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v5 2/2] kasan: call kasan_init_generic in kasan_init
Date: Fri,  8 Aug 2025 00:40:12 +0500
Message-Id: <20250807194012.631367-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250807194012.631367-1-snovitoll@gmail.com>
References: <20250807194012.631367-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kWjRi3ow;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization.
For architectures that do not select ARCH_DEFER_KASAN,
this will be a no-op for the runtime flag but will
print the initialization banner.

For SW_TAGS and HW_TAGS modes, their respective init functions will
handle the flag enabling, if they are enabled/implemented.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390
---
Changes in v5:
- Unified arch patches into a single one, where we just call
	kasan_init_generic()
- Added Tested-by tag for riscv (tested the same change in v4)
- Added Acked-by tag for s390 (tested the same change in v4)
---
 arch/arm/mm/kasan_init.c    | 2 +-
 arch/arm64/mm/kasan_init.c  | 4 +---
 arch/riscv/mm/kasan_init.c  | 1 +
 arch/s390/kernel/early.c    | 3 ++-
 arch/x86/mm/kasan_init_64.c | 2 +-
 arch/xtensa/mm/kasan_init.c | 2 +-
 6 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f70313..c6625e808bf 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -300,6 +300,6 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
-	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45dae..abeb81bf6eb 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -399,14 +399,12 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
-#if defined(CONFIG_KASAN_GENERIC)
+	kasan_init_generic();
 	/*
 	 * Generic KASAN is now fully initialized.
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
-	pr_info("KernelAddressSanitizer initialized (generic)\n");
-#endif
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca..ba2709b1eec 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -530,6 +530,7 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 9adfbdd377d..544e5403dd9 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -21,6 +21,7 @@
 #include <linux/kernel.h>
 #include <asm/asm-extable.h>
 #include <linux/memblock.h>
+#include <linux/kasan.h>
 #include <asm/access-regs.h>
 #include <asm/asm-offsets.h>
 #include <asm/machine.h>
@@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d21..998b6010d6d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173..0524b9ed5e6 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -94,5 +94,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807194012.631367-3-snovitoll%40gmail.com.
