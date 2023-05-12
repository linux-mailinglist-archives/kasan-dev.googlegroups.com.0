Return-Path: <kasan-dev+bncBAABBNN262RAMGQETKSG4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id A62B56FFEA0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:58:14 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-75784a27e8fsf610520885a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 18:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683856693; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZGhKNvDDb4hwy7IC7tP6nz/aXLrfVH86z4cVMEU7rWFss1+W4bGBqkiPOSJ03gi8ft
         +MN+vC3aAG8NCA4VWAapHJXtgDJl6v/ql4rG8nUNG/eNeajTkWDD/RrLa3e28tPplqQ3
         OuNIEDU25Gfo4ZL3jrJFQSnaFtcAkPtSXvGM5jkop7vOvBbUJL3nuAxL0L1/UgiihaVq
         yk4nLX/0IjEBabRZRNzSX6K+dioDJV7WnzXr/wvsTEDVEsQ7p/bwQ2Fx4b+KXlkhQ/ir
         q5NNWn1ND3A99ZDl06V1wK5SFnaKPPhMR4HYEDN5pwCt6tW8pYRAGimKAz49KTw6EkWX
         4xtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Wqe9Onch5vcbtrucsVJxW+9Txr2uhy+67zVYnae2vl8=;
        b=bvD5LpZ/KDtKxOLbbVp8/Q0RiDkh2qQL/j6yv52NUTQRtkkdLjGlD18Zbx8lJ9mcFX
         Ve/ElhPC7AJ6qrs+TJ4kiq8In3hC3p4VVygk1sqErEGy5NFsHvhBrywJPYcQqF7rPFJv
         hiQeAdJii/MHa38/7CiLJvZ5QlTFFoIMmf/BJPfjunMvWM5usZJGjcjKmAMSWbBs6Ui0
         2t+eeAUQaje4wgTt1ylU5IQ1mFB1EhNevtF3K9PG0DwXt5g39lrOA76pLlAYcyyDo7Rx
         CHTfKy6dxw2qvc1eroj3cUF95JnlSnSTcc+oZnaW8JWQkmEutsqCJHvoQTTnZAVag5K1
         Wihw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683856693; x=1686448693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wqe9Onch5vcbtrucsVJxW+9Txr2uhy+67zVYnae2vl8=;
        b=GHPnwZGl0gLR7BIT5nWPBuVy4KbF/DyIMyY1C+L4evhCU2FasBte7jDCDHO6Wslr2u
         Lyec+rXaVYyPDX/3KBaolUMfL+3yg7J62SCyiYs2lhF+kt2trCHN2zIgZahvrXOjwkwX
         6KYt/4s2l7ISqqlrHtPDVv02wnXU0NPoTrVkXzn0IV0QYPW85aDWK2rXPfzER8rz8OCR
         5+aBm1Uh6fsYeWufGPjqB2uM8z8F14tCzjWFHGjknesSPnn4mDibSwL616RCInoXLVDB
         RI7+G0Es6H9h7tMSlgpv4RR/7hl5fo3Q8Z0fMmRcMNTSpx/wAYvkL3EskCBef8n79ocH
         i1Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683856693; x=1686448693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wqe9Onch5vcbtrucsVJxW+9Txr2uhy+67zVYnae2vl8=;
        b=gK9RNSfomrjp7oek1Wins6b9oybfKUrhpRAua4GxwGWNk8k0c4pNsxgKTZWgO3ieFB
         lzmqJw9dl/1/5oaoWgUEQdDCRW0izPBsPGWmylXw20SS3GscDqXOrXGJ/aUypoy1JmqR
         SI2HrJFgiujnc3dvre/cLUj+P4m0SHbgIWrs5Y5umc1ChVXVEXJmUTAWuiLKl1jFS/DD
         7pJ9xkbaK61lmQxBWSeWhscR906AwrAnCYwh4MLOV7ov3hjIg8vQXv2Q4T+UxBPgwTlF
         xPrJHg4ebUtse3XacTc17Y2PNXhWtjhvF5XtffcbgQdz4xEgIiumf8lj/jHH+tYzH7+9
         fbdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxhZUB56kUQVHuZ2etrXNeg5CALrPsK9QJlSlSv8O7XPgDzjVqq
	XZSyahhcaI/TGdOX275QBdA=
X-Google-Smtp-Source: ACHHUZ52ZhwVingpMvr+N9SijtI63XBVD9rkVYDy3xuaJuMSolhI1OBJFUGhkQEKJAeezQ/ZVE2s3g==
X-Received: by 2002:a05:620a:4714:b0:759:1872:4f7 with SMTP id bs20-20020a05620a471400b00759187204f7mr634189qkb.8.1683856693388;
        Thu, 11 May 2023 18:58:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:41a0:b0:61b:6d85:fa61 with SMTP id
 ld32-20020a05621441a000b0061b6d85fa61ls15376552qvb.3.-pod-prod-gmail; Thu, 11
 May 2023 18:58:13 -0700 (PDT)
X-Received: by 2002:a05:6214:c8e:b0:621:5e3b:8eb1 with SMTP id r14-20020a0562140c8e00b006215e3b8eb1mr9088091qvr.21.1683856692976;
        Thu, 11 May 2023 18:58:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683856692; cv=none;
        d=google.com; s=arc-20160816;
        b=GuMoAWEjn1nfsiv9MK6WpZRl0sNdPwQ4DuUO0iv6CIK74aluQarunv6HbsNcYEp3U6
         huAJJiqwwMTfJTEmYVJPNo9+eKMc70+8+kqf7YREUFY+C+nHE++azXlA0ikpXfY/Cv0X
         8YFJPslkKyE9iQSrv5INk8pAV303v1+J3EEv2zgfZvapJeMNfxzZlJOyj8W+0VdTJtey
         eVytp3AlhOoulFe+jZWvu1M0YdUqcXV205KBMKLOEIp1oinWLxgGTG355euxTrGXIOAv
         KH7vFyuvN6pFk9wrw3pCIFYaEZbH/uxn5114QUdAg3COwq3Ko5Z85DEWMXGyf/BQJ9D9
         YHvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yzAzda16mqe338sC+sAz+KlyBmYwMwwXhUi8z5ZZGNw=;
        b=WrW5B1U8zvYQ/k2FKAXXMWH5OZF+di3MOVy2b2stLhDUs6apQ1p0INI84XC+YeckFA
         dSZ2rHde5lHVTAqJKuf0i4Kc/SJEAiIAbk9/ccdWVrj/YP2I3GgI9N1WRDd2aPXlHEWN
         uCaonHiUrFyiKlguPgGxmYMYd2cy4ZAAM67n83sFoWTRghkW5jhfh4RBji774iegyWAc
         VdcgMxA8apu+Tae0Ic/U4OlSdKYmDVFLBBJxMRNR3dWd4kDexkWYESukQccbithUzBdD
         lbpQ5geqn4lo9Kuw08X9bWfG3H5dntNn8Ks3u1b99F5sQJniA30QirXEOD+CNO6ufAN0
         ia1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id l15-20020a0ce84f000000b0061b5f12678asi607555qvo.5.2023.05.11.18.58.11
        for <kasan-dev@googlegroups.com>;
        Thu, 11 May 2023 18:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8BxJukSnV1kYfkHAA--.13523S3;
	Fri, 12 May 2023 09:57:38 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxXrMMnV1kocdWAA--.23198S5;
	Fri, 12 May 2023 09:57:38 +0800 (CST)
From: Qing Zhang <zhangqing@loongson.cn>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Huacai Chen <chenhuacai@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Jiaxun Yang <jiaxun.yang@flygoat.com>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v3 3/4] LoongArch: Simplify the processing of jumping new kernel for KASLR
Date: Fri, 12 May 2023 09:57:30 +0800
Message-Id: <20230512015731.23787-4-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230512015731.23787-1-zhangqing@loongson.cn>
References: <20230512015731.23787-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxXrMMnV1kocdWAA--.23198S5
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoWxCFyrXFykKF43Aw45Xw1DJrb_yoW5CF1kpr
	y7Zw1kJr45Grn7J34qqa4Dury5J3ZFgw1aganrK34rZw12qFy5Xw1kZrn7WFyjq3yFgr4F
	qFyrKF9Iv3WUJ3DanT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	baxYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_JF0_JFyl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVW8Jr0_Cr1U
	M2kKe7AKxVWUXVWUAwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zV
	CFFI0UMc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWrXVW3AwAv7VC2
	z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JMxAIw2
	8IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMxCIbckI1I0E14v26r1Y6r17MI8I
	3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxV
	W8ZVWrXwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26ryj6F1UMIIF0xvE2Ix0cI8I
	cVCY1x0267AKxVWxJVW8Jr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2js
	IE14v26r4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZF
	pf9x07jfl1kUUUUU=
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Modified relocate_kernel() doesn't return new kernel's entry point but
the random_offset. In this way we share the start_kernel() processing
with the normal kernel, which avoids calling 'jr a0' directly and allows
some other operations (e.g, kasan_early_init) before start_kernel() when
KASLR (CONFIG_RANDOMIZE_BASE) is turned on.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 arch/loongarch/include/asm/setup.h |  2 +-
 arch/loongarch/kernel/head.S       | 11 ++++++-----
 arch/loongarch/kernel/relocate.c   |  8 ++------
 3 files changed, 9 insertions(+), 12 deletions(-)

diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/asm/setup.h
index be05c0e706a2..2dca0d1dd90a 100644
--- a/arch/loongarch/include/asm/setup.h
+++ b/arch/loongarch/include/asm/setup.h
@@ -33,7 +33,7 @@ extern long __la_abs_end;
 extern long __rela_dyn_begin;
 extern long __rela_dyn_end;
 
-extern void * __init relocate_kernel(void);
+extern unsigned long __init relocate_kernel(void);
 
 #endif
 
diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
index aa64b179744f..aace7a300cd3 100644
--- a/arch/loongarch/kernel/head.S
+++ b/arch/loongarch/kernel/head.S
@@ -95,13 +95,14 @@ SYM_CODE_START(kernel_entry)			# kernel entry point
 	PTR_LI		sp, (_THREAD_SIZE - PT_SIZE)
 	PTR_ADD		sp, sp, tp
 	set_saved_sp	sp, t0, t1
-#endif
 
-	/* relocate_kernel() returns the new kernel entry point */
-	jr		a0
-	ASM_BUG()
+	/* Jump to the new kernel: new_pc = current_pc + random_offset */
+	pcaddi		t0, 0
+	add.d		t0, t0, a0
+	jirl		zero, t0, 0xc
+#endif /* CONFIG_RANDOMIZE_BASE */
 
-#endif
+#endif /* CONFIG_RELOCATABLE */
 
 	bl		start_kernel
 	ASM_BUG()
diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/relocate.c
index 01f94d1e3edf..6c3eff9af9fb 100644
--- a/arch/loongarch/kernel/relocate.c
+++ b/arch/loongarch/kernel/relocate.c
@@ -157,12 +157,11 @@ static inline void __init update_reloc_offset(unsigned long *addr, long random_o
 	*new_addr = (unsigned long)reloc_offset;
 }
 
-void * __init relocate_kernel(void)
+unsigned long __init relocate_kernel(void)
 {
 	unsigned long kernel_length;
 	unsigned long random_offset = 0;
 	void *location_new = _text; /* Default to original kernel start */
-	void *kernel_entry = start_kernel; /* Default to original kernel entry point */
 	char *cmdline = early_ioremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot command line is passed in fw_arg1 */
 
 	strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
@@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
 
 		reloc_offset += random_offset;
 
-		/* Return the new kernel's entry point */
-		kernel_entry = RELOCATED_KASLR(start_kernel);
-
 		/* The current thread is now within the relocated kernel */
 		__current_thread_info = RELOCATED_KASLR(__current_thread_info);
 
@@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
 
 	relocate_absolute(random_offset);
 
-	return kernel_entry;
+	return random_offset;
 }
 
 /*
-- 
2.36.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512015731.23787-4-zhangqing%40loongson.cn.
