Return-Path: <kasan-dev+bncBCM3NNW3WAKBBPXISPGQMGQEXSQSV7Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4OQLB0L0pGmcwgUAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBPXISPGQMGQEXSQSV7Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 422F21D2714
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:53 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-354c44bf176sf3717234a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 18:21:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772418111; cv=pass;
        d=google.com; s=arc-20240605;
        b=PoJ58g7N3TNzbtZZdLl4QeZ5q/bU3TlAQrEtdsBoKUyJTgd4X/n6E0ah+OFm12Ti9g
         Z8QJDYPVVJJvOZFxsXkvUV1ZMAb/20HJS9w23UllU/ht+MZ6KfwVVqBEsoE1515a+rdY
         bMGgvN3GkfDQijqnK8yGF9rB8IS1v3JxVqcjOMZNt7rAKninvac1qRBNEpL6/68EEx2a
         o+QtJJxhLORjkGHI8JlBmQVVImA1VdfDA1UGK8A72+3POMplWny1mB2h9VUOV2T4tRoH
         IkDqmJsMQZICkmJCGthjIUEzY7jXYXfK+r7YoyNtIHFhSGD/mbdU+PKTDTliyupvVQwm
         Z7jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=HbhT5ONrsSpPsMQeP062fQtYNUDhdm6m2+Wv/gfW2D0=;
        fh=B9s/cg5IMXNi1uumaEqBCwDY3QY4Y79hAis+DThlWv8=;
        b=JoVCSp1Gm6rF87km5f3LFv91DR9MHS4z6SM77JNklWqu6Z9p/pIZHesQ6irHoH8rbq
         EX9BK/rWvbFltHLtnbfrHgTDWNVq7RQIK6MmxrwOvJY2uVR+bUR/K+m7dxlpgmxmHQV2
         1708cMLAungiu3nEfjH3qzg5FoYBDwrE3alI9EVYyoddX2u4jCyTasQnvzowOe/1R/q+
         d3MLQROpPjE617AmVK1EpuLqCG0p6i+nB6WVKqOu9k+xH2nxV5ULVaV20t31VP3fTI82
         QptmTQabR6AwSogq5JvldVwNVCEjsam915//vSr3rOlm2FvU2uD81KRfA8P2F9oE+mjT
         9Fxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772418111; x=1773022911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HbhT5ONrsSpPsMQeP062fQtYNUDhdm6m2+Wv/gfW2D0=;
        b=JYoTtc3kUzvYe+2AJh/59cZnVSdPGiaeEdtPXC3euHe4lSeAdrBdRLDk6rkviyjKw1
         a2ZvkhXsKmFt5YP3YPxgdaQ9V1tBWSYEjp3n+N6Ouk6E8eVhoNO8U/LpALSYpPipQ1gW
         FOyYlRArBCxDRorPFJ8IX6DR2202nOql+WajPZEBhupo6Smoypgw9dt2JYTcR7+B9UQB
         myV0hH/k7pI292uTX92pajMdB1Zdip4rMCmbTulQacK8ajzVLceVWPYjEwHGdgkT2i3L
         sAME+ioT7E83r5fHz3k5eVkNbXIp1CRu7BzCSvKbbxDIMYqPXMMfS0yO8m3Ay+oPL+4s
         3WOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772418111; x=1773022911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HbhT5ONrsSpPsMQeP062fQtYNUDhdm6m2+Wv/gfW2D0=;
        b=txrjeQ4qMAj+lBhfJ4Qvb24jYuB5LS+iDG9GOc6evnX1XXaAr+96vpiUxZBLM4FdMS
         q+cxN6JmpKI3CwUrpmaHZQ9ncbjz8PJHnvrnAd5CrKfkPR5QqlPbe3qfvcv2/JmOoYqJ
         8n2szKIyQhsRexwBWLUfhiFdktIkyvTRG7OqpTxJwZxIol/n2EjRkLGcqmFln0zlnEud
         zrR8U4baowyvhavyBLIIy0bCjTVwNtLBb1cEySiaB22Uq/5ljw4gqFYIUkrVVKJe7phW
         k9yFfr7+JQuwv/UpgQGSBaxpF9uwPcSQWdiG1RXG7/DMtU7rVLGOCQjQRRzX8rIQYk+f
         1C+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU08RLBdgsLGFAVAGG7FXZLtlV23qu7pS0hzMy5NNEMwbwQR4TsUpgtFszUiDe9T2NzToq+dw==@lfdr.de
X-Gm-Message-State: AOJu0Yz+AyDMlcf09xGDD44I77TQE93x14hB8wxxrC4v/cUhaWZUl3py
	7aSacyEsKAUpJ35RqHie1hrMnyiAtdMJ6FE6YO9SdklTgVWHz+v7+O2Q
X-Received: by 2002:a17:90b:1d09:b0:359:8988:38d3 with SMTP id 98e67ed59e1d1-35989883b88mr2370080a91.7.1772418111190;
        Sun, 01 Mar 2026 18:21:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HML0uJJi/CxY+LrON4CbLlE3K/XXzl9p2dkmpfZVcjDg=="
Received: by 2002:a17:90b:94:b0:359:8bef:a04 with SMTP id 98e67ed59e1d1-3598bef0b6bls514363a91.1.-pod-prod-05-us;
 Sun, 01 Mar 2026 18:21:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzu2f3k77JzxX7XOraTI9TatOsIstQfxveOn6QxaVi6BEbjjSyWoA102fyA/TQQM9uAoY/M5mpq80=@googlegroups.com
X-Received: by 2002:a17:90a:d64f:b0:354:a60e:9bcb with SMTP id 98e67ed59e1d1-35965c22fcamr7631062a91.5.1772418109839;
        Sun, 01 Mar 2026 18:21:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772418109; cv=none;
        d=google.com; s=arc-20240605;
        b=kzwUTCXYK3F7ilInIZCJbLrMRL614B5uhFAzsDoJCpxVCGgC4acylrc4Ahwrssq1Da
         LvPWq85i5fcjOjL9MyVm+X34rOhmhzURaBenB8fFC92V20HJAtYoMaY/6me+x2h6ippy
         74TTjumkJEiwjItG2QTyWbA+z5zKOynSgLXqNO08HPQgg3ft2gK/8fhqF4HdVaj1gruT
         4N8RLiGSNHjiAfWc8wbMB/mygYPc0/WRO7UyuEdHEGGaMeqWRCvk28Z2oGwKzCt3dN6k
         JcIdM9QFKaxRPKtQ0dBkoGlca7197OcAfI9PrE5pclLSKlWsFZ3xqdpUiqtqma/Q2W/3
         nR0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=U2G+uIyyF9KGYdofkKtbx1cleDr30Mt6PRN1itC2iiw=;
        fh=L8rAVU/Y///N6DPc9GQrjb2RcG4PA6dV6b84bmkByNc=;
        b=f+UV9yW5qNuqPY5Gfl/ouF8zP3vvoZYcqoqiZt4zeTAIKg0f8GMysHsk0PXqA54ed4
         TjYP3NMUFGRvMQcKvlXTMNOL7Wkc7zfP3RxcQkgXwVCpat3kuAuNDeNk03F/IX9K7oq+
         aCiSon3UO6HtTYWeK1X5p+8RjRpwupCiKyryQdXyIDYdhHCnNXodR04CBMXFSf/dwz/x
         7I9ValpguIvpO9L48js7mGAs7o35q+u6/JfFIiZtOdpp4OlxgrjabhweSejfepnpKwVD
         79x7+qMG1vhSOPqEu4dPxI/9V6+h4r+pQhDhdors1MPrbRi02tvSCn9Pc6gKrA6i9GzT
         RYuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3593dd8666esi401316a91.2.2026.03.01.18.21.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2026 18:21:49 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAD3E9s39KRp6CWmCQ--.11902S3;
	Mon, 02 Mar 2026 10:21:43 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Mon, 02 Mar 2026 10:21:30 +0800
Subject: [PATCH 1/3] riscv: mm: Rename new_vmalloc into new_valid_map_cpus
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260302-handle-kfence-protect-spurious-fault-v1-1-25c82c879d9c@iscas.ac.cn>
References: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
In-Reply-To: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAD3E9s39KRp6CWmCQ--.11902S3
X-Coremail-Antispam: 1UD129KBjvJXoW3AF1rKFWkWw1DWrWxGrW7urg_yoW7GFWrpr
	W7Kwn8K34UZFy7A39Ivw48ur1rW3WkW3WSk3ZIqw1fCan8Jry7CFykZa9rXryxJayUGr4f
	Za1ayF4rC34UAa7anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmE14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_Jr4l82xGYIkIc2
	x26xkF7I0E14v26r4j6ryUM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVWxJr0_GcWl
	e2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI
	8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwAC
	jcxG0xvY0x0EwIxGrwACjI8F5VA0II8E6IAqYI8I648v4I1lFIxGxcIEc7CjxVA2Y2ka0x
	kIwI1lc7CjxVAaw2AFwI0_Jw0_GFylc2xSY4AK67AK6r4UMxAIw28IcxkI7VAKI48JMxC2
	0s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI
	0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE
	14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwCI42IY6xAIw20EY4v20x
	vaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8
	JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7VUjb_-JUUUUU==
X-Originating-IP: [210.73.43.101]
X-CM-SenderInfo: pzdqw2pxlnt03j6l2u1dvotugofq/
X-Original-Sender: wangruikang@iscas.ac.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as
 permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	DMARC_NA(0.00)[iscas.ac.cn];
	SUSPICIOUS_AUTH_ORIGIN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[12];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBPXISPGQMGQEXSQSV7Y];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-pj1-x1039.google.com:helo,mail-pj1-x1039.google.com:rdns,iscas.ac.cn:mid,iscas.ac.cn:email]
X-Rspamd-Queue-Id: 422F21D2714
X-Rspamd-Action: no action

In preparation of a future patch using this mechanism for non-vmalloc
mappings, rename new_vmalloc into new_valid_map_cpus to avoid misleading
readers.

No functional change intended.

Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/cacheflush.h |  6 +++---
 arch/riscv/kernel/entry.S           | 38 ++++++++++++++++++-------------------
 arch/riscv/mm/init.c                |  2 +-
 3 files changed, 23 insertions(+), 23 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index 0092513c3376..b6d1a5eb7564 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -41,7 +41,7 @@ do {							\
 } while (0)
 
 #ifdef CONFIG_64BIT
-extern u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
+extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
 extern char _end[];
 #define flush_cache_vmap flush_cache_vmap
 static inline void flush_cache_vmap(unsigned long start, unsigned long end)
@@ -54,8 +54,8 @@ static inline void flush_cache_vmap(unsigned long start, unsigned long end)
 		 * the only place this can happen is in handle_exception() where
 		 * an sfence.vma is emitted.
 		 */
-		for (i = 0; i < ARRAY_SIZE(new_vmalloc); ++i)
-			new_vmalloc[i] = -1ULL;
+		for (i = 0; i < ARRAY_SIZE(new_valid_map_cpus); ++i)
+			new_valid_map_cpus[i] = -1ULL;
 	}
 }
 #define flush_cache_vmap_early(start, end)	local_flush_tlb_kernel_range(start, end)
diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index 60eb221296a6..e57a0f550860 100644
--- a/arch/riscv/kernel/entry.S
+++ b/arch/riscv/kernel/entry.S
@@ -20,44 +20,44 @@
 
 	.section .irqentry.text, "ax"
 
-.macro new_vmalloc_check
+.macro new_valid_map_cpus_check
 	REG_S 	a0, TASK_TI_A0(tp)
 	csrr 	a0, CSR_CAUSE
 	/* Exclude IRQs */
-	blt  	a0, zero, .Lnew_vmalloc_restore_context_a0
+	blt  	a0, zero, .Lnew_valid_map_cpus_restore_context_a0
 
 	REG_S 	a1, TASK_TI_A1(tp)
-	/* Only check new_vmalloc if we are in page/protection fault */
+	/* Only check new_valid_map_cpus if we are in page/protection fault */
 	li   	a1, EXC_LOAD_PAGE_FAULT
-	beq  	a0, a1, .Lnew_vmalloc_kernel_address
+	beq  	a0, a1, .Lnew_valid_map_cpus_kernel_address
 	li   	a1, EXC_STORE_PAGE_FAULT
-	beq  	a0, a1, .Lnew_vmalloc_kernel_address
+	beq  	a0, a1, .Lnew_valid_map_cpus_kernel_address
 	li   	a1, EXC_INST_PAGE_FAULT
-	bne  	a0, a1, .Lnew_vmalloc_restore_context_a1
+	bne  	a0, a1, .Lnew_valid_map_cpus_restore_context_a1
 
-.Lnew_vmalloc_kernel_address:
+.Lnew_valid_map_cpus_kernel_address:
 	/* Is it a kernel address? */
 	csrr 	a0, CSR_TVAL
-	bge 	a0, zero, .Lnew_vmalloc_restore_context_a1
+	bge 	a0, zero, .Lnew_valid_map_cpus_restore_context_a1
 
 	/* Check if a new vmalloc mapping appeared that could explain the trap */
 	REG_S	a2, TASK_TI_A2(tp)
 	/*
 	 * Computes:
-	 * a0 = &new_vmalloc[BIT_WORD(cpu)]
+	 * a0 = &new_valid_map_cpus[BIT_WORD(cpu)]
 	 * a1 = BIT_MASK(cpu)
 	 */
 	lw	a2, TASK_TI_CPU(tp)
 	/*
-	 * Compute the new_vmalloc element position:
+	 * Compute the new_valid_map_cpus element position:
 	 * (cpu / 64) * 8 = (cpu >> 6) << 3
 	 */
 	srli	a1, a2, 6
 	slli	a1, a1, 3
-	la	a0, new_vmalloc
+	la	a0, new_valid_map_cpus
 	add	a0, a0, a1
 	/*
-	 * Compute the bit position in the new_vmalloc element:
+	 * Compute the bit position in the new_valid_map_cpus element:
 	 * bit_pos = cpu % 64 = cpu - (cpu / 64) * 64 = cpu - (cpu >> 6) << 6
 	 * 	   = cpu - ((cpu >> 6) << 3) << 3
 	 */
@@ -67,12 +67,12 @@
 	li	a2, 1
 	sll	a1, a2, a1
 
-	/* Check the value of new_vmalloc for this cpu */
+	/* Check the value of new_valid_map_cpus for this cpu */
 	REG_L	a2, 0(a0)
 	and	a2, a2, a1
-	beq	a2, zero, .Lnew_vmalloc_restore_context
+	beq	a2, zero, .Lnew_valid_map_cpus_restore_context
 
-	/* Atomically reset the current cpu bit in new_vmalloc */
+	/* Atomically reset the current cpu bit in new_valid_map_cpus */
 	amoxor.d	a0, a1, (a0)
 
 	/* Only emit a sfence.vma if the uarch caches invalid entries */
@@ -84,11 +84,11 @@
 	csrw	CSR_SCRATCH, x0
 	sret
 
-.Lnew_vmalloc_restore_context:
+.Lnew_valid_map_cpus_restore_context:
 	REG_L 	a2, TASK_TI_A2(tp)
-.Lnew_vmalloc_restore_context_a1:
+.Lnew_valid_map_cpus_restore_context_a1:
 	REG_L 	a1, TASK_TI_A1(tp)
-.Lnew_vmalloc_restore_context_a0:
+.Lnew_valid_map_cpus_restore_context_a0:
 	REG_L	a0, TASK_TI_A0(tp)
 .endm
 
@@ -144,7 +144,7 @@ SYM_CODE_START(handle_exception)
 	 *   could "miss" the new mapping and traps: in that case, we only need
 	 *   to retry the access, no sfence.vma is required.
 	 */
-	new_vmalloc_check
+	new_valid_map_cpus_check
 #endif
 
 	REG_S sp, TASK_TI_KERNEL_SP(tp)
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 811e03786c56..9922c22a2a5f 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -37,7 +37,7 @@
 
 #include "../kernel/head.h"
 
-u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
+u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
 
 struct kernel_mapping kernel_map __ro_after_init;
 EXPORT_SYMBOL(kernel_map);

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260302-handle-kfence-protect-spurious-fault-v1-1-25c82c879d9c%40iscas.ac.cn.
