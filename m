Return-Path: <kasan-dev+bncBCM3NNW3WAKBBCPETHGQMGQE43CM2KQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eKReBw1ypmnePwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBCPETHGQMGQE43CM2KQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C13E1E93D6
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:52 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2ae44c7553dsf11316285ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515850; cv=pass;
        d=google.com; s=arc-20240605;
        b=eJhnLvfkXcgJFt02cowT64lbkGRKskKUPrF2Nbj2IZDANo/LWEmYUWyo0Mk/Nu2hHO
         tLJklJG0shS1Eq6AGkF2gLRPe0hWU7p/WMLeVOr6cB++EU7RQz7kuZkcJP7v9ArMEHXi
         xt/3nuR7c+OtwTYp72ejoCkcEnErkytP4EQg4g74qU5MtdzwVH1PQlNRQPPSAZHUDzxl
         TsO2MmePrUEvgunGZHMkA6PpH+8ZuJ7rL6KDujALlqnln17GAJcPZokLB39YUP1y4gz2
         uF9lWZ2Ffv0NRSSEIKIhckxc5yyL/8/Wjo+XfReb/mXmVMERCrFyxVvAqIY5QwyRf2b9
         syUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=SDSAsqWmmPsvpnj7xVVjwxjE3SAos59qmHfm2QZ5tzo=;
        fh=LL2fKqWoh1ujCgjIrIaPzQqkbtd7a2t72ytUfIBv88s=;
        b=gSY7WAergbKjtAFBWQRmV3L/QM4xSD0/XQN12d6n+SjmrMgysgtvkf3edqxqjtbnu6
         zTa9sz8ImNZYqv0q5Q+1m6KibuCyiYmBbcdRMO0+OeLe946Ick0rYobbcG36d8Kdch8K
         TGSrX8ISqGGxGVU47hm2WLXUeXxmtBOl6PqjQMlzNCesKSmH3iTALW91p4zVA/61ioiV
         vUnAWc1ZkM+81TkeVrr2SWZxoZbf5vdS7y93YtfTdkSg3OZScWmC9/E7ZDH2uTmAiEx5
         cPhx3VCjO99qnHhDqqnBACiVvygqaY/TSJIMRx/YimSk65nkvCIncgVOa2TkJCISwR3H
         Ccqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515850; x=1773120650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SDSAsqWmmPsvpnj7xVVjwxjE3SAos59qmHfm2QZ5tzo=;
        b=lYgcSzmgZhyrnKtbZN8q2Mb911vPG3gulOYXq7GJtqHzfa3vnHE8KDZ26XREdNKVRZ
         KQKX/uGL8ZLWUr+fQ+xUSNu3KbpG/i/rBJULqxGm33PXKY9eXp/YlsLiJMi1eUr3HvLu
         AjGA60at+cuHAJA2nT1SoxelTkHFpEmqC0wSFAcq5FH11B7uEadqi3UiT9d7Twfeo8qu
         QI9uf1eNOoLJHT/hFlLL5+7Bu+HebVOBUHMkKFYSwbbsUqsRZwpiJN3D01M9+UikYO2s
         gKmNuH/pDuhfh/OM0xb4+Apt1S7HHO2DwzRfi+PbliuiP1N8yIR2d2IPkA/3vrxNnRGf
         hPbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515850; x=1773120650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SDSAsqWmmPsvpnj7xVVjwxjE3SAos59qmHfm2QZ5tzo=;
        b=OyAMP2B3MGaX5qsCmZ1ba3gBxRtGZSNQZq3xpgpwRJGayZdhczZ5W/pdzcpJVQkgGw
         jWpyiYwcxIovH7AGQxAOVPGHi5T578ECW78O9O/SM3PIK0zqlAIrUEF8b8oBOHJEKaJF
         7fZfIHfc7W6QveYbMI+WfGYw04YPnVt0+tOTH2CtAeKSuEjW5cuARRRorrCAoP0sEoA9
         FFkwbs5IvrzJJxG2eJhTwNadc1GBwLgDBjTY4B81DrTYvL3IcMtdHL1Bo5OwVIMlUBep
         2nb2IA47QeMYh1pajXD4PP1z+LUMPnPoUyyC/FLCwXJfoejSM3eFuRgCIv8SCp0gxCTu
         Hv4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkiWcXXBYBdcYC/1Nqo7muiRRuGgWzDeoVaJN+qzauajJ8IgcrE3l02m4N3TwU6FpJZNzCcg==@lfdr.de
X-Gm-Message-State: AOJu0YzTg1cXhCh2lSQmB5Fkyz96Pw91tgKLH3u3KMjq2JJqBqSbolnZ
	OfjMvOwAkvt6jVnGu37jPQ1D1YDaO2ce2JlkuYl6qesH3Xm+8bogxaa+
X-Received: by 2002:a17:903:41c6:b0:2ae:412c:d316 with SMTP id d9443c01a7336-2ae412cd763mr72033305ad.1.1772515849642;
        Mon, 02 Mar 2026 21:30:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G7XqTM+P6LFXIVdyceR0hdnCZOc/UqZN7bIpLgwUDozg=="
Received: by 2002:a17:902:e353:b0:2ae:4444:bd8c with SMTP id
 d9443c01a7336-2ae4444bf34ls17108215ad.2.-pod-prod-08-us; Mon, 02 Mar 2026
 21:30:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXhpPQeDpY9ePkrz29TSMzBtfo+X/IYwbeF6gbdCxKkHbDcfx8wXLhPC5nsYgYTt0hIlG+KEn0JX34=@googlegroups.com
X-Received: by 2002:a17:902:f68b:b0:2ae:5851:9960 with SMTP id d9443c01a7336-2ae58519b53mr40825895ad.21.1772515848309;
        Mon, 02 Mar 2026 21:30:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515848; cv=none;
        d=google.com; s=arc-20240605;
        b=ZbyR74O3b32YXY6ztoAtUaHtLzs5hNhrXjtotLL3+yEIYiLomPbZXcbQ9cfClYSIJy
         Rp/fHVDl1SSTJMSAbGOv7k3Z1RmqJYFhSeFlXsD8/WDCJfWcVCthoe1pnSlq100SKAVa
         z5hvINbIMJcVuke+DIIdv6gtw9/coLmcE+yOae6KJH7kCvwSQi6XrOUykX7zXIc2bSIi
         bfKYBWcasAsy0xvp7NW4d5KWn+10GpARzZArqKoLcGya1rFOLV87pctoUqyJomSbCTp1
         5rRkiH/agK0/L9P196CHPztafFSXMbXcF7Pa4Ermp3yWL+rZ3UWA5TnmRQwwQU6I3M5/
         bjiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=RB/kixCLocXouPXT3CU1vhI50eVZzZhMBOaCEgmPFrw=;
        fh=AbCZaUdyWvUg2b+aAmbGZp57qTiD/MkPGWyhIE7FtJ8=;
        b=QRKMV4fLvLUtJw5MoD98WnySxbKcGjHdufN1eJq0RTPE4Ic+kbSIeOvkeceZ4Ig6eh
         iUnqm+D8ay7kEehw59AGoIPzUc+zXervOuxtiL94Ve45VasZIGbk08L7QuYCo+h1Clgg
         3tvSq3DOK335H430G2Ly7JGXh8xQuZuYUq18OqZX5XABvCmngFWW/FeKTWYlVPknmvpV
         Kc4gcJ8dShY4XfseXmrjuJsD9eauJqO96mz8fZX6sQW3qMPMFCyL/lB9aeLxdmLzgXpP
         f3GPbTpO+Ie7xZXybpEmBSjhQT2N0Lp8zkMDqDo3spuSHG91/tv9R4Ut8QtJWPeNqa4O
         RFjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3599c43261bsi34134a91.1.2026.03.02.21.30.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:48 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S4;
	Tue, 03 Mar 2026 13:30:39 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Tue, 03 Mar 2026 13:29:46 +0800
Subject: [PATCH v2 2/5] riscv: kfence: Call mark_new_valid_map() for
 kfence_unprotect()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-2-f80d8354d79d@iscas.ac.cn>
References: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
In-Reply-To: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 stable@vger.kernel.org, Yanko Kaneti <yaneti@declera.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S4
X-Coremail-Antispam: 1UD129KBjvJXoWxCw1kXw45Wrykur4DJr1xuFg_yoW5XrW7pa
	9rCr10grZ5urWxXrW7Aw1j9a1UWws5W34Fka4vk34rZwsIqrWjq3s8K3ySqr9rJFZYgay0
	kF43ur1YkF1UAw7anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUm014x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_Jryl82xGYIkIc2
	x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq3wAS
	0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2
	IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0
	Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2kIc2
	xKxwCY1x0262kKe7AKxVWUtVW8ZwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWU
	JVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67
	kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY
	6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0x
	vEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVj
	vjDU0xZFpf9x0JU66wtUUUUU=
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
X-Rspamd-Queue-Id: 1C13E1E93D6
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
	RCPT_COUNT_TWELVE(0.00)[14];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBCPETHGQMGQE43CM2KQ];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,declera.com:email,iscas.ac.cn:mid,iscas.ac.cn:email]
X-Rspamd-Action: no action

In kfence_protect_page(), which kfence_unprotect() calls, we cannot send
IPIs to other CPUs to ask them to flush TLB. This may lead to those CPUs
spuriously faulting on a recently allocated kfence object despite it
being valid, leading to false positive use-after-free reports.

Fix this by calling mark_new_valid_map() so that the page fault handling
code path notices the spurious fault and flushes TLB then retries the
access.

Update the comment in handle_exception to indicate that
new_valid_map_cpus_check also handles kfence_unprotect() spurious
faults.

Note that kfence_protect() has the same stale TLB entries problem, but
that leads to false negatives, which is fine with kfence.

Cc: <stable@vger.kernel.org>
Reported-by: Yanko Kaneti <yaneti@declera.com>
Fixes: b3431a8bb336 ("riscv: Fix IPIs usage in kfence_protect_page()")
Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/kfence.h | 7 +++++--
 arch/riscv/kernel/entry.S       | 6 ++++--
 2 files changed, 9 insertions(+), 4 deletions(-)

diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index d08bf7fb3aee..29cb3a6ee113 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -6,6 +6,7 @@
 #include <linux/kfence.h>
 #include <linux/pfn.h>
 #include <asm-generic/pgalloc.h>
+#include <asm/cacheflush.h>
 #include <asm/pgtable.h>
 
 static inline bool arch_kfence_init_pool(void)
@@ -17,10 +18,12 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
 	pte_t *pte = virt_to_kpte(addr);
 
-	if (protect)
+	if (protect) {
 		set_pte(pte, __pte(pte_val(ptep_get(pte)) & ~_PAGE_PRESENT));
-	else
+	} else {
 		set_pte(pte, __pte(pte_val(ptep_get(pte)) | _PAGE_PRESENT));
+		mark_new_valid_map();
+	}
 
 	preempt_disable();
 	local_flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index 60eb221296a6..ced7a2b160ce 100644
--- a/arch/riscv/kernel/entry.S
+++ b/arch/riscv/kernel/entry.S
@@ -136,8 +136,10 @@ SYM_CODE_START(handle_exception)
 
 #ifdef CONFIG_64BIT
 	/*
-	 * The RISC-V kernel does not eagerly emit a sfence.vma after each
-	 * new vmalloc mapping, which may result in exceptions:
+	 * The RISC-V kernel does not flush TLBs on all CPUS after each new
+	 * vmalloc mapping or kfence_unprotect(), which may result in
+	 * exceptions:
+	 *
 	 * - if the uarch caches invalid entries, the new mapping would not be
 	 *   observed by the page table walker and an invalidation is needed.
 	 * - if the uarch does not cache invalid entries, a reordered access

-- 
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-2-f80d8354d79d%40iscas.ac.cn.
