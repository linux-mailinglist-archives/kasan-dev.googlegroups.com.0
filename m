Return-Path: <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gGJ3AA5ypmnePwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 75C581E93E0
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:53 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3594620fe97sf26611072a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515852; cv=pass;
        d=google.com; s=arc-20240605;
        b=iVLThNN7nzAw8Gk3BeXvRcu1NlCfiRQKOgZYysYBFpEIe35Woog0EhNFn4K9RQsMJc
         C9qpwHQ4oLrBsWVuEIBr3JyvWcquBr0PPxjsCB/1addCV2H9a0pDmTzCfbvV8RVUiMwL
         fIHyIdzA8J7hQrYyEwC06O4VnRcmECy4CV4NApGODIyreyO9ZFSysjUR6rczPjHOY5xr
         QViP+prydBQZIsGFDZko5z4oPVgZURa5IJDTfUceLpNVboXBUjeDAuZMrTX6g2VHM6E1
         7PuIyAnc8dUia5CNOou48Zz9CssBuvrK0dKr4biD730qO6kLSC8RkzQ9OOO+zRC7u+Yt
         AOow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=FcAvBEv8kOjiFWiHlH7nrwfaHzSk/Fs4CV1QlgiAAQ8=;
        fh=V8bwR9M35GZlUg7M6/eVkLDfcc5GmgmO6oQfuTMV39Y=;
        b=MVi2B34Fxw+xMfHt863owSqwbAGFW2lk2dHtJkLJDbFL/q5V0djn85iwaf6FL5B6sU
         Iu/8YG6Pj2DZwWGIkR/p+NlAZmYXkllPnksn+oe+DCHd7bqeZzhpuB/bFMjczmgfGiDP
         NwYUjNzvJqzbARJChACmD+M//Nl1KVHEDciGOzHLoZhdNMbzluh42Xv+Pu+e8rXGHFtb
         mimb9pzPWc6IthDkTDWegoy+CbpxfZJBmEkIHKumiGFHjy//v0Nv3gT7i3eFok0gBSRA
         K08C8VAdVQki3P//6vdw1gL4IYbu+uEyXE/IbtvSS1yeQdFFLA1Ew+OWYBPsWLXR3pyw
         MqOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515852; x=1773120652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FcAvBEv8kOjiFWiHlH7nrwfaHzSk/Fs4CV1QlgiAAQ8=;
        b=lZvcpIxJ8T7gfUWrbkAc17t5qQIAkMNzLde5YosdxxwQXFIds++1FwoP2IHoDD7Zx1
         Hmvd/8Nvay9h56Jwg6svBOPsXHad1rkhstpSM5eVt1XxaQGB64xFnnKyNbanmZO2Z4Fb
         pPZfu/qo45l8dVAkKLPaEl6tOoUHU3d7Uf0owWhZnPWMv9tAcAA+Ysrc03Hx8psmcqpP
         39W8cyndRLBe0yYVhQnB0jfhRbci0+Trl/lGn+JFjfD0poDWg6W+LSH8QdjY75pA8zoO
         fcbZnPWRtu/CJvphEkBOPR4dLXSF+8Tb8rT8w0Hi6lzse2WNNNNA4ZiLlYRz+9/q0n/7
         zg/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515852; x=1773120652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FcAvBEv8kOjiFWiHlH7nrwfaHzSk/Fs4CV1QlgiAAQ8=;
        b=i+jbLsgwkM1GRcMXda5+Exx1qMLtnvemHIeuzQ7yDZt0pMhppz7kPnfdQUe54zbEI6
         vOwLIciuvpcvx0n81YQw8h0wQ5MQAbGA/WhpHOiALh/U6Io0TSAry7Su/+VwHhGlJPia
         mTCQ5YZri6+mV7fjMTf3qs1xIEi0nqjXU8rW0CKk8R7/SrKLVZ4SFLKL2WYXhXpBCu7a
         kFZJyqtko14p11P7Es7KNfYnYtiBzp+pUwngufm7RJ3H8gGUKFU0DEAgaRCTDQ8JdvDs
         XHWp96myeepp/7fLh05nEzYRq2934ZQmP2S80gHvFK2EEPr1BYBckBXXR47bvSe+NNhE
         nOGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlBYWv4QYBrHLSx+Awye/7okiHRsQPbzn5gK7K8g4+On3qk7Nf+WLmLOEP/37FDOxMUegzzw==@lfdr.de
X-Gm-Message-State: AOJu0Ywc4QsX/+YqXYe4J33wgACbU//0A3uruXP7n24hhFL2YgBsTjnu
	e/NdhzfK7eDfR0e2ysDI4EIi1ViF/W5KZzJ26NUJWgrTkkSEdgeYir3j
X-Received: by 2002:a17:90b:57cc:b0:356:2872:9c5d with SMTP id 98e67ed59e1d1-35965cc5651mr14686388a91.24.1772515851742;
        Mon, 02 Mar 2026 21:30:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HnV9Dtu5DVDo+csmNE5vWlE1Yg9IceFhVmWcvMUSveZw=="
Received: by 2002:a17:90a:f518:b0:359:8ce0:e09a with SMTP id
 98e67ed59e1d1-3598ce0e201ls1401427a91.0.-pod-prod-03-us; Mon, 02 Mar 2026
 21:30:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWspj0zAHiwh+uKyyIC3/rPIXvfDlehvfZlYfDwBqI/No1Dc4XIOkbly/fIxjqGw3YnmyuVbWpLIQw=@googlegroups.com
X-Received: by 2002:a17:90b:4c0b:b0:359:8cad:bcdc with SMTP id 98e67ed59e1d1-3598cadbd66mr5487872a91.10.1772515850270;
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515850; cv=none;
        d=google.com; s=arc-20240605;
        b=fTaJdDfEFlT3rLeZzDas2hqch9IlXILMZBabpG2hqyE0nNyBx7XW6SXBjo863D1bpu
         8AdrDOgBOB2XcpnyiaF+Yh3gr1+W9aNy4J7VkiAHDF5MXUUy2hhGzi6s9VtJ889LOmoz
         IWFo8gHlcFgF2fp4zZFJCxPgsHOesYvHVfQV6jB3uyhNceyZj0YBLBPKwzwb/eDvm/dK
         1SO7IOXsERV2LU6is57Dh8rxUhVak/eu1QuzQHy3qs8jKAz217rIp5Q1r3E0o7lpfSVK
         +vPf02gQW9KIYEDpCCtCBBiPQ9Sa5hqxwsolfJ1g0lkJE50T2GHXxw1oTcGRF3CujGm+
         y4UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=QREJ4wnCktEiJbmtweypq7E7ynuce6ZiNb5T+lVSsx0=;
        fh=SdftT8st9Mc1yZfaIFEwgRMwSCuwzBPE+XriZKimrSU=;
        b=ChiIIjdbvOzYmv3+tWGK8VOQ27mguNJaDwR6uMuZzKgqUBm91Gsxx4aRJgZ8204xJH
         loDWv04rqXMrFzCTFPEH3lZzB+HMPOwYKCp1/+LcDKgn1vJN8lf0R0fmIkVwzZv5NKZM
         /ZRlkj1TjdW4C+cctnFwTY3yUvklpweYxkERXS19YXF2pxVgKo7RHveYdHaX5Bc42A53
         w/8BgCTMWyefW2F+KJ70n7KH1hBpJv33k7xLgFpzFgesqDC5ZkNiuLLFjAgRz3HINYzB
         UziMBG+im5dhDhCIzTUekAGFljbBVQKDPgT3ZvAKd9Cv9dPIWCm9B7xjTj5OB52HG351
         KvwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3599bfa4402si40052a91.0.2026.03.02.21.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S5;
	Tue, 03 Mar 2026 13:30:39 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Tue, 03 Mar 2026 13:29:47 +0800
Subject: [PATCH v2 3/5] riscv: mm: Rename new_vmalloc into
 new_valid_map_cpus
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-3-f80d8354d79d@iscas.ac.cn>
References: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
In-Reply-To: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S5
X-Coremail-Antispam: 1UD129KBjvJXoW3AF1rKFWkWw1DWrWxGrW7urg_yoW7Gryfpr
	W7Kwn8K34UZF17Z39Ivw48uF1rW3Wvg3WSk3ZIqw1fCFs8ArW7uF1kZay7XryxGFWUGr48
	Za1SyF4rC34UA37anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmY14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JrWl82xGYIkIc2
	x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq3wAS
	0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2
	IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0
	Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2kIc2
	xKxwCY1x0262kKe7AKxVWUtVW8ZwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWU
	JVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67
	kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY
	6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42
	IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIev
	Ja73UjIFyTuYvjfU55rcDUUUU
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
X-Rspamd-Queue-Id: 75C581E93E0
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
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
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,iscas.ac.cn:mid,iscas.ac.cn:email,mail-pj1-x103e.google.com:rdns,mail-pj1-x103e.google.com:helo]
X-Rspamd-Action: no action

Since this mechanism is now used for the kfence pool, which comes from
the linear mapping and not vmalloc, rename new_vmalloc into
new_valid_map_cpus to avoid misleading readers.

No functional change intended.

Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/cacheflush.h |  6 +++---
 arch/riscv/kernel/entry.S           | 38 ++++++++++++++++++-------------------
 arch/riscv/mm/init.c                |  2 +-
 3 files changed, 23 insertions(+), 23 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index b1a2ac665792..8c7a0ef2635a 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -41,7 +41,7 @@ do {							\
 } while (0)
 
 #ifdef CONFIG_64BIT
-extern u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
+extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
 extern char _end[];
 static inline void mark_new_valid_map(void)
 {
@@ -52,8 +52,8 @@ static inline void mark_new_valid_map(void)
 	 * the only place this can happen is in handle_exception() where
 	 * an sfence.vma is emitted.
 	 */
-	for (i = 0; i < ARRAY_SIZE(new_vmalloc); ++i)
-		new_vmalloc[i] = -1ULL;
+	for (i = 0; i < ARRAY_SIZE(new_valid_map_cpus); ++i)
+		new_valid_map_cpus[i] = -1ULL;
 }
 #define flush_cache_vmap flush_cache_vmap
 static inline void flush_cache_vmap(unsigned long start, unsigned long end)
diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index ced7a2b160ce..9c6acfd09141 100644
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
 
@@ -146,7 +146,7 @@ SYM_CODE_START(handle_exception)
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
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-3-f80d8354d79d%40iscas.ac.cn.
