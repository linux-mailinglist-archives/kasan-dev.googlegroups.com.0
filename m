Return-Path: <kasan-dev+bncBCM3NNW3WAKBBRXISPGQMGQE6T6LZAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KCgALUj0pGmcwgUAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBRXISPGQMGQE6T6LZAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:22:00 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 52F071D272B
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:22:00 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-899f474fae1sf84477736d6.0
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 18:22:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772418119; cv=pass;
        d=google.com; s=arc-20240605;
        b=gwoM9uvMKFPVyaIHTLZ5Vzr0lsvVfKRDIxso9Urs8Tu7PrnhSYbU0rqodg5WisYrTM
         0P1cQ75WbZAf1Ny7i+R3RgfwYKxSFjATexqf2ESz+tGdBUZ4R4nAgBPiUNzpPySmKFdm
         ZeHd22e+UT9Zm7HZY2yYe8ROmJK1Zf6zaHe7IviXb1mRwG5IgdEGv7n9rotFU518skMr
         1CObR3S8mQiEU8MEoZ3ygGOGvyTBkFBQXUHna1Vf65Nitf45NvuA0H7D+ZH7SSIbUPFX
         nwUsgP94waML9WH9K71WCRFC+I1wrFDYI9I24JE4sEH2IcZd6gEQCYvHMQ9V6K4X+rP0
         Yvqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=PInpZ+/rvEglt/qD4/oo68NTzNpjXLKSgtThc9/laIE=;
        fh=BtL/tVJDi/1nOz+uOIloFA9t/lo9Rec35+ZP46XwnBw=;
        b=UM6568V5pfiogFOR1fGvuX+PLC/BH0DUk3kz7m6r5HmYv2gpYG0NDsIWCmFbWh66vr
         uPSHzEfUKNh/hiJJswLENjkLRP9rY1gBSt5U5DUKkNn9CQyLIr5Cf6xe/i5peRGpLFa0
         BMcogfO5JM1iXCHOWaM5rIL9zt+nED0NN9JdfC8XXGXgocy93s0A3mNsXw5ArDMmiV3m
         1o66RGeSi5fkKV2at/lhM+1TLqnuHSSuLRXSvYV6YnsrS3ocI1oFkvW1Y4rvq/vo8JFT
         mvah4womA1vozlNYu/njzG8pymonuIAwLFOKdiXQ+DT0aBKIva9FZuBXWCNI59U7A1dS
         tYxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772418119; x=1773022919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PInpZ+/rvEglt/qD4/oo68NTzNpjXLKSgtThc9/laIE=;
        b=NSqVoNrDf1wH229YzC9fZ2Grb/MpkTwza8rnCJyf0egjmRh6K1TlvrZpDDiRS41lzq
         +Xf7h0mtjRZ5/WSLYFo5yBNABhEDvYQJ3QdZVwkmC6VCwJDK3ucLSw5YOUCQhdpvskYw
         YB4VxD+KGWYf9g1/YwE8w8KjXJUdo9t8l9bRexebqY7v7BIOvp6J9nLh35PdudNc8mJg
         waDSO3G4em4fxwbjdBWLBUEN3ipVz/QXfkBTk+uc/Pfz8RF7/8YHRVYhgbFX414r0Lqc
         1FEmmg+sriQhFkrg6wNx2S7Z70LPwpVUBlHmQeVpxplpATPRW7D9hJzLwkwAn0/L/CjN
         bh9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772418119; x=1773022919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PInpZ+/rvEglt/qD4/oo68NTzNpjXLKSgtThc9/laIE=;
        b=oByPuT/HpjLA5QfFgd42PzJs6N026GgbHVrml0goUznX9i/KTk3VU42vJhPhtTXaw/
         URrCGLew7Dy8qndsqN/u4U0BA8u0cQbpSkrbQnv3fQdU2/c0qYPEsy07NcDeam3vWnsV
         OuSOvFgg7y6h/fSuR8oFl86+9gfkC7WGEqJ0exBA8wEunZvrbAsRyfjMoWgWu01m2+QA
         cVBu2HDT58HMCF9da6LSTMFLXE3FqEKnlgeQXjpGv475bPll5XxBUJ02HoAQbkgbbc81
         4UTXu+DrNpoxVz95JQiXZ5LdbI9LQr9+YGHziOt25+IFsaVlJiKgRNry4uRhpf0GF1Zj
         Z+SQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXHF6dXDOOCEwXXN0SdYVSS81vohzHRnvBeNGkMDPABKjmhn7J2Eydfi6dmEsHXJSPvcxspuA==@lfdr.de
X-Gm-Message-State: AOJu0YyWB6DxF0ra/ePWQTRCEiHCsMVjXV7078HsLlxFvMBA5DGw2ADr
	6P2rJ9/cPNqgzws1eN3oZBx6E76W4SMavWjH1l3w2LTdVRjJ9+aDbMOs
X-Received: by 2002:ad4:5ca7:0:b0:899:ee4e:3c33 with SMTP id 6a1803df08f44-899ee4e3d89mr63591896d6.8.1772418118938;
        Sun, 01 Mar 2026 18:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FKd5cneDEu+sDHvXLfDv2QTl0z4BzsdhMyyctgPxts9Q=="
Received: by 2002:a05:6214:3f8e:b0:880:5222:360 with SMTP id
 6a1803df08f44-899a4b8fdf5ls71303756d6.1.-pod-prod-00-us-canary; Sun, 01 Mar
 2026 18:21:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbfX2kgmMmcttlCJyc2h9bgchtQb1l2W8KHEZPLatBfdA9CUbsedjFOjygxcdtu+aD+6lbRXuCDT0=@googlegroups.com
X-Received: by 2002:a05:6102:e13:b0:5f9:39a6:3c13 with SMTP id ada2fe7eead31-5ff1cfc9d0amr8014912137.19.1772418118030;
        Sun, 01 Mar 2026 18:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772418118; cv=none;
        d=google.com; s=arc-20240605;
        b=BBqWYYI8dNhQX9CaBsdt/Xuw32s+6rXQUk4eOeq+ykbNML+Jv2udbhOoq/BFiGpIfc
         6aQABWq73FYXYHk9pU9xn3E+xSOWqZkRHItdsb1peyb1PsfGJ/RLcEMjhxFtf+Hjt0zD
         qrM1axC6iL3Ags7WXwtlKRs0YHwqYV4mtUCKvxyCAF5EkfBQFu/WXux7XSHsW8QfOBX6
         Jx6QbTAMB7UzCpf73bnJG/BU8+rFRn2636QJmZgzRIeGyvOQ8jRGwbHlq0YSC6uN7zO9
         va8TtIGvm6KdcLAbZ4ELQut+rAnEaUg2UNaJGrrndll2jDtrfQ52V2s9OOEtzF5Gf2rZ
         DiHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=20rp8OS6sG1awc2wQyYAPM47HIoixtk7KamMG8dLzJA=;
        fh=uMI99yOLuoR/AuBuQTNjcfXiw7ZlvQdvsBzYrpZkss0=;
        b=N9hQWF5rPB9cdpWBMnUW8xdM/2XxBw3cVcs36gpDo8LI/5V/SOXPIZJYv/1/AyBY/g
         6XmERs3Z5A3yVHBpKB6YEBF5aKpXSRUD0G79f2jzOSJFo0Btfj00uRnjaoz7u7bllKcw
         loaGHaEu63bHb3R8++T9BbiK55HjRCFqjyY9WUZvaxnaWbe1ZayzCm+8sGoSW1BWpJJx
         PIEG/5/qfBj42LaQfOJluk1A8TJH39hY1/Y73cTloR+DIVhBwBXdYMiRpojt4cbOM0qW
         8iT6h9wMX6zrqtx89W32iy4N/F7KO3NjqaleRMEL1yy65Rbp4v5R6zMiGmphl6qwG08S
         ZHYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94df658936asi396350241.3.2026.03.01.18.21.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2026 18:21:55 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAD3E9s39KRp6CWmCQ--.11902S5;
	Mon, 02 Mar 2026 10:21:44 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Mon, 02 Mar 2026 10:21:32 +0800
Subject: [PATCH 3/3] riscv: kfence: Call mark_new_valid_map() for
 kfence_unprotect()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260302-handle-kfence-protect-spurious-fault-v1-3-25c82c879d9c@iscas.ac.cn>
References: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
In-Reply-To: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 stable@vger.kernel.org, Yanko Kaneti <yaneti@declera.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAD3E9s39KRp6CWmCQ--.11902S5
X-Coremail-Antispam: 1UD129KBjvJXoWxCw1kXw45Wrykur4DJr1xuFg_yoW5XrW7pF
	srCr1FgrZ5ur4xXrW7Aw1j9a1UWws5W34rKa4vka4rZwsIqr4jq34DK3yFqr9rJFZYgay0
	kF45ur1YkF1UAw7anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmE14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JrWl82xGYIkIc2
	x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq3wAS
	0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2
	IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0
	Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2kIc2
	xKxwCY1x0262kKe7AKxVWUtVW8ZwCY02Avz4vE14v_Gr1l42xK82IYc2Ij64vIr41l4I8I
	3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxV
	WUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAF
	wI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26F4j6r4UJwCI42IY6xAIw20EY4v20x
	vaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8
	JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7VUbvD7DUUUUU==
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
	RCPT_COUNT_TWELVE(0.00)[14];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBRXISPGQMGQE6T6LZAI];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[iscas.ac.cn:mid,iscas.ac.cn:email,googlegroups.com:email,googlegroups.com:dkim,declera.com:email]
X-Rspamd-Queue-Id: 52F071D272B
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
index e57a0f550860..9c6acfd09141 100644
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
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260302-handle-kfence-protect-spurious-fault-v1-3-25c82c879d9c%40iscas.ac.cn.
