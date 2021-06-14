Return-Path: <kasan-dev+bncBAABBEMUT2DAMGQE6NLKK4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 334E43A6C80
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:55:47 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id ca13-20020ad4560d0000b029023ebd662003sf9968621qvb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 09:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623689746; cv=pass;
        d=google.com; s=arc-20160816;
        b=d0DPY/c22KruGey4W+q6UvhC8eqNaBIW17jOo9dDzIFygyqew26tg1DnaZUEyFCWVU
         Q3+jN5mjQGeSj+NzvZRJBnFxTQa5W9yFTScEn+1/aKAAiA4kSdrrPvlvBm/htJKOk0Tv
         7kfRtwiunrRAo1qLvG7CRSbzKo+ZdVA624xEqd3eiZ7le/DOXuszoVIFm7/wfoSbRuvJ
         Z2fxscps/uuyMGf2wBH1NsJ0uyMxQg2nAsdk9UX71oeCu9neRNiUuLmks857fnA5PVaQ
         k3gsnQ0BxAMg9bX1Ai0nE9ry0qyaywPd2/almIlp21zfPaY3G6rPWcw0744WDgeo1mnI
         yOOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=2PYMMnZKdabvzMb96FZmUsSZ5HuGMelmmqRJzbX8Ors=;
        b=a5wiVFZu6rFN2nbMIYZTPLZfwp9KmYxCBYm8PM9Y7CZJL0ktYAEBIvGCAoD0ZHgNq+
         RUvH57YyE08DrAbwQnMq4fVqiDiS5hH60v7lSn+Oiz57FYCMtmSTXaziNtZ7tu5vWllq
         0+NNNPloJ7yoP7ZhXvPgF+nh3vGjvzEqREH/+YhxDKeSVi/fpxORHjBVR+hF/9DAQNY1
         QGXfPfaGfDcUDQxvjrNgG+yEoPLvHkupQxGze21xT9ROcNcaXSVjY5lXfeGIV2PvXiDp
         sNo7I4AzImF2Cxmseu0+msf2Kdg99cezy/rNgbqJcn6eyb0Fc5QRVYpSmAVzyNsFfKKq
         SECg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=wWznm3uO;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2PYMMnZKdabvzMb96FZmUsSZ5HuGMelmmqRJzbX8Ors=;
        b=U0KsTPEBncrS1iOA+00hsLk54eT5MoUayI/itZcaa+PJLWvXSc4WoPECLEAeI2URFN
         snN/G1SzhC2YdgZqbQA2wEHT3jCjtQl/AFbBwVP6YkoJEQpZcSFxYBOlKZbeoj0M0fWK
         UinkH+a1W3ADi2xLUOT9xsBji1yeyy9Vnj3K3l/VkirWRbr/70eE2bL84LZPwRNEroUR
         6TbNgnG64fbA0SI3XmXl43/bcu0S58SShp8kQcCNxcpWT7VztRQL5HseHSNTi9csYyut
         dvWj8nfjcOxoj/lb+UdF8euw5ad0T6SktBFb3V7krOR2TXMn1zsqLMRuy5VZlX4CeGMA
         /PTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2PYMMnZKdabvzMb96FZmUsSZ5HuGMelmmqRJzbX8Ors=;
        b=IzkNcYfwLp+QI81KIoFteVEs7nL12mI4aJSl6rR745uUlPXmLKQRcxoyXM3j4lXJo8
         Aai7NQkyn7fQ1XCxwTTLhh4jMx0CDP9qYSbgc4ZMavr25nyoPO8DNgjb55WAfsOB7yOQ
         KjRQ7hIeN1LIHOAVupPCBLHkCY3735ybjeShZIlONfzGIkfhGNCAatsyrYG/n9CH5QBK
         QmeU+LpkbIgzeDR9AhyNfjfF1OZTaBWBRUv7B/EK9fJU++KaQpQgv0r/QAdahMKW+2Ml
         o/PZs4W38+XEMbwJJGfP5Mq28c6l2N8+nZo1z1xA+wsC1CE4itIRs1t3w8jPAnMNwlye
         LxDA==
X-Gm-Message-State: AOAM53382hI5qTMEvOyVIw87twvtPrIVwlrOORTaiXE1RGGT+RnjpTIi
	23tCOtiZm80oxF+RvyXEQ3g=
X-Google-Smtp-Source: ABdhPJztEzXqtB3hZth3wxbhkhAHqpKeVOy6A5FV5KRfUQxNk1olAMCxx9EX+ZU/Vs9E5CowY5v9ew==
X-Received: by 2002:aed:2162:: with SMTP id 89mr17676488qtc.182.1623689745949;
        Mon, 14 Jun 2021 09:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4553:: with SMTP id s80ls4121005qka.2.gmail; Mon, 14 Jun
 2021 09:55:45 -0700 (PDT)
X-Received: by 2002:a37:6002:: with SMTP id u2mr14962469qkb.1.1623689745552;
        Mon, 14 Jun 2021 09:55:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623689745; cv=none;
        d=google.com; s=arc-20160816;
        b=wljLa93ih5e4NGT5WMx1g2aw/TQWDXi6GoFWqZHIPZ6mKRrzkyHZ5o2T4NkC4IR+ne
         cDVpyR18S+t683pRscv2wbGgBbgZ76ing86mbsPukRP6+9dahdSNGvfnN0MLJB3uxkjP
         7CU+Hzn4GI4/0acBPHx/CE4XMGa7rcX29pWSzRZiI/gHFpWKzWZgkB9ytt7Cnuz/J0Mt
         SUoSlgORGK7CdSRVV2tyEWz2YL9dT/UYIiLv44cC0/zASQZyP/0PjLlS0yYIB2ctZWTq
         m9/y03DqKc1nqw62oULl3vK2pSjef2qJ6MBe6nPXrqAhnNQeV6f9dI1mrsP2xbFIQ60u
         42wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cTQGzuLTNvXEGjTEb/xgHNPQ2J7ygTLFE8lIngQ6Kvo=;
        b=K9aRkx3gNlhZPM2QdvUTCmMnuK/rf8VfDsBlvqLrnOQpQ6PCAWs0Fdx/Ild2vKJMIX
         AJ3kpEaSjuo0aSopPRUDwaQj8Cvlk8Uyxz3UUf6BNQML5szMSctgHLh//mMlIqSsL5QP
         zB2T0XCwa6N6pAc6XeCIA4+LnIL121RBusB09RkTEUqvqlbW9zJgwZ0UA/eeVjkmIDI8
         Ss31lmaVHLNMs5CxgRYoYe4eVvLKVIy2Bkmve45qNexwvkeSU0CkW7Uf5eeXQ8KSjERS
         5sIG1+CrpaWuDKliTiUKAqJbAyUxEL2rdeJRpGEsTaKFJOURMcwPHMXTxcSJZc5Ux3+U
         dcRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=wWznm3uO;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id m9si26025qtn.5.2021.06.14.09.55.43
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Jun 2021 09:55:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDHz8PpicdgdkfbAA--.3750S2;
	Tue, 15 Jun 2021 00:55:05 +0800 (CST)
Date: Tue, 15 Jun 2021 00:49:27 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andreas Schwab <schwab@linux-m68k.org>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>,
 Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann
 <daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>, Martin KaFai
 Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
Message-ID: <20210615004928.2d27d2ac@xhacker>
In-Reply-To: <87im2hsfvm.fsf@igel.home>
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker>
	<87o8ccqypw.fsf@igel.home>
	<20210612002334.6af72545@xhacker>
	<87bl8cqrpv.fsf@igel.home>
	<20210614010546.7a0d5584@xhacker>
	<87im2hsfvm.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDHz8PpicdgdkfbAA--.3750S2
X-Coremail-Antispam: 1UD129KBjvJXoWxury3Cr1DGrWxGr4DZF4DCFg_yoWrGr4kpF
	15tr13GrW8Jry7XFy8Zry5Ar1UJw15A3W3JrnrJr15X3W7G3WDZr10qFW7ur1DXF4xJ3W7
	Kr4DXr48Kr4UAaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkGb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwV
	C2z280aVCY1x0267AKxVW8Jr0_Cr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJV
	W8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r
	4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWrZr1j6s0DMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07b5sjbUUU
	UU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=wWznm3uO;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
breaks booting with one kind of config file, I reproduced a kernel panic
with the config:

[    0.138553] Unable to handle kernel paging request at virtual address ffffffff81201220
[    0.139159] Oops [#1]
[    0.139303] Modules linked in:
[    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default+ #1
[    0.139934] Hardware name: riscv-virtio,qemu (DT)
[    0.140193] epc : __memset+0xc4/0xfc
[    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
[    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffffffe001647da0
[    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffffffff81201158
[    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffffffe001647dd0
[    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 0000000000000000
[    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 0000000000000064
[    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffffffffffffffff
[    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffffffff81135088
[    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffffffff80800438
[    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffffffff806000ac
[    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 0000000000000000
[    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
[    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cause: 000000000000000f
[    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
[    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/0x60
[    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
[    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
[    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
[    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
[    0.145124] ---[ end trace f1e9643daa46d591 ]---

After some investigation, I think I found the root cause: commit
2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
BPF JIT region after the kernel:

The &_end is unlikely aligned with PMD size, so the front bpf jit
region sits with part of kernel .data section in one PMD size mapping.
But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
called to make the first bpf jit prog ROX, we will make part of kernel
.data section RO too, so when we write to, for example memset the
.data section, MMU will trigger a store page fault.

To fix the issue, we need to ensure the BPF JIT region is PMD size
aligned. This patch acchieve this goal by restoring the BPF JIT region
to original position, I.E the 128MB before kernel .text section.

Reported-by: Andreas Schwab <schwab@linux-m68k.org>
Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/pgtable.h | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 9469f464e71a..380cd3a7e548 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -30,9 +30,8 @@
 
 #define BPF_JIT_REGION_SIZE	(SZ_128M)
 #ifdef CONFIG_64BIT
-/* KASLR should leave at least 128MB for BPF after the kernel */
-#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
-#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
+#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
+#define BPF_JIT_REGION_END	(MODULES_END)
 #else
 #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
 #define BPF_JIT_REGION_END	(VMALLOC_END)
-- 
2.32.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615004928.2d27d2ac%40xhacker.
