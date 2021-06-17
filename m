Return-Path: <kasan-dev+bncBAABBWVFV2DAMGQEC6DWNIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id F034C3ABB5A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 20:22:19 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id x2-20020a17090ab002b029016e8b858193sf4500130pjq.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:22:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623954138; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyDnkHzxdmAu+k0nGkuykEvGi7JfxVToPrGZ1bSvUN7UjMBy5yBt6GS7GThoeV7ccp
         868u0PFHoEAfsFy+zeZQ8Tsigy1NFNrxjPSPQtLie37hLRyQ5eVRoiFXthtEwaf0gva6
         y0fRtaQcAVGtHvELLLe+UR3U5NWp3WPGblkjzApoNghWLF2VsAtFXrL9fG89rLjU9lwP
         5DYjgZT8iCR8nUEeeCu/FBtmwiBMIFRT/zct1SzYLRbr10xdTzv44rvNE/Pv9Q+tWx+E
         jy7z930WCbKr5Xo1qRf7O5gdkx3gCsbbAe0oj4Ae5BT//5P5Jk5ShticcOnWYJxjeHpg
         Ngiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=i/OwVAHRn+I6g77NWBchVhaEb0/bbuKw+OeAkvb65Xo=;
        b=F9u+KfVR7h38IXM4ZLCpc8zEnyklAuirZG1rZCqLYLM570RFXFyDnFxueaP6Liv7Rr
         XTSHAZ0szkw6gEXePf4xcLX977SKEC5Dap5yJVCppFYD2UrTJa0CD7GShGtyyBXYerFg
         1Y7FYOLWERAle+Fqf12Y/Nmf3BWSfDryB926upPJhHN4qjMV+g1rgiI17iE9lHvIcVX/
         JJfvjZjO9zadh05OaOY8MJ4DfWT30ckWE+/pTL0uzWhywISGoJGqXGLnrVopVFtor9Ls
         pFt55ZgFEbf+c56kdCtnZdwxi1DW54SbQYibIptnJ9dl67aoMKmHhNSYrLpyKSw0undU
         o+ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=N6gznjnE;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=i/OwVAHRn+I6g77NWBchVhaEb0/bbuKw+OeAkvb65Xo=;
        b=beryMWBPNEKI1LmqEPLqH1VoSzsBxm1n1XiI6fnqtB6ugU5qsLmJiKxi9hXE0P/STK
         dPAFNMVBBT8j9p/py2RRmD+zKIN9FRMfySKmGkYydh35PHDncU0ikbYSnww39O/E2z6Q
         K8u/HbWYASzUe4Gn+8FqWo894sJEoxaByg4pLm4jd6g/4EYq+/h3LeJo31tbxLm4YWFj
         LDUxmXc+ul+KQlCU6ooQhLPU7HF+6/KNTIcnQ+E/h3Ntw9SNH9hJSwKevo5+dCCsQHw2
         6ZydgEFoVYb11IJJ93aILM0cOCXhic8qG7B0PtY3E8US/ANgplZJ3j+pouNkhf+9qrUo
         EL7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i/OwVAHRn+I6g77NWBchVhaEb0/bbuKw+OeAkvb65Xo=;
        b=DIBV9EOkqUXUyAv92MCRa0HJCh0kbuOuP3vVuCqdhrelqfS7Rnv4aIr9m/++6OzHWB
         ASxrbWvFOuE2nY4I4dwfjYh87PUYl5JXaq2TM29Ts0A/gnPLMdQQOj+ZeaDe+XXTrdsy
         VE34lDOWlWCYrkSWuqrnFRVqm8wXO5Tg0fJBvCp6/VA8n1NbNuadoKElfztPsO5h0/+8
         TGzfAH4A8xevYTjtKrgpLnU7oMUpNVYHmYffgloFrj/gTMNfNzepgZsp8t/Xstzkgre7
         Rv/OAEi5QnNRUDCEKWzil1D53nML+t77DqQHzqAghPPtDvu1fF7QbxCaCwFm+gCVale4
         HuCQ==
X-Gm-Message-State: AOAM533GO9zWUxDG31u8SqiSF/l7OwLRYGdIcfZpdQY8acntMZ4r+Bay
	ApvvjsZT9Pt4A23QGA05ZqQ=
X-Google-Smtp-Source: ABdhPJyM4Tqa8vAbdvDL8aDtOqaf41mikDKYYpaF2/kOxiLWbqu4PRoV9savwFPFuWKfSGzq5ER6pw==
X-Received: by 2002:a17:90b:b03:: with SMTP id bf3mr17983813pjb.47.1623954138690;
        Thu, 17 Jun 2021 11:22:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8410:: with SMTP id j16ls6934714pjn.2.canary-gmail;
 Thu, 17 Jun 2021 11:22:18 -0700 (PDT)
X-Received: by 2002:a17:902:728d:b029:113:23:c65f with SMTP id d13-20020a170902728db02901130023c65fmr1114504pll.23.1623954138236;
        Thu, 17 Jun 2021 11:22:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623954138; cv=none;
        d=google.com; s=arc-20160816;
        b=OFH/njj9VgG1NeiXZdfii5lS6WNjI1UvQrjgEI2w2VJcP4r1TKi8MI6EPoHRGwS+sa
         5Rd3PJVJkAOw4hYYLkedYo5TFUqUYDCa4BfG9I6RXExR0bTXSxFvOJ1svM975zirYP4z
         sm1RML6/FLewqPJuMnY6jarvfZuyxMWc0suOfuvONPzwQ/A5+FXlhAKGq0PIMug9kKAB
         zuA1bjtJvBluLl9M0varUSNliNzn8rPKzWgA5XW7kPJkmMRSLw7cthEdJoARAgpPwuTx
         c6l1comEVXEgz/LL9NG/Uy+VsF42fqsZV0ZNZ5rTpacxfOXjGxGF6db0LkH+AjhsDrK9
         Hfkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=X/NggHltieBlSZghv1lcNzH+L1pnmckyMPSOwkpW5XA=;
        b=pOn6uEBZiw857xn1vdPBldsPLF9Tnrhr5qsdfNWq0DQdMfZ4iFfp3iVD6hz6d9+/PT
         t3obh0z4XD53DQdZomoNGYW3aiQ/wk61dGA2Jw7SDJ35EkfkFx6QLWYw9eTw1fA87VEN
         +vRZNMsEkFWAJPrwGkf9J2JQyqL5HzbYZ8OWimpAIo2r7C+WPtSOEizdLZLtcqyQs4Me
         2EhpCEmQi+jXfwD9S+B97yo4TxWpyJgjfn8+RZFyOmglr0+/KkkKbcjsNcw1cOJwbCw+
         stD0zWyNxqiLo9bG/oXg0KQB45ft0HjHJXjM5tMqc3daS2+u1o5BFgleGkkxcpTzr7b1
         LMYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=N6gznjnE;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id a15si811283pgw.2.2021.06.17.11.22.16
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Jun 2021 11:22:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygD3+YGVkstg3kr3AA--.4612S2;
	Fri, 18 Jun 2021 02:21:10 +0800 (CST)
Date: Fri, 18 Jun 2021 02:15:35 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alex Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
 schwab@linux-m68k.org, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, bjorn@kernel.org, ast@kernel.org,
 andrii@kernel.org, kafai@fb.com, songliubraving@fb.com, yhs@fb.com,
 john.fastabend@gmail.com, kpsingh@kernel.org, luke.r.nels@gmail.com,
 xi.wang@gmail.com
Cc: daniel@iogearbox.net, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
Message-ID: <20210618021535.29099c75@xhacker>
In-Reply-To: <20210618021038.52c2f558@xhacker>
References: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
	<ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
	<50ebc99c-f0a2-b4ea-fc9b-cd93a8324697@ghiti.fr>
	<20210618012731.345657bf@xhacker>
	<20210618014648.1857a62a@xhacker>
	<20210618021038.52c2f558@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygD3+YGVkstg3kr3AA--.4612S2
X-Coremail-Antispam: 1UD129KBjvJXoW3Ww18tFWUCF1xKw45Wr4fAFb_yoW7KF4rpr
	45tr1xGr48JryUX3W8A34Y9r1UA3W7C3W3JrnxJrn8XFyUGr1DJr1UtFW3Zr1DXF4rJ3W2
	yr1DGrWUKr1UAw7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkCb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Cr0_Gr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Zr0_Wr1UMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxUqhvKUU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=N6gznjnE;       spf=pass
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

Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
breaks booting with one kind of defconfig, I reproduced a kernel panic
with the defconfig:

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
to original position, I.E the 128MB before kernel .text section. The
modification to kasan_init.c is inspired by Alexandre.

Reported-by: Andreas Schwab <schwab@linux-m68k.org>
Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---

Since v1:
 - Fix early boot hang when kasan is enabled
 - Update Documentation/riscv/vm-layout.rst

 Documentation/riscv/vm-layout.rst |  4 ++--
 arch/riscv/include/asm/pgtable.h  |  5 ++---
 arch/riscv/mm/kasan_init.c        | 10 +++++-----
 3 files changed, 9 insertions(+), 10 deletions(-)

diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-layout.rst
index 329d32098af4..b7f98930d38d 100644
--- a/Documentation/riscv/vm-layout.rst
+++ b/Documentation/riscv/vm-layout.rst
@@ -58,6 +58,6 @@ RISC-V Linux Kernel SV39
                                                               |
   ____________________________________________________________|____________________________________________________________
                     |            |                  |         |
-   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
-   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BPF
+   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
+   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
   __________________|____________|__________________|_________|____________________________________________________________
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
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 9daacae93e33..d7189c8714a9 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -169,7 +169,7 @@ static void __init kasan_shallow_populate(void *start, void *end)
 
 void __init kasan_init(void)
 {
-	phys_addr_t _start, _end;
+	phys_addr_t p_start, p_end;
 	u64 i;
 
 	/*
@@ -189,9 +189,9 @@ void __init kasan_init(void)
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	/* Populate the linear mapping */
-	for_each_mem_range(i, &_start, &_end) {
-		void *start = (void *)__va(_start);
-		void *end = (void *)__va(_end);
+	for_each_mem_range(i, &p_start, &p_end) {
+		void *start = (void *)__va(p_start);
+		void *end = (void *)__va(p_end);
 
 		if (start >= end)
 			break;
@@ -201,7 +201,7 @@ void __init kasan_init(void)
 
 	/* Populate kernel, BPF, modules mapping */
 	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
-		       kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
+		       kasan_mem_to_shadow((const void *)MODULES_VADDR + SZ_2G));
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
-- 
2.32.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210618021535.29099c75%40xhacker.
