Return-Path: <kasan-dev+bncBAABB76UWKDAMGQEWM3JWKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93AC83ACD49
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 16:15:28 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d12-20020ac8668c0000b0290246e35b30f8sf4780829qtp.21
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 07:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624025727; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sj3PDbXIj/Mo75XiU/X/gb6as4J8BFrjPJED72VW3o9FCMp0+bUz51b1tUhCazKD68
         kNm6m8qCNLqKs3ey2wAc7iG30aBLw7W7pGoGaulx+x0tems228BtkKlOcL5H1Y6Wj0Va
         zwq9Dxu+TvLcsWDdagODO5utuW9ccj3EpwjlveXzvCPSdHrCNsbiHcFtxk+8dkkGPy3R
         6khiz8Q28LjDTkJAsnK3HTw+jvd4bBvLwTm6EuQ7z1BfZJKT+FgVOmI7cl8xn58DTQys
         gRiMXvStPsuUL92yZCjdVo3Nbk5o3MqSSQloEMB0nZy+aspkjDVBeVa/jHwyTCpDMDaC
         VCNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=I2QBleMm1hIdhDTt5Ek3Xb5/tVSi8SEeU3+u7ayEFvs=;
        b=FqBJ5vh14ob3y7ljxdB3xPd+Rs+Uk2c0kC99PLbRgEFWglcotw8MaMzHaGpEjBGXoo
         7OFIZSsgefYXsBBhv3RmlXXyalQQ/hN0L0V9jre9xCGKJ+llpgw+WVCAbbSvvTd6bS9/
         Zfa98BR6wgpeYfRs5KBDtWL8Qf04C+C/s5GJbHWhRs2IOp+jrOvbPa3+XzIMpoRnsBc4
         TGKMffiQoeKqPyEnB4CPz7W0fy1pg5bQBl1s9zl72lSolM3KG+Fq4t+jD+Qn5UK1xHPl
         Wa8cVdzpvg+FUar3ARb24pvSC8rj/QHyDMdOGnLcRNEE+GoacTIR6JnhvbaUf7UPoxOx
         CFAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=s7whCFqb;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=I2QBleMm1hIdhDTt5Ek3Xb5/tVSi8SEeU3+u7ayEFvs=;
        b=BRtreNQUS9EaYfLS8RtfQ/66+dC2vbXkjpKZMuyIzOMYa+3gFaLaeQrD+U81LquUIA
         /BM3Gz8CaU0XWtHN6mzv4wtx6tH3GpWw2Q578A1b1CJ6swS7kph5YVKdnpW0Rnez7h17
         B2tP6x4x1xDmpsGO38vPZ6mDhGQ+wJnJHQs/9BlPQ2PejbIgk9nIxqDLq7gHo/DZCc5S
         dGwQsb8wOqbQ+g2anbFm9L4xXCjD2lkp9WwfAoyRC/RkQaAeZCnu750x7QeF/LcnKB2R
         Ej6MRgNUZD8yq76WdnIRMwN5JA6q0mmPefxw3F/4TJxeiEQgTpkP0KzKRcgxtP+0tZov
         x4Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I2QBleMm1hIdhDTt5Ek3Xb5/tVSi8SEeU3+u7ayEFvs=;
        b=fKhtdd6upRgSr7F0WWqbsWTineId4noZAu2yXehyHXv0DtrMnN5wkod4TpDR1ljiuJ
         8FjQM5EPGQtJHj289tFVZD+v4ESqcsrddsjKl2LkbEGXZBKMhe26vhRcH9V/KOlzd/+u
         VvVAVVcSCBvTQO0hKEP8ZsyjDV3teFE/WBC6U8paQFbmAjR6UW6t729VtrhurzA/wW1C
         hUz+DQ/fOGp9A2yP4kzkMYrXSUe6RQuRbpaf4YTYnAXAzgJc8vOSzlwaIedG+Yd8SHbM
         ok1O3g699LRmGL9e9V7KQoN+YvkMe476KR0tQzFcUDtWlcdEZvcTHcTFXfUhUf00zLHJ
         wdkg==
X-Gm-Message-State: AOAM532sYt0KyYGDy1oAhEeMyISbJshpdNjsAV3IpdMUNAbv0KBkrS0b
	IrwNPalzn2W8I17UAMgU3hI=
X-Google-Smtp-Source: ABdhPJzmW3wdWURNXQYfB2x9AlU16l29FiT7zfXlFLZ/ZVzpR1sSsTeRRurCKBPGoakJiacRdUPpEw==
X-Received: by 2002:a25:b701:: with SMTP id t1mr12959496ybj.517.1624025727675;
        Fri, 18 Jun 2021 07:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2b08:: with SMTP id r8ls5242877ybr.9.gmail; Fri, 18 Jun
 2021 07:15:27 -0700 (PDT)
X-Received: by 2002:a25:8093:: with SMTP id n19mr14428351ybk.414.1624025727173;
        Fri, 18 Jun 2021 07:15:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624025727; cv=none;
        d=google.com; s=arc-20160816;
        b=q9m760W5Mg30BxRUXGJUpSR6jdnYLwvunaoBJeGRZpp134m9GCsKMoURkzk9HN+vq/
         sHSQGkGmfbVPeqai/P0/J6Pu2356eYPOysQoOKOophbVvDouZ0WTlIT8WehmD8/Ht/u/
         b46aSve4ggQFfq3FxXay7a+uMC0zm+K5xKy73tDSX6yYYMNZJ/6x0EgaDF6HjMRglt2P
         oZXFISJ27Hp16pbZixcVdZ/W75YCj2oxpSKKGFAgHW+1I9XZzyoT7HrM9hH9mFz5E+pl
         kW0gWZ0OsJjzxFgHPDRc7L5OnDrEUDCnT+T1Us9w40S5htes+5wrA6M0etYNFP6UN2Vr
         Ec4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=R5rGWfYjWzannEPfCFi17k2rcSwUm8SqL8TNYdn/BEM=;
        b=TrfBBkHkHSUQcikpDIJdQeoNd9uurH9joRmdF9+q4hgBqrsCt9BKZENf4M/mFxwqle
         l37nU094c4kxFXqB/GLTq5K1c4fkei3kxC+hWVfE3QYfnTFwHBh/UgQNJmtNuRbEJOBJ
         QAP14sZbyAnI70+OtUfjIS6/gettgbsAhOulEWyrnl1eFeUNpTBFyixe0nmdQ9EPWX6M
         oKRDXTXba4I64ZsKd+kIOS1FKal6Hw6IuYnJuv8x1DEwleiEQnoEZV4hiMIIzz5eAh0O
         EuB/G5tWthbO/vVMlMtznAilHRjQboOMC0awUAZS8xSrAMvPlFtANuRREtpzrzbGwe5b
         Dbww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=s7whCFqb;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id c8si246768ybl.3.2021.06.18.07.15.25
        for <kasan-dev@googlegroups.com>;
        Fri, 18 Jun 2021 07:15:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygAHk6BXqsxgBAv_AA--.19232S2;
	Fri, 18 Jun 2021 22:14:48 +0800 (CST)
Date: Fri, 18 Jun 2021 22:09:13 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Alexei
 Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song
 Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Alexandre Ghiti
 <alex@ghiti.fr>, Andreas Schwab <schwab@linux-m68k.org>
Cc: linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v3] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
Message-ID: <20210618220913.6fde1957@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygAHk6BXqsxgBAv_AA--.19232S2
X-Coremail-Antispam: 1UD129KBjvJXoW3AFy3GrWDWF1xCw4UAr4fKrg_yoW7Zw1xpr
	45Jr1xGrW8JryUXw18Ary5Cr1UA3WUC3W3JrnxJr15XFyUGF1UAr1UtFW3Xr1DXF4rJ3W7
	tr1DGrWUtr1UAw7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkGb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwV
	C2z280aVCY1x0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC
	0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Jr0_Gr
	1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY04v7
	MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr
	0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0E
	wIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVW8JV
	WxJwCI42IY6xAIw20EY4v20xvaj40_Wr1j6rW3Jr1lIxAIcVC2z280aVAFwI0_Jr0_Gr1l
	IxAIcVC2z280aVCY1x0267AKxVW8Jr0_Cr1UYxBIdaVFxhVjvjDU0xZFpf9x07b0NVkUUU
	UU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=s7whCFqb;       spf=pass
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

| #define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)

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

Fixes: fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
Reported-by: Andreas Schwab <schwab@linux-m68k.org>
Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
Since v2:
 - Split the local vars rename modification into another patch per Alexandre
   suggestion
 - Add Fixes tag

Since v1:
 - Fix early boot hang when kasan is enabled
 - Update Documentation/riscv/vm-layout.rst

 Documentation/riscv/vm-layout.rst | 4 ++--
 arch/riscv/include/asm/pgtable.h  | 5 ++---
 arch/riscv/mm/kasan_init.c        | 2 +-
 3 files changed, 5 insertions(+), 6 deletions(-)

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
index 9daacae93e33..55c113345460 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210618220913.6fde1957%40xhacker.
