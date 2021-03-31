Return-Path: <kasan-dev+bncBAABB76GSKBQMGQEO7PYOUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D9C35047B
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:29:52 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id b141sf876663vka.23
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:29:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208191; cv=pass;
        d=google.com; s=arc-20160816;
        b=fd/KgN6ULeET20+QsWrS+tz/DLl1ZAQb7e7Brw9RqOBfDmy3ORNTaL0ljQhrn0WOh5
         PabkNjfpzqmADlQs1iEPq1OrNPrkLqGfOL7hxk/lXTV+NqolOvaQaE0XeVb9stoCaM9j
         A2rWsMiLV9h+neRtYU/NxGNRHuwRhx5Phdb8wvisMqZ4zgPOfS1j6ljVjDaS80hzuDOf
         aWZCsGrPd6XtCDsoKFZLJG2w+fapBg7qGXVmYGw3jODFK8pqam9YwqCC19I/L8LCXVUE
         Q1/3gbdguOM8LSK2xlctXwZyk7fb7CEOa+aJ+LlHKw0lN49Xf2JwYRuIfjDCzcEc4gIe
         OncA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=O+4XLFEsF0Nt6l6N0WingzuaXY5ax2EUKnJyexX5Rr4=;
        b=SjfqJBhrNrPXrpVZSctT0Ha4SIGD80uTIvXelt9uhxJYbnlY3rxz+Y3VS3d1oxWfsA
         z+JIqPWRv7rdmbBHbZjZPrU1f7a8fpYPMFYITVEguJdJnJ+Dhtf+oKacGFpHZDdq/NuY
         T1irzuXkpHQk2piev3kUMyXtPB4kyPqmFInkXzRnEurlTLKiZHo/OU+OXBGZVMif3b01
         lEnpKt169l0Q7ZpS6gN2RgxrTgsk13D91q1MZ6ShMh4gI9ycnrO0j2HAnPrb2Dh2cQyv
         0ORLOTy6Gb0AA5O4+E941ku1LpOGhjbdzDG4gXiufDU6ZuFt8QaPCya+vfU8zHVlPCMa
         4oZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=R4LfprXF;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=O+4XLFEsF0Nt6l6N0WingzuaXY5ax2EUKnJyexX5Rr4=;
        b=ky0FlkYgIBdJMg0xrLW5169GR2ZHwJBFyRt3Ug0Yw/Z919JzrCOjPGDPoJUwwbSfSA
         oXTXZWjezfDjaFDtZU6kvnS0jpaD/PBjnNo5TxFbmlzl22g/flY1N21t+a6AKvmdKngb
         nLbdnX8olq/G8DTg096Q90pVUHWpAABrHt+KUVMOM9m2DlGL2hryQcXgBZUOI+kYvf3d
         Gcvfc1/p3x1OCGF1O1/Det27xEoTzcuzP3BbjQ/snSI9rWCqOVaBilg1qfBRnrInwYGU
         K5KZTiV9cX1trPO2NcpoIs/1jyJUgcY4aGLr/N5MpEseZCMXadS6brHMVRBEkCTRr7Ah
         yYDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=O+4XLFEsF0Nt6l6N0WingzuaXY5ax2EUKnJyexX5Rr4=;
        b=sntk6oihV7f6l3nj+VexNdrd/DSPFHv21T4B093AITO1w0LsBwW4DYYHp3Z3XzX5rV
         lSpYnnrr2XkYOTNyTxu8iInxAhmN9bIn21OjpOvSixtgJ6mrRs4A9ZmRwRV9zw3rzTU9
         ovYvJvFTHnITXjLgqVoqeNut8TCSY6Ebr0Hnya++OP8YeU8HCBl5JCkjDAH9QyAkWLzY
         W0zdo0X8uWUjs4i2aA+v9e20bXSEZTw1YecH7qp/f0SjSHDO9F30dowaE1AE19m5Kckc
         lky1mRt99gbe/hdD32PoW2oJlkEeAM0DIbrr/hdmnSalzbDytaG6XbjWdBbQbGSoOg+Q
         IdTg==
X-Gm-Message-State: AOAM5307h/FicOOus/aff2pJHe2/JQMC7cYEMF1eib9lBAZGyU1zrrqB
	Moq+3D1cSAN1+wqsxO5mSxw=
X-Google-Smtp-Source: ABdhPJxZgabRQyePrKMpmd1UBcB4F/d5vQHHQsgdnIXOVTPByknvaOaLCbcULAU6V/nbrUWFR06O0A==
X-Received: by 2002:a9f:238b:: with SMTP id 11mr2134513uao.45.1617208191478;
        Wed, 31 Mar 2021 09:29:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e19a:: with SMTP id e26ls322770vsl.7.gmail; Wed, 31 Mar
 2021 09:29:51 -0700 (PDT)
X-Received: by 2002:a67:314e:: with SMTP id x75mr2237952vsx.52.1617208190985;
        Wed, 31 Mar 2021 09:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208190; cv=none;
        d=google.com; s=arc-20160816;
        b=rPzSIFYy/zqD5pjZoPFLMxJbdDBWUDr6wq1QqCg+90paUiCT+if7XhJp+539H08r8B
         rdJfTEAEqrelpS68gF902mC87ycZZ6JkbaroY1ZCsKCUYMmeRov8i6uvh8Zxajn43ND7
         4WVOAkxn7lGjVpy9YsEJHi4f/u6xXgSeBJ0921+veuuuBdhrO787IE8HclmGifmdaggV
         xkPxPPpWbTXgcJOh9+co0BCFEJOUkRKAYQFX+6MRJ05W+Trpp3xuW9b5t0AncWjdmf1f
         ESKO6CaX/gKQFZQzxXimBCyxXXxMT0YFHpIqV8Kf7O4dE3g4N94zLQzF4BAsM3qGjerF
         WIFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=Z3YZthlfu0euTQ+THZUZPW+nmkMWZoVGbwK6weVz8AM=;
        b=hX89v1z2qNx/CviB/loAn1XaOk9Ds5b7XFKHnLkimA1DYdiVx747dOBf1GMMHN3V6w
         XKzMwdqlJ2o1itM2aCfIrhi0htixhxOBQ4jl9ViWCVCm+Hoac0wJs3rTP+h3oWkRrC2x
         ulSoPL2hoMCUFH7M/FzVbanNv/aZevRaF2pj7sw98GVFlVWZSPaabsbM8OkgfiT8XkUa
         kU9rWiuMyP0aA6TByfyLkMe/JJPQt+TscB5xDP2yvxj4NN0McJJjcZdrOPtA8cUb8tlx
         nHr1Xdc8COdX260O8MWndSfLgON03zpLlO1Ybvt5JFRMO6nMiV0pQdqMV9rtsu+Yu5Ej
         5b6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=R4LfprXF;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id m33si180211vkf.3.2021.03.31.09.29.47
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:29:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDX30tzo2RgObt6AA--.16468S2;
	Thu, 01 Apr 2021 00:29:39 +0800 (CST)
Date: Thu, 1 Apr 2021 00:24:42 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt 
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin 
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey 
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, " 
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov 
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko 
 <andrii@kernel.org>, Song Liu  <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend  <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson  <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2 0/9] riscv: improve self-protection
Message-ID: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDX30tzo2RgObt6AA--.16468S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxKrykur15Xw4rZrW5Jrb_yoW8WFy7pr
	s0kry5ZrWF9r93C3Way34kur1rJwsYg34agr45C34rJw4aqFWUAwnYqwn0qr1DXFy0gFnY
	kF15u34Ykw18Z37anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkCb7Iv0xC_KF4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwCI42IY6xAIw20EY4v20xvaj40_WFyUJVCq3wCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuYvjxU2vPfDU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=R4LfprXF;       spf=pass
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

patch1 is a trivial improvement patch to move some functions to .init
section

Then following patches improve self-protection by:

Marking some variables __ro_after_init
Constifing some variables
Enabling ARCH_HAS_STRICT_MODULE_RWX


Since v1:
  - no need to move bpf_jit_alloc_exec() and bpf_jit_free_exec() to core
    because RV32 uses the default module_alloc() for jit code which also
    meets W^X after patch8
  - fix a build error caused by local debug code clean up

Jisheng Zhang (9):
  riscv: add __init section marker to some functions
  riscv: Mark some global variables __ro_after_init
  riscv: Constify sys_call_table
  riscv: Constify sbi_ipi_ops
  riscv: kprobes: Implement alloc_insn_page()
  riscv: bpf: Write protect JIT code
  riscv: bpf: Avoid breaking W^X on RV64
  riscv: module: Create module allocations without exec permissions
  riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU

 arch/riscv/Kconfig                 |  1 +
 arch/riscv/include/asm/smp.h       |  4 ++--
 arch/riscv/include/asm/syscall.h   |  2 +-
 arch/riscv/kernel/module.c         | 10 ++++++++--
 arch/riscv/kernel/probes/kprobes.c |  8 ++++++++
 arch/riscv/kernel/sbi.c            | 10 +++++-----
 arch/riscv/kernel/smp.c            |  6 +++---
 arch/riscv/kernel/syscall_table.c  |  2 +-
 arch/riscv/kernel/time.c           |  2 +-
 arch/riscv/kernel/traps.c          |  2 +-
 arch/riscv/kernel/vdso.c           |  4 ++--
 arch/riscv/mm/init.c               | 12 ++++++------
 arch/riscv/mm/kasan_init.c         |  6 +++---
 arch/riscv/mm/ptdump.c             |  2 +-
 arch/riscv/net/bpf_jit_comp64.c    |  2 +-
 arch/riscv/net/bpf_jit_core.c      |  1 +
 16 files changed, 45 insertions(+), 29 deletions(-)

-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002442.2fe56b88%40xhacker.
