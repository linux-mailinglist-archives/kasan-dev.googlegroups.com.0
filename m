Return-Path: <kasan-dev+bncBAABB45XRCBQMGQET3AO27A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D66C34D704
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:27:00 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id c7sf12793676qka.6
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042419; cv=pass;
        d=google.com; s=arc-20160816;
        b=HRpvUgc9vm3MAEw7Af2AeQhWVZ95DYZjBbUqlF6Xoklt8UutSVxIiSD1UpEX4PQaXc
         99aGohPJmU16VtTieD0Tof6tCI1cj0gJFzhG0tffhJswX9gGhOxmdZeUsXt8fhqXXm1G
         onVbfWAkg6UUtvBMbA34DxDkYtErtok2yDxCY3W4jAMnU935mD3D4uAFjUbacf63VNjy
         mm1dBgisq+quMN69eAp1x4YbdelQv3bDnOviwzUeEktdE+z0LJV4xIuoaL80Lkl+tknu
         hqWbBDojCRn3ufkhhr07hNBA5VsDGoihYjbPgmr4BAf3SxjAymkB/hUIjF2reCo5Kapp
         rU/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KfS9PG+vLZ4LroynM3gv4SNBRleuEdtiB8z0taD7rXo=;
        b=aNnIVV1/8kpq5Ld6SMsdh/7R5spx0JYUWXBmbHjGM4FZScvGKP+D7S5oG195uuOzJb
         ret3zr5IcC00Kr4nrRoWOzRhK0mQZz2Ruxqn9LkYKe5HyOnxPTel9BvSQ3IBfRrHgutF
         XJJGdOhLVWMfXeiHG8Fhgtn3xR8/4siBhaKNZ9YDK83hrvErSufsbHoN1nirjWtELyS9
         nH4EKeAL+ucSO8DMYPwSPi2YCkIj1/WJE21oy0LtMiRJAo4U3ZgenSpnEZ/eSDvqxAy+
         8xUH/dRqMLqaJejL7CxuEwYG1sJL+ZLiGn/F8/Wj+M1JBEcyy9VU1sR9Dm+zpt9jRz/T
         h3/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=PzuqL32U;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KfS9PG+vLZ4LroynM3gv4SNBRleuEdtiB8z0taD7rXo=;
        b=OTyTvQhKpJ03C9zWxLTCPoh7hRYGR3vzIl3NwLdLIm8b5PtUr/OK+4uoFIU3sI84cK
         6L8gnbyeJ/bOXHGO6dNNbNRNpUjkW1PDBJH7kNsjYS/BWzldrKPibQw6BQN/J91AX5DF
         ewEiH2qdnuq9dgLnRr+7tzTYg/i6Gw/iO14bIQqcQPAQ43gvUhOMxiZNz8ENH//stXMD
         VrWqxhMpBqzZxcOBXzy4OYwryivt5QR1At+cnB1+NX8YO4P5hlNJ2oAAXQneU2FMBpHL
         i0Y70R+B3PYHa5dThQHV1YKXVmE4KGpgg5xDaJrM8s9YEH4cLR9w+YU3grosnfyo2QKq
         Qgnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KfS9PG+vLZ4LroynM3gv4SNBRleuEdtiB8z0taD7rXo=;
        b=Jv/r6avzki9BJf3lgchavpMnZjPdWjbokuiIf9U1HUzF6Krr0TvF3xL52oXkN9Fwxs
         FHiLMAlzC9jFWVJd+i3p9TQ0UWYs7XrVEKR9g6jTOUVR35YM2iHlRDSPMvkyVFHzy2bn
         R6bJzs8ye3ivKwM90vJujErhOgefrwn/pW+kCe2gYgq8yAfl80wCBEg7VtX1szaN7cGc
         ukRmUvSZgquEnJWvJqgFy+xzuD0ExXZ4KAwZnWJ8RVWfLw8UXKyRLzmUuhmM/9klgDzV
         p6APDTA7KabYJRV9NguvXu7A+iQ54I2CGLz4JiU26NAeyAY2ZCUJpunQe3Rd/LFrQCUC
         9nTA==
X-Gm-Message-State: AOAM532aAc0juggF2iYxKz3lQxem2uxRA4IWJHupV+QNSvTlXp77QRKT
	RDEelqGEbSmruufcZ5E26SI=
X-Google-Smtp-Source: ABdhPJytMlslGwc4nCYnWVO3tDCaT2+eBiMYsuGgLRzYBs1OaYupFpIzy6XBTlohafWoUO0oW2OPqg==
X-Received: by 2002:aed:2ea4:: with SMTP id k33mr23661902qtd.169.1617042419567;
        Mon, 29 Mar 2021 11:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c207:: with SMTP id i7ls8990165qkm.9.gmail; Mon, 29 Mar
 2021 11:26:59 -0700 (PDT)
X-Received: by 2002:a05:620a:16b6:: with SMTP id s22mr26424226qkj.240.1617042419172;
        Mon, 29 Mar 2021 11:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042419; cv=none;
        d=google.com; s=arc-20160816;
        b=qfyKexX/4M5Rcijw13TX7arJ6oXpM8xEDBXj4yRjdhk4+ADnXMH5xPZTT95BsbBsxh
         zh37uLr0Iz7Evb3SY8AZKZJ7U3je74LHuHvu54IV0ToudBZRk5KJ4Lsxsdm4kk0cjGEb
         b9d0w0rk8f13rOcnhig3M685biG12tiJ23Mw2H+jQxQYeT+jZrRRcmIdUMFlo8NeoqZy
         teeTbnGxuFmoGKCDOJAxe7nHCa+6+zgEqZ/QEdvld9VaREktMXDvA9X74XvNnBlHdEAd
         vZd9suXUAPZjaC4OJk79tLj/MLvvXWLziE8+48LhQ6oQGWr2OojMVi6/ALWRjjGWMPB/
         qtsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=TtLVGU3fdGFUnspw6rWTgvkrU7WnO/Si+O2feWCXEJ0=;
        b=A5Erk2/oq1omgBz+JVXHAA0JN3wu7Y3OjsK/lExjWyEO4ogC7A0U1ASMFd1b0qCSrv
         Wz8RGRHvDm8o2v7mr3zTUuReEM6pvfcVcm7RCUodu2PHobfEl4OK1iYieaWuGt73+ftw
         sgAFwU+wnCBNTBhlTbKr/XaWXnlNj9Kf3mL22wpEhtYOZ/FzFhqrO3BZuVQzAO5/zQIq
         mDpSot6CE0OGspc/BYj1BYo1FXvfE44BUyTEf/7uQPp7/6RAibKuiK8Z2JdVAXSt8UMl
         iv8wcdagYgy4T/DLJWg1chjr0MRVu5BzYaBxIEnfzvfQb1Kkj5GLPT+JPDvZXHLF1/An
         424Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=PzuqL32U;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id w1si754089qkp.4.2021.03.29.11.26.54
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDX3EjgG2JgN_FpAA--.35355S2;
	Tue, 30 Mar 2021 02:26:40 +0800 (CST)
Date: Tue, 30 Mar 2021 02:21:44 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, "
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH 0/9] riscv: improve self-protection
Message-ID: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDX3EjgG2JgN_FpAA--.35355S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxKrykur15Xw4rZrW5Jrb_yoW8Xr4Dpr
	s0kry5ZrWrCrn3CF1ayrykur1fXwsYg3yagrsrC34rJw4avFWUZwn5Xwn3tr98XFy0gF9a
	kF45u34Ykr18Z37anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkKb7Iv0xC_tr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Cr0_Gr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Cr1j6rxdM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r126r1DMcIj6I8E87Iv67AKxVWUJV
	W8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26F
	4j6r4UJwCI42IY6xAIw20EY4v20xvaj40_Wr1j6rW3Jr1lIxAIcVC2z280aVAFwI0_Jr0_
	Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU84KZJ
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=PzuqL32U;       spf=pass
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

Jisheng Zhang (9):
  riscv: add __init section marker to some functions
  riscv: Mark some global variables __ro_after_init
  riscv: Constify sys_call_table
  riscv: Constify sbi_ipi_ops
  riscv: kprobes: Implement alloc_insn_page()
  riscv: bpf: Move bpf_jit_alloc_exec() and bpf_jit_free_exec() to core
  riscv: bpf: Avoid breaking W^X
  riscv: module: Create module allocations without exec permissions
  riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU

 arch/riscv/Kconfig                 |  1 +
 arch/riscv/include/asm/smp.h       |  4 ++--
 arch/riscv/include/asm/syscall.h   |  2 +-
 arch/riscv/kernel/module.c         |  2 +-
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
 arch/riscv/net/bpf_jit_comp64.c    | 13 -------------
 arch/riscv/net/bpf_jit_core.c      | 14 ++++++++++++++
 16 files changed, 50 insertions(+), 40 deletions(-)

-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022144.150edc6e%40xhacker.
