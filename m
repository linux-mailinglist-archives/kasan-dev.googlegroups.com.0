Return-Path: <kasan-dev+bncBAABBX7YTCDAMGQEHD2GSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 756D83A59B4
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Jun 2021 19:12:00 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id dr11-20020a05621408ebb029021e40008bd5sf25061064qvb.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Jun 2021 10:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623604319; cv=pass;
        d=google.com; s=arc-20160816;
        b=DUdb7G73Gs0atvp2kI5hITJrB6677z/+GbcIlsc6UY2QYfVV3F7Cu5+ei4HG+h1wBr
         A/aak+8OORs/OHrSlwuZ7X64fmSsDU4KlBr5rMSbg4Y1g+ushlbNk1OLYUhe+ocyhWtW
         XlQaBhNIDEmE2drm/lm0TP6zdB3lBn4W2zW0GWOtBFSTnNosraBgvUZpFQtfso4VUpjT
         e96fWjhy2bBcAJ4Pgcib6nJ8OzJhTR7IvXgkCUrTZuVqigQYQ/WnYUxoHzWnjs563Bt6
         rZTIJB/9fX3Gj5IStdUAJPLx5SGWewZhsXry40IFrHgLuzkMjO+TthWdCpCcbGsBWdlH
         mytw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7rlxogZXHp+L7HE1a+7R2hL6SbRQo5BKEh7aeBlsl2I=;
        b=q2CFO6Cpt/rhqe0OPCSHNWnb/qtLf7djc4eUgptmWG/TmYT7XGRdlRxq1lHIRv3Kvb
         epdyQuiFVqXNXTzMHTVXCgKI2LzjP3zEplqC4GO+92qDDhneK8Gf7VQS2FY8qDH1jBxv
         NhA9vSnhVz1/yDFvTmRILkjlCXEwVa4xNBd/qedeRt1sRqyqljkKqUx+nNlurIk95gKx
         BP0lOLsw+trl3bVEv4Q3LLXmSysUbJ7WYFVHxNhjKgnXHNnVCSREE2SHQ5d5JjRCKAtD
         PQf++0fOfU8anZCRWZB3hntLWVpkR3YvW4srlCe4q8Sl9Bho8FRF2Ic23CA9VJEVW7Vr
         bcJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=oZ8DSkyl;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7rlxogZXHp+L7HE1a+7R2hL6SbRQo5BKEh7aeBlsl2I=;
        b=VVoCadn2dqvt7FnwwX/3O87T3AHWBKPmiagKU3W8Wzk6tyfQfhXsEp5Voqr77CUas9
         0S9lNMlKB252G4864FYgVfEsJMqMAqM03v/OpqA+YBmZZ2/wIfT9Vcdv304IOMZwBkC0
         AaxXp9quZEeglOUa79s09lJYCE+1Wo2xST114nTP0fxQxYYorYqWskUsLwWJyy3n1eMh
         QIV8ClhgjZjykmwOBKpruId6i5lb8YKwp7IvfAqNYqWpQE0UGFCqyYKcUwczChzeNYU0
         CKKqweV5W7z7nEyyNA7wKTx1ZksJfcCHeTTBHhPDBTVD8YGxEJJEjsEqcOWFUEYwiI9j
         Vyzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7rlxogZXHp+L7HE1a+7R2hL6SbRQo5BKEh7aeBlsl2I=;
        b=uN3zNX3PqiT/ejQP/i7MKvjPqM9++Hy45PJZdeYzZP+7hkihvYHoRYGUXjdwpaTQAG
         LwenBZCsmUPYKu5C+aMyXkXZyXOowzOi3Y6bzs9cbR5Q2hcLy++Ki9QZtxM82/yaq2lv
         pkGKxiHb8U9a7qS1jvBoaaSGwRm0FfV263j6klDOgcDXaDhLgSAvhYPtCKgGl0tFn3qm
         i78JeNU+yGhNvw5w0sNg6gwhNgxnzXX8wuF7KC7BcRUz+iIxsUY5v/9a2zjsG1tcOS+K
         tTb1Hy5fXesLu3cSVB3ICwEGKoIU48zxEPKmnT30PLLTLwUrmQ1qkHv9gVt0yiObJUQS
         bT4w==
X-Gm-Message-State: AOAM533cfEM0Pc+p/VFkOlRq0R2xkCgb6pvpXxH/tD5aOQYa7M3ySjzy
	uNtF7d85K9KqOQius5+sJPU=
X-Google-Smtp-Source: ABdhPJxC/bU8oDw0ndTzpw9phssfMU6hDBlyMQqRNoAFyqTkxV+kVKnV6pujFwmbmy2TGrfCuu8y7A==
X-Received: by 2002:ac8:7d03:: with SMTP id g3mr5363911qtb.93.1623604319229;
        Sun, 13 Jun 2021 10:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a08d:: with SMTP id j135ls4714233qke.3.gmail; Sun, 13
 Jun 2021 10:11:58 -0700 (PDT)
X-Received: by 2002:a37:a47:: with SMTP id 68mr12902985qkk.432.1623604318835;
        Sun, 13 Jun 2021 10:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623604318; cv=none;
        d=google.com; s=arc-20160816;
        b=ViGlA9Qt5ElQ0/YtySU7bMD1hcMXHp/1k5vKbSr/iZn+wdEtDDWIEEV7PLOcifd6I5
         T27qUllcXU02Ct1XO3aepVAEx7eRLOCqMwvtjmKyVXPRcSIdecdEGX6xyjRY6DuZxH9L
         NfA0cHTTDLDWUoFJM959QcOSskWLyEhJg6bxFSRiFwPiNWW1aypXgqr4zVJu1OvkwrQK
         Pe6wsV8CiGesptUlv22wdTXcIuqYFSJ9cw0hTI8NT3dnDVG2HZDSVYe0Aq5gg+jHVs9U
         WeWiB1E5JO4zypGgvpiqjGm2punkLdf2T8/p5ZFo7ntRh2PluwYEHHXvFkVH2mGhHXvn
         eJrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9YrEcNG/N2YFUqtgoD+2CSLrFOJntdnn7MCq89XsJdc=;
        b=PSMF3VWu/AwkE+oIef4Pfy6UhD/isk7nqfN8SBJ6htx8ueQgt/9mRSdLrvwsRnnXQB
         zet7gTgrKcwqpAvmDzqvcn+oeM+sBXevk0jopAqFpDWHH3COu+0QGspltDV/RnSIGbnH
         QyfU5YyRLg8GXruToIeIo7p7nP9rFmha3fWZWE9ybPTlnx/uGRbeDkVGW1fQQ0c3upUS
         bBBM0aZ3xGR35RMq8J40nO8SEwJ9CHtK+bT8ulm+7G8NJ08XcK0/XkvGVe2wcLoO4AGH
         odoQUPyIEzTbycKrLwJReHwgNS/1D2Bg4VSbi+mB0898fMQmudFwwKsHTmn0TV/k+pJI
         Kz5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=oZ8DSkyl;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id 85si1182146qkm.5.2021.06.13.10.11.56
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Jun 2021 10:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCHj1s2PMZgI9DTAA--.35616S2;
	Mon, 14 Jun 2021 01:11:19 +0800 (CST)
Date: Mon, 14 Jun 2021 01:05:46 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andreas Schwab <schwab@linux-m68k.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: Re: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
Message-ID: <20210614010546.7a0d5584@xhacker>
In-Reply-To: <87bl8cqrpv.fsf@igel.home>
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker>
	<87o8ccqypw.fsf@igel.home>
	<20210612002334.6af72545@xhacker>
	<87bl8cqrpv.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCHj1s2PMZgI9DTAA--.35616S2
X-Coremail-Antispam: 1UD129KBjvJXoWxAw1fKF4UZF1fWF17XFW3Awb_yoW5XF4fpr
	1UCFWfKryvqr1Ig348Z3sF93Wjvw13J3sxKrsxXFyUAa1IqF1kZw1YgFW3JrnFqF4xK3y0
	9rW29rsava95Zw7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
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
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=oZ8DSkyl;       spf=pass
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

Hi,

On Fri, 11 Jun 2021 18:41:16 +0200
Andreas Schwab <schwab@linux-m68k.org> wrote:

> On Jun 12 2021, Jisheng Zhang wrote:
> 
> > I reproduced an kernel panic with the defconfig on qemu, but I'm not sure whether
> > this is the issue you saw, I will check.
> >
> >     0.161959] futex hash table entries: 512 (order: 3, 32768 bytes, linear)
> > [    0.167028] pinctrl core: initialized pinctrl subsystem
> > [    0.190727] Unable to handle kernel paging request at virtual address ffffffff81651bd8
> > [    0.191361] Oops [#1]
> > [    0.191509] Modules linked in:
> > [    0.191814] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default+ #3
> > [    0.192179] Hardware name: riscv-virtio,qemu (DT)
> > [    0.192492] epc : __memset+0xc4/0xfc
> > [    0.192712]  ra : skb_flow_dissector_init+0x22/0x86  
> 
> Yes, that's the same.
> 
> Andreas.
> 

I think I found the root cause: commit 2bfc6cd81bd ("move kernel mapping
outside of linear mapping") moves BPF JIT region after the kernel:

#define BPF_JIT_REGION_START   PFN_ALIGN((unsigned long)&_end)

The &_end is unlikely aligned with PMD SIZE, so the front bpf jit region
sits with kernel .data section in one PMD. But kenrel is mapped in PMD SIZE,
so when bpf_jit_binary_lock_ro() is called to make the first bpf jit prog
ROX, we will make part of kernel .data section RO too, so when we write, for example
memset the .data section, MMU will trigger store page fault.

To fix the issue, we need to make the bpf jit region PMD size aligned by either
patch BPF_JIT_REGION_START to align on PMD size rather than PAGE SIZE, or
something as below patch to move the BPF region before modules region:

diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 9469f464e71a..997b894edbc2 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -31,8 +31,8 @@
 #define BPF_JIT_REGION_SIZE	(SZ_128M)
 #ifdef CONFIG_64BIT
 /* KASLR should leave at least 128MB for BPF after the kernel */
-#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
-#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
+#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
+#define BPF_JIT_REGION_END	(MODULES_VADDR)
 #else
 #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
 #define BPF_JIT_REGION_END	(VMALLOC_END)
@@ -40,8 +40,8 @@
 
 /* Modules always live before the kernel */
 #ifdef CONFIG_64BIT
-#define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
 #define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
+#define MODULES_VADDR	(MODULES_END - SZ_128M)
 #endif
 
 
can you please try it? Per my test, the issue is fixed.

Thanks


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210614010546.7a0d5584%40xhacker.
