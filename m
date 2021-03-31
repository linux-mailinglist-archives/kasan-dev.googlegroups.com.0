Return-Path: <kasan-dev+bncBAABBXWHSKBQMGQERXEHSHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AC65350485
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:31:27 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id lj2sf1576335pjb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:31:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208286; cv=pass;
        d=google.com; s=arc-20160816;
        b=qxT4XaEK8039OEq6PQH4/UrTUAPQPMHdNsX+zIQh/EGHI0HHfcmlNDK4cakgD2Pc/j
         Q/GXGGH0V04YhafMJtm3TAYOKmVYMOmwFKKKlObNApRL+sktU6774uvFpj5IwnTq3oKd
         spk6BqgRBThXwPY9yyL9SEPdcUOwUjkx2fj9X/6QQgp8HOnCFvLmFnsBNbKKKkuZUU5x
         H4Q0Wnfw94G5T82VfAMlNA9iRlQP5CKduM/KCXYcSdqcCjUBZDzfyQ60FYEKsMM9MfYC
         6jG9r50a+3Myh6EQmaRXSyjyY3ktNs00/e09HbvjISXOHXBzn04a1eoqOxHc9pwP8kOp
         WRog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=yrcHBwXDs3YUgMeLYMoAQut6p0l/pQ6yjRKDjrm1rGk=;
        b=pC/b53d7zE6OFMSsghbh+Jiw6Xp+NDAOTWZqW617NYxSO2zXBHHTZLaYJgf8mWoCcQ
         TXzaHPveWp37U/xBGvbWAJv3hhUaaK0CZvuPJDu1i4ptfqPlJdo3pVSZRkfHMITBIrkv
         tn8JDUqhk/Rez9Ux7JjT0AI+0fdJSEgMm/AgUEA9LukU/tVak2tX3CThthaqNQSkXu2g
         HAy4y4MmOAljtKquSQ/V/+S9B98mjI7gsNebSe9+wwUzFO4let/SumY0TJp0lWQqsCvt
         4ifTj9hebiOqVLVFggbNT2fNjhuTuEWmYnrXkktJxeiIzj6du8fssr1Cvabi6S9rJANO
         dxZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=RpJibMn2;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yrcHBwXDs3YUgMeLYMoAQut6p0l/pQ6yjRKDjrm1rGk=;
        b=n7X03YEwyZokcsr+OBw4czTWsYBjiNfarO8K/BXMEfLaQPnGhKr+FbhpNyrN2DgpKg
         QaLxvbX7YY8dlBdkQVXn16zQU9n12nltYl/LaiJMg2SnY6J8zL98zshZXSlPPJQEt3mr
         RL2/xK7gK+notFJamozs5UpV/sUrlzEBqAYSLAgGq2XhAkgebVRqu3CANuxgpewrhlJU
         yDxDu2wIfM+WHnyOS6ZlWYsMoXE3Ez+Q+bbR0aZFNEL/fRjc3BuoY4b8ssalaVCRLF9r
         rbdtVqFC/ClvjpURh0aS8OAbv0kgfUWzc6yHKxW6Y7rzZIUH1aZNd/jVN/4JdISnF8AK
         Flsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yrcHBwXDs3YUgMeLYMoAQut6p0l/pQ6yjRKDjrm1rGk=;
        b=T6537EfK8d1b/PSJtshBXgao+raSOx9xf5h50PWO9apsweLCE8JVH7AuNw5FH/8D3M
         C4SfuU2NYmni0lcvAI0Ous5SCupfX6W6H0aPYplUvHyygLFyM8UFfrCxaOf4IIgTjfi+
         8dYBshzaN4FrZx0PtDDKeiE44AO5vxyRqG6IpQ7OXonZwZWjA4BbL8igvL1epFMVcIXB
         v2wzyO3Qtu52PWt+7sV+KJEmP5UvQCKuCymFiT7v9geMdQDIvSfHc8S2XWrxwsPFhubJ
         lqUZ2o5iUOrAYOQPugubG4XzBfn9wXTwtQQn/G4rzbpdlAa8GUGaQV88Otg3eYOLkCn/
         u1tA==
X-Gm-Message-State: AOAM530KMre3qkXHJ9CLkEOScOpKvAT4A+mokRCja/S507XJX0PN8cBI
	W7IY3k1Ya/BqU3lST95GiRc=
X-Google-Smtp-Source: ABdhPJy/JixugalB3sJGkpw4mGqUiGon0cZFZULS6NIUMMUJYjXCiwuiRpUgL1FU4wkvjq6soFNrQg==
X-Received: by 2002:a17:90a:8908:: with SMTP id u8mr4151487pjn.135.1617208286086;
        Wed, 31 Mar 2021 09:31:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f10:: with SMTP id a16ls1142777pfd.7.gmail; Wed, 31 Mar
 2021 09:31:25 -0700 (PDT)
X-Received: by 2002:a63:3ca:: with SMTP id 193mr4005841pgd.274.1617208285685;
        Wed, 31 Mar 2021 09:31:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208285; cv=none;
        d=google.com; s=arc-20160816;
        b=I99C4bfbAq29zBHxeoBHM0fP1jAHNmZeHg4Tv+acVP/5gHlMWoeAScpOfUi69MZMz6
         85GbvlPJFhX9B0OPEkSS4/ZgDrDbJU8Dp7jBYRznu8XpvWg1BcQmr+ILKd/c1KhktcGH
         4l/6Ylv7BgmQ3/qQJsWa6wD3CWxp60bMnhXaaZsXIkKT7Io+yjXBSfrOLklh2reWsrg4
         q55hryLIIsEQLsHmn4cAPem5uGa0Ll4dHhHjQzIiGEHWtj2IdWzH83KPpfzlNUSCVoUK
         8Dbz8PoA65kVMkFl+cFfE29oMqvKvD5e6JLdO/+TLCEie7gLeWLskobBMeDeOoJXG2Eu
         ldVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ikp7PZAuK4fo1XgsXlr4Y+BaLjbJ/cSgtNEE/K8IQMY=;
        b=Ws9mFx8f+QBDskopkOj+QGyUl2s/aumOc/PniRYYnCBzyBOEk4/sC+9FZdlZkGQ3go
         4qBz0iEZQzZwwszcXJK/VfSKMrWRpA3QChHMPmGb9l2b0h0BjIykYvcQ/NPejvN08l93
         6EGASgWMSiIX9+BoqBJWYOqPzcGX1j4HwbrX4i4H158SU8lIsqaCIiVpcRj2XQKk5HPr
         GjGhcwtNENCSTZ32iCO6alzvfpDbk15qem8ftOOLVlQ2C7/VRZ3R0Mf2UKjvFqyihgLD
         yqyy2w3UtFyrT5ECzArh2CJrRCIElgzcF/YuFmsLEttojLkbbwWBQHqw71qvlHKoAith
         D+ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=RpJibMn2;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id m9si232251pgr.3.2021.03.31.09.31.24
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:31:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCXOpnWo2Rgs7x6AA--.15943S2;
	Thu, 01 Apr 2021 00:31:18 +0800 (CST)
Date: Thu, 1 Apr 2021 00:26:21 +0800
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
Subject: [PATCH v2 3/9] riscv: Constify sys_call_table
Message-ID: <20210401002621.409624ee@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCXOpnWo2Rgs7x6AA--.15943S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxuF4kuF1rWw17ZFyrJFb_yoW8GrWxpr
	sxC34kKr95WF18CFyakFyxuryxJ3Z8W34agr1qkan8Cw13trZ8tws0ga4ayFyDGFZrWrW0
	gF4I9r90kr48XFDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkGb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUXVWUAwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	WxJVW8Jr1lIxAIcVCF04k26cxKx2IYs7xG6r4j6FyUMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jndbbUUU
	UU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=RpJibMn2;       spf=pass
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

Constify the sys_call_table so that it will be placed in the .rodata
section. This will cause attempts to modify the table to fail when
strict page permissions are in place.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/syscall.h  | 2 +-
 arch/riscv/kernel/syscall_table.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/include/asm/syscall.h b/arch/riscv/include/asm/syscall.h
index 49350c8bd7b0..b933b1583c9f 100644
--- a/arch/riscv/include/asm/syscall.h
+++ b/arch/riscv/include/asm/syscall.h
@@ -15,7 +15,7 @@
 #include <linux/err.h>
 
 /* The array of function pointers for syscalls. */
-extern void *sys_call_table[];
+extern void * const sys_call_table[];
 
 /*
  * Only the low 32 bits of orig_r0 are meaningful, so we return int.
diff --git a/arch/riscv/kernel/syscall_table.c b/arch/riscv/kernel/syscall_table.c
index f1ead9df96ca..a63c667c27b3 100644
--- a/arch/riscv/kernel/syscall_table.c
+++ b/arch/riscv/kernel/syscall_table.c
@@ -13,7 +13,7 @@
 #undef __SYSCALL
 #define __SYSCALL(nr, call)	[nr] = (call),
 
-void *sys_call_table[__NR_syscalls] = {
+void * const sys_call_table[__NR_syscalls] = {
 	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
 #include <asm/unistd.h>
 };
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002621.409624ee%40xhacker.
