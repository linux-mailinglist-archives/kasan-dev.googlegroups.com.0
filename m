Return-Path: <kasan-dev+bncBAABBXWISKBQMGQEXBJJ2RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BF7135049E
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:33:35 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id j12sf1577155pjm.5
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208414; cv=pass;
        d=google.com; s=arc-20160816;
        b=zaGrJjll65FIyEN66Dv8kWzr2wGcDdVOOdHkjV1U5xRJ/eyEaJU+BgZLgIUoDBfKpk
         Du3pC/9tebl+/AiCkcRNzDVxGvNM6qdpuFrfIvsT0pXB0DXaHO6ydvm9HCfwJataPlve
         UMuQ2NB5hCRnKhdBI5gVU0RGEMEjgY+YfrPkgDb2ONlFSdenvSycvexe5ERcX9zLC6fY
         zAqNuGsQF9ucmA+g8laBp0zDgfVNmLe2dOeGqFp9IH5tf1bjkm9euoIzjIKUCRkXWS+I
         KzRKL0RFOoHK+zDUGrqHkGH8wCk3TBO+2AcmezUUkallzGlyH48W5pIKRQ9BUP96R/d1
         PKdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=2L1iipYVRcfSgXd/v7yhybW1Jld0ONJ4NrKok/659VE=;
        b=ZCCLi1JAW+J3PCHXhLiJAdljrAPFs33vefKAsfyQJ4YIciQR68oRhLfaEQ8o79Ylea
         b7Wz+OVRw2g4z6C+a0bMoGYhIM5lhygwHxmvKzwUudmyzkHAbf9FQ8R8gVoI46rHlaDO
         44KIfxKp0YyQFWqMjCwOPgKYBs24AGgAO3McYbw7zcIHLQX7dD8NK765IDLI0EWtRsrB
         fy/fkj+KvaYDAoMK2ait+oh5GNHvv0ommYVVxPjAbiQhiP2zrjGu2gfDVGucQzvHf5Fa
         7BCt/LlHZqtf1VRegOZ+d4gK6My+m8KPofh9/xd+SqcXh51ZboAdlB8mexKaPERbPU3z
         hylA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=dplSMM64;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2L1iipYVRcfSgXd/v7yhybW1Jld0ONJ4NrKok/659VE=;
        b=J68oV7TGyNSeR61yBTsI3kHnugc7LmAObGmM4MdTzPHkSAOz5r/wF1CVTZQaxY4WFc
         Dbf8giZyd5/B79WDYE+PhI3AJckDnzIMAJYf29Mu1k7eWfGY6Miem9SnXjgkUyr21FZU
         dYsro9d3F/PyStb5mXTf1GnrG2J4d2bih9mM/1oInjwCbjlcgi+8kaC/V9xqQT5R8LYB
         jmzR1YmRAZyn7LHp2QtVtEn1zhZVfbFLsB6amxkuBIPZcUwOpq6vptaEKcsOwJOo0cfv
         JCsGYqnBdHdh51ZZDEqEExKuWw5F03WG4ABwv3ilTdTsoHhn04ojvWDxLgXUeLBXw/ak
         EmgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2L1iipYVRcfSgXd/v7yhybW1Jld0ONJ4NrKok/659VE=;
        b=qAwP6uiUkTNsQfaur23eJSR8Rd13lpJg/p4Y1z6XVS+U+3TedFJ9wIRIVmvP+a3sw0
         0c1RQpuhYqXhxVMzobDX5JQNUWCfppuZ2f/OocZIZ84CYsR9CKn9xH0qyZOXiO1ZvgnP
         nqR6azUz6vo8tr04M7Q5WZuUITBM0nEFRSoYYH95itg/KwjocXnextQ6MX/oxZcKZ7B6
         lwfLXv4F8cDlqM5I0zwRWvWHAdXRIZ23TaSYhGYkA4OsSYSNuu5ath+2qvFvxOhfapZt
         aHZUAdteCJfPSpHa8Q3n/iNW7fj8u4fH6BNjwjrmkhunuzNOGoSbDqSTR66ZpfVJuGJ7
         WURQ==
X-Gm-Message-State: AOAM5338P+2pu3jJYFWt4hY1ATWtejDkd3r8/RQIXqqe0+G/J26a32v7
	G36TbhUnfywH26yBC3XwJVw=
X-Google-Smtp-Source: ABdhPJzpe48fjFXp14YEPdrucZqR1pez9QGUftpU0QuiNIrNYkoVeEjh/eO+gSYgY1CtUc1xZKVgGA==
X-Received: by 2002:a63:4521:: with SMTP id s33mr3975809pga.1.1617208414241;
        Wed, 31 Mar 2021 09:33:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22c8:: with SMTP id y8ls1370953plg.2.gmail; Wed, 31
 Mar 2021 09:33:33 -0700 (PDT)
X-Received: by 2002:a17:90a:9f48:: with SMTP id q8mr4397039pjv.53.1617208413606;
        Wed, 31 Mar 2021 09:33:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208413; cv=none;
        d=google.com; s=arc-20160816;
        b=INmCwPEtxo96njKdn9vLLoNs+Fx71mjeeEvS7Nl8Z5dcmNJ4Trc0iMVnN0tqVkl8l2
         IEFEG74n+aRpaBVY5FOGvLh1kGqQyNw6KRnD/qh6KLTLRgJ+P3b5udKcTBBVBeZq/WzY
         6kz2xOYv8O4nmjB/gRHyC5EugImmf5RBikfnGV95jr4cVZXkvqc6lMy9XNKQT+/VeDuO
         BFzib2ZEg6oFdEuVcGBV2AyBbwxzGNSTAzWtNELOaPb8BwMI89PHNPE27I5FQOSZ4/R1
         b06lpA7F5xW4geQELHokVL2JfDpgUsHm3PEQfWK5F6y976lUYd5jeBS6X7zblbn1Bmb3
         aAHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kspMpVWA8RdaDQw/ELkzB8D1gwcI58BWj8lpK1+dMAw=;
        b=CD7zMG2vGg1fwYdJia+Y6YK66vAsMjqYoIkHhN81AGtZ+a2cIHUXdQlCrhZfTSDrFy
         +iFpofaagE0NHWosAr1yy2acmhXjBdXMADFL/riKCEKudsndmlvSBQJu2UOTHjh5ejnA
         BX87o8Rq84TutbJwcxBwF928HHTlCYdtXMm1mx5XxVaV/1ILfEhbZaHb15mISSPAJ/Eq
         4TCXeF3fTYeY+A8b6SnCG2yQt95gTlnYMB0Lk3v3RC64NmDglQ1ePZhyVWTZv+6J/Sp4
         WfZnV9+Rm4VxI+wY6fAj6vy24GC+1SQoRPYY3jUG9sgIOuV5QIJzYRXw9c4qR9ToeMo5
         LnWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=dplSMM64;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id z22si257543pfc.6.2021.03.31.09.33.32
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:33:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygC3vExVpGRgsL56AA--.1359S2;
	Thu, 01 Apr 2021 00:33:26 +0800 (CST)
Date: Thu, 1 Apr 2021 00:28:29 +0800
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
Subject: [PATCH v2 7/9] riscv: bpf: Avoid breaking W^X on RV64
Message-ID: <20210401002829.50b71b64@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygC3vExVpGRgsL56AA--.1359S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFy3Cw1DXF1xGF4fXw1DKFg_yoWfXwc_C3
	WxJFyxWw1rtr48Zw4DWFWFyr1Syw4rCF4kuFn3Zry2ka98uF17tF95t342qry7Zry09r97
	WryfX3yIqw4avjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4AYjsxI4VWDJwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM2
	8CjxkF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUAVWUtwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVW8JVW3JwCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU84KZJ
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=dplSMM64;       spf=pass
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

bpf_jit_binary_lock_ro() in core not only set RO but also set EXEC
permission when JIT is done, so no need to allocate RWX from the
beginning, and it's not safe.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/net/bpf_jit_comp64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/net/bpf_jit_comp64.c b/arch/riscv/net/bpf_jit_comp64.c
index b44ff52f84a6..1c61a82a2856 100644
--- a/arch/riscv/net/bpf_jit_comp64.c
+++ b/arch/riscv/net/bpf_jit_comp64.c
@@ -1153,7 +1153,7 @@ void *bpf_jit_alloc_exec(unsigned long size)
 {
 	return __vmalloc_node_range(size, PAGE_SIZE, BPF_JIT_REGION_START,
 				    BPF_JIT_REGION_END, GFP_KERNEL,
-				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
+				    PAGE_KERNEL, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
 
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002829.50b71b64%40xhacker.
