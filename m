Return-Path: <kasan-dev+bncBAABBLNZRCBQMGQEIW3PFIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E4E134D71F
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:30:06 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id k12sf2595135ilo.20
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:30:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042605; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Aw1Bfm+9cFMILwPKQ4/w9rf+VajHQro2mwoB0b3T2LLWTadyq8sx1RheUCquPJCrO
         5L2ivkWK89JHEd7l0Fvp2kdBFRcCuE/Ty4VRJZFQ0vysMycYCqxTCQSldeMCqCVXfEFU
         LW4eEmkjo82W5pMneQ0aKIHdQcJON9ssehzv5wevmzQWJi9kYc+GqrsPKycwgkcYBPwi
         eRGFQPU8y6ppVYQDOKoTiJLAsJ3hi0moHoZ07FBcKhgxz6fHXUtXFNKC5n14Oe7FncJf
         PNMRR7Hoz1JtivJTo+uJ2u1ywzsu1KMMnHXvKynChlExZMiOxNg0uEfPLuK9FAOu/kjG
         It2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DEj8TEK/R6i9nhy1RXEr8UX6SrAbvbrqL6qSNEt0RoU=;
        b=AiF1M+TbCKHjy5bHFhmaJLTSN655KuzhPGyjXu2g86z7DK+H/GJuJBG5NvfuqbAs8h
         acdk8j/i/tncwTbLyHtolXNHXT+ppX0wpyDhKF4/nn2hSKcE0QTWvqZxiJijX2fUKupQ
         uDtnzuhB7wss62CmPfph0Xoldb8CZp7mHT7idxX3gXTnipFPbn4NCUf0CDNm+2Y5AX8h
         KU2+w4tNU+3N+H0OFcd2rjIu2qQVv0SZ+YUgPmDPi20Y8EtuM+3ZRY7EnEmx5+pGaSOT
         XmRNqrGjcxANrd1oJ6anMJjZCw1qtGvhSzIjynRsbtl1SG0Vzb3C4BlLEtYUcnIzxmFB
         RPdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=kroUk+J7;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DEj8TEK/R6i9nhy1RXEr8UX6SrAbvbrqL6qSNEt0RoU=;
        b=AFa38DBfzXjjUpmAlAFQhyXrrd+UKtEbWJIXFLjK57Wr3pZxLCeDCEWj2YojcorhQY
         tKoYxMt1fnRmGpOC69wNAEPpuxLYKIPDh9aJ/qF/DzxAhXwU2SEVCh7M61wtVUlSBBqR
         yOjo4EJmEjKYPXzrlSqGJdJjBq/I0BTIxu/85GkYJzMHXfJvLqcrvGFLEmtA/BgkVrTM
         12ClpfjLMKmP0huEvato9Zx2GzTWL6PQkgGvMEREpc5WOsn1pDUSFLjJaiPe0NCjGSLU
         FS6br46z1fQkGVgoJDBFYCrqQpCBsQoCcVhVMUpR2tfdzZKZUghg9iaWjYGO+fvwGz+5
         RRJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DEj8TEK/R6i9nhy1RXEr8UX6SrAbvbrqL6qSNEt0RoU=;
        b=gtOs8TpNn5obHJ5ZXy6k0e84mKsVq/V9BPRayPWWEpUsMqigtjMCD+Ood1vCc/zajy
         u4uoDKoXXijV6LCofzYmKSFeI06+bAtrKN51XqUhQWxB38BmoZhGkt3UmaA7v355Eyh1
         i6v0Qe47f+ZwJgcUmsEjkASbu+rNP9A2UExZ4u4pYyWBEZHThzSKaxOrARRs+hrvT8xa
         pOONYV2Uudyvf9HZL0mnwcPcYiEBE4WBh4RlCv7auGAsBuEbkmk+2MzzQvlQslgIRWXU
         y9SbBBW8z8fH8nSTWNkzWD0CMfBbBypV3stOB89RqKAHkRop8MS6kz4WQ5ox1QGN1G/L
         3/uQ==
X-Gm-Message-State: AOAM532B50KYvAEylLarbWpJFxwXJQ/lm320sv/oPM5aDy6zegRkD+eq
	qyZgQ708E5uXED8ILfB0/94=
X-Google-Smtp-Source: ABdhPJytzSJL6nH/He12JpNnkVSZSbbGyTS+269O6wX9gU2XZAj01ffSt6kZ+96vZutyYVXd61HDdA==
X-Received: by 2002:a05:6602:14cb:: with SMTP id b11mr21645516iow.175.1617042605474;
        Mon, 29 Mar 2021 11:30:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3590:: with SMTP id v16ls2123578jal.5.gmail; Mon,
 29 Mar 2021 11:30:05 -0700 (PDT)
X-Received: by 2002:a02:cb8f:: with SMTP id u15mr24642274jap.45.1617042605219;
        Mon, 29 Mar 2021 11:30:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042605; cv=none;
        d=google.com; s=arc-20160816;
        b=csptCiQgNgpUkmy4NkcpgqYEVeLILqvy8TNUsDpmPpQ3h/sTw7UAoe9VAwOZSyAZOk
         RmWZUTDSU6LSJXUucFlVSAduRWuvJ9qMZ+6dHFkUgmotx67UjHTtc16X963PnRLbmIIX
         Sf3eKsSDCNIdE3tCe1uydBee/VdE1cvp384T13n/p7FHaLloNo1Ez0vorL5pl9ZsEu/A
         sq3jkcCxx45/3B/FhT/743pFysq9uc1YddzGAVuVAWeh9tEBTMZwIufmWBAN9zThgGdi
         Zi6/c9ZOHigKHO4ko34IKsMIfTQZeQC8Hluzb3iU2wB0IeUKTk+fdOSMLO8PlzDiqDAq
         qsvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=MgvKzE3RWjWapRps+L/qSm8ZaZUnOBtKKGClBE5IhG0=;
        b=hoRdgApbwf8KjME2v8PwSNwAhEttxx8R+keV5TTrfC8jmCnvD7uUJ5jqQSD2QWor0h
         TXuR4u74xEd//q4XvzD4BdISug0oSY1TOwvCLThmiGR/k3ztb4qCwwXCyFHYIJxQ6Q9v
         htcfBrfZyhslhq9FFlhWgThka+YDWt81kXMqNS0DJRY7kiC2SYVqWAeb4K5MpEpIit5T
         qrik4LmlU8ryaxLw6DyHFzmMdHOm4qToY5LdLu2yOvZdBbwfoebGPKL8+5HULl7yOORu
         y2vb5mka2qHeOUVV41xg1cmqhKGBFZHLuakhIEmdt7cbnkSeZSJa3qmYJ0/2C81ngQt9
         9bxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=kroUk+J7;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id y4si1329826iln.3.2021.03.29.11.29.58
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:30:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDHzk6eHGJgFvZpAA--.41814S2;
	Tue, 30 Mar 2021 02:29:50 +0800 (CST)
Date: Tue, 30 Mar 2021 02:24:54 +0800
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
Subject: [PATCH 6/9] riscv: bpf: Move bpf_jit_alloc_exec() and
 bpf_jit_free_exec() to core
Message-ID: <20210330022454.3d0feda2@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDHzk6eHGJgFvZpAA--.41814S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyftry5KF1fXw4fuw1kAFb_yoW8Cr1UpF
	s7Cr13ArWvqw1xGryftay7WF1Yyrs5Wa1xWFWUuayrAanIqFW7Zw15Gw15XrZ8ZFyjgayF
	krWYkr93Cw1kZ37anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkKb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjc
	xK6I8E87Iv6xkF7I0E14v26F4UJVW0owAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAFwI0_Gr
	0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVW8JVW3JwCI42IY6I8E87Iv67AKxVW8JVWx
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU8tKsU
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=kroUk+J7;       spf=pass
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

We will drop the executable permissions of the code pages from the
mapping at allocation time soon. Move bpf_jit_alloc_exec() and
bpf_jit_free_exec() to bpf_jit_core.c so that they can be shared by
both RV64I and RV32I.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/net/bpf_jit_comp64.c | 13 -------------
 arch/riscv/net/bpf_jit_core.c   | 13 +++++++++++++
 2 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/riscv/net/bpf_jit_comp64.c b/arch/riscv/net/bpf_jit_comp64.c
index b44ff52f84a6..87e3bf5b9086 100644
--- a/arch/riscv/net/bpf_jit_comp64.c
+++ b/arch/riscv/net/bpf_jit_comp64.c
@@ -1148,16 +1148,3 @@ void bpf_jit_build_epilogue(struct rv_jit_context *ctx)
 {
 	__build_epilogue(false, ctx);
 }
-
-void *bpf_jit_alloc_exec(unsigned long size)
-{
-	return __vmalloc_node_range(size, PAGE_SIZE, BPF_JIT_REGION_START,
-				    BPF_JIT_REGION_END, GFP_KERNEL,
-				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
-				    __builtin_return_address(0));
-}
-
-void bpf_jit_free_exec(void *addr)
-{
-	return vfree(addr);
-}
diff --git a/arch/riscv/net/bpf_jit_core.c b/arch/riscv/net/bpf_jit_core.c
index 3630d447352c..d8da819290b7 100644
--- a/arch/riscv/net/bpf_jit_core.c
+++ b/arch/riscv/net/bpf_jit_core.c
@@ -164,3 +164,16 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 					   tmp : orig_prog);
 	return prog;
 }
+
+void *bpf_jit_alloc_exec(unsigned long size)
+{
+	return __vmalloc_node_range(size, PAGE_SIZE, BPF_JIT_REGION_START,
+				    BPF_JIT_REGION_END, GFP_KERNEL,
+				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
+				    __builtin_return_address(0));
+}
+
+void bpf_jit_free_exec(void *addr)
+{
+	return vfree(addr);
+}
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022454.3d0feda2%40xhacker.
