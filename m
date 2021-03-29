Return-Path: <kasan-dev+bncBAABB2VYRCBQMGQEHKYHIIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 4675234D712
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:29:00 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id y5sf175353pju.5
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:29:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042539; cv=pass;
        d=google.com; s=arc-20160816;
        b=LhtukR0seVk9M3goVJfth6owRmQjGLYOFxm0CbMP7zF91abGkliaNDRvrpC6B9faRo
         FC1dBj+bxTcBtKkXyI5JT2tyI3B6QHSHlQlvHskPDObb5Nrz+zco+QH7FXjHn351kfg8
         b9vCErqyMpBu7dUyDPWJXhSSv3pJLYCOGm9wMxP7pYU5Af+qZ6nnTvGgFahZdEl1XQbe
         zkZb9LnnBimS+jYVzdxFkd78CFPk+E1M/tpXn1gLeMkksZDnXXT1KAU91uzA/IBLWT9H
         mTsMDNiI29bJ5+c4kwalTh8YGh2Rm4O0Ug6VrOZnBVgSGQB82lGD06tW0Hldkgm8jzGH
         1Umg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=whUCLCr8noYrY/kCswRFRklCLRPiZDHeHKBrh7n26F4=;
        b=j/tAbEaGeGnrQWEGNdfenaJCjAHHO3uFXH2gGhR46RSj8OB3SzXFEr+vtRsmuVqOY3
         q0t374NPKyWRmjk+Rkr7B6P9X5kBQ/h3PxBmA7dGWRleKFMeuxHN1EahMBOZqsQ3AjkU
         M4KtGk/Kkm2t2nOTBZzVfWiZQi1TRLe1KsBp9xHo+jrofnvv+6vV5gGIrTIeQwogptpX
         m7Kp7xL3vB9njEPBOWg2Lb3B7wEFpbB3WGMw1lgEW0DIMXoCZekQXPnjiZASPNaJF5lB
         i9Nrzhuyzi6n1QZCQauDPGFeiIlB25SNUONGFotsQZSYU/rkGIOzSunDs7zYpsiuyUlc
         fLtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=ciYwCT3N;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=whUCLCr8noYrY/kCswRFRklCLRPiZDHeHKBrh7n26F4=;
        b=UwkokJI+XbcvDnecxGxj522NaSmV2QAf2fGz85i+uQq66Ppmwl7fBbcLFxprFC3Fcl
         Gykd4sVRRECY60a5EIFsdA91FdhMVdZZpzlSkqxY+zPQsRANhrwzDv7VTAYam0+RLBxq
         Z1BiafzaEOWbdb81ziXkMgPvMEFP3WjOtJ2L8K6rzrepTqYLOfZUlQV+VSzYLhTmmiyj
         fs8JLlLJLoXTkbb5wrUbX6MuWiKsXLvKnlDze5UKYm2RpP5qiq5R3DLtOnBFgmfsuH0T
         pM03e3vJXxNhYdQC7o+S8WSnPc2E/6xmJyJK6zhMqKfL773ODv1Y6STHEqafVH+GGOL7
         49Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whUCLCr8noYrY/kCswRFRklCLRPiZDHeHKBrh7n26F4=;
        b=oAa2q0lSYiBRqJ1m7luiEDb4Cr13Er1mJGgIIM/EL4jAl6TaxjEnqxbSfccn8IzvoN
         wYkZ2mPzlJwfsT4kGScqq+p/VxzI5XVprfOA7O/KSOOJC0F58lTFznQMARkYtIgIaeLE
         6IqJh1UN8cBEIFPtNzbYsQqxcrcv6NBHKFV/J1BFq0L9idFIjtqxnj13Dj2ACBjfzMtl
         jbARXy9bOQEpE6jlhGJDm++CgBvt8g9kLTC8ct4viqDCAJRtOllds4gEvP8m0srCvtBo
         kUR1nZgLX7Dc6T4vOysS+fNrint/SkbyqPf3qvdmobITU7YEos2vHDKkToASCUGpg0dT
         XLoA==
X-Gm-Message-State: AOAM533mfq5Ysyf8fh6d5nC0yisutIoeLr60YzqxpyDQW/5zjAVTZz5v
	TOje719jjUqNr+tfAccZ3DY=
X-Google-Smtp-Source: ABdhPJyXSLMUvepea6Nri6u+fzwKFJg9EM4nPfKQwJG8gOfrCPIUtAk8E3LO1K3mqWXc3uQOgUYvQg==
X-Received: by 2002:a17:902:74c1:b029:e6:ef44:51ee with SMTP id f1-20020a17090274c1b02900e6ef4451eemr29552951plt.14.1617042538739;
        Mon, 29 Mar 2021 11:28:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:76d6:: with SMTP id r205ls1892090pfc.6.gmail; Mon, 29
 Mar 2021 11:28:58 -0700 (PDT)
X-Received: by 2002:a05:6a00:13a3:b029:203:5c4d:7a22 with SMTP id t35-20020a056a0013a3b02902035c4d7a22mr26194363pfg.22.1617042538297;
        Mon, 29 Mar 2021 11:28:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042538; cv=none;
        d=google.com; s=arc-20160816;
        b=dLOio0uWrbFdcn8sscYXp9aLMxHw+ohIrs7xRIO1S/NI2qGZcBTrfJCWw7y0jBgYqG
         fy+MRTAeP8HdnP9QJdKjst2TQq/ck6JJ1RcMl0v6U/DkZxNBJUW7265qgH9BqN0eq41N
         gzCBNQZnPvSpCVcAt0CW1m32VnmBIpvOBP5Lnsm+Z5+5ZAf7DanhrYVFHcGxmBpsdjyd
         gopotivGGjDvUwd4+ClLLEn5iE1D1Cg+zfsvvUd4xsj1CnY1dr9LoIjovuIvMNKvvEIO
         WBGULRZk+lyy7RSL5xhxElzxFY2TrcmBs7Z3xJ9QEOZR3BvjuLssXKmI8fL8oAgDvQvV
         R5WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=X3JnzAWB/wP2byqIVYcRzkGaaPhYaCeo9nv6lfgBPe0=;
        b=u0QHA6E69I4y2jiHDi0lIdoBAWOehI4Y3IVh7BsY7mDxmXv7HRgNrBrNoL+85KaSF2
         JtQPnqkDLlcIRAO3AdtmDWmGAtGOcL6eMUtfziHDUlQXI3NrTymaA6adFpDNmKUmGyF6
         6Cs/CeFvvZNU1ZRcBETPh+U//QAtu0vP+xZhj6I6Wfn5jAFNfdCideeWQ8XVS1y3ShXO
         gCUhNNSzO+90WsGCzikIPimXwbeKwd+B84Zo49l8b8QOp26c9eZTXbH+/2G6WZ4m7w+/
         bLIGB9LFcLDbeswPsLPa1nh85epydIMUtCEDTQP7Hi6v/Lb7n5dQCM8GE3be8WBZ6EcB
         9uAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=ciYwCT3N;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id f7si11394pjs.1.2021.03.29.11.28.56
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:28:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCXnkpiHGJg2vRpAA--.2864S2;
	Tue, 30 Mar 2021 02:28:50 +0800 (CST)
Date: Tue, 30 Mar 2021 02:23:54 +0800
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
Subject: [PATCH 4/9] riscv: Constify sbi_ipi_ops
Message-ID: <20210330022354.385a9a52@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCXnkpiHGJg2vRpAA--.2864S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxuF4kuF1rWw17ZFyrJFb_yoW8tw1kpw
	4UCr45CFWrGFn7Ga43tFWku3y3K3ZrWwnIy34Yka45JFnIqrWUAan0qw12vwn8GFyDuFyS
	9r4rCrZ0vF1UAFDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
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
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=ciYwCT3N;       spf=pass
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

Constify the sbi_ipi_ops so that it will be placed in the .rodata
section. This will cause attempts to modify it to fail when strict
page permissions are in place.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/smp.h | 4 ++--
 arch/riscv/kernel/sbi.c      | 2 +-
 arch/riscv/kernel/smp.c      | 4 ++--
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/riscv/include/asm/smp.h b/arch/riscv/include/asm/smp.h
index df1f7c4cd433..a7d2811f3536 100644
--- a/arch/riscv/include/asm/smp.h
+++ b/arch/riscv/include/asm/smp.h
@@ -46,7 +46,7 @@ int riscv_hartid_to_cpuid(int hartid);
 void riscv_cpuid_to_hartid_mask(const struct cpumask *in, struct cpumask *out);
 
 /* Set custom IPI operations */
-void riscv_set_ipi_ops(struct riscv_ipi_ops *ops);
+void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops);
 
 /* Clear IPI for current CPU */
 void riscv_clear_ipi(void);
@@ -92,7 +92,7 @@ static inline void riscv_cpuid_to_hartid_mask(const struct cpumask *in,
 	cpumask_set_cpu(boot_cpu_hartid, out);
 }
 
-static inline void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
+static inline void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops)
 {
 }
 
diff --git a/arch/riscv/kernel/sbi.c b/arch/riscv/kernel/sbi.c
index cbd94a72eaa7..cb848e80865e 100644
--- a/arch/riscv/kernel/sbi.c
+++ b/arch/riscv/kernel/sbi.c
@@ -556,7 +556,7 @@ static void sbi_send_cpumask_ipi(const struct cpumask *target)
 	sbi_send_ipi(cpumask_bits(&hartid_mask));
 }
 
-static struct riscv_ipi_ops sbi_ipi_ops = {
+static const struct riscv_ipi_ops sbi_ipi_ops = {
 	.ipi_inject = sbi_send_cpumask_ipi
 };
 
diff --git a/arch/riscv/kernel/smp.c b/arch/riscv/kernel/smp.c
index 504284d49135..e035124f06dc 100644
--- a/arch/riscv/kernel/smp.c
+++ b/arch/riscv/kernel/smp.c
@@ -85,9 +85,9 @@ static void ipi_stop(void)
 		wait_for_interrupt();
 }
 
-static struct riscv_ipi_ops *ipi_ops __ro_after_init;
+static const struct riscv_ipi_ops *ipi_ops __ro_after_init;
 
-void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
+void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops)
 {
 	ipi_ops = ops;
 }
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022354.385a9a52%40xhacker.
