Return-Path: <kasan-dev+bncBAABB76HSKBQMGQE44QNYRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0164635048A
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:32:01 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id s6sf1900419iom.21
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:32:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208319; cv=pass;
        d=google.com; s=arc-20160816;
        b=gdrx49Gov/4koTGyQRToLgayHCMRs8foEu+WMRZ9+Ov5L6/ZUER/PN/sT5BvqK1pUO
         cpqD7ObX7DphK/fxAHkuGVVgd9nHt4pchlsjlEQOkKLtXA4Cb0wyeVp5XtAAmrH2WIuz
         PwYi0HRmR1zOVOaeIbFWOCOwtnkgYXcxjdbr3xWcRRpiw4A4roxlbQO6ol/+zc44RQpr
         BhJr/VwFbAmCnflo9tqsVA8vwdakkGdOeoY3kLCaBdC7FaWyuHysd8O8FZK3Mk0gchEO
         aFy0vGCr+dJRQMAq7rPeB6YrHr7+Bey0AdlPL22q9Mgo2DqgjJDt20iLbb0YU3e6scKz
         s59Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=JG1eXFDzWh1K1dJiaZ331pEjgjcBGc/iDI1UMw5RyoQ=;
        b=eznHsMz/Xb/6J2Sm8/9qiHpLe94Ql9lZjvG1NpoKhLTT2NqLVWR5wYfjmFe107lOUP
         2/c/TqgzvHnms9bh5NV9Bi2aSwlsQKTSXUxhWoCowXBLxRu7cZjaPnU6dc59ZVvYWm0H
         XIvxto3V4/nIUZPCGSGBfXTcUW8pA9QDpNu0JVufYgUu5ahpkubDh3RoFIKCLx7RNmY5
         qPgMy20okv7QP+2G3aNZMNnQpomjnxAC6iSSZ7aR4UcYoyOTg01+0YfATQkiY2XqXZQR
         j48mKGPxn8prfg+08/c0A9Rd2dX6ldvt1jrv5bEO+fppTrfWkdaib+6ynXtbdkojEbXa
         tb5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="Xo6Hhyt/";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JG1eXFDzWh1K1dJiaZ331pEjgjcBGc/iDI1UMw5RyoQ=;
        b=WwsnYXffPlZFPRu8liuN0ayJTmNEgmOi/oaiKDJN36GzNUkh6qaBvKsgIiSdqTqjQd
         RJx6n56qn0AIC2MVx+zw6+maCNpVascR77zjGgAHPZoe6oEphtkp2MLmFH3s94QMjwr3
         XTy4jz+nG0MjdqgJoY4AI0hINDHkMxRYvzUC3GEyBEE84L+lbXN0n8CBDcchcOaPu4Ne
         sJf0gXA6YMd0am3+EbZuxFkPgNF+SYwW29+dqUrBR0BTnR6TkQvroEWC4HRp/HPlTHYH
         65Xmd1ERK8KQjaHWUE6aEBg0h5n9KI3Cr9y0B+0OMEmuIqtMTie8zTpgHYi/NxYC3iVD
         hiBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JG1eXFDzWh1K1dJiaZ331pEjgjcBGc/iDI1UMw5RyoQ=;
        b=amAQBd2kCFz4zEreg0XgdgM1eQzMQ0deQqaUWKHNEcz6Teu3ls0YIOjUP7wPfG4PBb
         AWUc24kpgHwi+k43CbfaQQevA1puNQ+RK/+4+6xGvo2OFZgZt/giKwg9J42k0qva2Dqh
         D54Z/CK/Vs000ZpVBKY6umBPRYQ3Oa2BHsEkFz9ctyeQFibT8+iD6faLO8GgH71JVOpA
         bboDujTnx4VjGTNJXRS3jPLaS3qxvhOg+zcfPFV38mCNJ6SvA9+faTA9G63EamYsUcSg
         bZ31JcFF/DBeDh7wslp9V7whPvKboCKXXOcN7jnPSRK5cq/xmZurIncBBmFLvK9xoscL
         PZWQ==
X-Gm-Message-State: AOAM530a3xOy9nINaNToaOLpyq7dx8Z+11RmflgT2kpbREui9FKdGO84
	IrgINUILh4qedHnYHHcX8Gg=
X-Google-Smtp-Source: ABdhPJxwhIzIjRMgRb1pjTxBVl9Lku5acX0pzDeIog+AUKqxitSgBF2oz0tP005lmb09ZW12veAmcw==
X-Received: by 2002:a92:de01:: with SMTP id x1mr3274971ilm.109.1617208319726;
        Wed, 31 Mar 2021 09:31:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a08:: with SMTP id s8ls601563ild.1.gmail; Wed, 31
 Mar 2021 09:31:58 -0700 (PDT)
X-Received: by 2002:a92:b05:: with SMTP id b5mr3329489ilf.240.1617208318790;
        Wed, 31 Mar 2021 09:31:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208318; cv=none;
        d=google.com; s=arc-20160816;
        b=USkP1urwBELtJCGNTzJvBsdKcn05eD3Oowwm7VfEo810MeMkvu6X38VIk9l6O+ajPm
         7e6XOmxWJIoDhgIlzK4bZ7tDPcjP5r41QKil+TDPMAdgKaSVxKZvuS1xguAQyrv0kWPP
         nJxMnzzTIL8nEjsy0w/SktP6MVVzn83Tl5eRKNBMF78lSx+owx0jd9cAW3Cx1ATeUzEP
         kntrT221g+YwS6Z42eNZzVLmwvvjKSHk78gbEdpBG8OEJX9U3fxyWUwLbZ3GsJBIthQX
         3CCLbwuvIl0pDGF9NAQOJFG5ucXdVClt0/nxSX6w47/P0Cc0iv35z5RAdas/35dDZtwf
         l/RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=X3JnzAWB/wP2byqIVYcRzkGaaPhYaCeo9nv6lfgBPe0=;
        b=ETpGm4tbQ4p4d1aNgpN6XGTQ+to8oetrRgtbHbF+cdm+ShqnSw7oysYcarE5a8wG8i
         ipXgRTAZaYAtnlzo67bFKQZsVDabydQm8cfzFRmp6s4WAogK4ZvHHdQFEpdmpUkOcncL
         Q9GsZ74TUO+JPcNvz1GDePlh4Uwr5k7G2Iv3qMiFhA/qw/PxWXg2JURbLksrq7TbAj3T
         4YoyN94hLlrICcV6H+mQsmCUD4C/bbR8RTz0rUoz3zkgTozzOpFmxKVl8c9PA68ZDEBJ
         lussTaedQq0ve7nb4Fl8As5GgwMdgXi0TufSxGl0Goh5LYTq8a60Ac6EbwqtASgwPoAI
         2RGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="Xo6Hhyt/";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id i2si169651iov.2.2021.03.31.09.31.56
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:31:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDX30v0o2RgKr16AA--.16474S2;
	Thu, 01 Apr 2021 00:31:48 +0800 (CST)
Date: Thu, 1 Apr 2021 00:26:51 +0800
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
Subject: [PATCH v2 4/9] riscv: Constify sbi_ipi_ops
Message-ID: <20210401002651.1da9087e@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDX30v0o2RgKr16AA--.16474S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxuF4kuF1rWw17ZFyrJFb_yoW8tw1kpw
	4UCr45CFWrGFn7Ga43tFWku3y3K3ZrWwnIy34Yka45JFnIqrWUAan0qw12vwn8GFyDuFyS
	9r4rCrZ0vF1UAFDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkEb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjc
	xK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG
	64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JF0_Jw1lYx0Ex4A2jsIE14v26r
	1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwACI402YVCY1x02628vn2kI
	c2xKxwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14
	v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkG
	c2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI
	0_Gr1j6F4UJwCI42IY6xAIw20EY4v20xvaj40_Gr0_Zr1lIxAIcVC2z280aVAFwI0_Jr0_
	Gr1lIxAIcVC2z280aVCY1x0267AKxVW8Jr0_Cr1UYxBIdaVFxhVjvjDU0xZFpf9x07je7K
	sUUUUU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b="Xo6Hhyt/";       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002651.1da9087e%40xhacker.
