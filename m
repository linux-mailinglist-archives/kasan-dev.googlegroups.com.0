Return-Path: <kasan-dev+bncBAABBIGISKBQMGQEDJ74VSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id ED11E350492
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:32:33 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g7sf1467764qtb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:32:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208353; cv=pass;
        d=google.com; s=arc-20160816;
        b=QflsuSvpWI2O9Wu51BOyQvLGIcSk+7+9w2msEG6CRFdU/Vhb9SnMSAjFHBj5F6WpZy
         fVyH+yxkIcf4nbOBWeAsanxytkZEvGCqvQboUi7c9n85DVM2dgg0YJM2QjuLrjwQelt9
         OPvhuJvj+aqv9lEa0+8rspXwhUkm940V5xL4O96EkxzTpHoO1Hu79njX6JAxHiO8Ldf+
         GP3ek9EHApzJGBkqzX+mEDILSfpT+IcJmpzgQhXR71UrcN0oUaMB+Iq5RwCctVyh9QeS
         ajLjM3gm3aSD0chi9um+rGwk4ll8aznC2OYu1yunLD0fEpJpgLte189YyijPqbbJQ0PZ
         QRmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ic81xh5S7UeReM+MuzIjzKYw3qWWmaLYUjaMHKHMokk=;
        b=WUT23y6PX3t49IOU88jckxB3AzyZLVcVaW3XJMPCsRuqqbgbUfUYN0fnGQkOzphZ5q
         /PnSCF47QNaDFYznjgBu7G7lyhZjOAwe3RYz+zBac10VBSozxOKSEMM9acyoQklSaVFF
         +EWHTmTrDzISNhdvOyiRC3+K4WC+p81Wl0jzztm7m5O8X2UnkNnCpu9/1905HDpoSbwt
         fVXkpmc+druTrEfO5ohNzVggS08VztuYrXCMll/F9lXsHSXGPX79u68Zeo7xr6cpbLdD
         B6XxA1xbZ+2tTAMqAdYYZtaFT0QS1td4fIVSg2jkwpFJSKEVwDVt8Zf96U1zh+q1mUWA
         uAVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=Z61ZrDU4;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ic81xh5S7UeReM+MuzIjzKYw3qWWmaLYUjaMHKHMokk=;
        b=CO66l1Sr3qJ1CLLacO7eob6ij/tdz5tOoG9lyzdqcH7YulfezSvmUn6aNlxpAVz7u4
         YKXheR+ncW+660wyzNIbFB6sfAO/b5w8hyuNxNDtbM/vWps0iDqwv3RMtvusFGtZXvj+
         LVpyXHWqp7bEQhgwqrvfwllG9m9ydcc96kyMmMCIMtXOGiuXs8Ofc/GHU95NEfcunw4p
         /q4v2qSYLnxna98CtwQizJWe8Cvi3ehuTkW9JLsNPuleqpKsOxJ3FfC6VVa8Gd3YR1lD
         9n2oFT1xDAPod81kZAg9zsghJH4JSgA3uBSZJU2aYflsN2ShhAsKTo0k0YJby8FyPrL0
         wC8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ic81xh5S7UeReM+MuzIjzKYw3qWWmaLYUjaMHKHMokk=;
        b=r+OeX62S2DnPx28K+fd0ehMTrtMajZ9JWJOELqFkceWCEEHo6PMgj9IMQFloOT0/9j
         8BDR5kPd9h9hGbCYDlVjNoe+xZLM12IIMwFeF0E7FA5q5neMxbsLohw4MrbiZ5K9qLqs
         KnBvmWXaEMp5vSbhnYuPlRVd2xQlr0uHpahoo3SfYICibHFUtzU4SvkzHsT929CSUUqw
         g+GoSYPMISe384lSdfT/69jxqP9uhzCBHdujMEZ6zkz8BTshEHfNDviS/JNhLLQIaM86
         Sz98kSvr0MbSibBhTr5VvssxkeZq7/wAy5OHz0yFkQmpqPw8ThPjuQsKDXF8qUnSSZQy
         8KQQ==
X-Gm-Message-State: AOAM530zcXRyECvXrTHq0wHh4vbD5sVvRPMAJP88AysUET/G5eOj7D56
	gcCq4q3yCAn0eQuoKXLVsiY=
X-Google-Smtp-Source: ABdhPJyg5cRBMTjAtT/jDUqp4CztEBTu9+OPNNmhe1Cou1ylZetlBWHcbiGrsspB0s1yes0BIdBU8A==
X-Received: by 2002:a37:9a8f:: with SMTP id c137mr3976039qke.495.1617208352980;
        Wed, 31 Mar 2021 09:32:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7a82:: with SMTP id v124ls1644226qkc.3.gmail; Wed, 31
 Mar 2021 09:32:32 -0700 (PDT)
X-Received: by 2002:a05:620a:119a:: with SMTP id b26mr4080791qkk.438.1617208352521;
        Wed, 31 Mar 2021 09:32:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208352; cv=none;
        d=google.com; s=arc-20160816;
        b=FAYYRGvcL9k6DvLy7U3R+7mHQaHLGYvmSoDmN0AlWa7XoKD/bVNYRSYJLYdqlgdX+R
         hvyvjtXkPaYnEXDRUUbjo+6DTDy8BqdYsWmAVAPOg6HGtRPPSPuF0w3KwP5I5qFOuyh0
         wygkg3TWIiwZvdjk1bHlvkz4Bml0gyPEk1WJmIrc9DiaKQAQjS1KoXmtFcSQaAmsDw4K
         f8q2Q3PczZeYkV6wjLHQoYBTu2e4u8wSwEElB9+d/RTtth4zgdnh+piLhqkan/yzwpwO
         8lhzeuMrEWIrj2TRDB6HoJR41Klguxp5Gv+hZj44y8w20PYdKXeXdI+t3Re3LNsQX7Zf
         6ZJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VCe4QmQLCwyArf7TfS2RTM//Ze/hAyVnYUNMw+5EuIc=;
        b=0cRMwwkFzIO6OJRXLAFEfM1ZQpgerPpzbYdGDgSry4hrL8n2JGiNG1ntVsLDoAxwMF
         N1bXNtqjU98u95tb+VIThtT9T3hKeiePz0Y6GHyqSaRoes2hG2ZRK+PHIWDFtwiQGalX
         B/8QQjg0/a64iLfRbbJkEbN9jXXeUhYyFYR6MQ6AZfDIhQcL1r4BQE7oIODoCV0PRupd
         e5R6tLw+eFrKIA5s5S+K1LtWjMzuPMBFE2NQYTBB9fPbNJBzlVMQhI8uEVB0FKtYWVwc
         9Frq8BZZoqTCI8k7CuAGcZ7smhoLY8Ybp63M58cW9r7xSmdbn8/e5ZAZZ4W9GNFVghrW
         4kbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=Z61ZrDU4;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id k1si177917qtg.2.2021.03.31.09.32.29
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:32:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygB3fkIVpGRgrr16AA--.5145S2;
	Thu, 01 Apr 2021 00:32:22 +0800 (CST)
Date: Thu, 1 Apr 2021 00:27:24 +0800
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
Subject: [PATCH v2 5/9] riscv: kprobes: Implement alloc_insn_page()
Message-ID: <20210401002724.794b3bc4@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygB3fkIVpGRgrr16AA--.5145S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFyDGF45XF4kJrWxuw48WFg_yoWDGrb_C3
	WxKry3WrWYkrWxWFyDKw4Sqrsak343KFykWr12yryUtr1DWr13Ka95WF45G3sYqr97JFyf
	GrnxX3srWF42qjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4AYjsxI4VW3JwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
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
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU8S1v3
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=Z61ZrDU4;       spf=pass
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

Allocate PAGE_KERNEL_READ_EXEC(read only, executable) page for kprobes
insn page. This is to prepare for STRICT_MODULE_RWX.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/kernel/probes/kprobes.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/arch/riscv/kernel/probes/kprobes.c b/arch/riscv/kernel/probes/kprobes.c
index 7e2c78e2ca6b..8c1f7a30aeed 100644
--- a/arch/riscv/kernel/probes/kprobes.c
+++ b/arch/riscv/kernel/probes/kprobes.c
@@ -84,6 +84,14 @@ int __kprobes arch_prepare_kprobe(struct kprobe *p)
 	return 0;
 }
 
+void *alloc_insn_page(void)
+{
+	return  __vmalloc_node_range(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END,
+				     GFP_KERNEL, PAGE_KERNEL_READ_EXEC,
+				     VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
+				     __builtin_return_address(0));
+}
+
 /* install breakpoint in text */
 void __kprobes arch_arm_kprobe(struct kprobe *p)
 {
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002724.794b3bc4%40xhacker.
