Return-Path: <kasan-dev+bncBAABBYVZRCBQMGQETVPY2RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 674B234D72B
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:30:59 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 50sf10068750otv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042658; cv=pass;
        d=google.com; s=arc-20160816;
        b=EYZIINwdj3gNN7uVmaClxCXATzA+l3aF9S3O0GtBzG9hvizzpUMGQ6xdHmJhV2vZp1
         11FdMRtsVN1MCkPc6TKy2ugpdNbrHJ/yTUmKtfS8wO0wq2vxRooow2GqB5hXbp0mTTGW
         SDBgK+ILPcj6lb2qFXWU/UbEgdj5I5rgJ2l8/f66wEVyFJ2rWsFZk4bVpZ8U7w2eKJ8D
         66J7+QKgZ2Bhg9QWrMW+JTE6/CQie+XqKHJSebhMmFUcesP8+xc7dJtDZg+kTHRBDtky
         IQTG1dOc6KV9xsAdBsfmNGi8lNfV5j2j7U0WyKVkeToVHb0YnAuoKQfyvxDiz3hyYAEo
         6lFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=dFKFcb85lUqVxlfIC4fi3H2dSquKHjbssO/rVmf/sMY=;
        b=VGwgWKBW4dgnv3wz5nWDGdqA79y7gjdVf32Mm/L+WVzaby9w70LmHraDqpRBI/jRbC
         E5IBrnxocd4isVtxBLkqJR7CCa34/U8hbahp28J3faW62LqCybxEDXeMZ2pCIvBL1SlT
         tp8p8tYRNtykEAYM+VFp6Hidemrf4mUeR5yQ9M9dEbY39F9VO9Zq15AulLVm6LfiMpOa
         vfDB4wdf4GCuACqVEPnFHLCDzaFot9sv/FZqebPE9H+rQo1qh9Wfild3QUYlfgU5ErAU
         Rp4I4iOAUIl8SGC3Dmgq97agSOKbI7Q8I6eDQ3Fxef4zuF4SLNy1JmIU4+sqv0EvF/Vt
         pKFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=gZBtfH2u;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dFKFcb85lUqVxlfIC4fi3H2dSquKHjbssO/rVmf/sMY=;
        b=jcr5LI63f7R3J05C+4TDgpkafTfl3VAL4Puzg4XjIpEz1di5LzjW3c7D/GGyOz0CrP
         R84haNozxftbixJ9xGO6kbmnVMKqzpVub1ZxJsd5YGcaRWHAPafN1vJdMeDgv0dc33U3
         NHQW0pUI+BjL3YbPGtzW4j2ClXeGhbOETPtA0M8lvK1IcidPBLNx6Y9hIe1NLRiGiIyz
         QkhXFn7ksk+b+RR4XlEn5q/yIbPGGq5A0WFK/u6f+gWZbMew8RwWZ3FYlQo3CYCaUToz
         8fWamV8/JvBEW6RI9mndrelT66aql3T0clgM4sRr0M/j1GPPnjWh8JHaf6zqcZKWL/m7
         yRGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFKFcb85lUqVxlfIC4fi3H2dSquKHjbssO/rVmf/sMY=;
        b=f69eXdPYV2z6ijupeoIxN0rwEMVCipQlfvG/eMvfhCbzkA2GtEVf+ZzV70bxHmA7Ee
         vkPFEcglIDjtgqAj9FVmrW0t8Fdyy2CML6UVLGwfIZXv3JFKBKsxAVQJTr0YMd7heoLf
         NGaRhSlI8UMUIh/VVIykfIcNrRB/DRAvWveo9V+mgPDvRlp5Hh0SvE2WGsmgty+okTEi
         hrr+t4kU1cCu+LUaKgXG2abUawGFBW+oOUcQdy0CPrq/sWEpz3Hy0EmzbaGeGPFILnlS
         94IJqwmXppqg8+lUKqkuFqEQUJibKUl9iCaKZbid8xXsK2PAZdui4QK/hSM/J93cmkDS
         Dmqw==
X-Gm-Message-State: AOAM5334Xn4MXr/V2BQPxlDyEPNLTb4uYjUubJjBxMI+rYr/JSNWYCIA
	IwRHkhljJroVUOi6oUyI++g=
X-Google-Smtp-Source: ABdhPJz93iAixpND6a+CEiDDDkfJWKhps9z2t9rix7ak2K6BfIC+i6JT3Z3uzlAwQ2VpmTanakCJqA==
X-Received: by 2002:a05:6808:2d0:: with SMTP id a16mr306610oid.83.1617042658303;
        Mon, 29 Mar 2021 11:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:f0d:: with SMTP id m13ls3977697oiw.4.gmail; Mon, 29
 Mar 2021 11:30:56 -0700 (PDT)
X-Received: by 2002:aca:3046:: with SMTP id w67mr311524oiw.57.1617042656457;
        Mon, 29 Mar 2021 11:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042656; cv=none;
        d=google.com; s=arc-20160816;
        b=fm/8af/AAvzsIU2MgL7rgoIPdqf3dKi99Zy6EOwSg4Rk/h5dOZtBkxlM4o9r8HiRr4
         qL8RkhlwsT9ShimXUPnIfiyqy3RIyJ5hUJASE7+tuPSfpCi7qZTmjWhlUgvC5I0Z9KFc
         0HY8oSBFfZldesFSMlOiTERmH89igFUOAtN2mn4aB6EUIcMaNONoQTdFUONqwjCOe2CO
         K52ie3rKE58u+MCrtzK0pPSunx3epb88utBaSVJlULOv3p74hv6fV4bhvC99/7WldKFI
         LKQFsS/E1GVAqKtzbLIDZx5asToOE4DaZ5ECk2F4F37VTKoBQHgkRFnSQox9pcR553JN
         YAmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ik1VNJyYjBgUbqJ51FNWR51hX8kbricRWlnztP2ATL4=;
        b=vU04nA3LelfDNKygGy+uHLPQBGFIDTaApYEFfcZVnLPUFbe1sT+GGUoFQ5bXfvW4NE
         UuHZrjmEmr9g/qvXHjmviQEOlbIqzgDXd0bAbpoOsOi23I7UvsYVD7a1qNWOKlnsA1/n
         NuwfHQC0IYVCvf29yWw+bvhgTHOLK+5QZ4jiz82pS0k204EUnX7NTwF+8Jj9CLARmdwm
         gEXvVHl5mt6N57Ll1LX67mKvW95NBfej+vcwR/E2jgysiD5iqm7CcS+GtinxyUIzoUMS
         5h6+riz8x+G3QL1SiLK+dJ5cKZhqfQ+5mNQe/1CF+tNGoLw2ZheJ/2wjDHXIGd/x+M6O
         rkIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=gZBtfH2u;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id y26si1266757ooy.1.2021.03.29.11.30.54
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygB3fkrXHGJgyvdpAA--.50159S2;
	Tue, 30 Mar 2021 02:30:48 +0800 (CST)
Date: Tue, 30 Mar 2021 02:25:51 +0800
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
Subject: [PATCH 8/9] riscv: module: Create module allocations without exec
 permissions
Message-ID: <20210330022551.58ce4ff4@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygB3fkrXHGJgyvdpAA--.50159S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFyfWF4rGrWktry5Wr1xXwb_yoWfWrc_W3
	WxJry3WryrKa1I9FZ3AanYvr4Iya4rGFZY9FyxZFy7Ga4DWrW7t3s8ta9xuFn8ZryfKrWf
	GFy3Jr9xuw42qjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4kYjsxI4VWDJwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM2
	8CjxkF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Cr1j6rxdM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1q6rW5McIj6I8E87Iv67AKxVW8JV
	WxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Gr0_Xr1lIxAIcVC0I7IYx2IY6xkF7I0E14v26r
	4UJVWxJr1lIxAIcVCF04k26cxKx2IYs7xG6r4j6FyUMIIF0xvEx4A2jsIE14v26r4j6F4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxUciihUU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=gZBtfH2u;       spf=pass
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

The core code manages the executable permissions of code regions of
modules explicitly, it is not necessary to create the module vmalloc
regions with RWX permissions. Create them with RW- permissions instead.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/kernel/module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
index 104fba889cf7..8997b9dbcb3d 100644
--- a/arch/riscv/kernel/module.c
+++ b/arch/riscv/kernel/module.c
@@ -414,7 +414,7 @@ void *module_alloc(unsigned long size)
 {
 	return __vmalloc_node_range(size, 1, VMALLOC_MODULE_START,
 				    VMALLOC_END, GFP_KERNEL,
-				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
+				    PAGE_KERNEL, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
 #endif
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022551.58ce4ff4%40xhacker.
