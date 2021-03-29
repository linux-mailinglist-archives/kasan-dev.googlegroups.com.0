Return-Path: <kasan-dev+bncBAABBSFZRCBQMGQEOXCGUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6980B34D725
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:30:34 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id g6sf11494118pfo.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:30:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042633; cv=pass;
        d=google.com; s=arc-20160816;
        b=JrmYa4/7mnNbQ6SQbuxWRMcFzR0994jFt5DAz6CPi+9JP8P0o3W1bPOMp3QN4VhADs
         9ai4Jx8hoVIRVaWA5jIhgP4RLSL0Bf841/bSbHKiZChPYIr8pVFyhnbYQnulIW8OXHDq
         K15yEQ82t3AmkZATMX5xvqh7/KPe3FHrW6V6Q2RryaR6kXfAw8t+Wll1XaDA5faHGH36
         w9TBhWGrPBrrGHfaOKRaCHeG+fcfHYrbBLITMkV5j/EZ7P6TOFlYSSA1FRioZdANfaCw
         iz22irh9SKTnK4kUKnT3JclQ9WDz+NYROHivSz/ZxK7j4nRUgRC/gigPnaCA1XjLkZ92
         XtJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=RMOyG9ldCYskqh9IWFVD+AkF/VG1zaNlTSgXlWzpWCg=;
        b=SKp/QDtWHk+pBIkaAljiDOTpA8AwH/YWL+whzbmQwGYfYmCSEbzf7HLITjy/5cTQ5I
         Q2gnUx8bd3kBKKsCr1fXOqUMAqOu8mYS2b+Yvye2r4pkntHwEgckDxiPA8jUjUbBa/x8
         tgLlkF0gDQQZBh+kEUOFAnTr/OTcfoG9NV/k/TXag9LkYl+XHrKTFTRu84tyDQa6OUK2
         HXB1YmULe6iLgmg0qowCso5wFg/ZbimPx2lAAC5w1uFndGPvuBgOX74YZPw+0P28D+gW
         iNfe9HlXtqaTRTRRl9H3pCD3x6BDGkVGBPT5NG8YsnUvsXG7cAnJKYHVP6PjVA4VIBxB
         WfVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=NaS9q8tO;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RMOyG9ldCYskqh9IWFVD+AkF/VG1zaNlTSgXlWzpWCg=;
        b=M28cjVfAHGphHvJq6rIHwhJCefbjA0ISM38JHLP2L9p3rvPXancGjXSCUjFlwb6+YL
         dsrBT728vJs3cmZ7zEHcEdPj7bY3VXDxrlZiA+F1XOahX+ayvyrwFsGLRHGN+ZnY7tQH
         WQt5crKaBrqa0zRxgSkoWDfym+rDyv3pxD8tJxtmAvsLSTB1HyrjjQU+jGBZiQTZ1O6g
         buy4bRLtAykPQzi3lqeC21eywGY9fjUNbfybZfqmWuRUJ/lc2+FArzS62Ke+gNLxwNmj
         KFHg9O6hkNkgdV2YJ34Ms+k41ymMl5hNOfmZOutkt2EjzxIJkQ7BS1UxgoqcrpXb7+xf
         L5XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RMOyG9ldCYskqh9IWFVD+AkF/VG1zaNlTSgXlWzpWCg=;
        b=gyY3FfYTFhHz/kQhe4gYieO2VNaxt3RDUkn5q6om4y9/WmZXUh9xvvYh7Mpsm1SjJZ
         4RLI1O4fyqHJ/AxAIHUV5QdqXMeAzx3kqcDEwL0JUGw8MfTx/V1mPmM6OJyZzV1oTUNO
         1FCWI+BLJYsKxYbe+JRekzEQm9bO7aXSjYSmBYcF8mfcBlhOkgyGXUuHdcNlYs/GWdLO
         o5mX0SxGvgMdYPX0Mur/f6Tf6fLwuj+YmfD3y34SxtUOlOKGQ1GQpFBQYKyIv/HBwnEB
         qwo8dzFRxECWfOmkcrK6YQSccyeWNP3Z07vK9fD+HO7cp/NbNg7E5d6TLMn8tSzOFHMf
         sFjA==
X-Gm-Message-State: AOAM533crSGdwjKTb5eeiaJpjzTJvuC1p9RXi7pia0KALPykuSJ0UuB2
	5ASLL6pm7lp+5Cv7ESF4aDc=
X-Google-Smtp-Source: ABdhPJws3qxxa6yr2MF7W175zqs6uI2N99osb29AYET+Z4QPm7q7PXYiBZtbyABCf5X9CxMiLUG/qg==
X-Received: by 2002:a17:90b:4a81:: with SMTP id lp1mr445365pjb.154.1617042633043;
        Mon, 29 Mar 2021 11:30:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eacc:: with SMTP id p12ls9383646pld.11.gmail; Mon,
 29 Mar 2021 11:30:32 -0700 (PDT)
X-Received: by 2002:a17:90a:cca:: with SMTP id 10mr419683pjt.103.1617042632542;
        Mon, 29 Mar 2021 11:30:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042632; cv=none;
        d=google.com; s=arc-20160816;
        b=MQtXqrsfeLGdSKbgkbXbhPymHiiU+bHK5kklV5qAR5jv9maKMo+9xoTsBUECYiXoHd
         AVHQepAT8008i4o1kp/fOFsYyHp+Z4KXzUb/ZUob72UwD9iZSGJD4flJHoh89X/PpEDS
         ke60EI3Pml99/hOyFdgAGMs7vWSM+IsIa1lMdWBGc+KIjQAHTleRX3M3wn/L3ERe2kkU
         Il8Wnq+TUGsxhtY6TnSt6+2ODjH1gvay9RNziG6d83JlZUINSrlTHOHPBlwwedFx1dV8
         yRoKTM6jflJKHd518l2h8x/bL09IGz6zUYhDTDuSfbtQM8TXxCPjLByBYD75e0Ugr1Jg
         9zrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Najrrc9y+/48DUXx4/endqtIY6BJkPiOWTuivmMc0is=;
        b=Z9ot9gFTs/k00HWUg9E26HlKKdmf+TH4MuG/tawZWEv1FmEYch8OwhX4IIjJlfm3Rd
         P8Mpa0LeoxUWvB1AUveLFncPnzgSijpq2ai4vYc/wcO63a1F6JwAtZKBeDJhhqgYCixb
         KEip3J08hDAY/9UJrDfRA4UyxGPyi9Xe3rwlHAHkx88zUo4gfy9ZjUM0PWpMMejcHzmH
         cQbfA6aEtJbCDfYkceqN4jlfcEMpF5AtHDDLaLanIyu15lZIGQwJy1TSC3EmqW60/0a9
         2ehb40lznboeDv1jwPWE0eusVt/5fGQL+6qSKosAC0H8GuPUnfS4U4m4p/rOGEAeJuV6
         rtQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=NaS9q8tO;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id c3si1173830pls.0.2021.03.29.11.30.25
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:30:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDn7Ei5HGJgEfdpAA--.51311S2;
	Tue, 30 Mar 2021 02:30:18 +0800 (CST)
Date: Tue, 30 Mar 2021 02:25:21 +0800
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
Subject: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
Message-ID: <20210330022521.2a904a8c@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDn7Ei5HGJgEfdpAA--.51311S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFyxtF45CF1ruF48Kr4UArb_yoWkKrg_Z3
	Wxta4xW3s5Jr4xCr4Durn5Zr1Ikw1FkFs5ur1xurW2y390vr1ftasaq3yrur9xZr4j9rW7
	WF9rXrWxZw42vjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
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
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=NaS9q8tO;       spf=pass
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

We allocate Non-executable pages, then call bpf_jit_binary_lock_ro()
to enable executable permission after mapping them read-only. This is
to prepare for STRICT_MODULE_RWX in following patch.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/net/bpf_jit_core.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/net/bpf_jit_core.c b/arch/riscv/net/bpf_jit_core.c
index d8da819290b7..0d5099f0dac8 100644
--- a/arch/riscv/net/bpf_jit_core.c
+++ b/arch/riscv/net/bpf_jit_core.c
@@ -152,6 +152,7 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	bpf_flush_icache(jit_data->header, ctx->insns + ctx->ninsns);
 
 	if (!prog->is_func || extra_pass) {
+		bpf_jit_binary_lock_ro(header);
 out_offset:
 		kfree(ctx->offset);
 		kfree(jit_data);
@@ -169,7 +170,7 @@ void *bpf_jit_alloc_exec(unsigned long size)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022521.2a904a8c%40xhacker.
