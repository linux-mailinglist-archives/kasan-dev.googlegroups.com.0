Return-Path: <kasan-dev+bncBAABBBNZRCBQMGQEDM5TXDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DE93834D717
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:29:26 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id o16sf170032pjy.9
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:29:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042565; cv=pass;
        d=google.com; s=arc-20160816;
        b=rQJLsRSnaasZj4AGVRSBtTjnon7IzLIkR59h/ASxXbpiWnwl3ejYkVmrxI9+EyD4Ip
         oc0BDI8krInhhelK0Qm5kBcQC2n99RQQDuMdKK5uzNazLG0H48KWG35Cryxz5MMs27oX
         UIdNFaDx3orZw5gJHsH43r4ZaFHRCsx0gAvLx+VIMmqFX8SBMkVBSUDI5HoSRjpcE//S
         ptLlkGHN8oRzGk3QAcUxBCEKGo1Q4+iY3ZCmcK5kiWmf3/yhxk1j/Ni+rtKp2hMF64Ae
         az0h+TfCOAcUnVPSpHT21/eBr67JoznUIulse2xaPczGjw4KDQXD3lVvyIS2g9cP4/P3
         kg3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=HlF/8CXXW/SBUEsDGAsAuOHcAFV5oxgNGtOkYBh2tX8=;
        b=0O7sSP8kskhe0RoIOiVAdcictBxzV0JFRIVxk4ZMqIuSHkDpnO1Q8CNLpZ4G1fw6G4
         wAlVe5qiN1UWMrv4wVw980bqEkqTV9O1kNzelyr7wvvEaGD0Uqyt46HsyIVrLYAxMGcl
         X3t8dH3lw4neV2BbYyf602phVgw3IU1VGVVg8TDuNtbAGp7oHKRjHhshMgiCNlIW89Cl
         ANsFbdgpIsNevnK8gNOa/RajRk6ipfnLn7IhfavfxlUWWP3Z6OTOnUAXKiXrXM6EIxLf
         QlWL1reaamaE+AHLu0/cj7XaNwnfwyhU8LnDB+Nm+F4UEUlbZY7i7yFIEPl2r1SxWlDH
         eBmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="jtLZ/TQr";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HlF/8CXXW/SBUEsDGAsAuOHcAFV5oxgNGtOkYBh2tX8=;
        b=I2nT5tWoJIa1gy6QuX9ovFFKoBeFPAyltGU7dTNQH+jRcpHb0yP0vrlRqCqwB6xA9A
         2isBSolV9F9K5hjcDvqpvNK71IDQ1km6u9KAAlfs+Ce3UGx4cw53uTF+xjO0chpmO/z0
         BSL/Cg4Rzwp4HaMwZSZFb02f4P/QhBotYLLa6Y/VitNP5z17rxKtJRcf1QacFp9Igg+V
         n4MCcDnABVO0FedSmgMmfNx31PRSH7Lg08YZfvFCDuZB6I0Pq/7aZmsd8PYqmefN7Q8B
         AsGj0iUXS4yOn9F2DRu0ZtVgp9K609HS1+1VLb7+OC6rSkOU+1jgEVrs1jJ9vJxRt77W
         iy7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HlF/8CXXW/SBUEsDGAsAuOHcAFV5oxgNGtOkYBh2tX8=;
        b=pfMHHA+cC9WRMTqolVfA5XH3x8Tjc6x1wH14FyTkLzSS8fhuXa370abX5Ub4Rb32cn
         +1bcf2/I+N2VRfsZ0HAAl8NcTeGAZz5tKzMKp4ECxilhNzAzyt3iNzjNfsIIokDs+HUE
         WH+taDUMPKycOirA9zlM3jx62VnR70bkdkVXjJAxLTKVbmVRv72nPNY0uYTAP9mPi/Cy
         ImZlhLtUwMNgEkaHhQ9sI4SZeifpX0/QXKD14/aGNsOA7kLWu4jMiMZjbMiKwBjAmKr4
         VOIC9cDFbTXswrPfFfugK5Tf3IL90dJ5zGyCpvTay/i/7jUCBEtD4aVaDhR6hncrWQUK
         rRWw==
X-Gm-Message-State: AOAM532GAyTmVe+iFyUTsiRkx5gmj/g2kRQ7ZmqpQPc2fsVbyPOAMnkM
	rb7E/2AXGfHU9zIcHwpCmVg=
X-Google-Smtp-Source: ABdhPJxC0/lOOXjK0pXcj3MoZtRlOI21ua0p/zC8F2PcqaJ8eABY0TaGCRpjHXWm3im2JOaaB9SG6g==
X-Received: by 2002:a17:902:d304:b029:e6:bab4:8df3 with SMTP id b4-20020a170902d304b02900e6bab48df3mr29519692plc.5.1617042565666;
        Mon, 29 Mar 2021 11:29:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce8f:: with SMTP id f15ls9393614plg.5.gmail; Mon, 29
 Mar 2021 11:29:25 -0700 (PDT)
X-Received: by 2002:a17:902:b088:b029:e6:e1d8:20cc with SMTP id p8-20020a170902b088b02900e6e1d820ccmr29617629plr.27.1617042565266;
        Mon, 29 Mar 2021 11:29:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042565; cv=none;
        d=google.com; s=arc-20160816;
        b=rdMjUlx3+wrmXRS+LjsoASxuAecH3hHDMugOCJcskIgtHbVyUyxMwGQHvpV2Bhxtkx
         RYbY+V6vOC2JHtKyyUEjT7z9GtEmebh/Se18sCJDBqu4zpVODFvIsc078KYdM9sAorXf
         QSxmLcvT5GZ6vX3f7nprMoKKvd3SmWb0c0ojZiXKKTEQbvoeZhgZ3ZVLlgi60UJ2OfMk
         3+leGDPYSGSwBvZ86qcYz0O/v4ziVNZ4guaLegaT6m/cpMeSex5E4SGxC3mCgnroJ15k
         1WpkLkvrza4DDdlYE/P9i7UElyHsn0/Kml9AaAJB4leEGJRN01yLi0KbXnZvfRs0i4tF
         oazQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VCe4QmQLCwyArf7TfS2RTM//Ze/hAyVnYUNMw+5EuIc=;
        b=w4wG10YTnWdl4TdSiVKRKbEmR4Gunzn5GUuPqlYPjiYhlyr7nhtv4C+5AmzgvmCSSU
         4ZKbFay5GyptARQKSt4OuetHNIiR3kxM8Du7Byt1qS5+1wzQkZlnAvUtReR4i26/twdz
         nSB9LmRkc0ARtITzMBgU3Knn/Hu4n+ll9hyL4BWSQ86vjTozsk/hMFYZQ1aH43OcKgaa
         3OxKxkngujbGX0VDp8xH4q5qYAbt/GouVfCcFNMSjyvH8rdazQKLh4xV0nwbDjo2WUhL
         IjYRZogr90San995LcNieIZxTW/4ckmUy0ifPtToriqbULHdwOh3q9uBKfb+W9kH9dxE
         e6XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="jtLZ/TQr";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id j6si8279pjg.0.2021.03.29.11.29.23
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:29:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDX3Eh9HGJgUfVpAA--.35371S2;
	Tue, 30 Mar 2021 02:29:18 +0800 (CST)
Date: Tue, 30 Mar 2021 02:24:21 +0800
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
Subject: [PATCH 5/9] riscv: kprobes: Implement alloc_insn_page()
Message-ID: <20210330022421.0ee61d0d@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDX3Eh9HGJgUfVpAA--.35371S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFyDGF45XF4kJrWxuw48WFg_yoWDGrb_C3
	WxKry3WrWYkrWxWFyDKw4Sqrsak343KFykWr12yryUtr1DWr13Ka95WF45G3sYqr97JFyf
	GrnxX3srWF42qjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4kYjsxI4VW3JwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM2
	8CjxkF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Cr1j6rxdM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1q6rW5McIj6I8E87Iv67AKxVW8JV
	WxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_JFI_Gr1lIxAIcVC0I7IYx2IY6xkF7I0E14v26r
	4UJVWxJr1lIxAIcVCF04k26cxKx2IYs7xG6r4j6FyUMIIF0xvEx4A2jsIE14v26r4j6F4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxU4yv3UU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b="jtLZ/TQr";       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022421.0ee61d0d%40xhacker.
