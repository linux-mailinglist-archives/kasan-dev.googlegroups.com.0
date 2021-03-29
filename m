Return-Path: <kasan-dev+bncBAABB6VZRCBQMGQEYPEK2PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EC6E34D732
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:31:23 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id h134sf12858205qke.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:31:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042682; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPHThAogsuMZWrmPpVz4GNrO/y1sxiFLuQbcezagPEMpYQQzB0jPcwNwWLFiij2VQU
         kqKsXpBwlhQ7YTRPTR62NxLvLq6eu+SLNzBP/ZHJSRrPCsZJmEXz7DXB/t5cW9Sbnfa7
         AUjmkxGjA3J/7KQHW33Sy2E+i9pA58Oe310SZzJE0RSDmeSE+eP8eylzexOmlsX/DwpS
         Jj4X7IsGUGPU/+rIvKGsiQDYn1cVvvVPLIfl4c7yAJG4YoG1zNkPqpMvmNpzTDe4Bl6o
         V9IIIb25fVuUH219+LbYOhXCegknlZICic+VaGSRK0KfpD8YX8YcqzQeKFVbCruD+v1z
         yliA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=acslI0dr8G38C0xI0Btb/8ndBCmiKXBRLTG5RGgOITc=;
        b=yr7XkCJk/Mw67TpST69rKOpXLuVSCUEfzzkqjRKTqcUL8Hbc1TVqEMkWsl0kGvgvcB
         7xfdB9GSYuIMqUV6B0bDvuksCf519Fqa8BlWlqQ6rCnsydNw3eOeEIyRfTngtaluLVz/
         EBrvbLsUhAcy9itmlLAUvU2H+JhoH8GkOe34YiLo1yPzkaTUhqzpD8R8uE8zjCNMsFQG
         tX4GPwF9AP0LLwhYrmgNtSipI2Mi9X+mHvnCWaa5w7FVBMYD1x+Sd61AjJfZaFOCWhAd
         NcH79WRxfDpa6KwYAwbI8irVY+xDi1EbJO7g8y29hXZky5tRty/AS+HNn2Jmq7Ftb0lZ
         pnBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="KJWdSb/T";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=acslI0dr8G38C0xI0Btb/8ndBCmiKXBRLTG5RGgOITc=;
        b=RlIr1GqB7jARolQ/vXeSgkSWgeUwZbkl/YSAemyHS2JREEEpVDG57Nd8+kHQVG5sFs
         Gj66lGpmhq+YOvkyiN6JcMcbetCWFc098pUzHxQSOsyAaVrhXLVhASPpxyu+6kP8rdfG
         lnUiJpnVQ4yF69wPtM1rQWVaRlDe5eYibFcp7ih3YjRnVMUWQ5yBo72yYkl+sZ/bIJZW
         zqR7yNoP7jJfOXx6/Jt170cV5JVRIXQReV05fBZOrcG4tq4cawG6COvUyYxVzguq083T
         RlNuxTSSnv/eHsQl/EDw1OkbOVnGoxRMaoa7U2+8tp1b3nIr6RBSDMte6S4FqG35WM60
         iEPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=acslI0dr8G38C0xI0Btb/8ndBCmiKXBRLTG5RGgOITc=;
        b=P1qLvkCcGsdHocwM9/hxzbsAcNQDBPV5LHd15LW6bfCo4uAgJfetgkBeyRlMCeXbFo
         lBLtoynthM05I/6scHtHwU9eIsrm0XaFEGS2G/c4Dysx8K2+vpG2bh4ngipNx5CsYJFP
         gJDgcdORkHO/SKrZIPBAuKktQTWNNN9CWwyru50K5NGhxy9Zhu6FeYtSe6j+4wgI7g0k
         RwaCsGy3HAebJ8VHBaFOGAyVsnbeoplRCTp6FPvEFF2cq/YoD7EeriXMvAAMSlcBnO8f
         NfF4qfKrWD2uhioeuovtbQU7o01vf3NXvFHEFIBfirXneDyV7m4BaNq5qPuLai2TpGnW
         GUcQ==
X-Gm-Message-State: AOAM532oXL2WHWB3HQVdRdXAVVVnm3rJ49Yv2ajY/OPFouZhODZWmP/B
	znfZPAwimmOyPvOsZ0vyQdo=
X-Google-Smtp-Source: ABdhPJxO1VtbRDD6D+9mfl8VBJgBJ27S7ZrzJMbfCPBQBHskKYXG9mWJIUZefgLkPqPGt4t+LgICDg==
X-Received: by 2002:a37:30f:: with SMTP id 15mr27160969qkd.494.1617042682544;
        Mon, 29 Mar 2021 11:31:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:3db:: with SMTP id r27ls9006910qkm.5.gmail; Mon, 29
 Mar 2021 11:31:22 -0700 (PDT)
X-Received: by 2002:a37:2c41:: with SMTP id s62mr26462766qkh.205.1617042682169;
        Mon, 29 Mar 2021 11:31:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042682; cv=none;
        d=google.com; s=arc-20160816;
        b=xx3HH4wXNWQEYSBReiv7kex9vCb7+C8MH0yhJP9KIqOi3WKCDP29HZuK0G9avFCCvZ
         JPWWnmG7BL76AJYu0PIm0BskfANJ2P+J+iJ8WcCypem5xBfumyGofRY3Q5U6EhldKKat
         FJgqs1Gs4kJB+7aomhoP/GDnmCzP9+pBtj9yw+9dZReY9EQJwTgOu0HWyLH8vEhacQ35
         e/sETE5ElWQ3rha2N7Sio49Y5MIgk7awo5L4Kav2QJv3wYGW4UL2AWTusKJ7q3RLcwIS
         aqN82Ku7YxJOllhG7YXi7wnf7o0k98veVtoMA4RjsilkFKEGO1IXM9silfvHeyvOnLgm
         nVRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9CYVVSdbdIN1CqoSzahmxkYgo2mgL2GjKI5zP4cVXEs=;
        b=mGAriA8cwelAgGBWnBDCqMM0MxoAehW3zX3Qviz858xvK1aUFmXPw84XQdOq1Dy6yq
         2gxb3mCeJ+QluVMFIs5C+fummiBOZxLM+RkaKUDOAsEIZ7pnKTvMEaxmKpgf2bAARbG6
         DFLsXDOtO7tAyjrFfrEt0gxQ82FfsnaSKL1zerK8fXMgtrEcfEDP2rY8iTvcLgxj7Xgn
         8oytxAK3ZmRUkp5RXRw8irzexOdisdToG8nZrxtf7JsWhV7Ab3JrOqRn3W4pICbOe/ls
         jbT+aJ05WRmPqxkJaGJ87Qlp5ZNg8aL766JfvrxKr8MUc9w1VN0W6PaTM9zTtieSweIJ
         UD5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b="KJWdSb/T";
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id n9si865255qkg.0.2021.03.29.11.31.20
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:31:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygBnuJrxHGJgRPhpAA--.5621S2;
	Tue, 30 Mar 2021 02:31:14 +0800 (CST)
Date: Tue, 30 Mar 2021 02:26:17 +0800
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
Subject: [PATCH 9/9] riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU
Message-ID: <20210330022617.525104ce@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygBnuJrxHGJgRPhpAA--.5621S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFy3Cw48Cr4DZw4DKF13CFg_yoW3ZrX_Ja
	yxJF9xur1rJaykCFZ2gr4fZr1jv3y8WF18uF1Y9ryUZa42gw13X3Zxt3Z5ZF15Zw13WF4x
	Z3yIqF4UGr1UWjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4kYjsxI4VWxJwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
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
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJbIYCTnIWIevJa73UjIFyTuYvjxUcyCGUU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b="KJWdSb/T";       spf=pass
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

Now we can set ARCH_HAS_STRICT_MODULE_RWX for MMU riscv platforms, this
is good from security perspective.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 87d7b52f278f..9716be3674a2 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -28,6 +28,7 @@ config RISCV
 	select ARCH_HAS_SET_DIRECT_MAP
 	select ARCH_HAS_SET_MEMORY
 	select ARCH_HAS_STRICT_KERNEL_RWX if MMU
+	select ARCH_HAS_STRICT_MODULE_RWX if MMU
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_OPTIONAL_KERNEL_RWX_DEFAULT
 	select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022617.525104ce%40xhacker.
