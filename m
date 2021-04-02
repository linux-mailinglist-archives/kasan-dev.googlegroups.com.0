Return-Path: <kasan-dev+bncBDFJHU6GRMBBBJFVTKBQMGQECOVCH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C6D3352607
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:16:36 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id i6sf4009913edq.12
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:16:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336996; cv=pass;
        d=google.com; s=arc-20160816;
        b=VIn04GJ2TeMDZheKDLoPVd0IZUGplr/r77MIQ2JNsmaUz1TSI4tldZZok05KKjYp5C
         2kmgn3qTilWNmKGp5Yd8xMJCA9zf5JLtKQt5i/QCaXoU/bcz5xWC7H9pmoe2SPGzhEPx
         wM+sGYqEp2MYfQEDOkO/vhXcwxQWaru4gWN3MVnCEq3D/SGFfX2VaSv+DpxCuejZsb6J
         h1d+ahxL0twEq38UuHMBBWgt3oKED50m5EFVw1jK2pFnZC+PkAapciuFYx9npzvh7uN3
         cqbavEZrqv7aDzVt94xrXRmM5I6Jilhc3gLNFH6t89x+x7hWZm63bsLTusB7Y2pvjsG4
         lghw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=703Tdtpc6aMW9B1T23GZsXegS9G3kDlONAtb5YoZnys=;
        b=be1uoJBAH98lbiuB1e3gxyNPX/jI5XlEMLUQNwVVWyy1leb0EwEDIYcmOruwlR2s5o
         5Omfv3WwgCYna63WSrsoN0p902dYBs1q65nmE+7atlNn7AXi/UeRWEb84X85mLHumiP8
         6hXkvPqgyi8V0Aq8BAVR+sbW6cgmVX+Fni5qy5m8Ji/pCw1kOtO49ouQ9HaOtyawQPlP
         HpxyH3Du3TA8hYKEba3n6HVkzPaWNY+cjAHc09Lo2EgTHurzyCl0tmNn2VlzS7x/UwKt
         EyB4thSZZ2lQH6+GZM40h7xIiZWzO5tRaY7f7fQX+2nOhSGqEhAIL9bpBZsLeMgnU7j0
         TyLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=YnksgUvT;
       spf=neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=703Tdtpc6aMW9B1T23GZsXegS9G3kDlONAtb5YoZnys=;
        b=ZPVzbL6V85ccaKWE9jjM5eOdLwDzUtIRZn0mVF05SCAtw1X+8k3Xcms48qXVOLozPp
         8AMeQ9VW0T+Zxb+o69WhyEpU7CM9jROya3fjjaLAVlOdkxmPzPHBf0hrqmguMHpAsgSk
         Xldv6qaLYINrkug7FQdbdGy2zpnP1MX2rlW0so+d5FXagqzebYQp2KhR3THKl8OL7DeI
         3cVDINo19qvIOA6LD0tGLvVdIxMB8XV9R5PXhmpk/tNPt+VPWgHy3w9ZvCLSqbQQlYVd
         qfNW6fCfT04ITPgF8rbcem4ac5VqX8fk7+B5RtlMY35TtJovc8+docEUn0/YTfRyKzrW
         EhmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=703Tdtpc6aMW9B1T23GZsXegS9G3kDlONAtb5YoZnys=;
        b=G2PtdJI+/ZPuOYfA79dI1EEbTsJSRg+ME4vxrHskImFCiTfwgwIVef+iXDqc/197A7
         zBQMPJaF+pLBfpXK1K4KL0ASg3V/sVgcxQqFQoCReF+XOHxYFbahhJ/CkL8jYKxl/HxK
         GBbzi3FQ/phG6frYEQAezGAfoNFnjhzE9YYvA1kqofmZt7qPs8mC7dttLDvH2+cLM3ly
         I+LcDovP4U+DY6F2i2l5RM0OJubAUqiq7UqAsvKGvVIFXPO7rtfXWvYQe0WgZPaFyswp
         B5wBJKgDVdycaB2BddYiWHzek2VFcTTQM7Ifqo2MVz5inFjRYcu+Y+mictmcI8yArNn1
         RnuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GUsQgracXVe+q6FskZ+UawZQQb5pLz8Yk2/G/8TPqXRfTMbfF
	qL1Ve4IgPwNC96YWcKL3UMQ=
X-Google-Smtp-Source: ABdhPJy/D/vp2K0fEHeoLpjKYx0auVcIpFOcwZsPFmx9MLM6S+mF697t5GCIb+c07+NvtOC/7HCq0g==
X-Received: by 2002:a05:6402:34c4:: with SMTP id w4mr13914773edc.367.1617336996179;
        Thu, 01 Apr 2021 21:16:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cd:: with SMTP id h13ls292034edb.3.gmail; Thu, 01
 Apr 2021 21:16:35 -0700 (PDT)
X-Received: by 2002:aa7:c0cd:: with SMTP id j13mr13987876edp.41.1617336995374;
        Thu, 01 Apr 2021 21:16:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336995; cv=none;
        d=google.com; s=arc-20160816;
        b=yG3lRa7sGDFoDEMlu0ro1YfQsGpvV0l3QMnfPyegDyKGo9YX79qGb1gpB/kEH5VtXf
         MxxVO1mEXrFrPpk/V0628/w4yiUmuTjqAueYO+BBcEmIX6IfktMv77nI4Z86Wvkkehkz
         5OiGjJxO6InidIV5CUVqJNCq1BzM3HNIrnipkdx67THjLZUxMBc7/RL1xYZQVH5GvI/Q
         abw6JWut/Fu4UOA1UFIAW9myj+R4XRekiRIA2jkFjxljNv7VEcu34cM3bRSpnGXoWNNN
         ccup8C6Ssjwjv3qPIjwTYpSf0DdYHGAG6Xxqe13toh+aiHpYL5GyiIJwBIySnkmRUNrB
         5TIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EF04ZQkeFciI3OPVClfJodus6PK+ab706FdkNzAwhhM=;
        b=n7Ymkm/hA4786wyReyvg6EAElc6h4qnLUlso+SGuWXZp0Xf7WLIsb5YMdxsmew8xar
         j3o3I7s9ZPZ2ki2JWg4CnWOUyhle5i5gOEoLvHjBM6919W5RjWUCM+6Wsf6YDj2wj/mX
         gFEsN2g62eAT4Y5ieXF6tS6fmQl4hdSfSwq6rCrbY7QwFzou6KZni5JEhijDYgx0ajzG
         1/qCnfTBc58Nx2vWjE37+4b0dB4PNyWnjBYieoYds5w+7SPyDrFRDuS2KZf/oMZHzTYO
         iCIJ1l6z1hyaigidJN0XVzj7LNsrp83BipVB6veywpl5P3zSPjmRU/kSMiW5b959eUqz
         ORkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=YnksgUvT;
       spf=neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id df17si810906edb.3.2021.04.01.21.16.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:16:35 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id x16so3680609wrn.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:16:35 -0700 (PDT)
X-Received: by 2002:adf:9544:: with SMTP id 62mr12966999wrs.128.1617336995047;
 Thu, 01 Apr 2021 21:16:35 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002724.794b3bc4@xhacker>
In-Reply-To: <20210401002724.794b3bc4@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:46:24 +0530
Message-ID: <CAAhSdy1qcNBy-o8NAho-bhJY1FOF_DCiQ37XX+FEiBbYqokxhA@mail.gmail.com>
Subject: Re: [PATCH v2 5/9] riscv: kprobes: Implement alloc_insn_page()
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=YnksgUvT;       spf=neutral (google.com: 2a00:1450:4864:20::42a is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Wed, Mar 31, 2021 at 10:02 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> Allocate PAGE_KERNEL_READ_EXEC(read only, executable) page for kprobes
> insn page. This is to prepare for STRICT_MODULE_RWX.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/kernel/probes/kprobes.c | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/arch/riscv/kernel/probes/kprobes.c b/arch/riscv/kernel/probes/kprobes.c
> index 7e2c78e2ca6b..8c1f7a30aeed 100644
> --- a/arch/riscv/kernel/probes/kprobes.c
> +++ b/arch/riscv/kernel/probes/kprobes.c
> @@ -84,6 +84,14 @@ int __kprobes arch_prepare_kprobe(struct kprobe *p)
>         return 0;
>  }
>
> +void *alloc_insn_page(void)
> +{
> +       return  __vmalloc_node_range(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END,
> +                                    GFP_KERNEL, PAGE_KERNEL_READ_EXEC,
> +                                    VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
> +                                    __builtin_return_address(0));
> +}
> +
>  /* install breakpoint in text */
>  void __kprobes arch_arm_kprobe(struct kprobe *p)
>  {
> --
> 2.31.0
>
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy1qcNBy-o8NAho-bhJY1FOF_DCiQ37XX%2BFEiBbYqokxhA%40mail.gmail.com.
