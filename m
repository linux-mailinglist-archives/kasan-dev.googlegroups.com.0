Return-Path: <kasan-dev+bncBDFJHU6GRMBBBRFTTKBQMGQEBPVLK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4367C3525FE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:12:53 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id bm8sf3987334edb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:12:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336773; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVflf1GdXFxTbewe6kdBYLO4jvfk2D9IFZ+5dZUg0Rn0vgKRzxo7wj0wDPp2SCQiMl
         3QUZIgY1dQ1Kp2H3R0lLRqy/eeQwDvRxg9cK6a1edOQM/VmieX8N6E9M+AhmSnw1c1tc
         Xfe8jB04msrEV3NlbekuMtkv4HMdb4aeGcTHSuXAkoizuZHLMkB9IizQs8n2ofbJnTWL
         4Wo9Fo1TLmL3hrtuD8flofTj0hcj0vmO7yxRkR7j9OXAHKRaYFd73zIjl14gjTxCsP5K
         4OmzmwCaZXlLWMOJ1n67BMYTC6lKJx7L6x9bqyRwS8qbO0dwJVol+vGXxyTUJgcnqaVb
         9vlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=N3+5riohYvIQFiNHPedltFGnQaSG+uCwIIZqGIill+g=;
        b=bugN5Yw+mrqsJ7jWnfGKsuuOIE3CUmg0LufKZHz4d7j1kAAut87JZTH3QtJwv7Iq59
         gRYkNvmQNFGKeRvqB/t4n1QCcyb/yfH6bislJTjXLzG33vBli4oxejWZi3XblsNUUYiX
         aeBrxXt+iiKsW1kcnulgQacAp4cOX8cdR9nVkcx98drzaWXDXH+U9MRbWijHQnpMosvB
         Ehlui5VNyj79aPcsTcKf3GYW8PrwN0G5rjpwA6SFf898DNXWDXTZgPHFl/HyAYStQFpS
         DG7sZLwavpU1TjSkcU3JJJdu4kTaEgDZUMd1HUnMZxG0Jw0fPjbnKN7CJkPbjJJwpw4T
         Q12Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b="xf/w8QzI";
       spf=neutral (google.com: 2a00:1450:4864:20::42b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N3+5riohYvIQFiNHPedltFGnQaSG+uCwIIZqGIill+g=;
        b=akAwiCaDKZZSMBvDN3dWzUw8TOzaLiPqmxNaB3UtnYPw50R6H3jnAR2f68sov5cvm8
         YybLuzWi0K6NecXWgS+ZGBn0S1ZK0w5mFCbcps5NmOm01jFMwIbVFzdAlFo07xjR7E3Y
         T0hY/AHmVPtLxbVfv8KozSnyjWkrGSjvijAjt1+gX1fllf1GofakLtO7DNljSdNU77BN
         w8H9woAo3YA3VjMUGxLzi7rqjfvjGBX9XPONaySb/BAmls6b5b2LiWdAybBpG9tAp2Sy
         yoTCizxaE1lDFaRqXyJGXEQAnRsQbscarQAvbW4sfXrDwH66hQPAH6VPMhYqnsNPgzbm
         MJJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N3+5riohYvIQFiNHPedltFGnQaSG+uCwIIZqGIill+g=;
        b=IW/mLdpiHtR0l6GP7z+U/EIANMKrDmPdRI9qO1U/Z9KUzvjyIhDScbXyUKCqWILqCQ
         +hZVe0bdTlKvjzJUgmuuoj2ftDfknfdfudPw0leL7Xcna5BDpFFjKOiFEm3PVnZX5AJP
         K9JBg47pD3/mcqvtTsMvQrm6eCgDPATAz22wRXXT28UOY/YL8cs7MHmW0DWj+HvZoIzA
         qI9Vfw8UTLFaBPf+KOsNNtxyvc+bLBcpPeDm6TyaxWHg9uSkL+5vdYZ4C3Kz5iMJt6TC
         joFrU9J0dWEPzSm2sw2vfiy4DHJr8pays0atpxEF8m22Ma4jTXCLJvpFGrGdUUefwtVr
         lbJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531z98a9FCo4482TzSgh97VqvUYaGUYy4iqz7uR50Ektt7xLrJsm
	LYx5QAkl0mF2ztBtUJk7xDw=
X-Google-Smtp-Source: ABdhPJzHScR74r1GiwApAUl4LM7FlZ2JfxBF0rgu//GVUlYJTv+HwuPNeQvOaqCTXp5tHdSq23lUpw==
X-Received: by 2002:a17:906:75a:: with SMTP id z26mr12066243ejb.22.1617336773023;
        Thu, 01 Apr 2021 21:12:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:16d7:: with SMTP id t23ls4037833ejd.7.gmail; Thu, 01
 Apr 2021 21:12:52 -0700 (PDT)
X-Received: by 2002:a17:907:d8b:: with SMTP id go11mr12549776ejc.167.1617336772208;
        Thu, 01 Apr 2021 21:12:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336772; cv=none;
        d=google.com; s=arc-20160816;
        b=YtdsNmaBoemfYEvvCL/u74ACiwLdxFTwQU16/LdwSqTgdGgJg85zQo8v353ROnIGIH
         0wh5zHCISKpgUcu/fxOmSRq3r8kHvbq/HHy9VByJL0lbuukXOpm48ggYB55Li2Yjlv8d
         Tww6IiWgrosiT6LctU/i4RK8Tur1u827ty0TAGvPdNnYUUDHyaE9f83/9/TI98nyy7ik
         eonme6NCMzgJa4d3ytrijjcujp1XqCAV29EOZsWP84kRHA2GmzK+1EwjoXDF8vBXXCoV
         N8UHU0LQBUgkh0DcNPziLBbdwSN2NAD+eawbmKSuCRsD5yBmc7ELQwx6m5YNBjXZGWiy
         3wvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Ab9mXgnZVMv96jlr6O1hIj0YRsCl0wKzDzAenTSuZc=;
        b=wdP0ZwysTc4CU1KODeOkfh11Eka4uNYpbLxbWBkYLF2PggWMJrXat2US9sb3bJxB1O
         Q4cujjA0k7YAtWbK4LpPJyCtAm+eRgPPrsabJIduGlkWwXxI+ACpc7y9q3xDXe4xvfW3
         1xGorNneI4ilNqXy9IrQDH7TTA6fhOigBH6nsdq6uCvx13/sWdb8npa5eCLWYFmRs0Me
         8FJ9ws8w4NvideE1aHnbJdmJbK0/OdpM31xRYvER+LhwetnXgzvqwcAPUIRL8n1kOIXa
         88jcuH01H61u+cgGgbg714mPKwaT02eQYslWULFL9UQFwT5uslWWFBJKXmn3DGeeQLdu
         6Wsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b="xf/w8QzI";
       spf=neutral (google.com: 2a00:1450:4864:20::42b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id c2si769033edr.2.2021.04.01.21.12.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:12:52 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::42b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id x7so3659480wrw.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:12:52 -0700 (PDT)
X-Received: by 2002:adf:9544:: with SMTP id 62mr12956426wrs.128.1617336771963;
 Thu, 01 Apr 2021 21:12:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002651.1da9087e@xhacker>
In-Reply-To: <20210401002651.1da9087e@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:42:41 +0530
Message-ID: <CAAhSdy18AwkvNj5bgq6nLV29UNBQcs2MTDCwf_9GL5dC+4=8og@mail.gmail.com>
Subject: Re: [PATCH v2 4/9] riscv: Constify sbi_ipi_ops
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
 header.b="xf/w8QzI";       spf=neutral (google.com: 2a00:1450:4864:20::42b is
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
> Constify the sbi_ipi_ops so that it will be placed in the .rodata
> section. This will cause attempts to modify it to fail when strict
> page permissions are in place.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/include/asm/smp.h | 4 ++--
>  arch/riscv/kernel/sbi.c      | 2 +-
>  arch/riscv/kernel/smp.c      | 4 ++--
>  3 files changed, 5 insertions(+), 5 deletions(-)
>
> diff --git a/arch/riscv/include/asm/smp.h b/arch/riscv/include/asm/smp.h
> index df1f7c4cd433..a7d2811f3536 100644
> --- a/arch/riscv/include/asm/smp.h
> +++ b/arch/riscv/include/asm/smp.h
> @@ -46,7 +46,7 @@ int riscv_hartid_to_cpuid(int hartid);
>  void riscv_cpuid_to_hartid_mask(const struct cpumask *in, struct cpumask *out);
>
>  /* Set custom IPI operations */
> -void riscv_set_ipi_ops(struct riscv_ipi_ops *ops);
> +void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops);
>
>  /* Clear IPI for current CPU */
>  void riscv_clear_ipi(void);
> @@ -92,7 +92,7 @@ static inline void riscv_cpuid_to_hartid_mask(const struct cpumask *in,
>         cpumask_set_cpu(boot_cpu_hartid, out);
>  }
>
> -static inline void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
> +static inline void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops)
>  {
>  }
>
> diff --git a/arch/riscv/kernel/sbi.c b/arch/riscv/kernel/sbi.c
> index cbd94a72eaa7..cb848e80865e 100644
> --- a/arch/riscv/kernel/sbi.c
> +++ b/arch/riscv/kernel/sbi.c
> @@ -556,7 +556,7 @@ static void sbi_send_cpumask_ipi(const struct cpumask *target)
>         sbi_send_ipi(cpumask_bits(&hartid_mask));
>  }
>
> -static struct riscv_ipi_ops sbi_ipi_ops = {
> +static const struct riscv_ipi_ops sbi_ipi_ops = {
>         .ipi_inject = sbi_send_cpumask_ipi
>  };
>
> diff --git a/arch/riscv/kernel/smp.c b/arch/riscv/kernel/smp.c
> index 504284d49135..e035124f06dc 100644
> --- a/arch/riscv/kernel/smp.c
> +++ b/arch/riscv/kernel/smp.c
> @@ -85,9 +85,9 @@ static void ipi_stop(void)
>                 wait_for_interrupt();
>  }
>
> -static struct riscv_ipi_ops *ipi_ops __ro_after_init;
> +static const struct riscv_ipi_ops *ipi_ops __ro_after_init;
>
> -void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
> +void riscv_set_ipi_ops(const struct riscv_ipi_ops *ops)
>  {
>         ipi_ops = ops;
>  }
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy18AwkvNj5bgq6nLV29UNBQcs2MTDCwf_9GL5dC%2B4%3D8og%40mail.gmail.com.
