Return-Path: <kasan-dev+bncBDFJHU6GRMBBBZE74KJQMGQEFRXCCXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1413B51F306
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 05:52:05 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id e9-20020a05600c4e4900b00394779649b1sf4553549wmq.3
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 20:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652068324; cv=pass;
        d=google.com; s=arc-20160816;
        b=Px3OvnsrD5FUMh5Ad4Ifgb2NPS6yASoy9+nlT9aqZ35+OoIhwY4vOvN7KNu7NmvfB8
         H0T79sq0OdBfBYYFxMmk2ciiWXpU0mZYRWxYRtEQ0HJ+WIdWphtS7LZ3BQu7kfohotgV
         8x40lAZ6J9y8MuTbifwJ46fIqTFnlpAJwoMzA37cvg3hKPmS7Jp7Sh8O4ZNzPYlrewvu
         ZYVnuCfn+Btu+NnIxaynrRxnsCUik8NO77Khqa7GODvVtgF0QoYTNqcwUgLd/1oQsWgH
         qtMN4uRUoaZ33xcBJqg3YIjsYj6f58k8vX72j7Yt+GqFrQc7PHhQUNL1USYlqsMSp5Ds
         H0rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Cdz8ZX6yGCIyUPxXiEiQwoUNebkKOWSiiWDX8xu54V4=;
        b=fFahJGwqQiF5n3QcJMRQHFur1AR17iWn1n26WCCU33NYVNEEPsStcXsHLkRbFWYr/L
         GKdOk80dHhi8MCzNyJ1pBAUdmGJC+ReJ5RHqQ8s60Vb/XLvSrPKsesvqWQO3YaPcEFoK
         k46RUKfQRNSnX10YdzOvwHE+4b5uHNmxnshtmUyr5Jb84PFviASQXAsI9MkDpzBgR6pF
         cqtagnVPsK9tg02LkUfOGM8tlwDoftiqAs9DCMzfPbCH9TLNR/sinPwtSy0fyUEgzwcZ
         GDUfugi5FlGB0xMbM/PrHhMN9lg4tcVe2P1XcWrmnakHNqS/Xh9f26tHWBiF3D9MIAhM
         Gkjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=pvxaieyw;
       spf=neutral (google.com: 2a00:1450:4864:20::32f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cdz8ZX6yGCIyUPxXiEiQwoUNebkKOWSiiWDX8xu54V4=;
        b=NKG141Z2ZkSzYB5maUfXve7u8LlriGIV7td89GRcf1r//um3J0aVpoPLtovS4dulSx
         wIeyQP59LtiyL7sV0uG+BeCkoNvSwfJ3wW1On2PiVDoQ2AA3e+9ACn0ln6WURv4mkp04
         HEJEYdkoSsJ4a4+8wf852QdguJNjHwIn1jNsWDcC/zxjPWDX9VMjSh6K4FLDzFh7ovdq
         E9IlUL0A/6jEy2Vj0GEjrUdJ4HhD6TOJGZ08VOcyQ5zslNIKgtTO0Ow2EDehibB7wC+9
         rvE6T0yulC03KBIV0XxjdTi2oF7Dw0n6jeKHcW1/86tXF/jpLAPfe1EUh1SqUy+QA108
         0PSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cdz8ZX6yGCIyUPxXiEiQwoUNebkKOWSiiWDX8xu54V4=;
        b=EdktYQEnmIQE46nyzaLboSFZWBTQVcxqWYyI56dO4Ji4oxWQfUEROY4Wrh0hf5rMYW
         x7fReo9Dr53AXI3roHUt/xMV6s6w/qWU/+iqkLGL26AG262wv/RQImyHk/Ee2lYNSrUS
         KXxOmJ4be6dNZ/4PStqw9Wzk7hGo99Htex/t6M8BZmCWIeby0w85EDeETzcWK79AOA8Z
         tL8Pbvy8sgwji0jFmtEoxp2tdyYEEDzpMzg8ZRfW9KqNX1Njjd7e5uBZeDcgGusxZXor
         JJx7+xHwZuTKxJAXrjfPoVOqFN4cEItCZxoJ/5bFUvW1gaMpAfyEGqTZXMPFJ/3+FmLe
         iujg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335HmhYTMV+ysA75Qq7w8/2tc+eIsMmh/6j/ZXAc7+aGSfftkzx
	kvzjpWPBcvmM28jo04hNIxM=
X-Google-Smtp-Source: ABdhPJzeNJTZ/LMGUAsH3McSIVleYmaK/nXkKdjE7sNdGxIXpkPul3J5Ssprc1l/xIKr9Ed1rrwPuA==
X-Received: by 2002:a05:600c:1d17:b0:394:646d:fd73 with SMTP id l23-20020a05600c1d1700b00394646dfd73mr20126734wms.103.1652068324643;
        Sun, 08 May 2022 20:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20c:7b09:42a4 with SMTP id l4-20020a5d6d84000000b0020c7b0942a4ls120463wrs.2.gmail;
 Sun, 08 May 2022 20:52:03 -0700 (PDT)
X-Received: by 2002:a5d:4fca:0:b0:20a:cf56:a894 with SMTP id h10-20020a5d4fca000000b0020acf56a894mr12200618wrw.528.1652068323676;
        Sun, 08 May 2022 20:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652068323; cv=none;
        d=google.com; s=arc-20160816;
        b=LzXZbDRvBDqC6M8shThzrMv5swX3VhcWDCwwlqtC6cYlKpc0iyidiWderQ86u6JKLo
         dfZeX/o/A1heOoIzRnCRDDm+7ltXtWDRHUs7oGOcCbimu5HXQlDxVwxrE2ynTHAdQqWD
         UxVMva2YXv5Yxo/ZN5AJ+999fxaFUllfzo4Nwyp/OyfvRkfyiMn/90pBYCf/UDnBhezi
         xMOq/jsmtJ3Kk1sDrEzZld+vm0UdRHJnkTwaU5aRU2dIHkGKFNvVBLHMNZVI/P0KRFAU
         LJ27aNCgYK7nDNjTNwYIpzXwZBr90HGlNePUXgkUxoGy9x9FAjV2ABSC3wxxOxz4jEqv
         R4HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l12WE5mp9PhO1IPRjTjpwmDGOQ7wb/4a5m9y3nBGeOA=;
        b=weDPFWoKC4vSW+m3knAnjxrM6aUHv98N25UX3uHvUPTKNCSlV52aGOl1NjYiWHE/KA
         IhUaqRa8tizCRHS1MyGw1ZBhBQRHyiaIGDm570FLxPu5UsmP7NeTTeNUoUxBvlZLFx7U
         9H+a8aqKOENXFFX2vqF1ezfpGswp83KaaSLH5gCT2N7vIgniwLP2lsMdvLBX/Rqooo1T
         /SI3JVtGFnfTeeEhW3zOJhDJBmoDbYOS0uwGiqW+2KKTG3Jzqb4Oay2PE8QvQ18SGbgp
         qsWfZn4diKWngTsOpbZqIZ94+Y7Lm6CpTBrvRKTPwyHZO8DcZ3T9geVRWAbz+6qJiAFm
         KgOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=pvxaieyw;
       spf=neutral (google.com: 2a00:1450:4864:20::32f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id p6-20020a05600c358600b003942a493261si526886wmq.1.2022.05.08.20.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 May 2022 20:52:03 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::32f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id bg25so7637111wmb.4
        for <kasan-dev@googlegroups.com>; Sun, 08 May 2022 20:52:03 -0700 (PDT)
X-Received: by 2002:a05:600c:4fd5:b0:394:55ae:32c7 with SMTP id
 o21-20020a05600c4fd500b0039455ae32c7mr20677459wmq.73.1652068323237; Sun, 08
 May 2022 20:52:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-2-jszhang@kernel.org>
In-Reply-To: <20220508160749.984-2-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Mon, 9 May 2022 09:21:52 +0530
Message-ID: <CAAhSdy2-L+eSE5P+-TG94exgTsDp8wPiuhD23fZQ88nukoNj-w@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] riscv: mm: init: make pt_ops_set_[early|late|fixmap]
 static
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=pvxaieyw;       spf=neutral (google.com: 2a00:1450:4864:20::32f is
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

On Sun, May 8, 2022 at 9:46 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> These three functions are only used in init.c, so make them static.
> Fix W=1 warnings like below:
>
> arch/riscv/mm/init.c:721:13: warning: no previous prototype for function
> 'pt_ops_set_early' [-Wmissing-prototypes]
>    void __init pt_ops_set_early(void)
>                ^
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/mm/init.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 05ed641a1134..5f3f26dd9f21 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -849,7 +849,7 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
>   * MMU is not enabled, the page tables are allocated directly using
>   * early_pmd/pud/p4d and the address returned is the physical one.
>   */
> -void __init pt_ops_set_early(void)
> +static void __init pt_ops_set_early(void)
>  {
>         pt_ops.alloc_pte = alloc_pte_early;
>         pt_ops.get_pte_virt = get_pte_virt_early;
> @@ -871,7 +871,7 @@ void __init pt_ops_set_early(void)
>   * Note that this is called with MMU disabled, hence kernel_mapping_pa_to_va,
>   * but it will be used as described above.
>   */
> -void __init pt_ops_set_fixmap(void)
> +static void __init pt_ops_set_fixmap(void)
>  {
>         pt_ops.alloc_pte = kernel_mapping_pa_to_va((uintptr_t)alloc_pte_fixmap);
>         pt_ops.get_pte_virt = kernel_mapping_pa_to_va((uintptr_t)get_pte_virt_fixmap);
> @@ -889,7 +889,7 @@ void __init pt_ops_set_fixmap(void)
>   * MMU is enabled and page table setup is complete, so from now, we can use
>   * generic page allocation functions to setup page table.
>   */
> -void __init pt_ops_set_late(void)
> +static void __init pt_ops_set_late(void)
>  {
>         pt_ops.alloc_pte = alloc_pte_late;
>         pt_ops.get_pte_virt = get_pte_virt_late;
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy2-L%2BeSE5P%2B-TG94exgTsDp8wPiuhD23fZQ88nukoNj-w%40mail.gmail.com.
