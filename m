Return-Path: <kasan-dev+bncBDFJHU6GRMBBBYNSTKBQMGQES3NBDRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 994CC3525F9
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:11:13 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id bm8sf3985167edb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:11:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336673; cv=pass;
        d=google.com; s=arc-20160816;
        b=E7/LFQL8maxhHWs7MgoLddkRcVeoNE3NfjXJ7A5DQu4DJFiCgrb9J9/GDQYSNUmh6Z
         eDj45reKfYh8LoZBWAhaaf166U1bdZp8Kyoti66wayKabZRtYp6vNp/Q3gW8Wg2jwQwl
         AQFBWTHDlO/6XfAvOQXsXSJZwtkZ0w5vClccw5fLx0RDPKgEdWhoq1p6nfTkA+5keKd5
         Ea6Xv2yuP6Yum8q36kLmMr9/BQEE4mVnIOX6bTbgmCZweI+nTDU/rgJ5s0tDe6iiKBFJ
         0JTy1QVrX2y/z5Sn+WMeS67gS6u4bqs+HAAdqFQ7Xz2Np3DeoM5FBxLPO0xkvjLC9id2
         Ne2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=qgbxw4OMMlnjNoUIDS1FcqAKQndoT2okQBmVyHYrCes=;
        b=I/lsv6Ztk4Q/6SIi2FW2Jp9jdJSKreQ2tJ22Aquy8BfjshAUPhKaxx79R1i6pU6rKl
         M0mLW5rx7V5w/Xf7nuIeUguIzhDxKZPiPl1H8Cu18oHGq1tFPzXPtFgo4Xo95/QM9aDa
         w/THrPWVRgsf/s1xDkHNqwBwrdG8GW5uxeqnepE1VXNx4U8mXNs+V4U/yPzAVU3nQGAi
         wiYaXJZrNA72zkUoj16GcP+NLmvtYJuDoeDsFJfNsBzokA55NTMJVhke9nhKzaSVNoL/
         6lZWIuNNHMxRtJF+eGQCw/pi0SbLeYruiQz/V3jSFddmy6hfxxkkBj8Z5J4J8bt4zXd1
         VWQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=lp64j9zq;
       spf=neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qgbxw4OMMlnjNoUIDS1FcqAKQndoT2okQBmVyHYrCes=;
        b=CmDJcZtT368KyHl8tl/AmYJeGvwh6qmH2HAkb6MZMMQpTyXaWnZPfu0W8UITTIjTKH
         PRfAbUAKUN1kBE91ExBKCStCn05NqMrAuZnYxCM2R2GeQJD1R1p3VqCF5OsmmmkY8q8F
         WQJ6gEu6AGvCubGDBnSrBQrcE6QauZReRFgv5z7NRAi+YHH2a0zUMsz4vXv0vyjKBk6Z
         EGhNScuvlIUVh+6CEyU1J+ljBStm71GZboo+T5N5KOOFwWXuEn0/FJ24gw9ICSWhxOhv
         qnVY/EIB+/Vxe8VkDAgUEZp6a8a6sEb8yjjLna+YAHrBIxmeIsPl0q/MPa0RduV29i2k
         VYLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qgbxw4OMMlnjNoUIDS1FcqAKQndoT2okQBmVyHYrCes=;
        b=oJ4UlZhSy6oTfYfV6c9atwMR1rnmrJmKUZWEIaGJadCgAxyx37r5MW07fIvo1JyMwr
         hL+7mFNYMrqh+QcgsJdFcDUk9OTYPmXJ2p/VIhfvINrsV0KrVVeKUTIBIiwPZak3hO8C
         LJblE3ztbMTxlbcDaOtteCLOIOxbDP8JN2HQZdcJCyfW+fK5oFT4uMIPB3Lz6T4T+oSU
         g8bLLDiGidv6YHLTjNSsE8ITUw1vuPKVPpl4kb9APWrFZ9UuineXsOspqRIWX/R/TrVx
         9mIso44ItVLlIG5oqMWCbOSXzCH7BU79tUbSjXTyZE6SNasJZEFGzHiUMk2Ye89HRvBP
         mDGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320mI+KaLvXlmdQ+aCdX0UdeaZbUqMZNMW4UILd9GFS8M9Xh3Lx
	Y2BVAgDPlmVkzS3gqVWpldU=
X-Google-Smtp-Source: ABdhPJz+vzT3FA9VYJHEOq4muiKnzM0cKRgj6GXlUbDXHi9cKBg1tPt6DwTCP2Enm4kIHlb7iBA/9g==
X-Received: by 2002:a17:906:4a50:: with SMTP id a16mr12420003ejv.256.1617336673300;
        Thu, 01 Apr 2021 21:11:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3592:: with SMTP id y18ls282263edc.0.gmail; Thu, 01
 Apr 2021 21:11:12 -0700 (PDT)
X-Received: by 2002:a05:6402:1649:: with SMTP id s9mr13441834edx.177.1617336672449;
        Thu, 01 Apr 2021 21:11:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336672; cv=none;
        d=google.com; s=arc-20160816;
        b=0DHT3VkwII9ZtyxnvOQuLScp0L1nXHzXgukVZr4RylLtci6vLUTGFAZW5rj6/zww9C
         5EHru5MhUKhqXtO9r6JJ9S0P/uWiGpQovcNM8Jaeo5jVfioW3LrB3BNp6XvlxGTcFgZs
         MA4326Vw7Laq/PYc03LEyvc5chnJxnselCDBuQRbrYBjhPbz+GqoK8h2XyL1H9Hkm4lM
         9huHeJQS5M1FB83lwPv6f4IBoq04jznqK6WkQ3eZ/0kd6JHC22eTz35wlVPl+O9S8LUZ
         e0VRSWCUoFgRNSXCqCJZ14BeVTgVk2gIojZuK9bOwPtkxo375cFcube76xeS5Z7d4NP9
         u38g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QCaXwDV10dhKrn8kJuleYfg1EWrPXQo+wqW+nmg1Iys=;
        b=S6+ci8NAzkklOShRDI+aIE1Y9TEBxEIYKVlYtBDd7F+/aa4GvOFhrBtMnmoitnpmFD
         9Apl4BI/kTXzwdpmnhvVwO5MDFUItQzMVrMGCEvRNo43nR2p+c3BFwgFlVSH/gzB8i85
         2yXwACrI+FwsotyAiNJcRamltybsfkrzTtpl/K4+pLHPW3FoNgpNqipAv5jjJkPf9GJn
         S142MiJrHsfnXVTr7DT4H5BBLI3biW3pm/h+YSYFoWD0k8ithW7oUbNLVuuGygl9orWL
         pcA3irVt9wokPYCpcc0XuK6JjYh3tTxGSpZvci1Vxd2qX1HopGlloaiRkPYttjDKrR9G
         2O9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=lp64j9zq;
       spf=neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id m18si528886edd.5.2021.04.01.21.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:11:12 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::434 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id v11so3657541wro.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:11:12 -0700 (PDT)
X-Received: by 2002:a05:6000:c7:: with SMTP id q7mr13166768wrx.356.1617336672119;
 Thu, 01 Apr 2021 21:11:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002621.409624ee@xhacker>
In-Reply-To: <20210401002621.409624ee@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:41:00 +0530
Message-ID: <CAAhSdy3-n7ASkPXN=UsQW72gY5JH-J3Rf7W6kfUxXV6Zdb5hDg@mail.gmail.com>
Subject: Re: [PATCH v2 3/9] riscv: Constify sys_call_table
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
 header.b=lp64j9zq;       spf=neutral (google.com: 2a00:1450:4864:20::434 is
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

On Wed, Mar 31, 2021 at 10:01 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> Constify the sys_call_table so that it will be placed in the .rodata
> section. This will cause attempts to modify the table to fail when
> strict page permissions are in place.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/include/asm/syscall.h  | 2 +-
>  arch/riscv/kernel/syscall_table.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/include/asm/syscall.h b/arch/riscv/include/asm/syscall.h
> index 49350c8bd7b0..b933b1583c9f 100644
> --- a/arch/riscv/include/asm/syscall.h
> +++ b/arch/riscv/include/asm/syscall.h
> @@ -15,7 +15,7 @@
>  #include <linux/err.h>
>
>  /* The array of function pointers for syscalls. */
> -extern void *sys_call_table[];
> +extern void * const sys_call_table[];
>
>  /*
>   * Only the low 32 bits of orig_r0 are meaningful, so we return int.
> diff --git a/arch/riscv/kernel/syscall_table.c b/arch/riscv/kernel/syscall_table.c
> index f1ead9df96ca..a63c667c27b3 100644
> --- a/arch/riscv/kernel/syscall_table.c
> +++ b/arch/riscv/kernel/syscall_table.c
> @@ -13,7 +13,7 @@
>  #undef __SYSCALL
>  #define __SYSCALL(nr, call)    [nr] = (call),
>
> -void *sys_call_table[__NR_syscalls] = {
> +void * const sys_call_table[__NR_syscalls] = {
>         [0 ... __NR_syscalls - 1] = sys_ni_syscall,
>  #include <asm/unistd.h>
>  };
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy3-n7ASkPXN%3DUsQW72gY5JH-J3Rf7W6kfUxXV6Zdb5hDg%40mail.gmail.com.
