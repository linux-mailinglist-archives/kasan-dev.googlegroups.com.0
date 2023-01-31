Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNI4OPAMGQETQO7NAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id BC0356826D7
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 09:41:14 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id x22-20020a1f3116000000b003c67dc01d12sf4974182vkx.17
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 00:41:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675154473; cv=pass;
        d=google.com; s=arc-20160816;
        b=1AgUVD5vZOdcc+fLpDE17AH7RQOHCKweWelia0ms4+Tjzd19yfxswSwyr1J2++BTWm
         KhJafLNU+9JCi/e00FkyGhYphR8KEM5Upb7BSVkC3HD9fBHWNdqnCSM5Xfg5qhshrglF
         zp3RDV5biQSPrK8Yl0lcrrF2QOv3VeLy37Jov8a/w+1v/WVarfNjwOBYVYA32+5m44vi
         zSZlK+BrlhtIqzG3IT08PP+Fuz3Lu6ogsA93Peiolo1PJOhae0vbpeBap9Nilfctec+z
         S2xraMXVzVnNmu0gqlJOFIuiKdO5uO8B8IInK/iZaQjPDCrXennbs4DFDxBk4l+jMcbp
         0ErA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5IX8S8t9e8sSNAJLZa0QVxpzeZPd2vor0AuBruoty2A=;
        b=GdVtqdXAFiL3r3Ac7Nmm+8Lla8vfxgXm0bCBp+T/Hxs0OnCpo42PeoPKPeooxQH1GH
         /qfo/BHSJK3Z223xWIzk/eh6o81yLiS4qSlyfq0T8CsGEPziMz66lKUpxAlaX/oDKytn
         LF5cJ7fthJxhnIDjArUx23m4Iz+tG8mxSMStreQTrmsxUp2dMor/1mdk3IIDqlfV0N+j
         7cxRzzH8ujgw6v3QW3GOTikze9Rewnl4f5Uf8UThx801HC/M4wsxQTB6XwPZD5Pkhzs6
         qMUJi5zCD62l9h9rORIKQYIpB6vKucP4wSCHzviftYaQl8iJ/ANIxYAn33DmcwAxYkpd
         9Mww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ETAdz3U3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5IX8S8t9e8sSNAJLZa0QVxpzeZPd2vor0AuBruoty2A=;
        b=KiMEZ2lRc0rr8vSviBPAE0ENXdf5sDXtHbiXIdfAZD1yno3XtFxjl50jv1LQUmOmZa
         NZAEbaaHXSfM/NUp2KrSB4kIEX16hb+0/lEhxSXfVlOBGO/y+ceTCFEWfIiQW8/BR/WI
         dWHmuS1mbbiEZy6u2gEYwgIGYxMpMGKr+qUmT/yciFXWFPkdk1LhSD30ZzXkS37FRI00
         KilvT3BAII5HMDkjV14Lgy8kW7wU2P7U5X+OfNPISnIDHFRnRXAi5eo25cigVEcwTuW7
         mGWkosfOIGonsyYXE7LUuhBukH7dP0HyZZZ3t0N40tcRHZyycjnrhxtXmUWWsJO8ic83
         u5Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5IX8S8t9e8sSNAJLZa0QVxpzeZPd2vor0AuBruoty2A=;
        b=v27dq05eMHaZ/C+o0n/rlhdfvcTzwgwdkm9hlSSZFHCHx1gpKr1IZ8dfFGdNOKps4+
         qigC3ja6QOCnAo2YzYjeRgUhfMQDvAEYiCRNspLK3E8fHLudmPK02ErZ8/tuCSLk63mR
         6JyFzUU+03XI157qBSSpBaYJIePrJlOhjYbijmeLe300tNpGJzmveG5Kv2TzIZquhKvE
         AvHT4aTLsETUZbYENyl0ZLYo2yLnl6JtNTDgOlcruf4r9pqJ/lw0+eQ+lX398qgFZqr4
         CY9QotKituWZdnZROPJa3oF5aXmJhl9kDW6Vyj7x9M6zriQtR497dM32LAgUcaodhDVh
         /CQw==
X-Gm-Message-State: AO0yUKW2T7nfV/0KOi4ZWMYl9M+3HGXigATvUL67JYvJzSfmdKdqfcv1
	TpHpVpZfhe2gKd7ozoF7ZiU=
X-Google-Smtp-Source: AK7set93Tm6KC4EhSiemcRBS1z1QR8C1r/Ts0KmF/wYnhIz1KbNzw0xPWFGgtukcoUSJEnq3bW5AOQ==
X-Received: by 2002:a05:6102:2850:b0:3f1:5e87:e293 with SMTP id az16-20020a056102285000b003f15e87e293mr1714217vsb.79.1675154473620;
        Tue, 31 Jan 2023 00:41:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e259:0:b0:3ce:af9f:92aa with SMTP id w25-20020a67e259000000b003ceaf9f92aals4481815vse.11.-pod-prod-gmail;
 Tue, 31 Jan 2023 00:41:12 -0800 (PST)
X-Received: by 2002:a05:6102:109c:b0:3f8:bbb2:941e with SMTP id s28-20020a056102109c00b003f8bbb2941emr2877493vsr.5.1675154472888;
        Tue, 31 Jan 2023 00:41:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675154472; cv=none;
        d=google.com; s=arc-20160816;
        b=xL+wDCfQwsaemRXLcBV/zaqxPNV5EmLZa3BGoQGhu6OuDKEhXiyoTl02qlxaYXzzcb
         iXZLAVDMVXS/MJogISAVVNp2rqZXZnf42OF/o+JDQr+fh/yU2ygEiceI+HDcw5KchcYb
         QkZo7zMWjq1a4XpZCJ79xNzZkyqPlnc7CoK+Sp8VIfQtfcsaNjCKf/jEGmw8w3mAxHbr
         DYI2n/n2z2WlECjzMUvv5b50huUcCKLQg4BRYSXTPsO70Sa7DztLsNQsiFktt9uCU9Zj
         8Fj1EDRMpbi18nrKb+09FY99nLheuqEX3EBLc+QchbvUgIg11Mc89Quf9J8v4JedaB7E
         j9wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yvlc2S1AAw794p9I4WDQhqKM70Pw3dKGUU8UcdesOEI=;
        b=D8sxc6zjDORec5bfIUMWphg5ZH58bfjsYZCPFhwuzAIrKV8A/EwXg/tDAuYMYeDxOz
         tpiT7saGPFIBElqkAim8r0Md+gAG7ABtF1ypziIeg8X+nZzi+8BS0LTcrSUNtPx/1H8V
         7AZbdKthj8BXzwvsLwuoE03TmWRrcQrCrfJPJQbuFAh+6nIPsm/O9LTkHFhO87CP25OH
         Tgk0d9SabcOd6EQGkZ9a2qPJczDs2Z/abVOwtSjLJv3DPmejaqJyzLoXklSsSCx2usvv
         +ik0oVgt7p63QAA2uC/WHcBQXE2V/EyuRjM3RdDX3J3fWlW7a1OVc+gbfW8FhC75SGJI
         U06Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ETAdz3U3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id u16-20020a056102375000b003d04209e4e2si909405vst.0.2023.01.31.00.41.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 00:41:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id p141so17150848ybg.12
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 00:41:12 -0800 (PST)
X-Received: by 2002:a25:d1d1:0:b0:80b:4d84:b25 with SMTP id
 i200-20020a25d1d1000000b0080b4d840b25mr2338010ybg.584.1675154472393; Tue, 31
 Jan 2023 00:41:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl@google.com>
In-Reply-To: <19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 09:40:36 +0100
Message-ID: <CANpmjNNzNSDrxfrZUcRtt7=hV=Mz8_kyCpqVnyAqzhaiyipXCg@mail.gmail.com>
Subject: Re: [PATCH 16/18] lib/stackdepot: annotate racy slab_index accesses
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ETAdz3U3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 30 Jan 2023 at 21:51, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Accesses to slab_index are protected by slab_lock everywhere except
> in a sanity check in stack_depot_fetch. The read access there can race
> with the write access in depot_alloc_stack.
>
> Use WRITE/READ_ONCE() to annotate the racy accesses.
>
> As the sanity check is only used to print a warning in case of a
> violation of the stack depot interface usage, it does not make a lot
> of sense to use proper synchronization.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/stackdepot.c | 13 +++++++++----
>  1 file changed, 9 insertions(+), 4 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index f291ad6a4e72..cc2fe8563af4 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -269,8 +269,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>                         return NULL;
>                 }
>
> -               /* Move on to the next slab. */
> -               slab_index++;
> +               /*
> +                * Move on to the next slab.
> +                * WRITE_ONCE annotates a race with stack_depot_fetch.

"Pairs with potential concurrent read in stack_depot_fetch()." would be clearer.

I wouldn't say WRITE_ONCE annotates a race (race = involves 2+
accesses, but here's just 1), it just marks this access here which
itself is paired with the potential racing read in the other function.

> +                */
> +               WRITE_ONCE(slab_index, slab_index + 1);
>                 slab_offset = 0;
>                 /*
>                  * smp_store_release() here pairs with smp_load_acquire() in
> @@ -492,6 +495,8 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>                                unsigned long **entries)
>  {
>         union handle_parts parts = { .handle = handle };
> +       /* READ_ONCE annotates a race with depot_alloc_stack. */
> +       int slab_index_cached = READ_ONCE(slab_index);
>         void *slab;
>         size_t offset = parts.offset << DEPOT_STACK_ALIGN;
>         struct stack_record *stack;
> @@ -500,9 +505,9 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>         if (!handle)
>                 return 0;
>
> -       if (parts.slab_index > slab_index) {
> +       if (parts.slab_index > slab_index_cached) {
>                 WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
> -                       parts.slab_index, slab_index, handle);
> +                       parts.slab_index, slab_index_cached, handle);
>                 return 0;
>         }
>         slab = stack_slabs[parts.slab_index];
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNzNSDrxfrZUcRtt7%3DhV%3DMz8_kyCpqVnyAqzhaiyipXCg%40mail.gmail.com.
