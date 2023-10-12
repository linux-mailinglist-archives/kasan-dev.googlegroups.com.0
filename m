Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHOGT6UQMGQERJMZOEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C9A77C6DBA
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Oct 2023 14:14:23 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3516575f07csf1194435ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Oct 2023 05:14:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697112862; cv=pass;
        d=google.com; s=arc-20160816;
        b=El1hNE/I190r/OaxqR+2OnDj3KEXCjcgrFVgS0NGO0e9s0CqFt7IOaAL+KAn9U+mom
         pUagmCL3wCYVRqmnjspbMtQxDK5KI1pAv8Juiomz4e/yD2JJKUGwWix+uy0yM2nFxaGr
         /m4TdNln/rmDUu/zBW6XLp6zD4al1oiRGf9wSPaoYYYKpK50nSu7IPE9hbL+v2a2mGQx
         wLBRmeEeV+M8pcf0H+edpDQRdygcO+Aym6xRywXnSsAUQMCKo7uLoOpmPVq7uywgXEjP
         arH+KidCQKAcY1v+DtxTXx8Pu4X91TsTVPJgTEb2OHzN2AlIs4u83pBs8VtOtgkCy/YY
         neqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QnUigKwiHYrX1IL2RoMIW5wqmS9QmK+Fvwcy7s0EUWU=;
        fh=WMCvVjgx0Aik5Uwj4vIj5310umnHyW3lCSjPE3tgfK0=;
        b=LuPneFBKh2+BBTw50iO5ESBG61xQyzNJBGBdMmppLwMwcKTRfqaYmCwZ5iwXvSP9FW
         5HslIbfT5VDIAO3ghIkPv39HEB9AjpTARuZrtWgPCaujHjqUr2eAL/Wv4BxqBg6fNI6s
         X++kurW6Xl5wBEIHuPuO7QYhSWbt9OWcvUFcWLYOl4fwgOqdPVOIdDsAXmwJFZeg3atu
         ap83hdcOO+J2VMdjFey0TkFpI25BdEgSFuqQwfW4txGlstMQ7AXLuWXE8oW7FBfiMKLH
         yoQR9KrQxqxsOKGscDR7ehs1xX6DGy3hHz+VxkABLD7CTCxHOXcmWzk4v9pKkBVhWp4v
         H3ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mo1JfIV1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697112862; x=1697717662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QnUigKwiHYrX1IL2RoMIW5wqmS9QmK+Fvwcy7s0EUWU=;
        b=T1Oi70DXB/oN5isM5Xd9bysfK460E+tC2KuoISYQ97+5KvpQhXS9qfaL1cE2ZyCacH
         e453BJdjMnrKRs3iqQQbylSdNslZuE+75cL6mFUTfCx+EZd+Y4YApXwqpHtGH/MTk1yA
         86V4Ilgt3yoKEUcMVRC+uOmRHbRIxCZLV9MtS3Vp4E33mGDpneyTG75yMScCc3Y3467E
         Oz9TSXvkj+11GRUHjkySqYoaf6vzQCEz/2g0iKSJI8D0PqRhWZI1KJkjXYfLQE991WEq
         E4TYk6D1F6kR0y5cQ98xnddiMI7xrr5xeNx/SlmFrjv6h6CCfRIMiAYRoS5mUqoP2YPC
         SYGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697112862; x=1697717662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QnUigKwiHYrX1IL2RoMIW5wqmS9QmK+Fvwcy7s0EUWU=;
        b=OzMsNVMMhaMK428ThjDRRHKwPDki9h0FmaaYSCLqTAHWg0m3FvubLvnom8skfaPqaS
         7U4OIWpSDXyKOnLXmPRANXZZICmtsqP1ZbiSw40mtgHdtKom1BgbuwOq9Lf+bn5/PDJr
         7o94RRV5V3p0eVZJ9UCd+sG14TkfawPM6agkIMCkmY2wnJTYoy3dhnEG/CfkH6nvfJYq
         Gmuk9cjILKNtpt9V/1iS12V8HVjCtUK3STmhBMwpyL6PHIpp6GwK5FxnWf/gBJfgW8aQ
         g8byO6NzRKccqDtwmd+F/W5JApdpMhO/OqsEnUMr0HQ/+dWYHO7XKPOPsD0N3/8AXs4z
         2PWA==
X-Gm-Message-State: AOJu0YzV5Ospe8oflFsrcKHBR5NlPAvFASeOSKb5STajJWe1nw9THRE9
	2nWCMhCifJnyOvFBMSmKh5g=
X-Google-Smtp-Source: AGHT+IGexO2QQEI6LQwaZWa7rEhpvefWmeb00C14Y5ylp8ceqdmbiqT1KhEPaCHDSsx8Ku8rq24vow==
X-Received: by 2002:a05:6e02:1648:b0:348:d80c:ca16 with SMTP id v8-20020a056e02164800b00348d80cca16mr575330ilu.5.1697112862067;
        Thu, 12 Oct 2023 05:14:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:33c5:0:b0:57b:5e7c:4b12 with SMTP id q188-20020a4a33c5000000b0057b5e7c4b12ls127568ooq.1.-pod-prod-08-us;
 Thu, 12 Oct 2023 05:14:21 -0700 (PDT)
X-Received: by 2002:a05:6808:211d:b0:3af:5aa2:a3d with SMTP id r29-20020a056808211d00b003af5aa20a3dmr30985139oiw.40.1697112861277;
        Thu, 12 Oct 2023 05:14:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697112861; cv=none;
        d=google.com; s=arc-20160816;
        b=LOmYTBxdqP7vwHVyznnffK/zEFU/T5TeBk3tlY6tnMxGCvZhjeEKyTB+oSDuhr9u6i
         WXQvOv7Xy55+tQQ3MUhWqDR3hY0qIq16Wum7yiwjr6YodXHqNproAsOAYyp+P6C1/s7x
         EwMd+L45l/qwtyQtSDEgs6K+3IIUxDJ6omrUgIl9VOO4+w41rBqKPSrb7Pi6ZhQ9kyb8
         ozDZWfd/x6ah2ghukfvcafxBWmoPBs3icZHdOINGtTawZSgxXjHBFZm4hja/9yJwbtiB
         9HhW9JBMMq7ktvxRgqWHIlyjndpQaw5sgQ/dBnoHFUU5eKYwRO52C3Z8w7yaRekwbU+V
         sSqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uIVKgMbPrdbBiBUZkSG3/934vJNvcwEmUkQTpoFMZCk=;
        fh=WMCvVjgx0Aik5Uwj4vIj5310umnHyW3lCSjPE3tgfK0=;
        b=pTT2MDr1C6IASHcWeR2stk3wqadmGBOHzIuo5YNPeE6F1i7u8HSOSyJzg8EoKFsbSp
         HGlDeck0Y0Q2hJOGxQ41F5xjuGmfJhmqo4oXcRZG0vyCxt5cbvFNJCmt87Cs151FtApJ
         Bk17viJFD34Y98j/yTkrmsl8RBjg5Bju6U2fz+LaJtpdbrsGVYzXmt2U2o9Vkxch8lIW
         +NOOXmB2qL0v9y/2ZZFjEcoqbRExh8+5R1NaFLMEVaYt+2pBCmPGoJt2YRkQwLD6kKlA
         I8caDqQ6uMdwroHOaosJSwYQ5nZYzOCjFEAbDyR/ya/9OnRJSJ/VcSDv3F1D2O9I8AcF
         x++Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mo1JfIV1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id gr18-20020a0568083a1200b003a843f1814csi143930oib.4.2023.10.12.05.14.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Oct 2023 05:14:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id ada2fe7eead31-4577f61c6adso338558137.3
        for <kasan-dev@googlegroups.com>; Thu, 12 Oct 2023 05:14:21 -0700 (PDT)
X-Received: by 2002:a05:6102:54a2:b0:457:a8fb:3251 with SMTP id
 bk34-20020a05610254a200b00457a8fb3251mr3718012vsb.0.1697112860491; Thu, 12
 Oct 2023 05:14:20 -0700 (PDT)
MIME-Version: 1.0
References: <20231002151031.110551-1-alexghiti@rivosinc.com> <20231002151031.110551-5-alexghiti@rivosinc.com>
In-Reply-To: <20231002151031.110551-5-alexghiti@rivosinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Oct 2023 14:13:44 +0200
Message-ID: <CANpmjNMvQUSNU+U80nWrUWPc4sszvSTGvivJjk0HOw8LRWx1sg@mail.gmail.com>
Subject: Re: [PATCH 4/5] riscv: Suffix all page table entry pointers with 'p'
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <atishp@atishpatra.org>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kvm@vger.kernel.org, 
	kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mo1JfIV1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as
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

On Mon, 2 Oct 2023 at 17:14, Alexandre Ghiti <alexghiti@rivosinc.com> wrote:
>
> That makes it more clear what the underlying type is, no functional
> changes intended.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> ---
>  arch/riscv/include/asm/kfence.h     |  6 +-
>  arch/riscv/include/asm/kvm_host.h   |  2 +-
>  arch/riscv/include/asm/pgalloc.h    | 86 +++++++++++++-------------
>  arch/riscv/include/asm/pgtable-64.h | 20 +++---
>  arch/riscv/kvm/mmu.c                | 22 +++----
>  arch/riscv/mm/fault.c               | 38 ++++++------
>  arch/riscv/mm/hugetlbpage.c         | 78 +++++++++++------------
>  arch/riscv/mm/init.c                | 30 ++++-----
>  arch/riscv/mm/kasan_init.c          | 96 ++++++++++++++---------------
>  arch/riscv/mm/pageattr.c            | 74 +++++++++++-----------
>  arch/riscv/mm/pgtable.c             | 46 +++++++-------
>  11 files changed, 251 insertions(+), 247 deletions(-)
>
> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
> index 0bbffd528096..3b482d0a4633 100644
> --- a/arch/riscv/include/asm/kfence.h
> +++ b/arch/riscv/include/asm/kfence.h
> @@ -15,12 +15,12 @@ static inline bool arch_kfence_init_pool(void)
>
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>  {
> -       pte_t *pte = virt_to_kpte(addr);
> +       pte_t *ptep = virt_to_kpte(addr);
>
>         if (protect)
> -               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +               set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_PRESENT));
>         else
> -               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> +               set_pte(ptep, __pte(pte_val(*ptep) | _PAGE_PRESENT));
>
>         flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

As others expressed, this seems unnecessary. It doesn't make the code
any clearer to me.

However, for your subsystem you make the rules. I would just suggest
to keep things consistent with other kernel code, although there are
already stylistic deviations between subsystems (e.g. comment style in
net and rcu vs rest), I'd simply vote for fewer deviations between
subsystems.

Real downsides of stylistic changes that have unclear benefit:
1. stable backports become more difficult.
2. chasing a change with git blame becomes harder.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvQUSNU%2BU80nWrUWPc4sszvSTGvivJjk0HOw8LRWx1sg%40mail.gmail.com.
