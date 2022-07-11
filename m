Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMMYWGLAMGQEM5TF5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E5D0A570813
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 18:13:38 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id l17-20020a056e02067100b002dc8a10b55esf341369ilt.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 09:13:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657556017; cv=pass;
        d=google.com; s=arc-20160816;
        b=sI2fbTXE0UIMJnaU7KFEQm6iThKphFBsXe2wXVO/eVe5w0ORIOj89Z2lVGNwDiVkHU
         OzRw6+lxm0PW4iWX5XLObd6JfvUCwdC1TfdMO6Hx1Uu8hS1V8cMZhIM+OpH7MBvEixBr
         Nw2i31F/sUCv548e3PaKAaRuZe4e4TS8NAVDN5PeOBLM65YKI6M4Ju2PwOdwqlasWQM7
         nkrutLLDJfISGnoCX0c7qHZnLPEL4isEvsRmQfxaWeHt5UOtxE8lE4jSjtennkUcVO3g
         W+Yx4TAaU6zshYQSOa8GtqjuZgBe4N47pt/2RmtLG/THkc8oUVm6Yoz5SFopuhLtsPMW
         ybSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MCLKIZ9Suwr+oWKC4NavsGmCWtNt7fTdh48LDv/L+M8=;
        b=b/npP3UZfkoNt+FD3o8IlqAiPKgfV6kkLBYcVjusOEOXUh2GT5McCiwhdISluEf7Kg
         9E7EWDyzdeS7Mnqlx38Jl2u08RhJzGiJDGGuKcHAqTHCSytWNasdF7hkqx+BhXLcdJ5s
         APTFiEoEl3KusTrOM1rGwtq8XA75BxPmUz4oEQkiCFDDt4dVL0IUyYVelOIFB0XKUpQN
         w+S9ScyIooUj2da3ybu00A8ozEm8kUl8XxW3uDaT2Rcvu3kFNLSgZyZZm5kE/xUk0LGa
         dnV93axre5gYjomqYDCK8+RXwHuwr9MRV6fuEz1okI8ZnPLde2u4VOsTViHg4MNQMI/F
         I0Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jfZhtAzN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCLKIZ9Suwr+oWKC4NavsGmCWtNt7fTdh48LDv/L+M8=;
        b=Xs2wlVYY4zI2cj0Z/xSOq2Br7vkzPqsSTAuEArMTV+gXysbfZNJdBYvvyOZn4aL+qw
         k4CkVMynYn1OXaPcTx9ovfr4J0xRyMre/Dq9l5HC1J7PGn85eijZORR0AjD/nRZY6s2t
         QOZSoyT+X8WrT3U2m+iI3t87pVyzcye7MYxZuGSXdESkce0xMGZDd+8T+x0ltViz1Z9f
         sQNcJgzn2AxISqD3ZVz3EKc2O5RclSGAYk63Wctd2LMQVWyS8URy0udVgvFVtbtFuI9i
         OL9eI1EgZpRJmm1rIzZgujie1QM5kcuu7pvKBmKtIP9jlNp6VkA0+5Yf5biIIo3t4KYp
         c2qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCLKIZ9Suwr+oWKC4NavsGmCWtNt7fTdh48LDv/L+M8=;
        b=VrJosgjId7uTKRRAkmVO3zLlpcQosu/ywhnsmmgEQIQ0RLBs0ImPrqNwR6e32tKGWd
         GAIj+qtNROEnz3YJrF2cBC21F8pVpG+29r39Y4iSw2eDLdO41bB6texUp5Rz2biFXu/R
         XZkSf0dXxosFbJ5gi8reABBYkZWD8Bc6HGY85hzmjOtPdAwDbtmdlmfyXjaJfhVcMwdB
         95p7y4HADUR99ox6Vto/gTSB20HVlG4ZCrQ+ofYT0DtqZZrPNg5S75uwWPK9tSIEHdng
         EoSUDWraiNWrMVsBfGefohO0Zkr7tUSfJZoGR6iRv2/T/iDV2kaYGz/I7IWtYAdLI43x
         s87g==
X-Gm-Message-State: AJIora9rDnXEwnocyhyGst/hxTikt8Fwm+Q8Kr+64XfV/fnxuYIVf0N8
	opFtY5jiBQd0KSJr0XMuSKk=
X-Google-Smtp-Source: AGRyM1uDko7OXPxHCyHT2Z1o7o1YMLIWJbnvVV7HDFhX9RXzCXalnazC+J8y8tdrGuT+Huf/DejO7A==
X-Received: by 2002:a6b:f718:0:b0:675:54cb:dda with SMTP id k24-20020a6bf718000000b0067554cb0ddamr10469296iog.114.1657556017328;
        Mon, 11 Jul 2022 09:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3711:b0:33c:9eec:3773 with SMTP id
 k17-20020a056638371100b0033c9eec3773ls23098jav.10.gmail; Mon, 11 Jul 2022
 09:13:36 -0700 (PDT)
X-Received: by 2002:a05:6638:164b:b0:33c:9b6f:457d with SMTP id a11-20020a056638164b00b0033c9b6f457dmr10386958jat.224.1657556016190;
        Mon, 11 Jul 2022 09:13:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657556016; cv=none;
        d=google.com; s=arc-20160816;
        b=xR2rnoFtykZyu7TkrmSd+BYovR9wKmQtsXiwQ9l3fkp3oJOXwKjM8eN08kVIKqwPTU
         /yeJ09h8acTauySr/XeqwxA4PZO4PBBmXdjZYC52dDCO9rHavgMYmhIpCltqdxebEKNn
         8mtaJ1+bpDk44ujcRYOOKybxAeliz/0+9nLEDZGFOLjE9kw+DgoLp7pid7Kx9wUfNq++
         vl3ONgSIOiBuK703D7A6gkOWLnKXJs2kB7EZBqrcdGwcly/yK9mQpF3Klx6J0VBiXkXj
         NYrGQNXLAyIcb63O0wUK7JnK5zce8mXS38iMUPzX2JJ5z7z05/3hGBtOkSQnW7xswzpo
         GMiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BOu1n0uYdCsudxoJVtyz5/UL8tUbc5xPCGC+9KrKzU4=;
        b=fqvNQHE2/owf3WOLr2GKoh0mD8jqWRXPuPh8M+3Ez093/r4x8siWOPtmFvhiK5mzqN
         Uy0zy1X2wG8+U+830sEHhbsg8+IpqtGcmh3U8d+PbnFz6GISVg045NlzEE5UGXlg48yZ
         3idOBXTkt5HvtW0YPfC6D0pV5NyvjAymF3znke/4YBxgvxmo1nV0IQRlgEZXPEviWYSZ
         zZIW0nkzIMr5rRKuYxSlKhARV+LvyHUax1ZgsvvGP3xMu0IFKP0S8PqkTT0xv0nqSAuj
         TNH/BCZ4ZcOtTVHkBzfiiFgwraXNljoAbiy7nx5Ox45ciFoFKBVj9UDEz65EEi/gdyuG
         T7XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jfZhtAzN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id k16-20020a926f10000000b002dc3bcad8f2si234722ilc.4.2022.07.11.09.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jul 2022 09:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-31d7db3e6e5so23622397b3.11
        for <kasan-dev@googlegroups.com>; Mon, 11 Jul 2022 09:13:36 -0700 (PDT)
X-Received: by 2002:a81:98d:0:b0:31c:921c:9783 with SMTP id
 135-20020a81098d000000b0031c921c9783mr19996386ywj.316.1657556015569; Mon, 11
 Jul 2022 09:13:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-10-glider@google.com>
In-Reply-To: <20220701142310.2188015-10-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jul 2022 18:12:59 +0200
Message-ID: <CANpmjNN8xD2WK_Au86ww1eqGaUbWr+B=m0GuzrDrbhKA=hJYwQ@mail.gmail.com>
Subject: Re: [PATCH v4 09/45] x86: kmsan: pgtable: reduce vmalloc space
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jfZhtAzN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> KMSAN is going to use 3/4 of existing vmalloc space to hold the
> metadata, therefore we lower VMALLOC_END to make sure vmalloc() doesn't
> allocate past the first 1/4.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  -- added x86: to the title
>
> Link: https://linux-review.googlesource.com/id/I9d8b7f0a88a639f1263bc693cbd5c136626f7efd
> ---
>  arch/x86/include/asm/pgtable_64_types.h | 41 ++++++++++++++++++++++++-
>  arch/x86/mm/init_64.c                   |  2 +-
>  2 files changed, 41 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
> index 70e360a2e5fb7..ad6ded5b1dedf 100644
> --- a/arch/x86/include/asm/pgtable_64_types.h
> +++ b/arch/x86/include/asm/pgtable_64_types.h
> @@ -139,7 +139,46 @@ extern unsigned int ptrs_per_p4d;
>  # define VMEMMAP_START         __VMEMMAP_BASE_L4
>  #endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
>
> -#define VMALLOC_END            (VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
> +#define VMEMORY_END            (VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)

Comment what VMEMORY_END is? (Seems obvious, but less guessing is better here.)

> +#ifndef CONFIG_KMSAN
> +#define VMALLOC_END            VMEMORY_END
> +#else
> +/*
> + * In KMSAN builds vmalloc area is four times smaller, and the remaining 3/4
> + * are used to keep the metadata for virtual pages. The memory formerly
> + * belonging to vmalloc area is now laid out as follows:
> + *
> + * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
> + * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
> + *              VMALLOC_END+KMSAN_VMALLOC_SHADOW_OFFSET - vmalloc area shadow
> + * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
> + *              VMALLOC_END+KMSAN_VMALLOC_ORIGIN_OFFSET - vmalloc area origins
> + * 4th quarter: KMSAN_MODULES_SHADOW_START to KMSAN_MODULES_ORIGIN_START
> + *              - shadow for modules,
> + *              KMSAN_MODULES_ORIGIN_START to
> + *              KMSAN_MODULES_ORIGIN_START + MODULES_LEN - origins for modules.
> + */
> +#define VMALLOC_QUARTER_SIZE   ((VMALLOC_SIZE_TB << 40) >> 2)
> +#define VMALLOC_END            (VMALLOC_START + VMALLOC_QUARTER_SIZE - 1)
> +
> +/*
> + * vmalloc metadata addresses are calculated by adding shadow/origin offsets
> + * to vmalloc address.
> + */
> +#define KMSAN_VMALLOC_SHADOW_OFFSET    VMALLOC_QUARTER_SIZE
> +#define KMSAN_VMALLOC_ORIGIN_OFFSET    (VMALLOC_QUARTER_SIZE << 1)
> +
> +#define KMSAN_VMALLOC_SHADOW_START     (VMALLOC_START + KMSAN_VMALLOC_SHADOW_OFFSET)
> +#define KMSAN_VMALLOC_ORIGIN_START     (VMALLOC_START + KMSAN_VMALLOC_ORIGIN_OFFSET)
> +
> +/*
> + * The shadow/origin for modules are placed one by one in the last 1/4 of
> + * vmalloc space.
> + */
> +#define KMSAN_MODULES_SHADOW_START     (VMALLOC_END + KMSAN_VMALLOC_ORIGIN_OFFSET + 1)
> +#define KMSAN_MODULES_ORIGIN_START     (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
> +#endif /* CONFIG_KMSAN */
>
>  #define MODULES_VADDR          (__START_KERNEL_map + KERNEL_IMAGE_SIZE)
>  /* The module sections ends with the start of the fixmap */
> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
> index 39c5246964a91..5806331172361 100644
> --- a/arch/x86/mm/init_64.c
> +++ b/arch/x86/mm/init_64.c
> @@ -1287,7 +1287,7 @@ static void __init preallocate_vmalloc_pages(void)
>         unsigned long addr;
>         const char *lvl;
>
> -       for (addr = VMALLOC_START; addr <= VMALLOC_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
> +       for (addr = VMALLOC_START; addr <= VMEMORY_END; addr = ALIGN(addr + 1, PGDIR_SIZE)) {
>                 pgd_t *pgd = pgd_offset_k(addr);
>                 p4d_t *p4d;
>                 pud_t *pud;
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN8xD2WK_Au86ww1eqGaUbWr%2BB%3Dm0GuzrDrbhKA%3DhJYwQ%40mail.gmail.com.
