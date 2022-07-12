Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCUFW2LAMGQELZWY6BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C580571C22
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:17:48 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d10-20020a170902ceca00b0016bea2dc145sf5651335plg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:17:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657635467; cv=pass;
        d=google.com; s=arc-20160816;
        b=VaPoB/xpym+epksDwGhJOWWCZ/lz/k9eWeYyhHKz6qGP/DwlaO6InurGdhKBej7Uqv
         VUAziFHaHqpUZV0XwED+3fRlHCEYoi6a5fu/sKPkZvSgo39J/Qy2xbMp2Pua1gCMlFa8
         hTv8Z9yxFkoecPXxS4o+4nziI+2olBMqGq9hKSBwJMQUPj6fzC+PQtIUHV1xoR1EDta4
         EW3RlNzBUv2GJZKBqa9RAkhM/by3omQE+K7d3S2tSUufFR1l6I4TJ35XMlwbHy+T6I9b
         JasBrproN8QNG5baCqdxohaZEyU2ATmQxdUintCYlYKmyatvfYjwmY1rD0eXkGQG66vp
         Kutg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tgp6/O7Dq9EzCZf3tmqhdsGsxQttnRDSL1nmH8yBHlI=;
        b=Eztfs+dLcd4m9jFEYBIUb/X1nH9vl78CZSbC2NNo2Wf2nGpKNPY1H663Z1TOVxYo2L
         i2w+WWCMrkf3ncnby10qPuyyfQLmMNrtgRSEuw+WmI7iphEZRJKSm/s1FwIo1cenmEBf
         0YKW7HgGm+lSlVXEHA+F1tqrFPFChQ+SL/haiPpGZMk/dEiwG579c0BZkN7cuGaqJp1K
         jdZEz0qXJ5vdEFpAVAUNeLvlw8hnHLs2LZLQALXw4rxwrXwbvDhKKlxedQ6Za4fqrMJP
         Lm6nAvIPcwshQTB7LmuJ7NQr95R/RxzCZA9JZGk/DaKdHqO2dcrO74zF9OGJGOXlR5Ec
         oX3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KBfwn0NW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tgp6/O7Dq9EzCZf3tmqhdsGsxQttnRDSL1nmH8yBHlI=;
        b=VqEOzU3k6sXDGAFcoZGHyr50fcETMZ+guJf2ESa30aFMP5W0NVZCnI8zkH8LRcBxzj
         ph5i2okJiMn8nhxY4w81PaFf438x9uXCJsUTV1skcZnMlkxMdXK4gLrUxlUKHU4ysh/B
         1vFDLIbgTlB1x4rxtuelLh7xXjh+4aWsZQJPk6+DQOs4glGi6HD+XQiAnOoQfHaj+Cfu
         OrSqf7FyeuHRZNNf3XnsoXaEbrx22v/T8y6h/5PvikS5MMWIfM0PB3ZHQOa1BZ/rrfbL
         GsozBsDdyKgSZMZwZ8zh1E/U255wuc96hk678QwC5VDycWJHq10fpDqDZiorveXVKn98
         SNkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tgp6/O7Dq9EzCZf3tmqhdsGsxQttnRDSL1nmH8yBHlI=;
        b=HzFTBDvmsHwmwmoh3h/etqYSVJPQIIfj0l/N30Ti30KTjmx+fKykYTII9AhrEXl0i7
         cs+bN72x+TQ3hHRH82AYh1qFkJy2gLLciQdaqZl9Nn5lzBK+W8dIqPZ/keXL8EFnbBqw
         IBfZNfX4aB6AcL5Y5OdjlVS1HtAxqujWsEHE/FrbvI82dzzZmXqmevMZgg0TQPUNWq9Y
         +rBybc/rp+ZkPOY46JYBpP7gag0t/fZi3Isy7/mNWUfIbinzBHreijvhyeKWJ8kOr2Mm
         6hhRdNwjTrxxwCBup/nGUxj4nX85TKjTk0bwMRz8E6j3ruOUyJwTZohN++paQhe8IXXZ
         zaMg==
X-Gm-Message-State: AJIora8+iuCCVwfxHb0HmcdCqq7oYzyAKaRMBkl4S0UeIyqdDcPKmq9P
	ki49IMYjZA0GV6RJvd/zTMM=
X-Google-Smtp-Source: AGRyM1vPOyEpeZKIbvIjRlIkxF/OB02TMKQRwUzMdmOjASNlKt7vWEfdfZwpP5OJxjf1bEXBpFCgxg==
X-Received: by 2002:a17:903:11c9:b0:16b:8293:c5a1 with SMTP id q9-20020a17090311c900b0016b8293c5a1mr24154983plh.72.1657635466997;
        Tue, 12 Jul 2022 07:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7bc8:b0:1ef:a483:c629 with SMTP id
 d8-20020a17090a7bc800b001efa483c629ls1297168pjl.3.-pod-prod-gmail; Tue, 12
 Jul 2022 07:17:46 -0700 (PDT)
X-Received: by 2002:a17:90b:1c82:b0:1ee:eb41:b141 with SMTP id oo2-20020a17090b1c8200b001eeeb41b141mr4748879pjb.143.1657635466259;
        Tue, 12 Jul 2022 07:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657635466; cv=none;
        d=google.com; s=arc-20160816;
        b=WHr0TXJZAjucdqxAdcVcUuRZA6FGpPDCER06aLB3LYVOUJzTewky0hi5UlYw1xElCp
         RNRJzdogDVDgmdEUsV6dOG/AWkIgx7zELkiL3bfpspq8sqoAWSTmuPvsgkuE6LC6RjJV
         A09zzGgmleFfJ7D51pJknR70OlcytNMYdzrM04/LpuSGr1BEbwCXH35poONhl/eSoDgU
         6pUHBvkN+xxgXdMZetbhJfg7NKzEfuDLnJCZ1autqxdfdKjkSdqQdV1IDnC8bTjj+JPo
         ktU6sO3bjZEU047+jJfKCO9f3+6gm9aQYiVWuCXqf39RbWxRZqyJGO/VLhDjnACC5jf1
         CSrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0beGq21p9DMXHd5s7bgYgiKqbqbtLOLYpdLEVtFVxzo=;
        b=sHQLWeeV6VLVz1i7svDOWEkeitqIVDgtZJTFXIJd9AyBG+OpEHU+EldcKtUE4bpxss
         qWciTPepxoGqIeo4ifGUFkdte9HHceZWzbWn0EqOzlToZdRGTZZVyX4KMYApSAGCGU+M
         Tq8YlPmYpzXs/wfKlJkIBM6a2EpAAPfY96RdWyzH/EldnHjZpIsQ951bK1T9qAZiSCpt
         82M19NAFE2NvagpmycTlJyJn74TNLTfXfSalfYNg66rMd5erIyu3xXnOVGhn6ebUyCNl
         Qfe0meMcb/wULhd8HKHSaYwwiSe/b0AgsGEEN1qIQU6OekkkSghDf9o8F9UoLQQhLUSx
         n/aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KBfwn0NW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id np11-20020a17090b4c4b00b001ecb6b8678fsi270263pjb.2.2022.07.12.07.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:17:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id l11so14108534ybu.13
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:17:46 -0700 (PDT)
X-Received: by 2002:a25:2d59:0:b0:66e:32d3:7653 with SMTP id
 s25-20020a252d59000000b0066e32d37653mr22600223ybe.625.1657635465536; Tue, 12
 Jul 2022 07:17:45 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-6-glider@google.com>
In-Reply-To: <20220701142310.2188015-6-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:17:09 +0200
Message-ID: <CANpmjNM-hotpgDZqHvutHedoEbyeuuNeoPQ5UR4Op8rs6itr3g@mail.gmail.com>
Subject: Re: [PATCH v4 05/45] asm-generic: instrument usercopy in cacheflush.h
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
 header.i=@google.com header.s=20210112 header.b=KBfwn0NW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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
> Notify memory tools about usercopy events in copy_to_user_page() and
> copy_from_user_page().
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
> Link: https://linux-review.googlesource.com/id/Ic1ee8da1886325f46ad67f52176f48c2c836c48f
> ---
>  include/asm-generic/cacheflush.h | 9 ++++++++-
>  1 file changed, 8 insertions(+), 1 deletion(-)
>
> diff --git a/include/asm-generic/cacheflush.h b/include/asm-generic/cacheflush.h
> index 4f07afacbc239..0f63eb325025f 100644
> --- a/include/asm-generic/cacheflush.h
> +++ b/include/asm-generic/cacheflush.h
> @@ -2,6 +2,8 @@
>  #ifndef _ASM_GENERIC_CACHEFLUSH_H
>  #define _ASM_GENERIC_CACHEFLUSH_H
>
> +#include <linux/instrumented.h>
> +
>  struct mm_struct;
>  struct vm_area_struct;
>  struct page;
> @@ -105,6 +107,7 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
>  #ifndef copy_to_user_page
>  #define copy_to_user_page(vma, page, vaddr, dst, src, len)     \
>         do { \
> +               instrument_copy_to_user(dst, src, len); \
>                 memcpy(dst, src, len); \
>                 flush_icache_user_page(vma, page, vaddr, len); \
>         } while (0)
> @@ -112,7 +115,11 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
>
>  #ifndef copy_from_user_page
>  #define copy_from_user_page(vma, page, vaddr, dst, src, len) \
> -       memcpy(dst, src, len)
> +       do { \
> +               instrument_copy_from_user_before(dst, src, len); \
> +               memcpy(dst, src, len); \
> +               instrument_copy_from_user_after(dst, src, len, 0); \
> +       } while (0)
>  #endif
>
>  #endif /* _ASM_GENERIC_CACHEFLUSH_H */
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM-hotpgDZqHvutHedoEbyeuuNeoPQ5UR4Op8rs6itr3g%40mail.gmail.com.
