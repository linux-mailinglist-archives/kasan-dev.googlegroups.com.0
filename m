Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD4FW2LAMGQEQPE5PCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E84E9571C23
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:17:52 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id h11-20020a170902f54b00b0016bfdca124fsf5661939plf.9
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:17:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657635471; cv=pass;
        d=google.com; s=arc-20160816;
        b=SCl44xMiHYy4kZRs3MGCkqr7insCGjwEI4jTMo6AbwPO+aU8w2nwBq+5EifaPsk4rG
         O3FDu/nROJ6RJ94ye43dK0u9wRsx8UgwZm2K03uHX5G89m6s+3XAjVJckq50+1AI9Z5r
         W+flImWD8KIl2Sf7Ktg2SLg9a/73cMVueGXpnZY+VcsSXJCZIIBT+m2WhatZgSnm3qg7
         qzAPAWtKsiQSnxewtV+R1CFkY1esNld8+z7K7eEdKC5Nikyy9jPlMApMoJVRkz2o6vZl
         PODr8Zf94Po6MdbnRihtDx0ozFR0D3LRZwcGRrSx8D9JiVzuEHytEgQN4+uyjJoggt1Q
         qbYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aZJoCpzkOCS/aXOT2xIs4IrDeARHjIJAHnx+nOVkudQ=;
        b=zqE4bTbu5NbvYgqUXMU4DrzHX9AuIsfAqlj3b0tWUqpXiIVSCvf5N4Xob+MEhKj1CJ
         aDNhdmGXY7MK98OoymvzuCEtZfodiEFVVikPW/51c/zZXytjTdpKaKpFPOnzoWFZBFBw
         cboaz/yUI/Yki0jk05ipt3Va3oxVcZwRrygNTnPU1Mm7VcS81UNSRI4UpKdWlyYVj9U+
         uctpEBZEU/EHCZY0dvzAgmcCZz90oqy5rVplQdJQC/fPmyrMpnFFjzGfZUTCHIhov1Jw
         QZZ1XHUkiA7wUw5wBEfRGavu1OH53CfXbmHmwvbb8SRqzvcLbb/yn7IqJKdskDGTKG+x
         2blg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aiMgzeBm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aZJoCpzkOCS/aXOT2xIs4IrDeARHjIJAHnx+nOVkudQ=;
        b=AYwK/VXwa+udkTp6y8ecG8ywptRD7YvS9MSmkw1lnHZ59qe8z594McKGA926HEh4g4
         4tdr90WctkCNarvd2UlCKlmAzOXYmMwCsJyI3+t/kZ8G0hCGeH+PbyKTROIlukL1E+lS
         s0+q1oSM4R3gH9oIpu+LBiPTIX7CTRQi+nT2EvIZKZ3dEtZWzSNI83avpSNl/5XPy9ZF
         aTzg8vmWnnjrwI6XLPza11gSSiPldzRvgvc9IsKvgXD5PU7s0EJRsGngfrI/vqAFxrnB
         ZgBDJpZjylmShZ+nu8dGOmrPRDDb9vD1PGmzSOFcX+gJVitkPH7OyKR4EqkDlvuRGagC
         OivA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aZJoCpzkOCS/aXOT2xIs4IrDeARHjIJAHnx+nOVkudQ=;
        b=Q1YaXtMP72wlkQlGqTl0HjZDxyyw+nlDB2i9Fw6xP4kbycX4d9RvooolsVn/PeSpF9
         BCm2oFArw48wD3UAQRYVP2zF8DOlMYSOfwARPvIqr4mkbeRSTa1aE9MZLiS5f4nkJ5Yy
         NdZhzryM7BdBTE4bw8v4f/+iSDvAPaTidFF7C4jzd0K008hKKSUx45Onv35L6Q8fB1lz
         o1XuahA5RwCA34jSuggVuHO3XX/VtPVhjov2JTjQOyIZYFLKn89M22cvFpV8GjQzLDm7
         Y0KqtwipQyioRCabSZBvUznek9lvuAJiam1WGCK30ceR2pC39/9rU//em+jSCbYG5OtY
         Bbbw==
X-Gm-Message-State: AJIora80iN27uHyogOkDYjTm3kgZAelp7H3MGREeEO2JwYKI9h85MsNV
	J17nLO5Q5zfqmay3Soc6u9c=
X-Google-Smtp-Source: AGRyM1tzbpnKkcJhXCCh+IBTJW6myhBeT80FQRGI9wmK1LExgN07sNNj1GmEbI9V9dmTryE9zSS2rA==
X-Received: by 2002:a05:6a00:4211:b0:52a:c86e:aba3 with SMTP id cd17-20020a056a00421100b0052ac86eaba3mr13558177pfb.41.1657635471518;
        Tue, 12 Jul 2022 07:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6845:0:b0:419:65b9:16d4 with SMTP id d66-20020a636845000000b0041965b916d4ls689065pgc.4.gmail;
 Tue, 12 Jul 2022 07:17:50 -0700 (PDT)
X-Received: by 2002:a63:585f:0:b0:418:6f73:c2af with SMTP id i31-20020a63585f000000b004186f73c2afmr4094458pgm.114.1657635470355;
        Tue, 12 Jul 2022 07:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657635470; cv=none;
        d=google.com; s=arc-20160816;
        b=HyC9lxI3Zdsa2rT6ZVZPHIf68gSOvdHzi3/F3UQyIM4scC4VOaAl7KLwbi7/XlFb0a
         nAGy//swxAbVRZtPLBravf5ZF2S+qi1x7zLUt3An8g1uMrYZq0LFyoa5chTJVbYn5Uux
         qCYNvGCRvtKTsIhWt6kBpI3uf3Y9F0+Xf9mCcdG+ZbORyLQGG25h20tfxOUsESfYq3pN
         SAmuqK5GejIMbKZ7OBPGr6D1a96rbeME2S2RCkgb+crSerXGKIK55KpwzeTok/yWOOfE
         0oxv4qZ/S3w10fhmgvPkyl41LAzicB/S29HukZ7ntKCzUEdfdH3RLFARkc38kaIzjBOr
         Y+mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rAqtnQvHicJEwVtFwBWlT2ImbHkxNKwCydMf49aDhZw=;
        b=wlIDDk3sFJe6eghKZCMVd2OpU2IqfNBciozxnqSYYYN069/XTceB6SIEDcdMXP/9+s
         aUkdAzrw2SV9Jcze9bqlbkHk6tya9LnVrFh7JtYOYQkSU0HcvdX7pyYfLlmT8y0BserE
         BjsSgdt0JoQ/k0l9XhdjXv3v6bb0N7TLBi81yH21SE4UWQ15K3gJs2E9XJQmm8qfvHQ6
         71OIx8SwxZ2M7MD0G3xDDsTpIbkI6jg0OgBX5DDRBT8R6pBHowblC6UYDJgUcM0+5mzo
         sZE3DV/+/kpmeTFxc3xCko1337CySrxCWtQhj/LP956wOH+B08Bo3IxUf+c+ScGjH5dN
         7PFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aiMgzeBm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id mj1-20020a17090b368100b001ef8b809176si447343pjb.2.2022.07.12.07.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:17:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-3137316bb69so82209317b3.10
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:17:50 -0700 (PDT)
X-Received: by 2002:a81:98d:0:b0:31c:921c:9783 with SMTP id
 135-20020a81098d000000b0031c921c9783mr25429483ywj.316.1657635469677; Tue, 12
 Jul 2022 07:17:49 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-8-glider@google.com>
In-Reply-To: <20220701142310.2188015-8-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:17:14 +0200
Message-ID: <CANpmjNPmp9J_2T8yw4oTBp_beywg_o=e-A3Y9nVvcHhTio4hDg@mail.gmail.com>
Subject: Re: [PATCH v4 07/45] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=aiMgzeBm;       spf=pass
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
> __no_sanitize_memory is a function attribute that instructs KMSAN to
> skip a function during instrumentation. This is needed to e.g. implement
> the noinstr functions.
>
> __no_kmsan_checks is a function attribute that makes KMSAN
> ignore the uninitialized values coming from the function's
> inputs, and initialize the function's outputs.
>
> Functions marked with this attribute can't be inlined into functions
> not marked with it, and vice versa. This behavior is overridden by
> __always_inline.
>
> __SANITIZE_MEMORY__ is a macro that's defined iff the file is
> instrumented with KMSAN. This is not the same as CONFIG_KMSAN, which is
> defined for every file.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>



> ---
> Link: https://linux-review.googlesource.com/id/I004ff0360c918d3cd8b18767ddd1381c6d3281be
> ---
>  include/linux/compiler-clang.h | 23 +++++++++++++++++++++++
>  include/linux/compiler-gcc.h   |  6 ++++++
>  2 files changed, 29 insertions(+)
>
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
> index c84fec767445d..4fa0cc4cbd2c8 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -51,6 +51,29 @@
>  #define __no_sanitize_undefined
>  #endif
>
> +#if __has_feature(memory_sanitizer)
> +#define __SANITIZE_MEMORY__
> +/*
> + * Unlike other sanitizers, KMSAN still inserts code into functions marked with
> + * no_sanitize("kernel-memory"). Using disable_sanitizer_instrumentation
> + * provides the behavior consistent with other __no_sanitize_ attributes,
> + * guaranteeing that __no_sanitize_memory functions remain uninstrumented.
> + */
> +#define __no_sanitize_memory __disable_sanitizer_instrumentation
> +
> +/*
> + * The __no_kmsan_checks attribute ensures that a function does not produce
> + * false positive reports by:
> + *  - initializing all local variables and memory stores in this function;
> + *  - skipping all shadow checks;
> + *  - passing initialized arguments to this function's callees.
> + */
> +#define __no_kmsan_checks __attribute__((no_sanitize("kernel-memory")))
> +#else
> +#define __no_sanitize_memory
> +#define __no_kmsan_checks
> +#endif
> +
>  /*
>   * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
>   * with no_sanitize("coverage"). Prior versions of Clang support coverage
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index a0c55eeaeaf16..63eb90eddad77 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -125,6 +125,12 @@
>  #define __SANITIZE_ADDRESS__
>  #endif
>
> +/*
> + * GCC does not support KMSAN.
> + */
> +#define __no_sanitize_memory
> +#define __no_kmsan_checks
> +
>  /*
>   * Turn individual warnings and errors on and off locally, depending
>   * on version.
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPmp9J_2T8yw4oTBp_beywg_o%3De-A3Y9nVvcHhTio4hDg%40mail.gmail.com.
