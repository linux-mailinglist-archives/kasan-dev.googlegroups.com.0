Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKHVWWLAMGQESCOXCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFE5571B92
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:44:10 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id e65-20020aca3744000000b00337da223b83sf5380678oia.14
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:44:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657633449; cv=pass;
        d=google.com; s=arc-20160816;
        b=n7sMSeHRuSrHlosxLaNfvdZ16IgH7IXzAJBmlTXmtcgBmPjpiu4pn80vW3GWZxkThE
         vEPFxf4qDtvTBzRHb/kCMfyMdryGJF4pKTAWzfNjyLaoBRIGM0FWwOKoKoF6yxP9PA+L
         oFRywCKvsTej5vV/rtzC+7A8vBybgL/wULAQJbuMF4/gcd5ihPw4BTnk420h4GIiPu/b
         mjK+9PQHzbuDbaEEOkZIFg5ZdTS4qKUMEP7JahB/a1iwz9McqUKBBL48DOzD2zH2vukJ
         Q+Rlh0dE2FPr0Z20kPJNRgtfy0Z/QaUI2G36Wivnhaa3H6uuvc+O+ya4CeaoMEAJrSUz
         8O5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lXS2ZYIe71NzH8/m/LrNX9b9grO+WwdL/xA6Nz/5Uig=;
        b=dNVtH1pp3RDAvz6QSRuOdwI8Dx0b02xiHnfndq13vGDfAkLcQcmVa+W4iGsYYwUl5a
         pp2Ju2O8/CCKgdJM51V8iD5pbsfRSi2y55B0oCO9e+oHQFA/VDJ7ffv5dHTlpD9LLri4
         IeQXivFmL0SQpSGIvtbUJaOjA0SaHAcHlxfxVPENYpE1TRgvaIL3eKEdWrMAdQKg4wRg
         lwNjuTQE7C6d3U1bT1R/m/ZTtsKmQnG9XkIuXoZ9yQSdgPBcOsu3ntGHtAQBUzCTrdPz
         v/4kcDJEYh46qmVQYumVQ9pJtJDNJyipHWkBU0wh+hv9yb9S71l1YXbgls3VqpnwWh1w
         3wRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XsmwdUhn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lXS2ZYIe71NzH8/m/LrNX9b9grO+WwdL/xA6Nz/5Uig=;
        b=kwLAWt64gPrO+E9WQFI5KNfIxFEX4DLSrjc1Gk9ZafuUYIWK07hxkajPuGh+TRpyTQ
         W3gVl5JTUuDwcPC3NgtSDdAlUnwD2UOauwW+iLi10nn2jN48XAL5krcwMpXOhWWg7lyR
         V/aqwdqe0NnH22Et/l/Z35IMeuyLDhqttQnMGg6/tngc/QcQavXw94Ky2OyiEBaQ4uhT
         1C81Oym0NP7UTgCg1Zn9ssB0Wp9bpNGqj0opQfGsYg3xKL/FlsIUu8uoVYenC97hjTs3
         R4VHh5vYRl5HQQCc78f+pcWzn+kbrJIgcPHZ60y1PMQSoMx4KIpmhbNG6pGUGkOi0VNN
         ePyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lXS2ZYIe71NzH8/m/LrNX9b9grO+WwdL/xA6Nz/5Uig=;
        b=5Usr5ziJKf7V7yrhn4+7n3Cm681yKD3i6l35fLgQm1BnT5K+iMD3hwqVp+vfMxuJAV
         tGhqeswS5zh2KT/pmyEN8OMpkqQ7Ga6y8UgDakfVtB8V3GfaJN/Er6cbk5uVlCHtfhAc
         al2jkdWaTE4PItc0n46ZTNmwB4BaUIw9iqiyle12FFLXdZeLzvWmWxXYIimRkq2OO+zS
         rRQISZl2pohbyx22kk4b1qispyDr8nMNZKAo1pKFDdAdkzqI2LxkGFujU55rpCdy5caU
         Cdv7dCKZucnrvt8Si/m9XS92y2+j8OEa1EZS4GRaXceGCbzKPhIs6a1yME9/Bt6wZHxl
         tuRw==
X-Gm-Message-State: AJIora9++GW9lBBpCll6+XSocvmHrDfREHrUU6Cd+tOe5goDx8hUcSJy
	TP+5QT/77hfK5/TWoAWqZMA=
X-Google-Smtp-Source: AGRyM1twskRSpB8wrjIZufbOGmhPY7C35xhg9gJdqzHXf+e72kWsOkO561hLkhJqQ+X1T5Jcke+T6Q==
X-Received: by 2002:a05:6870:7022:b0:10b:f0ea:d441 with SMTP id u34-20020a056870702200b0010bf0ead441mr1720966oae.39.1657633448966;
        Tue, 12 Jul 2022 06:44:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2421:b0:61c:6266:b9be with SMTP id
 k1-20020a056830242100b0061c6266b9bels151076ots.9.gmail; Tue, 12 Jul 2022
 06:44:08 -0700 (PDT)
X-Received: by 2002:a9d:67c3:0:b0:61c:4c2c:a819 with SMTP id c3-20020a9d67c3000000b0061c4c2ca819mr4336141otn.116.1657633448451;
        Tue, 12 Jul 2022 06:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657633448; cv=none;
        d=google.com; s=arc-20160816;
        b=oZV+B/D1xqUGcWQwghksR5Bfm3BU8PtNYm6Kqh/q+P8NM2d2H9uiNBpI95OBhqrjJB
         6ac/TvOulXZ0oGB4MuKvi+2PkTO8mNR28htMinPjoifMetUEWJbu1RHEGiPIRNOD1OKV
         WWyiZ5gozllqOXUeBQC3kui9CW7YqBOyuWiOQ/DhojZsjiEq8CCTnvFAt6+GU7kQoV6n
         IhWhcbLaTJzgjJh8UGLhU9ffRKH07y6sLhpSPzx+TBT2Wb6E2+sxEQW9EJaI4NckjnNb
         sQipi+9Mdq0KKWdTEU8pzaMfnaW6467HuYhMpFHaN9YWOlBCC8qpodyZlFLPM/7Xgcq+
         JWmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MyQuL5EzG5eMdd3tjqHgbmALZQ6QoMWn3xa4SlD7s1A=;
        b=jdvJd4RpnX/AkcoL4+ao5Stnx765heaKzv1vJSndZUVGq2XmLRb31Pos68ofhgBnkp
         4ilwX0+wHfLUL+1JktShq42kOSlNusezaLHr1tlzltIVEShzD5KTtssR2mhYVXcv04RQ
         RZyoF0HH/moAUHELdXUgSZCxn7WrDU1GQiyjEzke3kf7i6+AicTH+RhtlVGPLeF3yBKY
         Ti2TgH/B+SMrRYl9NQBlT//emYsQSyZBeb13+tvFzAh+Zst+vBuCzp4+uzgdsOB5HfC7
         yEmob7ol1WvkqklH73YOEnLK/3Nhanjry5nYMma9AspezncJkRzJzg0etq4UPb5TTDE1
         skDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XsmwdUhn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id z20-20020a056871015400b00101c9597c72si592766oab.1.2022.07.12.06.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 75so12712204ybf.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 06:44:08 -0700 (PDT)
X-Received: by 2002:a25:1583:0:b0:668:e74a:995f with SMTP id
 125-20020a251583000000b00668e74a995fmr23207491ybv.1.1657633447949; Tue, 12
 Jul 2022 06:44:07 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-34-glider@google.com>
In-Reply-To: <20220701142310.2188015-34-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 15:43:31 +0200
Message-ID: <CANpmjNMpCow-pwqQnw8aHRUZKuBcOUU4On=JgEgysT8SBTrz6g@mail.gmail.com>
Subject: Re: [PATCH v4 33/45] x86: kmsan: disable instrumentation of
 unsupported code
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
 header.i=@google.com header.s=20210112 header.b=XsmwdUhn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Fri, 1 Jul 2022 at 16:24, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
[...]
> ---
>  arch/x86/boot/Makefile            | 1 +
>  arch/x86/boot/compressed/Makefile | 1 +
>  arch/x86/entry/vdso/Makefile      | 3 +++
>  arch/x86/kernel/Makefile          | 2 ++
>  arch/x86/kernel/cpu/Makefile      | 1 +
>  arch/x86/mm/Makefile              | 2 ++
>  arch/x86/realmode/rm/Makefile     | 1 +
>  lib/Makefile                      | 2 ++
[...]
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -272,6 +272,8 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
>  CFLAGS_stackdepot.o += -fno-builtin
>  obj-$(CONFIG_STACKDEPOT) += stackdepot.o
>  KASAN_SANITIZE_stackdepot.o := n
> +# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
> +# recursion.
>  KMSAN_SANITIZE_stackdepot.o := n
>  KCOV_INSTRUMENT_stackdepot.o := n

This is generic code and not x86, should it have been in the earlier patch?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMpCow-pwqQnw8aHRUZKuBcOUU4On%3DJgEgysT8SBTrz6g%40mail.gmail.com.
