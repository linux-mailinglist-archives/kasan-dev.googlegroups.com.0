Return-Path: <kasan-dev+bncBDBK55H2UQKRBAHIV2PQMGQERAAQVZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D940696913
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 17:17:06 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id g1-20020a92cda1000000b0030c45d93884sf11734943ild.16
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 08:17:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676391425; cv=pass;
        d=google.com; s=arc-20160816;
        b=GJ5UGfXI3omiyDs0jAAkKLKY99U9swR5aAyOx16RXsiKK7jbmqa9+k8yuB/xj+cSNn
         m7F717/rRnFupp1qDU/+SHPezWBchdxsMIB8WuaTXvL8PFrvi6tiJW6RDF3oMccAytOs
         reXTuXEpYZAG5hzUD7XCCBJt6/SXw+0/99IPLPBO9T39OZDeYkRgbFmshxZpWQ6iAKt9
         WQPoBY2v+5fFvcM9PGif46WHMj9ORKqMjSUf0SBjrnI9OmaYDU+sbkcRamcWmPnuX3US
         jy31NOTCuHojYIya3OHf8Bz+oP29GUBTiaqcgp+dEb/oAq4ESjwoKUojitU6sKwXw5tn
         W9Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OSNuV8H9sBQzzHUCptULPWrOoLPDphj2FXnjt7XvzeQ=;
        b=XiAkpFs9dy9Mh4L00qo8yHrdHm6OEP4lApcT5AY+ikJFajuBeKVUCS9CXcOcwouQZf
         Yf4EP6RS/EWz3E43ZHdK/wUA+7lpBOz8BFu0r6edAUwx7kUHrxE+IHAjDgBboccX/QOM
         4kwzaaztSvZo90IrQom9QOUOlJzIEzGYFTWhjg163M/nhDB/Q3v9ITrZ6Sh/i7VOSANf
         J0UXKywmbEk5ivDpIGhO4pqv3WwetyuM6XUAD7Vzckgj32BKEvXOr8/9hCTOtpVoqB3P
         W+iNBMk7AbnIk2i4rWiap4dY7u+DjXbOPP+NBtBYZvPpFWmmdnF981VTZLEeofF8o6Ph
         mNyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GOd04eRW;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OSNuV8H9sBQzzHUCptULPWrOoLPDphj2FXnjt7XvzeQ=;
        b=NGbahIkSB4j8WPTGzkln7KEOWvI2BxnRxnJPC7LMuhFY0gZqKxgStRhmzC+H1MeCDt
         FOAuFoC7rh4fmdtk86XaVbXVmcj+hQLJdRTwXFcHmpp1xnCPgeX+0MS2GRJ42w5T0vsb
         8QnVBh/N4VHHahDR96OuhNDNLfFylG6136hDKcXoyrCbyTzyU7yryKaN8prL2MYLusVt
         nqd+6jlStTs1jT6NLGuE0vSuTlb8jzyyEV0hesLvxfik0BDLggVZp4kq5cdSCiVTtuqk
         vUvPkylSAI6y5TfLR3SWfdoUgTjgwj+tYCp++BXNBo3n8djH6V0jaSs2KB3o5FNsEpYK
         C/Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OSNuV8H9sBQzzHUCptULPWrOoLPDphj2FXnjt7XvzeQ=;
        b=gUBTuNACmAJjR6cnlIYkIDyy7hHTr7tN2OdqttzQmxsauMVNtKzIuuOkoUapVhBjW/
         cftiIbyIlf81EISoeGPyEFzU5zzyYnEGB64qsdJIwfN/qE9rkEX87gr61WsIikCJGKUY
         nYMD2RIxWQ7MR/qEM9MNS3r96YBzJUPJS4Rq0fPEZW87Z/wh/j0e/pSMvHatsswCzNQQ
         aYOwYp3XKm9zCUBmOD/7lXU5QQMkZ0vkGcqxsirHVtOh5VciiiEd3J6VnR0mVvaL6h8f
         vDdWeD35cfWnxuBEs8vZjnsYI1kVvlOFQE/m6xFYOo33PapLwO30XlhT63Sb1Q8HHMuM
         w6zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVONHcTG1w07RuStZceTyBcNagwELey9Q5R3AwTiXIJ9Cd2bQPP
	NSBknDlHHW/6nDBSdOeO/1U=
X-Google-Smtp-Source: AK7set/oe3UbgAg9Nya0hAVmH4v23ASTCWMkLSwwrEj0aU2H2+H51N4mWh+nuxiSu/6gi51uq+M/ig==
X-Received: by 2002:a6b:4101:0:b0:740:3d4f:c393 with SMTP id n1-20020a6b4101000000b007403d4fc393mr592391ioa.46.1676391424951;
        Tue, 14 Feb 2023 08:17:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1345:b0:71a:70b6:81e5 with SMTP id
 i5-20020a056602134500b0071a70b681e5ls2293518iov.8.-pod-prod-gmail; Tue, 14
 Feb 2023 08:17:04 -0800 (PST)
X-Received: by 2002:a05:6602:2497:b0:6e0:3110:9ee7 with SMTP id g23-20020a056602249700b006e031109ee7mr2392029ioe.7.1676391424226;
        Tue, 14 Feb 2023 08:17:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676391424; cv=none;
        d=google.com; s=arc-20160816;
        b=Wbv3xjSB/dkT0+e0tTl7Q/9S5aOP8c33eF7nh8/inM6ovce2lY8OQCEGWPxCVhYsjk
         Kl6/E0POizBzWQsnHqKwGQvh8e1f5GP/eSQG+5W0o2Zn+fWz+abAdKr/JF4+TuIixJeJ
         Of8S65fnm3fwKGgQA4fcRGXZq9acDpG7NpApB2Bs1KWr4atUAhSO6ptOlzxTw2JS3KXU
         oDPzdcwCKeFgcO3TF6XNDLoiS1VL9b6BK3vIMfBP9OJAT4D8tHFMFUW/FuQpLUqQSuaE
         Yi18PjMRp74GapfkQsis92RLh+GfAshE6k0fjlpXThK+/RNUMs7iQdHKOlCitY3NXAD7
         Z+UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HQWT0UEujdRQnf0AFB/1J+vl+szo2swZATL+M3tZN50=;
        b=RRLhNEVzsIzS2uITg1UC5WiB2wtkqR00XCUpIRFmEOHpxujcWh2bp/LYLL+egZ6OHY
         kilLYGAkHRSS0oXh3AtdUjVl1qS55/cpKpzkOeQhcJiV129FnxCGsTEKKTjUvS+LTSM/
         cuKk+Kr3ZXruU1mYZm7TbCz0SVhKsqVBjKhoRYRKABSyrM5KmJQiiokZe+UOUOytImzu
         6k+vwN5vhbZ7wXIVl96aVyj8czxo4Z2tOSf2pDrMcxmW55sZQMVZdUsZCiUctVyd7FU4
         uk+muw+d3a2yAniqkC5SeMSO3BtNJ5TMXPdURmaVBAWnK/MlMl7MbYJ5UgZNPacxR/CT
         uxvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GOd04eRW;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bk5-20020a056602400500b0073ce88e6206si976085iob.0.2023.02.14.08.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Feb 2023 08:17:04 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pRxz6-006dOw-P6; Tue, 14 Feb 2023 16:16:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D1DC5300750;
	Tue, 14 Feb 2023 11:18:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 92A2720D16AB9; Tue, 14 Feb 2023 11:18:13 +0100 (CET)
Date: Tue, 14 Feb 2023 11:18:13 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>,
	Tony Lindgren <tony@atomide.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH -tip v3] kasan: Emit different calls for instrumentable
 memintrinsics
Message-ID: <Y+tf5ZOR5J92wSsw@hirez.programming.kicks-ass.net>
References: <20230213201334.1494626-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230213201334.1494626-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=GOd04eRW;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Feb 13, 2023 at 09:13:35PM +0100, Marco Elver wrote:
> Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
> 
> GCC will add support in future:
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777
> 
> Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> architectures that require noinstr to be really free from instrumented
> mem*() functions (all GENERIC_ENTRY architectures).
> 
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>

Thanks!

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
> v3:
> * Resend with actual fix.
> 
> v2:
> * Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
>   param, it also works there (it needs the =1).
> 
> The Fixes tag is just there to show the dependency, and that people
> shouldn't apply this patch without 69d4c0d32186.
> ---
>  scripts/Makefile.kasan | 7 +++++++
>  1 file changed, 7 insertions(+)
> 
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index b9e94c5e7097..3b35a88af60d 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -38,6 +38,13 @@ endif
>  
>  CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
>  
> +ifdef CONFIG_GENERIC_ENTRY
> +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> +# instead. With compilers that don't support this option, compiler-inserted
> +# memintrinsics won't be checked by KASAN.
> +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
> +endif
> +
>  endif # CONFIG_KASAN_GENERIC
>  
>  ifdef CONFIG_KASAN_SW_TAGS
> -- 
> 2.39.1.581.gbfd45094c4-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2Btf5ZOR5J92wSsw%40hirez.programming.kicks-ass.net.
