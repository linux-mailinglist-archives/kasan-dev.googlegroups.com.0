Return-Path: <kasan-dev+bncBD4NDKWHQYDRBR74ZSQAMGQEAPIVKHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ADAAB6BD4A4
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 17:05:29 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id i15-20020aa78d8f000000b005edc307b103sf1335873pfr.17
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 09:05:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678982728; cv=pass;
        d=google.com; s=arc-20160816;
        b=AZRX6WKI6DwXQpmht2YTtcEaJXzvzc6VakgBiPq9xYbbMOUtnFMCEk+oD6RAwQgn5M
         12FenNxEfzfNENG/OHZpz/3Ll0YrXgg+NDuPE/X+UpZW58fXlEXfX4sJ+UTsm9gec2bu
         KTUzXZypGwMOLnuUwRZPR5BOp/AKHoFX5tkFFKDRC8m8/vNTIEODJtr6CJ4KJ6f8l9OU
         nLgf9e+nlW0bPS+pPeBAY8uZxQdBEoTd838ix1q+5+RT4oAyiLc7x/nJlP/7QDVyrHR9
         QhGbvMlsWeqdOtUhCC82GCq9sqaf5/kdYN6RwbD6aKS//DmFcd4XyaTnCfRcZScb0STU
         DFMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HVVAtHCXzMSpdnCHTTfnm+nGjCgOw3U5GhRVdEwiE60=;
        b=BqCuEXPkWFN3nJE6q+xmPs5s7mJ09JgOqfu4xS+pZCQyDEkxavKypfSbDXNKytmUSk
         lzSAbvnxzc+/vf/kMcrc+qM0g+I1ed3CRFHUwviyt2efXm10V8bBXkA8CB/X6VTcLSz/
         LATQQycpSbeYy8QoUjXNJfq1RLrW9jOKxJbNAmZZ5HQ2HiqcZJKXcK/7wCN9JlIGRWkV
         9FGEBZtzyFHyA5gCFNsXOJdageBSVChe1q6jH8pB0hfGDUeSodZJBtsS0ATf0qIZeY6q
         LvxexRRVu4wkL0aPluqtAzooUzZknbYZ4SW35e0DLYzIfk6sFugWMosJzrgf8AJ+SBpF
         G77w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H5XSWADr;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678982728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HVVAtHCXzMSpdnCHTTfnm+nGjCgOw3U5GhRVdEwiE60=;
        b=WMl8DWZpw4HG67d9tr/Bo/eOmZwX1bIS9nO20s+DY+rY2gIp34RhBAxmYqxd8E2hOB
         6ryzWLyJT0rYHb65MB2aXaaSKg6haxzN1nTiV63rp5cW4j9IOqBUTMOTt6zjeN3I8r2c
         vr6bVr29AnD0Hx0GhiklO62CEi8qNChegsX/5Ztwg983egEFkYuvnKlZfb/E1+/qNss/
         Rx4rmPjlQVL7uy95BydC6B8ZUkukTTgMhwYlytPO/outV9ZnCb5xqe88awMHybZ1fXCH
         D83LJ76Q6y5V09tztuO7nDIb1UPJQD8d1Uz3dG9V41Ev3g8XrdF9csV9mr0FDyNE0AOK
         oW4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678982728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HVVAtHCXzMSpdnCHTTfnm+nGjCgOw3U5GhRVdEwiE60=;
        b=gjPcKra2HF2CNZLxfDlF8UCRlKiCix1GBuoVdN6jmT2E0UajECAKWR7zV8Twr+4euA
         J8KwPJfSAJ97n9zkMdX2zZT5msLlbFbItdLb3VuMpS5VLvJjcTQEisq/6wMdjRxtwb6k
         xWTZ85/EJUizz6NfK3pWBA8/h0PrOD7bz0oVu2wupbXYcifncUERYoyw1xmMvhEV8Kdv
         sha0yEehU5riCjq8SouJQKZCZvYuZw/nsmCKlv+20l0hOtb+cM7Hl3+iDh0X66n38ydB
         04b2dTktPfWdhZ/e8PzOudjKnC+UAdrCX+2xM4bIxv8HgsqTAkbLZIKmk0OlywJhqupV
         uRRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXK1FSGJwlVWgMSdYfP/JsNGGyJf3xRi3pvBkIHSliY4zfi/GCY
	Y9ZzcBb7mypF8DfTSB7+rKg=
X-Google-Smtp-Source: AK7set/nSybMSmB5nNjPjKke8uR1bcjNYzkWCOuOoDT+s1/rTN4QdlE5OXhLNRNSr7IZrgTtdmwU2w==
X-Received: by 2002:a65:528c:0:b0:50a:c1c3:5500 with SMTP id y12-20020a65528c000000b0050ac1c35500mr1017588pgp.3.1678982727875;
        Thu, 16 Mar 2023 09:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8e85:b0:196:751e:4f6e with SMTP id
 bg5-20020a1709028e8500b00196751e4f6els2354215plb.10.-pod-prod-gmail; Thu, 16
 Mar 2023 09:05:27 -0700 (PDT)
X-Received: by 2002:a05:6a21:339d:b0:cb:c4de:a20 with SMTP id yy29-20020a056a21339d00b000cbc4de0a20mr4966454pzb.55.1678982726661;
        Thu, 16 Mar 2023 09:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678982726; cv=none;
        d=google.com; s=arc-20160816;
        b=zH6KSvsLo6s87sqxnQF6qMEuPr9ZQ2KzgBjy3NkWzh7kmgPJso8Bx48zeYFV6i3NTb
         YuVmlR/W9k+RcfOVINClOY3Od1H9EKL2/L+s9VzExveekD0b9ZYc6aWALZPzyPfgPiw8
         ybNEvpQbQK4v9y3VEx/A0wQ1kOpgowAsDOOFvZR956vFK86gMO/yROlwSUspwUkiJema
         jyJa4H/aHQNjvYJ2N2hVigwBAtIIcod1WW+hU4IuitcdYrYQlEf+WF0pxQbVBnK6/Y/Z
         wAyPmKUMlJLo4h8B1ya2gxaScYcZNcgGQYVQQj+SsVdd0dnwAH0/UXl9G6XCPF6GVrRu
         tXaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rBuZwIWk6njNYF6jYzQqSqcUyIQ/46OOkwIZJafnIAA=;
        b=JWIJ3I3g7eRe/geGoDaM+LtU6aMQtH+wgVC/FF1nYIQN763aAUOh0HZrtizgyabBb3
         qNQ60+VpjieAEu7KRG+4sLXZID2d10X2mttuLMVs2xLk5ZfUbRRQivKpbfGHt4fD3A3e
         BeHoTux2AEJY336lho9Rtzn5bUVoQsecbpewW2c+9mEZFmkQ3DpOMuF74bjcRfMDxwOX
         UQmfdm2SvSopxyxjTTuyO3MWpp7Pu2SZb3vo8dGmeUo+svuMiBFIgvRk2QkuSHJNNxRl
         ITXZbtr1Rr5riKE/5zCC3M2Zabv+Ht55AizocHrHu32PZqI+LehCpIPWG3W658TFxsHB
         JybQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H5XSWADr;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b21-20020a63eb55000000b004fb840b5440si331311pgk.5.2023.03.16.09.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 09:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3070462091;
	Thu, 16 Mar 2023 16:05:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3393CC433EF;
	Thu, 16 Mar 2023 16:05:25 +0000 (UTC)
Date: Thu, 16 Mar 2023 09:05:23 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH] kfence, kcsan: avoid passing -g for tests
Message-ID: <20230316160523.GA90073@dev-arch.thelio-3990X>
References: <20230316155104.594662-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230316155104.594662-1-elver@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H5XSWADr;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Mar 16, 2023 at 04:51:04PM +0100, Marco Elver wrote:
> Nathan reported that when building with GNU as and a version of clang
> that defaults to DWARF5:
> 
>   $ make -skj"$(nproc)" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
> 			LLVM=1 LLVM_IAS=0 O=build \
> 			mrproper allmodconfig mm/kfence/kfence_test.o
>   /tmp/kfence_test-08a0a0.s: Assembler messages:
>   /tmp/kfence_test-08a0a0.s:14627: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14628: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14632: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14633: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14639: Error: non-constant .uleb128 is not supported
>   ...
> 
> This is because `-g` defaults to the compiler debug info default. If the
> assembler does not support some of the directives used, the above errors
> occur. To fix, remove the explicit passing of `-g`.
> 
> All these tests want is that stack traces print valid function names,
> and debug info is not required for that. I currently cannot recall why I
> added the explicit `-g`.
> 
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks for the quick patch!

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
>  kernel/kcsan/Makefile | 2 +-
>  mm/kfence/Makefile    | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index 8cf70f068d92..a45f3dfc8d14 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -16,6 +16,6 @@ obj-y := core.o debugfs.o report.o
>  KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
>  obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
>  
> -CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
> +CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -fno-omit-frame-pointer
>  CFLAGS_kcsan_test.o += $(DISABLE_STRUCTLEAK_PLUGIN)
>  obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
> diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
> index 0bb95728a784..2de2a58d11a1 100644
> --- a/mm/kfence/Makefile
> +++ b/mm/kfence/Makefile
> @@ -2,5 +2,5 @@
>  
>  obj-y := core.o report.o
>  
> -CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
> +CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
>  obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
> -- 
> 2.40.0.rc1.284.g88254d51c5-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316160523.GA90073%40dev-arch.thelio-3990X.
