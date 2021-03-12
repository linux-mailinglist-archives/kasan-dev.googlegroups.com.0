Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5EIV2BAMGQEMWB36TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C652A3390D8
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:10:44 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id r12sf11298268wro.15
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:10:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561844; cv=pass;
        d=google.com; s=arc-20160816;
        b=PWGihSfYICdLRKQlQoTwq1Zy+KkGCo5t4+wAifmlp2BYRhZfZMOhEqdOrmBvWv+Jup
         XUDZTI0qCPqLnePldKZaQGuw8mDFZHBDIkH9o2KLOHIzPKytU4MXsfvE3F5xmWg6RZPk
         Ic7T0/F3cPTKBqeKJwAnZtdXdQrx17P736pgUUb6qMbo850lCkuMjARR/+tuPNXgLbz4
         h+ZY6HB27CDAFvpN5uwJyRJF/1PXH1HUhh/5g3+uY6TfX+q6jFobUwwP0s6Yogcqi4mm
         FZdAJnMHwqGNEIoktBWHnRo2oun2LJnqmSV0TtGHM1BX2lDUqXRGPpT/PV5/FSw5tsHH
         UISQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=flrbVhXQTmivn6svCTdwwpQZW94dhRIHaTbV+ROA4Us=;
        b=puNM4vq+Lw74ovCiMiGhFiDD9pidRQ+Ls1EhnlDOMYg5VaTR2b7xTM5XQQUgLacBZC
         s2RF67WcFYC9IHwqV42lADTEKkFWu3de1oIbNS3EY+5RHVpM5bHLVOqsytxd9SRhnlfL
         T5UdtpBOb0Fu+52qrbfgtaFYNXeJH6DV+rRRVeJxhaTPle9wHVmLPT7U4nngCJLhtz0d
         Xx9XlzKAsvxJ9eRg25alow4Libwb8zGvuy1jSC6jeQ/7uCpo+q7Br7E04fPiHrFrCV34
         VWl2NFDV9pUocDXTNPuHC/gt0R0fec4Seh4oPANxNqGHaDU+FIb6En1VkpA5M6OBHZwk
         bs5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uEkUsdXA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=flrbVhXQTmivn6svCTdwwpQZW94dhRIHaTbV+ROA4Us=;
        b=qPXXpoj//ftvBtYru2D7PH3lZPL1alYRuH0/c03FGptw+65Dj86xV3GByjOWXbxLxA
         1mwc36eQTLEKTZ6vzc7FiSOlTs8csopUznijhCyXuHkxkHs5KK3w79N0FQrFZ875JKa4
         MnTqksZnonhM/CY14jhJerhNcIjxiZUH0qDEmXnPmxfWjOELkKgEcj/JqVwa0o97jtcA
         7KAJ6TIqEGqTpoOprp9ejTcP/smCz1WxS1Lfzz6bNkEVOiPKcWqT8iZn+qZZDez8IGuP
         /o1a4qarfKaRRy6bCjnwI6gLqoxmAB3YncOIGI/EV7IxETmv2ZrFZU/zNbOlal8hT2P1
         ZS2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=flrbVhXQTmivn6svCTdwwpQZW94dhRIHaTbV+ROA4Us=;
        b=mYVkeaK0AwHjNu5VNRCRib4ppULXmwBtd41P0HduOk3WzBKS4AfhapZzQRtYMblaD8
         1o5hEFK2cd6PLFM0yrZAJtPVfOQMQE0EAfpobcxzqCc/wJQGQNh3TYxNdf6UEGM6VpQv
         FIpjwykryhNbths8N4vOA6WmQNfOX1SGSUZTJAlZ3slT2QSDsAcNJbHIZbP6wtnBenuA
         bDYzLDFm5PFr/7+asUgLb9+2bQOOIKiQh+7oXMc57NjtPKmTWjBJxV85iDEZDBuHDRqo
         WWST++YRmnbben6ArpyhGdKMvwicOf3k0EzFt6DvjOQjUorCJH9Qh0LTHZZcPs+q4lrC
         JZKw==
X-Gm-Message-State: AOAM532jidRaWpoMy9CsQznCRas4ic27vDzXGDD0KC9nDxsnKeUeYB84
	XJaLR43PsrNG4/Pr5gOIxYs=
X-Google-Smtp-Source: ABdhPJx8HBZe7eLOF6suNjRQpwTSZhdr6zxCYojw67bTpJKfR0VQ6RZCWTEcMYTUzihD+QqzrRXdww==
X-Received: by 2002:a5d:4443:: with SMTP id x3mr14453073wrr.49.1615561844625;
        Fri, 12 Mar 2021 07:10:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls125256wrd.0.gmail; Fri, 12 Mar
 2021 07:10:43 -0800 (PST)
X-Received: by 2002:adf:eec5:: with SMTP id a5mr14191299wrp.303.1615561843794;
        Fri, 12 Mar 2021 07:10:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561843; cv=none;
        d=google.com; s=arc-20160816;
        b=QhhJ/Xe7qRrzQJ/niIJbNsroaO6JzEpypgsr6eCJmnBJPIaxIRMojUbBrw5oGBgIHj
         cONzO5BeTtjs7/tXNcyR+0//12bKupa4FGMXJ60OQ5/1Wi7ZuC0ZzuFVQ+s8JE6dzLUx
         hZCTxbYOjPdlmUzPHalsSd+elSgKyge0HSHGS38g2LuTHgZo8GOTWGUlkdc+gdlMbrit
         HuGzddyJQZkPBRL22/9j0zM9QucZ3VqBql8eoGemGvC47TC22UOofLG71ambvCzTe+81
         mcitxhkLVcOm28h1cF/FcOg6Oa0DGSRpP4VaqoCezLlfNxUzOw+f+Ab6vDHjadYguSX1
         3ZAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2dVcHDhdrF5JaCCByrKqwImhRd8nHqVH/GMv12NMUYc=;
        b=OXEWFmy3XDqY0bjDqNqjAyzjLpCfcpPaBgtx3f7ixUNQ8r3MIFxuNReoSz/+wP0B+x
         zulAJfUUhn0bMpqIoBfNsQ54l3nkiqChumg6IFRONY5z7CHlH5rv9U92oir5oUVPfD21
         o2NJ3izC6v3te0VQ9w71M1ncivYR8F4olcIjo60RrJO3FJMDSpIZ0oK184GrCWcer0so
         vmbF79N4fiP2Hd9vnNNJuVNQqGrlZau3BztpqVv7sriXCW/mNyBTZNpBnt3IP5COfpUZ
         G8sVtWIi9mwiPg0cRF6OCzNr2/N3PvY8YoMZ/JW8hstm4ihjDLZnpQoPmgmuo5GUzy6U
         3Rhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uEkUsdXA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id p65si597937wmp.0.2021.03.12.07.10.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:10:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id r10-20020a05600c35cab029010c946c95easo15377281wmq.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:10:43 -0800 (PST)
X-Received: by 2002:a7b:c303:: with SMTP id k3mr13820769wmj.100.1615561843302;
        Fri, 12 Mar 2021 07:10:43 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id c131sm2481968wma.37.2021.03.12.07.10.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:10:42 -0800 (PST)
Date: Fri, 12 Mar 2021 16:10:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 10/11] kasan: docs: update ignoring accesses section
Message-ID: <YEuEbRvzdf9x1yNI@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <4531ba5f3eca61f6aade863c136778cc8c807a64.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4531ba5f3eca61f6aade863c136778cc8c807a64.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uEkUsdXA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Ignoring accesses" section in KASAN documentation:
> 
> - Mention __no_sanitize_address/noinstr.
> - Mention kasan_disable/enable_current().
> - Mention kasan_reset_tag()/page_kasan_tag_reset().
> - Readability and punctuation clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> 
> Changes in v1->v2:
> - Mention __no_sanitize_address/noinstr.
> - Reword the whole section to make it clear which method works for which
>   mode.
> ---
>  Documentation/dev-tools/kasan.rst | 34 +++++++++++++++++++++++++++----
>  1 file changed, 30 insertions(+), 4 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index d0c1796122df..5749c14b38d0 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -368,12 +368,18 @@ Ignoring accesses
>  ~~~~~~~~~~~~~~~~~
>  
>  Software KASAN modes use compiler instrumentation to insert validity checks.
> -Such instrumentation might be incompatible with some part of the kernel, and
> -therefore needs to be disabled. To disable instrumentation for specific files
> -or directories, add a line similar to the following to the respective kernel
> +Such instrumentation might be incompatible with some parts of the kernel, and
> +therefore needs to be disabled.
> +
> +Other parts of the kernel might access metadata for allocated objects.
> +Normally, KASAN detects and reports such accesses, but in some cases (e.g.,
> +in memory allocators), these accesses are valid.
> +
> +For software KASAN modes, to disable instrumentation for a specific file or
> +directory, add a ``KASAN_SANITIZE`` annotation to the respective kernel
>  Makefile:
>  
> -- For a single file (e.g. main.o)::
> +- For a single file (e.g., main.o)::
>  
>      KASAN_SANITIZE_main.o := n
>  
> @@ -381,6 +387,26 @@ Makefile:
>  
>      KASAN_SANITIZE := n
>  
> +For software KASAN modes, to disable instrumentation on a per-function basis,
> +use the KASAN-specific ``__no_sanitize_address`` function attribute or the
> +generic ``noinstr`` one.
> +
> +Note that disabling compiler instrumentation (either on a per-file or a
> +per-function basis) makes KASAN ignore the accesses that happen directly in
> +that code for software KASAN modes. It does not help when the accesses happen
> +indirectly (through calls to instrumented functions) or with the hardware
> +tag-based mode that does not use compiler instrumentation.
> +
> +For software KASAN modes, to disable KASAN reports in a part of the kernel code
> +for the current task, annotate this part of the code with a
> +``kasan_disable_current()``/``kasan_enable_current()`` section. This also
> +disables the reports for indirect accesses that happen through function calls.
> +
> +For tag-based KASAN modes (include the hardware one), to disable access
> +checking, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``. Note that
> +temporarily disabling access checking via ``page_kasan_tag_reset()`` requires
> +saving and restoring the per-page KASAN tag via
> +``page_kasan_tag``/``page_kasan_tag_set``.
>  
>  Tests
>  ~~~~~
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEbRvzdf9x1yNI%40elver.google.com.
