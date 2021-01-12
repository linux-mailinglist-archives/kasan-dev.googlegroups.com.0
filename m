Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLMU637QKGQEKQHHKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 26B902F2E0C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 12:38:22 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id v187sf944775lfa.14
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 03:38:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610451501; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqHathvLtFMGQpJ8+sMl+2H01vFmYb+nlV1RuRuF4mby+wbrTP4x8eQVrqz9TYiPC7
         iiBjgvK/8l+PMyaMoRqJuxx5WDw35KYg3X/anjSzr3VNXH2mNMyCALXgLPklfoLq/ZgD
         6vAyRLYkro1VHzdAcRFg7sMlnrbXXKkbDs9WcqH2Rv0bGilcXcnqQnGRUNO3bs/nKshv
         96COlKC2CHddW231tLYN9/4Y6T+21CGI1oeIEziG7BV2FT4k2A3WYgGNXuwR6Qcc86mX
         OzIr09Is3zNKAqnqQ6LknGXYJHPRFyceS7RSOGrA2+qXegW2gJOIVLLb8NTNgUjh6Xvv
         bgTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lKY3tw0SywpDbg2GaDNdkI3UysK7MAAgw7m2xHyVlH8=;
        b=M/S5KI+jlfRSorfmYmek4CQS5FmBWNuK/WApxelEV1PcDYa798jl2eUeGaMuvaSm3q
         HGUaChMiSS6ZqP7agMnWxrarAuVuYhChYDxZq47EYhAhTb+i9445Bz5u/4dV1eyKTVYC
         FdENPRtF+yZR7QzMvn4Enafvmw1GmeXmZAIGZLSOslWBrPZ+56psbXfIh13CTlJCtRRJ
         y+qUkjiLecnKe31BtS6V3XdQYllnRIDvbPI4v0eYpLPSekdfSnmfCclFbwEGxy9NEB+j
         r2S5xB/vA5GDlFP4RBERdjbkUdDbE1lxCKVYesBNEnBTxkk1XkBklOnEwxJ0MNUEEJB1
         N/Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lTj2eZ0D;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lKY3tw0SywpDbg2GaDNdkI3UysK7MAAgw7m2xHyVlH8=;
        b=r7tjwo5Ro3/m7etBOJeLpFM/oE+Wf8Kw+iuscdj/PaRT1heraYzfwRe1mHJeNp+CHe
         7P7eoGDOq26VpirWBwB3kUwJtxvtn86hA7kmOPXW3QLMiZT4n0z+hOrz31GshZhPrFkx
         0V9/6cp+xVI8750A5KfljTKFLP0af9Jju73Ift6JlyyNAiUmqjb8SY9GonBUIgHOTR9N
         hXyTNraWPm5HCESxXv9AFlKYAkxyXeBZ1ZxLtQti6goWPLfWscm2witQ60VwIMXlTsgl
         Mjnz0iGF0Fpq1dCQUoIj4B10MTbBcx1dS6pXmCAc7EYh6Fzjb8u8I6fYDO1T2o4IsPFd
         1uDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lKY3tw0SywpDbg2GaDNdkI3UysK7MAAgw7m2xHyVlH8=;
        b=Olp6OBxNqEoHMRJ/Qw6wh5ceZZ7zs/1W/zEpD0VXNndHQLJdCqVLJw7N+SNerKQRI8
         8jqGL01Lq0TdghO67lgk3CaxekjYv1wkc4eWfNklJgj9hX8uHXWOcJOR9HQ/SAROW4Rn
         1S6+cBbSuFT6YDToVBmgqfyLX/DVpVpcCZMSvs8TGd00QmutU/ymkRct3tumo7qnWH1i
         /yR4e08tGArVU3C1u9UFMucjiPQYAhNiq9IdlvPz6t0pQIE907ZjB3XHAyboKI18FOAq
         Aa/1ljTVmR7S+xyJt7rVwWEfhYwnHnHsNtx6TRrhwsXLPWEaKN59F3WrFV1pTz5C7h1d
         C5GA==
X-Gm-Message-State: AOAM531TlPRDkkhdScQr1AbEyMZAe0Ns34XehtMPya/pfxp1NyMmBRCH
	/vYvkfonbBIlsKI4m/uQeN8=
X-Google-Smtp-Source: ABdhPJwcNcblOGrvVgIDkpqmLfzEJ2hCERitMFHS3/t1eJYUfXvs7lhISCjV2As+cYMVDX/Vq+uclw==
X-Received: by 2002:a2e:99cd:: with SMTP id l13mr1888422ljj.318.1610451501702;
        Tue, 12 Jan 2021 03:38:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6145:: with SMTP id m5ls2032016lfk.2.gmail; Tue, 12 Jan
 2021 03:38:20 -0800 (PST)
X-Received: by 2002:ac2:5f75:: with SMTP id c21mr1889675lfc.213.1610451500444;
        Tue, 12 Jan 2021 03:38:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610451500; cv=none;
        d=google.com; s=arc-20160816;
        b=HSE4vu3URJoOrOnXqc37dEQTRGmnAMkGdxaLMI08ZGN3nDlI20P2EqUfQiJOvN5R92
         0Wefmt5wS0po6Dl+8nxncyfTD5q/l5C8YUFiYlghln66W0XRYHL4cBrX/Wbt7M4A8LYQ
         IB3worcBE/nYobj+EPK1r4eNZ9QjM98XabynXtUlIs2lvO/x1PKrLfqG8mzf47t6W910
         5Vjaehz/GKqBnTsYcPZCf7euphz4SzQuuoS1VLEhkQJBh+wrUpdlGVsgX7RvlYOy0VQL
         sXGzn+DjUC4cEcMkBcEwiQ/PxkrA4S92e7wu2pmEtWP83A83vhuYBXvntq/9QDmJzV78
         jjUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GDpfESbYxGF6Trv+/Pck55IrVLlVuQoy2fDX+R3JzHs=;
        b=PK7vXDiSv0hz49iBZrPCIeH5Jy+JjVGFCzblP4NJlP1CiX1o6MKPKPX/PL/2vINcrk
         ncihZ5ZzK+BVm+e8xsR3yKRpXW9dY0nqPG1JjGPu6I4XMJHidauXTqxh5vX0MttTWRKi
         0TK8Jqq4qF8K992nIHkOS7/CAp9KeWup2uV3jr0hW2FjISGNN6LjKRXI7jdKRKD55dek
         VTXWdVLNuVsQz9pafLyIuHC55kPQgJAAnDY9EC8UmwsECc5eX35JAuMTEHkdwz4o4pg5
         CdOt1so4B6/MklUFjdzXCnKOYNDTDA4Rp6dHaKRSsPeTu+Exdw5isjGSIN1GYMBSJLaB
         /R3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lTj2eZ0D;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id w10si53314lfu.1.2021.01.12.03.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 03:38:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id q18so2168942wrn.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 03:38:20 -0800 (PST)
X-Received: by 2002:adf:db51:: with SMTP id f17mr3957788wrj.83.1610451500054;
        Tue, 12 Jan 2021 03:38:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id o74sm3825348wme.36.2021.01.12.03.38.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 03:38:19 -0800 (PST)
Date: Tue, 12 Jan 2021 12:38:13 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 02/11] kasan: clarify HW_TAGS impact on TBI
Message-ID: <X/2KJb5SN5DUq1C+@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lTj2eZ0D;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> Mention in the documentation that enabling CONFIG_KASAN_HW_TAGS
> always results in in-kernel TBI (Top Byte Ignore) being enabled.
> 
> Also do a few minor documentation cleanups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Iba2a6697e3c6304cb53f89ec61dedc77fa29e3ae

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 16 +++++++++++-----
>  1 file changed, 11 insertions(+), 5 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 0fc3fb1860c4..26c99852a852 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -147,15 +147,14 @@ negative values to distinguish between different kinds of inaccessible memory
>  like redzones or freed memory (see mm/kasan/kasan.h).
>  
>  In the report above the arrows point to the shadow byte 03, which means that
> -the accessed address is partially accessible.
> -
> -For tag-based KASAN this last report section shows the memory tags around the
> -accessed address (see `Implementation details`_ section).
> +the accessed address is partially accessible. For tag-based KASAN modes this
> +last report section shows the memory tags around the accessed address
> +(see the `Implementation details`_ section).
>  
>  Boot parameters
>  ~~~~~~~~~~~~~~~
>  
> -Hardware tag-based KASAN mode (see the section about different mode below) is
> +Hardware tag-based KASAN mode (see the section about various modes below) is
>  intended for use in production as a security mitigation. Therefore it supports
>  boot parameters that allow to disable KASAN competely or otherwise control
>  particular KASAN features.
> @@ -305,6 +304,13 @@ reserved to tag freed memory regions.
>  Hardware tag-based KASAN currently only supports tagging of
>  kmem_cache_alloc/kmalloc and page_alloc memory.
>  
> +If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
> +won't be enabled. In this case all boot parameters are ignored.
> +
> +Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
> +enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
> +support MTE (but supports TBI).
> +
>  What memory accesses are sanitised by KASAN?
>  --------------------------------------------
>  
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2KJb5SN5DUq1C%2B%40elver.google.com.
