Return-Path: <kasan-dev+bncBC7OBJGL2MHBB246WD6QKGQE6TE5NHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AAE42AF61D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:21:00 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id t3sf615725lfk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:21:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111660; cv=pass;
        d=google.com; s=arc-20160816;
        b=SRqOqRE5QAWBc5MHkDicx2+0k/3A8TiRDU50WEjxtx84UUyep9UEcXAomWF/zG3tle
         Zc6gqKIig5u0o+BO3YZ6d/wBY2gsaP2PU6rn8/3TJnf4P9FWx3tLRbWHDuPCuISSrHYx
         +7gCjcXBZ3NERBuAkhPlvXFmIMzLy88TEcJyqauqCdd1WMBo5uu9848iOrJkYyVxVp0q
         rpDYf02YYdpGGLInJBr+k0bjpC2GMp1viz1jVsitJP/GpIk0NP2WtkIy8rMze+q+AYjS
         cs+H1rwfAeeMO6EENYJ72C0mhlP105lCoDbh8XBsEcFen+RXvj/aCFG4l639L9Fl1SMd
         4MFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6ECbvHXIS2y+lzh55/GLV4/0Xoo/CwyK43MaC6r7vM8=;
        b=0WQy0ODlR5KfIIHh7ZpchkPeTCsxSCnsQ6fqf9j+Hw1vNGWJOBnAcvQCSm0zsRhv2n
         nJgXeNd94Zwmvks1RbopCdFB1PwNNu1zVHUdmbPJMV6AH92ZdHJCpR68VPfhSlesx7AZ
         lwspaBhRuW5uhGRFIqtQKzCvhOfZ47BuyonXfG12xPrr41FxjkhBVSN7S4uAj9OMTUq9
         VpHu7mC7q3DP9fdLVStDM/iU1Tr/OAVmqps6d1sp3hYmz3Gl0+Eg5H9GS3+B0Ojht8Sp
         RdJPpONIsJUCgJnMWhTNyLhIfvGsxLmFkcvPYvxrAtuG5gIM2Ja0Qb3A5QNo4EaWeDNR
         SYAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OU4m2N6j;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6ECbvHXIS2y+lzh55/GLV4/0Xoo/CwyK43MaC6r7vM8=;
        b=WEc4ZrpCZJInukpGzobWgJggcBc842g9R2QTwvnGduYYH5k+Yga6Ihod7Zg+edkxqY
         uyMCFETTEKv+ng7SMWhwdik6snI/jZKPzglPIKckmH6krBZ0COvtQqatK094olrLnfbl
         e7HA7Vc5AizrCHesqJJSqoW5/KoRI+1VvHseqRx7X2IZxIIb8V4SaDlLxOJMSI+iOPTw
         noowGDuRhykFrl4W4zY55ZlqnTWHbKhJhIn9IX4I0DDGDQdq7JgEYI8KDFHuscodxkdC
         eTJlhcWWfB+4/cXlhFe744RvYZUN6qYNNZpVSyD1MSaNg7BqpOkEgg0Shoibj/lUq1dk
         thSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6ECbvHXIS2y+lzh55/GLV4/0Xoo/CwyK43MaC6r7vM8=;
        b=YEIsjnu7x8wcCDc6ec1kENdI/yhWERUIl66GTkna0itqPwNrPN8ZHL7NjjKp+OitQ8
         4Fa6G/aco0J8naX7ZpkWZ3PR84+fcOKR2RHagTJUWuBEzxru88jQ4zNfqAxeT1bWXUpc
         WNoAFfDRSnk5Lso3ieQqEidUP/y5c8eWYGaBKyLEmFjTsE15BXOvcJrW5SKAYQpE1qqN
         eHKpkcDAfZWV4HNK5kMSPXS6gNsY8igwGwW87tL/YLyqjweUDwiNdt0NuZ2njopn7ABY
         W8iECjjU22zZ8RiyBkoTD1AIWYNy/yXo0CwbAra3kL2X+gCQ4l8fdAxEvXLpjfHogU0n
         7Dww==
X-Gm-Message-State: AOAM531LAvxfubMuvRSKPd+sFjFIZFgbCBaGBBiBRzhT5G7WpSfJiIdE
	e6ATc6CIgz+nEDckI9xrPGA=
X-Google-Smtp-Source: ABdhPJwhRg+zx216vzH0CjyN2/OU9U1pSwzVglhnHgj6VqcsrJATlW8Lc4hyXuvtJfty+P01KhXjPQ==
X-Received: by 2002:ac2:4831:: with SMTP id 17mr4470954lft.487.1605111659957;
        Wed, 11 Nov 2020 08:20:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls28113lfa.1.gmail; Wed, 11 Nov
 2020 08:20:58 -0800 (PST)
X-Received: by 2002:a19:4b0a:: with SMTP id y10mr10883023lfa.570.1605111658801;
        Wed, 11 Nov 2020 08:20:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111658; cv=none;
        d=google.com; s=arc-20160816;
        b=rqOGhi/7C/VhAAiLHHbVZ1El/VB5AYyZKqSRCJjIBAmWMUX9LoqeFQyIoAWW1Wc5T2
         EURVu0IhK67tV7f6DgvWEvu/Sz/AJOPj0I9ua6sEpUwgsSqKk1GqGxBunuPfmXPqECfx
         VRh34UGMrtH8F0ddeAMM8qJjHBNm5jQzIwGee/zYAn7JRMxiTSkwx0fcT8j6J8qHcbKZ
         N/VoZX7tVV+E5vwcDKc1GmvVjBMEakaHxzKKeVWJo6tjtyo4RedfE3rrjGa9q+SWmcjp
         teFnYS8tpTF7sqPlKT2aPjwSMFq/IBMweT+BHeki/hxABfcTr7yev7DqDG3IxaRZ5Kts
         KjHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=h04pzBWTT3/7lLb3bXzNbuLnpXPPVyksc65veB41bHc=;
        b=Wg9Rzpumd7uRZyDTfOq4QRotkWS3pwfUaIuUxHjWfjlPrlv7bnWoMXjadvX92ZdkpN
         GknHirr0avlSWenLEFyfrh3A9+F0O0G3j2JeodIFIwNwOT5d6pBGxwWEyXFdHGkmxoh4
         qkm1LsobjaextuK0kplcPMGtDP+SCUPukxaNg+C4VImC4g8xgjcotCEMXHQ0Xt3IxbVs
         UagnjnVgWfM/bhYiqSnJBibUApXqW6Fr8q3VYigVGaqFOY5oMgBBmtGt2ZmYQjh0fe5T
         R06APhx2FMoJ1zv7KoqDmJUV6+9fJqORbasjGnq/GstBw9lEEfxxG9EMPpwZ3Qj5bFaX
         mP+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OU4m2N6j;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id i67si41250lfi.2.2020.11.11.08.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:20:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id k2so3109576wrx.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:20:58 -0800 (PST)
X-Received: by 2002:a05:6000:364:: with SMTP id f4mr3136596wrf.290.1605111658027;
        Wed, 11 Nov 2020 08:20:58 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id e5sm1926733wrs.84.2020.11.11.08.20.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:20:57 -0800 (PST)
Date: Wed, 11 Nov 2020 17:20:51 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 05/20] kasan: allow VMAP_STACK for HW_TAGS mode
Message-ID: <20201111162051.GG517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OU4m2N6j;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Even though hardware tag-based mode currently doesn't support checking
> vmalloc allocations, it doesn't use shadow memory and works with
> VMAP_STACK as is. Change VMAP_STACK definition accordingly.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> ---

Shouldn't this be in the other series?

FWIW,

Reviewed-by: Marco Elver <elver@google.com>

>  arch/Kconfig | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 56b6ccc0e32d..7e7d14fae568 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -914,16 +914,16 @@ config VMAP_STACK
>  	default y
>  	bool "Use a virtually-mapped stack"
>  	depends on HAVE_ARCH_VMAP_STACK
> -	depends on !KASAN || KASAN_VMALLOC
> +	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
>  	help
>  	  Enable this if you want the use virtually-mapped kernel stacks
>  	  with guard pages.  This causes kernel stack overflows to be
>  	  caught immediately rather than causing difficult-to-diagnose
>  	  corruption.
>  
> -	  To use this with KASAN, the architecture must support backing
> -	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
> -	  be enabled.
> +	  To use this with software KASAN modes, the architecture must support
> +	  backing virtual mappings with real shadow memory, and KASAN_VMALLOC
> +	  must be enabled.
>  
>  config ARCH_OPTIONAL_KERNEL_RWX
>  	def_bool n
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111162051.GG517454%40elver.google.com.
