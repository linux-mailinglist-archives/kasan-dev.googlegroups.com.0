Return-Path: <kasan-dev+bncBCF5XGNWYQBRBFN6VKXAMGQEUAV5NQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D6EEB8521A3
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:43:34 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3c044726448sf97416b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:43:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707777813; cv=pass;
        d=google.com; s=arc-20160816;
        b=Znm7VvqDnr7/hItohB+j2gEFkZNjqxPn+OqQnqAsSBwGuwJQt2OQ3YWBeXWM6rYsfQ
         hDsVls8If+B8OKJ4f6eZfNT34zq2+KstPgwHSbToUFe2fs64rEOQI8CTwk9j8/NrMIxP
         AEuaIrFCYnHayEefBgdvMyVG4BIRVUw9Mt1RnPU91sWbkRASem5EDB30cgh9R5TtE8QY
         4rlBLXMf868otdboicZa4VgRdtm6g2+ex3MoSU93sVYy6p1qI2NR/KT2vhCae1208+H+
         nj1v3Hjn39h4YbIoeDvDVxOoVgugUori+saQjKkTCirLHYuyFnvMnm1wRDEfVhBYJhmp
         hygQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ysuHpc2unfdeG7BkAL+mXnvshJEkv9IbwC5X6uVmsyc=;
        fh=PYMchTk7YA55F3omfIRVxz4jVm2uQ4D40aQwcTj/u+g=;
        b=kf+esa5xLN5NdCsC2SFN/bO+FUdAdvcISw/ADntaAGWOYbcTIcLAmVGzeUyf6vi2gq
         AuilCVJiDzQPwHsPH9HxV1V5WR/B1nlmMAPD6sHMzpLzjLxC1nykCjQvOkDxzddI62YO
         uUq1wX7wNbWh57OX6uq7q7ofXlCUKziqpvNr1dTeZP88E71KtXaSmCYpLhXc9JF8Ciet
         +BwlLZoTv9O5n06nOyn0cf65CL57v/2inlr+sX/0IlLJ0uPcbHKFBNlAFM2n1MU43/8B
         OeWFTJwV0H7vXUzJxKx0P0KbXRsPLDs4nP9033wPkpRMx0cUSBnjNNeTCupLjVUW7+IZ
         FxMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=anIBqNFU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707777813; x=1708382613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ysuHpc2unfdeG7BkAL+mXnvshJEkv9IbwC5X6uVmsyc=;
        b=qaTYKjL8Gj+cUe7TR5KTtehQ/SUeyhDgPMgnDII4DMT9EsU3dThFMPZSHbglFtnKPz
         0tikZ0J6wHi/Sh2AQVL6PLD9RldNFbvebxRqtobP/Xp8GLUVUlOEHSJPXVEu52cR0b29
         DVfPkrojTFLxKHjId6U30p9ihS95ntKeQ89nQ3Lz3cJGLfUgJ18XOJUwxPTlFe6kM22x
         3rq+TTcuTVMSCKPRm1308n6qpTg/oZyo4BtGznYovFg86/+uM02diZpWAu5BJYF2RV7W
         KKrqsJMaa2AbfEZ7ZrDn7NHbJ1gbzRLV3+SRTorZp4N810bWHPcUcsD2q2zXDswrfM16
         tefw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707777813; x=1708382613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ysuHpc2unfdeG7BkAL+mXnvshJEkv9IbwC5X6uVmsyc=;
        b=Nke7kgBpjLwCIYahoMY9dSx9WGFZ/lrF+Zp+zD6p0Ko/JA7gqgkn7Kg6ZDZj03ssbu
         Dl6FWJLMYP/AtDrF8UflGxcgQEc+YZCcL6GMQ74SLnLZEVuGMnxhizsYGyxUVlUAWck9
         Uq7IqlNDn7ToBKl0bxaY8ZoxlnvWxCWJ1dChULrbaynTI1Zz1c89B1sN2Uu3XwZEJekb
         zUhNzg1gkfI0tj1/UrNDpmbAXGapyOHRZETnWe7LijiP44oZRIsYdHcmuD2uZ3jpFCTj
         Vd7EUs1N3rjLt2kIy0sF7jcKtogcM2vGSpqxqXbRVJmVuu7COCEEdJ/LZRaMDE0x6Jl4
         GZ4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTvgxLV1nAWFJlSDbEDk74wV5cXHWvM9qqotsFU/m3Z24Nk3sGcko/C8X2fSF+6qKTeDdb7pl25Hp1JNureLszb9l7SwhiyQ==
X-Gm-Message-State: AOJu0YyW+Qgsgu4Srg4uJmvzGd55yx1XCZLLyRE0hjmhJ8eS0UH6qIFW
	Vgrx4/rKrYRQxMRMz7+ZNTK2DuoVDyZJSPhwnjJD8bGeW3I6h4uo
X-Google-Smtp-Source: AGHT+IE04QR592OGjxv8bm/SBuC3m7wXMXuShJs/o0mzs1GSYj5K81Dw5PfHwUoTr4VdG5WhpvQeKw==
X-Received: by 2002:a05:6808:2348:b0:3c0:4455:a2fa with SMTP id ef8-20020a056808234800b003c04455a2famr269261oib.18.1707777813802;
        Mon, 12 Feb 2024 14:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:180b:b0:42c:75a3:274d with SMTP id
 t11-20020a05622a180b00b0042c75a3274dls1945167qtc.0.-pod-prod-05-us; Mon, 12
 Feb 2024 14:43:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXPsjGjTutow5JrJtZGto1DFYumrRugT48JOEchaRNskVczOMyyelCcVERv4doaGubM8OHiZ6TE5X7rptxWaqsyx6Ky7g20p7rgjw==
X-Received: by 2002:ac8:5915:0:b0:42c:6e6b:2d75 with SMTP id 21-20020ac85915000000b0042c6e6b2d75mr9786641qty.44.1707777804759;
        Mon, 12 Feb 2024 14:43:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707777804; cv=none;
        d=google.com; s=arc-20160816;
        b=E0FS9O+ISh2IahlJ1xZldrZRqJsl1PCfMuBFyatp0zsMSGcLABbwmQ1HmCHPryR5/3
         eUXFxmb+D43vJo2rPOMKzfKe3Ru6DHmshrwhVRZZ06f2RUoMkkaaA0ZNzoXW2BeeQS5y
         lmUL8qKZOgRFeMiVlNOn7I5oPm0fnjd7Ft84v2SgFIeDOCvRgB/Ypk6sAoSUU0tTXie+
         QLQcXtAd0AbxrAwk/ZuxvGGewZtyKWFYEPibAl1hZ1uPj1vCdXZOUAdRlJ/ZejErJzP6
         53FzT4XmwTV5xa+8Xx7LeM5RsQ49xWKqN+Ft9S6o0SZyiNpcq869v5sSUamLvUQmpeIg
         i4lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lHfbSvdCb97XCfftcH6VJtR+XcLQrp5kkgikwsWfekY=;
        fh=3HPF4OX75OMM3DOVV2OMFnrea7qytNfWTPy8kQ52euE=;
        b=LRz2rzHdigWqvbW7h6AeNCvozhBwSSuZthvGVh5V95pzfASpgsAUwBsAbmV0xnmKqR
         ojm6sXT6m98wTC0m7VRiW11VKteUtyHcXDP4DWstErQIINsmpnJ38j/sa6imuptvVFv1
         qfapbm8rilMqLdPChjcCxrNc0zU1fN7nYyTiRZCU860gzJYaTXhRNDGholrpZJOF1FtY
         zwQ2G5fMHTXLFMjkHfHGlDOn4+fDhSaXjJmNOuVgcsu8yMRm/13+HQlHh9ULjzEywk+R
         BdOEx1lKWF0Ajbrq72X2oyLPq7H6W9zsk7daA5wcvmDCWCGLwuCtGeOaPMIqA/4Ktf0O
         mSgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=anIBqNFU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCVtuCTztFp9KuDHZe6r7NgQ3rL9HyW4k7zPHLn/myzEVmMmm+oAgmKXOfUELzg2Z0xxHh7DZftYKs5LObGg88LaANvffRnzAT4Dpg==
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id g7-20020ac87d07000000b0042c67fd04f9si152025qtb.2.2024.02.12.14.43.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:43:24 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1d8aadc624dso27322765ad.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:43:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXpkJ5Na4PdowKeiOriWwJq4rlzFe1GQBKjUN37cazKuEEv2Uo1pP4meU9ZK+GZX2NjYc0y6SyRdUsBwUQfDUOOE0rgPIGkILg93g==
X-Received: by 2002:a17:903:28d:b0:1d9:6071:30a9 with SMTP id j13-20020a170903028d00b001d9607130a9mr9304351plr.13.1707777803866;
        Mon, 12 Feb 2024 14:43:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX9FXIiKJlNVBwapdlDh/SgP9f6ciXUwXlOM5cLLbcyn8sRd4t5ezlbov/9BlxC8OVO5bUYyuScxtoCYZlt5TCkzEx/3C8aG+yTKWKrQX//+PMIxh3LSudxSCrzbEQDbSjECHwMwBJd7XwhodiJbxzrAqBc0gwG0LmPYSB9muEnb0zmP3hdH8Z0wcJD4xT/lENDaljrvEnNLWgI2Ztyk3x8i0hAHin9xe5Nvo9A27Jnsd12gv54pilwZFbVxNRcXJ8o/afase7NnvvgJ9IdRnhmm0m3PVQgDCDz0Sq0UBsN1fMNZ0b03+qnBGydFl4hDnECzSonEjz4Unwygoy6QZYN61ZFExyaxBImRPjC5k2TaS1XUuD5XebdswIdY6MQkE7fwpnXUVtYsdj/qgU5XeoVG+CEhHWPIaSOfg/UO5fdPrt/kjmUGmU2LlNcWvmlzcW2wV//tRT0ZScDt1zzlWQh7gkbzzXunUDUQUuPhKZJGV6Z/HCqT9ZN+8ivzC53KT/BIJxeSzL+ES3Mwhh1BcDJC1DiSmMR3RCsvfbc9KnSE0iap74FTN9Bg+pyudwJhK/eLcsCLbpR8O/QmNGU4E67ob4R2PV+SPJi/VpesCXs367T1b9gntVI6I68qvSE0fQgvSZzrxTw5dY7Dc83iqc8LMs2/jSB7QCqzVROo/K4NyGR1T/O6a5+6U1xY5mwzKirNm3yH0X26BOFvfYAqSRB6GIsnBduQF9KXklNjtR26wKLhIlZiSsl42jJ0UwKwgtqNy/njMNVhvaczzupXE76K2qXoU3WYnHrypkKn+cmz641Sg0TkpZgIcNdL6UGNxj6uTfxVXe4FXzN1Jwa2D1I8273bWzgVVA6KFOVKL8FE9jhM+n782cz/dzVv8bDRClobR2A4Dr27HUfMOdhzyIja8a3ep95FveT8UDOqFfFLQGhaNbi73xkAKQzuforGghglH
 H0H9XXf/YvOjHVOKTHEgD69wIPSsZ1wdZGgarbBWvv5xfI1WF/3R0nYo78caIQmz+Q5jUfrKRRATgSHmlpVnDUw7TqJf9RQd6SUdfcNEheDmH0pmIImInmPRI5dVEcQMMs/zo9jkd9qSDPLdKTZwAd6Do3i+sAI2NqEfIJrPhiIuq/uIKUV8EgInnJ45nEkyADjTSAfL/2Q2YaDKAbo9viG7qfQKWNEife39xe3RgBWph45qg1NtRgqnilYDNO8zYIwRByjkiSq2cr1AzhVV+FqN35SEDoonzbqygAkeikgApynjiDVWsctJ+hx7LQWU9jJKL4CtpXuL0s+cMOjHQQZ4hk0dUpz0JoEQkj66wK4Qgv66OnmZWqjf3wgOSiRbTpUj4P9IJBjylQ37S8JpTgOyq0MPNbLYQiolRa2kOeI/Jqbo8YvOFamaaxECQ=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ju15-20020a170903428f00b001d76f1e8a18sm830066plb.181.2024.02.12.14.43.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:43:23 -0800 (PST)
Date: Mon, 12 Feb 2024 14:43:22 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 35/35] MAINTAINERS: Add entries for code tagging and
 memory allocation profiling
Message-ID: <202402121443.C131BA80@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-36-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-36-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=anIBqNFU;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:21PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> The new code & libraries added are being maintained - mark them as such.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  MAINTAINERS | 16 ++++++++++++++++
>  1 file changed, 16 insertions(+)
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 73d898383e51..6da139418775 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -5210,6 +5210,13 @@ S:	Supported
>  F:	Documentation/process/code-of-conduct-interpretation.rst
>  F:	Documentation/process/code-of-conduct.rst
>  
> +CODE TAGGING
> +M:	Suren Baghdasaryan <surenb@google.com>
> +M:	Kent Overstreet <kent.overstreet@linux.dev>
> +S:	Maintained
> +F:	include/linux/codetag.h
> +F:	lib/codetag.c
> +
>  COMEDI DRIVERS
>  M:	Ian Abbott <abbotti@mev.co.uk>
>  M:	H Hartley Sweeten <hsweeten@visionengravers.com>
> @@ -14056,6 +14063,15 @@ F:	mm/memblock.c
>  F:	mm/mm_init.c
>  F:	tools/testing/memblock/
>  
> +MEMORY ALLOCATION PROFILING
> +M:	Suren Baghdasaryan <surenb@google.com>
> +M:	Kent Overstreet <kent.overstreet@linux.dev>
> +S:	Maintained
> +F:	include/linux/alloc_tag.h
> +F:	include/linux/codetag_ctx.h
> +F:	lib/alloc_tag.c
> +F:	lib/pgalloc_tag.c

Any mailing list to aim at? linux-mm maybe?

Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>


> +
>  MEMORY CONTROLLER DRIVERS
>  M:	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
>  L:	linux-kernel@vger.kernel.org
> -- 
> 2.43.0.687.g38aa6559b0-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121443.C131BA80%40keescook.
