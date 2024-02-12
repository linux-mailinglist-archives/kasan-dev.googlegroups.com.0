Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQ5WVKXAMGQEULR5UWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id DC74085215F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:27:16 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-218ea70ba0dsf4832280fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:27:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776835; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjR+F9Vs7J9/X1X+ZGMXviUQUwMx5PfvNvLFmE9Yd1DdCHcnOaIxXaAHz4D9vFOBJO
         hDeeodjVpAtFKiEgPZdtsOgfyb5Fxi8WA+Ku5hMCTfbyQmIhakQkaOf6hI8ts2Ev7Pfv
         xRraKMrMGh60EujZ/AWmKoRuZB55Rn+zfnoHqF+Xu3ldNUfRPXMwShw7EdNrod6wdEQm
         dFWeoh7oTwU414lGrY8a+E+Cx31SHt1IyFuLuJksLUetMcLN9ez94WA4n3JA1FgBRKZB
         bpFexX9bpdTeWmDyfKvSwjzjTFM6H/9eQ3XHSp0mfKHnx3XcUS6JGkMPCX6peKUqiDCf
         5fQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=t2qegxogtkq/KVGNcnZ4ViXQWBo6e9qOxohNFMYKBUk=;
        fh=3wKkT7n+huT47m8N0Sn3BAzmRgXV6ProAim3L8GdHq0=;
        b=zv598hqPK6AaFSmQKjEgt8oKrZiniZCbvCni/WSl2MJl8VYI6XB+L3CXupJiTtZK9/
         DCtAWzqZt14CT/K5xAlXURx0R/p0PxDfm2YSCG4IhMnrf35aTaowhYNfDWxZKjm/aIvG
         Q1Nm8X6bZfvNcqk78R0jaiIq3M1IqG0RGX2QLE/VIZrAhn4pUsaYHbn+DQRq2zMyHuzB
         RhUSKbMHZTelpBZqIjzGZ3NElepLyPcTDlBZRn6Xzf+NkUgNAHa4adPmV8lRyNC/2GJP
         kMVVddDtm35oF4h6SyDj5zCbaUqjj2VHMmPueiVH7ASCLK/OgqfQuUrwDvKIvIrKgTCO
         eOfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f90Rjhq7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776835; x=1708381635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=t2qegxogtkq/KVGNcnZ4ViXQWBo6e9qOxohNFMYKBUk=;
        b=LO2yhhzQB2jy+eK9kyuqxai7LghI9yUTEt903m68C88q1lUVbpB35J3UppS9t84mLL
         N468Qg2rMGtzboAulYjtMHLEtUfiyJ13wCQdyplYnmC1WTvXDFyuezAIiO9z7I+c4khe
         V4cIVY1/A+84dHkHyMpyyEHmZ0BXb+8WSWbOysVfUQq3cHQeqQfC8R5AZ3g6U42JSh4L
         Dl+4U21Dos3ceZ64UDwAq8RqSu8KHCxJz1DGMCsA+fKYKQz8i63WXsYGNaj3aFeftx6M
         0+cH3iAawyqo+gCr5fx0ZsUqCqTE9pgEA1wIKIflMEAfXwAvWi7YBbfv+ddkZF2zvAdv
         yrgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776835; x=1708381635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=t2qegxogtkq/KVGNcnZ4ViXQWBo6e9qOxohNFMYKBUk=;
        b=ZK0sbsJ0oqRfsFfIWrn1PdE1gyTNGevC0vq48+UCCoiw+A2sWLaaysFsOc9cgbbbjC
         5BdtWQ4oYYumyokyWQ8Hh4l7scKEP6yElJrgn4k7N2QdplYr2/x7uUmTNiVK57EPuKmm
         q29KflK6+YReT5RavfHs2yv8Tz7IfaNLW10FnOQbS73LLMmvjksuBykmGIBQkJ4VtXqw
         8C/vjOu6KIb0CqOTqKWNIvBB2dPSIXUyY/T8NHMrK7HtGAl/ODQtk6DJQkLPiMS1fDWH
         XvuS4Ghb2dsOn/d9MGba5el92XBhj+9IU1If0ad6JXlm2Vt8F0fTLuSSjKYiswFoaMmN
         AmqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBTC/QtyCg3YtCFW/CosZZEELRsE+wdDl9VVLwo3XNELTR5VDMfa6JWfW0PyHpsEmKfkEa4nK3Ck2da5gyzlUJAFNiHXKmBg==
X-Gm-Message-State: AOJu0YxbuQ9JsFDNra9tV56R3uuewn5xhalYMaXwt9mkzKlHiRZw2/N/
	laPswYN3HJsQo1dZGQR73eST7TXeh4pJS3e/uJLJRwNmSgoiKdJq
X-Google-Smtp-Source: AGHT+IFai+Jlzk71WjnwFAvY79yFaxyoGBctJL9G5kPmdSjWiAUyeJ7xW08EqSF0rbZ7x4SnmZYx6w==
X-Received: by 2002:a05:6871:5822:b0:219:dff0:ffba with SMTP id oj34-20020a056871582200b00219dff0ffbamr9702490oac.49.1707776835621;
        Mon, 12 Feb 2024 14:27:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c0d2:b0:21a:216d:5a25 with SMTP id
 e18-20020a056870c0d200b0021a216d5a25ls4076278oad.2.-pod-prod-07-us; Mon, 12
 Feb 2024 14:27:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5P3KifpGufqYOcGklNF2nAnO+a+EKnW3HekZZD4DJeSBt7U5txUT1ZStUyJCOgekUEgXOtiG+a2S4HmO6zuKLOoN3Qo0O+uJ74g==
X-Received: by 2002:a05:6871:440d:b0:210:d385:e497 with SMTP id nd13-20020a056871440d00b00210d385e497mr9462153oab.17.1707776834937;
        Mon, 12 Feb 2024 14:27:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776834; cv=none;
        d=google.com; s=arc-20160816;
        b=ZjGuLU3OLqIRMFX1Lc7L2+DO8XQd0PwVz9Hd1lhQvYUN9d23nu30oaXTehPX/0rlDw
         X2f+O2Nm7VBbtIBKPT8rp+TvRYCHpL72WFizT7cnug7kne1FFfN5VgIc12Bih8uyembi
         jNxnO4dLoApJ+8R19mA5qMdOelotXdOGq3zvqVVeulchXMfF70l+574YRL1iqLCLuaI8
         hykkWABknhI/J2Y0/PxHxnJiIM9zcbUqfpzUxjyz1Iug6O9PpTr6CgpAaWHV0Xwdwa9J
         9cIEWEo9Wne4gPJ2AEuno4wW3k6typ6zupOAkp3vvs0775Qmv3UH3SBjD4gb3wFx2E32
         OB8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2fCTTjLWubBPUVqrfEz/Ix5Fohf77+LrHQ9JGOiJ25Y=;
        fh=lierNhEKM6sTnNjraDrsT4xPUtkwB6DxRDrFv2qf3hg=;
        b=WxZixBjAQb3ToJQTGwqwE2GCfkRIWj7dw0ow6oW1eG6fWb6MJR39aB8jreV+j/1VJj
         TI6NCK1ImT8qftV8nUYB670KU6uZmLHj+gqNne35PthjJi4YeWW2jOzNceedaulIEx9s
         0z0PZpw9h6o3mqoPUvw1x0qKyLBOcxP/myyKzKDNyG9/sXlx+wlnhAbjX2pFro8Ttgu6
         f1EeR57hHBVE7xcwG+TejNU5IWmhsJnfrNUSyki3R7E1++bsuJ5+BTswb1TTp6SdWD1S
         vfeGnMJ0B2wZmuEb97f7z4yE+SWmsR90zwJ3PIPSGiof0V62z8kYYbJDtDEo9WmfN8IZ
         jVKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f90Rjhq7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXCEI4UUDQ7RcvVQQC1zmGtK//tCIBwpSxpll6wIWgs1xUg/31q+awYqfXSNvVreXut+MbONB+pNLgqp3cfmHtvO+Um7VB69hkNYQ==
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id yn6-20020a05687c014600b0021a31c0cc15si585864oab.2.2024.02.12.14.27.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:27:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1d7431e702dso31649975ad.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:27:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUrIaecIu4Epx5HBO9jkY6K7pbNzP6g9OXRpZcuAl5/HhfBVzsuAqxlXBZUaONHha1KqjQR8UYgOyt1sD6qOA842d7nxyXNmvvCcw==
X-Received: by 2002:a17:903:11c5:b0:1d0:b1f0:1005 with SMTP id q5-20020a17090311c500b001d0b1f01005mr9019206plh.63.1707776834123;
        Mon, 12 Feb 2024 14:27:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCViNm2UwBffaBkDD1Y2NdwnMEZMnfh75IEO10MXOz1pvEVWYD8cKnUXP9RcwNvb61eqkj8k3/KM3h2ULmARDJX5nuqJL653cxDrBVAEqX9fIIC/DaaSFkJP+1CaJh1g97I8DY4cs0LmICXoaRbzjoSJM9QDKA3dXCwcpjqBlshIM2bMvvifm4q4No+regvI4L3sVOQ+OLbBQR6d01nG/FGsBwiivvcNk95YlwImFBEDIdKxSIVyUGK5anJWEB2u5DYGHzdyu2Cb1S8smzp7Zs5iH6ADe6EEiKrd8GSgnUyBS8/ziZibdJyFqwcd7/COFhtzPp20uEvxGNlcs/QaoD0JKh18gzB8zgk6TVlQWITsl3TRkIT8QyJZ7FSGZ+jrCuR24TJ8I9thS53xxH4iUfVG8FAD6OChWdIApYwDqW49+ZqFjlbGPJ2ew4VOyBjzL+MxPnSsuB03oTtGjYBG/RysIK9Iu27reZb1pU5K5hE80iqQqBz4l5rFXZNOmHePH1zHQ1N/eNWYuNdWJIXfxfLja/4w4oGGuDXfDe2jiJGSEjLtZfm9TVZOcr9KAvMe/HRQeAWP6NfLK+KhU9GrJRsBLRWT6Gy4Crek7KRmIl0feCFMmhYeEmI2KX9UtfWPG8whD93hexVoxXmnTWZV+7lA2Ycr8Mifd9A/5I6hjANOmtsnX16noiQEvtb2ZekjUOCZKueAxsEOtVZf8mOq7kpXOZYtODlO5rvVYBUgyAwvGE1zzTmh57L9zSlo0/U5OmkkbgPbNqo4aHXxliB/Y8r6fhWCZOEKer7tEal4jFdyn1y/dNXiGsNxzV3pa4E+gmJ7Wj1AM5wXKop8GN2CsBFUyJn3pvc/xO7kMY0VFgXdNdypC5TOITlb2eEYdyYtp79R2sXewJW8Rl1BOYG9YkURbkM45qwdBxMYlT/IivA8X786pj5bqNnFbZiALbgpnc1LgE
 rVl6m6GRZo3R0U4hcFrq/YngBx2EMc4uzNXGBGgVWbUdizfPSkK32yVq0iwn6D3ZWeLavNGvTjuxOpHRBMetuvuK45mw/5M2V78ih7ajEgdAqeX0CtAVJBRi8W0ElDxeRG2B/nZJTLa66D7ktNTnDQw7tk0xUHOQRHF8yJIF59UNRhSU293h6Iwi1I5AT4bkD3Dj4YeG7ATOcAuKzRJlnd5GqLc023DXR6DE0EkELrrbmGH0lQKOskXddGVfe98PbTOhabVY4XlZ4RpEeNL3oi9i0rPvicAIl3mCOl3mJSW+neG67yCM6fzKjO0dYCX2ujnqZbIvB/aHxA5l0tIjWU1F0le9fpDr7FQioW8egzL6N2oiSEzByjFLEcZkX9wIsXBbDU/uXHmrAXY6NmdrxgzJTJ/ydW4AVPnNyTtVPwOlxkN7ewpN1W6u/fwec=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id lo12-20020a170903434c00b001d88f0359c1sm818238plb.278.2024.02.12.14.27.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:27:13 -0800 (PST)
Date: Mon, 12 Feb 2024 14:27:13 -0800
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
Subject: Re: [PATCH v3 10/35] lib: code tagging framework
Message-ID: <202402121419.7C4AAF27ED@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-11-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-11-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=f90Rjhq7;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f
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

On Mon, Feb 12, 2024 at 01:38:56PM -0800, Suren Baghdasaryan wrote:
> Add basic infrastructure to support code tagging which stores tag common
> information consisting of the module name, function, file name and line
> number. Provide functions to register a new code tag type and navigate
> between code tags.
> 
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/codetag.h |  71 ++++++++++++++
>  lib/Kconfig.debug       |   4 +
>  lib/Makefile            |   1 +
>  lib/codetag.c           | 199 ++++++++++++++++++++++++++++++++++++++++
>  4 files changed, 275 insertions(+)
>  create mode 100644 include/linux/codetag.h
>  create mode 100644 lib/codetag.c
> 
> diff --git a/include/linux/codetag.h b/include/linux/codetag.h
> new file mode 100644
> index 000000000000..a9d7adecc2a5
> --- /dev/null
> +++ b/include/linux/codetag.h
> @@ -0,0 +1,71 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * code tagging framework
> + */
> +#ifndef _LINUX_CODETAG_H
> +#define _LINUX_CODETAG_H
> +
> +#include <linux/types.h>
> +
> +struct codetag_iterator;
> +struct codetag_type;
> +struct seq_buf;
> +struct module;
> +
> +/*
> + * An instance of this structure is created in a special ELF section at every
> + * code location being tagged.  At runtime, the special section is treated as
> + * an array of these.
> + */
> +struct codetag {
> +	unsigned int flags; /* used in later patches */
> +	unsigned int lineno;
> +	const char *modname;
> +	const char *function;
> +	const char *filename;
> +} __aligned(8);
> +
> +union codetag_ref {
> +	struct codetag *ct;
> +};
> +
> +struct codetag_range {
> +	struct codetag *start;
> +	struct codetag *stop;
> +};
> +
> +struct codetag_module {
> +	struct module *mod;
> +	struct codetag_range range;
> +};
> +
> +struct codetag_type_desc {
> +	const char *section;
> +	size_t tag_size;
> +};
> +
> +struct codetag_iterator {
> +	struct codetag_type *cttype;
> +	struct codetag_module *cmod;
> +	unsigned long mod_id;
> +	struct codetag *ct;
> +};
> +
> +#define CODE_TAG_INIT {					\
> +	.modname	= KBUILD_MODNAME,		\
> +	.function	= __func__,			\
> +	.filename	= __FILE__,			\
> +	.lineno		= __LINE__,			\
> +	.flags		= 0,				\
> +}
> +
> +void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
> +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
> +struct codetag *codetag_next_ct(struct codetag_iterator *iter);
> +
> +void codetag_to_text(struct seq_buf *out, struct codetag *ct);
> +
> +struct codetag_type *
> +codetag_register_type(const struct codetag_type_desc *desc);
> +
> +#endif /* _LINUX_CODETAG_H */
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 975a07f9f1cc..0be2d00c3696 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -968,6 +968,10 @@ config DEBUG_STACKOVERFLOW
>  
>  	  If in doubt, say "N".
>  
> +config CODE_TAGGING
> +	bool
> +	select KALLSYMS
> +
>  source "lib/Kconfig.kasan"
>  source "lib/Kconfig.kfence"
>  source "lib/Kconfig.kmsan"
> diff --git a/lib/Makefile b/lib/Makefile
> index 6b09731d8e61..6b48b22fdfac 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -235,6 +235,7 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
>  	of-reconfig-notifier-error-inject.o
>  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
>  
> +obj-$(CONFIG_CODE_TAGGING) += codetag.o
>  lib-$(CONFIG_GENERIC_BUG) += bug.o
>  
>  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> diff --git a/lib/codetag.c b/lib/codetag.c
> new file mode 100644
> index 000000000000..7708f8388e55
> --- /dev/null
> +++ b/lib/codetag.c
> @@ -0,0 +1,199 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +#include <linux/codetag.h>
> +#include <linux/idr.h>
> +#include <linux/kallsyms.h>
> +#include <linux/module.h>
> +#include <linux/seq_buf.h>
> +#include <linux/slab.h>
> +
> +struct codetag_type {
> +	struct list_head link;
> +	unsigned int count;
> +	struct idr mod_idr;
> +	struct rw_semaphore mod_lock; /* protects mod_idr */
> +	struct codetag_type_desc desc;
> +};
> +
> +static DEFINE_MUTEX(codetag_lock);
> +static LIST_HEAD(codetag_types);
> +
> +void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
> +{
> +	if (lock)
> +		down_read(&cttype->mod_lock);
> +	else
> +		up_read(&cttype->mod_lock);
> +}
> +
> +struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
> +{
> +	struct codetag_iterator iter = {
> +		.cttype = cttype,
> +		.cmod = NULL,
> +		.mod_id = 0,
> +		.ct = NULL,
> +	};
> +
> +	return iter;
> +}
> +
> +static inline struct codetag *get_first_module_ct(struct codetag_module *cmod)
> +{
> +	return cmod->range.start < cmod->range.stop ? cmod->range.start : NULL;
> +}
> +
> +static inline
> +struct codetag *get_next_module_ct(struct codetag_iterator *iter)
> +{
> +	struct codetag *res = (struct codetag *)
> +			((char *)iter->ct + iter->cttype->desc.tag_size);
> +
> +	return res < iter->cmod->range.stop ? res : NULL;
> +}
> +
> +struct codetag *codetag_next_ct(struct codetag_iterator *iter)
> +{
> +	struct codetag_type *cttype = iter->cttype;
> +	struct codetag_module *cmod;
> +	struct codetag *ct;
> +
> +	lockdep_assert_held(&cttype->mod_lock);
> +
> +	if (unlikely(idr_is_empty(&cttype->mod_idr)))
> +		return NULL;
> +
> +	ct = NULL;
> +	while (true) {
> +		cmod = idr_find(&cttype->mod_idr, iter->mod_id);
> +
> +		/* If module was removed move to the next one */
> +		if (!cmod)
> +			cmod = idr_get_next_ul(&cttype->mod_idr,
> +					       &iter->mod_id);
> +
> +		/* Exit if no more modules */
> +		if (!cmod)
> +			break;
> +
> +		if (cmod != iter->cmod) {
> +			iter->cmod = cmod;
> +			ct = get_first_module_ct(cmod);
> +		} else
> +			ct = get_next_module_ct(iter);
> +
> +		if (ct)
> +			break;
> +
> +		iter->mod_id++;
> +	}
> +
> +	iter->ct = ct;
> +	return ct;
> +}
> +
> +void codetag_to_text(struct seq_buf *out, struct codetag *ct)
> +{
> +	seq_buf_printf(out, "%s:%u module:%s func:%s",
> +		       ct->filename, ct->lineno,
> +		       ct->modname, ct->function);
> +}

Thank you for using seq_buf here!

Also, will this need an EXPORT_SYMBOL_GPL()?

> +
> +static inline size_t range_size(const struct codetag_type *cttype,
> +				const struct codetag_range *range)
> +{
> +	return ((char *)range->stop - (char *)range->start) /
> +			cttype->desc.tag_size;
> +}
> +
> +static void *get_symbol(struct module *mod, const char *prefix, const char *name)
> +{
> +	char buf[64];

Why is 64 enough? I was expecting KSYM_NAME_LEN here, but perhaps this
is specialized enough to section names that it will not be a problem?
If so, please document it clearly with a comment.

> +	int res;
> +
> +	res = snprintf(buf, sizeof(buf), "%s%s", prefix, name);
> +	if (WARN_ON(res < 1 || res > sizeof(buf)))
> +		return NULL;

Please use a seq_buf here instead of snprintf, which we're trying to get
rid of.

	DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
	char *buf;

	seq_buf_printf(sb, "%s%s", prefix, name);
	if (seq_buf_has_overflowed(sb))
		return NULL;

	buf = seq_buf_str(sb);

> +
> +	return mod ?
> +		(void *)find_kallsyms_symbol_value(mod, buf) :
> +		(void *)kallsyms_lookup_name(buf);
> +}
> +
> +static struct codetag_range get_section_range(struct module *mod,
> +					      const char *section)
> +{
> +	return (struct codetag_range) {
> +		get_symbol(mod, "__start_", section),
> +		get_symbol(mod, "__stop_", section),
> +	};
> +}
> +
> +static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
> +{
> +	struct codetag_range range;
> +	struct codetag_module *cmod;
> +	int err;
> +
> +	range = get_section_range(mod, cttype->desc.section);
> +	if (!range.start || !range.stop) {
> +		pr_warn("Failed to load code tags of type %s from the module %s\n",
> +			cttype->desc.section,
> +			mod ? mod->name : "(built-in)");
> +		return -EINVAL;
> +	}
> +
> +	/* Ignore empty ranges */
> +	if (range.start == range.stop)
> +		return 0;
> +
> +	BUG_ON(range.start > range.stop);
> +
> +	cmod = kmalloc(sizeof(*cmod), GFP_KERNEL);
> +	if (unlikely(!cmod))
> +		return -ENOMEM;
> +
> +	cmod->mod = mod;
> +	cmod->range = range;
> +
> +	down_write(&cttype->mod_lock);
> +	err = idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
> +	if (err >= 0)
> +		cttype->count += range_size(cttype, &range);
> +	up_write(&cttype->mod_lock);
> +
> +	if (err < 0) {
> +		kfree(cmod);
> +		return err;
> +	}
> +
> +	return 0;
> +}
> +
> +struct codetag_type *
> +codetag_register_type(const struct codetag_type_desc *desc)
> +{
> +	struct codetag_type *cttype;
> +	int err;
> +
> +	BUG_ON(desc->tag_size <= 0);
> +
> +	cttype = kzalloc(sizeof(*cttype), GFP_KERNEL);
> +	if (unlikely(!cttype))
> +		return ERR_PTR(-ENOMEM);
> +
> +	cttype->desc = *desc;
> +	idr_init(&cttype->mod_idr);
> +	init_rwsem(&cttype->mod_lock);
> +
> +	err = codetag_module_init(cttype, NULL);
> +	if (unlikely(err)) {
> +		kfree(cttype);
> +		return ERR_PTR(err);
> +	}
> +
> +	mutex_lock(&codetag_lock);
> +	list_add_tail(&cttype->link, &codetag_types);
> +	mutex_unlock(&codetag_lock);
> +
> +	return cttype;
> +}
> -- 
> 2.43.0.687.g38aa6559b0-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121419.7C4AAF27ED%40keescook.
