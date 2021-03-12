Return-Path: <kasan-dev+bncBC7OBJGL2MHBB34HV2BAMGQEWY55BEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A793390C9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:08:31 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 73sf5468304wma.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561711; cv=pass;
        d=google.com; s=arc-20160816;
        b=x1MO0xRNDfmwyJFtdXvZ/rn5lYVWiUV8vfjUsq+PxiLX3PSeAGKxCF+kt5W7UKkAWA
         3aulRdA0Q4q/1MK8V4ptqIVvneTSIbwqdzpNxR+YoyFxqAFAQKqcoHX5wcf7Rf5KI5QP
         65QwuvKJRWTeekLzg4mO9BhO9Vjav3fCp77AbCoI5HlARRmHcbU7kvEjztYHMXvLYmGV
         Q8uYwKDMLmBugArhbfrRj9yXbs8AP4+vkpSwd7pMEzAaB/wxsLzWMupGrSplGKTHi6ii
         yRWIOwrfc0PKAgAVV5VKPDOAnaiwwhMOfvGkoHBhXPbmAeLowwYmUKuD3lniCdWLeZal
         IS9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tPjNECxsEtJYRgL65NhPbmmMWzXmd7EgqU8+tGl3k0k=;
        b=IXWION2U7f3WIUcIdDPInFfWsIGVjtcVTwQAPUKkJAMfU4j5kSeG6I7Ieq+VShr+4k
         pfZ4W2MACQJh6g0+h9Bw9t9IOpweauv2Iyf93IFL3jqDeJgD1ABWdwB/olvIy9jPdKSo
         ZPB6pqjruTz483Vv2ztJODMR23BhjHF9SSgxcaUUn1Izz4ByLTQCrWa5YqszfjA3rmfe
         WO9/B8lEGOdTzelg4p0r8cpxNqzoTJQ1QoxI8dQzbSpK1j2RkTZJdiOmrUhLp4vlbVoH
         WZzHxoSPt3mvzj5E11sN+7Eg2GyVwEFtQPNqIK/3xX1gW/2/uWv/fEttZ9m+z/gnZIIB
         vxPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twQbMdDX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tPjNECxsEtJYRgL65NhPbmmMWzXmd7EgqU8+tGl3k0k=;
        b=FLrkiVNUVYoii9prjje34faREjM3/pYB8/hjATCb4oBWRs6VbXJ95LbGyEQInrTMIF
         o7OzW7ySW1W1KdrnLXkh4HqfAJtqu52hs5JyQBPpi5g8Ih7b09FeP3tn4EUn3dOHCJXy
         HBqeB8kTwT/qIkZ4VG8k+PCn0arQNaF+sqOe1LwITqmDobZk33deu5tjmhvbtZ3E6kLS
         GSNTiVet4MQJ8GVlXnK+8rnTEUFs3+FT+6yWMpRleK9lbDZklocsYSM0Zx01roGSmVd0
         hizNSBN7D14UwFDl5n6dc06MUIxaWbSjJS9DH0XYv1MSCulYP9ya6yoKdN75bWMKCwuD
         V5ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tPjNECxsEtJYRgL65NhPbmmMWzXmd7EgqU8+tGl3k0k=;
        b=C2Jo5RrAlPgGMZ1uqOp3o8r8/IXEFPyTiSqIjZRqBGZdJbkz/ueCypZo5gsigf4ulk
         +ldKToz5lGrFUSaPFmcbtsEEPTfuprJP/lu/4pI2veaslXEG9Td1z9HdGxjLhy6GB0yF
         W0vrFqtaYe+/JLQsiwD+bNQS5PPPa55QDSxhfpwd/nsDm5v8iekix4cmMmtNmXHZZTDi
         IYKJqxUyfp/9Snkm0WJ9Lg+jDfSBXrg5wAPdkO+H9KzSrnJbSZtNk+3yqkUq/uM/e6HR
         aqFhQWMUaDtOKYBo53uAE58Obsv7wEPFwmvBg5+H7v++ogmmY8QUMaHyNRJP+WvadV3A
         tyjg==
X-Gm-Message-State: AOAM533wpbZM5Alq2epjT9j3k9Iyt3p1NmUxfy4W7e7aK1UhL6X8jAPY
	e0jyJsLPzHsGmiFeStPhR5s=
X-Google-Smtp-Source: ABdhPJwwlt+qec877RJunjpx58GbJPLopWZ+Kw4Aa9wgv7Y6lLDgZnhGR4Waq2blBatlTxoRM3dW8A==
X-Received: by 2002:a1c:e041:: with SMTP id x62mr13298183wmg.95.1615561711578;
        Fri, 12 Mar 2021 07:08:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls115499wrd.0.gmail; Fri, 12 Mar
 2021 07:08:30 -0800 (PST)
X-Received: by 2002:a5d:4e52:: with SMTP id r18mr15181899wrt.28.1615561710589;
        Fri, 12 Mar 2021 07:08:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561710; cv=none;
        d=google.com; s=arc-20160816;
        b=goT4rTIrCyursql93tftyEiY337BlLEAK/ML6rWjZ2uwia3m68NRrWG4OTLUzPAnwb
         +hQE0vVRlb6kSLuRBZ7/gejhvTd2BAv0UC3EL0pgWwHvUNHelu++C/ZBod6iUPG1NH5S
         sW8K5QfgPSlLUH4Pp/sXKAV56PtbOhnPIoVOj8PvbqoaB6XDBIy1EgV1UgkyXnoAXljb
         V2I/fLK/jyiyrTVSEyqiy+L4GUXdmTlSW3Y949+CuZSozp0zWjK8xCbkem0PZ1ddJSqn
         YTJwpRd2ieCNv8WNWdoNy6CFVHjvdSJr2iRREJWHlrpHu3kittmXzALj1ldxjF2boSaM
         o5gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=N8S2s5rJcGUHcU1OSYPYZlzzNPfPJNrusRzWOjftzyo=;
        b=npPJj5t5nxkIqOTTpQ6GVKY6O0J72gWAEMMcZRXymmvjuvHh8DwFPBTa51DimH2+uK
         w5nWDO7aMS0EDihgYPH8l0Q/fkdoow9X/zBLlptDsf0jONvuOYmd41y+Qy15SZN0qZ4o
         AYUs57GnVItcUYrmFgPWC9j1aRKm8Qbzrve9ByI0mjMF7+h0OTsfoOu46ydJBcCh+A+z
         mEpjLsLGxHNjWXjWoR7yvHmPSEedn9MsBtTTDCDVzPDcRtzoJdQRWcKDritVgKaHOomW
         FzxeZ1pO4TLJyDWT66ZjAUGPtvKWhKFLkt6cBcC1q+WNJoqmL8ZKYCM0UmyluzsH7Pa3
         QgjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twQbMdDX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id p65si597646wmp.0.2021.03.12.07.08.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:08:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id w11so4971590wrr.10
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:08:30 -0800 (PST)
X-Received: by 2002:a5d:5051:: with SMTP id h17mr14242807wrt.80.1615561710089;
        Fri, 12 Mar 2021 07:08:30 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id j30sm9332276wrj.62.2021.03.12.07.08.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:08:29 -0800 (PST)
Date: Fri, 12 Mar 2021 16:08:24 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 05/11] kasan: docs: update boot parameters section
Message-ID: <YEuD6CIhVsSo9uqA@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <01364952f15789948f0627d6733b5cdf5209f83a.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <01364952f15789948f0627d6733b5cdf5209f83a.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=twQbMdDX;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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
> Update the "Boot parameters" section in KASAN documentation:
> 
> - Mention panic_on_warn.
> - Mention kasan_multi_shot and its interaction with panic_on_warn.
> - Clarify kasan.fault=panic interaction with panic_on_warn.
> - A readability clean-up.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 14 ++++++++++----
>  1 file changed, 10 insertions(+), 4 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index cd12c890b888..1189be9b4cb5 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -174,10 +174,16 @@ call_rcu() and workqueue queuing.
>  Boot parameters
>  ~~~~~~~~~~~~~~~
>  
> +KASAN is affected by the generic ``panic_on_warn`` command line parameter.
> +When it is enabled, KASAN panics the kernel after printing a bug report.
> +
> +By default, KASAN prints a bug report only for the first invalid memory access.
> +With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
> +effectively disables ``panic_on_warn`` for KASAN reports.
> +
>  Hardware tag-based KASAN mode (see the section about various modes below) is
>  intended for use in production as a security mitigation. Therefore, it supports
> -boot parameters that allow to disable KASAN competely or otherwise control
> -particular KASAN features.
> +boot parameters that allow disabling KASAN or controlling its features.
>  
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>  
> @@ -185,8 +191,8 @@ particular KASAN features.
>    traces collection (default: ``on``).
>  
>  - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> -  report or also panic the kernel (default: ``report``). Note, that tag
> -  checking gets disabled after the first reported bug.
> +  report or also panic the kernel (default: ``report``). The panic happens even
> +  if ``kasan_multi_shot`` is enabled.
>  
>  Implementation details
>  ----------------------
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuD6CIhVsSo9uqA%40elver.google.com.
