Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDOFXGHQMGQEJOTPGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 342E6497A48
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 09:25:50 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id c22-20020a056602335600b006101beff8bcsf2770566ioz.23
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 00:25:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643012749; cv=pass;
        d=google.com; s=arc-20160816;
        b=XKnC/16l1gW844xfpXAONARf3/yI1WXhcJutHwzTApoXMF/Z28VAf96uy6VMYmg/04
         56EGG56N06Jw+8sKYs5COAc7pXG/RUd5m0uwMWmyfsJlGHt7NomHOK4mqC3w7KkhI3Y7
         YJpnzL12kDlO3atG3jfpoEnd5J03Q8kC4shgmrvb7hnD8exh17oi7a9tH3av4bmAGSsk
         Ed+c6icuTh2IWGV+1sE287IahGpH+EiMgFvPDHMsbOIojm9kfGyoVZiWCjBpKFZtCH+8
         EXkFWQ8XskAoFhKwZ9yQoDL/iyOE3biydUu6w5JchCsNwkkCyVEyZbscYU6+u0h6BW3W
         9XSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TR2eCVnlbeIvIROeUpKoQ9MVhUSYaQczoJkDhQNlCIo=;
        b=TVgnKFZt6xpBjdNp7VgLHwYV6cajQUnBzjvT9RFBEBNJVCWkiaVUMpjaUvSOO6SRmN
         AG6kfcVOOQNSeDpdox9MitEaAvY/SZ72zM8FVnH9UPbiHgSZNSPY0WbKPKNLUTTwbzDe
         5Nim3oRqyxq2O+eDgM9ZY+ZCR8Z+AjYJsBfOiQjkNOcJ0E4dfZadeIbt1V17+CpDwNT8
         xsZ7k01tUHOkdDVzoJGrZdQZCduID7OinkXMDYufn9c3Hf0ZPu0Cy0RKdAA0aYGi8gCd
         qfF+OnrqSWcwVRnjXCgJ3q3GozDQ4xc1k+oqf3iM3L6GxOyu+aq2Jxy+4WOSnsMNYYiu
         ljcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eazm9+k5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TR2eCVnlbeIvIROeUpKoQ9MVhUSYaQczoJkDhQNlCIo=;
        b=HJDoWyfv9YHyMmyK5MP7Zw+a7upcHHLGP4PQEV+3B1rSDocdgefugqNg/Tl/WdgoDk
         A2Ya739kdtCxYmUYtRZw8IRLMdh+LFOQJ7QEpwJ36phwCujJ1QbxpKb6eDYv15QjrlnF
         /3Ey9puMi2aJqjKHNDI7zPTLrzrlwEWWKCcKRL/YlMUhHA4L3lx8vHSgXbOQyXgpnyxP
         wEtAvjju3m77SmQn/N6ii7Oj3+8eBTkOK7ipnmrbflfX64DziKu2p4rxOyOzRSKSXOZC
         IRpVyGBxLPNfKfIBZyRZl2xRW7BJlIYF+kZ3TBFdsFN80Zpu77ilsUnwtnB+1gPJkL4J
         3rWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TR2eCVnlbeIvIROeUpKoQ9MVhUSYaQczoJkDhQNlCIo=;
        b=M0E3QYuv2fRrl0CWqbba26V0sLtcdyLiC3LDMPGdY5oCfi55SWjd2/uhK5gx83ZFfI
         GDjigJG5Tr1Nb9UU3CBVplWT2xaT1dbMLYCspRlsoYl/tMRVDIsHTaog68Jq98HWElc+
         jO1tXzD3eLF+tpBBbNIBldM/4DaiIoZuEjGjgaDmnf2SL42KlcdJ+RkEjf5YG5YtGtdI
         U23zvvYjv/l6+zJkk3HTqI2Go9lbyrFxpgoZD1G8iBpuEpkar7B5pGAxYKIJQxkmGVB8
         JsdGv7czsB1JOz1c0cb/O5MaHa9yJMC0S4sob00LTlhYUmj6+n4r4Asecs5SOLgHxmyi
         8KGg==
X-Gm-Message-State: AOAM533S0RoNVbWynJS61rzF8+H7almJM9W9Wt4gM10piMr7GyDlu1AE
	6xaBc7NW0wEf/oopOWjgpS8=
X-Google-Smtp-Source: ABdhPJw7VOrX5KuHTcqv3AH3ssGZSKbpPTBErYY5nH2cpDjNSIa24tM+Sxr6Qavuj/8n4EarUdvWXg==
X-Received: by 2002:a02:c80a:: with SMTP id p10mr1098052jao.218.1643012749170;
        Mon, 24 Jan 2022 00:25:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a0b:: with SMTP id s11ls2629812ild.5.gmail; Mon,
 24 Jan 2022 00:25:48 -0800 (PST)
X-Received: by 2002:a05:6e02:16c6:: with SMTP id 6mr1595657ilx.186.1643012748755;
        Mon, 24 Jan 2022 00:25:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643012748; cv=none;
        d=google.com; s=arc-20160816;
        b=sNn1t8DXNn1IAY8T/VjXVC3Dw9TklOLS0WYFVcb9FPDJ1AzIA0LmKUUNaj8+GpKmw4
         K5AxTdVdgHeCQuPGzZy8FOzuBtJqN2ohHFO1f2Xii/ayE74QaH4gh7Vb4SEiuA0R2f7T
         p6QwH4SJM42w4XZTXBLl4zZc4dRdlVWxnav0Mx/3wFXR+QomKVuPOwGoF4cY47jUSPyn
         qdCTUoWMZ5JwMB5o28XzbU47yDKMPhNxhjZ1s4UNymVUAdky2BI4nMiai+Tjatg1qFSs
         MRazRzZEVwj0qO6Vx8dBBZy52yb9aE6SaMe/z7T92HjqZ01ZxRCATutyzz9chqd/Pbx6
         nykA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K5Kon1fyx96zs+S9bI+PC9J+wxhNv56hJEaz7FbSFSE=;
        b=JPHiA8LIJHBVNQqH3JfVlkOCJay94yqF0gABQ3WbJqc1E7In5+mpQI8pW1R12bnZp1
         78ayRPiBMohf04d3NlPAKkt0wbQZTiqU8cGjZwdguGRVRDleAQuy391U8p+HBzK/5uWr
         KuDQZmhWRSv4YR8gxx0IcnM4JZGbE0sLCLxymWVDGZAFlExmoa/8tHTgbii6N7XK74sx
         Pr4y0VXn8MmdnLySZ7k4WhMRmm7Hn8PURBr6aEDH9XT/v6VDb5FNwcRyB730Y+0du0Ak
         JutXaZayK+rtfDlANzz1xMftvh9PZ/z/LfOndn3OVoPbJ06z9ba/igVchsD7gNPG/BVV
         jRXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eazm9+k5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id l5si1686305iow.3.2022.01.24.00.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 00:25:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id g205so24336971oif.5
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 00:25:48 -0800 (PST)
X-Received: by 2002:a05:6808:a97:: with SMTP id q23mr606047oij.4.1643012748254;
 Mon, 24 Jan 2022 00:25:48 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com> <20220124025205.329752-4-liupeng256@huawei.com>
In-Reply-To: <20220124025205.329752-4-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 09:25:36 +0100
Message-ID: <CANpmjNNYG=izN12sqaB3dYbGmM=2yQ8gK=8_BMHkuoaKWMmYPw@mail.gmail.com>
Subject: Re: [PATCH RFC 3/3] kfence: Make test case compatible with run time
 set sample interval
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eazm9+k5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Mon, 24 Jan 2022 at 03:37, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The parameter kfence_sample_interval can be set via boot parameter
> and late shell command. However, KFENCE test case just use compile
> time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE test case
> not run as user desired. This patch will make KFENCE test case
> compatible with run-time-set sample interval.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> ---
>  include/linux/kfence.h  | 2 ++
>  mm/kfence/core.c        | 3 ++-
>  mm/kfence/kfence_test.c | 8 ++++----
>  3 files changed, 8 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index bf91b76b87ee..0fc913a7f017 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -19,6 +19,8 @@
>
>  extern bool kfence_enabled;
>  extern unsigned long kfence_num_objects;
> +extern unsigned long kfence_sample_interval;
> +
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
>   * address to metadata indices; effectively, the very first page serves as an
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 2301923182b8..e2fcae34cc84 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -50,7 +50,8 @@
>
>  bool kfence_enabled __read_mostly;
>
> -static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +EXPORT_SYMBOL(kfence_sample_interval); /* Export for test modules. */

While it would make some situations more convenient, I've wanted to
avoid exporting a new symbol just for the test. And in most cases it
only makes sense to run the test on a custom debug kernel.

Why do you need this?

Should you really need this, I suggest at least using
EXPORT_SYMBOL_GPL. Should you want it, you can resend this patch
standalone detached from the rest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNYG%3DizN12sqaB3dYbGmM%3D2yQ8gK%3D8_BMHkuoaKWMmYPw%40mail.gmail.com.
