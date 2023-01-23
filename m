Return-Path: <kasan-dev+bncBDW2JDUY5AORBT7TXKPAMGQE6KSS6XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 50AAA678217
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 17:46:09 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-4cddba76f55sf126628607b3.23
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 08:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674492368; cv=pass;
        d=google.com; s=arc-20160816;
        b=fIDHC6tIW4fLfKQRWAg25ZFKg++e7IE4KTvKQ/7UdaJpz8BMCUbB/LbxlgnQKdHrwS
         jYNnxHNB1Bli3MPj4mh0WT+Wfn6aur7Ye21eC30+JyQA1oXOOjBPAYnR9YV26LFs6688
         wv3yHfCG5MwUE644ePPUwckmNnzp1EFhCUhM5xguV0v6w3rTGd0rbnbcZA4GFTM+0pRI
         pnyI/0/ibHESbEZvnV3uSuwZN6fUd/VG4N6i3nbJHEdzaPqYV7ZkXtzGmJulI3Csyoxu
         fv5aMsoJ9m88R1iozL281bTteM9hNeEkP8rCg1c/+NEwEnGJEQG5qpuKSRDiALT97LL7
         WpUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=XAArbhYiYKV7cqN3MDoGJ6KprUbcBlICemCP2y18lqg=;
        b=ONc8q8+iAOnzgDi/E2Lf9EIkh53yphtmtacdDjy9+Xk6/KXDC9UcthIj46pn2YFJ4u
         xA5IXURMHcF9DVYAJkpxW5NkZxiYIlc9GO214up0FmQqG+bzmsANQl2PxdsJrpaSTNYQ
         HzvH6EmTm6jyhbw4ssMU600hiMpu5Kd40mRmcVdQCI8/MJYEzxuOaMzGOA+VjMHib1Ej
         sJ3rPeobP6jYHta92tASlzYVvgYpInIS0ytvSmfrS3wvijffjqvyMIIJnIy5LjsW9Q6P
         4MWO79LsF61em2sqiXVdjNjor1NQrHWDW1ZFiLvyi+LaD2Nw90NYCWcJ8lYl9EdlgimZ
         qUrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FkGh1e+e;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XAArbhYiYKV7cqN3MDoGJ6KprUbcBlICemCP2y18lqg=;
        b=MVyhLLWi/c1zUdjlHvtxtkzcRNNRaXN50CLdnUAMwhGnG6SM8ovaquhLJZpzWVX2Bw
         Hnryt0MagJSz9SLVZzpqpqofxIXKwa7rjUMSPFCNHZ6WeiI7Z2D0XNfrhcscNQP6tiIP
         0LpG+Ezjma6RRCElS3JKVA4ioMBs7HfCF4XHQXO7H71sD7KddGYJSZDbl3CMbnFnzfIK
         mnPOc5CymMprMcScbiCUIfwUckb6badudodJtyxOkr7NF9Kblk//xcAvr2PE90esHO6r
         3GXxBBAlVh/HB2AHBBXF/jL82nMr28JyI+JWTwrqzjLiPQ2EJA5kE0WMBMRbfFKMjI0M
         UxKw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=XAArbhYiYKV7cqN3MDoGJ6KprUbcBlICemCP2y18lqg=;
        b=e4Jp0CgGcakrEZkhZ9nsAtWm8H1GGa/ftBPqay/JrHofGXDFz1r8g0pkl87ajcXSXW
         DTuoxcBBSBGGG7abmGoYmopiWItgWBd4tjS1Si6kBpwTj/MsksVevRvHuw3ASZfIqVIc
         vU8MKOvqIx3ytPDqA4LwHZ58yvRwmUXd9jus53tfNnPpqi5zyZs831K9MlXwIfajYuFW
         atpxbP7d8wyG1mZg9J3MtIbZ8mRuolvg88Kg1OeS8XHN2vnj2OGF9ihkXTTd+TZJZ/JV
         RtD7qTEGej20Oin+8fqqYHTf9sO2psSHc+aO7DL2ZUEljB08TuMUWZQgNztECRts2ACG
         KQYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XAArbhYiYKV7cqN3MDoGJ6KprUbcBlICemCP2y18lqg=;
        b=4rP94azruSKzzMP9JsgZjUN9m+lo64C6pjucnWo9D8dICh6Z/yQvXKzOCGf1MfNEjY
         UyKg+a9q7+7MMC0NVZz6ks3nM8ApVI8NSVQSog8A/KQkqWRJlNUF2AsNMSy5kEkGVKfm
         hxjNUTNEvZRQGPyeEg4Ng1ABXqyWjBjfaBqlvTtQaJ6DVOzeLWc4a0zXlSbyXbq6f9xo
         bRIrOAbrlCUkoc71Vewqevk6aCTYUmnrv61mc+rP8HFmqINHDGKaunFLIp9WQ4SIWwzl
         nLQYNItNOu0XJr99qFmygN2uIswEFGkRV4cCBoyb+NzUcrJo2d9xSE3hTQ0e7duhsEho
         UuEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp8TE7kLZ0JRkG6ZOanNXtjN6i59SiYfAwrPOw54W/8jRsDmoAs
	oKtcKzrUAvVmnkyZF0FNfvc=
X-Google-Smtp-Source: AMrXdXthuc5vullhc+AdEWATJrG0moNB2hM06eHyB4c3pxvS3f2ZXho2IGgo3XMhfjeyUJNKfpGYDw==
X-Received: by 2002:a25:bec6:0:b0:7be:e902:e9f8 with SMTP id k6-20020a25bec6000000b007bee902e9f8mr1924999ybm.43.1674492368055;
        Mon, 23 Jan 2023 08:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e083:0:b0:4db:64cf:49dd with SMTP id j125-20020a0de083000000b004db64cf49ddls6700904ywe.6.-pod-prod-gmail;
 Mon, 23 Jan 2023 08:46:07 -0800 (PST)
X-Received: by 2002:a0d:eb07:0:b0:502:a740:bd77 with SMTP id u7-20020a0deb07000000b00502a740bd77mr6107737ywe.9.1674492367586;
        Mon, 23 Jan 2023 08:46:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674492367; cv=none;
        d=google.com; s=arc-20160816;
        b=l6XiKrF31zYpuNnBj6Hsd0QbcDiSn6Uo97FWn09yn6AyFuLuyMOJgm8eIoi9gC6yJt
         VwG8M35H96ND10/tnYdi4Iporkn3hx596NxrCw7SBb0Vlhk6LQvbVh3MYC7wYQfr58D5
         5KwX3SsrAvCzrY/zALxVay9dIWRQ1oSUBbJP7eG6hLv/B766pITf09tfvUr79+QBSu51
         vDmUdz8p6xkd8wHmkEWLiD8/YVmCS9k8vZTbhe8fm+PcpaDiEBsxSnLG9TjbRiQsuYhY
         YO292iwA+M/jn4vQj9EeJ8NBIEaXAtr7PSir4QqK2wCW6sAJ3jWJyspLSgXwig0yDePz
         aDIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vWGUNu0aGu5ZM4nyV44fizskyQNi5DbrMxpX2Ig+Ym0=;
        b=spEazYzhKZD+LXV4DGA54Vnd6VjPRagwcyIjAnKbPoTel0gifXgpJAhe5tNJBS7ypO
         5YP26+r4lHNkPb152pxkgRHJOghllJI6RxLU0RIiNtRL99f/YPfhrkFk/WMjq4ChjhcX
         ZJ5MxBEYaLOveyubYCMBNmWBQjKfBZ9Mmh0LKSmzatrg7ZSa/JeoMMtFkOQgwVfZrVmR
         Etf3iS+oSTxNr9WQH++Kh5BHKepT7ZSb6EKuxa95/shhA+1fV0aM90Xe5di7pOx7301u
         59c8h2EyJrfNTF9MCC2yihtbquRDuRfejgkz5+PXpDD1xke0RK/h8BK87BPIcXe5VYwj
         kf0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FkGh1e+e;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id bw24-20020a05690c079800b004e082b60c9dsi2681554ywb.3.2023.01.23.08.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 08:46:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id 200so9249569pfx.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 08:46:07 -0800 (PST)
X-Received: by 2002:aa7:8046:0:b0:58d:b5d2:fce1 with SMTP id
 y6-20020aa78046000000b0058db5d2fce1mr2622294pfm.21.1674492366745; Mon, 23 Jan
 2023 08:46:06 -0800 (PST)
MIME-Version: 1.0
References: <20230117163543.1049025-1-jannh@google.com>
In-Reply-To: <20230117163543.1049025-1-jannh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Jan 2023 17:45:55 +0100
Message-ID: <CA+fCnZfTrxvmQqVd5zo8jo3JY5YqpvQJGx=PSuUvzb8J+KNG3Q@mail.gmail.com>
Subject: Re: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, Andy Lutomirski <luto@kernel.org>, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=FkGh1e+e;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 17, 2023 at 5:35 PM Jann Horn <jannh@google.com> wrote:
>
> KASAN (except in HW_TAGS mode) tracks memory state based on virtual
> addresses. The mappings of kernel stack pages in the linear mapping are
> currently marked as fully accessible.
> Since stack corruption issues can cause some very gnarly errors, let's be
> extra careful and tell KASAN to forbid accesses to stack memory through the
> linear mapping.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> I wrote this after seeing
> https://lore.kernel.org/all/Y8W5rjKdZ9erIF14@casper.infradead.org/
> and wondering about possible ways that this kind of stack corruption
> could be sneaking past KASAN.
> That's proooobably not the explanation, but still...

Hi Jann,

if you decide to keep KASAN poisoning after addressing Dmitry's
comments, please add a KASAN KUnit test for this.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfTrxvmQqVd5zo8jo3JY5YqpvQJGx%3DPSuUvzb8J%2BKNG3Q%40mail.gmail.com.
