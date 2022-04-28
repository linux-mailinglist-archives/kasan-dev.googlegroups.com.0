Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGMJVOJQMGQEGUBPAJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AC85513A43
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:45:14 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id v14-20020a056e020f8e00b002caa6a5d918sf2083652ilo.15
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:45:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651164313; cv=pass;
        d=google.com; s=arc-20160816;
        b=NuMjpmCTj6iwVabsWojjrVfoxvdDdIIGpNm0+tyj0MCpIF9Mi38VMSNsHjQQ+qxYxU
         rvltT//pZ94eMvD5vym1fobZnYLVNS9OkWkdfZlQ3d4egdrhPefPnkjPCJMqmznXaK0t
         ucUbBX6pZRk4p4skGoOgZupLPu9Ry39X5+NBjbtIdS+Gae4GwriCjFJcguy0nH0avMLZ
         eBONGTFYahv80Mxaql1SLUODU08iIWUEa1WLB20Il+hxd7PCnF9WNLSUiLCmSyWR4NX0
         U3CiRIwau6j0IDg/96wIGx9uDFw3Ic6AF3KZQN+K203Xel6bWbQ0Sxfcomt8spYBNAxX
         p06Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vVC7noCSO7+JM+AGZdA4Ic8ylKXzEezp/L0gTHy9UVk=;
        b=KDEOBCJinWL24/t30PXRQ6LzGAEASkfi7t1+GLaBcrSVu3pxwt+3IkrVP+aCNJZvEj
         OVuMtlxRUX9QX4+kZSJYkcg+egFB+ldwfePxELp9/WqnkykZJVXNmS0OC4hUkonnC1L8
         xVNbbAmZEGr2LcnFFzVUuLv1hoHKkogkJ/fSdWW606UwdaF9PMDDiEqaS1qDm/sytnUU
         b/h03xeqpggtZoVQsy8nDkWOK4TkkmdYFOBrD7ikPz4GQq4S+VTulSkKSTxfWBIfwTuH
         NfcLg2eXr+1C1R7ZtkmaXb5FKZJlaTFIMgOspcZUpl06Ni/G9PkBTJsp4ICCQTjkb/YV
         z5Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YO0d6jn5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vVC7noCSO7+JM+AGZdA4Ic8ylKXzEezp/L0gTHy9UVk=;
        b=pAx+IudwKz/EOJZbjyWDL1A4oKwOoB79vNJrUJMnSayhRbxj4DUsvJPIwh8ZfPjZnD
         qlO5wOe3U90Fe5p5rH/VEy6nBNYGo4P7h3bhKjmL+82NO8/hTgpR+PMtCIeMl0idPzIO
         1nfecS913S2md/0XAue83QyenmNe5Aqw0RbULkU6RL0sWrMYKY66wH1WylkYZLhZVahY
         P6MjvslcicHZoYgzBA0X/zLuHrX4V4Y00OJwRZYxYTkET9dQfDhrLLg4monsg5YJUN4m
         BHLf9fy2HvKj4164rOEADIlT1fyYc0UDgPtHnwv2Yxf551TG8xL4+UpCsqhmPba2AuSe
         0Ghw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vVC7noCSO7+JM+AGZdA4Ic8ylKXzEezp/L0gTHy9UVk=;
        b=EzgAKnvZcR90bL0eoM4Y7F4/h+XM/1upMb+QntKpepDPfkFk1mxFeUXAXUuRMeOHbT
         EWKAE99NqNyNIOT0uLLvKvezWDH0DleBiZTCpkACt6Z2KeFhmWUTxdLWDv5D3bIurQaN
         MaIXy9TN/KvS0IAq0nqW48p5S86EvlK6nKoY6KX2FZWi1tsX4wSV50wKMBlXovlVo78h
         rIwuziytmXQZzvR0rzMriBijnzJAbEOTwyCSaoJzEJnhdbrkgE4ezVJJV9joz0/2R/6A
         esIvOJJ18TATVqa2eHZZn2RTaHG1sAOtMreBEJa5BXufzFXuR7FQ6YxXrbAajvMtnZoe
         w7hg==
X-Gm-Message-State: AOAM532Gez/oXBNueNsER6hG8fnWdT3TwOIwns7syTwyQHmmkK4YpNF0
	kMpV+f6GI9hQ1bFa2y+zLTo=
X-Google-Smtp-Source: ABdhPJzd/q22mthZtXcGAxXVJRuhEkwJREiXjf1vglGIkFIxtwzqc9EQfrJ1JmJ6Yyo6xhDFnjAkEA==
X-Received: by 2002:a05:6e02:1c2d:b0:2cd:7ada:ae3e with SMTP id m13-20020a056e021c2d00b002cd7adaae3emr11807094ilh.176.1651164313187;
        Thu, 28 Apr 2022 09:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:190e:b0:2cc:2a1c:9028 with SMTP id
 w14-20020a056e02190e00b002cc2a1c9028ls89873ilu.9.gmail; Thu, 28 Apr 2022
 09:45:12 -0700 (PDT)
X-Received: by 2002:a92:ab04:0:b0:2c7:aa89:d17e with SMTP id v4-20020a92ab04000000b002c7aa89d17emr13943875ilh.108.1651164312692;
        Thu, 28 Apr 2022 09:45:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651164312; cv=none;
        d=google.com; s=arc-20160816;
        b=pqJXLI/qheJEa+pNMvi3qlA3kd4GmB7UGL7K0B/IVrsOGxHiC+t3VIbeJxp4+Ifuq8
         vdfP4sCKzsKAXFlnZF8hTh0ufH/Edy95p1KNwww1ncT8rDwO42pfx0B0R/dAugF/K2cU
         Gy6SxJFeaETyiSTbmV6UbAZ9vJ7pf+teBhx/R7MCySVkuDDhjpzmb35pjB1BnD79sCHt
         6rrMjtE2ZNF/akeBgiAkVC9dIf0aURjPEsTFKCQHvzEsnzE7cUsCtzdKFfU5vPulLcYP
         3PizoP6Iph/t3sqT4Y7UYYw+ol7xp3oqkD+M0o2zq5Zc5m24iR9Czy23R9OUpK1Qbv7b
         oZtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fknn/A/aplgNNNjRdKgmyiKBYINuUEGbLWPpyif/20A=;
        b=wMac4nN0XkM+ekX6lhBiVcpapNYPLqAY9QkQDmXsbdaZle0TASIh+OfoxGmGB98KqH
         vAbmBZ9Zc6AyCYcvMvoYF7LfWWEGmBPxf+klsjP5XS/1gsIsXReZljtslqoncfDvm1UT
         AnzU47rYrKChySISkbO6+LcK9y298je63P3Qfscdg3Zn6lZ3zPUyqPH9JPJECcANAfcR
         HkgcyO5BhryioEJb+B3LnYB3UvyQQa5KhpeQbiuV15fF8XX2lyFERJQnDW/4ybiNQqjM
         RNusAjiRC0kNn0DiR4uaEQjMK01XC9DiHBh2dJBqKQ78A4H8Exz6kiYOPqghIrwh3Vjh
         jFOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YO0d6jn5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id i65-20020a6bb844000000b00652f6c18b70si353700iof.0.2022.04.28.09.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Apr 2022 09:45:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-2f7b815ac06so59629697b3.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Apr 2022 09:45:12 -0700 (PDT)
X-Received: by 2002:a0d:d615:0:b0:2f7:cdc9:21c0 with SMTP id
 y21-20020a0dd615000000b002f7cdc921c0mr25441432ywd.486.1651164312085; Thu, 28
 Apr 2022 09:45:12 -0700 (PDT)
MIME-Version: 1.0
References: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
 <c4105419650a2a8d9f153f55b5e76f4daa428297.1651162840.git.andreyknvl@google.com>
In-Reply-To: <c4105419650a2a8d9f153f55b5e76f4daa428297.1651162840.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Apr 2022 18:44:36 +0200
Message-ID: <CAG_fn=Vy+GuQ0YCCvU1i2fwO35ZWbE3MqK9if6+iX4q5_3mTRA@mail.gmail.com>
Subject: Re: [PATCH 3/3] kasan: give better names to shadow values
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YO0d6jn5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Apr 28, 2022 at 6:22 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Rename KASAN_KMALLOC_* shadow values to KASAN_SLAB_*, as they are used
> for all slab allocations, not only for kmalloc.
>
> Also rename KASAN_FREE_PAGE to KASAN_PAGE_FREE to be consistent with
> KASAN_PAGE_REDZONE and KASAN_SLAB_FREE.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVy%2BGuQ0YCCvU1i2fwO35ZWbE3MqK9if6%2BiX4q5_3mTRA%40mail.gmail.com.
