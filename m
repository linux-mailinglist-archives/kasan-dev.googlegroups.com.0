Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VO7GCAMGQEPNTDKCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3C033807CA
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 12:56:43 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id g10-20020ab039ca0000b02901f7b6d6a473sf5369892uaw.17
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 03:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620989802; cv=pass;
        d=google.com; s=arc-20160816;
        b=ltDtXEU3pQpaRxfvNCDS4p1kEA4ow34ZTnbLXqO7ly4PAEmsJNfSNlzDmNTxv0ikmz
         5FGqZtcS/6JnoaXvKNx+lbP7H/VDUs6PbtCUH+YrIGxkjOr4rqw0sroQEcauJVPAKF6I
         L9F/K+ZG0IPjT82wAG5tbTjXZ1hLKkqr32QVXsF90S540od4XStXiRegABvOrAFh/iRo
         ThTs4dd1YrHdrSOxWHEABP5dgqkRbdllgDrJZevwz5R3pkwLX6AyGo7VGiJjB4/XP4xR
         nezbFtny0NJlIV1g0J39ChAIR7EXw4kckcV7BD8IfEiepD3+t/qzqj6c0uqGsLWyZe6b
         rOsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PNOY7q4Dj0wxRaTxKXhnuCTirsxDAgOKnFdhi0voSrw=;
        b=kppmlKCfD1gf4pEhm1LypG/jspWwrHvtGIdLwfIpkbxLZRs+q4L23NH8przqTC6BKR
         h42bKLC6iloxq3vf7tTCT+E8ElcI6g7WDQvLX6waGYwcFL/o+k42G3LbWijNmWzgiN5v
         z0zGPIXbFUMrjNQheoiwME/p0wvYhfL5Nx3Ca9W8TqTkieCLoHwPrxQm6k2fzGIQ3DEe
         4omdLei4f/fEJhWGtcWM8z6cHgBW0HUWbjy/xhC4Lo2KIc1Uknxdnzaa70lrg0dW76u7
         flfo+G2Is+ZtNMYCJ+hI7OHN8SQ1QxkPuWFPN6kSOb3VDxh0GiVbD+m6RaTlO7xE3d3l
         N2VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A1kyzqpG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PNOY7q4Dj0wxRaTxKXhnuCTirsxDAgOKnFdhi0voSrw=;
        b=G9JQsnN0LyPxXGlMvRSEch8BrZDLkYd56lYT0nKDH4moKX0rPMLFGbi5kx9WqX+1hn
         bsMXDF+MNrJORrYJ5YYCjCOaTZuG+2iWC1yIBdDxUEt7ckZl1+AgI5PYB7HxvApZ8jOw
         4BR9Q6x7KPUqP5c1JymDFC63NSnhVQapMRc5tnGkzOOv1N4ktjqis+6EQe/f8y8A0mwa
         rbycjIssRen63Rs2NQByJK5+c5STefttgZuJqRxzGw0pmMrRxAAdwh2LWKv9Y2vLHLHc
         3q5+kRhFfkixVZOl7IPiuRJ7BNqGSegNMfipOsTvTxQjuYT9G3Pb+MrIEn5lwNWE1Hlo
         tWEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PNOY7q4Dj0wxRaTxKXhnuCTirsxDAgOKnFdhi0voSrw=;
        b=IhqbqqZUdGuhXK0ayEjEHV+j+sN6CWuTlwo1U+Qs10aGKZDlYVDaFvuOSTbI5uaBfy
         Q5JrnidZqkjREA91gbs1450YBhbDz017TQRU+3/poqXy9ryk5/QqbNuSDe0kd1SRQ2KD
         2uPrpZLUiBBQBT/8is/UFJFnkmeCbsE2xvX8hjAKXMRMJtd4GWFQcq0f5Uq1QSHQTHvV
         fIgw5MZgtq32SGFWYmM8vEO/voM7cDw800oPUpF1VcUxD8V5G9qoWukh9bcyqTQ0dAHt
         d4OHkVThp4Stn/xBNQ/XQVhsWLAQQplmN5z4iyrwJmLYYVCPupSdg4vizNnHj2F5MIOJ
         y29Q==
X-Gm-Message-State: AOAM533OnuIwZHOwFZ8UnO8KfvgH8t/FO/BqZRWGRPRqraXK7XPUEJsg
	hQm1x2lF9OlrFe263Vrjuoo=
X-Google-Smtp-Source: ABdhPJxGZApt7zNT6ecAi9qrNOEDn6/+S7AY/k92P9S2QwMCljtGsYyabvqrVFLDADmqR0m6AfBz2Q==
X-Received: by 2002:a67:cd1a:: with SMTP id u26mr40778943vsl.58.1620989802697;
        Fri, 14 May 2021 03:56:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f7c7:: with SMTP id a7ls1842446vsp.5.gmail; Fri, 14 May
 2021 03:56:42 -0700 (PDT)
X-Received: by 2002:a67:c904:: with SMTP id w4mr28446056vsk.48.1620989802226;
        Fri, 14 May 2021 03:56:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620989802; cv=none;
        d=google.com; s=arc-20160816;
        b=BGVsJ7h1raK9YMUJTDrJcPxUOBf6/iM9mZPIqOpAGaOd94uZNZIQXo4vnJfZwXja2M
         WLR7Bh7wZg+eLso33WtnCxVtQR2x76ntLcLV4SnFNOgp1rLhBZPc6jYqJZWDMrJ8G3+7
         S4833x4yEsf92ZRBg6DqQXm9Oi0Vj93YVdpXJRGysZzP/EBS7FIqrWUmuOYdzlwlMGxT
         WM2jCop6RMRJwxqdxGNEzOtvSV1CBu4c5ygmh63F0jzilZMjZRduZ1bpsNJhY9o3k5cy
         BYH7cCA/oWmJMKtJBpWFCGB1pHCCvzOFD+YqPJi/JE/Rwk554BmJa+TB31i46pWtFoIJ
         Q58w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ydhimE0ShUzHe5UlupIsgatmNxglV8e9FXvQTc9zlwI=;
        b=Dq30ZG8r07i4SLeFJlBc+6lA2ROX8bo6tJp7G+jLSoD2qZ0nhXVhjBrwpMvwX0tMhd
         9UsvNFf6ZLPd9LEaPHfVSxkeJeR1/C6aCYuGh/+B2xQsGb0li6kJ+qfngKVuYSdJHuEU
         dvzJPto38D3tZZ7pUcL4F6LucYXqRvnR+bgyUmo/R87PoS0mQPJ79zrZ4ZDbIqJzrSwM
         87Ycvh+ARH2yktv1XZFiou9+TsOA4bECGPHmvCM8Lr/OhydJBruDHvX8FXdmGem1eGVe
         wKPPruChUxgy1IdJ3FEP94d5L7eCKBq7wBLeaMJMlQ7hhxV5mwXqVqDpHbPzbpGFW6SN
         eEbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A1kyzqpG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id u15si355159vsi.0.2021.05.14.03.56.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 03:56:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id n184so28050642oia.12
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 03:56:42 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr34058523oia.70.1620989801557;
 Fri, 14 May 2021 03:56:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210514092139.3225509-1-svens@linux.ibm.com>
In-Reply-To: <20210514092139.3225509-1-svens@linux.ibm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 May 2021 12:56:30 +0200
Message-ID: <CANpmjNMViC4thxCESfmj8j1ZWvNsz2oPSraPta3BAUQjFBoDtw@mail.gmail.com>
Subject: Re: [RFC] minor kfence patches
To: Sven Schnelle <svens@linux.ibm.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A1kyzqpG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Fri, 14 May 2021 at 11:21, Sven Schnelle <svens@linux.ibm.com> wrote:
>
> i'm currently looking into adding support for KFENCE to the s390
> architecture. So far everything is straightforward, and i get the
> kfence testsuite to pass, which is good! :)

Nice to see KFENCE being added to more architectures.

> One minor thing i encountered is that for a translation exception,
> s390 only reports the page address, but not the complete address. I
> worked around that by adding a function to kfence which allows to mask
> out certain bits during unit testing. I wonder whether that should be a
> weak function that can be implemented by architectures if required, some
> kconfig option, or some other way?

I've commented on the other patches.


Thanks,
-- Marco

> The other thing is that s390 (and some other architectures) has different
> address spaces for kernel and user space, so the decision whether an
> address belongs to user or kernel space cannot be made by just looking
> at the address. I added a small if (user_mode(regs)) check to
> kfence_handle_page_fault(). But this could of also be done in the
> architecture specific code.
>
> What do you think?
>
> Thanks,
> Sven
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMViC4thxCESfmj8j1ZWvNsz2oPSraPta3BAUQjFBoDtw%40mail.gmail.com.
