Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUPVWBAMGQECMA6BLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A170C338A95
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 11:52:22 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id z22sf7834102lfd.23
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 02:52:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615546342; cv=pass;
        d=google.com; s=arc-20160816;
        b=GKv0TxwE29Jb0EytF48j2k+oplZQ7li/ahh3jXn9FLJ6rcrjkueTWUhKD4t+6htjEn
         zsxH9UIsa1K3FYl4ZsldMnAxszKGZMG1LXBOrrXA3A4oWFmoKHJ2CnYWdoHKsvOB/w8c
         E61U89QwaThNwbed0yVXOAAiMXG987ecvXEsxFkma+DflWVVE30IhfA68GkgWueu4Tq8
         DJ+5z2n4JL9RnrrJ9QGYfk1L2tgGsGQ2SUvgaOzyWcif1XFFtjb5eJHSHhrwYyi/xgyI
         XXgAIXK69I64ORKtXOHzF0KBW3yzY8bxlHzkSEcq7VaGenIklfFsD9SE3gtDTzqVHl+5
         Wi+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=K3rIbuWZGVcH5/T2OJdI1iQFQh2ozlTKz+UkIAm71EM=;
        b=vuodzAcSRDGAlW+CeC1q1Salfs4cYSOjcYf19AaviC8CjPB8TYu0gstJHF+Hl6Lekg
         RJalDDxgaIIZTYi/Erh68kVv+fQpuGT/C5h2K4/gZoheZco8ws/N5CLniq3scyzD9OCM
         ElWZj4OqQ6GZDemjOo+Ve47XQqxjrvqonSzJkBr3djpSOuDujrhQ5MgpkpnSrvIVldWB
         GSX3eXkg1Z+/rBEFDeOKYtJWcOtQtgy14fWkJELhzytdc5zq33fAuCky2hYWY7kJ4fbs
         CoGGguw0IycHnJNcH1q9XWPwBT/md6ALTBDw4ia/laccGVbfghdA526eP3J9c7M7c3Mu
         JH1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdpaSkr1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=K3rIbuWZGVcH5/T2OJdI1iQFQh2ozlTKz+UkIAm71EM=;
        b=evAWl5q+QAhfjaiHLiWfIls8Sh2yMLXg+Y8HKPySFIm95wvNWe4/js7jvxHmM+w3+6
         f1YbFSb/YijmKiVNYY0FTEnBv3CMkWJtGtO1kEBMHURF8AP6yo3sANchertxN6pNGWAN
         rcrEL606r2uxcylK8QT6a76FyDzC+sQS4fLsjMDrMT4OPEOAAeT4v8cswct1ZkrkZw68
         fGjyzu7Cc0j4fLlC1qvspVph9OI1KeSkegoPHd7pVdu0DADzavImOzp1NCQRJTXuStv0
         o8Z5L7EUUdOU3PsRBNZLIKBB3z49uwf36KnBuwX+h7B2+URbifKNV0m9+Ug1FnZZAS7M
         M+UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K3rIbuWZGVcH5/T2OJdI1iQFQh2ozlTKz+UkIAm71EM=;
        b=rcgBQZ0Af/WUhPqTTJac8OkB28sb+6lnyGmoez1gmYX35P6wZrQ+ji9hqyUIgksj/d
         nuuH02AyVDaiCLUwTUw2FpzL5Mu359zW1Ctfx2BogOYQ3qRvsBqBGFbiHepmPkwmKBlR
         +Fp5LMY/dGvg6miVvB+NllK19RZhYTLodORV9O1Ez3uoHb6OSSElsDOOAvgsGgFcbgFV
         f5B3qgOHWrS/IiRyAfRay8KxEkyyQc58dfVRXZ4oOWo90bzpap5ABveC57vjvJB2w9a8
         SFWxaqbGhVK2CbyJ/GTQfGTUAxJQ952Qtd9qt6pj2qNC79ux+jPjUWr5wa8i3BFe+0mn
         brmg==
X-Gm-Message-State: AOAM533F2AyNT/Kxxa8QMr2JHOxQRkSBU7YVABarpw+/a2b5+YWDaUyo
	7jCZxfk355yVfFR5mDxPBSw=
X-Google-Smtp-Source: ABdhPJxZ4ZidF3TgrH27zo7Pgq/Vr+/f2J+es9789g+V8Brr/r8KMkC6tolmj8mMbI1R7Z0HpvaFuA==
X-Received: by 2002:ac2:5ec2:: with SMTP id d2mr5189339lfq.214.1615546342268;
        Fri, 12 Mar 2021 02:52:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3071243lfu.3.gmail; Fri,
 12 Mar 2021 02:52:21 -0800 (PST)
X-Received: by 2002:a05:6512:376f:: with SMTP id z15mr5177224lft.420.1615546341103;
        Fri, 12 Mar 2021 02:52:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615546341; cv=none;
        d=google.com; s=arc-20160816;
        b=XzqXShNSSKwCop3TSIePkGjbnGsMp2BcheLVmJNGBekyZ0GsnrO9XEdDljbq2Lttbt
         y54PqQIlfe0yychA9LHzdlZlAIEMDmXaOcJI5uzIwMtefOy96znBUIrx0cKKwpEthIYB
         oeBiqymTgZw0L00Hq8qMJ2GmWEAYK0ikDdE51MxxtgCIOUOPqkn1RL4dJ/wGetCUlCmj
         fG2szq+72eemeliGOCg5kPVvWi8CaOX3EFRgDEwkPedfISTpRFyXsbDRnCrZN5jxlsI+
         xx84SXiAtbM8H5S9RIr7hVuD951hCN4joXaldSkLkQKY3skdytQVBfRYnZ6B8KJfuqeT
         tvvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5vl4TnJGbtOwZE1EsiegxeOEN6L8oOxqwuScwUDj6dw=;
        b=agT0131lLMn0dUM3aP0h6XO6K/G556ahL+ie+DCYht0sNbv4kFaSUq44kkZmylh2eg
         AYm5OkLpe1v7Ek2O0EESLuxaKSan9JZ1uOb7nTgBbiaao6oU5E5bx+jQG8ijWw4qh0ir
         4bVi5xB5O+ccxMUS0tT32/9vTm21zsqCx/5rd4cfvBwoxjTa0BXTYBOme2T4wgUu/lXU
         +ITJTnwZt05wJTjTFE8o0Ms2YF/J2Z0Z6ont/SVEeMh6w0PQZVIKKyaWTTT3ERPrubgg
         3VFL4cOk1tb8JlKGCocLjD989ctQ0M5nZ7r4v80yRfscTqbiJWDfv0JYj+KxvQYWF/u3
         bgIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdpaSkr1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id j12si169892lfg.8.2021.03.12.02.52.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 02:52:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id d139-20020a1c1d910000b029010b895cb6f2so14899442wmd.5
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 02:52:21 -0800 (PST)
X-Received: by 2002:a05:600c:214d:: with SMTP id v13mr12602188wml.162.1615546340506;
        Fri, 12 Mar 2021 02:52:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id n186sm1707383wmn.22.2021.03.12.02.52.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 02:52:19 -0800 (PST)
Date: Fri, 12 Mar 2021 11:52:14 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 09/11] kasan: docs: update shadow memory section
Message-ID: <YEtH3oADQeTx1+bK@elver.google.com>
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <6cb4988a241f086be7e7df3eea79416a53377ade.1615498565.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6cb4988a241f086be7e7df3eea79416a53377ade.1615498565.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fdpaSkr1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
[...]
> -The kernel maps memory in a number of different parts of the address
> -space. This poses something of a problem for KASAN, which requires
> -that all addresses accessed by instrumented code have a valid shadow
> -region.
> -
> -The range of kernel virtual addresses is large: there is not enough
> -real memory to support a real shadow region for every address that
> -could be accessed by the kernel.
> +The kernel maps memory in several different parts of the address space.
> +The range of kernel virtual addresses is large: there is not enough real
> +memory to support a real shadow region for every address that could be
> +accessed by the kernel. Therefore, KASAN only maps real shadow for certain
> +parts of the address space.
>  
>  By default
>  ~~~~~~~~~~

While we're here, can we change this "By default" heading which seems
wrong -- the paragraph starts with "By default, ..." as well.

Perhaps "Default Behaviour"?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEtH3oADQeTx1%2BbK%40elver.google.com.
