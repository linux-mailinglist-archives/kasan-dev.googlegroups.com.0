Return-Path: <kasan-dev+bncBCMIZB7QWENRBNWC3T6AKGQEAXVOURY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CB712996B0
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 20:19:19 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id e8sf6776126qtp.18
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 12:19:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603739958; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQaiOrGnu7RwiXUyYcdPvm5wcts+5lhl7bxozRT5gHJatZ3ykwcly7XLZP8ufydCUR
         XTlqQUjRqlnzCsTtqCinI+RrzMtCnX7j8hbN/kReYg16o4ApVNUSKQzbEyYyYKO+vHGx
         unfyc8vI7GBrekNsDFmSJb/0i7ELCM7SfEkMD25GG+1RR4CvndX9ktQhvW+KlX2iNR5b
         QrQ/QhcCqormkxacTHSEcf8/iJs+6h4EjMeFLt7ZdEoGmF3UJVx6zEyu4gmGn4idNQt2
         CALaiypZgmO67bNFiZezPXsHXjcZjwU0ICdukh0oQ2NBDhRFtGqpITJyEQlUmvu7gUrX
         toMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pH82rcygvAOaoF2GAgsFduIM/V4MefNMzGtKUckW09Y=;
        b=sQFVHCSvsijnICH5XCMs1Xge3mWhsoKxrFV0Lep9ZzfUYeZEq8nXM+luKPSAGRJRKM
         Wt3WVwBveLjTr8nv3za6CiNd/omUOJcj1YDrr1D6r/R2tcj8pyDWQsgQmkcI/aIvIs98
         9wk92e/Nq/OMs0spN6F7ftdPmm8ISXAbrd7vmR88+ykSnU6z0JsFtNfP8e3mqr01X+0P
         bbmvB9T/LbmhJ0XAtujxgI2oW2OJSkhhPsXoFHaSrH1L3z+f2etdJT0ioAu6v2ChLImB
         +u1Su8K3nc37IHvI+VcuN9I4iMOkTb+LwJn158XGYhSHVjY933a6XxB6tpXeko43vP4l
         SH+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfHpHUuY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pH82rcygvAOaoF2GAgsFduIM/V4MefNMzGtKUckW09Y=;
        b=fN7gO0/hBIfBWZWze1N+Nf60Xi2ipm7KXE9H0oNN5aK+37VK5HP4NPzN+4oPLZ1759
         unZlGeYCP+tCu1z4V0QrpZwJ4CtzVmP8u5e7cB5NivYBHvGMN6euSLP903YxFesjpQlT
         DfMK1H9wpZNSuDNZkhD++fmyLTEpCeGL0yWhcKEcKtzagCMXgrWTV4cKj6yiTqlHMWaj
         wpOXNPrhnknka054mb58ztnmA6KevUh4NAzydP12na8q0F7ewgwprKaDWJ7wz7ZqXPxH
         DsnOKaoNCDIVHpgngE05YBKQPOBwSiVhUKVVX0Nmc7r8wj1wjXIQMqVpBAdDCmwEUXgs
         WRnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pH82rcygvAOaoF2GAgsFduIM/V4MefNMzGtKUckW09Y=;
        b=BZs72/yWGwx/nhd6E/S6MK/eA2e2EV5AgnF/ZdE1aFIigfTHluTihvkU98CraqWb9a
         nktJN+VYImrvmkhAQXCZxlQvPWlSsvOAAOMR6cVQH3hxrAX6D9GD7UtK9Gt9XaNZgag9
         MUVuOSxIh5jDJ/RH6a7k9G82vVEv/l2OLO+vWw2WX6I8uErCb3eduyabWLD34oMV9kwj
         I4+yXPBt56r33/4njnxPL61j+ZKZaMNISl3YZeCsIxSzfGEucBLHjU1b6eiR7A8vYgaD
         eP6py0/3E7K7mu9YNX6sOM5Xss3hWrOGSo/yypg9/fnkHjRH5ztL11HKegzi3N4XmzLY
         7DPg==
X-Gm-Message-State: AOAM530hfYyeeP5lIMwZ6s/cX4AqVfACMKvVNAE6FP/jjHCQBb77nlJ4
	g6T3+vVietJCunNMHBQairI=
X-Google-Smtp-Source: ABdhPJwiGx+kzGrlpTmNviuilrV1sifE1JuqBnhv9wxe70+5JujqhHGtWV0eZ6Z3xii48nvgqNudcg==
X-Received: by 2002:a37:6183:: with SMTP id v125mr19434870qkb.497.1603739958213;
        Mon, 26 Oct 2020 12:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4d0c:: with SMTP id l12ls2519708qvl.4.gmail; Mon, 26 Oct
 2020 12:19:17 -0700 (PDT)
X-Received: by 2002:a05:6214:a94:: with SMTP id ev20mr15493473qvb.4.1603739957765;
        Mon, 26 Oct 2020 12:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603739957; cv=none;
        d=google.com; s=arc-20160816;
        b=aJLWgCgVvigBUAz6KiJEYLi5h+9ee2t/iAe7Iiw4b/Y8Er+OQAAJbVfh59H6C42uk1
         blpLn7G0P3Uvjx3rPWayYb+130GyGy8iXmUQ1NC8GTu0BvUxhVrxhdEhM5FK8EtpA6/E
         iYN+RjoSSR6Hjr3/8LOm8KmbJFXPG9CRCtDQCibVdeAOLJ3ZiAA0Dx2+SF7ugZ54Fqaa
         Zge4FMsH18ZkJYzUMCBgLHWdlw6BkYwdKPYhX15ymvetizsv63vdBn/2uGhucwt1RDKR
         3Moo/BPFNaaphCH9vg/Tw4Tlt/ZAJsDYbdM6wkT2X3VX93GES2MeVZ8f+VFBLkRZsLSM
         rchQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1mArYS3UwiTyBp8u+wTdVR1EfclchgunOB5x/ndmscE=;
        b=VpI/BljaTsnCrU05/soyXMP6JEdwtkEpDNbOpICdiSKPMs0JeXq0q3n6nZaq6t2aze
         2A275Jh+nVVRPIKhrxxSiZKI5469h5obAuYweQyJEqSbrrNyuoeqImqx1tK9glBIIEaE
         PaCx25TbiJRxyNAu+bWuUwT/H0oYrpYwRQXLdwL79MMZ691TDN2t+Rbxx+j129zejsPL
         K2QJZXoLWpRCH3U4fqrFU92ovMscpOTscOMu0nM50McJqJefrO4IdzmcCTsYy3xVm16j
         akXmbn6GaBvE8VH/qVPkJvr1wyEcC+vTmVjfL8HtBpDy4QZTZt9PYEoBXNWFofTm+qnR
         pu9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfHpHUuY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id k26si482657qkg.6.2020.10.26.12.19.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 12:19:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id f5so4853463qvx.6
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 12:19:17 -0700 (PDT)
X-Received: by 2002:ad4:414d:: with SMTP id z13mr7762175qvp.37.1603739957099;
 Mon, 26 Oct 2020 12:19:17 -0700 (PDT)
MIME-Version: 1.0
References: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com>
In-Reply-To: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Oct 2020 20:19:06 +0100
Message-ID: <CACT4Y+aGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg@mail.gmail.com>
Subject: Re: How to change the quarantine size in Kasan?
To: Jidong Xiao <jidong.xiao@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QfHpHUuY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 26, 2020 at 5:30 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
>
> Hi,
>
> In asan, we can use the quarantine_size_mb parameter to change the quarantine size. Like this:
>
> ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
>
> I wonder how to change this quarantine size in KASAN? Do I need to change the kernel code in somewhere (mm/kasan/quarantine.c?) and recompile the kernel?

Hi Jidong,

Yes.

> Like I saw in mm/kasan/quarantine.c,
>
> #define QUARANTINE_PERCPU_SIZE (1 << 20)
>
> Does this mean for each CPU 2^20=1MB is reserved for the quarantine region?

Yes.

You may change QUARANTINE_PERCPU_SIZE and/or QUARANTINE_FRACTION:

#define QUARANTINE_FRACTION 32

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg%40mail.gmail.com.
