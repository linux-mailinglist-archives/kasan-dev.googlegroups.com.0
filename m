Return-Path: <kasan-dev+bncBCMIZB7QWENRBJ64WTVQKGQEYFWCKHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 46C4DA59F6
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 16:58:49 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id t24sf1604179pfe.23
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 07:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567436328; cv=pass;
        d=google.com; s=arc-20160816;
        b=qu0oXlDtEBNI6mnzrAt64NLG8tLts5jod/9qaL6sjpflBLmPg4ryToNLg9Y2bWziAN
         vhZrCTLbVeIjHHjmZb1lzGF7LDVHMleni/rkilrGKdN1/Ykq5eHFMI5fEHWiguK8GMtP
         ZxHWXf9lajGCmhcpwsKjPpKBGrPWOEuBGh5JTLNwMvVhsjJyJxTk92owm3TuvbVrtwum
         776o1uWKNYnbRE93qFt6BXk8isCwh9UpxGnS9+F/+neum3BPHg4NuI2xNKfmOUvqI3iY
         wVJv5Bo5BrT5Z6KhgrKyeV7Aohzqx5Hjrtq6wpTbiLaMAqkGtkpVJ4KJCgU+A+dAIdcD
         78gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sJ1zGUvyeqPma6xmG48f+fGmdHLdZGsxCsRZ3iO1N1g=;
        b=oDpPNLsaOj2G1KaSZGo5xXaAdyGEARtBmdbC59ISe/Yma+nGLJ29sx/AlO+uNcs1mi
         dlNjYkjrnhvzFtPC4G4zVN9JrVizTep2rsn5zl5ovgQb3ghe+dk5iuNhI91GpZpMVDy2
         rFABkHv1WsUCKqZjHexfXelMPY6LiHeRZsy3xXdCQdlLEXHd7sTzhkqxapPL4UQAklzX
         gvmuAtUB5FkrLHymd0blW6gdFVR+T8Ge/X71rY6JRPUlUl5EiRN4bRp2DCYgfgt2rkD/
         fb3/sHPB0dMuPAHKEk3YrPRH9rlArToqJOdb7dS0TPuHBM/s58F66Dpyw2l8rqgAZmyJ
         2ryw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXYq647f;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJ1zGUvyeqPma6xmG48f+fGmdHLdZGsxCsRZ3iO1N1g=;
        b=kS9amn/lQ0XbRCOb7/cHKVNvmfb3Rdbuw+eOI0EdwGt4NiUPKTTULnapOF35usZTka
         /r9rAjSaD1S/CKASN9A7stoea5EzbD84LcD6Ypyd40gYcZ0mVAkUIWa29RPjUm6QjFk8
         2fTizLPzgihSd5inrQykYqlS4z/O/5k3RooCyHqebp0/Ls+7ZFL/NNL/tCFMgiP0u8Sw
         ARtqFRN9CGVPjlHDBohn7A7TnPkw4vtaInGDpNXXoXEcp2VKZBVBzxOQce3Eiw5aTR4D
         bv9rkhDZI0/ApvDj7Xj28xfVAnSkDdR/yqDJZY44FFUI0XvhlZY7tmWfnNg4PSD1RX7r
         xk3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJ1zGUvyeqPma6xmG48f+fGmdHLdZGsxCsRZ3iO1N1g=;
        b=Xesf11mJRn3E+abKbQTWEehK6OdWWmBTtLsf2PrTMAWwZsbtzONkTrc6FcweM+A+W0
         oYe2fMDPq6BGMqWAqS2QT7I/0WOLfxS3V1SStcBoI+X3dG7kokj62xLWFwdOFQAWYOZb
         Fo4rL8xiCzBhlNfWaoT//I3MSe13xxHGEYgiMbCBuzJj/ZKMdMxjwdDW7oSt48zT06Wi
         IGMF6jSz7ERAcnUiYAqGd5ppSlJDNat6AfyHV6eJmAJ2XIdPl6ra4rtFa6zJnZBBK+6Q
         TacM2HDRdyjZ2MYnfQMZJOTvKK2KgvXKCOIK6In+CKqc2pEJvYA+DvFeMXJAdFc4KQxY
         caQQ==
X-Gm-Message-State: APjAAAVDxXJXabH3nhpqbi74uRENUZXWyZVANSEFJ3LWyblv7MS/SN0T
	l06pdEhU+azcNtNkRs0oiXU=
X-Google-Smtp-Source: APXvYqyRjY4oBKx+AMb85+9z79EVBNDueUDyOyx8EjG7+/0g4xHCmo+QOSoM9x08tnwwh1MviwF01Q==
X-Received: by 2002:a63:b346:: with SMTP id x6mr25918076pgt.218.1567436327945;
        Mon, 02 Sep 2019 07:58:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a705:: with SMTP id w5ls4638965plq.7.gmail; Mon, 02
 Sep 2019 07:58:47 -0700 (PDT)
X-Received: by 2002:a17:902:b08f:: with SMTP id p15mr6561278plr.49.1567436327660;
        Mon, 02 Sep 2019 07:58:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567436327; cv=none;
        d=google.com; s=arc-20160816;
        b=m1amrtSrjzCAS5XqPi0wKr7GS0cwV3JcW0Nv91GNryTNyYoZv5t+v1VMK/nNL/f+3n
         1XnMCeH6PRFYVhCtjtLnQFrsZre+MOTDiIe/V8j4c1y1FRzA9wXFbt2KKT5u/dl62LBw
         Nty8I4p47SF0WipG6BCNEiMcTqS5p6Ja4syBEMHLDu4hSstjKsjEM07MtJ9vKBjeOLTk
         f+Sj1z5Z+BwZuDJF3EtQmZTzoCk0i+um0qB4ti/+tOb5+r6yJ2dxoeijz+ppuxaXtjIg
         FReIKwGWo2cAZJTLXNytg8J6ReghnTKusqhb7IIV3as/U7pGPWssUxwGd75NcxmnsjCC
         wa9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HDZet+RQLzoR5GcyKX4FRuQnx1nkwBVCACEOzTiAoCo=;
        b=IOlzxyCQn1IvaT6YmI+wAXM2sXPYnVOJxqecVZUIBXJSJqDRojgZ5An8Q/EaOskyHy
         gCa/uIdPTyWPE8HBbMe6t4QF4ZyUUcICuslp8PladsOEFWkpEk4xHDbQandgVR/KQ4kk
         o5F9r/A1xRvGQQGYojrpNTo7Uf1hxUnMyGNbj1OFNji2lNaiW4mYVNovLFCeRnA79R/V
         FoaYKnZBm0tP7rG94N7bv1HnME/duEaeUiIH6w/5eE1Os4NcqzVzIoerzyzc5/mpvsau
         ZNZnDOG3ss65W+05inWllh+3WMupXELQHJOmTRLwamR4tqZBlr3kF3G5K2hHMYYZZ8IX
         aqNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXYq647f;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id x2si927468pfq.3.2019.09.02.07.58.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 07:58:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id j15so15819506qtl.13
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 07:58:47 -0700 (PDT)
X-Received: by 2002:ac8:424e:: with SMTP id r14mr28515975qtm.158.1567436326820;
 Mon, 02 Sep 2019 07:58:46 -0700 (PDT)
MIME-Version: 1.0
References: <20190902145310.GD2431@bombadil.infradead.org>
In-Reply-To: <20190902145310.GD2431@bombadil.infradead.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Sep 2019 16:58:35 +0200
Message-ID: <CACT4Y+Zi0L3OL0AtrBH4Sq8zoYVFFvsar-fqXZ4p0bE+bouUeA@mail.gmail.com>
Subject: Re: Better stack traces for RCU-delayed freeing
To: Matthew Wilcox <willy@infradead.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XXYq647f;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Mon, Sep 2, 2019 at 4:53 PM Matthew Wilcox <willy@infradead.org> wrote:
>
> This is from a syzbot report of use-after-free:
>
> Freed by task 26359:
>  save_stack+0x23/0x90 mm/kasan/common.c:69
>  set_track mm/kasan/common.c:77 [inline]
>  __kasan_slab_free+0x102/0x150 mm/kasan/common.c:455
>  kasan_slab_free+0xe/0x10 mm/kasan/common.c:463
>  __cache_free mm/slab.c:3425 [inline]
>  kmem_cache_free+0x86/0x320 mm/slab.c:3693
>  shmem_free_in_core_inode+0x63/0xb0 mm/shmem.c:3640
>  i_callback+0x44/0x80 fs/inode.c:216
>  __rcu_reclaim kernel/rcu/rcu.h:222 [inline]
>  rcu_do_batch kernel/rcu/tree.c:2114 [inline]
>  rcu_core+0x67f/0x1580 kernel/rcu/tree.c:2314
>  rcu_core_si+0x9/0x10 kernel/rcu/tree.c:2323
>  __do_softirq+0x262/0x98c kernel/softirq.c:292
>
> I'd really like to know how we came to call destroy_inode() which calls
>
>         call_rcu(&inode->i_rcu, i_callback);
>
> Is there some way we could capture that stacktrace at call_rcu()
> time and add that to the stacktrace reported here?  We could have a
> call_rcu_freeing() macro and manually annotate the ones which are going
> to free memory (I suspect that's most call_rcu() sites to be honest).

Hi Matthew,

Yes, this should be doable and should be super useful (and cool).
Let's please move the discussion to
https://bugzilla.kernel.org/show_bug.cgi?id=198437 to keep everything
in one place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZi0L3OL0AtrBH4Sq8zoYVFFvsar-fqXZ4p0bE%2BbouUeA%40mail.gmail.com.
