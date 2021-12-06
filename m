Return-Path: <kasan-dev+bncBDW2JDUY5AORBQPZXGGQMGQE4GLTOKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4949546A93B
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:12:34 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id bk35-20020a05620a1a2300b0046d2a9b93dfsf12830483qkb.16
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:12:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825153; cv=pass;
        d=google.com; s=arc-20160816;
        b=CiC3Sx/BJdhECC3vJlHPjXlc634gzrOCgkRfpDVOeQ7GxJjytdenFok7ty0cz79NNf
         dM/OQNOSu75Aax+y4VnP+kYTyncDKPBcEUKvmbpKzNrmWC/IgrZKsSAdkM0lZBMGD+PL
         5CT8T1t4Vol+k0xcLpuvVEuCT36Hrv8cwLCYbvHdF+W3fPwGAxuO1eQsXOrAR3E8ejmB
         JboQav/il8ZZdfRWSsJNUDsz/AYFzTojEVR9S6iE2cRZf4R4q5lygiQDQ+sfZr+EQe3F
         Cxu7QSj26x/I+tgFlBoHYTKDhQSSMkWu4SakI8R6zwJLpwkXkqa4tUa4Z5RhtPtaETGQ
         s9XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=o0nqdTVct8khsz6F0wkXJ97vlGB/bYTiGlO6mh5qDlU=;
        b=thv9lHUnCBtGs7hjwQI/RarAxPgN61wRo6bz5siF2/xQKw++q+ZCv77H6XWHZZ7A1a
         TJToJNqh+wgsHOqqKUw4fI4XTqoZdgsibuOCglJe5a3VbT9jxkoUCVZg59YP5VK6Z6P5
         doZxUXnHBV/csft4nspenOpZUHdu5Fh2A0U4pc/XPNX6p5JfNfsg/P6NdgU8yjV8ZTaX
         KwuUKZ1gxAQ3em/mSxlwSZBI3XGJyWUDJaVuAPkQmezQ6vYEMI2C8GN0/lbiw6wiInKu
         Nx8X0C2FG9TqyVIyKEg83q9/lBUIvPkx+IqCi9LV5YjprqQXX9hpv9XIr7khqSq+OdR2
         8m/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Jpv/phoH";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o0nqdTVct8khsz6F0wkXJ97vlGB/bYTiGlO6mh5qDlU=;
        b=ICQQ+fkwU7G2umaNKSOcN6opmpdhXSXV9XQkA0E0GfdOnr3h5XTLR+ru2XVwE2nB6X
         w5QmaqMichFRMyj/x/vBVfrHVxjO79GCxQAMHyqAvCruQt/c64Z/lHSnPzkvkKEsGDFd
         wuL99go4OZsZdsBgEsBQQfwXVoIFzD9CUK/YxOhEadCeQlsEqyhf4FzBqcagoxhxfOqK
         bVJ78HBIXmMuyxSyYFGhbJNdiUyuf47d307n3uGOn82KALlsB481M1klIOxNtRURYXIW
         4snE1uFok2ySSj73ow0W4AvrOiRuY7LE6rqblFWsAEvp1Yl1bKJM7gJ6d/Svk3jexqTn
         4uXQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o0nqdTVct8khsz6F0wkXJ97vlGB/bYTiGlO6mh5qDlU=;
        b=kMBl6qfUH6H29wnE/uWTnwHXX3Xy/hj7YicvkfujY4l5LaVFSvyLbhGwHwsuwdyY4A
         X9hjaUWzzXdy06ZuZBO6p25/Yo04zgh1Gcmd7Uu04Ofir+kT9OmNHkqiy8nj7vXRHNL+
         RCQofXH3+5EJQoaTqOPmEIPpLpn0U21UTWjc3/bZ0lmfQGhXSii6grKmpp0j8KNCRmvk
         jfO0ZP4X+5iyC2M8ucs+zSWmQ2gN4bgnoYL8/Rpd0msR5LHnsg1iHaXDeIeot2AyC4iy
         8oQRaDFiFtY9EHOb+qAqH+IbJ7hJ5KRsGgMmShbDVlAdYL3co2H84mQk15ABja141LhY
         rrHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o0nqdTVct8khsz6F0wkXJ97vlGB/bYTiGlO6mh5qDlU=;
        b=Yj4cLnzPaTws54my2zbFcFXGkDT4/n7ltrCP4IuJASGu4uuTcHoW3wrKzY6F1/Kv/M
         CUUE5TFy8LUX+23aRVHUeMfbxp93ZNo6K/1MF5EZCuV60BtRLdNmv6SWvahnuSqex6t2
         l2GILFTFOBi33qI/CyJ4bzCthkYZnvjlH2kKENzIEdujS3tWDZponi8UA4dJf+xPQsi9
         g9znzLi0Ei9Da/KZ1CdB1gkwjwUzLn4ejQXfXW9mlyyxNBGKk7AMW+aXXCMCw+3vHC+D
         j+uHR20mgoSqhkDlwkwhfCROi8iobsYHvi8AdhlPeu24IYV/dRQnORxekB9jm4/TGzUV
         2EDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oft3jc8W3MxgxgcNAteHd83eUU7Um/yrywfztVk7ZeX8oB4JX
	+xLic664MenOEIFS4Evr9Ng=
X-Google-Smtp-Source: ABdhPJzUAYKB/wKob74RlWHsXhwy3GfqI0SQUYLXAWmHJUBsrjr+4bWOmi92r2G3YX2c+rISvl1xuA==
X-Received: by 2002:a05:6214:d01:: with SMTP id 1mr39600152qvh.113.1638825153309;
        Mon, 06 Dec 2021 13:12:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:294b:: with SMTP id n11ls12542956qkp.3.gmail; Mon,
 06 Dec 2021 13:12:33 -0800 (PST)
X-Received: by 2002:a37:5f44:: with SMTP id t65mr36011328qkb.32.1638825152941;
        Mon, 06 Dec 2021 13:12:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825152; cv=none;
        d=google.com; s=arc-20160816;
        b=MPk76H0QrkU5MyrmX9Q/8DhiDYFfeQvwd3ZGIidLvFMhJJflPm/yDdJhRUOcbHW9kO
         amMKzRHaWXwZjs93jwSL+FTp/DbvhJePJboy0MVMqKmt4+U/9eoYuTeyk4m6TAvwd2b1
         vyxW4c7NL5qgNVOMdLvywIBpL7YIZhXoQz/exfOXjgqMJtUmaSPJ3GFxcnKev7Wqj3wZ
         meU6EFRotnZdB+9mqfdz/qCpE9y5xvyJ5chh80K5CqZ+VP2/5vdvWAirx0LtZmdF1tUL
         2z827pcKc3Y/e5WptYVO3ORbY0GzkhT+vEXHDljdVqxqHuyE66gPjTW+iB/QTx1cNybz
         YgYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bvN4dyZ6ySRUU6I+5//n6rteuxKcOj9JtT0P4yYGfLg=;
        b=MnUMZHbnDmaD5wLHzZizIhBkp49hKXWxUpGkuiRHOGMDrYNCWT3h0c1H0en6psKvYW
         bMjeIWClcvGdvS64VUAZYu2jbx5Wm8eS+YW4bfzhznpDB3+WEZN4Shfe1NvfdQ1XXKeD
         Z8joqjKUGhMDnVFlr631tLzqm/SjSF5chHBKd5RWmDJTIy6ExCya6UirlptpUSAfwSXN
         0fx2jBFjxvpPDMr9cyMSlrIk87ThKil6BvP9dbTOfB5sD828IBTM26kL0r50p/T5KuGF
         +Emxi7thvw3lS+u2jLxpA8fQlAIMRGlUm5aArgiFxaoiwaFwXmWPpfMfhfSqnU06sV12
         fE3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Jpv/phoH";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id i18si2117437qtx.0.2021.12.06.13.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:12:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id s6so6151545ild.9
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:12:32 -0800 (PST)
X-Received: by 2002:a92:ca4f:: with SMTP id q15mr35096921ilo.235.1638825152535;
 Mon, 06 Dec 2021 13:12:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <aa90926d11b5977402af4ce6dccea89932006d36.1638308023.git.andreyknvl@google.com>
 <YaoQbt/7FoEnBx4K@elver.google.com>
In-Reply-To: <YaoQbt/7FoEnBx4K@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:12:21 +0100
Message-ID: <CA+fCnZcDjTn0A4a3zdxVQ7+a90yt3zUHthMxFHa1XdHm+n+G3g@mail.gmail.com>
Subject: Re: [PATCH 27/31] kasan, vmalloc: add vmalloc support to HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Jpv/phoH";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131
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

On Fri, Dec 3, 2021 at 1:41 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > This patch adds vmalloc tagging support to HW_TAGS KASAN.
> >
> > The key difference between HW_TAGS and the other two KASAN modes
> > when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
> > physical memory. The other two modes have shadow memory covering
> > every mapped virtual memory region.
> >
> > This patch makes __kasan_unpoison_vmalloc() for HW_TAGS KASAN:
> >
> > - Skip non-VM_ALLOC mappings as HW_TAGS KASAN can only tag a single
> >   mapping of normal physical memory; see the comment in the function.
> > - Generate a random tag, tag the returned pointer and the allocation.
> > - Propagate the tag into the page stucts to allow accesses through
> >   page_address(vmalloc_to_page()).
> >
> > The rest of vmalloc-related KASAN hooks are not needed:
> >
> > - The shadow-related ones are fully skipped.
> > - __kasan_poison_vmalloc() is kept as a no-op with a comment.
> >
> > Poisoning of physical pages that are backing vmalloc() allocations
> > is skipped via __GFP_SKIP_KASAN_UNPOISON: __kasan_unpoison_vmalloc()
> > poisons them instead.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> This is missing a Signed-off-by from Vincenzo.

I didn't add it myself as the patch is significantly modified from its
original version.

I'll ask Vincenzo to review when I send v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcDjTn0A4a3zdxVQ7%2Ba90yt3zUHthMxFHa1XdHm%2Bn%2BG3g%40mail.gmail.com.
