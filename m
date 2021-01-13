Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTOH7T7QKGQEA4E2DWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 79DF22F5049
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:46:06 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id t14sf1564574plr.15
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:46:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610556365; cv=pass;
        d=google.com; s=arc-20160816;
        b=RxL7YIzuQ+JiFkfipvgsMyk5/AUnMyla56yoQRa0ooxaauKgn8Z1E7ZC6qdqxJaMph
         klAg/dNO19wcMHLENbyzApCa1v1ST4M06EEREOAg8crRCZDcLCtIvxphsqwN6pLWGBai
         w8GWJXbVL7KJwQnPEVh410MAgzmezosuAI79C7rST1Tv1tCu9EwWCB/IwIbfEuNryJtJ
         1VUtEY4JEnKLSF8550IZ4qzVsKQ9BNttQMBpbwu7fpKsl9k5ta9PGfRODzUl+OT6IqHI
         fFb6V6GVUK1UXX+Th4khY3k/bB5jeBDCTQ6HWxW9pVw+nEUwfSKUyIUhqrnWohM04Juw
         9gjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nM4hKNuh8H6SD9sdhndRw5cTuOZc/pVa3zX4ba4tId4=;
        b=vQsCwG6E+ehDYKbwaCgpoOi1LdsWc54ZEhpKRi3/wPRsaDuCekSbrGqZ1azkANOvXh
         ery7TFD4Yax6sHI2flelDqBSDNWzqM/9TiprWqMf8p9l13ZaxFV1lNlJsqv25mOHjWIL
         pFJd7yY0E5kuk+wR86qnr5gbdc9KSYYZ8N+lN3jfGtcS0fHCNDTPIOUaA9CJhe84toST
         4Xh7ucbFLPGqF0BfWikGrjE3dyUnAvMZEA1xp06JQ6ATfgMetGmPZQb9zOkwH47u8W/w
         gir2I9dRz0f5D5KJ5BAlcStioOnIeun5ik3psp9Xh3fOeLi9+xhkSYTG/72DpKzCvLBc
         HmhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZCXXS7+I;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nM4hKNuh8H6SD9sdhndRw5cTuOZc/pVa3zX4ba4tId4=;
        b=QvCP9D4FlvpJ7z2tVOvOqq2vg8S31mJAM3SKtWFjLToP+1YLU3d2ysIkBA95xwLdaB
         Ruy/BC6GOan44QpD/jHDPH5ZIHe62+9LwpeFHMlhimM7KFkwW6yan3O85mqkKoDYofsz
         DC8K42DfKL2hjGTu6/+TQQobl+ybBlaZBEv9UH43NOE5n2jfIMagIWm2QiMJFrT1F+Mp
         41J1RETtWitTfh8qZfwxsZUJ4hHCvf+qqrhZceC0FBFAaG2DsyOYIuAA2lgXH7weyWkc
         1d9utnhmheY8AHeS+otW03v9qYwkBQKMW9iIUjqo9KhZEDuSkWULPbIjmqewpMYlffMT
         zMfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nM4hKNuh8H6SD9sdhndRw5cTuOZc/pVa3zX4ba4tId4=;
        b=QHu7gZzQ3R81az7mGcNP4efrySm2f/zRzz5Ozr4RfHPg6a8+cf1XdaiaxB8cMwdcYB
         /6qlSisZXUI/h3m+eKpN/mjqUvijrvKB2LYNiLmoVbBYwpFulqFsWsIxOBwLrjAQ+B90
         yDejjH41AIyqPAMIaMclXtVsnEwcYJr/GQhiOss5hwKb+CDVa2k3p8jh0McPmaIKmrWT
         njc0o1lBrLra49KhuSRRQb3Ashjre4x4UbUvbHvdKM8daeAoa1mVJT8oZltcN6IWjOBQ
         hsMV1VrQmoEiLwhLgZyRBEk7HxOZKS0ELW8Yl7jl6eQYZ2SZNNSQSjnjmNcRsa6axHbK
         STeQ==
X-Gm-Message-State: AOAM533Z4vZ48tz5o2igZBexeU4PgJVjWC48bfLHwZAyhkL/DEnrFb39
	4QuszBHVNWrC3Mygp7PHt/U=
X-Google-Smtp-Source: ABdhPJxw60CCdkxuScmeQPi969FjdCd2z67rI638qmG5hQWta1S3xSIY+82P9PDg1MgdEgbx8XORNQ==
X-Received: by 2002:a17:902:a711:b029:da:f065:1315 with SMTP id w17-20020a170902a711b02900daf0651315mr3100737plq.36.1610556365248;
        Wed, 13 Jan 2021 08:46:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls1310094pjz.1.canary-gmail;
 Wed, 13 Jan 2021 08:46:04 -0800 (PST)
X-Received: by 2002:a17:90b:4785:: with SMTP id hz5mr121333pjb.157.1610556364652;
        Wed, 13 Jan 2021 08:46:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610556364; cv=none;
        d=google.com; s=arc-20160816;
        b=O8nwFBaIxx7xMeZ5m51hLyoFx57d3Y3zcyJULU2g5C9KH7VAitOz7KZzwJZ99j5wvk
         k9GtqUxn/XhYe/5JBddJoJYlO7Ky5kpPD8eiRno8A67KV2UAogG6R+i1Mtpm8HiHeC76
         XJ6PyS+moC7sqaoSQFvKHinEk3M8NulyhgT3/0CA8K+yUIxSQ9Z7vpzcdMidWbxLW6pW
         +rGQpbvl+obmU7LtVZWSBmeoFeKVcBEha4CcQXORsNEDcfPb16WuM62QARGPjWrZi5wV
         GM4c4uMnBq2toXumZEpzy+Yo87OguShVQ8GofCKInSvpDAiyM3ijfHspC8qEoESBPcmE
         l2LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CMjUDnqe142kyL4JCtMxq/r9cprLrjt9yzIWhPD32rs=;
        b=SK2EqVdUip4mWQvPfOl3L3Jt9sRBnkp0te9c4KdVBtSMBXrBJ88NgMMRQJQgcVzkr6
         EFg9pX08U5vIn+f2fcqcbefS9Mrj00k5Xm3l4I2PA9U3UeAGvW2TAazvsaMo/emkHv3z
         f+nYLUt1qZpqqM/87ssXTHs/jSVc87M6tIGAOb0Zau/Ou/8FML/eTu+LP9wNHoPoms8n
         jSno9OKA1hwbdIKmy+9hcYFmfTnWrovW8zH8w1vHYqOMV1DmQsll22jM4nxecu3s4pff
         XqEgixHx3l6T1UB14JL7GDA2RH+kwfLliUV3kP7pOJUx6qqhexJYF57/CEhmpQSf0eaE
         bInA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZCXXS7+I;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id m63si148303pfb.3.2021.01.13.08.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:46:04 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id h13so1049012qvo.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:46:04 -0800 (PST)
X-Received: by 2002:a0c:e90a:: with SMTP id a10mr3297670qvo.38.1610556363951;
 Wed, 13 Jan 2021 08:46:03 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <0afed913e43017575794de0777b15ef6b2bdd486.1610554432.git.andreyknvl@google.com>
 <CANpmjNMZHiwKDTyBdHzHB6CexJTfN9TUjk=q6zmj_nebtq9=mg@mail.gmail.com>
In-Reply-To: <CANpmjNMZHiwKDTyBdHzHB6CexJTfN9TUjk=q6zmj_nebtq9=mg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:45:52 +0100
Message-ID: <CAG_fn=Ur17=N-Unsi4CdSnx-Qnfjuh1d__zKOHPUAC-3RLHV3w@mail.gmail.com>
Subject: Re: [PATCH v2 04/14] kasan: add macros to simplify checking test constraints
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZCXXS7+I;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jan 13, 2021 at 5:25 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 13 Jan 2021 at 17:21, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Some KASAN tests require specific kernel configs to be enabled.
> > Instead of copy-pasting the checks for these configs add a few helper
> > macros and use them.
> >
> > Link: https://linux-review.googlesource.com/id/I237484a7fddfedf4a4aae9cc61ecbcdbe85a0a63
> > Suggested-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Nice!
>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUr17%3DN-Unsi4CdSnx-Qnfjuh1d__zKOHPUAC-3RLHV3w%40mail.gmail.com.
