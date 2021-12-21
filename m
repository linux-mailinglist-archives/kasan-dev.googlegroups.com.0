Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHVXQ2HAMGQERMA5UDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B86347BCAF
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 10:17:19 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id g16-20020ac85810000000b002b212f2662asf10093516qtg.20
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 01:17:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640078238; cv=pass;
        d=google.com; s=arc-20160816;
        b=DUzakEMgpUwwOI0ky/ryWYBOchj04nL1eX+m4lzAnom70hJmMhB+uYY/doVux2QuDd
         5g5yVdURCn++7IFXzNlhbBZVQsndzEn5A2+o0xnmfjiFPulDYDxa3wUr9pUyYjTcdRIr
         O6wPQyD4OHdhxN5stJUxFsbeCS33CERaeEhK58HzlpNxGpO5n7NMf5ja9sFf+0fLoaO2
         CFxiwJ70KJ72ylkR2u9lekRfrygyhpku+EwjvYeSv9/Nnd4Dtldjt2cDWRme3zblvCUU
         U5KwrDz57OtswhLQnJ9eJNmaXVydIvTC5wUJAYvrCJZl7XupsaWSzljeKJY7tU0wgdCB
         sKkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eHwOT3qtsOggBJRHND5lVPLZV3XSjT41rhHj6yz11sQ=;
        b=tL5+iBpF5BPVGudZ2xi+MpHLHavHew6GQ8TxyGgE4EkADvpwD/35rkzfeNOYW6F33t
         +XaR/mjMuzIpPdn84IBNal6nMcxj9MMQMLfkm55bY1jRwrHDbTBeh6BJS2VKwqc9wzia
         LQLC+wps+FVjSpOu0IHDfPNiCyPNUippy7410Ws6TSt8wc9aswVLs5yb2tsZmR45fRxz
         lUggBclkF8/22UDq7Kfd/jylJoq1Y9HktZAZMXWNglg5JKEGCChRO/dGWVF2nZbkWK9E
         dyifoWMWrYcFGt5DPztFlpeSgn6g8a+TRzfpTByy8aWff06drwgodGnwHwZS22RqP4JP
         HndA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Rc/RWdXi";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eHwOT3qtsOggBJRHND5lVPLZV3XSjT41rhHj6yz11sQ=;
        b=jUKc/6+7Ge5/n7CemNtC6L1Vm4IMvVyKUIF38deLWDE7nT2cPD+juBv/HuBaWeuW2K
         pn1VQMWCwRg7u9VFjAaTu5SJ5RmdapoUSqG2JJifxxT65F52B7iut44VBA003NoMeGhN
         i0fB9P/qM2nUP5ps7myZLo7tpsKtw1oSWfhK8uDqpkKfl2r9a0Gw3OvNv0mt2DcdZFDO
         FmeX/WGlaijrz6dmvqpMKWH77q8NKU6/wPXVS+U6zs78og/2rZxevN0v7HYP+RrfF+bT
         bcRCq9nlL/6b5ZeHg2K6vgu/WDsh/cAW5CBGZCF3QJPp/7EIXEEJZ0EMEX8JFASv3h8P
         bz1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eHwOT3qtsOggBJRHND5lVPLZV3XSjT41rhHj6yz11sQ=;
        b=Ac2IFY0EhqW0+UpUZQ1WfPGda/0mvd+PxnDKuvkRxeI9BQDcb51h05yfcZzGiOO0Xq
         hxCh2gQVilVgkvql6HNegJfQPLK5cNx6vEp5/yWqTZaWo8AxcVzbcTTE2r/L3L8drkUF
         OG4wOU4I6xNrxfIQZe4nlu9fqiDfYCijk0bd2dkMtdULTtgkn4ATAdfHnx1XlfLlJJBF
         r8weLp9db+ap9YYg3vcCT/eMoVGR30iWxx1x9lshkE1L/n/nf+/JnNl6/Yq7zL36Zwg+
         v02ladqdLI+yN7zBK6yVAqIgBCnUGKcu9M7VjiNG9ZGH7UlsIUqOZUoTo5Pn+iFR1QAm
         lTqg==
X-Gm-Message-State: AOAM5317KKnYV6lBuT94nNFfXibcIk9H6m0a5d02aLzbNhpy0iyNTqoZ
	B/2aZRg5VhXZ1Jx7KVKnErk=
X-Google-Smtp-Source: ABdhPJwXRikXJr+TiVCi2aq4rti9bY27Og8qXC79YqY9BBgqS+z5rOfUQZf3wTKRKRIuOK7WAnsraQ==
X-Received: by 2002:a05:620a:4301:: with SMTP id u1mr1341031qko.134.1640078238216;
        Tue, 21 Dec 2021 01:17:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:db8e:: with SMTP id m14ls1485911qvk.3.gmail; Tue, 21 Dec
 2021 01:17:17 -0800 (PST)
X-Received: by 2002:ad4:5745:: with SMTP id q5mr1667742qvx.108.1640078237826;
        Tue, 21 Dec 2021 01:17:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640078237; cv=none;
        d=google.com; s=arc-20160816;
        b=vSXnmU6gagNyZQpScC3jIYuQnuA8nk9SY4stJPn9VkuCXghNdvWk8fV95d2FB7r5fS
         J9OtTDnaKpPfo2iapkQ3MkM4nHKJBCFgV+z4Bd3h1AuZnvcw4j0+HQZJUjhRowSKcaDH
         gDayxhMaAO5KsfY2zmVcMRLi+umfYNI4a84tVT0ml87Ntl1DQJaWYcni4u7rI3fq/v5E
         /ZIaCL8F7QTtlY5eOdQLwxrDraRy8VKNO3RBG8D+KPDRqYOFXKZKo3uIXR5M9iK0f83b
         uiIwylVSPUdGTKHse74lSyoty+p8Fth+JbjJqyWV/Bu1OjKW82qqFUA8Ar+kFQmaxNUO
         owtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GsQvaI7A1wdAxmeueWYfyyxE+cFPs78qCZTLJz4uaZA=;
        b=CAwzDswK6jOmGqe5fi/fsv6Z2nm5aH7nie+1BcXnYC/5IT1Ze/xVDYmNzTrBAeZNX6
         q61HBKJ9IM+Xj7wfK3le9oNSJDs82CeDKZ0mMtbL2c3Jxy+uDl2yWh7ngeHWasm9DStI
         6/6FzS/dwPl9cu3TPdY1TW6mZP2OJ76WlJie/FxbPlb6Z3Oa3QwNwi6VN6o7uvoynmyo
         gtyiQe54TK8zFAVCXe0yEXnc6NBicW09nSIN4bCN2KKbMWAFNLCJmUmdi7BrjK1Y61jq
         WJJEWW3nXJKDcux3KUp3shSKjBf1lmd9b5J8iCMUWjC9w+gA4w/w8aIvpakTSOVXOwXc
         CA1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Rc/RWdXi";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id k10si1434952qko.0.2021.12.21.01.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 01:17:17 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id j17so12301487qtx.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 01:17:17 -0800 (PST)
X-Received: by 2002:ac8:5712:: with SMTP id 18mr1304135qtw.72.1640078237345;
 Tue, 21 Dec 2021 01:17:17 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyknvl@google.com>
In-Reply-To: <92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 10:16:41 +0100
Message-ID: <CAG_fn=XcPT=e6zmm-B4KQPLujpuC9D+hTbJEsua31onzopDT5g@mail.gmail.com>
Subject: Re: [PATCH mm v4 07/39] mm: clarify __GFP_ZEROTAGS comment
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Rc/RWdXi";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as
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

On Mon, Dec 20, 2021 at 10:59 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Alexander Potapenko <glider@google.com>

>
> __GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
> allocation, it's possible to set memory tags at the same time with little
> performance impact.
Perhaps you could mention this intention explicitly in the comment?
Right now it still doesn't reference performance.

>
> Clarify this intention of __GFP_ZEROTAGS in the comment.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/gfp.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 0b2d2a636164..d6a184523ca2 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -228,8 +228,8 @@ struct vm_area_struct;
>   *
>   * %__GFP_ZERO returns a zeroed page on success.
>   *
> - * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
> - * __GFP_ZERO is set.
> + * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory i=
tself
> + * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
>   *
>   * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poi=
soned
>   * on deallocation. Typically used for userspace pages. Currently only h=
as an
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyk=
nvl%40google.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXcPT%3De6zmm-B4KQPLujpuC9D%2BhTbJEsua31onzopDT5g%40mail.=
gmail.com.
