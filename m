Return-Path: <kasan-dev+bncBCMIZB7QWENRBDEURHUAKGQEQ5U46OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DEBAF43638
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:05:17 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id b10sf9535513pgb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:05:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560431116; cv=pass;
        d=google.com; s=arc-20160816;
        b=IV7+tXfMdOg7PLMLLgNaN4d/KrTUafE34xLvSSNkTjtgzBQCeNZr7+ycJzQ1WtGCIc
         fiEiI0IyZjfPTybr2jhKgUMYmOmOIOCy5i56YkhE5uma9uHgENNb/z47ho2xI/VgngLy
         HHEpZqAfmd/9avu3ul1EbBqDvqvTSaw99loLjNCD9csVspCccOeY33m7acs8aDJgRSRB
         5bx3bA3oUEN1ZskDVG7AXao3gCChr0nsdqApFCJPhmBO47l3zv5BGyTgTAaFgtj4N/13
         cSWwM9SuIN87m9h7UsoC/cXBk0rRehAIk3FfEvnjOWT3cV6eiQEiHDX5oUzIYwWkbAS2
         Fv1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gmQ1pkohwxlcOU2y8fxZ4JPhTnjzlDEev0M+iWRg+OU=;
        b=QDqoY/6Co6uLK/VFu6RjA/q6wCGquGwh4id3IeIk61VsMWmMiTTdlSMOSH3vWJmAdJ
         +g5L7FnfxsR2VRAJQiRXZYFRS8zP016vBqABjuEUo0OC2WkeIKyDEKMx+CZcRS+hMImN
         rbIL9sQwW+KD4ZmnnJcwDgo0GsQm5KAOKb6v3LjTS4DFAxtbdtzqmTTvIdnJ077e5w8p
         uf+etYRCNC3tE1OwCJSDQEEg/55Nqk4r23dA7YH7FBWcPTyMkLsxvK7B0KPKoETze0Iy
         2osPwNMrxXQJOrr3w/I02aMWV31wD8KkAtZFrGnCs8G5y/OWUrcHR7CpyeI3IdzxmKHS
         SWQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qc01olia;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gmQ1pkohwxlcOU2y8fxZ4JPhTnjzlDEev0M+iWRg+OU=;
        b=EP8VagNMKQMFJMdgh/A0lnwvrQkCg9SCNTO4Pja84JOQtGeSk6AaV9/j8mJlhWRxNN
         DlJr7P+0jKT2K1j6djqIsIx2uP6qvkXWjR7eGVojg4vTXMJFlRPMeElxNQeUKyJgMt5Z
         bU8pTxF7dxBSiHN59TcXKf1WcTNgDr+//fivNXlOhZxC49E7EDog/6R6c60k8ah3HQtH
         HkPUYzgHtIDJZCf6uLLeaEiY5AO9MD/niFHLRwBBjIXCmKw78KWdBqXvVQtQlh39YeCT
         4PPz4F7zbGo0gn4SC7h189GOO2ZziiXen+nBqMS6bIPQq5Q+mxDwFHQJD93RKQJdua5r
         0fjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gmQ1pkohwxlcOU2y8fxZ4JPhTnjzlDEev0M+iWRg+OU=;
        b=NnogaqDwF7ZkwJc0ubF2ZR9iRMegchlRl5EELT2t6SqhlO4fRa4XiCHrBYoVJAq4NJ
         Fsqut7PoNSf6Y1dh0/3UqOcOLqdSxYLejaMaUzLRWiOw/AsTqGAxtT1YfwjMkMhmzEAz
         H69RpnK27IialDXkftURVClmqZ8MHXULOKsTe/4T94YcPlN1wR7hUGJmhkV8KKCa07mB
         5HsS3WN0Wj9F6ndAHl/4VZTrHPPnusrV3zPcoOU3zuMCksd0nOSA10GmEW7LZCLHr4uc
         pH8sEKIpzuytxp1DKqrSWJGHfu6+ujc+yM2o4rWeQvVCtE5HN3p4PA0FPDhjO84ZWnIf
         J0ug==
X-Gm-Message-State: APjAAAWTXZ99A2SfhkkOxmCgPaddsJw1owqcsP61b29RaR1jWgMH/aK9
	WzapuPahKA05el9Txsjjqsk=
X-Google-Smtp-Source: APXvYqxu5KkpETCZu5TRuMA1hA0/D8/Op/aByj47tsFFajOOe73FVNmotS06GyVzj5Z5oOcZZqYaog==
X-Received: by 2002:a63:26c4:: with SMTP id m187mr30799646pgm.221.1560431116557;
        Thu, 13 Jun 2019 06:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9694:: with SMTP id n20ls1421831plp.6.gmail; Thu, 13
 Jun 2019 06:05:16 -0700 (PDT)
X-Received: by 2002:a17:90a:8d0c:: with SMTP id c12mr5339416pjo.140.1560431116260;
        Thu, 13 Jun 2019 06:05:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560431116; cv=none;
        d=google.com; s=arc-20160816;
        b=h89qXw7teifLTkUcnf3IGtcUcut3VbBZTDxSu9XaMWVSTB6oaDRSB8rV2OXNxEh2ir
         ZV8hymnCcXj4Gfqf1ajO5+IDew7NZLhVUdhUEWZ6m7ajGfvsoix4/moVY8VN67n0+8cd
         qT2x6w0QW+v+L8zCaQS6yU7uy9DUg81ublu1NKc6dYgxudac/gdGkMspt+G21+8FyL1Q
         Q9m9m+ewagJLL78n30NVEcUFlTH3nTZog4SQkL3HwZFFVOxJzWrfPeKUuZxCbRZAGaZC
         YoSKfJf6mlwnHI6nOgjFbcMY57es1nr9nRYq+XVn/hTmmHu1XNnu9p/iODFwJJ/7i4Fc
         IJ2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=COMq1DZp1tUFDOVJCz+Oc5oRle5W+TVy2bbvRpSIdF4=;
        b=0+mjxoVeZjyZ0M3HsaH/b3LSTi7oc+YJ14sU4bDmt/0TS+riV/vJjKs7B5N5k32WuI
         hsy1shFyKzXziZrHGvEUL+BsCZdNUTlwwXMROvZIg6P0BgfMzt/CC8XVzdcN5LmnjqCG
         2cma8GLgTyjH97RA8SOpZZtKd/PMhovNCrjJrlFdx06Un7wQdM7A4Mcp7JOySSezYczo
         C8APZsGAyyJ2IhejKwsmiK726+VT4sQnThCI5v7YhzLJqlU3mBoztP9AISyESVl/tMOA
         4Z8IdBQMk1hP9STVbaAeIJwP7Zgjf0E73StxETp+eFwxVjTjcuR9NaWZO6oDJ/aIwmCq
         Pyow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qc01olia;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id d128si96918pgc.5.2019.06.13.06.05.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:05:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id w25so16627182ioc.8
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:05:16 -0700 (PDT)
X-Received: by 2002:a5d:80d6:: with SMTP id h22mr6100497ior.231.1560431115386;
 Thu, 13 Jun 2019 06:05:15 -0700 (PDT)
MIME-Version: 1.0
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com> <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
In-Reply-To: <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Jun 2019 15:05:04 +0200
Message-ID: <CACT4Y+ZGEmGE2LFmRfPGgtUGwBqyL+s_CSp5DCpWGanTJCRcXw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qc01olia;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42
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

On Thu, Jun 13, 2019 at 2:27 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> On 6/13/19 11:13 AM, Walter Wu wrote:
> > This patch adds memory corruption identification at bug report for
> > software tag-based mode, the report show whether it is "use-after-free"
> > or "out-of-bound" error instead of "invalid-access" error.This will make
> > it easier for programmers to see the memory corruption problem.
> >
> > Now we extend the quarantine to support both generic and tag-based kasan.
> > For tag-based kasan, the quarantine stores only freed object information
> > to check if an object is freed recently. When tag-based kasan reports an
> > error, we can check if the tagged addr is in the quarantine and make a
> > good guess if the object is more like "use-after-free" or "out-of-bound".
> >
>
>
> We already have all the information and don't need the quarantine to make such guess.
> Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> otherwise it's use-after-free.
>
> In pseudo-code it's something like this:
>
> u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
>
> if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
>         // out-of-bounds
> else
>         // use-after-free

But we don't have redzones in tag mode (intentionally), so unless I am
missing something we don't have the necessary info. Both cases look
the same -- we hit a different tag.
There may only be a small trailer for kmalloc-allocated objects that
is painted with a different tag. I don't remember if we actually use a
different tag for the trailer. Since tag mode granularity is 16 bytes,
for smaller objects the trailer is impossible at all.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZGEmGE2LFmRfPGgtUGwBqyL%2Bs_CSp5DCpWGanTJCRcXw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
