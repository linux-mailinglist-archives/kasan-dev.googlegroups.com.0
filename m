Return-Path: <kasan-dev+bncBDW2JDUY5AORBM4662FAMGQEPIYARIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 27793423D5C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 13:57:41 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id t6-20020a6b0906000000b005d9a34ee5b9sf1894169ioi.8
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 04:57:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633521459; cv=pass;
        d=google.com; s=arc-20160816;
        b=hcOA4FCNcfWwMYWZxKTWyUmM2g0r/8nxUipW/O57o/RKXDSxAu2rbQhkoYNk4ognIt
         rgfO1jFiDRIMDXOaiBiQBV8LOe/NErEsA1kxvA1o3/4ZYj0RjywVQO8gOaSZwuquuW5f
         M+OrzCZmo9eTmgBn0a3bAdOEXnf+rAr6b+kHV87IQXRNOImu1pmBDCZ0MR80217EKMdh
         UN1GJOxj7FAFPUrCEBjrEmGCH/bgxW9G2GJrzYodiYGSp4seblpr2r5GvGe8GCtdfdUI
         ZgJromQFiBEqHX7k9tdTp254iWOeKZ5aaxZtb0r+PhmbWh0Lop48NT6/Elaukg6INmGV
         8yvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ZFp8j3Ltm7BcUHQsXIhCHQ6wXDKtq2g5qE/WvErDgxA=;
        b=M1isK/Xt7TBttFWCvE3CvLj8kCusSRApORd4bxKOtKeOWWQ/T6ZCfGQMDATL6qaBLM
         5rnN1SV8o+4+toFnSfhTa08fscMS+VzX80j9PJ9H5QdiAFY+2UT50QyNUP2YcGJzDq76
         JtE7hwtAsr2FtpZLAlga02I9NiNFg6b3JChuuAJ/CjtaT6vkfjpntPegP2V0TDtgw/zZ
         KIbCa3JIi371DidQAIYTGO0ViESCxp4jVBcYPe4jmNudb85BE+2mODdxDW+pgPCspkPw
         r4+fuNUS8+QhDRXkXWtsD1H6EI3QpC5WnHQoYXHzjZvVVH+HDYCMxhwr9BxQEeIcaL9+
         kRGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RHqUFEet;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZFp8j3Ltm7BcUHQsXIhCHQ6wXDKtq2g5qE/WvErDgxA=;
        b=s3vCO7Vfdv/uzTv6iVEcilszIxmsbpSj1FPRBqY+a2O/wAYeOeMrDwhWDVHYUQhbKB
         0yBrhBW/l9tQzFPCSsYdNycZq226ZyzB0PqMxSH6vT0/0HjBpfCgdML9S3Eq38C1nGuc
         iGTPpg/V6lysgFdkTb1OacxY4tyZmn9KdoMDPv5NeP8cABu6+64C24HYJUrmPiFh8ahA
         +x5YFAjQai9WMDu2tzTHjuWPpP1xnz0XYpmirMMT/VXjfaFmYFU5XFq6aoGFeUCwDRCd
         ywy679RR9UyPXPRl0zrD9+Z4B1KbTO0PToi8fu08IYsbANcOP6qUav+5YfvfJX4sAFvM
         eJLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZFp8j3Ltm7BcUHQsXIhCHQ6wXDKtq2g5qE/WvErDgxA=;
        b=LXGGzyckENeZPv0qOTl9dwtJk8xiEcuyontX81kUIvMXcv7zZnH8M29Btod2/1KabV
         W/gCYrh8IkR9hIjCajHLL6re+/HWTobdhtj9WEsTVKd2GR5GLEukhjwCEL/hIyolD9pG
         ZiNQgCIjUc3pL6coVevGQebDJ1Wp2GRkq4qcU5IrJcfuGjDpIJyIJ2q1ExuG8ni5s4iG
         1/66I2n0JlPrSKeO/Ks7p5U2M5998UjjTRAlRLmlmx1T0nU/R1HkKN5e9holO36h5uU+
         Bf1GjKHDbVfv41JIhblCJSReeh8F/xx2RLfFo1pp8wt/Ng7CeqPQ7o6ZdSZDDgwE//09
         GVbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZFp8j3Ltm7BcUHQsXIhCHQ6wXDKtq2g5qE/WvErDgxA=;
        b=eLJ/DT5Nyh/wJfGAo3s0K+Sz8pXVODfN1hX9T9DcAXAT96nLRCo29tvmQb4ZgahifK
         QBTrt4JXyjzgkozskWdsAtkC9MOCrTt+I7x8neHHWbkeLsDHnyJJHwq7DUL4YzDLX5tg
         m6gYXW+FtpHFrcnUo1wSVtGAQL7rHI6UHJRl00GgKatFQHUyTuW7OMz5pdJcBS57LzrM
         rf6K8y2VAvOD/EiOX+vjPoj48sdqo8O+7vywx/Kzf0ke9TePMVz8Nth3intqGNIP+EhB
         WkLCvjesz6UdrydL3SlLgpMV9yldZv8tGxQiCUWRaPdMhLu9vdO1WpQZsVJCsjHzG4/0
         m2Ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BuD0dRpjt12AU4MLzi+I4D/DSj1ZNm1AEa4SmSVpmbz4k+Wui
	6BoCSBrruRcJ0LGuHGv0XbA=
X-Google-Smtp-Source: ABdhPJy+yWJoNzQH5NjeVZdpl/hSXoaFVlGD9SiXtvIQ8aIkOY9cHhhe1xlIWwu8yfLyl2aBSVYvMw==
X-Received: by 2002:a05:6e02:1529:: with SMTP id i9mr1044495ilu.201.1633521459701;
        Wed, 06 Oct 2021 04:57:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1be2:: with SMTP id y2ls2776012ilv.7.gmail; Wed, 06
 Oct 2021 04:57:39 -0700 (PDT)
X-Received: by 2002:a92:6a05:: with SMTP id f5mr6672581ilc.140.1633521459339;
        Wed, 06 Oct 2021 04:57:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633521459; cv=none;
        d=google.com; s=arc-20160816;
        b=KK6VZJynLs+44NNLi0kZN4yvW/5YWZe3jPjp5ErkZ+KsmhxofivEDyBCuVodVHOYX6
         7Z4u8fANmCsQj/pqchwVuiZZPkiP7LP33cI5oo7Bbc5TlSZrqgltasy0thhkLk18WE3A
         sepCiQWbK5a78T4jkWxRsz/DCS1Iy+5TwHJ4V9Yf31dZgbXr3NbjccCnUM97MBiAyBh6
         XL959WElV6r0KFzCQSoCGwsdlb+raa3jYxECi3p/l0S8U+yfAKZNbohzJas3LimFHuRv
         1468MA6Rk4mI6cV/iHMm/dZT8OjkCXgtVvtHcb2nAHDs8n/qMooeP4pKCH9d7C4d67Oz
         KtSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qP8qUdurFon+vS8eyUqKuAmxlr00Ucs7J31uCZEKlng=;
        b=tczDyJsht8S37v3K2Pconc0083C+hT2QjzLwYWl5gZIsR0r7JNusNWz/DKUOm9X0fY
         wThmhmM0w011xw8mqgI3qP0hUSwt372ePTCHuNiMNb/eHvrM9MjZ3Q9lPn5bbyr/xvCr
         pB8gzDq06ZSMiDUKGcXo72wji0FrGqMZNV9Tn2N7e47KyTsEuKuerSAJaKUicu8hFcio
         nnB9CG196BvwONMgmP/IMnjIwB0n+pwp5yhDS/n35qVF7HWQGRNmHA8KLLRUb8x1vVGC
         fAYbfRCxKX9nj4cHZjxULBY6p9jTELkjhJDADksuLnBB5kfgpcljK6CRx8pqm7Z2Hsv6
         5RPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RHqUFEet;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id k7si171211ilr.0.2021.10.06.04.57.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 04:57:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id d18so2441192iof.13
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 04:57:39 -0700 (PDT)
X-Received: by 2002:a5e:9b18:: with SMTP id j24mr6049480iok.202.1633521459169;
 Wed, 06 Oct 2021 04:57:39 -0700 (PDT)
MIME-Version: 1.0
References: <20210922205525.570068-1-nathan@kernel.org> <CA+fCnZdfMYvQ1o8n41dDzgJUArsUyhnb9Y_azgCVuzj6_KBifA@mail.gmail.com>
 <YV0NPnUbElw7cTRH@archlinux-ax161>
In-Reply-To: <YV0NPnUbElw7cTRH@archlinux-ax161>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 6 Oct 2021 13:57:28 +0200
Message-ID: <CA+fCnZc5=fqM=eEZ3RLqBFaxR72bjxndDdnM_rOkiSBi3+2L6A@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RHqUFEet;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
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

On Wed, Oct 6, 2021 at 4:43 AM Nathan Chancellor <nathan@kernel.org> wrote:
>
> > This part of code always looked weird to me.
> >
> > Shouldn't we be able to pull all these options out of the else section?
> >
> > Then, the code structure would make sense: first, try applying
> > KASAN_SHADOW_OFFSET; if failed, use CFLAGS_KASAN_MINIMAL; and then try
> > applying all these options one by one.
>
> Prior to commit 1a69e7ce8391 ("kasan/Makefile: support LLVM style asan
> parameters"), all the flags were run under one cc-option, meaning that
> if $(KASAN_SHADOW_OFFSET) was not set, the whole call would fail.
> However, after that commit, it is possible to do this but I was not sure
> if that was intentional so I went for the minimal fix.

Ack. Filed https://bugzilla.kernel.org/show_bug.cgi?id=214629 for the rest.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc5%3DfqM%3DeEZ3RLqBFaxR72bjxndDdnM_rOkiSBi3%2B2L6A%40mail.gmail.com.
