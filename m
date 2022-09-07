Return-Path: <kasan-dev+bncBC6LHPWNU4DBBKWA4OMAMGQE4P6C5SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 893CB5B0C5D
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 20:17:15 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1278ff55da4sf4149815fac.18
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 11:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662574634; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xh8fbF6wcvPlqhzZ7f7nt9XlV7bK7LdfZHVljmLIOCzA1cF0i2Uaclcrhxplx/Ps1p
         hOafKj+jQFZXqwcvqW7Bok4aHFSKVRvxkYKlw1i/Lw3f3f5KqZpZp8Gx+7XqUmz9LaQn
         gxB/QOLHZs5OlAr1xabv5bXuaKus9bGpdje6yovpsHGRSuu3jV3/83rFKOu3DURO1vsD
         gnelcpsXhbfpzGfnSQ6/rA63oeXfrSvjfXgEdfgWttVpWRIIEyjBmwaKZAs91WFc5LHW
         i/9NH1UiaGAJQHAwvjokvz7RBj+cwBvuS/PV336hWO8wjzco736UrTBnuVkeJJE/NfXv
         9WLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=LGdjIQlsxusLt14EosA2Zoslb6cNQiE1C2qMO0wAjmI=;
        b=zxU7Bc3G9y6y/l0vNPbWS2JbAo1yLWJf1yAz+oxz7V/b0NVFAJ+rI0KMtlcbFMnqBf
         XJ4iZQgo7Ao2oxIAVXMRqFj8EaVoRIri615NPK4jLL7Ppsj8BnNFyiiOBy4X/cilzTSO
         Qp+yfS5kYywEXqF/PEFvLzwpk9Cfg676npOsxuJ+8eF74lFYPYb5F8HAuzHJAo7H4Fr5
         UP9PFoKibp6PQnGJVlfZ2yjwcJmUv5Xd6wQMmcDtYx6P2lT+4bQUzON8qXP0nZDjbIAh
         z2AHxk2Yv6GntgXLOs0i1XFThazuG6etFLnQtRcoLuRwKgure5GdxbK8DSYFOKkdBZJa
         CaLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DShQGpb3;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date;
        bh=LGdjIQlsxusLt14EosA2Zoslb6cNQiE1C2qMO0wAjmI=;
        b=tx3fSoawY9QcP5q7gHeMGOrTSTAMqLSz678gYVwHrXMQMoRIiHZ6ISRuxyDMzWmIwQ
         b8T2Mivo24lOOGVbPdVa6SnQqn9CCtvZ5P/7aND+BSnVlftLu/N7TLl8c1FH7auIQ+Jl
         LMKqsteNk6aofaqHNi5fItCYzzlDgs8/KwruyoiCBj/q5yySRv7BCaNcGVR4rZC+ZBu0
         9t6ksL/29P3Wz+A1SryE4R6a470MBSpNAOQgEAByVsGmeU//2xsnl7UMf9HGbHLGEgnU
         CoyjUT3Wl2sXueEU6DbVRzIxmcXrwoio6gkriBE4265UlEmcRKSpxBGZ8shEMH2cwfsr
         54FQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date;
        bh=LGdjIQlsxusLt14EosA2Zoslb6cNQiE1C2qMO0wAjmI=;
        b=ad1bhSNy+RlJRs3Kvs18jOX4pJ8+Yg9bO9FOKdgoIa4ODuvOanAWQftuI5B+Q7LcaR
         28ZqbxqVD7K3eL4YYOhpjSApFdBFDsC/pyT2J/VEXKYxjhw9TQBESaxPF87kCHgy/w/m
         4b4rot4Qwdm1/UPExgm4vDs2Wk4MuDAtlPzlBSFNSeXx9k5z3f/cgXqhFbARHGtcT7jB
         JUnWtwqAjwV+s+JGwKmHkn+Lukw96GSavI9gqf7XZSsNDRwqxOD2N8ynpSV4Ain9cnwM
         DnU0qod8WbdibwV9kqCiDroQvMxQVdSQSKJmwvDbW0sZofkDeLjnBF0/lnbSJwsihwaH
         OzEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=LGdjIQlsxusLt14EosA2Zoslb6cNQiE1C2qMO0wAjmI=;
        b=3TDMWu0eSMRMhvXiykNJzKEIOZ/QzPQgiMNufOdaKoE4TZ9CNITvHHawKZLghb4iIf
         wGk5ZdNsi/UHaTTbrzltsPEkYUdAMaP5v1pYy5hvs4r9oxobPxdSFejj0TmSrw8LDaCe
         SmfegGNc7T0Jdl4Sz5MvCybILpJbUCmqNtsZHqqzBKh7qJZ2I5644cIJhjgzaVdHGJq2
         zlRgLLruwxET3XYq3+yWl7gcx7k6nD/wboNNSr2ztNp84iVUnhg+FU16Uf6QJnhmJFLg
         MEuVqceIaswED+K5BFnQpvhzyld8kzGKqZkx1oWoSKMMasje6T3CgRsqKpqZCzt3j+7l
         c8jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo13uWocJBy//p30S1hzGvR6n7wsgq4vAM2jvDR0lHPlc7h/2f4i
	Z3EvJiGbdb1KYS1v0kp2fCg=
X-Google-Smtp-Source: AA6agR7Z/7PdROPNj1XcmQq1ZF2XL5Q8gi+hvped/prsb8KK0Vng98XrEh7bpJMTNBjmviJVyTWu4w==
X-Received: by 2002:a05:6870:46a8:b0:128:b162:621a with SMTP id a40-20020a05687046a800b00128b162621amr450021oap.90.1662574634245;
        Wed, 07 Sep 2022 11:17:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b782:b0:127:7af0:8da5 with SMTP id
 ed2-20020a056870b78200b001277af08da5ls3180565oab.2.-pod-prod-gmail; Wed, 07
 Sep 2022 11:17:13 -0700 (PDT)
X-Received: by 2002:a05:6870:f14a:b0:127:9b8d:7ef3 with SMTP id l10-20020a056870f14a00b001279b8d7ef3mr2427821oac.200.1662574633864;
        Wed, 07 Sep 2022 11:17:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662574633; cv=none;
        d=google.com; s=arc-20160816;
        b=aChvqUawMaZCt5acqr5/MLzKQ/ejnCL+EPjjMBl1KpQBeMcUejgvai8TvxcB4FdELi
         7ao8PK8I9n9AyOYmEp5lyw6FzWgVG0vm9jJMfGn+sUDrDeLbBx83hSCObC6iSRV55A67
         8P+Y2xZsAFAgpRJWedJRb7koLrh/Net0sU9zlKSJvCcl+H9RF+TaLv84FVSKoH1rDVb7
         7f/mk9N23UeG33Fb+UUD07vYhAxbyTwOvWxTDb5ZKa6Kv4QqghIedu7Jfh70oLU7/bi6
         DV+Nqsy3CRJClEQQDfLoekA9Te1d3sdGLJAJkvepa1aXOS0LC6E1C7gW1YkXqCqvd1H7
         jpIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=dubdDeXQwaEqO1LQ7CfpmQjP3T8FcaEec1BqYW1q66o=;
        b=pzCNqckzfJ288G7evdvX7JB+2tEOZS8O/JskzC86V6zmZchNHUHH9noHDR8dnJ4gEH
         fGjSEUBd2u9lfTbgsVeY0/ZXmdfaVbubd0oxPKHrfmnNJFsXIcwbAEuGrhcsOOCIpWvd
         dDmxxMQCks7M1XbxVFlE5sKyjTHuS+S54yPWibmTCe7z5o4rNqU70hfbKh4V/SiE7T1x
         ZPBJI2Am6Mwy/vNA6vFKe+/f+CNmmnEYw8pn1+AB2EY81Bympqti2Z38Px5b53GK3ncj
         daPA+Xxo4gpCeBev4sfIBTJ8X0MXGIAXizGdXtf0H6TC7412ewFbFTzYu8aMN0yFBDgi
         MzWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DShQGpb3;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id y9-20020a056870418900b00108c292109esi3088467oac.2.2022.09.07.11.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 11:17:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id x5so11076922qtv.9
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 11:17:13 -0700 (PDT)
X-Received: by 2002:a05:622a:1394:b0:344:648b:575a with SMTP id o20-20020a05622a139400b00344648b575amr4376650qtk.607.1662574633410;
        Wed, 07 Sep 2022 11:17:13 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id m23-20020ac86897000000b0034355bb11f2sm12538387qtq.10.2022.09.07.11.17.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 11:17:12 -0700 (PDT)
Received: from compute2.internal (compute2.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 3935B27C005A;
	Wed,  7 Sep 2022 14:17:12 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute2.internal (MEProxy); Wed, 07 Sep 2022 14:17:12 -0400
X-ME-Sender: <xms:KOAYYz9s-YN3wnusJ2fYdc91vL5Kq4-6hJzTu7MpYQbxAP6-nspqjg>
    <xme:KOAYY_vMffySFolShRCpI6PTo8XqmS7D65jyGoEyDjuGJJkJWw52_Jd3-_otBycuW
    qYXSFxyM3dzho-rew>
X-ME-Received: <xmr:KOAYYxAhfiDg7OfMpN8U0HDz_Pa4vYTrSve3xaCnF8nLP8dVONtJav76rj0>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvfedrfedttddguddvfecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhq
    uhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrf
    grthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleelieevtdeguefhgeeuveei
    udffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomh
    epsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedt
    ieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfh
    higihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:KOAYY_ffC8cJS0J2z2ud2Drp1GoPHGY4xlnlq9npkgpqQ792dca4xA>
    <xmx:KOAYY4MKPlHFqA3cGk6eoLa0c3YBD9yK7MNiSJNKV_sXPPkcY37i2Q>
    <xmx:KOAYYxnIhiCkHSCVLXGHYNaWwNBmxwSPJSlxDQoIGe-_KO7UXdJT3g>
    <xmx:KOAYY5FDmJAahG7nyhbH6LgSCcv4zdFo2wzTfdDFlVccV9IROooESA>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 7 Sep 2022 14:17:11 -0400 (EDT)
Date: Wed, 7 Sep 2022 11:15:52 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	stable@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Instrument memcpy/memset/memmove with newer
 Clang
Message-ID: <Yxjf2GtNbr8Ra5VL@boqun-archlinux>
References: <20220907173903.2268161-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907173903.2268161-1-elver@google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=DShQGpb3;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Wed, Sep 07, 2022 at 07:39:02PM +0200, Marco Elver wrote:
> With Clang version 16+, -fsanitize=thread will turn
> memcpy/memset/memmove calls in instrumented functions into
> __tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.
> 
> Add these functions to the core KCSAN runtime, so that we (a) catch data
> races with mem* functions, and (b) won't run into linker errors with
> such newer compilers.
> 
> Cc: stable@vger.kernel.org # v5.10+

For (b) I think this is Ok, but for (a), what the atomic guarantee of
our mem* functions? Per-byte atomic or something more complicated (for
example, providing best effort atomic if a memory location in the range
is naturally-aligned to a machine word)?

If it's a per-byte atomicity, then maybe another KCSAN_ACCESS_* flags is
needed, otherwise memset(0x8, 0, 0x2) is considered as atomic if
ASSUME_PLAIN_WRITES_ATOMIC=y. Unless I'm missing something.

Anyway, this may be worth another patch and some discussion/doc, because
it just improve the accuracy of the tool. In other words, this patch and
the "stable" tag look good to me.

Regards,
Boqun

> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/core.c | 27 +++++++++++++++++++++++++++
>  1 file changed, 27 insertions(+)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index fe12dfe254ec..66ef48aa86e0 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -18,6 +18,7 @@
>  #include <linux/percpu.h>
>  #include <linux/preempt.h>
>  #include <linux/sched.h>
> +#include <linux/string.h>
>  #include <linux/uaccess.h>
>  
>  #include "encoding.h"
> @@ -1308,3 +1309,29 @@ noinline void __tsan_atomic_signal_fence(int memorder)
>  	}
>  }
>  EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> +
> +void *__tsan_memset(void *s, int c, size_t count);
> +noinline void *__tsan_memset(void *s, int c, size_t count)
> +{
> +	check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	return __memset(s, c, count);
> +}
> +EXPORT_SYMBOL(__tsan_memset);
> +
> +void *__tsan_memmove(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
> +{
> +	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	check_access(src, len, 0, _RET_IP_);
> +	return __memmove(dst, src, len);
> +}
> +EXPORT_SYMBOL(__tsan_memmove);
> +
> +void *__tsan_memcpy(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
> +{
> +	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	check_access(src, len, 0, _RET_IP_);
> +	return __memcpy(dst, src, len);
> +}
> +EXPORT_SYMBOL(__tsan_memcpy);
> -- 
> 2.37.2.789.g6183377224-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxjf2GtNbr8Ra5VL%40boqun-archlinux.
