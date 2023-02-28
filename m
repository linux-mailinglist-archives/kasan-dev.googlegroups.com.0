Return-Path: <kasan-dev+bncBCR5PSMFZYORBVGY66PQMGQE3SZ7F5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 43ECD6A58B7
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 12:58:14 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-172b1468431sf5488836fac.10
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 03:58:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677585493; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWGUsu8ZAa3dZ3OSNnQ3vytF7bJzrREyz74PeGm+LD560HDso7nYyf/dqb7QftBO+w
         2hwZEJU7/dZKxAYnpIddWd5uakmVCenI75ufvnlxP/DctOj/GNzbnUePotf4hMt9O0GU
         t7mq5ysQzlE06uy3o06rMJoU4132E/ftBRxCX7RSPJu6st8v0IB6ApkGtFGQGtf7O/Aa
         Lie00+d64P8h8rTy2T4zNuO7YvC9GQhr5C/PA+y0LUqrllTCzAI0r29W/QNVx14/QZ4G
         YWImTFFrZDHSO8II4uCeB2Ug/a3iNgUL6C8Vu4rAdMWXnE3plSYMjpmYca8XGQm4oz8l
         AKig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=eJQ/uXv1fJRRIjVvkeOqvIwfE8FAufCDNuGfEZxyqEk=;
        b=oRAsvOb4O43baNhFOMy+jGhoI88OqeT4Vtqwy6cO/4AfIM+r2a8+EqMNJF4Ifdkgbk
         rph4l2aT4PVmDtvkad5tlt+gJosAHVSiv/7JpBlePqVv3msTEEBl810WkCiM2XYRkkgb
         euP+JYwQK1GKKewLZAAcZmxCiCLTy+oiL08/FhOW6wMNzbXLiQkNqOEqw8/WS268I10N
         oIXLJgaGBUswvUlBkXb6U2R7AV4l9qjfbL3QowdcWbGYofVJdkOkmPdJAlYzhfgcGy7B
         ATkCKoPhgBmCS3UNtHWX6AM1nWjLXZpf35Z8j1qaffZ0Pzio/WQBjB3hNDW5C6p8mAGj
         WOXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=f5n+G1Sa;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eJQ/uXv1fJRRIjVvkeOqvIwfE8FAufCDNuGfEZxyqEk=;
        b=bbTsMiqrLPlxRtCWsAsMD5p1rCkNh9b2HgBlJGOwT/oRCaY7EQfJJ8x1TWlyIGczLn
         ZaXn6uANoZ2Mn0coYlCoHFfekWR3WxF54mBVhvQb+Nk+yXsU9kWQasWX8AmEnfMtCjSL
         lurWPKLcYBC3kw1T9s/ZCNTedrx7I7oRk6gOArmbdBsG3sKoEiWj9g8VxjUYWYGcZIZD
         3WEWbVqeQO+3kzUhwNScTveknps4Q5QknE3tswY5xS8TK1E2UNk4Jq/OlqMhlngz2jJC
         IK+oZtxM2JovJzh3CJEfp5mMEDgUHSZHZvJkL6x5ohfSVb1S12KXWqYQVRwrknkfR9Ye
         sS2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eJQ/uXv1fJRRIjVvkeOqvIwfE8FAufCDNuGfEZxyqEk=;
        b=6oDH7J/IUwaTn7R5i3XcA5QWpu9j8MZAhwjCS3Jgfd2b6dCT4n23HCtvo9xTZ/r0Ei
         vMNrxjy80EOZ/s6rlMOg7hzE7Ycopft5CkayupJixT0l8JfnYDP/rwQ7jTG3eEejlddC
         RPR2quYIeEkzKkJuMgg5jzbRUPSkhHf44n5hxBFewy69g0GyJJCKuuVzwwY89a++U+M8
         t3XwDYSOzmp0UxhqYvYLDxItyuUH65otDe0A6wN0AOoWdJMM5+Z92PPDEEAlHY8/Mbf5
         IZOCzx+srAhPK2W+kd3mTShz04WpuIVuAWZW2yp45RP2s2Em3OaOSSyC9LdsTHd5+NV9
         U+SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV5V2ngXJwZ56xgXqZvsxiqrLsAm48zHoFTE8kFacVoYt0MoGTF
	/xymR9m1ZIx73S5/6vEXLNM=
X-Google-Smtp-Source: AK7set+PPiHsrAStYNtLKjPvblRZ+ehqPJAejM11C80EWaZJFdjSRRWV2CIpQbYx6cr/FBxkoKkN9A==
X-Received: by 2002:a05:6870:bc04:b0:16e:8993:9d7c with SMTP id oa4-20020a056870bc0400b0016e89939d7cmr5462547oab.1.1677585492846;
        Tue, 28 Feb 2023 03:58:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4b87:b0:16d:c495:95f9 with SMTP id
 lx7-20020a0568704b8700b0016dc49595f9ls4890620oab.0.-pod-prod-gmail; Tue, 28
 Feb 2023 03:58:12 -0800 (PST)
X-Received: by 2002:a05:6870:1d3:b0:172:8ae9:81e8 with SMTP id n19-20020a05687001d300b001728ae981e8mr1242728oad.17.1677585492325;
        Tue, 28 Feb 2023 03:58:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677585492; cv=none;
        d=google.com; s=arc-20160816;
        b=XVusuxLZAVKZ9xm/cSwcvU2gpDMuyoDdHI6ysx953ER7nkf5eA6k7g+4V99Xwu8IXv
         XuHpDR8libWIg31UtuSykx63/Yi67a8l/glPoldMdsskIBCz6vWTCg6DP6PRGMAeM86P
         x/ZTLmddD2uGgsQMrFH0HJS0y/9LaiIF01AR1Qr4NVjoVv8Poz/U2zKzSpOxi670JWPS
         F/SRK3V9Epul0MIdzwU7Ek6e1XgtnxM5qg5ZZITNDWEkokaqFcCk3hxd8/lvZR71YiIF
         1/KqrBdxdZ14k6KbmnPFCUZCd0dOyvdvSLpzLLRGl/3z+p7M+BvtOydoagvcZFiscZH3
         4cDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=T7m6rAKgrT8sjyDmNLKdZltCp4n7kd0f94FIxHvHRGw=;
        b=wRh9MygJyN5aqGflJhaE9urnaC8mVS0iadzCVK+SpqVIz9IEPlX0yYMC7OmGq1ZnFZ
         xFjI/h0g+TirOeO7VVTYpqXtE6zgGyr6V5uaG+3g6rMqZ9uwNImipbHECftfgDJg6GU3
         U6w+J0SWNUUtdg8OCRYk0k2lkYhqh/kwWgxHfR5iUvvzZW+z2yjhrONAKgEItymH5I4t
         55Ymobx4Kg9cOexfogltog4xnm+39ChRdB4Re43RH0+mJZEd/p60H3pq5hhGpb8urfWU
         S4Wag8AwAm+wQitKSYM+YnaQduaC3ehpBdONlo4MBoGONlHDISpWNmy1oR7stTW19FPY
         3OrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=f5n+G1Sa;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id nx12-20020a056870be8c00b001723959e146si509031oab.4.2023.02.28.03.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Feb 2023 03:58:11 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4PQwqL0WKnz4x1S;
	Tue, 28 Feb 2023 22:58:05 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>, Liam Howlett
 <liam.howlett@oracle.com>, kasan-dev@googlegroups.com,
 linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, Daniel Axtens <dja@axtens.net>, kernel test robot
 <lkp@intel.com>
Subject: Re: [PATCH mm] kasan, powerpc: Don't rename memintrinsics if
 compiler adds prefixes
In-Reply-To: <CANpmjNNtxW41H8ju6iog=ynMdEE0awa7GYabsuL6ZRihmVYQHw@mail.gmail.com>
References: <20230227094726.3833247-1-elver@google.com>
 <20230227141646.084c9a49fcae018852ca60f5@linux-foundation.org>
 <CANpmjNNtxW41H8ju6iog=ynMdEE0awa7GYabsuL6ZRihmVYQHw@mail.gmail.com>
Date: Tue, 28 Feb 2023 22:58:03 +1100
Message-ID: <87o7peuhmc.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=f5n+G1Sa;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Marco Elver <elver@google.com> writes:
> On Mon, 27 Feb 2023 at 23:16, Andrew Morton <akpm@linux-foundation.org> wrote:
>>
>> On Mon, 27 Feb 2023 10:47:27 +0100 Marco Elver <elver@google.com> wrote:
>>
>> > With appropriate compiler support [1], KASAN builds use __asan prefixed
>> > meminstrinsics, and KASAN no longer overrides memcpy/memset/memmove.
>> >
>> > If compiler support is detected (CC_HAS_KASAN_MEMINTRINSIC_PREFIX),
>> > define memintrinsics normally (do not prefix '__').
>> >
>> > On powerpc, KASAN is the only user of __mem functions, which are used to
>> > define instrumented memintrinsics. Alias the normal versions for KASAN
>> > to use in its implementation.
>> >
>> > Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/ [1]
>> > Link: https://lore.kernel.org/oe-kbuild-all/202302271348.U5lvmo0S-lkp@intel.com/
>> > Reported-by: kernel test robot <lkp@intel.com>
>> > Signed-off-by: Marco Elver <elver@google.com>
>>
>> Seems this is a fix against "kasan: treat meminstrinsic as builtins in
>> uninstrumented files", so I'll plan to fold this patch into that patch.
>
> Yes, that looks right.
>
> If a powerpc maintainer could take a quick look as well would be good.

The patch looks OK to me. It builds for various configs and I did a few
test boots with KASAN enabled, everything seems normal.

Acked-by: Michael Ellerman <mpe@ellerman.id.au> (powerpc)


> The maze of memcpy/memmove/memset definitions and redefinitions isn't
> the simplest - I hope in a few years we can delete all the old code
> (before CC_HAS_KASAN_MEMINTRINSIC_PREFIX), and let the compilers just
> "do the right thing".

Yeah that would be nice.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o7peuhmc.fsf%40mpe.ellerman.id.au.
