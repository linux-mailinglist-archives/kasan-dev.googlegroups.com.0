Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GE2SIAMGQEOXM3R2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BEC4C0071
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 18:50:55 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id x16-20020a6bfe10000000b006409f03e39esf7671682ioh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 09:50:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645552254; cv=pass;
        d=google.com; s=arc-20160816;
        b=fwyQoo7ZYuWsSP0slpHe+WtPFg1EryVGFqf/08oCPnTS68UywnvqUb/L9uWWAacEqg
         FNQvejXlxyop4yaF7bcsYziH2OT8bemwyFh+8TCbtyjqDmAqU1vla+1QR4J86aaPw8HE
         hIgOy4bM2vUyuENzmeCB+374RYdZuTHlx0/nUWthw/30cnRwT4mzehKAt2leNfgDnxIh
         qPNrCc9AOUDAtxUiYkjJXDyYwaEt4We4Vzg8t7wfMly8x6Gk4XZZfDUtxcvDwVSwAsOQ
         OzQ+R20o0bnf3x+Lm+1k/vERSxgWncP8Mw0pwP1IdjQb7gDgdveQp1NYyoX2aGX/e5Vp
         vyxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nwm9dH8cxQOI2BghncLKuLILFjsm9OlIn/tRuFw5k1E=;
        b=lL+8Q6Lm8JRv6DOtwXjAVdc3eo4SZmiazKRa8vmjbLIQBWthVWDo/KcxurP+5xiiR2
         PK3Y7CK3c3RA00Q4hSFZkQTpHv9hRlU3/seSDrxYghVT/zRxiu4Lz6KEc8M9i5d3I1X5
         0oBIS1R+6LK5jMr0yyP/Ji/TP4vEZJVdB+lB+uUq0aYaf0v5yLrd7EQgQyYv0C30WVjc
         Nsh0s29rGKgrVSiV8ezDv9ya2XgL95je5Uxmp15e3jNR7nqvVCwEtdiX6XodjLTwXeMT
         WGlOhXFRM9Q1FRnEaNf8/WW5T++9TdvIX5+TZWTZdVT4iyE9BJaEe7wYZSNJoj0h0PBe
         rm/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E7oEHcm+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nwm9dH8cxQOI2BghncLKuLILFjsm9OlIn/tRuFw5k1E=;
        b=j3nc2pFnsQZvmqJLbthhEehoS1nhEUZyhAU7Wvaf12QIwQGUPCsFbxJNvb2xgx3dcL
         w787Mfjw2qbwQvzEAWzm4mCs62lYldWTTDsGiw2lTuG3cFOQ3SQhsUMI5DjYtC3UFLrN
         m/F5lyd2bXVTSamkrpiAwheCWVzzSTOauI94dX79zGjVX4TGdaT2vLk0GKujTOYGNCuR
         VojoXkOlOJ0Nmy7kF0CnAk2GeVnfSjaqdblolEVbODkosBV+46SCotKTmGDeht8vWxb0
         hDNUgE/WDF+qTWeTrpCbuGE+rx8yT+lWV+DpqdjaLkkLj73rQ8Wisl2gm4UWzW+zmnF0
         SL4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nwm9dH8cxQOI2BghncLKuLILFjsm9OlIn/tRuFw5k1E=;
        b=e1HPBjlJ5jOIJ+VA3YhIitdRuYLdirEPJOaWJDyDxoj1Rk5Hn5wdDuWfQc/dgigVYN
         WVW195lFUuM907IZBL7R3lfd1sJzYd5vfucH/zZmW/eHPTqkQnAWiE/BpFhJk91RGAfm
         O6Hg9TWST0XsxypNhiXWkQYaATSg+ts5FaFOfUlczXUG02LqvjuzIuIx6grqz5Rjr3NU
         TJo/Dww8QvVNjkfvBzuaRjOOvroMuVB86EQpPzwglOfuEm229ZW/bstZeZSqqTPto/3w
         supr/LnBinRX1ZejIKkuEst9HvyfexNs1c2lWqFCWlCwz1eEIoPsHuuRyisyJAEANCYo
         1gow==
X-Gm-Message-State: AOAM532+vGXRMSK04iILZsbkSAlGJ4UelfHgNcjQdQKF4pCWX0Rytid/
	CZ0hfQkoW1hKtNy846k4m2o=
X-Google-Smtp-Source: ABdhPJy2eKw+88zj914ayOvp92BECVXG8UI6gxDwh/7eh2JYFmS6Vmx4HaQjW5sWAU0vyW5djOn6Xg==
X-Received: by 2002:a05:6638:3805:b0:314:fe73:ac15 with SMTP id i5-20020a056638380500b00314fe73ac15mr5281217jav.153.1645552252460;
        Tue, 22 Feb 2022 09:50:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d444:0:b0:2c2:6d0c:9366 with SMTP id r4-20020a92d444000000b002c26d0c9366ls309120ilm.7.gmail;
 Tue, 22 Feb 2022 09:50:52 -0800 (PST)
X-Received: by 2002:a05:6e02:20ee:b0:2c1:ebd3:5a5a with SMTP id q14-20020a056e0220ee00b002c1ebd35a5amr15106272ilv.276.1645552252059;
        Tue, 22 Feb 2022 09:50:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645552252; cv=none;
        d=google.com; s=arc-20160816;
        b=PRrcmMBbZd8QKAImu/5Iuej9+G9z8Ft1+/5sTqnc8pqw9uQyYf2IBYva+BlvymZnEu
         TkEWM2BqGVWHXeEwFZ0xt6DciRiP4Olrc/VKZruYJHSd7RgY2Z/t3+TF9orLWSDMpjtW
         HEB2Dpd+D9eEtmbbwNio+yM7dK6R5YTvsV9xbUQNSOrXOOCvuf2o3DaRP7RZFGMVqPZw
         1hdsRUGRQ7cTCvwquJ8LztgoQE87Yx6HJTgADywgKcn88MssfQBYnz62naYSqxQ5JCxB
         M+QGpbLwTiVgjYTUoa9qzLak+WpqcCRwQ9NQ0m6p19XBta6/W7fea+dO2aOzal+kkvay
         BtNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n9xVaMbyiCTyGVqLYvVRvUgZYTi80RFry9SG8JbTIuM=;
        b=Cm5khucI7HGFAy37m57XHCUZRSaqQ+/iGsnS/f7GYsKnZwIeahEO4LhOTfrBob+A5K
         X97WBomK1XdJZOwlQBRiBGVV+K28iccn16zlQ3a/oVRB83eFDWFsZClrwokqd0864Ybf
         gNmqPYM1g9a1xWUYuiQeJuSqs0eYIi4Pj0W6FVynVoVhtaMD3dCl+gmRKZ5zPyiDas1+
         7s4VFJfewrGLeagPgB0fs+e0u/6ALbuH7oDLBw/FKOFQbvpKDfva5W2x8u29Jq4EdaQv
         P62RyONAjGvBWoKUy2kO3hE84cLusLhowx4I5dPfs3Cw+tgd4attTKfbliSxQj0DuVFv
         g+8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E7oEHcm+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id h12si907595ila.0.2022.02.22.09.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 09:50:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-2d6d0cb5da4so128400137b3.10
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 09:50:52 -0800 (PST)
X-Received: by 2002:a81:743:0:b0:2ca:287c:6ca2 with SMTP id
 64-20020a810743000000b002ca287c6ca2mr24456433ywh.327.1645552251533; Tue, 22
 Feb 2022 09:50:51 -0800 (PST)
MIME-Version: 1.0
References: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
In-Reply-To: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Feb 2022 18:50:40 +0100
Message-ID: <CANpmjNOnr=B_o83BJ6b1S6FKWe+p2vR58H8CHtGPNPnu6-cQZg@mail.gmail.com>
Subject: Re: [PATCH mm] another fix for "kasan: improve vmalloc tests"
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E7oEHcm+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Tue, 22 Feb 2022 at 18:10, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> set_memory_rw/ro() are not exported to be used in modules and thus
> cannot be used in KUnit-compatible KASAN tests.
>
> Drop the checks that rely on these functions.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/test_kasan.c | 6 ------
>  1 file changed, 6 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index ef99d81fe8b3..448194bbc41d 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -1083,12 +1083,6 @@ static void vmalloc_helpers_tags(struct kunit *test)
>         KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
>
> -       /* Make sure vmalloc'ed memory permissions can be changed. */
> -       rv = set_memory_ro((unsigned long)ptr, 1);
> -       KUNIT_ASSERT_GE(test, rv, 0);
> -       rv = set_memory_rw((unsigned long)ptr, 1);
> -       KUNIT_ASSERT_GE(test, rv, 0);

You can still test it by checking 'ifdef MODULE'. You could add a
separate test which is skipped if MODULE is defined. Does that work?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnr%3DB_o83BJ6b1S6FKWe%2Bp2vR58H8CHtGPNPnu6-cQZg%40mail.gmail.com.
