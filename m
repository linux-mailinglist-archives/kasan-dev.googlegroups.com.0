Return-Path: <kasan-dev+bncBDW2JDUY5AORBMXT3WCQMGQEQLD63YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 7616639898A
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Jun 2021 14:29:38 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id x9-20020a5d49090000b0290118d8746e06sf959579wrq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Jun 2021 05:29:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622636978; cv=pass;
        d=google.com; s=arc-20160816;
        b=g7c+hd1l6pQTaerknESZHJeIVaUdV7Q+5VU4GMgIVe3NWRZCip1ReNTtWeKNc+58kO
         SXfnC9d82SEiW8CXUBTPb537dBo0w7ZKkdKCFEN36ms/DEgxL7EeUwdGTAD8FxSbrAv9
         PwmmjDOl2T+CaV9b/YZWNz1dvQY6BMNSYYyAZK0KfhftHTshYl9tTGePLDPlrI42/TMg
         zngvGxcAGQO5ceE2WxvDjm+/z1DugAYDmJ3nPpTgoO2TtRQ8UYTlc4yCvX/f5VskFYrS
         P6WU+oW12Ume6pY2srgKzb3DBwgus7bIOZLYWvpdOTx1ks7DM1Y5N5TOCMj8EaW69KJY
         +5bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BuTt4VRUt18j9jAjVT4FWjbO75iBedW7e12Re5eXo2k=;
        b=FWHke9lbO/ncw48NGJ90OhN0AgdamtQrzp0tgDkwInCftQOh+K4L/EDNu9hQTtYe5t
         kSxU5P+z4JTCPK9tPVUfTR4xWWHITJnU4mS57UlrzTezBURKKZClhb859mMvYyS6Y9Sj
         L2ANbWCHorIGCQ/kUd0kTNjVVOMXElCukbs1QXRsWnwFiom8KILiZlYqzDOrEndAprZn
         b9WV1Tsdq6e9BCVwBBbzCL/9oOUehfcJCs47sYlyblIGsh8ubgDqAEgHAYsJ9gxfGn10
         6kIm1QWAawpQeXKZKO+doq9+XP23kma/WXDFuWbEUtmc7xxplokeyumLeeVsElrksUq9
         /jzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kz6oMbWy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BuTt4VRUt18j9jAjVT4FWjbO75iBedW7e12Re5eXo2k=;
        b=YQfRTYrDy3WdtmRvMGJ4lFgaBxJ4PTVKsCTt+FAsUTbZKwGLmooVGCjIsaDULPBp5a
         DCic7niM1cLkgDV/msC9cOG7NCzcJQ7/Qx4SJ4bwyccEYFABxZg3SCqJD/lCg8eZCz00
         oNgId77TbMxnvffx+ldP79vlHHDtnBjUIWNyJN3QxNDJazJkXummRDgOcBzVMjBFTtlr
         I/3SI7jaorgUiHIolF/3NwaAAr9HVMBEGD1vYkz1+Qqsp6lDb4aDOvLmftRFTzesHGdK
         /ZeDXyKB2tGztuwRUuTbQo7C/ARw8kKdysRxeYO79zBXlhQD0xYl6WLBQy5zxmo++Fdz
         UMPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BuTt4VRUt18j9jAjVT4FWjbO75iBedW7e12Re5eXo2k=;
        b=pbSAjIi7Y2qyp8s1DVtV2bXmEr47nmunmgwFbpDOpWZSf/LYsWJudG27e1ACVyP1oI
         k8Urw3RHQSO6/WvpoLglFjrq4AOnPxqNjHhRvi/JUl1CjswBx5o9MnW4g8+w5SG8+80q
         2pkmpCCzTSEo2GArLhZCCU19bZvS80rHUmxWQCec7h2cjgIJ1lL9PSEw8VHjCEWTIuIt
         ABk5wuj8sfDhTv2UAv2ZYNqW8hq8mo315m4aJKK1jKtIDpnlfhpO/HGe1NA7zEqSyX6s
         BSl0dnmy4UVXVZ5PiSGPJPZzYfaUz0O58sF80WUZWVR9FaiUCobZY2MJIx5tbkFg1pQY
         0BMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BuTt4VRUt18j9jAjVT4FWjbO75iBedW7e12Re5eXo2k=;
        b=hVu+romqF/CyYwik4KfNxosYpvcbfEoRVEkHwYdlXJ6SjrHOg9OtLDWgr0sbeOjmmW
         c3SkifodsFtNkd6YbHSQNWqKZf5dzFez823G035ayAbJzLUCaymHV4XdofDN440blWMy
         2NeLX/JdKnWcDcq3S1R+jwU/MEw+FK48CeEfsarKxDctYiahFRaFwVxDzyv3ptgC82wk
         0QmY/p1VWln/X6Dedklz7MQt9iPv9Q040hJhtcFVXcjE9Vd98FkU8NkaLfIBIFrIBLaZ
         S9i4pM4mYOTVe7fG8MetaHrnFLxJjrZDMQDqd+C3Pl/8VXTv7yNU8fmatloxeymZDxyj
         /fcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qY62K4MBMo4dKF+58Sc2xeRstHWVnmXOWimC1IXMOlX7w3zxB
	BRLWPWcqkNm8UW9BlMolMOs=
X-Google-Smtp-Source: ABdhPJzoqYBbniUa6ZM2v9fB6C1y1Zp5mdGiLMGu5hRUyhMZiQDUWMsOi0rr9V6q6BN/JGUdMXLVew==
X-Received: by 2002:adf:f346:: with SMTP id e6mr5958683wrp.179.1622636978284;
        Wed, 02 Jun 2021 05:29:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls6118047wrn.2.gmail; Wed, 02 Jun
 2021 05:29:37 -0700 (PDT)
X-Received: by 2002:a5d:58f6:: with SMTP id f22mr21248784wrd.128.1622636977531;
        Wed, 02 Jun 2021 05:29:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622636977; cv=none;
        d=google.com; s=arc-20160816;
        b=X/GbA35X9GBrqoVpLFsttYUbU0cXsswygIOmHbLb7iZ2DKpmloibPPdmW7rVswFIrs
         4sS+zUbXeduEJV4i13p9qoYAWTwomkFh6idyuEGBYLgTHKjBWCxg3wopLdHG3yLfOPAW
         Pk5yfy+VpT1JQIVY2Cnj/Bj/R5V3YGz6gq1U/XcRAk6FxuCOFRPGOq/UtSo2J7A2Wxx5
         gJ1od+accs/ugHOv80Wvp+fBTO2R6bx0I09uzeFjoDrCoqgAuNs5qDubtHJkMnBIfUz0
         AvH76FDiNuD5z2HQCxHD5o0URVIf6Kfu+7pYkEK36rkscsaohXVm6fps4Fq6r1bJh1jY
         kHLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SOLFaj0eZMbhvhU5JE2B3PkFVC/DaKVhxKSu0FKRJ1k=;
        b=eMfuTg28j/G/Nm6PS5qUCehErFDujBHC10WrGoKWrdYU2V1StK+zvoCQLm91M0H9HZ
         3Xzug7gcgu7Lu+4t1faJaIFW6f9KUt2CAdFiQb2NFSOxFg4D8E4cybXkcjm47ztKvlgW
         E4qViNvS3ZeL6X3YqjmJbV26If7rz75d2w0B1Hjy+ZNM/Vpz0gxxQn/m0jH0XNLdXxOA
         ey1gqrsXPqiXC2Kv0PnPjm0T89rMA6rDoeD4XAe8bBj35UwmkZ/VargbMN12OWDg37G1
         zUcaJQt9VsUYr1+F4FoRsqprx2uzwF5K+UhdP5POYP1MnU2l+6fQAId6LuZ52Nnxtw0C
         JafQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kz6oMbWy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id z70si132035wmc.0.2021.06.02.05.29.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Jun 2021 05:29:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id ce15so3588228ejb.4;
        Wed, 02 Jun 2021 05:29:37 -0700 (PDT)
X-Received: by 2002:a17:906:4c5a:: with SMTP id d26mr14801491ejw.509.1622636977355;
 Wed, 02 Jun 2021 05:29:37 -0700 (PDT)
MIME-Version: 1.0
References: <20210528075932.347154-1-davidgow@google.com> <20210528075932.347154-4-davidgow@google.com>
In-Reply-To: <20210528075932.347154-4-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 2 Jun 2021 15:29:26 +0300
Message-ID: <CA+fCnZefz_Jf=bodZnUn3axdMijGTC1+T5nLriQta8BJMK8n5w@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] kasan: test: make use of kunit_skip()
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>, 
	Marco Elver <elver@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kunit-dev@googlegroups.com, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-kselftest@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kz6oMbWy;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631
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

On Fri, May 28, 2021 at 10:59 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Marco Elver <elver@google.com>
>
> Make use of the recently added kunit_skip() to skip tests, as it permits
> TAP parsers to recognize if a test was deliberately skipped.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>  lib/test_kasan.c | 12 ++++--------
>  1 file changed, 4 insertions(+), 8 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index cacbbbdef768..0a2029d14c91 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> -       if (!IS_ENABLED(config)) {                                      \
> -               kunit_info((test), "skipping, " #config " required");   \
> -               return;                                                 \
> -       }                                                               \
> +       if (!IS_ENABLED(config))                                        \
> +               kunit_skip((test), "Test requires " #config "=y");      \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {                 \
> -       if (IS_ENABLED(config)) {                                       \
> -               kunit_info((test), "skipping, " #config " enabled");    \
> -               return;                                                 \
> -       }                                                               \
> +       if (IS_ENABLED(config))                                         \
> +               kunit_skip((test), "Test requires " #config "=n");      \
>  } while (0)
>
>  static void kmalloc_oob_right(struct kunit *test)
> --

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZefz_Jf%3DbodZnUn3axdMijGTC1%2BT5nLriQta8BJMK8n5w%40mail.gmail.com.
