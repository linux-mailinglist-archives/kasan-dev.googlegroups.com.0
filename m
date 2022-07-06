Return-Path: <kasan-dev+bncBCA2BG6MWAHBBT5LS6LAMGQE4BV5IQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CD045691E0
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 20:34:56 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id o22-20020a05651205d600b004810c974c17sf5420425lfo.23
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 11:34:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657132495; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ye0QbEj43mrh88U1VRHdsmLiPA3ETsdpNxEjAHihrjb6MUNU1sbMJlLg8+t8fr7RN5
         WmHMPhcXXx3dvtAWEveag3j+clMOse0mj43Km176Aq8J2Su7V3czJoz6N2XMpx7bKHA2
         u/PjUn36fmkpvqHO3PJL4GxciRS5zsMkNawudgbSS2LJcXc4RVKyy6EgRyDC20i1dHGx
         e5tdEhzfK3QlnY5flM48uzmKEtrA9/gZ7wvjThFPHa7CN2HEZKUlnj/bCIZXPP2Hik17
         A+VPOrfw8xiul6rU30HuYrDgjo04KTVUwLjuk2jMf239D5XG5fSoFHQhVjoJkb6W7iDK
         /sJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x4k+heDBNDEOHRfw5jakAbGuwlqA9usjIKOR3Ay7dig=;
        b=q8W+dAOX3ypz8Qql4Gj2iHzP5TVfaEoiB4IW/eFbZLRlLN1YLrABaUT3lSs5R//Z0m
         I5LTGgLdblXLW3TUiHhOCQC7HqoYYx5qzo1gIhBexbNyO9d3EVT03E7ET3bYQTuAFuKx
         F/Azb2GOv7iYeZiT9pSoDEuo259SUMjhN8cmZxWyMQ5yuujcZWKIHnopQdGttXW88BlG
         pYuoqmsrRcwrn3/dXs0Gjfnb4AHejM1/+t3JHhSLznEeSsye4khUs4JXCa77ROorcHEl
         tbTVI/VPseVPwRqFZ7NprkleGn6EA3On6iFDi0ynaxt0aBGdZpiBH+Sb/ERirWxLjupj
         nTjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K6UVv820;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4k+heDBNDEOHRfw5jakAbGuwlqA9usjIKOR3Ay7dig=;
        b=CmSnrQqSDMXU8LTmlyZ+2soXMMfydqAUziCiUC/pftLGf55nWSJYdmYJKG2yX6iQRn
         jUeZ6ECtf6qcgpnD7AWjsxqYENriBHNTVW1mxcfXWL5BQ48ShUv2jC92TSLNU4iDMmug
         QFyMt0Ar+N6gfJ50UVJA7hR2i9il8ZjxOwvZvTH/0H7nuhpGz0QM2GYpc3g5DlCVTD32
         aq8+YeZxuSqgQ0qPIIG1PBQMutvAROsPdD07rwJmKxhbKdChr3B9N/M9BMAD/ra9BgCH
         8aJGe4Xt2Csq7vWrk7uqjv+eeq9XHS22xYkPxn8zUNKqLsDKm8dpfBW6i/pBv5xEwIx9
         afFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4k+heDBNDEOHRfw5jakAbGuwlqA9usjIKOR3Ay7dig=;
        b=mmsbdxiXWll8iidF3rZi5VvegU7HJc+IDA1OtjuCnfjeWHxeceFdckzXEennGpnF1y
         jMzDZFpoGF2mR3F3oeKlIdqaEYC0M9dCJVamIvLNO2zmD5GPZiWjiejz8Tk7Xhtw4Zjk
         Cj5RcIR4N1LIAwIGZTm9n6KsO6OXNXbobCmOxo8OHDQFhEmAu3+LNlS4IVNaEseHXIct
         cj9p0vDS1/svgF3JKedahGgzjj5EeAc+NL/vn7lxbA7yskkaeoaR5Pm7CzK6ajUIIpDf
         3XgqO4HVjSXjg/AUwAOdeZGYWqbhCUbeS9Xcv8fSYf6PtVvsS1jKvmQPWGE97E1JJdBv
         AN8g==
X-Gm-Message-State: AJIora+qZWZEZc76VgTm8YBgonmvjtR2jsqJLqxerlzGzjbSsdr3oE1E
	iZzdctvRJ8P5oQJCaehPDJA=
X-Google-Smtp-Source: AGRyM1tWyCi9+PHuGffAmt8OuIPhSS9PnqUkrRoa/wuDpechAJ5r3U+rLv6jsAMvSW2KL4v5/bPhJQ==
X-Received: by 2002:a05:6512:6d4:b0:47f:74b4:4ec4 with SMTP id u20-20020a05651206d400b0047f74b44ec4mr25991222lff.654.1657132495632;
        Wed, 06 Jul 2022 11:34:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls520075lfv.3.gmail; Wed, 06 Jul 2022
 11:34:54 -0700 (PDT)
X-Received: by 2002:a05:6512:3b22:b0:47f:6756:143 with SMTP id f34-20020a0565123b2200b0047f67560143mr26349017lfv.419.1657132494525;
        Wed, 06 Jul 2022 11:34:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657132494; cv=none;
        d=google.com; s=arc-20160816;
        b=VfA1cOvUvzdXhxekZrMlhblHONjtjjwL6v1xiov1BX2/E3d/W0WZYArlIvacwBMsZI
         ZQD04DDEQplLGiUTcsfZYcAaR8u5hjge1xtsn+a9+Q54+QR9feOv6wLskuN/lA7V1/s3
         +9w/8oDmqjvM4Rc31ht020hUZmAqD8Dr3TP3VWy8lFgKDbgMc5CMDlamlUI0Y8Os9/50
         bTMyXcLA2fyYPmD9s/Lea4dwLAtn1n0/2GMOAOplWJDcIbu+Glb7PE+gM0vzr7Z52Toa
         MlBKQSEnkQakEOQn3RESagokIZuzOb+p8XBzRVsDNwZVscC2TnGGxSiB6GRvqwU7wmn6
         Z14w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lG8GWm0pmr1Neu+cMWEfjz23I2y6CFYI8JxXePQozTs=;
        b=WymeiZWRhWB195IazGZLlOzJIMdmeViwY2vmLcd1u7ycI3uF9rVFxdYKha42BUeD6x
         rdnjBZbdgUZTuVA0d38uLb92aQbZ+WH6SaloGCQl4vCk8K4Y/88+Y1/Iv/lUWhHCLJ2k
         p0thtJdar4KENyLsjt8u+vVnc0ZNEtn9Lpjb5dMswPlVxrvbcA5Fac7c0XoUzvqZpak5
         GfRKfeikCAUdOwCszxKDdEvl5aUYPMVgbHqEuxlVYJ9Dy1Rf8hr+vvW5iiRQEflYhZuR
         UbMgHuPnLNfLpocSdgNoyamUG4zPSdZfl4BwSIjDlD3/hLooh6PZcpa1d+YS+hQKAEdV
         UtWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K6UVv820;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id b23-20020a0565120b9700b0047fa023c4f6si1524947lfv.7.2022.07.06.11.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 11:34:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id x10so13003193edd.13
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 11:34:54 -0700 (PDT)
X-Received: by 2002:a05:6402:201:b0:431:665f:11f1 with SMTP id
 t1-20020a056402020100b00431665f11f1mr56090922edv.378.1657132493907; Wed, 06
 Jul 2022 11:34:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-2-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-2-dlatypov@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 14:34:42 -0400
Message-ID: <CAFd5g47NFMnOWioSws9k1S7_qhHGnF0rhB4bHy5FaseiMi95fw@mail.gmail.com>
Subject: Re: [PATCH 1/3] Documentation: kunit: fix example run_kunit func to
 allow spaces in args
To: Daniel Latypov <dlatypov@google.com>
Cc: davidgow@google.com, elver@google.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K6UVv820;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Wed, May 18, 2022 at 1:01 PM Daniel Latypov <dlatypov@google.com> wrote:
>
> Without the quoting, the example will mess up invocations like
> $ run_kunit "Something with spaces"
>
> Note: this example isn't valid, but if ever a usecase arises where a
> flag argument might have spaces in it, it'll break.
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47NFMnOWioSws9k1S7_qhHGnF0rhB4bHy5FaseiMi95fw%40mail.gmail.com.
