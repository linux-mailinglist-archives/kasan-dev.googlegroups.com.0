Return-Path: <kasan-dev+bncBDW2JDUY5AORBEPWWW4AMGQEI2ENQJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D620999D7F3
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 22:12:03 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-539f7d8bffbsf531773e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 13:12:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728936723; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lqwl7hrRTc+gk6eJT9Zpmwt2RvbqFpbbbMMT31ndujHozN2DY0u4em3GHjc1cYEI+r
         WCuUuW9sMdlQyvDJYTuiqwa1ocadcJpigvYfThgWTcqPXPM3/IOCmDrYzogzcbcsVG3R
         3Ykcpsfy15eJ457tYzwYAwevI3wbIYfF0gThkvV5515Mt5ihXZTMIy0V2SRRUxnvoR9O
         Y7nvqOqimDuxOIxljrcHW6swJ9MPxiDBpXVqpFhhI1KLPY54ulRd7t1lHCXHqPTjHAcM
         rPYaOAWR5L98qoK7Le7lhyGenr2Uh2uf2ARiNWd5tl9MFuZkL0D469dBVfGExy09+ZD3
         vXcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0TfnJAjYSB/uPG5VdUW2nnx8bituDEgsSFWLxlbrel4=;
        fh=HeeDV8Ex1GBeiMCw9++7kTyYhf3wjj+kfxhTATs7dYQ=;
        b=FLjhCw6oM15VkUSsd9AWEK2cI0fS1IpgpNTP8DKGFXRW8oIVA0G4Tk/eMB1XXtV3tP
         fhXDS3wu6IVTv/Q91yU8vPIADHinmORBfq3O8UpD8bML9Fw2dVM6xoL9Fj3isPADlY4r
         2Vulzzbtu1HjFYjoBdeN+VQiEEZXN14JQ+T6IyIzlIhpLRu7i8YdhsEWYTr8Mwf87zUa
         ZHm6eHPGGO6DQvtPjyUDL7N9kSL3GzFAoMozmGDJJ2mc8LREkfH93n4tBp/fK2qKbZfL
         BqllKkzbJMS5QGaRRB2lWYaF1y+cL4IB9mUk6DJGTUENoRlLvCt2XpOpv1uDsua++yZO
         oOsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lFmNjui5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728936723; x=1729541523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0TfnJAjYSB/uPG5VdUW2nnx8bituDEgsSFWLxlbrel4=;
        b=NB/62Sq9PqRO51MqeZUgcC/R8fsfT0UODCSna7scJlsODDrf9udDCrFBBLjkBX3FOU
         Iu75Q4EgWfpLeafvRhlorlumvCzSTX0pha2Fxy58fkUATy2JGEmAMZszcygwTuwbGU6E
         3QFMR56bVROI85s3HiCZOJBwx6ab+du46mAS4FWPRGQgRZpPqXDex6Q6ioM2txID5Kc2
         9a3HmGfJDcYjaW7CNinwHRCYJ+zX5P28VEimEkM+DteEJJJWlRYQyHwAU14oUbBLPoms
         oaIeSS3McbbPs3XDTSyN94BJk5B1gL+xbEXBeyXNnH7PqPQROF6sVgp+DbPsG0CcqXBY
         gbrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728936723; x=1729541523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0TfnJAjYSB/uPG5VdUW2nnx8bituDEgsSFWLxlbrel4=;
        b=KXuEI4/orQYlG7x+2vInGE5TyQNrMNT8fCXwIqe5X/ckFd/ih2SF9ZZCXCDhc3X5am
         TI9K6DL8FiBM9hAo3k4CsIMVylzflC85QhKkUHC2Z2J06lPnVWVRJPGhE/Zqxo0k4u+X
         1ic6GKhB6HcwpBg0UKZF3mwi3W6p7dcXsabbdIfUZ4E4KC/ptlNVgSdFLwFIG9NjO3oM
         qOxtzjLGrUKvbVy42n+lIKoYCFmACJ2IEyiivW+6A6MP38j1E11mJ5V7epNxaYd8gywP
         4NYBt/7US4MBEMReL8L8z26weVDkmoAW0T/6fuVGAwUiNDokfzqNaJmX+SYfPPmMoWSk
         j+dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728936723; x=1729541523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0TfnJAjYSB/uPG5VdUW2nnx8bituDEgsSFWLxlbrel4=;
        b=iT7BbQiNVTYsU5p/OROZXA6vwXMp+3O4HDl0ijiu96G0pFFlVhCv083zrWvLMF1iqP
         zvRvGgth1M48dEM2bVovn/GsmO8b+SbmwY7rXkdYUofVpLojIufu8GWdE1m/ySn2WeNP
         yCbUnbNtlIsjyxmWFTuNxpec0lMaRjzyMma5sE7PqK4SnR2iLpy8BZi9JjlI5Kn/bOG0
         PK05pBbsZe0jSIFzQl8zCrz5op2zGy3sme4gac1r60M+ihaCV5PHSg12G9AHkmxCjcJy
         SrVETbV1m0Rn9y6t6mwq77/IaJGp9xslUTpkso6P1kzxeCHw1mI3bZx69AVMyJ6Xi9Iw
         tvMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwFFZtukxyTCw2yXa92UH2dXqfffGpeeTs26qgsfxXoY4zS3hLOZRXM1L6yTN0dYQHM630yw==@lfdr.de
X-Gm-Message-State: AOJu0Yw0KDSbz8mZ/tfm3wvkEQXIbbnFtr4XT0O34TlgiyEjGp+JH7KN
	v8RUse96tJHaoTqbd7fxFdEaz17xQ7xwgDuDhDRzAGaUdpiUyVkO
X-Google-Smtp-Source: AGHT+IGNPQetNiEP95xj3l7QuW68bhhRKeUOU3ZnOuVultHtvilfOmWQ9JawdX1J48W4WGcyo6yo0Q==
X-Received: by 2002:a05:6512:3b0c:b0:539:ea33:c01b with SMTP id 2adb3069b0e04-539ea33c18dmr2431083e87.9.1728936721603;
        Mon, 14 Oct 2024 13:12:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b2b:b0:52f:c72f:ddd with SMTP id
 2adb3069b0e04-539c9b6610als1322932e87.0.-pod-prod-00-eu; Mon, 14 Oct 2024
 13:11:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIZco24JHvR+HzsUGvEkdBZCyT4hE2mJRVyISe+x7u4Y62/TwgGAFbYN5+03IlKB3D9Nf7zCIRbTc=@googlegroups.com
X-Received: by 2002:a05:6512:3f0a:b0:539:8ee8:749e with SMTP id 2adb3069b0e04-539c985a7f0mr5861823e87.3.1728936719158;
        Mon, 14 Oct 2024 13:11:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728936719; cv=none;
        d=google.com; s=arc-20240605;
        b=WwdLKABmZubMQSp+e9XaonwrNGZDQQuZVfA8e3e5OwMJVBg/f0ApcuQ+y78YEO/QuN
         NnMgGfEURB9KOkQgpH14z0AU3FDbCZXTx4iLKqfuHeu6pf9UW5X3lBguTMT+dlZa530R
         m356KbnktHzvngjtLJhQ630DxUHSvNNdukAtqZFOD5mO/7QfP7Wgbqk3pmDRH3hwj30x
         fXykFGZzYRiySPYh6HB4dcm+pVYIyu7cEkpbDAD3YwL+rXXvOAh0PeUE9kfxJlTXGArw
         DBSx7xDIOAea8qL6as4APSaNg8XVdjNGRldhLX7xQbFFzxdpCXs4Af6UWt0VOvmTBplS
         lOxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=soeb6YbR58TlyNb9WlOFV9xKVMAzyllWqObFU0oSEYI=;
        fh=DyA1Sgrj5xpjJDldOGq8ialU4FuOPu9ZHuw6QqQ87NU=;
        b=k75y2vyp1bFu85S2nFTGVekLvWYcAiqCSfJzUaHhEHbT8BBcOAnIEfn3/7CC22LPqq
         ejB4OkoCh6xp8qT9dmq90JgGVZh3px5JJu0lTDy4haBS/EnbL2g6Mwg+FxiWDpCwwZH0
         gFZNQc8Oxg6ImvTTViFm1GEx3ZYtwgjMV4UqmsyWdzLt3m8Q3jmL1K9TCc3juf9UD376
         TSJyx4TPovVMbyTO8dnZjnBK8zEFYlGXIxkxBnRdxEqzXmOArxMSxPPdr+C/DzzGA3D7
         4D9Gckl2rqS/HTUoBCwZqcXx67VC4657/slS9YeHviU52YXtGl5Soid3zB9ZBK2fB4uc
         8HxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lFmNjui5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539f1e3cd5csi62956e87.8.2024.10.14.13.11.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 13:11:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-430558cddbeso31402875e9.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 13:11:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVPuVLp2RETlm2Jp4+CszUXvE+ASw/D6ScI2olkSTFQpC/Fv+7drrUiNB35HjU5/VGpe7qDiwGaQQQ=@googlegroups.com
X-Received: by 2002:a05:600c:1c9f:b0:42c:ba81:117c with SMTP id
 5b1f17b1804b1-4311d8914ecmr100623995e9.6.1728936718148; Mon, 14 Oct 2024
 13:11:58 -0700 (PDT)
MIME-Version: 1.0
References: <20241014190128.442059-1-niharchaithanya@gmail.com>
In-Reply-To: <20241014190128.442059-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 14 Oct 2024 22:11:46 +0200
Message-ID: <CA+fCnZegGx3hTV5=Tfu1VUih80fcbGN4bxKFi8RzonMdUW-OCA@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, skhan@linuxfoundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lFmNjui5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 14, 2024 at 9:08=E2=80=AFPM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The Kunit tests for kmalloc_track_caller and kmalloc_node_track_caller
> were missing in kasan_test_c.c, which check that these functions poison
> the memory properly.
>
> Add a Kunit test:
> -> kmalloc_tracker_caller_oob_right(): This includes out-of-bounds
>    access test for kmalloc_track_caller and kmalloc_node_track_caller.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D216509
> ---
> v1->v2: Simplified the three separate out-of-bounds tests to a single
> test for kmalloc_track_caller.
>
> v2->v3: Used the same size for both the test cases.
>
> Link to v1: https://lore.kernel.org/all/20241013172912.1047136-1-niharcha=
ithanya@gmail.com/
> Link to v2: https://lore.kernel.org/all/20241014041130.1768674-1-niharcha=
ithanya@gmail.com/
>
>  mm/kasan/kasan_test_c.c | 31 +++++++++++++++++++++++++++++++
>  1 file changed, 31 insertions(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..7e7076e71de0 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -213,6 +213,36 @@ static void kmalloc_node_oob_right(struct kunit *tes=
t)
>         kfree(ptr);
>  }
>
> +static void kmalloc_track_caller_oob_right(struct kunit *test)
> +{
> +       char *ptr;
> +       size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +
> +       /*
> +        * Check that KASAN detects out-of-bounds access for object alloc=
ated via
> +        * kmalloc_track_caller().
> +        */
> +       ptr =3D kmalloc_track_caller(size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');
> +
> +       kfree(ptr);
> +
> +       /*
> +        * Check that KASAN detects out-of-bounds access for object alloc=
ated via
> +        * kmalloc_node_track_caller().
> +        */
> +       ptr =3D kmalloc_node_track_caller(size, GFP_KERNEL, 0);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');
> +
> +       kfree(ptr);
> +}
> +
>  /*
>   * Check that KASAN detects an out-of-bounds access for a big object all=
ocated
>   * via kmalloc(). But not as big as to trigger the page_alloc fallback.
> @@ -1958,6 +1988,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
>         KUNIT_CASE(kmalloc_node_oob_right),
> +       KUNIT_CASE(kmalloc_track_caller_oob_right),
>         KUNIT_CASE(kmalloc_big_oob_right),
>         KUNIT_CASE(kmalloc_large_oob_right),
>         KUNIT_CASE(kmalloc_large_uaf),
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZegGx3hTV5%3DTfu1VUih80fcbGN4bxKFi8RzonMdUW-OCA%40mail.gm=
ail.com.
