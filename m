Return-Path: <kasan-dev+bncBDW2JDUY5AORB4G5WC4AMGQEHLZGYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8272899BBB2
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 22:34:58 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-539d87244besf1963892e87.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 13:34:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728851698; cv=pass;
        d=google.com; s=arc-20240605;
        b=KK2d4He74+PzUAL3pf7bLD74g2tWOcFwmk/ov4mldhcvMGHVZL3ou25py4YHZTXpmM
         DyV0qWlWZK7JYvXEkO9zpwvptvTiwl2xI/cjNtogjD7u3iX3gyDFVZdHO9Q36JoaXI0U
         Lmzh3E7ktIIw0TaHFgxQBHxUIaUawJqDA0igoyf34AGurl4y4K5FcnOhwqr4OK7e+aOd
         VQFepVn9mUa93iiSLOuDQQYo8qA6bfODQbqHl2cfuulXgiLEwld56mEVY97s7CirPJSM
         dwG1bj68YBNmYgP9Yd0eR+0Ugm/DYQqK0K15MzT2/8c8RumP3a9HuZJ2gyMTFRYNW23H
         WRug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=iUu4KKSSVUE0szCdNNcQKNnnnV0Iyaz5YVB+4Ps8fBE=;
        fh=KvMSE5TjuW1XpWdVLmXfDv0NoDA80MKi0yrMT4olWys=;
        b=QKl41UVSInVKy3DCDPNxcb6vHqljSWkoNGIEMnFvA4L3ZzMrrEFwJQQEqcFDIZZk1X
         4MkTTkmdjhhJ3L7DPcz/9iiC1AM+cIAmWUQVBhrMORgwgFY2WLroeFvP7hncgvzE0yl2
         R40YE1HujNf8XNsEU2jrCBJFPnfILT23jj6e1TsE5Br7bAcbblyCUM7dx1yr94IetSaN
         RfcdJ7ViXQuXmEr7Bv1mTmOT+jel8VN6Ceuqb5VTi5V/m0IQAudKQ0jF2Ksb9MGvtdpx
         4KpgQkrc7CiJFi/H1kPcVACX9a0fVhPXeinFuVJJ3geSyZYpzb8DeNiRpGSjQ3wA/dQf
         5YHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c8wsJU4d;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728851698; x=1729456498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iUu4KKSSVUE0szCdNNcQKNnnnV0Iyaz5YVB+4Ps8fBE=;
        b=URTgGJS/1eM6xrBgJy4U67YmXkBlC151VjgMGJDHngf4WxX+LDg5SVXdNsF0Ylh6Hf
         /0YjhHP0T/6f+GyVeYQ0p/vffnLnZwPZiZ2XyYj0r1vfAIduqynTYz9gu5haY+0/uC/7
         KWVg1wpL3SQpVLbXuVXm97ddr7JT1EV9nYZHqUfHamTm6Zp2xmydWP6U+U8OMgUgYc5i
         U/SBrsn1tig9z+Nc8xtewIL13m/b025vj8PtbzFuqXomVGS0yruOKncoV4DmMGBz+kgQ
         CHRTg9Y0Fmk55Sdi3YmL9+RBgrprhID04Wwsh5BNLBu/ydR0cXl8M0aTO/ugQx6+o8DG
         uIeA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728851698; x=1729456498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iUu4KKSSVUE0szCdNNcQKNnnnV0Iyaz5YVB+4Ps8fBE=;
        b=j8367sc0vs1vJuJUhLeXGPKWylmEtCWiWMkRM3h46YLS5N4clEgNjx+iJjvd7+vA48
         vZ2LJRT+g9BZLdqRBd4Df7gs+a85G3F0maMTxFsYOo7urF8Ic92H3Ef6d6b+Mjj5a/HA
         nhUmM5JCq2G+WqJUA8/6MGNLAyrSPzorQvFQnS+URMktrisgBK4ECtlxF7FTWPK3HTmK
         ZjXQJs2p3LEN4wwWde3+l9TS7JEzyoV3WzNTHSjpeCYJ1SWaNBGrRZFWRABeTw7BERQ0
         BawHH4HlxOehGhQGvihmAlLlhz6q05uUiwBGrI/TpeMK/8jq8PT9B3VQBbGEukjRyz+P
         6CLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728851698; x=1729456498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iUu4KKSSVUE0szCdNNcQKNnnnV0Iyaz5YVB+4Ps8fBE=;
        b=WZEafZ56U72pRR/Ff3DDx2Tj55LrNwBIkZlNR3ZdvQw09ZMNPJWDva7asbeQ9j0k8R
         DgfG7h3nK4DhV/BVkxL7PVZp03NQHYajQn9VOHwlpinKT5bybmHSEDc6ftTIrf9NeEib
         DTnGSMVeAi7RUtVhXd2wnIupktrxeqSm0v9aLmYyDauf+3P9OpMEND2vlvWIJvzcYEE4
         xLiJp+VnOoY9U7s+MqnRMyAthksDMgSthaVbNt3ECyCsgid8s+21Z6p/auRBCW/kZteN
         6QKCsrlyEEJt4AfQjZMCss6dzDZj/Wg6TeZo5jOZHUEELiOnL2YkXO7hZshwDLawgA3X
         DNQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOcaCfPW48+aA/pjqQAF3C5wxh3JtZuf+dXgAwHTTgRNs0c3Rw82bMoLrIpi/Suz5bF2sJCQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbWINm1zAWFgPVgAWAMWNHh8RWcfaL96KAI87QbuoL+wrjbXuT
	/9a0TG7+6WasTC6sYK/hHZ+vwAHvwog+FE73PjIdZkjM+Y8O5vQi
X-Google-Smtp-Source: AGHT+IGzvAiu5U9PgH6AbLRTw6Zxj4LjZeu/dwVtVQWGz/KWpYmkf5Q0W7EpCCep7vFPDG9lkeN1kQ==
X-Received: by 2002:ac2:4c43:0:b0:536:54c2:fb7c with SMTP id 2adb3069b0e04-539da4e0c6bmr4345953e87.25.1728851696345;
        Sun, 13 Oct 2024 13:34:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2810:b0:539:8f60:967e with SMTP id
 2adb3069b0e04-539c9b6aa1dls548158e87.0.-pod-prod-02-eu; Sun, 13 Oct 2024
 13:34:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYjdhyvg6LuH7cNuc26EUbMqflBICE1JS+AD9ovUYNfIWPGW6Pub6dx+TT5NY8YZ9L2kQVo4ojHwM=@googlegroups.com
X-Received: by 2002:ac2:4bca:0:b0:539:e6fc:4162 with SMTP id 2adb3069b0e04-539e6fc4310mr1589339e87.53.1728851694136;
        Sun, 13 Oct 2024 13:34:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728851694; cv=none;
        d=google.com; s=arc-20240605;
        b=AAXTQzQLgasADpJS1HbxAro48asaO0LGhA58qmp24IbHsKZ9jxmi4GDVYr92FJMIJu
         4MIPihqJnAHMpgLT4iUQrGqKQjl60LX7OBU/CbfsLZuctlMV76u2dldNc1KyBUlA1exM
         P0BePJ54/D/Kf3ZrwNZ8XHKwFEIC9KDSUIOfffnz68TNfaobyMLqTQVrut48vctpaUle
         Rwc9HaxLzNRMiuN/wTUuaOxo3218yrPiwcWLfWxebAn6X2XRUsSLGMFZsS8Dari6WAzW
         POho0Duqjny84ce0KQrotfT/e497OPhLJpIH6BDNRjUos3B+IQpYpOYoY5lWVRxJpv36
         rtAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Er+DyA+nIZCWp4voswFezoCAMxbkG62zzvLI/ETBGJ0=;
        fh=B9uIJ4ZNUSH4O+hXNTHn0DOT8bguq/2NdINvwQNXukI=;
        b=OwEhdzUKH8W/nD0APqUSsbTYudI5zDx7VDadk0nVwFZ6iqL5MJyOZ6IcJNTdA1OL8K
         tK1oxUcyg3wHJuZFRMEkSrxG4wTEv5mahS/HU8cvzUtX4VF3aVdMYAa6mNiVbF+3SvpX
         RWzKb6oEahgSBFQE+dWDCFtbdCAt7pCUckt4R5/FFA1G7DzTsMNXxK7egSeQUUEwFcbn
         jETxzWVXUpZkOrCDhN0heAR7mY83JwZMJyAkUaXBKgy7p+e+rmt024CSBjT5Bz3MoVGe
         A7MnmFzsOwxmqQEXbzMhnW+3pC+jdefaIsX96gYOyOmj7+EwtVht8NFFsBZicIrUqjfK
         D2pQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c8wsJU4d;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539e429101fsi70197e87.13.2024.10.13.13.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 13:34:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-37d447de11dso2610586f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 13:34:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXW2VWw+8r4iSNSAp39mgoLNgfw0J1UuRrCyiaH1be3GmI9ZPOVqALZ/T8DdpKNPX9ZbTDIiQp17c0=@googlegroups.com
X-Received: by 2002:adf:a1d9:0:b0:37d:324f:d3a9 with SMTP id
 ffacd0b85a97d-37d5519884amr6151232f8f.9.1728851693089; Sun, 13 Oct 2024
 13:34:53 -0700 (PDT)
MIME-Version: 1.0
References: <20241013172912.1047136-1-niharchaithanya@gmail.com>
In-Reply-To: <20241013172912.1047136-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 22:34:42 +0200
Message-ID: <CA+fCnZcM_xufVqgpmyJ_GxZC_70-kJVF7Hjhr_Vv6gKTUL5LoA@mail.gmail.com>
Subject: Re: [PATCH] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, skhan@linuxfoundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=c8wsJU4d;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
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

On Sun, Oct 13, 2024 at 7:32=E2=80=AFPM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The Kunit tests for kmalloc_track_caller and kmalloc_node_track_caller
> are missing in kasan_test_c.c, which check that these functions poison
> the memory properly.
>
> Add a Kunit test:
> -> kmalloc_tracker_caller_oob_right(): This includes unaligned, aligned a=
nd
>    beyond-aligned out-of-bounds access test for kmalloc_track_caller and
>    out-of-bounds access test for kmalloc_node_track_caller.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>

You can add a Fixes tag here to link the patch the Bugzilla entry:

Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D216509

> ---
>  mm/kasan/kasan_test_c.c | 34 ++++++++++++++++++++++++++++++++++
>  1 file changed, 34 insertions(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..b418bdff5bdb 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -213,6 +213,39 @@ static void kmalloc_node_oob_right(struct kunit *tes=
t)
>         kfree(ptr);
>  }
>
> +static void kmalloc_track_caller_oob_right(struct kunit *test)

Let's simplify this and do a single bad access check here for each
kmalloc_track_caller and kmalloc_node_track_caller. Precise redzone
poisoning checks are already done in normal kmalloc tests. This test
is just intended to be sure that we didn't forget to include KASAN
instrumentation calls into the track_caller variants.

> +{
> +       char *ptr;
> +       size_t size =3D 128 - KASAN_GRANULE_SIZE - 5;

size_t size =3D 128 - KASAN_GRANULE_SIZE;

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
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'x');
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] =3D 'y');
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D
> +                                       ptr[size + KASAN_GRANULE_SIZE + 5=
]);

Just one check for all KASAN modes here:

KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');

Nit: add empty line before kfree().

> +       kfree(ptr);
> +
> +       /*
> +        * Check that KASAN detects out-of-bounds access for object alloc=
ated via
> +        * kmalloc_node_track_caller().
> +        */
> +       size =3D 4096;
> +       ptr =3D kmalloc_node_track_caller(size, GFP_KERNEL, 0);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);

Nit: add empty line before kfree().

> +       kfree(ptr);
> +}
> +
>  /*
>   * Check that KASAN detects an out-of-bounds access for a big object all=
ocated
>   * via kmalloc(). But not as big as to trigger the page_alloc fallback.
> @@ -1958,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcM_xufVqgpmyJ_GxZC_70-kJVF7Hjhr_Vv6gKTUL5LoA%40mail.gmai=
l.com.
