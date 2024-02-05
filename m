Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2NLQOXAMGQEPL5WFBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 08E31849A61
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 13:34:51 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-205c90a36a3sf5256179fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 04:34:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707136489; cv=pass;
        d=google.com; s=arc-20160816;
        b=ml0KmN7AVsw0DhGa4vb90yNyWNxMM5sUeo2NEQwMJc1/98lRRBOFU8ZnjY9dOMo6BM
         NR3VscAWdzkOy++q4cydov5HRRCWXKE8F2SJOk8KbdCfU6DPYme/0Zcc1MlzsYRGJ9Xr
         rXGBXQGuIya3zhmqW3xFfqdHvYaY1mly/apXypZzimGCkDXJC2kGRLu4DgodJtlN15Xl
         Z7sqhU1JwGd5t+Brgr/C1w+RlceJMCQq2XXa2VXUb9Z0bFqBaUFVPIrQlRVghJg/9n78
         t1Do0/WLhbpXggAVpryy9xqC3a3X6yfhjbBoMPA8A+VbAywLzJOwLr1VCZtFUBehOrwD
         OQ6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uv/F7/nhFDu/7udV/aJ7/aEeKX2q1afemjbBHqoGMOc=;
        fh=UsNSmIaPYxnv65ynQ72cdtmNX+ool2BLH0oZUEKHVBQ=;
        b=A1PL5CR2+KpeL8X8gq3mS0QK/yEm4nP5ZXDA9bMOegSgsZs2nbDTRakF+DiobuiOe7
         XTU/gXaLhd5EuRdnzDmTkahex6z4SUULWJbESfMmuZ+rndDFj9jn6CMQF3F1bEfXWsGm
         5nqRO8NgSv+RrifhXH9jKHIx6DNv+zmkCCc/KX7R+l1WHJY45RYwYdCOsmEESEa5xIe7
         YOCuLzbCs2v0cFrRvu6D7MnrU8oCtyK3M+g4IwI0PWN9kC+Rvv1EUDdBJoZaRts++6/2
         TtEGEWxJ9+9rE+EYG+kRpMjimCAc/bl9GhR0sWp/T7CSG8zEF/CkURXRN8w+zQ1AA8HX
         05Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Hh2KdtTr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707136489; x=1707741289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uv/F7/nhFDu/7udV/aJ7/aEeKX2q1afemjbBHqoGMOc=;
        b=BOQ7sBbwzmsiVusx1/2OGEUOkp9xQdOdY9mImvvG23Yy5fTJcQzKKjT51MCxrb7XJf
         ftXwlywiz6xLNTkPt7Y6hH0a7/LPJNT+jf3g7T7aekKOOnj8WGAMDJGRopbK2DgpGjqQ
         1T9zjY5hV3WOLNkUiqab4+AMvlHfqNolHWBHBMmGgqeaMy2cCOfeNjCmmuFyOjF9NgnF
         KXiufa+2/SOAbHjVWvoiEEI9wIcABtDB9yo1fRns5E5fiNw8YVUDfxzWICaRqzFT/vY7
         CbFPgZQVGGr6YJUONNFDTlOb03FjeLk2KSDr2DtwD1qQ/GvAoQjsCDLmQFywJWHTFlp9
         Eauw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707136489; x=1707741289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uv/F7/nhFDu/7udV/aJ7/aEeKX2q1afemjbBHqoGMOc=;
        b=BhyKYrtsDuJUx1sWmE+6k2kOkCW1y4WshzMaVKdyMEgc270HBYX13p/yAQXvYsugwd
         XTJWdmANGgQcRlvvgtUJXV6Xuea4bt08YPBsCQqPPFI1vEvwXbhgMouMAWN0MxBbrLN2
         CfmaIrCaZdWNZeFcZQ8/lK8J2fo8WbMhJgtN524YID/o4hpAH5173VljNZJUjcr3t6tB
         oSAR7FCbHLOalwZeT0T+OS9jECzBKLO10kyBIPyZyeuyBPOxJnhKa7jIra6rHPEWXgP+
         +Mkt7ywYzYTqhXu/wUz3nyLAPMiYzGBiiYi7wJZmAyfz84fEVUeimrv0XMewci+eOeoy
         qR3w==
X-Gm-Message-State: AOJu0Ywq9PZbJLManGSNAU8kAoK8vrGU/67DtJfsdbzvbnf8EMC8QTyy
	9u0jjNIJikXAHXZ89aDq9CoUMPQekMh4kd6Yn5E1HpEJ5jAg81mE
X-Google-Smtp-Source: AGHT+IHSPJJ6+mL3m2vGpfEkbpA0Hk+r5i1E5bNWQISCdcBUYJalxbNB6YgcpKYMb2/1epiZa7TMuA==
X-Received: by 2002:a05:6870:886:b0:219:426f:d921 with SMTP id fx6-20020a056870088600b00219426fd921mr8205275oab.0.1707136489455;
        Mon, 05 Feb 2024 04:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:718f:b0:219:a14d:86d0 with SMTP id
 d15-20020a056870718f00b00219a14d86d0ls124354oah.0.-pod-prod-03-us; Mon, 05
 Feb 2024 04:34:48 -0800 (PST)
X-Received: by 2002:a05:6870:96a7:b0:219:3ca6:3b43 with SMTP id o39-20020a05687096a700b002193ca63b43mr6759912oaq.16.1707136488442;
        Mon, 05 Feb 2024 04:34:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707136488; cv=none;
        d=google.com; s=arc-20160816;
        b=ojWxjoUh/SCiebGydZhwmO5GzVLtU7+tUx3e7BjXXs4EFQdK3ezHLh6j57KRTlhkUJ
         PiDNaToE53IuQDC6vcFpWIz88bExx+dCv8aL1fmx4is7BM+4kyirg3BGvIJ79UshA6pi
         onPMf1lLrGckOTR9dIhqbhQb+edx6o8h2lT5qs8lAhIwcITFT2r/52EE48gNCS3QSLke
         QLpghwR82M/wR/gIjvZx9IhhC6o+AgsE9/c6foJxGVnsMlMnRf88lbfpHkRmueGx6wvb
         owd07o2iT1DkuUm8hLflCTEL4PYH3bwPs82J391FFYgoUxNz4TH19baWc24/GnXjy56/
         46Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l8CVvdF5Aiu8bbnGwIPzuUGttJIlOEds+fQB4E+B8Xc=;
        fh=UsNSmIaPYxnv65ynQ72cdtmNX+ool2BLH0oZUEKHVBQ=;
        b=ju9PG0/RmTX7PjOKt+VtLX9Pg/BWF4xQZwP0JnA8KivSDP/oCPQYTMTTKgzslbY9J0
         dI0CfwWuGjpKHiJgm/IHwW7Qy/tOTYU6z7LVN7C5bffaynrqrDLaUTRoI22KvOYBKm60
         2ewrWTz48jzS+0neRkjWw8Iku+DmTsiukJdclq9LbT1zUDpD4WkqB2I2nSZCEITAONJR
         GgUf3lCIxGz9/8CEWskXeF1OGT2Jq1SnLKq3d5Ttpb0Ovrr5U6WUePm35TPo1xbqq1en
         CzK3UY0nI3A2uU2gbfeVN/GmV+hvRJl+c67SQQh3+fNtdLt+L68bsIhegY0n+q2Nnmua
         VgWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Hh2KdtTr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCVdtlnnwiR/mA4+uPJiR8ZBncqPIvP0qzXoubnqey2q1Um/UN7P8fie3mSbFVeuFwLpBI9nHxued/zHMjwlIZ4HKmkRinSp15k7Zw==
Received: from mail-ua1-x92b.google.com (mail-ua1-x92b.google.com. [2607:f8b0:4864:20::92b])
        by gmr-mx.google.com with ESMTPS id nx20-20020a056870be9400b0021992e50b22si105272oab.2.2024.02.05.04.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:34:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) client-ip=2607:f8b0:4864:20::92b;
Received: by mail-ua1-x92b.google.com with SMTP id a1e0cc1a2514c-7d5bbbe57bbso1697521241.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 04:34:48 -0800 (PST)
X-Received: by 2002:a05:6122:16a6:b0:4c0:328d:c4f9 with SMTP id
 38-20020a05612216a600b004c0328dc4f9mr1108119vkl.0.1707136487476; Mon, 05 Feb
 2024 04:34:47 -0800 (PST)
MIME-Version: 1.0
References: <20240205060925.15594-1-yangtiezhu@loongson.cn> <20240205060925.15594-2-yangtiezhu@loongson.cn>
In-Reply-To: <20240205060925.15594-2-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 13:34:10 +0100
Message-ID: <CANpmjNM+aX6v3uiaZ8OxjUBb5ax=HcGKz6dG+6xcEV4oWODwhg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: docs: Update descriptions about test file and module
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Hh2KdtTr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as
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

On Mon, 5 Feb 2024 at 07:09, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> After commit f7e01ab828fd ("kasan: move tests to mm/kasan/"), the test
> file is renamed to mm/kasan/kasan_test.c and the test module is renamed
> to kasan_test.ko, so update the descriptions in the document.
>
> While at it, update the line number and testcase number when the tests
> kmalloc_large_oob_right and kmalloc_double_kzfree failed to sync with
> the current code in mm/kasan/kasan_test.c.
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>

Acked-by: Marco Elver <elver@google.com>

Thanks for cleaning this up.

> ---
>  Documentation/dev-tools/kasan.rst             | 20 +++++++++----------
>  .../translations/zh_CN/dev-tools/kasan.rst    | 20 +++++++++----------
>  .../translations/zh_TW/dev-tools/kasan.rst    | 20 +++++++++----------
>  3 files changed, 30 insertions(+), 30 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 858c77fe7dc4..a5a6dbe9029f 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -169,7 +169,7 @@ Error reports
>  A typical KASAN report looks like this::
>
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> -    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_=
kasan]
> +    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan=
_test]
>      Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
>
>      CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
> @@ -179,8 +179,8 @@ A typical KASAN report looks like this::
>       print_address_description+0x73/0x280
>       kasan_report+0x144/0x187
>       __asan_report_store1_noabort+0x17/0x20
> -     kmalloc_oob_right+0xa8/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0xa8/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -200,8 +200,8 @@ A typical KASAN report looks like this::
>       save_stack+0x43/0xd0
>       kasan_kmalloc+0xa7/0xd0
>       kmem_cache_alloc_trace+0xe1/0x1b0
> -     kmalloc_oob_right+0x56/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0x56/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -510,15 +510,15 @@ When a test passes::
>
>  When a test fails due to a failed ``kmalloc``::
>
> -        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:=
163
> +        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_te=
st.c:245
>          Expected ptr is not null, but is
> -        not ok 4 - kmalloc_large_oob_right
> +        not ok 5 - kmalloc_large_oob_right
>
>  When a test fails due to a missing KASAN report::
>
> -        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:=
974
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_te=
st.c:709
>          KASAN failure expected in "kfree_sensitive(ptr)", but none occur=
red
> -        not ok 44 - kmalloc_double_kzfree
> +        not ok 28 - kmalloc_double_kzfree
>
>
>  At the end the cumulative status of all KASAN tests is printed. On succe=
ss::
> @@ -534,7 +534,7 @@ There are a few ways to run KUnit-compatible KASAN te=
sts.
>  1. Loadable module
>
>     With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a lo=
adable
> -   module and run by loading ``test_kasan.ko`` with ``insmod`` or ``modp=
robe``.
> +   module and run by loading ``kasan_test.ko`` with ``insmod`` or ``modp=
robe``.
>
>  2. Built-In
>
> diff --git a/Documentation/translations/zh_CN/dev-tools/kasan.rst b/Docum=
entation/translations/zh_CN/dev-tools/kasan.rst
> index 8fdb20c9665b..2b1e8f74904b 100644
> --- a/Documentation/translations/zh_CN/dev-tools/kasan.rst
> +++ b/Documentation/translations/zh_CN/dev-tools/kasan.rst
> @@ -137,7 +137,7 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=
=93=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
>  =E5=85=B8=E5=9E=8B=E7=9A=84KASAN=E6=8A=A5=E5=91=8A=E5=A6=82=E4=B8=8B=E6=
=89=80=E7=A4=BA::
>
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> -    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_=
kasan]
> +    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan=
_test]
>      Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
>
>      CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
> @@ -147,8 +147,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=
=93=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
>       print_address_description+0x73/0x280
>       kasan_report+0x144/0x187
>       __asan_report_store1_noabort+0x17/0x20
> -     kmalloc_oob_right+0xa8/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0xa8/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -168,8 +168,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=
=93=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
>       save_stack+0x43/0xd0
>       kasan_kmalloc+0xa7/0xd0
>       kmem_cache_alloc_trace+0xe1/0x1b0
> -     kmalloc_oob_right+0x56/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0x56/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -421,15 +421,15 @@ KASAN=E8=BF=9E=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A1=
=80=E6=9E=B6=E6=9E=84=E4=BB=A5=E6=87=92=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=86=85=E5=AD=98=E3=80=82
>
>  =E5=BD=93=E7=94=B1=E4=BA=8E ``kmalloc`` =E5=A4=B1=E8=B4=A5=E8=80=8C=E5=
=AF=BC=E8=87=B4=E6=B5=8B=E8=AF=95=E5=A4=B1=E8=B4=A5=E6=97=B6::
>
> -        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:=
163
> +        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_te=
st.c:245
>          Expected ptr is not null, but is
> -        not ok 4 - kmalloc_large_oob_right
> +        not ok 5 - kmalloc_large_oob_right
>
>  =E5=BD=93=E7=94=B1=E4=BA=8E=E7=BC=BA=E5=B0=91KASAN=E6=8A=A5=E5=91=8A=E8=
=80=8C=E5=AF=BC=E8=87=B4=E6=B5=8B=E8=AF=95=E5=A4=B1=E8=B4=A5=E6=97=B6::
>
> -        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:=
974
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_te=
st.c:709
>          KASAN failure expected in "kfree_sensitive(ptr)", but none occur=
red
> -        not ok 44 - kmalloc_double_kzfree
> +        not ok 28 - kmalloc_double_kzfree
>
>
>  =E6=9C=80=E5=90=8E=E6=89=93=E5=8D=B0=E6=89=80=E6=9C=89KASAN=E6=B5=8B=E8=
=AF=95=E7=9A=84=E7=B4=AF=E7=A7=AF=E7=8A=B6=E6=80=81=E3=80=82=E6=88=90=E5=8A=
=9F::
> @@ -445,7 +445,7 @@ KASAN=E8=BF=9E=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A1=
=80=E6=9E=B6=E6=9E=84=E4=BB=A5=E6=87=92=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=86=85=E5=AD=98=E3=80=82
>  1. =E5=8F=AF=E5=8A=A0=E8=BD=BD=E6=A8=A1=E5=9D=97
>
>     =E5=90=AF=E7=94=A8 ``CONFIG_KUNIT`` =E5=90=8E=EF=BC=8CKASAN-KUnit=E6=
=B5=8B=E8=AF=95=E5=8F=AF=E4=BB=A5=E6=9E=84=E5=BB=BA=E4=B8=BA=E5=8F=AF=E5=8A=
=A0=E8=BD=BD=E6=A8=A1=E5=9D=97=EF=BC=8C=E5=B9=B6=E9=80=9A=E8=BF=87=E4=BD=BF=
=E7=94=A8
> -   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BD=BD ``test_kasan.ko`=
` =E6=9D=A5=E8=BF=90=E8=A1=8C=E3=80=82
> +   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BD=BD ``kasan_test.ko`=
` =E6=9D=A5=E8=BF=90=E8=A1=8C=E3=80=82
>
>  2. =E5=86=85=E7=BD=AE
>
> diff --git a/Documentation/translations/zh_TW/dev-tools/kasan.rst b/Docum=
entation/translations/zh_TW/dev-tools/kasan.rst
> index 979eb84bc58f..ed342e67d8ed 100644
> --- a/Documentation/translations/zh_TW/dev-tools/kasan.rst
> +++ b/Documentation/translations/zh_TW/dev-tools/kasan.rst
> @@ -137,7 +137,7 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=
=9F=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
>  =E5=85=B8=E5=9E=8B=E7=9A=84KASAN=E5=A0=B1=E5=91=8A=E5=A6=82=E4=B8=8B=E6=
=89=80=E7=A4=BA::
>
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> -    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_=
kasan]
> +    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan=
_test]
>      Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
>
>      CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
> @@ -147,8 +147,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=
=9F=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
>       print_address_description+0x73/0x280
>       kasan_report+0x144/0x187
>       __asan_report_store1_noabort+0x17/0x20
> -     kmalloc_oob_right+0xa8/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0xa8/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -168,8 +168,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_=
warn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=
=9F=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
>       save_stack+0x43/0xd0
>       kasan_kmalloc+0xa7/0xd0
>       kmem_cache_alloc_trace+0xe1/0x1b0
> -     kmalloc_oob_right+0x56/0xbc [test_kasan]
> -     kmalloc_tests_init+0x16/0x700 [test_kasan]
> +     kmalloc_oob_right+0x56/0xbc [kasan_test]
> +     kmalloc_tests_init+0x16/0x700 [kasan_test]
>       do_one_initcall+0xa5/0x3ae
>       do_init_module+0x1b6/0x547
>       load_module+0x75df/0x8070
> @@ -421,15 +421,15 @@ KASAN=E9=80=A3=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A4=
=8E=E6=9E=B6=E6=A7=8B=E4=BB=A5=E6=87=B6=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=85=A7=E5=AD=98=E3=80=82
>
>  =E7=95=B6=E7=94=B1=E6=96=BC ``kmalloc`` =E5=A4=B1=E6=95=97=E8=80=8C=E5=
=B0=8E=E8=87=B4=E6=B8=AC=E8=A9=A6=E5=A4=B1=E6=95=97=E6=99=82::
>
> -        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:=
163
> +        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_te=
st.c:245
>          Expected ptr is not null, but is
> -        not ok 4 - kmalloc_large_oob_right
> +        not ok 5 - kmalloc_large_oob_right
>
>  =E7=95=B6=E7=94=B1=E6=96=BC=E7=BC=BA=E5=B0=91KASAN=E5=A0=B1=E5=91=8A=E8=
=80=8C=E5=B0=8E=E8=87=B4=E6=B8=AC=E8=A9=A6=E5=A4=B1=E6=95=97=E6=99=82::
>
> -        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:=
974
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_te=
st.c:709
>          KASAN failure expected in "kfree_sensitive(ptr)", but none occur=
red
> -        not ok 44 - kmalloc_double_kzfree
> +        not ok 28 - kmalloc_double_kzfree
>
>
>  =E6=9C=80=E5=BE=8C=E6=89=93=E5=8D=B0=E6=89=80=E6=9C=89KASAN=E6=B8=AC=E8=
=A9=A6=E7=9A=84=E7=B4=AF=E7=A9=8D=E7=8B=80=E6=85=8B=E3=80=82=E6=88=90=E5=8A=
=9F::
> @@ -445,7 +445,7 @@ KASAN=E9=80=A3=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A4=
=8E=E6=9E=B6=E6=A7=8B=E4=BB=A5=E6=87=B6=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=85=A7=E5=AD=98=E3=80=82
>  1. =E5=8F=AF=E5=8A=A0=E8=BC=89=E6=A8=A1=E5=A1=8A
>
>     =E5=95=93=E7=94=A8 ``CONFIG_KUNIT`` =E5=BE=8C=EF=BC=8CKASAN-KUnit=E6=
=B8=AC=E8=A9=A6=E5=8F=AF=E4=BB=A5=E6=A7=8B=E5=BB=BA=E7=88=B2=E5=8F=AF=E5=8A=
=A0=E8=BC=89=E6=A8=A1=E5=A1=8A=EF=BC=8C=E4=B8=A6=E9=80=9A=E9=81=8E=E4=BD=BF=
=E7=94=A8
> -   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BC=89 ``test_kasan.ko`=
` =E4=BE=86=E9=81=8B=E8=A1=8C=E3=80=82
> +   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BC=89 ``kasan_test.ko`=
` =E4=BE=86=E9=81=8B=E8=A1=8C=E3=80=82
>
>  2. =E5=85=A7=E7=BD=AE
>
> --
> 2.42.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM%2BaX6v3uiaZ8OxjUBb5ax%3DHcGKz6dG%2B6xcEV4oWODwhg%40mail.=
gmail.com.
