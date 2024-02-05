Return-Path: <kasan-dev+bncBDW2JDUY5AORB2U2QWXAMGQE7Y7543Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 122F684A693
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 22:04:44 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-51143206e25sf348611e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 13:04:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707167083; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDlzUTR3eLm7EiRW2efXJAAj4k1ebIsixIlC+zZVQKyoQCnnRblwXX6UbYagGITvOd
         0fhv5xhdGFU6fSaWA98O8GKLMEEwjWpafuST+Y5jH2P3gpKiSWqK2/CRwLtm6duOe+mO
         yHezvf/jrWMWpO5HVlTVkfJiAUZiR0aIAtjDeygyiJVGk9CAmLXRIymHhb0GDtJc/9u8
         sSxKSIWg6NLCpDmYo4yBOx+hZmhdDfN3u1gqOCQkST8TChczXWwLJzIVpVTWFaIHyx53
         OdkgW+YxbZHt4fe45cmY0O9zYE8GGz25XCMRiiSBWkbo8ky/hSAShZ7ZqwxRyNfKkcXQ
         y4Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=D+ejY9silWdkepsA6G+zECEv0l2S8GiPUlZPAlIDpeg=;
        fh=5CcCnTZDIJBn4LajitajVDy8Zl3VxsmG4CQ2U5/gemk=;
        b=tsmxGvLWxOaJEvtWIM7nPuoEWJVnfjwp+WdKTmdxaYPM1rykxl1EOSkfYuJplI6vDP
         Ii8bSZTm9igp0xWxCc4boNR7x9tUbrj73ZDCWGxI9SYQU4ruhkcDNUDrH6fIQ2IA/HOm
         u6fJMI2sT5mxUBYQTMgraau6MdAKtIJpQuhh/kGS1o9SAKpwyT7R9VAdKrCaeg3w0mfS
         /1oZhczi/t+zmfgiQ9qQ+5gp51x/5Eb5dFH0n6QqqHxTDwBGaloQRiRsHHiPzlxAM21D
         fhL2FhalmgSkbYQIWWB+IOEvtAdqD3xGh3eL4IuFjj1Gavj99423ZlriitSuKB5ohvtk
         SAhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UsjzVWSy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707167083; x=1707771883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D+ejY9silWdkepsA6G+zECEv0l2S8GiPUlZPAlIDpeg=;
        b=YGvxf3r+Axuaq0ucsr62QnI2d1De5h6Lsonou1tfAOgkq2hPCB/WwBy3Ec0VHysF0C
         aaf/getmtMj35KwpVCl5NkFOBnoZa4Ef5EZMxG9IRvlpNcN2LW3gJ3Yug4v7mJf9gUCL
         FipVtShk8xDjedYNX1e23z1iuidtKRPxZlBHjPGcJ7Epj9gYkGhhPPWKjc0aC17c7F/f
         f5tg/NBaX/nm974qHx0+vDobfS7fKcS3H/Tkg7mXhFpA/ZpKeL6xAk2E4OtoYiXwaVbx
         W9lp2lLd21YS8xF2CSwxxu4WwbwFyHEfIEZ1HIkZL2ZOOd6RPhA2S4y+Y1EF2Z9VNTY6
         A/mg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707167083; x=1707771883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D+ejY9silWdkepsA6G+zECEv0l2S8GiPUlZPAlIDpeg=;
        b=Eh/QD0D8HvPU+SL1K+5lS95VDB5B1ZjPdpU20MhICwNc9YpCZIBQ30niDWlKwHSM5R
         YeTKyrtdQVFrtYi3sH9cTOEhyf0Bf2vl8aAD5zyUvcSsmyE3sVzn4UPf3Fh7XLI3YWKw
         qzHArN2S/aKBhq4WpKpLPGZA6YNSelRrueXXZsuL0gqDQALTRhnZk9ONL0ekP6tURlWD
         fWQRgO0Fg5rYjmcmw+t8UfJ5jBJPWSyzeLT4dZIwilXB8CVTDfcwz5KcMU9I27hXDbu/
         lLPjUJtjPPupSjWXVPSDJRFoaS1T3m2/E+6WSMBdPVnNiFqeIR0JWBHXWVOG+OIXuwuL
         VeTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707167083; x=1707771883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D+ejY9silWdkepsA6G+zECEv0l2S8GiPUlZPAlIDpeg=;
        b=Gy/kwFaOTCQvfmOoJBkH6KuogbRlTC1Yt3/yMxlDUjhoxTy67IT6O9BllRCxA+b785
         fXi4EZP5/rHufR7VzAJYs1rAzjxLdBBxTpU76ollV4eTP7Bdebseqm+GNJE98z0JKcNj
         DZQyQHbe+aQoKUdqXF58yz5Av4eXy8mTlnv0Vvvtb7Zs/vvmK0GsRRZG5ZQg3NDrL+df
         Bzz7wNUBbMwGfjcYozqu0TNQUtZjIaBpYC8YvT3pZcxqVTag8/kKHxwZFGX1in+zTJ7H
         sod6Tnbqm87D+wiJc6VK2z7T+Pf/eKP3jmmCbd2/bBJUaknvMRxP/zj+zospuwE6o2vH
         J/JA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXopF0sMnwSkChDt2SO4WYYUz1JnqPSShOXpAOovkVoAN2jFHcAAzKQGzUsDRNcuNUb0LQe6vg2Sp2zefjQI1kgXqr2HMWfzQ==
X-Gm-Message-State: AOJu0YyXIZWrIEjPQgXryZp9HN14QihXY7r6NlS2i1BpLSvtSV6C6f43
	c/c/UEUt5lpDId0TgQ8O1ydzZ0yc82MUEHnsEi66x3PWPoJxC/15
X-Google-Smtp-Source: AGHT+IGqEibw6Z1pjVKIoplFhFMfabF1fakQQy89zDvgAnFegxidTkC+br/mc72EJU67z+dyvZl7VA==
X-Received: by 2002:a05:6512:511:b0:511:5b35:d118 with SMTP id o17-20020a056512051100b005115b35d118mr167162lfb.2.1707167082717;
        Mon, 05 Feb 2024 13:04:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a92:b0:511:3561:bca2 with SMTP id
 q18-20020a0565123a9200b005113561bca2ls629381lfu.1.-pod-prod-04-eu; Mon, 05
 Feb 2024 13:04:41 -0800 (PST)
X-Received: by 2002:ac2:4db2:0:b0:511:454e:6032 with SMTP id h18-20020ac24db2000000b00511454e6032mr498960lfe.63.1707167080764;
        Mon, 05 Feb 2024 13:04:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707167080; cv=none;
        d=google.com; s=arc-20160816;
        b=m6oXgxFF+B8PNAdOWc+l5hQcfwRJw+yNkVgENsxWy/jsQwuSuQp9wCgM99iEz477Bm
         3nClSuTOCN5IxpPt5DxlBec5KOE5qdECx3uEP7QJEn93/JPVc7eWnmQzhlsZ4iDfc/7M
         kiS+eOPUIkGOzMfnwzPny1uFnCaUqyDAN4vpDpHCWFNJqGhTAbRGXYEJQkQowy24QuAZ
         bOp3E7r4+zKDlKvhkPQiJaXXKUJT9orfRTV1dRkFJHjdU8eNe6dKIDMHQJazNGpEISX/
         My6hL5u3scVKMgeYgsRG77aLMjYMNwfLoCPB/RsArFSxKTIIH6QqFzejhAOc4gK3g5/g
         DRVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nqJL7TqpfRwuD6pFCu0aeAbehlV+SJSjj9oqhH2/TvU=;
        fh=ow3RB5mo6IF3/efgli2eCWKvynbWkrgCNQC9t1C4dzc=;
        b=0VdKgDkpJm6KbsV3AUdDoN8r4oq4/OrRD8nGqyXkypVe1gJM+lZFvLd9BdFik8mTAz
         qcjYNO4o3JbH80ci7Qf1YOhNMo2dkpRZyyzuUhaXCvUcH5oZB0IR7ZFgQo4NJtBNuTOk
         uQQN+j9dhXmhouXgAqNltWeF6QMcF7/Ix0K8kYcnRnbDSVNB3730d8Q5XZ3mglowaoZq
         gRvD8WPDglfs14POnu3OCygmfyHj3QEchaahBXWeinlJw0OyH7QciK/T5ISCARnS4uVh
         ndggaygd3yeTObIUwHocE2SKQocCJR6kCCJ48+fonvMdYzcQeqxN96gWEKXy6fLocovh
         qChA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UsjzVWSy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCUj//2tPtDGVf6/6eWHDkQXpkjt3O5fIv3A+T4BCyPtMgi3yiig5Ycix6umFDmR6QFv27K8fBjOxMNFIB1gbyF5UJqGquMUI+Wc0w==
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id g29-20020a0565123b9d00b00511495618fdsi35951lfv.7.2024.02.05.13.04.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 13:04:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-33b130f605eso3188919f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 13:04:40 -0800 (PST)
X-Received: by 2002:a5d:67d0:0:b0:33b:4164:5fbe with SMTP id
 n16-20020a5d67d0000000b0033b41645fbemr464734wrw.20.1707167079640; Mon, 05 Feb
 2024 13:04:39 -0800 (PST)
MIME-Version: 1.0
References: <20240205060925.15594-1-yangtiezhu@loongson.cn> <20240205060925.15594-2-yangtiezhu@loongson.cn>
In-Reply-To: <20240205060925.15594-2-yangtiezhu@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Feb 2024 22:04:28 +0100
Message-ID: <CA+fCnZfDZvcFHG0anZQQKD_GVOfmcKhCmY82U9X2ZKBJp4oRZQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: docs: Update descriptions about test file and module
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UsjzVWSy;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
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

On Mon, Feb 5, 2024 at 7:09=E2=80=AFAM Tiezhu Yang <yangtiezhu@loongson.cn>=
 wrote:
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfDZvcFHG0anZQQKD_GVOfmcKhCmY82U9X2ZKBJp4oRZQ%40mail.gmai=
l.com.
