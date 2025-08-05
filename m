Return-Path: <kasan-dev+bncBDPPVSUFVUPBBDOCZDCAMGQEWQMPY6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CF8FB1B759
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:19:43 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-31ed4a4a05bsf7938253a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:19:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407182; cv=pass;
        d=google.com; s=arc-20240605;
        b=c39Er3gex+YYMp3szJ0X5CCZdN0mW3aXEAe2zkjWVbnNtrgcLxJDE439VSr0Io5zW8
         Sf7vGJ/jffF9xd6cMXFMDtBbbbzzfDhJT/4KylTIci9hohspVXKxu6V4cCN0d2mOGVkV
         QU5AqpAEk+Aik80yl7sBANKfHdWlhJxOYlCFmI68a5BlAWNTivMT4B7YKRXZDi4EM6eJ
         0RgaFUd39FXdYc0LPh/oZIWTqeDAyDKj4yzZyd0mAowBpOwjHcxOeXX6V4eS6LZvnL+y
         oTtqlsBpZ1OiIt734NKuAkEroNVRe1N8wMU3fLl1M8+d3U1f24Sf9oTpTFu8CQ77Dh6X
         enTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bVk9THgCZsU6/5AC8Ur7/IjOJaKb1wqPMUfW/XDZ+6U=;
        fh=AdxkeppIiIGoNPP8jL0Ec9ozYmckOIZmBBwsBvBxmPQ=;
        b=knuYgQNjNml9FU7jIPN7OmIY622jNrZjnbH5FMj4V28XZZxRp5dgDDmL9/iK8UsbOW
         xCbe2v+WxbjEBWqv4QV8c3O0XG4vIW9kOa9baICeZW83yFaezvU/VijkxFcpv4qUgGz2
         pvIu3ltxWkR37FT6jQfpQk5S4P0XlXyqO/b0EkP4n+XMppNvJ78T1HWHXtXAfQvZNCCr
         o920WshW3c5Rq5/GGSk9E+1DAxLkZaiU1e3vFq6wmhCW04nFPkZHpSacbHgk1XhUv6gU
         tO15olF1zc/0a2H3G6spwSbaqIRm2RLjVfeYG7oFTwoDaiz1Sbn8bYHEu2APZsLsF/gg
         xnlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=z5tpFZqt;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407182; x=1755011982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bVk9THgCZsU6/5AC8Ur7/IjOJaKb1wqPMUfW/XDZ+6U=;
        b=h3Ky811Rjx9xv0me5sh71Tj7BXdZffGV4FzAq2qFHv3Ic+cVnU7hz3Q4AU63bdZoXY
         mpp1PAVTBznHMZDxi7SrindKTf1f7oaA6AfqJ1/41/9Ua0/EaIblvxTweGU7aPBdeJAe
         QsOjrhgBfiDsnOpQOTEDWkC5djZB4P+H6G+vAyMdSYjtuGW7Wk487Yma9Lvqj04elF4M
         NQ5y5H9DcexWLkuYOstUPTMTXKsu8icdxbOLx27V0HvEL8/R4sW2/PHIiU0zcBUCMEmw
         h8Y5zfvfDo2qffAL/Uumg20GDNVrl6B9PiAk3hGqRyf0Az3U2LKGilbU/6SxMblz71vH
         187g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407182; x=1755011982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bVk9THgCZsU6/5AC8Ur7/IjOJaKb1wqPMUfW/XDZ+6U=;
        b=OXmCtt1+IJF/zdPoDCWs2iUi8qGbOiJI2Z3pmDjvMB0+QKLPGElcKLYwXLZPkV6VWK
         7kSQNLpAwda5TvAd1eHoruzquqyePIYopVFnQvOF73EDeirnTRIiJH1xBIS6lDfPT+rR
         s8hYm10kUmveGX48eT3U6VN2Mt6waIBP+gICAZO9k4SUV+oEumfPk+S+WRR2H5RKqnPU
         m97XSn0I0HpqyLYNeNAV8yxOtd/mo8phJIIYokgobFEElBt7imuBHE/ke25sRMa2EtcU
         HfiLalZMoy/KTv9fkllP6QFl+HebM/WX8Zb5t+CurhyqR+qWgG8aNOu48PjKEC96GWgL
         tAyw==
X-Forwarded-Encrypted: i=2; AJvYcCXhu3zfqHkTCPKrRv1vfqNrXH7Akl27/m1gArZHMd6fq5QU9ja9AIV8TYiP+Vd8r14OXen2fQ==@lfdr.de
X-Gm-Message-State: AOJu0YyivoIxkkw82fmalGGMg2pv5NT2Cr8RZ+QRceOOObYSirJl4Ot9
	pu+KP1xpaVuF4+WGUoMbe+xUsd85v0MUEj8N1URgO32YpuxRZf93+K3z
X-Google-Smtp-Source: AGHT+IE2HTi+v9TBan88P7jMLLMDkp1GHpaIbc2raRVCA4IEgmiRvJstSAcDCJhGX4Hqv9LjIp02YA==
X-Received: by 2002:a17:902:db0f:b0:240:b884:2fa0 with SMTP id d9443c01a7336-24288e24b4amr57230985ad.26.1754407181668;
        Tue, 05 Aug 2025 08:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWSIgCbajpbHF7/Z7/feoop6Tf2mj5EiOtZTP9LYr3jw==
Received: by 2002:a17:903:32ca:b0:23f:8cfc:8dee with SMTP id
 d9443c01a7336-240969e303bls38785955ad.1.-pod-prod-00-us-canary; Tue, 05 Aug
 2025 08:19:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeB6d3LVb8D7FWpKqHtsfXza9t66didvmo+arGuU+SXFS7tz6BoL+IWERd/okoajLTrKefthB6cTs=@googlegroups.com
X-Received: by 2002:a17:90b:38c7:b0:30e:6a9d:d78b with SMTP id 98e67ed59e1d1-3214fe9da63mr5004159a91.12.1754407179336;
        Tue, 05 Aug 2025 08:19:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407179; cv=none;
        d=google.com; s=arc-20240605;
        b=EfQxJkkgGqO5vTilkoRwoTDrjhxr0LM4FIIqQ5ZcVdtcc/slo3xYl32gbsG41ku9LM
         9jGoM9XePhZQF0oXF7vNPdEsQVCNAw6/0kSt1gOvo4IiIcj4B14n2/vKBAuFh3wcjAiQ
         Hj49xNR9PDZZBjOb2TKN8M5PgMmLPocbVwY/LUzOZU0Z4/0S+hnP/2oCajVU5BM+kzrF
         Xhupy7GfoRUOXzqXJvNg9AmHMY4eJXWKLBi0bqWl70C9XZMAtXLTRUHHBAcYPrI824b8
         mRqPFzqZgXf1QJRhHbrKjNVsaVa3SdgogmDF7BBvusetCV2l8WkjP1bFboCGIWHiGsR8
         87eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=O/zN/Iw+mbc9m0aZ/VoboIauT8chB+SQVkzXgCKtaFY=;
        fh=enhOjxDHy4WuAa8RhC+i39ABW4ZwnSGvk1L8/c8tUho=;
        b=UTbYxnKfFsWJ38D7dTTTxFfRSfW/942AfNVf+26lK8orrNqACPph+qyXOrf7AqVeBa
         elesHJx1NgACI3juivrfHjGHQBACCJFChdDlToKQh8tyY7/LkgWC3l1gCzx6/VdAxMWU
         pWbHV2ftsvxUWfIr1NR2dUNpYM5wd/IVQH9LRLyI3A2bcnhSXRcd+dlwpSeqo/g1OJ1R
         MVQR3QH7hRReLZKe4xINw1BvGnz5BFB3n037O7GrkAPDs+yEPB4GBck9jAgBbUO4vfw3
         rLvRhe5huZ84W/KRIxuzdXXklzfxofUJw6oF1NwaWKPLGPefRF179BYYco3dEQnUE/Lj
         VWoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=z5tpFZqt;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32102854509si365720a91.0.2025.08.05.08.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:19:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-4af156685e2so38834541cf.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:19:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXMag0HrU7Twe09YEb/0KUiF7T7QUAUe1mnk4QloXmLIHO2g4ZpSgPmTgHNX3L1h/4/9zs5eu5uFyI=@googlegroups.com
X-Gm-Gg: ASbGncu4CrYH1XL23XCPvtdM4PtduozxiKdajWfPkbrMZO4GDty/C1jtXmy7TiM789D
	fuNIWzx2df9yhFuW3a9Xhy8mwNDkmk3sj3hZSha+gk7kddJ26tKtTSHUlqH4MouM6YVRZg2MyYr
	9KB81zhT45z14AcC3QHKLIn4423WT8+iDIaPO3ky1aKgZkB3Xbrf6foBaPwfNK9J+T5Nhwvctd7
	QNJ/TOEpchIZ4ohF20NysdMrryn3E/c9JhJM4YXWg==
X-Received: by 2002:a05:620a:a116:b0:7e6:38a8:bbd1 with SMTP id
 af79cd13be357-7e80ac4bb47mr585290385a.2.1754407177366; Tue, 05 Aug 2025
 08:19:37 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-10-marievic@google.com>
In-Reply-To: <20250729193647.3410634-10-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:19:26 -0400
X-Gm-Features: Ac12FXzb8E9oY6BCewcT9Ms7A5F3Fn9upcwWL-ZUIRDMMrjcR8bruiykdaRbHrg
Message-ID: <CA+GJov5q-mAHuchZNqS6DEv1zFmDzhF1SSdjBfJyB0ZnqUCQfg@mail.gmail.com>
Subject: Re: [PATCH 9/9] Documentation: kunit: Document new parameterized test features
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=z5tpFZqt;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82f as
 permitted sender) smtp.mailfrom=rmoar@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Rae Moar <rmoar@google.com>
Reply-To: Rae Moar <rmoar@google.com>
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

On Tue, Jul 29, 2025 at 3:37=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> -Update the KUnit documentation to explain the concept
> of a parent parameterized test.
> -Add examples demonstrating different ways of passing
> parameters to parameterized tests and how to manage
> shared resources between them.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

This is amazing! I have a few comments below but I appreciate the
effort to document this new feature. It is always incredibly helpful
to have documentation to go along with the code.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!
-Rae

> ---
>  Documentation/dev-tools/kunit/usage.rst | 455 +++++++++++++++++++++++-
>  1 file changed, 449 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/dev-tools/kunit/usage.rst b/Documentation/dev-=
tools/kunit/usage.rst
> index 066ecda1dd98..be1d656053cf 100644
> --- a/Documentation/dev-tools/kunit/usage.rst
> +++ b/Documentation/dev-tools/kunit/usage.rst
> @@ -542,11 +542,21 @@ There is more boilerplate code involved, but it can=
:
>  Parameterized Testing
>  ~~~~~~~~~~~~~~~~~~~~~
>
> -The table-driven testing pattern is common enough that KUnit has special
> -support for it.
> -
> -By reusing the same ``cases`` array from above, we can write the test as=
 a
> -"parameterized test" with the following.
> +To efficiently and elegantly validate a test case against a variety of i=
nputs,
> +KUnit also provides a parameterized testing framework. This feature form=
alizes
> +and extends the concept of table-driven tests discussed previously, offe=
ring
> +a more integrated and flexible way to handle multiple test scenarios wit=
h
> +minimal code duplication.
> +
> +Passing Parameters to the Test Cases
> +^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
> +There are three main ways to provide the parameters to a test case:
> +
> +Array Parameter Macros (``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DES=
C``):
> +   KUnit provides special support for the common table-driven testing pa=
ttern.
> +   By applying either ``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DESC`=
` to the
> +   ``cases`` array from the previous section, we can create a parameteri=
zed test
> +   as shown below:

Is it possible to bold the titles of the ways to pass in parameters:
Array Parameter Macros, etc.? I feel like they should stand out more
from the rest of the text. Also I think I would prefer if there was an
empty line between the title and the rest of the indented text, to
again further separate these titles from the rest of the text.

>
>  .. code-block:: c
>
> @@ -555,7 +565,7 @@ By reusing the same ``cases`` array from above, we ca=
n write the test as a
>                 const char *str;
>                 const char *sha1;
>         };
> -       const struct sha1_test_case cases[] =3D {
> +       static const struct sha1_test_case cases[] =3D {
>                 {
>                         .str =3D "hello world",
>                         .sha1 =3D "2aae6c35c94fcfb415dbe95f408b9ce91ee846=
ed",
> @@ -590,6 +600,439 @@ By reusing the same ``cases`` array from above, we =
can write the test as a
>                 {}
>         };
>
> +Custom Parameter Generator (``generate_params``):
> +   You can pass your own ``generate_params`` function to the ``KUNIT_CAS=
E_PARAM``
> +   or ``KUNIT_CASE_PARAM_WITH_INIT`` macros. This function is responsibl=
e for
> +   generating parameters one by one. It receives the previously generate=
d parameter
> +   as the ``prev`` argument (which is ``NULL`` on the first call) and ca=
n also
> +   access any context available from the parent ``struct kunit`` passed =
as the
> +   ``test`` argument. KUnit calls this function repeatedly until it retu=
rns
> +   ``NULL``. Below is an example of how it works:
> +
> +.. code-block:: c
> +
> +       #define MAX_TEST_BUFFER_SIZE 8
> +
> +       // Example generator function. It produces a sequence of buffer s=
izes that
> +       // are powers of two, starting at 1 (e.g., 1, 2, 4, 8).
> +       static const void *buffer_size_gen_params(struct kunit *test, con=
st void *prev, char *desc)
> +       {
> +               long prev_buffer_size =3D (long)prev;
> +               long next_buffer_size =3D 1; // Start with an initial siz=
e of 1.
> +
> +               // Stop generating parameters if the limit is reached or =
exceeded.
> +               if (prev_buffer_size >=3D MAX_TEST_BUFFER_SIZE)
> +                       return NULL;
> +
> +               // For subsequent calls, calculate the next size by doubl=
ing the previous one.
> +               if (prev)
> +                       next_buffer_size =3D prev_buffer_size << 1;
> +
> +               return (void *)next_buffer_size;
> +       }
> +
> +       // Simple test to validate that kunit_kzalloc provides zeroed mem=
ory.
> +       static void buffer_zero_test(struct kunit *test)
> +       {
> +               long buffer_size =3D (long)test->param_value;
> +               // Use kunit_kzalloc to allocate a zero-initialized buffe=
r. This makes the
> +               // memory "parameter managed," meaning it's automatically=
 cleaned up at
> +               // the end of each parameter execution.
> +               int *buf =3D kunit_kzalloc(test, buffer_size * sizeof(int=
), GFP_KERNEL);
> +
> +               // Ensure the allocation was successful.
> +               KUNIT_ASSERT_NOT_NULL(test, buf);
> +
> +               // Loop through the buffer and confirm every element is z=
ero.
> +               for (int i =3D 0; i < buffer_size; i++)
> +                       KUNIT_EXPECT_EQ(test, buf[i], 0);
> +       }
> +
> +       static struct kunit_case buffer_test_cases[] =3D {
> +               KUNIT_CASE_PARAM(buffer_zero_test, buffer_size_gen_params=
),
> +               {}
> +       };
> +
> +Direct Registration in Parameter Init Function (using ``kunit_register_p=
arams_array``):
> +   For more complex scenarios, you can directly register a parameter arr=
ay with
> +   a test case instead of using a ``generate_params`` function. This is =
done by
> +   passing the array to the ``kunit_register_params_array`` macro within=
 an
> +   initialization function for the parameterized test series
> +   (i.e., a function named ``param_init``). To better understand this me=
chanism
> +   please refer to the "Adding Shared Resources" section below.
> +
> +   This method supports both dynamically built and static arrays.
> +
> +   As the following code shows, the ``example_param_init_dynamic_arr`` f=
unction
> +   utilizes ``make_fibonacci_params`` to create a dynamic array, which i=
s then
> +   registered using ``kunit_register_params_array``. The corresponding e=
xit
> +   function, ``example_param_exit``, is responsible for freeing this dyn=
amically
> +   allocated params array after the parameterized test series ends.
> +
> +.. code-block:: c

As David mentioned, this example code is a bit long. I would also
prefer if this example had just the highlights and then a link to the
source code.

> +
> +       /*
> +        * Helper function to create a parameter array of Fibonacci numbe=
rs. This example
> +        * highlights a parameter generation scenario that is:
> +        * 1. Not feasible to fully pre-generate at compile time.
> +        * 2. Challenging to implement with a standard 'generate_params' =
function,
> +        * as it typically only provides the immediately 'prev' parameter=
, while
> +        * Fibonacci requires access to two preceding values for calculat=
ion.
> +        */
> +       static void *make_fibonacci_params(int seq_size)
> +       {
> +               int *seq;
> +
> +               if (seq_size <=3D 0)
> +                       return NULL;
> +
> +               seq =3D kmalloc_array(seq_size, sizeof(int), GFP_KERNEL);
> +
> +               if (!seq)
> +                       return NULL;
> +
> +               if (seq_size >=3D 1)
> +                       seq[0] =3D 0;
> +               if (seq_size >=3D 2)
> +                       seq[1] =3D 1;
> +               for (int i =3D 2; i < seq_size; i++)
> +                       seq[i] =3D seq[i - 1] + seq[i - 2];
> +               return seq;
> +       }
> +
> +       // This is an example of a function that provides a description f=
or each of the
> +       // parameters.
> +       static void example_param_dynamic_arr_get_desc(const void *p, cha=
r *desc)
> +       {
> +               const int *fib_num =3D p;
> +
> +               snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %=
d", *fib_num);
> +       }
> +
> +       // Example of a parameterized test init function that registers a=
 dynamic array.
> +       static int example_param_init_dynamic_arr(struct kunit *test)
> +       {
> +               int seq_size =3D 6;
> +               int *fibonacci_params =3D make_fibonacci_params(seq_size)=
;
> +
> +               if (!fibonacci_params)
> +                       return -ENOMEM;
> +
> +               /*
> +                * Passes the dynamic parameter array information to the =
parent struct kunit.
> +                * The array and its metadata will be stored in test->par=
ent->params_data.
> +                * The array itself will be located in params_data.params=
.
> +                */
> +               kunit_register_params_array(test, fibonacci_params, seq_s=
ize,
> +                                           example_param_dynamic_arr_get=
_desc);
> +               return 0;
> +       }
> +
> +       // Function to clean up the parameterized test's parent kunit str=
uct if
> +       // there were custom allocations.
> +       static void example_param_exit_dynamic_arr(struct kunit *test)
> +       {
> +               /*
> +                * We allocated this array, so we need to free it.
> +                * Since the parent parameter instance is passed here,
> +                * we can directly access the array via `test->params_dat=
a.params`
> +                * instead of `test->parent->params_data.params`.
> +                */
> +               kfree(test->params_data.params);
> +       }
> +
> +       /*
> +        * Example of test that uses the registered dynamic array to perf=
orm assertions
> +        * and expectations.
> +        */
> +       static void example_params_test_with_init_dynamic_arr(struct kuni=
t *test)
> +       {
> +               const int *param =3D test->param_value;
> +               int param_val;
> +
> +               /* By design, param pointer will not be NULL. */
> +               KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +               param_val =3D *param;
> +               KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
> +       }
> +
> +       static struct kunit_case example_tests[] =3D {
> +               // The NULL here stands in for the generate_params functi=
on
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_=
dynamic_arr, NULL,
> +                                          example_param_init_dynamic_arr=
,
> +                                          example_param_exit_dynamic_arr=
),
> +               {}
> +       };
> +
> +
> +Adding Shared Resources
> +^^^^^^^^^^^^^^^^^^^^^^^
> +All parameterized test executions in this framework have a parent test o=
f type
> +``struct kunit``. This parent is not used to execute any test logic itse=
lf;
> +instead, it serves as a container for shared context that can be accesse=
d by
> +all its individual test executions (or parameters). Therefore, each indi=
vidual
> +test execution holds a pointer to this parent, accessible via a field na=
med
> +``parent``.
> +
> +It's possible to add resources to share between the individual test exec=
utions
> +within a parameterized test series by using the ``KUNIT_CASE_PARAM_WITH_=
INIT``
> +macro, to which you pass custom ``param_init`` and ``param_exit`` functi=
ons.
> +These functions run once before and once after the entire parameterized =
test
> +series, respectively. The ``param_init`` function can be used for adding=
 any
> +resources to the resources field of a parent test and also provide an ad=
ditional
> +way of setting the parameter array. The ``param_exit`` function can be u=
sed
> +release any resources that were not test managed i.e. not automatically =
cleaned
> +up after the test ends.
> +
> +.. note::
> +   If both a ``generate_params`` function is passed to ``KUNIT_CASE_PARA=
M_WITH_INIT``
> +   and an array is registered via ``kunit_register_params_array`` in
> +   ``param_init``, the ``generate_params`` function will be used to get
> +   the parameters.
> +
> +Both ``param_init`` and ``param_exit`` are passed the parent instance of=
 a test
> +(parent ``struct kunit``) behind the scenes. However, the test case func=
tion
> +receives the individual instance of a test for each parameter. Therefore=
, to
> +manage and access shared resources from within a test case function, you=
 must use
> +``test->parent``.
> +
> +.. note::
> +   The ``suite->init()`` function, which runs before each parameter exec=
ution,
> +   receives the individual instance of a test for each parameter. Theref=
ore,
> +   resources set up in ``suite->init()`` are reset for each individual
> +   parameterized test execution and are only visible within that specifi=
c test.
> +
> +For instance, finding a shared resource allocated by the Resource API re=
quires
> +passing ``test->parent`` to ``kunit_find_resource()``. This principle ex=
tends to
> +all other APIs that might be used in the test case function, including
> +``kunit_kzalloc()``, ``kunit_kmalloc_array()``, and others (see
> +Documentation/dev-tools/kunit/api/test.rst and the
> +Documentation/dev-tools/kunit/api/resource.rst).
> +
> +The code below shows how you can add the shared resources. Note that thi=
s code
> +utilizes the Resource API, which you can read more about here:
> +Documentation/dev-tools/kunit/api/resource.rst.

It would be nice if these references to the Documentation files were
actual links to the webpages. This would look something like -
":ref:`kunit-resource`" and then also labeling that section: "..
_kunit-resource:".

> +
> +.. code-block:: c
> +
> +       /* An example parameter array. */
> +       static const struct example_param {
> +               int value;
> +       } example_params_array[] =3D {
> +               { .value =3D 3, },
> +               { .value =3D 2, },
> +               { .value =3D 1, },
> +               { .value =3D 0, },
> +       };
> +
> +       /*
> +        * This custom function allocates memory for the kunit_resource d=
ata field.
> +        * The function is passed to kunit_alloc_resource() and executed =
once
> +        * by the internal helper __kunit_add_resource().
> +        */
> +       static int example_resource_init(struct kunit_resource *res, void=
 *context)
> +       {
> +               int *info =3D kmalloc(sizeof(*info), GFP_KERNEL);
> +
> +               if (!info)
> +                       return -ENOMEM;
> +               *info =3D *(int *)context;
> +               res->data =3D info;
> +               return 0;
> +       }
> +
> +       /*
> +        * This function deallocates memory for the 'kunit_resource' data=
 field.
> +        * The function is passed to kunit_alloc_resource() and automatic=
ally
> +        * executes within kunit_release_resource() when the resource's r=
eference
> +        * count, via kunit_put_resource(), drops to zero. KUnit uses ref=
erence
> +        * counting to ensure that resources are not freed prematurely.
> +        */
> +       static void example_resource_free(struct kunit_resource *res)
> +       {
> +               kfree(res->data);
> +       }
> +
> +       /*
> +        * This match function is invoked by kunit_find_resource() to loc=
ate
> +        * a test resource based on defined criteria. The current example
> +        * uniquely identifies the resource by its free function; however=
,
> +        * alternative custom criteria can be implemented. Refer to
> +        * lib/kunit/platform.c and lib/kunit/static_stub.c for further e=
xamples.
> +        */
> +       static bool example_resource_alloc_match(struct kunit *test,
> +                                                struct kunit_resource *r=
es,
> +                                                void *match_data)
> +       {
> +               return res->data && res->free =3D=3D example_resource_fre=
e;
> +       }
> +
> +       /*
> +        * This is an example of a function that provides a description f=
or each of the
> +        * parameters.
> +       */
> +       static void example_param_array_get_desc(const void *p, char *des=
c)
> +       {
> +               const struct example_param *param =3D p;
> +
> +               snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> +                       "example check if %d is less than or equal to 3",=
 param->value);
> +       }
> +
> +       /*
> +        * Initializes the parent kunit struct for parameterized KUnit te=
sts.
> +        * This function enables sharing resources across all parameteriz=
ed
> +        * tests by adding them to the `parent` kunit test struct. It als=
o supports
> +        * registering either static or dynamic arrays of test parameters=
.
> +        */
> +       static int example_param_init(struct kunit *test)
> +       {
> +               int ctx =3D 3; /* Data to be stored. */
> +               int arr_size =3D ARRAY_SIZE(example_params_array);
> +
> +               /*
> +                * This allocates a struct kunit_resource, sets its data =
field to
> +                * ctx, and adds it to the kunit struct's resources list.=
 Note that
> +                * this is test managed so we don't need to have a custom=
 exit function
> +                * to free it.
> +                */
> +               void *data =3D kunit_alloc_resource(test, example_resourc=
e_init, example_resource_free,
> +                                                 GFP_KERNEL, &ctx);
> +
> +               if (!data)
> +                       return -ENOMEM;
> +               /* Pass the static param array information to the parent =
struct kunit. */
> +               kunit_register_params_array(test, example_params_array, a=
rr_size,
> +                                           example_param_array_get_desc)=
;
> +               return 0;
> +       }
> +
> +       /*
> +       * This is an example of a parameterized test that uses shared res=
ources
> +       * available from the struct kunit parent field of the kunit struc=
t.
> +       */
> +       static void example_params_test_with_init(struct kunit *test)
> +       {
> +               int threshold;
> +               struct kunit_resource *res;
> +               const struct example_param *param =3D test->param_value;
> +
> +               /* By design, param pointer will not be NULL. */
> +               KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +               /* Here we need to access the parent pointer of the test =
to find the shared resource. */
> +               res =3D kunit_find_resource(test->parent, example_resourc=
e_alloc_match, NULL);
> +
> +               KUNIT_ASSERT_NOT_NULL(test, res);
> +
> +               /* Since the data field in kunit_resource is a void point=
er we need to typecast it. */
> +               threshold =3D *((int *)res->data);
> +
> +               /* Assert that the parameter is less than or equal to a c=
ertain threshold. */
> +               KUNIT_ASSERT_LE(test, param->value, threshold);
> +
> +               /* This decreases the reference count after calling kunit=
_find_resource(). */
> +               kunit_put_resource(res);
> +       }
> +
> +
> +       static struct kunit_case example_tests[] =3D {
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init,=
 NULL,
> +                                          example_param_init, NULL),
> +               {}
> +       };
> +
> +As an alternative to using the KUnit Resource API for shared resources, =
you can
> +place them in ``test->parent->priv``. It can store data that needs to pe=
rsist
> +and be accessible across all executions within a parameterized test seri=
es.
> +
> +As stated previously ``param_init`` and ``param_exit`` receive the paren=
t
> +``struct kunit`` instance. So, you can directly use ``test->priv`` withi=
n them
> +to manage shared resources. However, from within the test case function,=
 you must
> +navigate up to the parent i.e. use ``test->parent->priv`` to access thos=
e same
> +resources.
> +
> +The resources placed in ``test->parent-priv`` will also need to be alloc=
ated in

Nit: I think this is a typo for test->parent->priv.



> +memory to persist across the parameterized tests executions. If memory i=
s
> +allocated using the memory allocation APIs provided by KUnit (described =
more in
> +the section below), you will not need to worry about deallocating them a=
s they
> +will be managed by the parent parameterized test that gets automatically=
 cleaned
> +up upon the end of the parameterized test series.
> +
> +The code below demonstrates example usage of the ``priv`` field for shar=
ed
> +resources:
> +
> +.. code-block:: c
> +
> +       /* An example parameter array. */
> +       static const struct example_param {
> +               int value;
> +       } example_params_array[] =3D {
> +               { .value =3D 3, },
> +               { .value =3D 2, },
> +               { .value =3D 1, },
> +               { .value =3D 0, },
> +       };
> +
> +       /*
> +        * Initializes the parent kunit struct for parameterized KUnit te=
sts.
> +        * This function enables sharing resources across all parameteriz=
ed
> +        * tests.
> +        */
> +       static int example_param_init_priv(struct kunit *test)
> +       {
> +               int ctx =3D 3; /* Data to be stored. */
> +               int arr_size =3D ARRAY_SIZE(example_params_array);
> +
> +               /*
> +                * Allocate memory using kunit_kzalloc(). Since the `para=
m_init`
> +                * function receives the parent instance of test, this me=
mory
> +                * allocation will be scoped to the lifetime of the whole
> +                * parameterized test series.
> +                */
> +               test->priv =3D kunit_kzalloc(test, sizeof(int), GFP_KERNE=
L);
> +
> +               /* Assign the context value to test->priv.*/
> +               *((int *)test->priv) =3D ctx;
> +
> +               /* Pass the static param array information to the parent =
struct kunit. */
> +               kunit_register_params_array(test, example_params_array, a=
rr_size, NULL);
> +               return 0;
> +       }
> +
> +       /*
> +       * This is an example of a parameterized test that uses shared res=
ources
> +       * available from the struct kunit parent field of the kunit struc=
t.
> +       */
> +       static void example_params_test_with_init_priv(struct kunit *test=
)
> +       {
> +               int threshold;
> +               const struct example_param *param =3D test->param_value;
> +
> +               /* By design, param pointer will not be NULL. */
> +               KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +               /* By design, test->parent will also not be NULL. */
> +               KUNIT_ASSERT_NOT_NULL(test, test->parent);
> +
> +               /* Assert that test->parent->priv has data. */
> +               KUNIT_ASSERT_NOT_NULL(test, test->parent->priv);
> +
> +               /* Here we need to use test->parent->priv to access the s=
hared resource. */
> +               threshold =3D *(int *)test->parent->priv;
> +
> +               /* Assert that the parameter is less than or equal to a c=
ertain threshold. */
> +               KUNIT_ASSERT_LE(test, param->value, threshold);
> +       }
> +
> +
> +       static struct kunit_case example_tests[] =3D {
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_=
priv, NULL,
> +                                          example_param_init_priv, NULL)=
,
> +               {}
> +       };
> +
>  Allocating Memory
>  -----------------
>
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov5q-mAHuchZNqS6DEv1zFmDzhF1SSdjBfJyB0ZnqUCQfg%40mail.gmail.com.
