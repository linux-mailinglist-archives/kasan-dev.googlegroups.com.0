Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJGUZ6ZQMGQEBFUE2HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id B131A90FEFD
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 10:36:53 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6af35481ea6sf8969396d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 01:36:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718872612; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNJlmP1BLraOs7saDaUSI4j7y0YYfyQIunxDV62ZrvbtBi/IglGTkrc2/NnH+Wj7ai
         ChRQ2eyJk7TeKk+IqyURE4JrDqznB3lLGqrhUmb+lRBhaTiMVhOpmN8ALJULr72Y6D8p
         nAEzDYYs2/vDFWE7Z7AoADLO3WZDxX6UE43ZFExqxzqc6OWM0FD4CHjNOJyvWoNYwgZN
         2yrlp/O1ptdP+GcX/LeLIg7tIzgrLlf6eSp5E73eu9cWigr4Ifigs4qdw2qia7E+noH9
         2xswSM0QwOHNais16QQ8s0lnhxbg9DmkangzLsAx3DnLwwGS62tk4QUrEde+LB59ocVx
         5PZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=na0+51rMSL0aMrGM4XXhd5KWri34nPdCxBLK/EkIhWA=;
        fh=jnSrPlDZnVZ7zScdds2pts7CUzXcL86jSdVDgxu/iRw=;
        b=jrq88T9JlhVaR5Gf7wv4VBPTH2kZ8r2Apb1YwwfLgYb6SwlKaNqUSeG1kKITNiy3KW
         DsmJ0/VawPU4oy+l4gSjyK7V/EUiCo/Fyj2Yh+hrqR9uQWvoA45eCwJGQkBuNmW/DiC9
         jOlU2yb7pij2T7Q2vDcfFe1dAGVLWWGeRG4tYi9+OAQUgK17Z5B4G3RjqPMAHIPPkgvZ
         UuMLauhJLocx14FlZBebw0vJNrzIqPQCeHQYzozISzCy+PWIDKnHkJKInhO2w1nUl0fk
         dwHSKUxnyz9OjS1SMNUPiSsXVItLjWOZEJpTYZyf9CxgYP7uedlY8rccAO5dfl95eAh2
         bWhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SQTsc1nr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718872612; x=1719477412; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=na0+51rMSL0aMrGM4XXhd5KWri34nPdCxBLK/EkIhWA=;
        b=Y3zYIS8jbzJZFOujQ2eZqrdIiV/nMxPZ5SVBdSymWALuFg9ziTZyWDCpi7b6O4K0W1
         7e4a/qzBo8t585Ge7T2Cw7A+FktyVBD2UvaJzQDB8UXCP+LFl67iwWkYCGIDYgdmCuio
         Z4Pl1LWTywZSFzLGAYWEFuEK6lTjD8brbGerpyMKVVfDyslosIh3sQh7KNYr2plEDXn4
         lfQKPlNtK2pFR/zO4f6Ak14PieZdaoZgZAWgP6xV5gyd48UaOt5yxnUetKCXwwyE1kVi
         maWyPYTD/GM2be+ZyM6t7H/BZ4T0lUxrt6mGC/2jEuvKkAbsN6IXpxGu10WSzyqdQ4gH
         4BqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718872612; x=1719477412;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=na0+51rMSL0aMrGM4XXhd5KWri34nPdCxBLK/EkIhWA=;
        b=itxosnW9Dfu68TOCRz4O7Mdq46QOst/znHhU4lBL315J8Wq9Cn3XESrkwr7VKHhEBw
         r0FhfkD961WEYqrBaST42zem7MzVcXiwQQbGMa0a6n/dCaiyKl/1fTIzWkfHVf1WFPLC
         m6aaz1TE0ZUjKIBMCwhzHzrEeedACMqMuq5a+FQbXTvOgNLXWSF+lXnbO5/aDQRgLine
         LUHoYK91YdDQVHikxRHje1Nl4PTK8KzsHVvE89NpCOMEGBDaF7ZeY6AqnlDNKs02JECT
         opEAt2Td0v4HwhEq+uVoJsA+reThL8GxZVeb61LTab56hHUxCjvkthEEhOijEQ+Mooc/
         PU2w==
X-Forwarded-Encrypted: i=2; AJvYcCVqLnTmnaUFMye2rLlBOvLpWpe6sMMlXUO8HqZOcU7NaEeoYsirlmyzn3GasnErVQxgDPiRVWqYSx+OzvbNraO1XBpsYnvPAg==
X-Gm-Message-State: AOJu0YypWDKjUeGuRfYZ5uENk5eIL3hxWhHbRg2nyCa6rs3rZqXHyG/m
	u5hrb+Kf9ElOMPNdT/Vdfmll7wi5E39vnpqDdNbFX5JPJGi0uu+u
X-Google-Smtp-Source: AGHT+IG51cOtssMsnPh72Ur5EWE8NtLlZN7WCSD6QgvCabGfw4n7GeJ3cAJDgO3KTro7HOQYM0sIew==
X-Received: by 2002:a0c:fb46:0:b0:6b5:6a1:f89a with SMTP id 6a1803df08f44-6b506a1fc85mr35876076d6.2.1718872612372;
        Thu, 20 Jun 2024 01:36:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3290:b0:6b0:9379:f464 with SMTP id
 6a1803df08f44-6b5101cdc47ls7947256d6.1.-pod-prod-04-us; Thu, 20 Jun 2024
 01:36:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWA8A/uJYv3tW8l0m37Y6VwmZvUptfqZ4Lqj3Zv3tZA0Ib6vtYVKF3GJP9SE4qt1lbLuyEhxDRTg7Vu8eLXGao+fBnxHzcpEfBzKQ==
X-Received: by 2002:ad4:530a:0:b0:6b5:40c:f108 with SMTP id 6a1803df08f44-6b5040cf171mr44649246d6.37.1718872611142;
        Thu, 20 Jun 2024 01:36:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718872611; cv=none;
        d=google.com; s=arc-20160816;
        b=z8+HKgZNAXdyRCVOyHA5n3Jdsd/clNtajtlBEZDoZzOwDUowTGkBO9R5O7dyeosJdT
         8U2LIYtalo91XglqjJGiBM6cObAGUnJu+ULrPDSlrBvHZo0gLovoFwhJuu8gSoxci8b2
         7muU6OkAStoGz/phqKj02G06qECgGqTxkX2V0bsErnJzcs0EbfR+wq6HN3h/d4Lg/4gd
         4Fcm1UL4SyECW0wUvfLf1vvpeNMk83Z7F+zhAzitGLvYFEXnTQkXXjCRbw/NcFr7kuve
         tnSV5UpiYsrILjbghl8RDF2e45SbC5MfYh5W/AVFQGGH+PtrqSmrADllmRePO7Xt5bKt
         jEMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/OUYcIAPu8Sr/lzFQuuddP6LocZmaVvpQ1N05tgsbXo=;
        fh=qtTZbJtbaz+TkK6ps6AWwgOGrTSNW5jRH3CPJwCsPZo=;
        b=CAdTknB+hZ2YIxYxdu8z5NFXdGCpE8U+TNUDANkE5/vKA050DZA8mW93wefV/DJ8uN
         hOYMOr0TqlQ2dAakLfOopzZm7LJFrxEsY8JvoyCnCf+3C0DlgYiMZjBiEG7ivRJpJ+3S
         vNLYj58ojvmiasjOIsN8mO3uax5J3ThdqR+XrmlmvbKglWK9SlccwIFDLg2SEDvYcmgE
         jrZ/dzPF41taOUujliskIVeE+qXa1ZgfZr1lXw0Ry4ud/VUJLPo7KC2fYOazluAbEyLN
         PX9VY3Au2OkYzNYIhOp8cdy2KBiusOAPdyasy7XHkMf2xo7LSdMyyCx+D5dw1AbjC0Uw
         Lp/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SQTsc1nr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b4f43a5d9fsi2254836d6.0.2024.06.20.01.36.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 01:36:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-44218680203so2726601cf.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 01:36:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUiNMXbCn0PUIZ6lBLkfqCRaYenq5A5DXBC5DR4t5cwDZjQbFERYzYYmG/y7pyABB2N2RmcXEbLjihJHUie9eOrTfhAnIwyGPvzdg==
X-Received: by 2002:a05:6214:4a42:b0:6b4:f761:f0b8 with SMTP id
 6a1803df08f44-6b501dff5a9mr45755846d6.8.1718872610557; Thu, 20 Jun 2024
 01:36:50 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-34-iii@linux.ibm.com>
In-Reply-To: <20240619154530.163232-34-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 10:36:12 +0200
Message-ID: <CAG_fn=V8Tt28LE9FtoYkos=5XG4zP_tDP1mF1COfEhAMg2ULqQ@mail.gmail.com>
Subject: Re: [PATCH v5 33/37] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SQTsc1nr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> put_user() uses inline assembly with precise constraints, so Clang is
> in principle capable of instrumenting it automatically. Unfortunately,
> one of the constraints contains a dereferenced user pointer, and Clang
> does not currently distinguish user and kernel pointers. Therefore
> KMSAN attempts to access shadow for user pointers, which is not a right
> thing to do.

By the way, how does this problem manifest?
I was expecting KMSAN to generate dummy shadow accesses in this case,
and reading/writing 1-8 bytes from dummy shadow shouldn't be a
problem.

(On the other hand, not inlining the get_user/put_user functions is
probably still faster than retrieving the dummy shadow, so I'm fine
either way)

>
> An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
> work, since it's __always_inline. And __always_inline cannot be removed
> due to the __put_user_bad() trick.
>
> A different obvious fix of using the "a" instead of the "+Q" constraint
> degrades the code quality, which is very important here, since it's a
> hot path.
>
> Instead, repurpose the __put_user_asm() macro to define
> __put_user_{char,short,int,long}_noinstr() functions and mark them with
> __no_sanitize_memory. For the non-KMSAN builds make them
> __always_inline in order to keep the generated code quality. Also
> define __put_user_{char,short,int,long}() functions, which call the
> aforementioned ones and which *are* instrumented, because they call
> KMSAN hooks, which may be implemented as macros.
>
> The same applies to get_user() as well.
>
> Acked-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/uaccess.h | 111 +++++++++++++++++++++++---------
>  1 file changed, 79 insertions(+), 32 deletions(-)
>
> diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uacc=
ess.h
> index 81ae8a98e7ec..70f0edc00c2a 100644
> --- a/arch/s390/include/asm/uaccess.h
> +++ b/arch/s390/include/asm/uaccess.h
> @@ -78,13 +78,24 @@ union oac {
>
>  int __noreturn __put_user_bad(void);
>
> -#define __put_user_asm(to, from, size)                                 \
> -({                                                                     \
> +#ifdef CONFIG_KMSAN
> +#define get_put_user_noinstr_attributes \
> +       noinline __maybe_unused __no_sanitize_memory
> +#else
> +#define get_put_user_noinstr_attributes __always_inline
> +#endif
> +
> +#define DEFINE_PUT_USER(type)                                          \
> +static get_put_user_noinstr_attributes int                             \
> +__put_user_##type##_noinstr(unsigned type __user *to,                  \
> +                           unsigned type *from,                        \
> +                           unsigned long size)                         \
> +{                                                                      \
>         union oac __oac_spec =3D {                                       =
 \
>                 .oac1.as =3D PSW_BITS_AS_SECONDARY,                      =
 \
>                 .oac1.a =3D 1,                                           =
 \
>         };                                                              \
> -       int __rc;                                                       \
> +       int rc;                                                         \
>                                                                         \
>         asm volatile(                                                   \
>                 "       lr      0,%[spec]\n"                            \
> @@ -93,12 +104,28 @@ int __noreturn __put_user_bad(void);
>                 "2:\n"                                                  \
>                 EX_TABLE_UA_STORE(0b, 2b, %[rc])                        \
>                 EX_TABLE_UA_STORE(1b, 2b, %[rc])                        \
> -               : [rc] "=3D&d" (__rc), [_to] "+Q" (*(to))                =
 \
> +               : [rc] "=3D&d" (rc), [_to] "+Q" (*(to))                  =
 \
>                 : [_size] "d" (size), [_from] "Q" (*(from)),            \
>                   [spec] "d" (__oac_spec.val)                           \
>                 : "cc", "0");                                           \
> -       __rc;                                                           \
> -})
> +       return rc;                                                      \
> +}                                                                      \
> +                                                                       \
> +static __always_inline int                                             \
> +__put_user_##type(unsigned type __user *to, unsigned type *from,       \
> +                 unsigned long size)                                   \
> +{                                                                      \
> +       int rc;                                                         \
> +                                                                       \
> +       rc =3D __put_user_##type##_noinstr(to, from, size);              =
 \
> +       instrument_put_user(*from, to, size);                           \
> +       return rc;                                                      \
> +}
> +
> +DEFINE_PUT_USER(char);
> +DEFINE_PUT_USER(short);
> +DEFINE_PUT_USER(int);
> +DEFINE_PUT_USER(long);
>
>  static __always_inline int __put_user_fn(void *x, void __user *ptr, unsi=
gned long size)
>  {
> @@ -106,24 +133,24 @@ static __always_inline int __put_user_fn(void *x, v=
oid __user *ptr, unsigned lon
>
>         switch (size) {
>         case 1:
> -               rc =3D __put_user_asm((unsigned char __user *)ptr,
> -                                   (unsigned char *)x,
> -                                   size);
> +               rc =3D __put_user_char((unsigned char __user *)ptr,
> +                                    (unsigned char *)x,
> +                                    size);
>                 break;
>         case 2:
> -               rc =3D __put_user_asm((unsigned short __user *)ptr,
> -                                   (unsigned short *)x,
> -                                   size);
> +               rc =3D __put_user_short((unsigned short __user *)ptr,
> +                                     (unsigned short *)x,
> +                                     size);
>                 break;
>         case 4:
> -               rc =3D __put_user_asm((unsigned int __user *)ptr,
> +               rc =3D __put_user_int((unsigned int __user *)ptr,
>                                     (unsigned int *)x,
>                                     size);
>                 break;
>         case 8:
> -               rc =3D __put_user_asm((unsigned long __user *)ptr,
> -                                   (unsigned long *)x,
> -                                   size);
> +               rc =3D __put_user_long((unsigned long __user *)ptr,
> +                                    (unsigned long *)x,
> +                                    size);
>                 break;
>         default:
>                 __put_user_bad();
> @@ -134,13 +161,17 @@ static __always_inline int __put_user_fn(void *x, v=
oid __user *ptr, unsigned lon
>
>  int __noreturn __get_user_bad(void);
>
> -#define __get_user_asm(to, from, size)                                 \
> -({                                                                     \
> +#define DEFINE_GET_USER(type)                                          \
> +static get_put_user_noinstr_attributes int                             \
> +__get_user_##type##_noinstr(unsigned type *to,                         \
> +                           unsigned type __user *from,                 \
> +                           unsigned long size)                         \
> +{                                                                      \
>         union oac __oac_spec =3D {                                       =
 \
>                 .oac2.as =3D PSW_BITS_AS_SECONDARY,                      =
 \
>                 .oac2.a =3D 1,                                           =
 \
>         };                                                              \
> -       int __rc;                                                       \
> +       int rc;                                                         \
>                                                                         \
>         asm volatile(                                                   \
>                 "       lr      0,%[spec]\n"                            \
> @@ -149,13 +180,29 @@ int __noreturn __get_user_bad(void);
>                 "2:\n"                                                  \
>                 EX_TABLE_UA_LOAD_MEM(0b, 2b, %[rc], %[_to], %[_ksize])  \
>                 EX_TABLE_UA_LOAD_MEM(1b, 2b, %[rc], %[_to], %[_ksize])  \
> -               : [rc] "=3D&d" (__rc), "=3DQ" (*(to))                    =
   \
> +               : [rc] "=3D&d" (rc), "=3DQ" (*(to))                      =
   \
>                 : [_size] "d" (size), [_from] "Q" (*(from)),            \
>                   [spec] "d" (__oac_spec.val), [_to] "a" (to),          \
>                   [_ksize] "K" (size)                                   \
>                 : "cc", "0");                                           \
> -       __rc;                                                           \
> -})
> +       return rc;                                                      \
> +}                                                                      \
> +                                                                       \
> +static __always_inline int                                             \
> +__get_user_##type(unsigned type *to, unsigned type __user *from,       \
> +                 unsigned long size)                                   \
> +{                                                                      \
> +       int rc;                                                         \
> +                                                                       \
> +       rc =3D __get_user_##type##_noinstr(to, from, size);              =
 \
> +       instrument_get_user(*to);                                       \
> +       return rc;                                                      \
> +}
> +
> +DEFINE_GET_USER(char);
> +DEFINE_GET_USER(short);
> +DEFINE_GET_USER(int);
> +DEFINE_GET_USER(long);
>
>  static __always_inline int __get_user_fn(void *x, const void __user *ptr=
, unsigned long size)
>  {
> @@ -163,24 +210,24 @@ static __always_inline int __get_user_fn(void *x, c=
onst void __user *ptr, unsign
>
>         switch (size) {
>         case 1:
> -               rc =3D __get_user_asm((unsigned char *)x,
> -                                   (unsigned char __user *)ptr,
> -                                   size);
> +               rc =3D __get_user_char((unsigned char *)x,
> +                                    (unsigned char __user *)ptr,
> +                                    size);
>                 break;
>         case 2:
> -               rc =3D __get_user_asm((unsigned short *)x,
> -                                   (unsigned short __user *)ptr,
> -                                   size);
> +               rc =3D __get_user_short((unsigned short *)x,
> +                                     (unsigned short __user *)ptr,
> +                                     size);
>                 break;
>         case 4:
> -               rc =3D __get_user_asm((unsigned int *)x,
> +               rc =3D __get_user_int((unsigned int *)x,
>                                     (unsigned int __user *)ptr,
>                                     size);
>                 break;
>         case 8:
> -               rc =3D __get_user_asm((unsigned long *)x,
> -                                   (unsigned long __user *)ptr,
> -                                   size);
> +               rc =3D __get_user_long((unsigned long *)x,
> +                                    (unsigned long __user *)ptr,
> +                                    size);
>                 break;
>         default:
>                 __get_user_bad();
> --
> 2.45.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20240619154530.163232-34-iii%40linux.ibm.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV8Tt28LE9FtoYkos%3D5XG4zP_tDP1mF1COfEhAMg2ULqQ%40mail.gm=
ail.com.
