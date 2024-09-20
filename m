Return-Path: <kasan-dev+bncBDW2JDUY5AORBIXNW63QMGQEOOV7FTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 61F6997DA8D
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 00:26:44 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42cb22d396csf19887265e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 15:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726871204; cv=pass;
        d=google.com; s=arc-20240605;
        b=TrubBiQY8iO6+RQQivguS2TZjgkcc6PGBzsyvXJkTt+2gup/PgNvnB3mt9AU6Cge1Q
         zDRAM5iLMsxZuJt+QnhC1Dg1Wp+D7ahcu3pdgx02bGQuQrQRCHMLLwEcRpt+d6cwISdP
         BLlVz4mDuX7wo/vjvohSY9WsEIlrSK2y3OgFIP9lLjrHIesgGbjHqSb2bUmL2s4O0OKw
         6nU0ngyD4X5/hUFTfvUMqHbTIGCpc8jR0k/zvyzfuWYBkpQra0ApOBYZpXjFoPEa6p1D
         ZllwoNUOmNdL5RQFvzF98sNSpYuQKqTyBFKcYVhjzGk5p0RHAxBTuW/yPBY8NCRqSJyF
         rH0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pQ6pJfXZYvLfBaBj3+jAmoweK/58cUpNtAWgKwOwGuw=;
        fh=TglMjDqJCAV7k9psvwjGeLdiaprA45mj2gOBkPY5s44=;
        b=bLg+Zb1A2ohMQKiDUKdly8KsnYW+2WfePzAW6Vy92tBlrXmAaSS11dqLl46L7JY7rL
         IyKt5ooY1fqEIkcFRe93gxAwqgyJqFUz8ddho9M/6qgBz0WOhDoQPLkD/AUC17asL68a
         GWe7JNxy6qBW30i2MBSgx/QiiOxJPVO70p5TunX5psnCl4ojobDMVKSccJVRhXoUhPKe
         qFOa1A5byhMwaizLjrNBwhLAyqscinBF4dve5iIxnYGLKGCcz9tvnKR6enO9jUew1ZRL
         Q6VnlzZ0a4dSEYqtv9V7cljF0hB/PaEU9JtbW01nEI9kNo1HAHrRz2lmDIpKrjvzlTDM
         e6pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gDs8cAtt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726871204; x=1727476004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pQ6pJfXZYvLfBaBj3+jAmoweK/58cUpNtAWgKwOwGuw=;
        b=nOWtTE238ecxShKSajY5LrrfrEct3C11Bk4Gejj4UWt9osKtF4KHQPmOcbOuMa97x6
         qJMXilpbxR67L1G1kv9JXMVS5leJ5hd4PUEhXq8HfBl9P9x7IvDiujrf56LDWS6e2wsb
         YWTSzPOdhxamYhMm5WGGGhxHD7jLCs2lbdM0iCi+fY1ZMgnd65va1woL+IvbM6fh3aXh
         g5tJuaUZwU3ZZU4Uyrs68MiGZo7GENU0M6tQvHUHT1oykpuPMjJegQrUcMTn/vi0uXN7
         CuF/rNB2MdrZLi3iZlfR9w6idiNY857/4rfZNHLxfWhpVVSS8RxBP3S7w60BonWqwzpl
         1BFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726871204; x=1727476004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pQ6pJfXZYvLfBaBj3+jAmoweK/58cUpNtAWgKwOwGuw=;
        b=J8ptrTuYtswn7b7r+G7XscTx+ZOxVF8CAh7UlJpC2t2UJKyY1q6ZLC605kSuhbyGTn
         lhMgJBENiekq5t/VELH6LEAe7RyGmpu0d53HNagcIObb1Rar/RpdEIDmh/ZJBYETJOIr
         HXXtznU30mzZk0BKD6s6zAMz/HEIZMgcbWjK4d6woQSgVtdMq8oz5P6HzfB9TPQBDWeb
         71qOnigDlwR3q68ndqud8ivKNb7WFounr2glkiYG/e0pkfXjj/YYzYqm1zOcnmHy+gmE
         1JgLKFSnM3FwI1MceJOieT/p7WZHV9LBVyyF5d8iFmKAF3uudUeRyoW7ytIgLxmiOKWq
         89TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726871204; x=1727476004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pQ6pJfXZYvLfBaBj3+jAmoweK/58cUpNtAWgKwOwGuw=;
        b=CbyD/uddQOmYa8kaqnIrjoRY19w1rIoVnk9uVZ8tsLG60hGKHikg7+ik+ShhbRX87s
         dfGiW3+78bwpenx6Xt0PthShr0cSp8kHxd+o78QHTvTMS45QQuOQ0Xw8s79UdnmUjtKy
         dUfn5evRdFIjhjIV/RaR18EHNo0stu2AKrTCuaex3rVCzfF2WNRqqmzLFMg9yrLlgt74
         DCVkfWJYSxOZLTBSWLJ/2czT0sqmzha+GezQgzX+MGAuScq3NdbIQRQ4cZLrXhwvh7Bt
         en2RS4oYWrhPZYYrBlbyT2K9Dp5vduoChSNDalATm53696rXAsaaDSXmUWQsCV4vZR/C
         NmCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOExROBuUyOfD2MQ9lYz48rsINPXXO7HPwN5NJppHzxXDYpMMM5IhDENEROD45GLGiCYCzWA==@lfdr.de
X-Gm-Message-State: AOJu0Yw58j/rrT3fzhXHOCoCAdXHxHHuoZ71tIAGeME78FN/JdtjBPFv
	OZohcIYatvBZOdSWuXh0yzMhSO1dSI9+uYgIOh2sajfzjxdmvy+F
X-Google-Smtp-Source: AGHT+IG2PI6kCTKxPfeBNxCAW72DzLQDabRunp9CKuEsp6HcTqgQF/9W0tY9FKJAWRaRKctbDKbgzw==
X-Received: by 2002:adf:f9ca:0:b0:374:c1a9:b97b with SMTP id ffacd0b85a97d-37a4312b2dbmr2554853f8f.8.1726871202815;
        Fri, 20 Sep 2024 15:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:154c:b0:42c:c82f:e5b with SMTP id
 5b1f17b1804b1-42e747476d3ls7939245e9.2.-pod-prod-09-eu; Fri, 20 Sep 2024
 15:26:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUyGkgQtpvEdy5oX4lvfn2Wsr1zji99EBeb90+Jno8DPqU35OAtHUWi7dcNLPhxmhCREw5sDwHFVxY=@googlegroups.com
X-Received: by 2002:adf:e28e:0:b0:374:c56c:fbc7 with SMTP id ffacd0b85a97d-37a4314628fmr2301208f8f.15.1726871200822;
        Fri, 20 Sep 2024 15:26:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726871200; cv=none;
        d=google.com; s=arc-20240605;
        b=F3iqyEqZaWgwpy+n9D3P7KhIcNfAD6gDibLHNPCpwsIm7k2tlg2dgUsP5VdnOJSTX6
         uqXr/RmXhG0sNT5+QmozIwVGG2UG+cILns7DToIcSGBKjRPam2HChvN9icJeqzLHUyt3
         vjntWL0h3Is64QhS1TecIvwwv6e0aIOYfr06m26EGaJt68/8+i2q4ioLC4ACUwg5pgPt
         EdLJ3Lg7jvGjuod2ZAydmNt65ocvOP4nKvChJ4+DlrjMJqIkEA/TGDjMm2X9qNntn9le
         C8flUsBCuYUyPQi0V0JlqOcSclcsRV55hpuO5vamVzbKPTDCgscreQR3uAV5UvVXZFru
         ndNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6ne01jFW0K4x6QCPtZYjHKYV4ojmW2zokGbfexor1Lk=;
        fh=/I6E6nPes+E2XTu7PgT7PudbQM79PQAA4nYXYJsOuDQ=;
        b=VmTt508qGiT/qX56m5kJr3gvEfrlzfSY41UatQYsMrsEFlvZDQ8QTLzoiox28yq4y8
         Put/5wT2VL0BXQhNb2J58zWir9TBogbo/OZjhlUo6fsfm6fXK9e5ZsIk0mB2Nke2h2x8
         /U4/blavbgyoKQDDklVYyymqOeqrAcHbFRZ59uE7C09/4ZnBL24dXDPtklSfTuI3FQNA
         pWMiW1wGwlzWcpP0uq7JIIualEXn1Xfe2XPFzS1+R/wmfnmpq+AJEYNe8rTVzhQnVqJ+
         gSbD/Lk2kD0LpCTpmjocSIy1My7zKMyXRmpNegmgYgBY4kj1cH4wnR69rm3f6G14ockg
         0DUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gDs8cAtt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-378e780de08si249418f8f.6.2024.09.20.15.26.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2024 15:26:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-4280ca0791bso22897565e9.1
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2024 15:26:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW1Okusqj0V8jMorwq3jPDvRQpX4WnU5DIxzD6YXZe9d3A98HqMIsz9TXtYgvyNpyg5mYKI0aYMUTw=@googlegroups.com
X-Received: by 2002:a05:600c:1c87:b0:42c:af2a:dcf4 with SMTP id
 5b1f17b1804b1-42e7c1a3283mr24646825e9.27.1726871200155; Fri, 20 Sep 2024
 15:26:40 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfg2E7Hk2Sc-=Z4XnENm9KUtmAZ6378YgeJg6xriMQXpA@mail.gmail.com>
 <20240919105750.901303-1-snovitoll@gmail.com>
In-Reply-To: <20240919105750.901303-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 21 Sep 2024 00:26:28 +0200
Message-ID: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
Subject: Re: [PATCH v3] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gDs8cAtt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
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

On Thu, Sep 19, 2024 at 12:57=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> On Wed, Sep 18, 2024 at 8:15=E2=80=AFPM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> > You still have the same problem here.
> >
> > What I meant is:
> >
> > char *ptr;
> > char buf[128 - KASAN_GRANULE_SIZE];
> > size_t size =3D sizeof(buf);
> >
> > ptr =3D kmalloc(size, GFP_KERNEL);
> > KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > KUNIT_EXPECT_KASAN_FAIL(...);
> > ...
> >
> > kfree(ptr);
>
> Thanks for catching this! I've turned kunit test into OOB instead of UAF.
> ---
> v3: changed kunit test from UAF to OOB case and git commit message.
> ---
> Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
> strncpy_from_kernel_nofault() where __put_kernel_nofault, __get_kernel_no=
fault
> macros are used.
>
> __get_kernel_nofault needs instrument_memcpy_before() which handles
> KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofaul=
t
> macro, instrument_write() check should be enough as it's validated via
> kmsan_copy_to_user() in instrument_put_user().
>
> __get_user_size was appended with instrument_get_user() for KMSAN check i=
n
> commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
> put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.
>
> copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB bug rep=
orts
> as expected for each copy_from/to_kernel_nofault call.

"as expected for each" =3D> "as expected, one for each"

>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  arch/x86/include/asm/uaccess.h |  4 ++++
>  mm/kasan/kasan_test.c          | 21 +++++++++++++++++++++
>  2 files changed, 25 insertions(+)
>
> diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacces=
s.h
> index 3a7755c1a441..87fb59071e8c 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -353,6 +353,7 @@ do {                                                 =
                       \
>         default:                                                        \
>                 (x) =3D __get_user_bad();                                =
 \
>         }                                                               \
> +       instrument_get_user(x);                                         \
>  } while (0)
>
>  #define __get_user_asm(x, addr, err, itype)                            \
> @@ -620,6 +621,7 @@ do {                                                 =
                       \
>
>  #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
>  #define __get_kernel_nofault(dst, src, type, err_label)                 =
       \
> +       instrument_memcpy_before(dst, src, sizeof(type));               \
>         __get_user_size(*((type *)(dst)), (__force type __user *)(src), \
>                         sizeof(type), err_label)
>  #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
> @@ -627,6 +629,7 @@ do {                                                 =
                       \
>  do {                                                                   \
>         int __kr_err;                                                   \
>                                                                         \
> +       instrument_memcpy_before(dst, src, sizeof(type));               \
>         __get_user_size(*((type *)(dst)), (__force type __user *)(src), \
>                         sizeof(type), __kr_err);                        \
>         if (unlikely(__kr_err))                                         \
> @@ -635,6 +638,7 @@ do {                                                 =
                       \
>  #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
>
>  #define __put_kernel_nofault(dst, src, type, err_label)                 =
       \
> +       instrument_write(dst, sizeof(type));                            \
>         __put_user_size(*((type *)(src)), (__force type __user *)(dst), \
>                         sizeof(type), err_label)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..d13f1a514750 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1899,6 +1899,26 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +static void copy_from_to_kernel_nofault_oob(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[128];
> +       size_t size =3D sizeof(buf);
> +
> +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_from_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_from_kernel_nofault(ptr, &buf[0], size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));
> +       kfree(ptr);
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -1971,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +       KUNIT_CASE(copy_from_to_kernel_nofault_oob),
>         {}
>  };

The test looks good to me now.

But you need to send the patch as a standalone email, without
combining it with the response to my comment.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeiVRiO76h%2BRR%2BuKkWNNGGNsVt_yRGGod%2BfmC8O519T%2Bg%40m=
ail.gmail.com.
