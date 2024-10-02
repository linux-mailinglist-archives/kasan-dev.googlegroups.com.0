Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCW46W3QMGQE5U5F47A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D95C98E002
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2024 18:00:12 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5e1ce60337esf6636629eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2024 09:00:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727884810; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gb1myZXjNW/XCWjWKgKLyb5IzqGDflrgY039FyNVwm/pTAtRAtSIWEI4NfCk8vLwDo
         ZrVSOC4xm8pAQdVXWDfjwL9CbjFUG36IWe3iBcDYYgqpm+GSmFcfkuNO6Slcx4Ds2QuA
         nYcdYkQKftkD2UUFce5DEOt3Q13eqmjSs0D1rBr1ywdBqeKN2DOKLnBU6OD7Qxi98rAB
         VUIfevLRgzVWzkeNaY/AiHCWO/dwROPuZHpXNut8tvT/GB9yUWHlTK+jaF1bMsfq7+EW
         hF3xuhnCYGGrOkkp3YcQRALPC1vdt6IbapZN/gvc7Pwx6laeMYuefsTLZtsBkJRgdNZN
         ZCpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g8qw2WPAX2bMvWphXCt9bZ1fsiVQR098Y+0M4qOebhg=;
        fh=iCxMg9v2dkCgJRtOi0yfjxyID97JId86+MWlV+5ExpE=;
        b=iAGlqQoGHxjBiai974jxMT6GgUXWXem3/HKVn9Yx0/ir/83ce5erQ34eQoWkSxFjRj
         i1YYLVskqSyaS7v5bkwIWUuoDhB0xjY5GcVfxXOdKfFFXkV3k5qiPd54qFV0crtsdNFb
         9kkI2ZFvb3892klXyq+DvwEJu4xfVpAImMtzVVLXKJdesu0a4za914lJovEy+vsJwY7i
         b8wjDoxGuwhsA5nQlRBGTOnJKo+BvyNpUbFRAJ7rVSbQadNrJFw6Fo7Y/dBDwHqDoD8E
         hs4S8fQR/AH9MPn+zCjxkbRb4pzscyWhEufpizQaDoCyeniImTHLSqgJ8yEZFgXRnnRP
         sudA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MVQzFGyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727884810; x=1728489610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g8qw2WPAX2bMvWphXCt9bZ1fsiVQR098Y+0M4qOebhg=;
        b=r8DCGf7bdZcZhGLSlloM7pruoGTGn6XIyzElxv3NQGDS92HpRnqiuiRZOeO7dQZlax
         s52E2ktbY6h/HqVAjXRdqpoxZTLYAojZSOp8UvJEyfDzAKynrqbrKZcQzR1a2xfBT4rW
         2pVj5jYQJXfVKP1v0D1xPOzdFw29qmtY/4nAkWAoC83/tcvHm+SV3oL6MAza3eB67w70
         cKjXPyeIiDF2L19EMhdo6MWejzW8ORpWPhX8balxNDQPa/4ZKm7Dvq+a1CU6/iyi/llD
         XDYg0KQFjvCC6E2XHLC18gcQ4Wo5JXDsxWfsER8yClHRv1zJlrNdpMy/uf+jzgK+wV8v
         h3DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727884810; x=1728489610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g8qw2WPAX2bMvWphXCt9bZ1fsiVQR098Y+0M4qOebhg=;
        b=awkGC7zV4yHUQ73S0pPq97RqnMVc34wHDF7Tmb/hhJSwXRtxAiRZNARbeXgj/wBTBb
         cM55DoP1qQFHI9t/2iibHGIkpZUPOve0TS60vIRYVt6PoVE/KtejslIqcSwWQlHAQFxJ
         A6y/exgGiNFbaeVtq7uGJMkzNJJM7TZpRFrXHMSNvwt4x39Rg/oZid4FoYa73aS2ixDV
         Wd5wHnRpWvHRvrVAh5JsK/AvAUISm9ssNkAc9FA9a7W5bI/viXnZGL93PkUIMBn7yoU0
         UrBKg6y9B4voU6nBLDw76pHdbFkJIObWAuAIm7iI+T4Ho3k5PgIByzft1Pd7hWH7OAoT
         /28Q==
X-Forwarded-Encrypted: i=2; AJvYcCVC4QAPW+0CMn1+Dmxhb7bLM0ylW5JyTGosFUrZU4VAvaAgt5C/cNfhqvukbCIYFxUALka58g==@lfdr.de
X-Gm-Message-State: AOJu0YzV0HAOo0XUPKBfSb313sxVFIo/S7f/maRw9xx1hyg1Bb2NfrYG
	emZM+oohKaSiaLuggNHDrAPV7GOKRyfRMvJW6EbyC7seGCe8bNvy
X-Google-Smtp-Source: AGHT+IEpnMOCesPwqwvwx3K+Jf6Nl+nM8ilwwP5VhjpR8VQX2WSrDsV55ZPZUE+oo0pexuJQUEXIKw==
X-Received: by 2002:a4a:edc5:0:b0:5e1:ce95:9e1f with SMTP id 006d021491bc7-5e7b1d02f37mr2929498eaf.2.1727884810327;
        Wed, 02 Oct 2024 09:00:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4b82:0:b0:5df:97e4:bd5 with SMTP id 006d021491bc7-5e7bd72cfe8ls19094eaf.1.-pod-prod-07-us;
 Wed, 02 Oct 2024 09:00:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3C17CWDxjT4ToU/FBUBiMO0FsfTNyGPRjPr/MbqyEgaDtJUyAFi2N2H59vfSNMXVpBCnX3WOObgE=@googlegroups.com
X-Received: by 2002:a05:6808:10d1:b0:3e2:8c31:a49b with SMTP id 5614622812f47-3e3b417bdb8mr3045507b6e.44.1727884809055;
        Wed, 02 Oct 2024 09:00:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727884809; cv=none;
        d=google.com; s=arc-20240605;
        b=EMF3zv++EeiEYoG8NdS1SJ5zshUel8rt+mCsVum4KstZqjQB7QaBmb8mOlBznaDtW6
         WaqeoT/k0T4fi6g/JAkxxkFhF6aAi3GdLqXx+Vo+gP6KFIIO9uarFUZXO4PjHu1lXqVJ
         B1HEHf7I5mVfxdW1szmh661QHyZgRsIRbVNBwLZ0NAEM0+OTn7okQLCr2tjnWEcGGKFe
         KyEswjbRvBZMk2gWd3zNhefXiYuJyUxpZqEU5/nK+tylFmUvGge2EJnuarGNr7deMp5J
         jCDjjR5cH0T8eJGZ9AKzSuD8ngst0mEKgtBlKpAiVxM3X2RxniyGaBIDfyd4pi5mdRgY
         WZuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ugcP+XI8NwDswML2qKbmqUc0ZRLhImizzjcaJfjzZtU=;
        fh=B98uYKn82LtSfGlMPFVmIDHEpxFbzZBS4EtSPhRXtf4=;
        b=Y+dPB8NV0bGCzVtNvLGbyLROpIRQW8A/MsPrGxhzcEmESmZl+EpL/SMA3FGrmVkt8i
         kCC04QtuC7B5KkGQR9kL1Aq6WGa6M/GArQeq7DDb2ocAENm8ApLuKsCrWMGN16/Adhyg
         Qc4nHCO++oza8r9YIGqeyOKsS9nvdKB+eQuf66UMfbvAeriB9gojA+9bkze8kRCLa6p6
         irI3J6duuWjLyjBvXf/q+WnjEpatDucCzdHfYambfyZn6Nz+xVeALM8g1fnOAW20auSc
         5PYG6jhNkU2KtVotyNhJLTkUijkK0vcFMeHQ9UiSn3PkTxM5tfJdnHirVACx/NPawsrp
         gkEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MVQzFGyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e3933deaeasi524790b6e.0.2024.10.02.09.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2024 09:00:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id 5614622812f47-3e0719668e8so15017b6e.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2024 09:00:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdFwblvNv/cEGw6kJEUx1Q1SaNY7Iz4y3AqBQ0ZD8Sv9w41bu1Y5UK2n+6WnqkyuGe3rcTAIalPRE=@googlegroups.com
X-Received: by 2002:a05:6808:1295:b0:3e0:70d8:2f60 with SMTP id
 5614622812f47-3e3b416b395mr2872794b6e.32.1727884808371; Wed, 02 Oct 2024
 09:00:08 -0700 (PDT)
MIME-Version: 1.0
References: <20240927151438.2143936-1-snovitoll@gmail.com>
In-Reply-To: <20240927151438.2143936-1-snovitoll@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Oct 2024 17:59:32 +0200
Message-ID: <CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com>
Subject: Re: [PATCH] mm: instrument copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MVQzFGyA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 27 Sept 2024 at 17:14, Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault()
> with instrument_memcpy_before() for KASAN, KCSAN checks and
> instrument_memcpy_after() for KMSAN.

There's a fundamental problem with instrumenting
copy_from_kernel_nofault() - it's meant to be a non-faulting helper,
i.e. if it attempts to read arbitrary kernel addresses, that's not a
problem because it won't fault and BUG. These may be used in places
that probe random memory, and KASAN may say that some memory is
invalid and generate a report - but in reality that's not a problem.

In the Bugzilla bug, Andrey wrote:

> KASAN should check both arguments of copy_from/to_kernel_nofault() for accessibility when both are fault-safe.

I don't see this patch doing it, or at least it's not explained. By
looking at the code, I see that it does the instrument_memcpy_before()
right after pagefault_disable(), which tells me that KASAN or other
tools will complain if a page is not faulted in. These helpers are
meant to be usable like that - despite their inherent unsafety,
there's little that I see that KASAN can help with.

What _might_ be useful, is detecting copying faulted-in but
uninitialized memory to user space. So I think the only
instrumentation we want to retain is KMSAN instrumentation for the
copy_from_kernel_nofault() helper, and only if no fault was
encountered.

Instrumenting copy_to_kernel_nofault() may be helpful to catch memory
corruptions, but only if faulted-in memory was accessed.



> Tested on x86_64 and arm64 with CONFIG_KASAN_SW_TAGS.
> On arm64 with CONFIG_KASAN_HW_TAGS, kunit test currently fails.
> Need more clarification on it - currently, disabled in kunit test.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  mm/kasan/kasan_test.c | 31 +++++++++++++++++++++++++++++++
>  mm/maccess.c          |  8 ++++++--
>  2 files changed, 37 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 567d33b49..329d81518 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1944,6 +1944,36 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +static void copy_from_to_kernel_nofault_oob(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[128];
> +       size_t size = sizeof(buf);
> +
> +       /* Not detecting fails currently with HW_TAGS */
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> +
> +       ptr = kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> +               /* Check that the returned pointer is tagged. */
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +       }
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
>  static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -2017,6 +2047,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +       KUNIT_CASE(copy_from_to_kernel_nofault_oob),
>         {}
>  };
>
> diff --git a/mm/maccess.c b/mm/maccess.c
> index 518a25667..2c4251df4 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
>
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)  \
>         while (len >= sizeof(type)) {                                   \
> -               __get_kernel_nofault(dst, src, type, err_label);                \
> +               __get_kernel_nofault(dst, src, type, err_label);        \
>                 dst += sizeof(type);                                    \
>                 src += sizeof(type);                                    \
>                 len -= sizeof(type);                                    \
> @@ -32,6 +32,7 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
>                 return -ERANGE;
>
>         pagefault_disable();
> +       instrument_memcpy_before(dst, src, size);
>         if (!(align & 7))
>                 copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
>         if (!(align & 3))
> @@ -39,6 +40,7 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
>         if (!(align & 1))
>                 copy_from_kernel_nofault_loop(dst, src, size, u16, Efault);
>         copy_from_kernel_nofault_loop(dst, src, size, u8, Efault);
> +       instrument_memcpy_after(dst, src, size, 0);
>         pagefault_enable();
>         return 0;
>  Efault:
> @@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)    \
>         while (len >= sizeof(type)) {                                   \
> -               __put_kernel_nofault(dst, src, type, err_label);                \
> +               __put_kernel_nofault(dst, src, type, err_label);        \
>                 dst += sizeof(type);                                    \
>                 src += sizeof(type);                                    \
>                 len -= sizeof(type);                                    \
> @@ -63,6 +65,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
>                 align = (unsigned long)dst | (unsigned long)src;
>
>         pagefault_disable();
> +       instrument_memcpy_before(dst, src, size);
>         if (!(align & 7))
>                 copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
>         if (!(align & 3))
> @@ -70,6 +73,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
>         if (!(align & 1))
>                 copy_to_kernel_nofault_loop(dst, src, size, u16, Efault);
>         copy_to_kernel_nofault_loop(dst, src, size, u8, Efault);
> +       instrument_memcpy_after(dst, src, size, 0);
>         pagefault_enable();
>         return 0;
>  Efault:
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240927151438.2143936-1-snovitoll%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw%40mail.gmail.com.
