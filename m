Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI5SSS4AMGQE2MUESBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id A55A299473E
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 13:36:04 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4584224c8ffsf145509151cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 04:36:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728387363; cv=pass;
        d=google.com; s=arc-20240605;
        b=O0oODrPKQIE5pHZJzlTn7WV0/mvFgeHqqf0qKdH2z+u35s/QulSRzr6laLF3f1AYu/
         77MnsxtrnDXuYrBAXtrlhYevN2MV09yj1Hod9hOgC/A4ATW11uYlIjN4mqGsywf9vT7v
         OayFx7Zcb0bpsoVcPbrGy3pquHUmKNrp/8kf4kMrpYeegMqMM3dhr1qnttZIawaOnUiq
         ISQODfO09rb1cL8RdN6+QpN9qFfN/ASlNhpDzTNCY+NWn32P27XVmCv+hSeBlwKE0Crk
         bFB6S9jqOJLldtTRrWAxVRLsi5A6avgGpGUt3kYP13hLkvJseN2XR5lihEOIyK5Gag2e
         titg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r9KKDrF9RdAwYV/gxa4VwTtuBNRV+tOy+NSOooCwPkk=;
        fh=1nk+pe167ClOXzdNBe7Jq1my/7wgWtA+8rMR6nP76wQ=;
        b=B2lALG22Gq5RbEmtI0dCwu3pwDq8EaP48g8fD7uBvX0/iVTkFoYzjpeUtnQFPIXoky
         46exijv5KGPu0l8/QKz0+360SVr7ghoPbQasoRXPV6xM+d2FXETM02ZA/8zZBajGYMNP
         /GxYPqcU39XHb4yRBwIGQqcEYFc2yvZuvAGWTq4LISWJ9XDo6FgOlxdiFkEOtnaEL5F4
         iCVlOPdvJriyh2LNCm6IUQsCSmvhH74WrMB2olsVWnJ2za9P8ts9nlDDfZKill3z1CIf
         4ummChj8IiOEJxoE5azAFmQ5fdgFrweg/b4S6Sv6UcGkzIQAjd1GJlW1T0ddMlCgY94C
         SOEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mJWO7r69;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728387363; x=1728992163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r9KKDrF9RdAwYV/gxa4VwTtuBNRV+tOy+NSOooCwPkk=;
        b=CqyJXTrDo6EcQj89TV8sCth2jz+3SMY99wn8+VTdisev54Qx0qgSFQpn6FfiMNDRab
         P+rlYYYo7MzlJRb4noJkT50lzAYHVuV9X3jWaOtRYJ7LAEdrjAViyMaFMdwqtClSdulX
         87Vt7sEC5YCCW3uVXZWJ/PbWNeLkN3RvvE7WkWSpf/1tEpRK25GXFgdaJ89HCrKlO1Um
         lzs5ZxpR9dnL3XneV45Tv1iA8qZcDEqvjaUHdrsY+zDvHxP4CIi67DWK1mub5klYtViM
         hoY2xFvnwepEtZZbpvS1jqgbEPiqqWrNxEMPhtuomObyCxMjAYAaH4UnojfOcjT+gpMH
         7hkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728387363; x=1728992163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r9KKDrF9RdAwYV/gxa4VwTtuBNRV+tOy+NSOooCwPkk=;
        b=AAztxnYrkkPDv1C4MPFOB0bXT3dUBnG4m3JQUokAVt4QtZz38wlQAmRfjWOUKWTbzY
         mvkgy7AREEAdoT52r2+f+tP9eKanNOtx1su8EDbjUHc0GQsw19VvYTaKD9AVEDdPioAp
         awk+tNnqy4bXOknZs62Ff1cbB9+0PBbTxpsYMD8+6N3KnXAVRQClho+ZxuY2NJtivbnz
         5v5EatW6yV/77WkJ35yIrj2r0oumzZyGgKluWtf6nWUbG9em+r7MjnpDkrr7t7NNVbvr
         LFxTb3Cy4RkcGYndn3ifOgzfwPvsXSufqxvfpZ87hftYrOtdNd87GHoqUWjNVWWF9Kig
         QLaQ==
X-Forwarded-Encrypted: i=2; AJvYcCW3QMqHj0YYm1NXuFgSYL9x8ExX7KuwVqYDkCw7Us9Cdnlwed3rs3h1tbA9mrUMMXF/2e8LNg==@lfdr.de
X-Gm-Message-State: AOJu0YyvhW3BS3s3DJAh0vOJ++qB2bs6YebnBEgfY5WFN+PAbDw2eLfc
	PrYznZy7GFLAhx42XPWiTKNNUZbq0nLFYbycw68KBKlgIu2JL9Om
X-Google-Smtp-Source: AGHT+IFniSLN+dnPtdA4jrRCs9+u4AwoIsBnwOy6jnaHCccgJ0lV8z4YrZyB110/gSHFm6zgd6wjMQ==
X-Received: by 2002:a05:622a:598c:b0:45b:16f5:6c16 with SMTP id d75a77b69052e-45d9ba62e5dmr257533451cf.24.1728387363304;
        Tue, 08 Oct 2024 04:36:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1448:b0:458:355c:3632 with SMTP id
 d75a77b69052e-45d8d7bacdels16778851cf.2.-pod-prod-04-us; Tue, 08 Oct 2024
 04:36:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrvk/SrAAt6f4PKIx+Nue3P8xVs4/InKGb0DVsQYajgvcZhUkLbnD+xSIalRYkvNE2w0hxecti7U0=@googlegroups.com
X-Received: by 2002:a05:620a:1921:b0:7a9:c31f:e4df with SMTP id af79cd13be357-7ae6f42cf09mr2548023285a.6.1728387362428;
        Tue, 08 Oct 2024 04:36:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728387362; cv=none;
        d=google.com; s=arc-20240605;
        b=P7MyCg7rNHVCarrn6IB29RnhH9IzjP5Kbk2ERlQj2HulQAp2QxTrPUtAfJKIXujuc0
         t4H1B5XFa7fJNg8WPCqHNe6+Ugcf0BTCpdJ1f07EMbBxkDT3QN0XcJ7uFxf2DpvIj04A
         G/ykylmtObUnvJNtX1GCaTExLRe9jhLHThcK+6pptm6c4QrewybWyCmcX9Q3ZLOKUPWA
         Yy9njV23bBVqECRkibp3kBbV7Q/WFb9SbPD0S6baCJrQ8X1GkJQEbqvrXHrm2DoTc6wq
         wCbyOxdSKXFGNBsSuK39QQhqLibl/7a6JdUXImc2Fs7qL2jo3ZLbqTemGp1CwvGt6rCX
         0ZEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ALIusGAUH/4/gvGvjWJecPeh4PIpgeoXr9PxFWIdEcw=;
        fh=vXATM/r5FNLVt7ITfomVlDaA+0XiXwrQW1PTg2nEMNk=;
        b=OWYI/7jIdvOuqtGjH2nsDkHVDxe4cX+phc1Cn++R8gTufmsedWNufT//k4W/0YyrKy
         PAEIaKObauq+w8YYUABQx1oNqeSuotA5ey4qk9p9IC/E0s7pn0SlIYp30EGfua5wE/g/
         pJsNuw9MhJYH8YXoN/GaWumF0FCEdN6p5DjoWP9dxabBm9qE2afEENrOoQX3ER4kZY2T
         EZdPbbhKvFn9IbqPbJx8xCSyvD31ajO7KYlx7XMrk/uOdEUvvZ9Vcp3PSDV8zoVtXyHT
         dtLF/XpViKMcJMGjOxJ6yq3kUtrG9EBryJCR37IlaprfxeoBom8g6kh76TsBR7d+tpWx
         zBMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mJWO7r69;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ae7576681asi26856485a.7.2024.10.08.04.36.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 04:36:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-20b5fb2e89dso43039505ad.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 04:36:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUTQUekAh5qC9Ezrz1T6uS1ko3XW8DQ4dygKOZvNsOQgbSTLwjHoU9oVFWKvizUjRpsi8mGIL6J2Zs=@googlegroups.com
X-Received: by 2002:a17:90a:bc92:b0:2e0:9147:7db5 with SMTP id
 98e67ed59e1d1-2e1e63bf552mr17536878a91.38.1728387361594; Tue, 08 Oct 2024
 04:36:01 -0700 (PDT)
MIME-Version: 1.0
References: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
 <20241008101526.2591147-1-snovitoll@gmail.com>
In-Reply-To: <20241008101526.2591147-1-snovitoll@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Oct 2024 13:35:22 +0200
Message-ID: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
Subject: Re: [PATCH v3] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mJWO7r69;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::635 as
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

On Tue, 8 Oct 2024 at 12:14, Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kernel
> memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> the memory corruption.
>
> syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> KASAN report via kasan_check_range() which is not the expected behaviour
> as copy_from_kernel_nofault() is meant to be a non-faulting helper.
>
> Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
> kernel memory. In copy_to_kernel_nofault() we can retain
> instrument_write() explicitly for the memory corruption instrumentation.
>
> copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> kunit test currently fails. Need more clarification on it
> - currently, disabled in kunit test.

I assume you retested. Did you also test the bpf_probe_read_kernel()
false positive no longer appears?

> Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> Suggested-by: Marco Elver <elver@google.com>

This looks more reasonable:

Reviewed-by: Marco Elver <elver@google.com>

This looks like the most conservative thing to do for now.

> Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> v2:
> - squashed previous submitted in -mm tree 2 patches based on Linus tree
> v3:
> - moved checks to *_nofault_loop macros per Marco's comments
> - edited the commit message
> ---
>  mm/kasan/kasan_test_c.c | 27 +++++++++++++++++++++++++++
>  mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
>  mm/maccess.c            | 10 ++++++++--
>  3 files changed, 52 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..5cff90f831db 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,6 +1954,32 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> +static void copy_to_kernel_nofault_oob(struct kunit *test)
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
> +               copy_to_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));
> +       kfree(ptr);
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -2027,6 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +       KUNIT_CASE(copy_to_kernel_nofault_oob),
>         KUNIT_CASE(rust_uaf),
>         {}
>  };
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 13236d579eba..9733a22c46c1 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +static void test_copy_from_kernel_nofault(struct kunit *test)
> +{
> +       long ret;
> +       char buf[4], src[4];
> +       size_t size = sizeof(buf);
> +
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault");
> +       kunit_info(
> +               test,
> +               "testing copy_from_kernel_nofault with uninitialized memory\n");
> +
> +       ret = copy_from_kernel_nofault((char *)&buf[0], (char *)&src[0], size);
> +       USE(ret);
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
>  static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_uninit_kmalloc),
>         KUNIT_CASE(test_init_kmalloc),
> @@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_long_origin_chain),
>         KUNIT_CASE(test_stackdepot_roundtrip),
>         KUNIT_CASE(test_unpoison_memory),
> +       KUNIT_CASE(test_copy_from_kernel_nofault),
>         {},
>  };
>
> diff --git a/mm/maccess.c b/mm/maccess.c
> index 518a25667323..3ca55ec63a6a 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
>         return true;
>  }
>
> +/*
> + * The below only uses kmsan_check_memory() to ensure uninitialized kernel
> + * memory isn't leaked.
> + */
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)  \
>         while (len >= sizeof(type)) {                                   \
> -               __get_kernel_nofault(dst, src, type, err_label);                \
> +               __get_kernel_nofault(dst, src, type, err_label);        \
> +               kmsan_check_memory(src, sizeof(type));                  \
>                 dst += sizeof(type);                                    \
>                 src += sizeof(type);                                    \
>                 len -= sizeof(type);                                    \
> @@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)    \
>         while (len >= sizeof(type)) {                                   \
> -               __put_kernel_nofault(dst, src, type, err_label);                \
> +               __put_kernel_nofault(dst, src, type, err_label);        \
> +               instrument_write(dst, sizeof(type));                    \
>                 dst += sizeof(type);                                    \
>                 src += sizeof(type);                                    \
>                 len -= sizeof(type);                                    \
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag%40mail.gmail.com.
