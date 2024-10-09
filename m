Return-Path: <kasan-dev+bncBDW2JDUY5AORBNGKTO4AMGQESVJ2TEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4189F99764A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 22:19:02 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2fad1771626sf1253101fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 13:19:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728505141; cv=pass;
        d=google.com; s=arc-20240605;
        b=Me/e2qkOVjGuums1fhJCvSnpAhrbHBKAjWcN4AlHEXCulDTEzTdyOPFuydfiQKA3tB
         qawJYdwq6+xZHGbdruUb1k4m6rCwTV8WTVxlzE8AoFcl22PXM2v1y4dJvWAb847ALzv2
         lpbeod2SDFrUyRHzo/d/yDm7Tp58IAN+nSQdZYVIHUmxbXhxBNR7jkerH3u1n0Q8XvZT
         jBFZegPlAhZnPxa8Q74IAUMwzq14LiBQwFgBmo4OSUbgrwFeXPG3eb3WwTsdU/fM+88w
         4xZSg01+ZMBBGEudX9gS/ezylc7IoyAGlstcocdh7bhQf37APnDtqQA8MdS7fIt6R79+
         yWHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HKiqfhtDzaVjrM6PSwNtAoMEyvlAip/i+k2rj4q4LKk=;
        fh=1hoAz9KuwqHyhcMmqqmULd6RqChy8zjwl3ljqpwMYhc=;
        b=WsEDYwQZZ+V6YatDvUQLmDvW9eBDSNpyGf/1Ur2VX6NWg/eJJmiIM2EFwy7FMfSt7x
         CHYmF5jOUBF3PDDjpF2272BJgzCtAW8VKthDpDKqOoo7kIkL79UPi0YJmyVo10DA7uBX
         JYVeO19PhbTqp791y3bUTzApKV9ANvnStsZDkMjhzjy1BWc7jyvAUCtbllxaytIhXKuf
         MRG069yWPvgbs46YZlW9MTa8BNRVSx45CHjMNqY+t++L8/PsGD9eItYsgCXIRsxtQmDF
         hXXVbE51ezcehMGcyf/jdnAsWs48K7p1S2a3JnirznN3NgIyfRmpArf8Wp8cxN1vahnK
         V4sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=icNme11m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728505141; x=1729109941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HKiqfhtDzaVjrM6PSwNtAoMEyvlAip/i+k2rj4q4LKk=;
        b=CKJ4PiXZ7rlcOsgY9u1Ab0Eoij8qSOqy+f5Q8rR5dIMslc8U3BJbSAet6PXvsbi2Wx
         izCV6izCxF0faXflU6csJ5HTLMwJfWb9SSUshHN3YIs06XJjSc2//eXkyy7veAFevh1R
         M/29anxKMjNpPWkXLATtL7YsSDn4lsTHQGI0D6HUU2Jw8jEbZkkNP1zrB4pHJ0u3KmPx
         +l3jg8xfCjFwRNwlpDRdA207ZAb0H2rMFBeNsIl64DaA4Qz5LtedFa1hGWXYCbv2Len9
         JiXg2L4egkMmY63O68dcB3wWKoQ7omQRsfpl7CJAaSkGmF/FgmHuIHY9Hzfbbh1kCR5x
         yxSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728505141; x=1729109941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HKiqfhtDzaVjrM6PSwNtAoMEyvlAip/i+k2rj4q4LKk=;
        b=GU74wFdfxLi7Ad0APr8dd3MAZzGf5a7OpVqiccioaUPMjyXM1zLT4Hi/xe0ACZbcwo
         yP0+IEZnhnG5sRQexHBLxLSmrGGj32+xRgnLhRSz2UosrAgs9XsqBdAB7KwTzFB0Shcq
         7hCqbM0LQ3nOypIOQdaa6ge+Q97KqXr5WJDtatF5SyPFASxZKTQbxeWwoYPwhZjZkEgu
         fLMMtljUVlYS8cfxHjNV2WHte1k5q2HLjbuoXSKUAZrhnmhJVEdgqYqznmBAx91Qxe7x
         aP9FMxAKNuUWlOEQEjdmg4tozuiDbqtvavyw3ObCIL5f9BuI6hAfTOuLXrGTaNH38zl7
         y46A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728505141; x=1729109941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HKiqfhtDzaVjrM6PSwNtAoMEyvlAip/i+k2rj4q4LKk=;
        b=GdvRk7dBkYRUUA0bwlUMBWXo+cP5S7W9e9zh3J2HY8WMhZYuarOzV70IAe7QMdQt/G
         0oF3Bith69dydijrYn2xID5LTplszIFtYM4+v6k/v42eprU53lZb+k4COaEbRhTq3BxC
         21Q/REceAA05rkeZOYPPOAMvDPbl+P0VR5GkgdofMqATTQOv3p1AzKTkB2Yw0IudML4e
         oyUEqgwWz5adM7XSDurhXcC2maopfjq3TvDwlRFNmFzChR8SjTI17pN4cJIquAO8QPm/
         4AtTKQ2eTVHbMAn22dO8qDedX5z0NO30yDHxLqg1tdVEh0/qAJnDTpRl7DDxa/Xu/BYN
         nScA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsNXPaRnDXY8teCSBrhKlajBf2axL+CLxo+lX0GJvMfQ/Enhm5gzjsBS7dLPMOZR/Qs6mQPg==@lfdr.de
X-Gm-Message-State: AOJu0YwNxvsLkfzOVyc7z8d8DScQw73uA/b6JNcGLNrpQoW70v+Wuh4W
	M+zv1BV0ukGS6uy0UJaPFxj7nlvENhxqLopW/LwYGQPiknRucM3m
X-Google-Smtp-Source: AGHT+IHba6hg4SHw25iGv8kFdUpW5uKwFBcZzlHJl0shtgz08UMX3goDln2os3t2xgnKAb/ey1+nlw==
X-Received: by 2002:a2e:bc1f:0:b0:2fa:cf5b:1e8e with SMTP id 38308e7fff4ca-2fb1872ba6amr25473451fa.2.1728505140354;
        Wed, 09 Oct 2024 13:19:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a46:0:b0:2ee:89a7:12ac with SMTP id 38308e7fff4ca-2fb2121809fls481641fa.1.-pod-prod-06-eu;
 Wed, 09 Oct 2024 13:18:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAzHwgjrl2fDl45Qf6u1jKwfuPW3F9Zbm+5RVgTRmC2XLVYQCMHgKVCdu54TMQG0hxIDFTXIIYkhY=@googlegroups.com
X-Received: by 2002:a2e:4e0a:0:b0:2ef:1b1f:4b4f with SMTP id 38308e7fff4ca-2fb187d12c0mr21794861fa.34.1728505138122;
        Wed, 09 Oct 2024 13:18:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728505138; cv=none;
        d=google.com; s=arc-20240605;
        b=UAhGj5nu//eS30uXmCmPfbKpw+GbKuPV3JWjMFvoM/iCJGRsu3YH1/Zu9lrwtXRtf0
         cQuqjSPQu5ub7S/ZjqbUJx3Xb/BlcX58+uw9Avf71thAEqI2V+zF2RyLaTK+G+DbNWyl
         C8MTZ9IhyRnLZR6bMMFo6gp8phq/GDLxkCYsRtfnMMugIwYjFA7H4aorVg5Ax0BKVauN
         V9oJKvjzFOAHs3J01LAv0SYc33BU4Ns6JQpcGJcutLYPvhe9U2ie6/7vKOcL4SEYSarL
         jPRGuaGpOsdq3/Kf9/IUtVZ97ESZ+dhFhac7ij2vpU78KuMhSFlbL+nH7t1Xlo29ko7O
         hIdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7c35+JpWEpsPpCJZNGS7NrTRM+BKUrPMr11LkkZQ0go=;
        fh=thD+l3UHKQTvHIoGfsNROhbkjpQhdGlgnsekfIFt/NI=;
        b=dhKabwJrHesC0GcqUVkrc2IImmWHxOlPq0MN5G/2iOdOyyhXdE+R1PfGUIIY/CnYUR
         mEnrWJHwDzHbkHes84VdIRksQWHrXMejpgeeScPnCByWgtuiMKTalb62mDngjWJ6qK+7
         90H7FqTjBOk7C04hq4mrYn7MubdoshD7k038FQiPMQcpmJ6DzI2nAtC1ZQv3+iAiVSl0
         9nbuoDVuCXZ1HDOWEI2g2uwgzHxRo0Iyz2YBe6uODl8WhCtkmODX7ttZqRmDl3VFD1sO
         GytzQq+XmKvs+iCXqxuOt3SkfThFGTUJqqruIGfZPN+3kl3lS93lLI9/EwkEVUtyXyJq
         VcLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=icNme11m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2faf9b42a1fsi2226891fa.7.2024.10.09.13.18.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2024 13:18:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-4305724c12eso1180115e9.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2024 13:18:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhsiqFjdKglIBWwL9eCuqMKs3Nzh7ARRL9cU80VjJQ6LSr8fjQBSGvC7jEs7tDst82nJKDouVX4Vw=@googlegroups.com
X-Received: by 2002:adf:dd8d:0:b0:37d:31a7:2814 with SMTP id
 ffacd0b85a97d-37d3aa579famr2243483f8f.29.1728505137061; Wed, 09 Oct 2024
 13:18:57 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
 <20241008192910.2823726-1-snovitoll@gmail.com>
In-Reply-To: <20241008192910.2823726-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 9 Oct 2024 22:18:46 +0200
Message-ID: <CA+fCnZeMRZZe4A0QW4SSnEgXFEnb287PgHd5hVq8AA4itBFxEQ@mail.gmail.com>
Subject: Re: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: elver@google.com, akpm@linux-foundation.org, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=icNme11m;       spf=pass
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

On Tue, Oct 8, 2024 at 9:28=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
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
>
> Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7=
qeeeAp_6yKjwKo8iw@mail.gmail.com/
> Reviewed-by: Marco Elver <elver@google.com>
> Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D61123a5daeb9f7454599
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

(Back from travels, looking at the patches again.)

> ---
> v2:
> - squashed previous submitted in -mm tree 2 patches based on Linus tree
> v3:
> - moved checks to *_nofault_loop macros per Marco's comments
> - edited the commit message
> v4:
> - replaced Suggested-By with Reviewed-By: Marco Elver
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
> +       size_t size =3D sizeof(buf);
> +
> +       /* Not detecting fails currently with HW_TAGS */

Let's reword this to:

This test currently fails with the HW_TAGS mode. The reason is unknown
and needs to be investigated.

> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> +
> +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> +               /* Check that the returned pointer is tagged. */
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN=
);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KER=
NEL);
> +       }

Let's drop the checks above: if pointers returned by kmalloc are not
tagged, the checks below (and many other tests) will fail.

> +

Please add a comment here explaining why we only check
copy_to_kernel_nofault and not copy_from_kernel_nofault (is this
because we cannot add KASAN instrumentation to
copy_from_kernel_nofault?).

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
> @@ -2027,6 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
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
> +       size_t size =3D sizeof(buf);
> +
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault");
> +       kunit_info(
> +               test,
> +               "testing copy_from_kernel_nofault with uninitialized memo=
ry\n");
> +
> +       ret =3D copy_from_kernel_nofault((char *)&buf[0], (char *)&src[0]=
, size);
> +       USE(ret);
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
>  static struct kunit_case kmsan_test_cases[] =3D {
>         KUNIT_CASE(test_uninit_kmalloc),
>         KUNIT_CASE(test_init_kmalloc),
> @@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
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
> @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const voi=
d *unsafe_src,
>         return true;
>  }
>
> +/*
> + * The below only uses kmsan_check_memory() to ensure uninitialized kern=
el
> + * memory isn't leaked.
> + */
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)  \
>         while (len >=3D sizeof(type)) {                                  =
 \
> -               __get_kernel_nofault(dst, src, type, err_label);         =
       \
> +               __get_kernel_nofault(dst, src, type, err_label);        \
> +               kmsan_check_memory(src, sizeof(type));                  \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> @@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)    \
>         while (len >=3D sizeof(type)) {                                  =
 \
> -               __put_kernel_nofault(dst, src, type, err_label);         =
       \
> +               __put_kernel_nofault(dst, src, type, err_label);        \
> +               instrument_write(dst, sizeof(type));                    \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeMRZZe4A0QW4SSnEgXFEnb287PgHd5hVq8AA4itBFxEQ%40mail.gmai=
l.com.
