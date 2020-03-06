Return-Path: <kasan-dev+bncBDK3TPOVRULBBMOHRPZQKGQEEBYHE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CCB1117C939
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Mar 2020 00:58:41 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id j13sf1331387lfg.19
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 15:58:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583539121; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJ9SEishofTXJ269ntWDo+N4+pRkNyEIxY71gbNVHmQFgXC6WW/uXysP9URaH8N97U
         XJqnjv3fGGaCxe60VKRso+JwEHLtRqs9BShzYOYtxriLWKAm6qd9OmIuQq/a8rq1AxDt
         f1XZmskZgnmt84nMkSl7ZcgeNoP/cCuYZvF/GV0sWx2KjMeMC4KQXEI5bqQ59ikZqATw
         DQ1fMS7z+YNJA8mUvEkWjuJEviLsT+Aefsl5IBMZalrfw73//UFQxxObJZkdcS187+EI
         h8y0BP+0TcpMKT/zIL5TvgPG4TAjjoa8rN1CKe4unpGnJMvh+p2Z3/ZChBzBW+i+evfo
         0l7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RZUOlTyV50C9pCKVhVTZYJrg7lY9reVKi9kPrrKyD+A=;
        b=B1hnl6FdDRhZgQrXTbAcOxSCsQ1rGL4ygj12LM69wPzMBrAKpO0s8PNAdaB65Z1yGY
         nCT27SYDesQmVTV0GcnWQtHxT4ULDpl0f8opDlI8qUYFBR4/iNpHMrI/vEKddD00EfFf
         8Lb47Z8BedMX1A6EIjuWFDrqIhUvCmJIQ7V4VyjT6uxu9MZiILWjFFquCQ1Q4209Fvkk
         +DDZyFRRSmnMgvWNwa+VIQF3CdA0wb8tRdeCpIUDSCVjWFa5Kr5mwmP6040aSRL4RhBS
         lmd+A04CQQZDBRSWKG1lt4BUij91envYEDkYLOCPgQpXMGb7q5/RLAfFys8QqyVlsNf3
         w4VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IBcp+BhH;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZUOlTyV50C9pCKVhVTZYJrg7lY9reVKi9kPrrKyD+A=;
        b=jnAHJ51FdZ+JNsLdsdiBHEhBIBKJEG/uvPG+8cNaW1lzNy7dEjjGxBz5jifQ6EKV7h
         +HMYJWGXjCgIPUtsbzXMawL1NRl8wqbWI4Dr0hCE166TeHKLmEgQ3FTfG+Lg4eeCpu9P
         vx9s4HGVrcR1ZrXd2J06r2KSn6HIIhZoohqRI7vhUmMuE2j+QOted5ZUaVB/LGH1w2tp
         RGf7QCkUY2ky/SizqK/X7/XNbC0S4SH4wWXG+KkcPKzh2VjdDjkG7oylEkRz1Vc95zOj
         Fpxcy40m9prK3TYLdN8BKXa5Ln/pmOOf09x5znSihB2RlplJ+aO5UJQxUiMrGCzpR+ux
         gBBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZUOlTyV50C9pCKVhVTZYJrg7lY9reVKi9kPrrKyD+A=;
        b=nLh4hrJNhtmcg3sIy2gDfo7IocPJwaJyUVuZGHQPsUA/fIllJ1AJ4DEWuN3oh22r88
         V9GU3KA+kq8JbiWx1H/aeTrSLqI9KDOR7PyoXRytiF8lcFIJwIUOig+CXsu3BpU4h6Ls
         k2Z16XZ0ubHc/2au/RpjQCKw6jlO453eVBiqkjB9nUdF1K8xy1l03WUATHSp7CBSNROU
         vkSECKVi7LCvFJiJ0H5v1Y5k+q+Mu70Pr7UlUCkXhFh5j72bZRvsh+LAFKyC6ChVqm/L
         Lzq3yKwgN8A50zYhZYEJscwbokGailWXRp4kuSrc+s6c5hfAmzWwB9mQgJPEAk4gMRvG
         Psfw==
X-Gm-Message-State: ANhLgQ3EifP10AVB/lBlrAxN+sChOHU00CERxg4mb98JoFbKgbuQYq56
	C6grvhoLm5XE4pXjLO4qM2c=
X-Google-Smtp-Source: ADFU+vudAFGAV+X4LnVvPS9tceruVmpCJgYktvEAu0ZuW5UH0HmWVzvGr1pvtacw6B9YzIUNNcGXBw==
X-Received: by 2002:ac2:53b2:: with SMTP id j18mr3263951lfh.144.1583539121269;
        Fri, 06 Mar 2020 15:58:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3188:: with SMTP id i8ls569331lfe.4.gmail; Fri, 06
 Mar 2020 15:58:40 -0800 (PST)
X-Received: by 2002:ac2:5df9:: with SMTP id z25mr3266438lfq.8.1583539120641;
        Fri, 06 Mar 2020 15:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583539120; cv=none;
        d=google.com; s=arc-20160816;
        b=nL0O+gHlaBsqlL2WzO4+KLiiOP0QbpvrUaHeKocIyMeTpkjWHQdjQFZc4Bwuk+s9YW
         1Ui4Kg10OsagZ52vhvnu3+NPP6zYMTwOKspF1Npla291LV7KZQDBWLT3+8BuhGZvwZ6m
         2byH+7RVWM0b2E0yzrUDQaWSzCjBf2exjTCd1rlcOzm2s2WtCnylYco+HAtRjwIzvpSF
         7iHjtz7Xhx/Kyh1+4ZsrSA8KkY80syHKQPyDUQvg5M1g468GiLhsEGCKy+LEC69XFo9N
         7pJNjSqsA54Z/06JPuojMWOIBnDx7sEa9Jd4FtNj5P8qvB13TARHOi04U6aHLWifXCoC
         stZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7GFRyQqmQIECMrJNabXAzRqSAvtGf9JYWLTOf7sH0Jk=;
        b=EjaFkn8WAKmaIpHw5ESXCW9cAfJJio1/jgy1zUBJrYS+LO/3TWnopnB3YRQ9s/vso0
         XhRPYNUlUe7UT04fS7U5MAufklFS0/DPUzE1yI2hvLjVm2ZCH2kjqPHxufz2udkecJ2N
         Zc0hJPGlKJ7M8mPBIBnk+dfowL8wXAfQXXuqe4vGYQkNakI1588Tq/+RT55eCNb6FRoy
         u2R4UT54yGBqfFWxVrIie9WfWgN6R52f7MthTfwKTRUYUM9GMhbc+y8VaTTYs1xa7+s2
         aqdR2R9TzEZ//mfUGdoLGCIpax0nZywXkv+k4zGYsAloC2xeqpMLbBWfsR4DYQdI+5O/
         DWnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IBcp+BhH;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id s8si140249ljg.0.2020.03.06.15.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 15:58:40 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id t11so4297552wrw.5
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 15:58:40 -0800 (PST)
X-Received: by 2002:adf:ee48:: with SMTP id w8mr6131055wro.290.1583539119611;
 Fri, 06 Mar 2020 15:58:39 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com> <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com>
In-Reply-To: <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Mar 2020 15:58:28 -0800
Message-ID: <CAKFsvUJtNNDohCp30ytkSRoS03z7m49nKjQ3Nhzo5gbfVzKdNQ@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IBcp+BhH;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Thu, Feb 27, 2020 at 6:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> .On Thu, Feb 27, 2020 at 3:44 AM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> >
> > Transfer all previous tests for KASAN to KUnit so they can be run
> > more easily. With proper KASAN integration into KUnit, developers can
> > run these tests with their other KUnit tests and see "pass" or "fail"
> > with the appropriate KASAN report instead of needing to parse each KASAN
> > report to test KASAN functionalities.
> >
> > Stack tests do not work in UML so those tests are protected inside an
> > "#if (CONFIG_KASAN_STACK == 1)" so this only runs if stack
> > instrumentation is enabled.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---

> >
> > -static noinline void __init kasan_bitops(void)
> > +static noinline void kasan_bitops(void)
> >  {
> >         /*
> >          * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> > @@ -676,70 +598,52 @@ static noinline void __init kasan_bitops(void)
> >          * below accesses are still out-of-bounds, since bitops are defined to
> >          * operate on the whole long the bit is in.
> >          */
> > -       pr_info("out-of-bounds in set_bit\n");
> >         set_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __set_bit\n");
> >         __set_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in clear_bit\n");
> >         clear_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __clear_bit\n");
> >         __clear_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in clear_bit_unlock\n");
> >         clear_bit_unlock(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __clear_bit_unlock\n");
> >         __clear_bit_unlock(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in change_bit\n");
> >         change_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __change_bit\n");
> >         __change_bit(BITS_PER_LONG, bits);
> >
> >         /*
> >          * Below calls try to access bit beyond allocated memory.
> >          */
> > -       pr_info("out-of-bounds in test_and_set_bit\n");
> >         test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_set_bit\n");
> >         __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_set_bit_lock\n");
> >         test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_clear_bit\n");
> >         test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_clear_bit\n");
> >         __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_change_bit\n");
> >         test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_change_bit\n");
> >         __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_bit\n");
> >         (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> >  #if defined(clear_bit_unlock_is_negative_byte)
> > -       pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
> >         clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >  #endif
> >         kfree(bits);
> >  }
> >
> > -static noinline void __init kmalloc_double_kzfree(void)
> > +static noinline void kmalloc_double_kzfree(void)
>
> Since it seems we will need v2, it will help if you move these
> mechanical diffs to a separate patch. I mean removal of __init and
> pr_info. These produce lots of changes and it's hard to separate out
> more meaningful changes from this mechanical noise.
>
While making changes, I have edited enough where I don't think
separating out the __init and pr_info changes will make much of a
difference with readability of the patch. Making
KUNIT_EXPECT_KASAN_FAIL local to the test requires changes in those
same lines. If this is still a problem in v2 and you see a clean way
to separate the changes, I'd be happy to fix it for the next version.

> >  {
> >         char *ptr;
> >         size_t size = 16;
> >
> > -       pr_info("double-free (kzfree)\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -750,29 +654,130 @@ static noinline void __init kmalloc_double_kzfree(void)
> >         kzfree(ptr);
> >  }
> >
> > -#ifdef CONFIG_KASAN_VMALLOC
> > -static noinline void __init vmalloc_oob(void)
> > +static void kunit_test_oob(struct kunit *test)
> > +{
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_right());
>
> I think the 2 patches need to be reordered. This
> KUNIT_EXPECT_KASAN_FAIL is introduced only in the next patch. This
> will break build during bisections.
>
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_left());
>
> I am wondering if it makes sense to have the "KASAN_FAIL" part be part
> of the test itself. It will make the test and assertion local to each
> other. I hope later we will add some negative tests as well (without
> kasan errors), then people will start copy-pasting these macros and
> it's possible I copy-paste macro that checks that the test does not
> produce kasan error for my test, which I actually want the macro that
> checks for report. Then if my test does not fail, it will be
> unnoticed. I may be good to have assertion local to the test itself.
> Thoughts?
>
Absolutely! I don't think I fully understood this comment in my first
response, but as I mentioned above I have been making the
KUNIT_EXPECT_KASAN_FAIL local to each test. I'll send out v2 soon but
just as an example, this is what kmalloc_oob_right() will look like:
static void kmalloc_oob_right(struct kunit *test)
{
char *ptr;
size_t size = 123;

ptr = kmalloc(size, GFP_KERNEL);
KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);

KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
kfree(ptr);
}

This way, the expectation is for the exact condition that is expected
to cause the failure, and the ASSERT has replaced
         if (!ptr) {
                 pr_err("Allocation failed\n");
         }
This will cause the test case to fail and immediately abort if ptr is NULL.

> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_node_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_large_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_more());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_less());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_16());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_in_memset());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_2());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_4());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_8());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_16());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_global_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, ksize_unpoisons_memory());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memchr());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memcmp());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_strings());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_bitops());
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_oob_right());
> > +#endif /* CONFIG_SLUB */
> > +
> > +#if (CONFIG_KASAN_STACK == 1)
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_stack_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_left());
> > +#endif /*CONFIG_KASAN_STACK*/
> > +}
> > +
> > +static void kunit_test_uaf(struct kunit *test)
> > +{
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_uaf());
> > +#endif
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf_memset());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf2());
> > +}
> > +
> > +static void kunit_test_invalid_free(struct kunit *test)
> >  {
> > -       void *area;
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_invalid_free());
> > +#endif
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_invalid_free());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_double_free());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_double_kzfree());
> > +}
> >
> > -       pr_info("vmalloc out-of-bounds\n");
> > +static void kunit_test_false_positives(struct kunit *test)
> > +{
> > +       kfree_via_page();
> > +       kfree_via_phys();
> > +}
> >
> > -       /*
> > -        * We have to be careful not to hit the guard page.
> > -        * The MMU will catch that and crash us.
> > -        */
> > -       area = vmalloc(3000);
> > -       if (!area) {
> > -               pr_err("Allocation failed\n");
> > +static void kunit_test_memcg(struct kunit *test)
> > +{
> > +       memcg_accounted_kmem_cache();
> > +}
> > +
> > +static struct kunit_case kasan_kunit_test_cases[] = {
> > +       KUNIT_CASE(kunit_test_oob),
> > +       KUNIT_CASE(kunit_test_uaf),
> > +       KUNIT_CASE(kunit_test_invalid_free),
> > +       KUNIT_CASE(kunit_test_false_positives),
> > +       KUNIT_CASE(kunit_test_memcg),
> > +       {}
> > +};
> > +
> > +static struct kunit_suite kasan_kunit_test_suite = {
> > +       .name = "kasan_kunit_test",
> > +       .test_cases = kasan_kunit_test_cases,
> > +};
> > +
> > +kunit_test_suite(kasan_kunit_test_suite);
> > +
> > +#if IS_MODULE(CONFIG_TEST_KASAN)
> > +static noinline void __init copy_user_test(void)
> > +{
> > +       char *kmem;
> > +       char __user *usermem;
> > +       size_t size = 10;
> > +       int unused;
> > +
> > +       kmem = kmalloc(size, GFP_KERNEL);
> > +       if (!kmem)
> > +               return;
> > +
> > +       usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> > +                           PROT_READ | PROT_WRITE | PROT_EXEC,
> > +                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> > +       if (IS_ERR(usermem)) {
> > +               pr_err("Failed to allocate user memory\n");
> > +               kfree(kmem);
> >                 return;
> >         }
> >
> > -       ((volatile char *)area)[3100];
> > -       vfree(area);
> > +       pr_info("out-of-bounds in copy_from_user()\n");
> > +       unused = copy_from_user(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in copy_to_user()\n");
> > +       unused = copy_to_user(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_from_user()\n");
> > +       unused = __copy_from_user(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_to_user()\n");
> > +       unused = __copy_to_user(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in strncpy_from_user()\n");
> > +       unused = strncpy_from_user(kmem, usermem, size + 1);
> > +
> > +       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > +       kfree(kmem);
> >  }
> > -#else
> > -static void __init vmalloc_oob(void) {}
> > -#endif
> >
> >  static int __init kmalloc_tests_init(void)
> >  {
> > @@ -782,44 +787,7 @@ static int __init kmalloc_tests_init(void)
> >          */
> >         bool multishot = kasan_save_enable_multi_shot();
> >
> > -       kmalloc_oob_right();
> > -       kmalloc_oob_left();
> > -       kmalloc_node_oob_right();
> > -#ifdef CONFIG_SLUB
> > -       kmalloc_pagealloc_oob_right();
> > -       kmalloc_pagealloc_uaf();
> > -       kmalloc_pagealloc_invalid_free();
> > -#endif
> > -       kmalloc_large_oob_right();
> > -       kmalloc_oob_krealloc_more();
> > -       kmalloc_oob_krealloc_less();
> > -       kmalloc_oob_16();
> > -       kmalloc_oob_in_memset();
> > -       kmalloc_oob_memset_2();
> > -       kmalloc_oob_memset_4();
> > -       kmalloc_oob_memset_8();
> > -       kmalloc_oob_memset_16();
> > -       kmalloc_uaf();
> > -       kmalloc_uaf_memset();
> > -       kmalloc_uaf2();
> > -       kfree_via_page();
> > -       kfree_via_phys();
> > -       kmem_cache_oob();
> > -       memcg_accounted_kmem_cache();
> > -       kasan_stack_oob();
> > -       kasan_global_oob();
> > -       kasan_alloca_oob_left();
> > -       kasan_alloca_oob_right();
> > -       ksize_unpoisons_memory();
> >         copy_user_test();
> > -       kmem_cache_double_free();
> > -       kmem_cache_invalid_free();
> > -       kasan_memchr();
> > -       kasan_memcmp();
> > -       kasan_strings();
> > -       kasan_bitops();
> > -       kmalloc_double_kzfree();
> > -       vmalloc_oob();
> >
> >         kasan_restore_multi_shot(multishot);
> >
> > @@ -827,4 +795,4 @@ static int __init kmalloc_tests_init(void)
> >  }
> >
> >  module_init(kmalloc_tests_init);
> > -MODULE_LICENSE("GPL");
> > +#endif /* IS_MODULE(CONFIG_TEST_KASAN) */
> > --
> > 2.25.0.265.gbab2e86ba0-goog
> >



-- 
Best,
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUJtNNDohCp30ytkSRoS03z7m49nKjQ3Nhzo5gbfVzKdNQ%40mail.gmail.com.
