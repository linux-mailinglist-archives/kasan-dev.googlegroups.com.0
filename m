Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZFNQS4AMGQEG4GYDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5991299161F
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2024 12:37:26 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2e1cda109cfsf2125272a91.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Oct 2024 03:37:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728124644; cv=pass;
        d=google.com; s=arc-20240605;
        b=S4pUyBUuKMB2S+5BSVadycGoWU/D6UUjXbw0haoA81MeshlmR53AowckQUWAKh5XAU
         ztCHw+QhdgGCXsuPBErFFTxhde+Ef7oFOXuNBZNMwx5MiB/OFRO5vINF9xYkCWSAch/l
         m9qYgi1wRKgfWjs8jjI2K7hlMX3goGy0JPbur2jjeM3J+IOkgzJPz1ykvd4zFxSHvYxc
         RrByCGGfgFt+BpASCXxI+kl87YWmP/7L2yyvMonrEJKtT9bTxcQDMUi4eaiB2NoVSpD/
         r5jm8P2oDLnqdR0hEcr/5uM3gj5+OAlyR9Vz5Xw101WJUr1TRIP9Pks/wMeQfDD/kcHM
         oyPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=twCNCWKVirHgcIkln0e0jHqzk4jdfzwTNW1pYrgHixQ=;
        fh=4NKJd+6RaCfo7VZIf5yJ1YnvU5KyJ7M67S4pVpHXfx0=;
        b=Cf1UNV+c4yoTj1GhJhpI1pFRg9evwpMK0d9rBsU5ENPo1J4gyxPHITJPJkhqapFSh6
         BTdorV0dwYZBOCTms2o1hsmbDOVtJ8lWa804x0MXWHhBVvAVDiJmxLvfZ96ULsHk/sJ/
         7ORc4qIa9AFU1W83S1QukhjLINDlBYJjrbP7wkErTwFntU0TqCYwzhoAZzmFjpLnjrhv
         V4/heaYbnAEzAcX7D4WHcEmICAzCrb/rrUTQaDxJz2NJW9jypddttRdKQiwoaVRHd9Vk
         3FjT5XySr971w7cZ7nLxEwRSQR/R/E0IkdJIUOXNctr/TVPwCSPBh/Wdd84Sio5KpOgg
         cLsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h4CKdthH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728124644; x=1728729444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=twCNCWKVirHgcIkln0e0jHqzk4jdfzwTNW1pYrgHixQ=;
        b=wtnyFaZSM5RHIQOGVu3cYKpZmPxmJEdWlc+o1+Z4bZ7hFaA6CRNyvSxnGqoBIunwOi
         mfvz32ax5KQdvtv+9bJqWMdlCkmaH62WfdHc9kz53pieLtphp3E1F8Q413Mzj9dYWWnp
         xidRMYAvhEGek7YxeMAZT3h8nfGHKSy4srsZpClwn/0TzB5YyKzk/V6NzJ0/Xu2PosL4
         8SMuQlrXTa9gnH/E/asb3k9mhNo5RDLLlSHMEr7tfnUpYYzmZkmYRCY3iGlu8gp8r1Kr
         gTk9ia1UOsO08F9c+VprznJB2oAmLi+yW8H4VIQ61HlAwNd0j/TdHpXzECYHSGsvjbng
         N8Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728124644; x=1728729444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=twCNCWKVirHgcIkln0e0jHqzk4jdfzwTNW1pYrgHixQ=;
        b=YzNbcADOYEytLCeVkbgFDCl2W3BG8B/xZ0+nArYm8COWrOeRtpLaPR6AM1Z1eNN/Na
         /H5rlYuGXm6NvKP7ROSOKSk1pH4BIOIxqY9VvKciQ1eFu0AF5bQdnxYRwPKrzG76kn4e
         tlsG6oecn90DKqXpvJZajYB2DQHm2XzFKTgmAg1YUOGTHo3cm65RVEPs2qbya6j8BUQH
         1V4uWTTHHO0kPvnMSGQeaysS53kuxcjoHUS/AsLW0k7OzD49+T1vd8AhVU1UNkcIR9fZ
         E5PzJynfkm5Hrrji/OPxQU2jYHxckRH1tI200S9ZO/4c+9Z4BCcI0ktqxqX77+yQEtqr
         OLEg==
X-Forwarded-Encrypted: i=2; AJvYcCVZNXnISjXmLVi07RRicsUbCEoAUZSPptrKrKDtd7BPaX+ETSGMJAZZlkBe/b0gdSeNBsCwpQ==@lfdr.de
X-Gm-Message-State: AOJu0YxPM+oK0qfxxWhMJSMLcdeY+jsgXGK8i+4qfuRz21fp+IuXTsrE
	uwjgrPZTrRIs3QTXhAPUmCn20DUtmaeSf/NbBd4HNOG6Ji0S2lZy
X-Google-Smtp-Source: AGHT+IHWjrI6TKEIwy8TAVeSv8HV3yyiNhSzdA9TZ3DnhwayPPoiI4RVTwCAOLxtFrCxcUeeGEj3mg==
X-Received: by 2002:a17:90a:a412:b0:2e0:db81:4f7a with SMTP id 98e67ed59e1d1-2e1e6211a19mr6599272a91.4.1728124644574;
        Sat, 05 Oct 2024 03:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:11d7:b0:2cb:5feb:a0b6 with SMTP id
 98e67ed59e1d1-2e1b3932e08ls687588a91.2.-pod-prod-05-us; Sat, 05 Oct 2024
 03:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWL6oYeaxpnmbEpiPhXb+HW9UcOD4KIHQ1diiYYE1CKG6Y0meREAjpWQpNFUYmgcJ4JrMB+UExmizE=@googlegroups.com
X-Received: by 2002:a17:90a:ec07:b0:2e1:e1d4:7f2c with SMTP id 98e67ed59e1d1-2e1e62259a8mr6486791a91.11.1728124643155;
        Sat, 05 Oct 2024 03:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728124643; cv=none;
        d=google.com; s=arc-20240605;
        b=bNBN3I/c/xHsnTWul80sqEcdWjV2lmhg+D2kDQZubNX39qBnpZ/wugJesVf98DcKT6
         2erIOpGi4EObnvHogxgP/qvHxB6qcrsga0exGQ5s6NaacBghtDnrCPGhCjP0V+iN2f/i
         6TLNEE+rx4rMcqiKjPe2wcG/0wwLzbisXSF3gX4Nl9JLrS/7tF7z2Zkv+rltxJzeYug0
         VDE848h3Myt0YDyEke5fsP5kS8PRAbC0x3w6YeIDJ1zjRgqh0yw1AyY2D8j1aTGwYWPu
         sFGrfvJLHd7MdUunorgUEuOWqUfGbp+kHmsie6idRGpscMu6R/IZ9/PXployTK38EwY3
         NIwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B4ms11ZQkraDYH9Xo26ocEAmXpjpDosjseyHDy0gtFw=;
        fh=T6JOsLDorc54vkPsemDUZuDQJQ66d0lXyqVdu4GgdnY=;
        b=P313uFu8zdKzb6A+w2rnPYNsTQLPtQWm6hg14IrVSbP4h4rwMNuV+L9S/sT2jF77fp
         XXujUHPXPdmFSVTROnCha+doLoSV66viUIkxM8g6QSFybGC7BzBsbGIEUZdw/OrJaWjh
         9f1yinDm3XgDxRMxyGMlEL1rwkeXi+NuQFZYrVSP5PSFl+kubaE2FIr6jirG/YU+Q5qI
         zlzqUmQaE3nPj19nqtujNCZoANkhESyeDm7tHIVu1oXFxiBO3/n1AkHVCAVXIl78u3Lk
         RR+5SRz9PjFtOWsd4Og54MYB664UmCvYwv7gaRAhAzh/dH+cv/MdjRPHxkVI4KDJWqTl
         tOlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h4CKdthH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e1e86a94bbsi173755a91.3.2024.10.05.03.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Oct 2024 03:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2e0894f1b14so2246919a91.1
        for <kasan-dev@googlegroups.com>; Sat, 05 Oct 2024 03:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUssDdbWV/akYk19733wVbus8V/z0NM+0DYpL5dj9ad11tc4ZucY25Cyxu3xrRJtrPSRiUI15557SE=@googlegroups.com
X-Received: by 2002:a17:90b:494:b0:2c9:b72:7a1f with SMTP id
 98e67ed59e1d1-2e1e632369fmr7417174a91.28.1728124642435; Sat, 05 Oct 2024
 03:37:22 -0700 (PDT)
MIME-Version: 1.0
References: <20241005092316.2471810-1-snovitoll@gmail.com>
In-Reply-To: <20241005092316.2471810-1-snovitoll@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 5 Oct 2024 12:36:44 +0200
Message-ID: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
Subject: Re: [PATCH] mm, kmsan: instrument copy_from_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, akpm@linux-foundation.org, vincenzo.frascino@arm.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	bpf@vger.kernel.org, syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=h4CKdthH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
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

On Sat, 5 Oct 2024 at 11:22, Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:
>
> syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> KASAN report via kasan_check_range() which is not the expected behaviour
> as copy_from_kernel_nofault() is meant to be a non-faulting helper.
>
> Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
> kernel memory. In copy_to_kernel_nofault() we can retain
> instrument_write() for the memory corruption instrumentation but before
> pagefault_disable().
>
> Added KMSAN and modified KASAN kunit tests and tested on x86_64.
>
> This is the part of PATCH series attempting to properly address bugzilla
> issue.
>
> Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> Suggested-by: Marco Elver <elver@google.com>
> Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

I'm getting confused which parts are already picked up by Andrew into
-mm, and which aren't.

To clarify we have:
 1. https://lore.kernel.org/mm-commits/20240927171751.D1BD9C4CEC4@smtp.kernel.org/
 2. https://lore.kernel.org/mm-commits/20240930162435.9B6CBC4CED0@smtp.kernel.org/

And this is the 3rd patch, which applies on top of the other 2.

If my understanding is correct, rather than just adding fix on top of
fix, in the interest of having one clean patch which can also be
backported more easily, would it make sense to drop the first 2
patches from -mm, and you send out one clean patch series?

Thanks,
-- Marco

> ---
>  mm/kasan/kasan_test_c.c |  8 ++------
>  mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
>  mm/maccess.c            |  5 +++--
>  3 files changed, 22 insertions(+), 8 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 0a226ab032d..5cff90f831d 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,7 +1954,7 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> -static void copy_from_to_kernel_nofault_oob(struct kunit *test)
> +static void copy_to_kernel_nofault_oob(struct kunit *test)
>  {
>         char *ptr;
>         char buf[128];
> @@ -1973,10 +1973,6 @@ static void copy_from_to_kernel_nofault_oob(struct kunit *test)
>                 KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               copy_from_kernel_nofault(&buf[0], ptr, size));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               copy_from_kernel_nofault(ptr, &buf[0], size));
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 copy_to_kernel_nofault(&buf[0], ptr, size));
>         KUNIT_EXPECT_KASAN_FAIL(test,
> @@ -2057,7 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> -       KUNIT_CASE(copy_from_to_kernel_nofault_oob),
> +       KUNIT_CASE(copy_to_kernel_nofault_oob),
>         KUNIT_CASE(rust_uaf),
>         {}
>  };
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 13236d579eb..9733a22c46c 100644
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
> index f752f0c0fa3..a91a39a56cf 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -31,8 +31,9 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
>         if (!copy_from_kernel_nofault_allowed(src, size))
>                 return -ERANGE;
>
> +       /* Make sure uninitialized kernel memory isn't copied. */
> +       kmsan_check_memory(src, size);
>         pagefault_disable();
> -       instrument_read(src, size);
>         if (!(align & 7))
>                 copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
>         if (!(align & 3))
> @@ -63,8 +64,8 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
>         if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
>                 align = (unsigned long)dst | (unsigned long)src;
>
> -       pagefault_disable();
>         instrument_write(dst, size);
> +       pagefault_disable();
>         if (!(align & 7))
>                 copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
>         if (!(align & 3))
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZ4N5mhqWGvEU9zGBxj%2BjqhG3Q_eM1AbHp0cbSF%3DHqFw%40mail.gmail.com.
