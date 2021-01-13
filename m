Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ6A7T7QKGQEURQOHWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id EE6832F5000
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:31:36 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 33sf1803412pgv.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555495; cv=pass;
        d=google.com; s=arc-20160816;
        b=wrLTGi2eZ3YrVgobnZJ6qVACjFZnP/U5SAB0JgtRUJxem1LC3mt6GdLXQrRDl+JNLZ
         2AK/SXYoklzaGEVNvUlLMBGDR437UVDTJ3eSgEmVJmdgV7iBtsXhqJ5Z76Z49QYX/dRz
         wXTwuAr0QIm538I5ILLrjfIPsEhSRPs8XFzbcVRiPB8U+kIA3ys3dbo9AUiFM5apgPXv
         pwKSdAYmn5OS+DYD9Pqd1EFFKEKIPxTacK6fztgF3c4Y5bcxJZdRNBtzN20CRD6S2VOp
         ntRo+vvBCpDA/vBUaXK5vE2qaEzEx6XSmDlPRISmWkcbmIS/FtgjRmeWgOV9xTSDYhrU
         p2Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zTHtgcyq+HbGWsPjZx6Kwp21Qd4i3nsQZXMbbQ+J39s=;
        b=fSWJ7m4iKEiKyh9gCo3q0jhgUZq3pzUd+TY0Pc06DnI6wpOHfL5U7PyzNs7d2FSL5/
         GTHvfnh5Kn/Hnut4p+ode2ZmKGS+yWq5GBKTcmXk2Z8z/lcDfiw8MZH/3TCacLsN6S4U
         nxuZswhH0zYyYciHOoUvWf4oJCOUXuOfSGnevtZ+QnW7bEmR3ZjDzuARzjqAMXv25b9f
         oeZfgUMAdOg3SrT2bPeVnP2Ly+KEzrkR/s2zog49JqwDk/1yI92I7Hnca7+DcxpPpx41
         02DCVte4b6vneX5gwL4wh7SB2etsfWinbXLj8pT2dhWNdzv7HDIfWh64iG9tJwMlV2Xk
         ZTWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lzTuCstB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zTHtgcyq+HbGWsPjZx6Kwp21Qd4i3nsQZXMbbQ+J39s=;
        b=XdHEHhPVU0FcfFRWV3ZZ20DuSL7a1LJLpvccz0CKLoa6RMhbJDmtG3vaE/gJr7/pp/
         BPKZuYfGPxOBU/J2m+tlSWrTZnAz6Zv13rxz0GL8gE9NQf4V84Ozo6i+zOtSXVX58yoC
         22tyQEgx1oJIMHNOjWKRShmNChI5Fvph4DhnRKu5CsAMGxGj77b48IXDoLQe4U5wUZ2c
         UK4knoHIC9Jb0NaA68UMmiFJnzlr2UmTbkjD48lM3NrNkck2em+/pKxvTyAZq4V5yYkX
         /Tk74vJbvyjIOvWUDcsUlch2Ddj/lJpHm83ApIwlIP2WS3QhgjfSTzuPGTqABE2/yWM4
         NrAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zTHtgcyq+HbGWsPjZx6Kwp21Qd4i3nsQZXMbbQ+J39s=;
        b=a7fgclVnoe0h9pBEOAuPtiR0IBVhWnHALZMoqMpzLJVZ94m9Xvu9dF/hgn9VUZ9j4H
         M2ggDlwz6EN8JITIDwJozc5Rg1aKpOGW4ee2lf/wHW9RmQagNS0vIZk22fo/86yQ+fhD
         nwTr6HSqZPDOe2qJp5/QkP1R3SKrpLN0Px4Twgr5aq3ctFn5w1Ru+/xOvYXVuwVhqA/C
         u7OW/CVU9TjKLKgGhuSnZbsLz0m2CWOlXiWOpxTDXxNDbpn3v0/wI4sZRKIiopRClZal
         bZEgscIH2VxtoqS1m8ea8HELDnVRbeGW6wUnKwa9YIGg6GGrXIYAalj2qOVMfkHJXLxN
         9KyQ==
X-Gm-Message-State: AOAM533y67pCRDfcTUyKel8NlrTLy5CULdos157oTfl+xiFs1cX+YQ3W
	XZl7hnNkyulRTr5gYJf8xXU=
X-Google-Smtp-Source: ABdhPJzMV7rMEH6DAxZUtX8MJx4OfZRe0Uc9fsZTpFXTEbOGhTOraRlTcxXYK0GRY71uFb+MqH/lgA==
X-Received: by 2002:a63:c64c:: with SMTP id x12mr2829513pgg.293.1610555495734;
        Wed, 13 Jan 2021 08:31:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls1042547pgh.7.gmail; Wed, 13 Jan
 2021 08:31:35 -0800 (PST)
X-Received: by 2002:a62:ee0c:0:b029:1a8:db14:927e with SMTP id e12-20020a62ee0c0000b02901a8db14927emr2948694pfi.14.1610555494936;
        Wed, 13 Jan 2021 08:31:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555494; cv=none;
        d=google.com; s=arc-20160816;
        b=VQbqjIgGt9HMb4GZeNxJMNTsJSrrW8Q8QHynGxO4THtt+HmojBtYCmNU0Be/MFD0uN
         mc4IL3KOpcvcvUfcNJvqxva7zlxdLYMO4nlRFtQd3XKZ4lZEtbOpgtADDr6LsaEyJT8n
         osCClH4CTIpXGSLXdOnVhwARHtg08sc8VyH0Qc1Oa4z3/P5WZufZaLyRrjxNtkBnk2uO
         Mhe7dLb/3JRifbxpwiDdYguFbVhoIlxH11wc2YV9RLHnBrrh7xKBB3BGGm6SdqfqRxqt
         QhZ26xxIa5mYQX/v0O7BDXr9a/hqzRQQuMDOeiq3PBLjNZ/gu8ZYz9F5bKMV1RXEpWZ3
         gOAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5O0XZaro4xKRzF3tZMIIKYZ6A4RiPSbA4A/IZtlADzQ=;
        b=YzKvHfwp0QyUWCgIE8w9A+yye90n2s/LhYy2E512FfUmwXUwXI5toEneWT55ATKivH
         MKFP1cMptdV4PxmzlEoGomqi/zSbahBukM8Q2iWtc/fltSRKDve6g6ISdxM5eODaEmxl
         a0gWDXmVAIL7dJGp/q6x9zuvSvWhVrufVpGDW9q6dccUzFxP2qmJYRz8JTpplWpMruyK
         47vkc2jlA6tDNmzBdv3NTV7C2fD4inIFFLjXbQjZGuFykHdjZSfglJaUM948YURSKv82
         xGbSsRO/D3iLeXcAjEG3a5+CpLGVHQ7Aht8MfUzZNAtQCAuOG3d28b8VGMKWulVgZbj/
         7YHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lzTuCstB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id o14si212524pjt.0.2021.01.13.08.31.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:31:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id y14so652492oom.10
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:31:34 -0800 (PST)
X-Received: by 2002:a4a:a11a:: with SMTP id i26mr1812321ool.54.1610555494097;
 Wed, 13 Jan 2021 08:31:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl@google.com>
In-Reply-To: <1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:31:22 +0100
Message-ID: <CANpmjNMzQ7v_wwdzf9q72nwJ8paMbvJTA9u7SpyCER858at9EA@mail.gmail.com>
Subject: Re: [PATCH v2 09/14] kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lzTuCstB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as
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

On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> In the kmalloc_uaf2() test, the pointers to the two allocated memory
> blocks might happen to be the same, and the test will fail. With the
> software tag-based mode, the probability of the that is 1/254, so it's
> hard to observe the failure. For the hardware tag-based mode though,
> the probablity is 1/14, which is quite noticable.
>
> Allow up to 16 attempts at generating different tags for the tag-based
> modes.
>
> Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 283feda9882a..a1a35d75ee1e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -382,7 +382,9 @@ static void kmalloc_uaf2(struct kunit *test)
>  {
>         char *ptr1, *ptr2;
>         size_t size = 43;
> +       int counter = 0;
>
> +again:
>         ptr1 = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
> @@ -391,6 +393,15 @@ static void kmalloc_uaf2(struct kunit *test)
>         ptr2 = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>
> +       /*
> +        * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
> +        * Allow up to 16 attempts at generating different tags.
> +        */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 16) {
> +               kfree(ptr2);
> +               goto again;
> +       }
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMzQ7v_wwdzf9q72nwJ8paMbvJTA9u7SpyCER858at9EA%40mail.gmail.com.
