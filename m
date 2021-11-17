Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGR2KGAMGQEB5CFKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 037CA454187
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 08:00:51 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id x3-20020a17090a1f8300b001a285b9f2cbsf780302pja.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 23:00:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637132448; cv=pass;
        d=google.com; s=arc-20160816;
        b=IFz89wqtIxyNFkjrctaEVzBuWE45GlSlw1rYJ4gSl2ZhEPXjiW2dSPtMyOC+2fx+PW
         6wBK4PtNRXSM3LqQaM3MhgceuD6GUDmob+6xJKoTUPYEfz/wEhzwX5kPhALT+6PTEnpA
         3DtuyzehQPvyM7BB7x0Z8dDJDbT6mwCfmSCiigYBM+msGzVD4ko1zY/6Q3K6EejU1EVE
         nid2h7i2XPfFIrqH9zUPXd//UFxl7h87h9WE2l5EAAP8PdPC+qxERJrlqkYwta0i0cB7
         m2ViildOzzzUcfQZSfA/HCdz2Z4mYTBLjcxdDzzTczce2wUs8QSn3YEoMN46Hbn4iwQW
         OlBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ir5Pm44kXlldFZ7f80i75MIUhYaYhJ9Kgnif635imIY=;
        b=xYKnWspUxXB3xB4OD4rUfM55jbUtQdZuzBBsCWTUgxEtZpOWvmOcTsWfOKEBp74abD
         yWKSAeB1g6nCa+PnCyZ0r27WUT1Ccl5LtXp9LypLQ0g6+wJbWe9/4vmA/bmH+PLP9jDY
         8cXgyYHLm1OVo7DFTJYmUOyu/cllOvNcCdMU/zypQ10WRRzw+YsrioERtOIl1qqOYKSD
         FexRbaI5WIqmW4LT5QnTmgbctCNRoT6u3+MTU6O5YRO+F3rGCjkAVgxQO8njp0BjvDjT
         NeCp6QEzuOqpG7YocCoeyOg1OdMY4QgH/SsaK8t/s2wP4n8nKB7iHX9mNiLLfjs6/BkD
         +N7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MqfKvny1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ir5Pm44kXlldFZ7f80i75MIUhYaYhJ9Kgnif635imIY=;
        b=mxcdR6zDt7209e6dfhzAHjpbxcCdkeWDXqDY09+zVNX5hXIIZwrQHf9GjE2Hz+9wVz
         Gjmw6YFDcKHK9DbFQIB62wrjLi0k9HZUB6GL74Mp4Ri5scnAOUq0PvANOFsqytNwPSO0
         pof9AQSCt6XkqtZHykiHUSMoVtrdAOc4PmGh4QVPhb/W6Wgnxvfvbi40sAKCXGs2/AX5
         LbZd/F7uYJXcPdmuMk1tWg54J8uXy3S/jWKUfnMt+iEdx9OlJN28Y45anjJsZkCUbHmj
         YNZxBMFd4C14Q+ePkmdzt542Mx4w1pngfSHzbATvD90UyOdo2ckSCwvAMLj7vC2/WEn6
         l8nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ir5Pm44kXlldFZ7f80i75MIUhYaYhJ9Kgnif635imIY=;
        b=YB7xzahF6FJ81+8qLpx1wzHsgHs2FUdrsu+ylSQy+cz6bbLLpH3h5cJWZclp+4uzc0
         RMGJCr1uWmZ7hvDJKVVGuq/mqjGTxHnJVsNKysko8rmiCDoXFrWm+bVuBKAWbjMTjc7k
         qZYI1MsZxHW8FyIc+C5GRD3JyGvnAOSWvHp1r2ns2dSWlF3LHi0JXyEUg45VXekA9ISf
         0PcSwZ5PduEItJ8DGv8SDypMQv5FKlV26yGMXvRedzU+KbZyrYhX840ww7407mL/IdcL
         vUzV88tgWH22OAoS5Y8ffx9hJRZkeQNpzENWO7YG18lvVbZgdczvahm4He0/5earVBbw
         ZxvQ==
X-Gm-Message-State: AOAM531XCRPZPtdMyg4WuCg4aO37eW06wbRuosPn6uIls5SylmKHqyr+
	+WWC5MD6OODRSSOICnWWuIg=
X-Google-Smtp-Source: ABdhPJzAH5ZeczMVcjLM1WdmWLeRFAOsufLQMhljXvfDQ4x6j47gxWVJ9cudkuxaMPrAMQ6QOiKnCQ==
X-Received: by 2002:a17:902:bf4b:b0:143:aa96:f608 with SMTP id u11-20020a170902bf4b00b00143aa96f608mr46637793pls.23.1637132448182;
        Tue, 16 Nov 2021 23:00:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1a8a:: with SMTP id ng10ls2537413pjb.1.canary-gmail;
 Tue, 16 Nov 2021 23:00:47 -0800 (PST)
X-Received: by 2002:a17:902:b682:b0:143:7eb8:222 with SMTP id c2-20020a170902b68200b001437eb80222mr52889755pls.31.1637132447479;
        Tue, 16 Nov 2021 23:00:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637132447; cv=none;
        d=google.com; s=arc-20160816;
        b=N6NfwSjJebSf9DHg9G825d4k1PhIdszrpfR3XUFqHpF6zoM4ZNvOUeYEx+I3dAdILb
         SXT8u+Ni2c3i8aCNCWRqVxc4vjrpRxFNC2HBmo6WLUjJ1taQEJZJvCX3SrwFTQ91ijvN
         rJLfGa2XP+cjhSq/hGb+62+Iza//Go/YsRNlLjrozDDNAHO74UN14FfBtWHdQwRCTqOs
         /V/6lAnvV4efiQeDkmGrb3GdXK9/y/nRc96VhXtIGRwI39Q/u4uGAXYG/WmOcBBtxab/
         7cjcGGRs+bIaOuveUNu7WlX2WUy3+GCe/YD9joyhk6ifmZBxjRA4CJ9z9w7PdQeGMZ4z
         GK+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FmHhPvzXYRq4QxQbLd7/J2OjVDAM7gnWOdWR2WZAeoU=;
        b=m9SY2Y8++NAJcSMwLgnT2AdhjkBhFeY/DjG7++t4xSIpmsgmquP38ZpLxB9yU0EuWX
         zoWKQfKx58r5i3+Qf5luWrBvzZu0BoPKgzp3ESxl9xmzkddiCzr8mlSnBPpvrGRXPEeR
         LU6mENU7CAR5yoCFPAc0Xcu5IAGwd2QWPFAZ6vOgc8MwXbDSaYsN1GOxfHX+anhuLJI1
         daKd+fB+25wJsOKn1l90Nf5ZWOZQEk1tLGZCidM1XN4p5wMimte8YcPwIFCRnQGjplRB
         clLDyjW8jTsj7sYHRfqK/KTNd28+lUOtyNxYrwWZsIlPOhSI39jVzRrLDWXjZ4xHdheF
         SGlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MqfKvny1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id t69si210122pgc.4.2021.11.16.23.00.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 23:00:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id bk14so4332716oib.7
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 23:00:47 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr1173117oie.134.1637132446743;
 Tue, 16 Nov 2021 23:00:46 -0800 (PST)
MIME-Version: 1.0
References: <20211116004111.3171781-1-keescook@chromium.org>
In-Reply-To: <20211116004111.3171781-1-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Nov 2021 08:00:00 +0100
Message-ID: <CANpmjNMdUJj3YZ6Bb-pDmcwe73axzuVpvQs_WNcQLnKBE-0Agw@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Silence intentional read overflow warnings
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MqfKvny1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as
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

On Tue, 16 Nov 2021 at 01:41, Kees Cook <keescook@chromium.org> wrote:
> As done in commit d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
> for __write_overflow warnings, also silence some more cases that trip
> the __read_overflow warnings seen in 5.16-rc1[1]:
>
> In file included from /kisskb/src/include/linux/string.h:253,
>                  from /kisskb/src/include/linux/bitmap.h:10,
>                  from /kisskb/src/include/linux/cpumask.h:12,
>                  from /kisskb/src/include/linux/mm_types_task.h:14,
>                  from /kisskb/src/include/linux/mm_types.h:5,
>                  from /kisskb/src/include/linux/page-flags.h:13,
>                  from /kisskb/src/arch/arm64/include/asm/mte.h:14,
>                  from /kisskb/src/arch/arm64/include/asm/pgtable.h:12,
>                  from /kisskb/src/include/linux/pgtable.h:6,
>                  from /kisskb/src/include/linux/kasan.h:29,
>                  from /kisskb/src/lib/test_kasan.c:10:
> In function 'memcmp',
>     inlined from 'kasan_memcmp' at /kisskb/src/lib/test_kasan.c:897:2:
> /kisskb/src/include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   263 |                         __read_overflow();
>       |                         ^~~~~~~~~~~~~~~~~
> In function 'memchr',
>     inlined from 'kasan_memchr' at /kisskb/src/lib/test_kasan.c:872:2:
> /kisskb/src/include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   277 |                 __read_overflow();
>       |                 ^~~~~~~~~~~~~~~~~
>
> [1] http://kisskb.ellerman.id.au/kisskb/buildresult/14660585/log/
>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Fixes: d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
> Signed-off-by: Kees Cook <keescook@chromium.org>

Acked-by: Marco Elver <elver@google.com>

Thanks for the quick fix!

> ---
>  lib/test_kasan.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 67ed689a0b1b..0643573f8686 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -869,6 +869,7 @@ static void kasan_memchr(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_ptr_result = memchr(ptr, '1', size + 1));
>
> @@ -894,6 +895,7 @@ static void kasan_memcmp(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         memset(arr, 0, sizeof(arr));
>
> +       OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_int_result = memcmp(ptr, arr, size+1));
>         kfree(ptr);
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116004111.3171781-1-keescook%40chromium.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMdUJj3YZ6Bb-pDmcwe73axzuVpvQs_WNcQLnKBE-0Agw%40mail.gmail.com.
