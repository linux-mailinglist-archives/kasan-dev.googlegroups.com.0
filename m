Return-Path: <kasan-dev+bncBCMIZB7QWENRBCOHUO4AMGQEZIEPD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E97B5999F21
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 10:36:27 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-539d1037a57sf1025761e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 01:36:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728635787; cv=pass;
        d=google.com; s=arc-20240605;
        b=CKWLLRSrCkTycwXX2cOjhwjbt/84U27Rzb7QHrGVd1In/03A/AJbxtTCJ+INgkJ0/7
         efL3ri7YjL1ml6itRrOirNIN4IpK6DzNbxVrHFbTAIqvjATzMeF3vtX43Qrhc9UsIA0P
         Ntztpc3Wk3vAcwHKrRDmimyr1dhUj+0SuGq0ZmOpkjPp5v4FXQ0lAreQ6d50WXFfTUBP
         YaTBWV5fPQf46KNm25fVwUpQHmIO8M/qKE8ZjP33cYEFyGzaZ8wm45B93A9TEJ+dhgw4
         Mq2m8ma54vuuehRCLoQynuIq93aq0BipYT3vS+8+MFvBbymkxcPO57xtaZZySM8s9ajO
         EuMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fJ90+UV9r2w687qfXDZe/5zxpzrPnSsmk789PrEmouM=;
        fh=YkLpZdLB77w3MO4yNr1vH/4tVr7QJ5oJgOsolJmqXtk=;
        b=j57uS/8MLiPFJZ4dn0Ky4ilekwUX0IKdujrSt4nPZUQV59YLfNxJWFvkdfv1EBtTBB
         5j6ncgJbqoS+uK4PK9olW8x5CqqaPrtVKcGQjUELOPzeSHvzbeY/JoNUL/qEDifpnKwB
         PSZG6iNujETSUlZy8ZUgjHwYcRZVgdpWrbNf4RE0F8AEWnbmI9veXfVEOytx5/c3pqcN
         k39OdjkSfzpqM2NwCsdu1pJlMAQHwLQMt+QfCGp2XeDSts/KGbqsqeQUv+V6TXYRyMer
         lnnJelbwORTR+oP8KrdaVTpdw9Hw9q3xgWYghcbU6lBshRrsrkJsZL21EiTktuRppgpE
         7m4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2x7AAz7r;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728635787; x=1729240587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fJ90+UV9r2w687qfXDZe/5zxpzrPnSsmk789PrEmouM=;
        b=P11eY/Aht3SqzCWzV5P5iUwVUV4MxKMhubSc7W+9Qy3kn6dBvczP1JzcqHEXdA7MW0
         dV1eh7szj/j/0sAKMVDDqHPf6f3Ww0qERWKkSod6OSdvv+bX86g3vaxmDThBmLPwO27C
         mTZKIbDYQcEwmLSW6QqaJZwtXMlAW2wEbLazn4LUDGy2LojIuErutur16SoNd4CvUJJk
         jGMK6bgWhkJdO1V5zwJEV+MxTqpRBQOxmTkkWsBGp6Iz71gSWlgteyxRf7q47M/qjqv5
         b+1XiIchBKMHGGe40McKhdEHIuzQqVK6yrISMGFPEFxUpjkQ0tMqbfZwzNrcB4QxDD/I
         idNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728635787; x=1729240587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fJ90+UV9r2w687qfXDZe/5zxpzrPnSsmk789PrEmouM=;
        b=POvu+X6G5xQ0C0bMJItoOTw+pOdh4CIcEifUi7VAjoVtFbRlbCdwnWmz7zKfHc4I/6
         mk5+W+nak0FXH7qwnw/o9YbIawQcZTlJLo20T5Sehr0kODyLwnPSsrf6/1k43EKKorW1
         BWIWNPa74mBDYXVk9vvuIm9LlL04qCTvcC9M6ZAMnM5emHpde3q9KLQmgtfcRuti2ibY
         s8P13aYhCvfilO2gFNWdFx2kf5wQ5wZqlRGAtJH9+08nOaSbM5zqoQHT1PP32t7xDY6/
         C+ZWxSRbAIlyc+gIv89tLHIc6JqlBp1sVt4EBMff71JcqBU9uTRr4hnuT08AZTtzYw5u
         8uog==
X-Forwarded-Encrypted: i=2; AJvYcCUr9HnsSQicFLfarDsCByotaASFSqXzf21FLDqZdVjWM0/F4jkXIgDs9jp2Uu+rYxzB14RM1A==@lfdr.de
X-Gm-Message-State: AOJu0YzT9OkBNpQdOh0zO1K5jngk2yrPwDELRhHN+G32vuektmcXa7dZ
	7scwXmTJ3KHh51zl0/bIowrWPuruzgXy2ac9TyImp/nbjmPExaqW
X-Google-Smtp-Source: AGHT+IGNylSrD706TfgQ/MN9Vhg9zYAQEIvJ03SrlNNDNj5KKZN9VVs8Xw851B6uoFWWGyAd7EyYCQ==
X-Received: by 2002:a05:6512:2308:b0:533:4b07:a8dc with SMTP id 2adb3069b0e04-539da4e28damr868924e87.35.1728635785614;
        Fri, 11 Oct 2024 01:36:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d8b:b0:539:907d:1edc with SMTP id
 2adb3069b0e04-539c9be7521ls926389e87.2.-pod-prod-07-eu; Fri, 11 Oct 2024
 01:36:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTfihCpV72VM9qMnXGLsV/eSk8tHlsq2Tet+v09QTQ/OXBW3wFUZ2scpilFXcELUVNXF4jBWb+VTc=@googlegroups.com
X-Received: by 2002:a05:6512:3091:b0:52e:9f6b:64 with SMTP id 2adb3069b0e04-539da4e09a3mr871418e87.34.1728635783369;
        Fri, 11 Oct 2024 01:36:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728635783; cv=none;
        d=google.com; s=arc-20240605;
        b=hem99xHXDp1DNI7Vcy76CZ9gT9h7FDly/LXlAwwRj7jwExsOcfnT05t/TwX8Y/ctLu
         dDQhN+rNXcfhlkOsOAYFN5eu2X4zVTREHmZmaXXv2p7p0FFacF4PcC56lhGPTiDrpF51
         rLjHaDIen4shY7BgFM5FPczqKUXi3nFypeTlhbwIlngpm+Wwth7V4Qxqp7HhSd6yNrtP
         X66IKkKYFtQjQix+QCRbjC7tNtnAZGeX65jlykgom/nxfNACTbaTl9QummXSa9wn9tI7
         g2QMbyRgvBW/wJTttHTub5kUtMKqXEgI+fdIC5wS8BsGw4BnAiutnS33xnMkRn1tY+8v
         YbFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HeWIw2EIIrUhovMyS0WmAAf1++JCdkJVYyCxNs9AfLs=;
        fh=PUfkjDYSfaZLak6HD69QO3wEEWg68DvH42Rosa3SHBU=;
        b=HcQ5Mwp/Y7VOjCnZRK4yuj9URFwVuvCvEIhGhVuiqOvPdgHwFJV+3RLh9ES04Lt0aJ
         3FHjzuGkDbfh67iWQw7O/Hlbx5vudhjti7oFCAaSl9G9VSHI/kkTBFZb2T9K3mO1sJ/O
         Q7gFu7AjPVapsqfW2WWWzkIPUSh/e3k9DahAEYMa5OtEejbrk3QoehQu8G8LlLodSboh
         69Ggbae+7A5xtddxbujrFK7DoyKthgsfvMOs08mHsGK0a+6xGd1LPUe4MV+Dox3L2qQ9
         rZ49JzdGsbUndodsoLQFosvykbMqOOkTq3ohr48hvv5kG77DwpIu/D8EfOS9n+DEsj3v
         J85w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2x7AAz7r;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539cb6c4fc3si54295e87.2.2024.10.11.01.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 01:36:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-2fad5024b8dso20550711fa.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 01:36:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvlLOdLytBQejktqGerc0Y/wuFm6acCbaCof898CWEkxDzEgAa8jkfiDXGSeNa4JpbFF290j6huHs=@googlegroups.com
X-Received: by 2002:a2e:be84:0:b0:2fb:2e27:5324 with SMTP id
 38308e7fff4ca-2fb326ff3admr9890051fa.4.1728635782731; Fri, 11 Oct 2024
 01:36:22 -0700 (PDT)
MIME-Version: 1.0
References: <20241011033604.266084-1-niharchaithanya@gmail.com>
In-Reply-To: <20241011033604.266084-1-niharchaithanya@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Oct 2024 10:36:07 +0200
Message-ID: <CACT4Y+ZVq76St5hTTNYtpU_EZGNf2g0iPf82DzzW9-SByh=t2w@mail.gmail.com>
Subject: Re: [PATCH] mm:kasan: fix sparse warnings: Should it be static?
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, skhan@linuxfoundation.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2x7AAz7r;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 11 Oct 2024 at 05:40, Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The kernel test robot had found sparse warnings: Should it be static,
> for the variables kasan_ptr_result and kasan_int_result. These were
> declared globally and three functions in kasan_test_c.c use them currently.
> Add them to be declared within these functions and remove the global
> versions of these.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> ---
>  mm/kasan/kasan_test_c.c | 13 ++++++-------
>  1 file changed, 6 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..d0d3a9eea80b 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -41,13 +41,6 @@ static struct {
>         bool async_fault;
>  } test_status;
>
> -/*
> - * Some tests use these global variables to store return values from function
> - * calls that could otherwise be eliminated by the compiler as dead code.

Doesn't this change break what's described in this comment?
Since we are assigning to a local var, I assume the compiler can
remove these assignments.

> - */
> -void *kasan_ptr_result;
> -int kasan_int_result;
> -
>  /* Probe for console output: obtains test_status lines of interest. */
>  static void probe_console(void *ignore, const char *buf, size_t len)
>  {
> @@ -1488,6 +1481,7 @@ static void kasan_memchr(struct kunit *test)
>  {
>         char *ptr;
>         size_t size = 24;
> +       void *kasan_ptr_result;
>
>         /*
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> @@ -1514,6 +1508,7 @@ static void kasan_memcmp(struct kunit *test)
>         char *ptr;
>         size_t size = 24;
>         int arr[9];
> +       int kasan_int_result;
>
>         /*
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> @@ -1539,6 +1534,8 @@ static void kasan_strings(struct kunit *test)
>  {
>         char *ptr;
>         size_t size = 24;
> +       void *kasan_ptr_result;
> +       int kasan_int_result;
>
>         /*
>          * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> @@ -1585,6 +1582,8 @@ static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
>
>  static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
>  {
> +       int kasan_int_result;
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011033604.266084-1-niharchaithanya%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZVq76St5hTTNYtpU_EZGNf2g0iPf82DzzW9-SByh%3Dt2w%40mail.gmail.com.
