Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDMDQOXAMGQEAARRKDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EE5F84986F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 12:07:59 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6e11b2c1cddsf4778526a34.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 03:07:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707131278; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0Bok92kEGEu1O/Xk8F1m3IAv7JvN05UcYuP5KFatYxUYAbeNM/8AtFLtRooYbMqaL
         KcwOGZRF7V+PpapNgXpTIJQDtuhuNp18SEKrnTX1dY96F3Y3XLlsVbdEz7GaBcAOPhCc
         4vl31XyHEbVYZWaITEEpjww/juKV/F5+kcBkMqKZpmDk5lYpZRfz0jqpj6ko2oT95har
         SslO+8dJRFluF7gMkXTnChZ67YRfCGYDJZxtbErs/L1ESLkUbCCGYjDoUJIClPVUUYiq
         ROXmeToE4GdgVZUrti6sFzN960MR0ty/fnJXT6NKPrXDNPotaIZ8jXi6V0WaQxrPm6mG
         u9Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9IdK+v3pwGEiPaOis82SzOphf4vJTyi0xa+1801i9ds=;
        fh=fHWgEtvTFyQ35CQRDOg15WeK4TZv5AtcozlLlrKhjpg=;
        b=D4yaJbxNz5/IIDLnDVgEwyWTBTS18Qh5VGLo7a+dc9gFyGW6PNfTyWZ/IbHd91KImX
         fSfkHUXu0kDEX+eT2e0/pZ+11Dcu+FWytY+KjXV3GhoO8UKbd9PpRDt4w5tTq29CXNZn
         7L3HJwRgkTnwlCHT0tcpevWJo5N+K6SSfd95w/ZQcI8bGi9frSVjK8OUhISXsOIa0pGO
         OfeFaxzEUYf6MtoRE6RfFJXdFrWiC7fLSreItCoJr0+g9IyR77dHhZYDLehaUjBgpsX+
         6cDoPfpQdRH8HsR8FnmkdbbrsDLJ5WFDb/kdLbIjw6sMBxBKbPMCDNzTUglbZA9cr9FZ
         dtLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sjiLJX0D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707131278; x=1707736078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9IdK+v3pwGEiPaOis82SzOphf4vJTyi0xa+1801i9ds=;
        b=LoOm3Nslg0l9qpJPnHlVH9PPncKQ0b/53tRlFihYfntXpthj7JrVUXUyZn5OCzr/Qa
         yFku7WTxVXqx8ecczJqEw66guH687QgruX6RclvL7b/0AvdU3PJ5L3IavDxC8+J6tH0I
         uXf6AlGzS+Q+dyAfLUtDDRzb8jozpyrMAlUs+IIwBH3b8n1oulT27nYuvcUrzQYnvFi9
         MUTO1JweeBdaMgJzFe1azraUqELNTF74aXFVGX97DwAI0kVzsMVrkj4UDJJVnwGQ2I9q
         cVIGyFNvguoUlckKQ00VhAC3XU1gbgqkP4Vvg5+oGQZM19Eh9wsmPiO0EnOUvEhth58Y
         NRMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707131278; x=1707736078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9IdK+v3pwGEiPaOis82SzOphf4vJTyi0xa+1801i9ds=;
        b=Kx7lS91p9wZ+7+Yo375m/RDWJGNtJtE7qBHTP0I6oZldgG/UUW6XZPR/h0b8O8LzIy
         WpThDRvFX++CIw8tTmX2Lv/uqqISUII0dHTRJPyKhRUbHgBpvJgvyX3vbk8aTFIxf8aH
         vltV/UHifwEW635SnQT2LRVBGf5DxtIQiqFCnCYMLoHgBnAemAWAKZJnQ3HGziCYmaPN
         AhO0gWGP4C/uluf8yub6mCdKQmfsotMz3B8cu7PgK2dwi/V/HRg+3csez947wMN/O7oL
         AcN0bR+bL45R1Xyf0PiFMksMQ5Iql8hSS4TE05F0FWix4qA6s2jjVbQOJda/Ys+H5E3Z
         d/5Q==
X-Gm-Message-State: AOJu0YzikaDiCVQw4V+uUVro/jFDN7+lz+xitru6P5ypEIVx7qeg/j3O
	gUG1zsSfnGPbPBu8f7CY//iJvhyn+gg7cu91fiBrRIFNzgI0kYJR
X-Google-Smtp-Source: AGHT+IEwO/o+LH2XdhgGtKR/Gegq806msEW0i7gBLt4FdHsI4DS6WpLQPUWun8iCHmBL2flf8qe1eA==
X-Received: by 2002:a05:6830:1410:b0:6e0:fd9d:69e9 with SMTP id v16-20020a056830141000b006e0fd9d69e9mr10601681otp.1.1707131277832;
        Mon, 05 Feb 2024 03:07:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f8d:0:b0:42c:526:68aa with SMTP id z13-20020ac87f8d000000b0042c052668aals754545qtj.0.-pod-prod-05-us;
 Mon, 05 Feb 2024 03:07:57 -0800 (PST)
X-Received: by 2002:a0d:ddc2:0:b0:5ee:a910:107 with SMTP id g185-20020a0dddc2000000b005eea9100107mr9841656ywe.21.1707131276939;
        Mon, 05 Feb 2024 03:07:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707131276; cv=none;
        d=google.com; s=arc-20160816;
        b=defeLXC+/jOyabb0uobMpw37xsjR4nLyf6NqBAOknhfNbUMP6mfbl7IigTLs5X+WOq
         w/SVIxMsYzST9HqSDGVE2JnhYqfe79yGvVC8L13OzMrQ4bgsQD5Let0HPHb0UZB/Qibf
         2ADWiN7uiEXQue/x/Th0T24ct+41pRgNu0t0w0kkLa7qhemRA4jBU0B0fHQfrFUPEMoV
         fbvM1FkGSZQx6LMqULhm6wU+A61m5ixDl1ql+ShqBk/T5PcnIu9RuHCJIFK/GYRDuieh
         fFa6vgAwg5eS8fD+Utb4zyvPYuBoRSJAE7WZaGbRvo9/KDvwapGj5N/46aREB+EvbX+S
         3teQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b2S4QWg5rbsM0zVoer/U9D2xYC6cQRyp0XiaCDO+VCA=;
        fh=fHWgEtvTFyQ35CQRDOg15WeK4TZv5AtcozlLlrKhjpg=;
        b=JyaUKtGiecM0fsN6mzSHiS8wr/s6xj2JGh/xTO2J8J18dFKqtDWedtHE/1JvvErXWM
         TfKY0LucuD3u8VYWwUCgezGXyzX41NNPde0QSeWpWoV1qFQIvs/Ht9WrFGvq/OQycme8
         9QPKpeRhM29tOGzQHRSFp3a9GH08sFfWw6dxrZq6eUkxjYVSPt26BzzTKoP+hmBnwjhy
         RcHFGXnukON5hOLZDS6gux1VKhEEXQod8wzbG1L2/+jKpdXoCKB5rliYYEVXzVtkz5OS
         gWtxpo1XM4NcCJYy1GZj91mZUL9gZjvJDhpsn6mtNktrEMzt0hGYYjrYczMSCPqykoBE
         Hbhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sjiLJX0D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCXON5LxQ24C3QTZvsOXLbu6HXGGhyePbB2lGJTCxxaBXfiUDJl2EWtI1qkJsD7ySpOFfuznTa2jAUeRCZl2KXs/JF/htq578eE/mg==
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id n3-20020a0dcb03000000b005ff8221e768si693314ywd.0.2024.02.05.03.07.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 03:07:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7d2e21181c1so2141483241.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 03:07:56 -0800 (PST)
X-Received: by 2002:a05:6102:2fa:b0:46c:fd6d:7233 with SMTP id
 j26-20020a05610202fa00b0046cfd6d7233mr7818207vsj.9.1707131276246; Mon, 05 Feb
 2024 03:07:56 -0800 (PST)
MIME-Version: 1.0
References: <20240205090323.it.453-kees@kernel.org>
In-Reply-To: <20240205090323.it.453-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 12:07:20 +0100
Message-ID: <CANpmjNNMJn7xtpUxwxiUV1KXgMsDmyvGAq+4etFy5aiESdcDxg@mail.gmail.com>
Subject: Re: [PATCH v2] ubsan: Silence W=1 warnings in self-test
To: Kees Cook <keescook@chromium.org>
Cc: kernel test robot <lkp@intel.com>, Andrey Konovalov <andreyknvl@gmail.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sjiLJX0D;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
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

On Mon, 5 Feb 2024 at 10:03, Kees Cook <keescook@chromium.org> wrote:
>
> Silence a handful of W=1 warnings in the UBSan selftest, which set
> variables without using them. For example:
>
>    lib/test_ubsan.c:101:6: warning: variable 'val1' set but not used [-Wunused-but-set-variable]
>      101 |         int val1 = 10;
>          |             ^
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202401310423.XpCIk6KO-lkp@intel.com/
> Signed-off-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> v2:
>  - add additional "volatile" annotations for potential future proofing (marco)
> v1: https://lore.kernel.org/all/20240202094550.work.205-kees@kernel.org/
> ---
>  lib/Makefile     | 1 +
>  lib/test_ubsan.c | 4 ++--
>  2 files changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/lib/Makefile b/lib/Makefile
> index 6b09731d8e61..bc36a5c167db 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -69,6 +69,7 @@ obj-$(CONFIG_HASH_KUNIT_TEST) += test_hash.o
>  obj-$(CONFIG_TEST_IDA) += test_ida.o
>  obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
>  CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
> +CFLAGS_test_ubsan.o += $(call cc-disable-warning, unused-but-set-variable)
>  UBSAN_SANITIZE_test_ubsan.o := y
>  obj-$(CONFIG_TEST_KSTRTOX) += test-kstrtox.o
>  obj-$(CONFIG_TEST_LIST_SORT) += test_list_sort.o
> diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> index 2062be1f2e80..f4ee2484d4b5 100644
> --- a/lib/test_ubsan.c
> +++ b/lib/test_ubsan.c
> @@ -23,8 +23,8 @@ static void test_ubsan_divrem_overflow(void)
>  static void test_ubsan_shift_out_of_bounds(void)
>  {
>         volatile int neg = -1, wrap = 4;
> -       int val1 = 10;
> -       int val2 = INT_MAX;
> +       volatile int val1 = 10;
> +       volatile int val2 = INT_MAX;
>
>         UBSAN_TEST(CONFIG_UBSAN_SHIFT, "negative exponent");
>         val1 <<= neg;
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205090323.it.453-kees%40kernel.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNMJn7xtpUxwxiUV1KXgMsDmyvGAq%2B4etFy5aiESdcDxg%40mail.gmail.com.
