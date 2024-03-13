Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVG4Y6XQMGQE4FL3HTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8838387AF3A
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 19:20:05 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5a36dc5e472sf39762eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 11:20:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710354004; cv=pass;
        d=google.com; s=arc-20160816;
        b=Py/3rjfjIsvr7ZZ3K9dvuCFNIzwumLe43fYvpBharHhFvqTAaDezucQ4+NGBlnZ9J3
         7+9Y51sDAPz9ubO9qYGR2ypkb2/EY1Gfxm9RNHcisQtS9Uf0N09TFlhU0pShE6/HLg7Y
         mwVo9Ur96COV6xVCKbirGTE/pXkC0hY6hYyqiI6xzPVw9Mbshz6Xq8jud82Z1E78HOVM
         1M8rm0O0rQxKKV1XcsJu+qiU4+W4Jy5DM4TsNZYJNv4NuA+C0xee/Uv6R8JFo7/IRQ1j
         5v1vmi0zr40kQSpCVWYPlqhfUiG76t9cSJJkVGJ8uyf4MpMLP6B7rC8biycAtJyqCthe
         jFWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VyGiiy7AFR65TYw2cHVnBGrkwsePeZN7aooBFHvBtUg=;
        fh=Bt+pfZUj7EFgPS7D//VnnWD8fD9cz7JeahAlTsSviNg=;
        b=H2moO0GJR8s0eQwvBjnK0JYtvgYima6Qz/RqewLZjSy50z7WlrFl7XTtpLvZgIQLgx
         U/l0HVo9WbpeeFEXKaV+szNooZ2s8QMQrxee1ep/1I1RuKPs3wmL9AAMpxQZmuuH7AH5
         zd+CKwcAbtsBQIvbXakZ8n2V9bpbod2mmVBz+MOGdiT/0+Q3qxEjf1uGq/6PdS5gMtUz
         pPd3Nv10u7HbuMCnR3a/8HhzC3jq5lsvXf3qRdiESjE0ojjEK/2ap/4PqA/2IYOyC7s6
         JdxZGhj5H1L2WXjXwhWHd8jA5biAnJhHDJLZNEjmWKT1B4EHgq6UDLKpm6yuaGq3zRXv
         glvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cO8DvYBn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710354004; x=1710958804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VyGiiy7AFR65TYw2cHVnBGrkwsePeZN7aooBFHvBtUg=;
        b=gbxFfqTWixwg7hqJBRlQMwq0DOX7l3JONFURFt7lGlvaKF3ulfJpUiFbeJAYHvPJdh
         zwyInhP8Gl7w8dS+AVsdFHcaH3JQMRj0bfpaffpNLfkRNIKOYYzHtFvhQyC+JWvPRUsC
         tCKqnbTEP13en2Zs4EUsH6NZj730yNFC5VlY5XE8qH2hh1+txgPjQ0drgGJwqrMX2k4k
         VjslL3fPsy1yYHrNzqoxD6CfRTwAZYA+CbMQ3mO3sBzKUl33Ng+q+EBOynbRaLoKZb14
         CyIj/P+AzXKrNSPTTgC37/70fJxaWLWaLAgkGRzXxaGGWajt2S2RB2kt0lCaEPL91IXf
         GxlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710354004; x=1710958804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VyGiiy7AFR65TYw2cHVnBGrkwsePeZN7aooBFHvBtUg=;
        b=rWLJSfWzjiA7UeMuoE/zFTEl++h63Jb3QtczhiFMfLjTFcN9rBMC7cf3uJLCd+PGa4
         hacDDshDxl0/jJqWHWmnGztpJDtS+PgoM1iydib1TLi9FYLzqh/TM+q3lGpTVT4Q5ZGQ
         jBlNZtETPef+L+E5Lp7khQE3CPFb9ygylbWJURop1JxZ+pp5HmdFjgV9n21awnBezqbC
         YnGDXin3wxuqtfZL0dIvXrgxA0/bINluAXlluMzh7EjTFFa4jbKGtpxmjxctZ5abaBQ7
         D8IeIQxj7Qezh2xbOBmiFGcOG2qZuL3VYJLzofyT1tM4SqgLmdCwWENLiSZo6TT6JP1P
         +Pkw==
X-Forwarded-Encrypted: i=2; AJvYcCV7JLCmO8/sKcfDG3rWy3FfMfT/SnA2Q88QM/HgNO+qMArJkpMyH+uvOT3oaORZqs8kZvq+7uWti/1bn9hcxQXg58ScILfdDA==
X-Gm-Message-State: AOJu0YxV7yEb7MyKC8W5uw1q0eN+xBwTQ+9OyiSdhfxhKlAApBX2UP62
	ViJEN+556fvm8QjoA9+k6gGwutXZ4t8kFRW+g42GCSJIp8j0HaUP
X-Google-Smtp-Source: AGHT+IGO48WnjIfOiGcZdzOAwh1Cn8XoGp8ThvVUTBPvEQnNmCxfDrhAfSkxgH3g/aKxVuLBNrwQHA==
X-Received: by 2002:a4a:2455:0:b0:5a1:dd31:a398 with SMTP id v21-20020a4a2455000000b005a1dd31a398mr848115oov.1.1710354004160;
        Wed, 13 Mar 2024 11:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:91d8:0:b0:5a1:a267:bf1d with SMTP id e24-20020a4a91d8000000b005a1a267bf1dls63477ooh.2.-pod-prod-09-us;
 Wed, 13 Mar 2024 11:20:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4h55B20eNhAMiHQSC3Irtt6clUri4PnFXCxn3K+CHRS/XLYfibgn/iGiQq94H247ai8yVvbdBM6b7Sx9A9NuoK/jUjaKo6ZgjQA==
X-Received: by 2002:a05:6808:1983:b0:3c2:5d2b:7a2 with SMTP id bj3-20020a056808198300b003c25d2b07a2mr673257oib.12.1710354002879;
        Wed, 13 Mar 2024 11:20:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710354002; cv=none;
        d=google.com; s=arc-20160816;
        b=wZjRuGlZGGndBA1koYIlJ7TKZz+34k4IzVoQT2K928SOGmyAhxQN+3L5p1CQisSegy
         I9VqjQYOp8qdDoTU+pvv2bGBdDFVkw6ijA4zJyNJUXDgjD4NJqJNQNq+1Pbrq87jjWz3
         p0TmHyQpQwWvOc21WwfAYasUJqpuP7FrtOLF8lzIHvY4A9dl6AgDQE/LVx48r2gyOLN9
         8cv1t4LI08Y5fFqcxzsFakqui1dff6uZIps9MlUm4MgJweCRIze+JVYRjr8uIh/hUDfe
         WPPF0AeBuBTsMgAFL4OsPjkoPzkZDMZemKzpp2R6NKK8wipwvYeAuh2K9mzHskUvga8X
         Bruw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NwvnBQtlcUyRAyfwaWKEGU4GgQpA6zLF0Jl2IAoI3iM=;
        fh=i2pJEuCxmYWDVQbFTDajio9XFoV2K5jS8UkUJOvZXbI=;
        b=pQXnqXaJBp6VlUdjULgutlF3smGcq6p0S2+kim8TTiPWrb6d1ncenGqEHMC2zZH9mR
         WKcDN+zsZv8ClkJJIUqbr5o5hPF0ijM73GfVnxvQA9L6R1O90LBaz01P9OmLgOJuhpIh
         YMM/yI6FnlmHaViHCHultAjUA9V3mYnGaBZCynYiwiKDCGefzeJ8FdDNG0B3rK/l3LVV
         BsX68Kd04Q759AZx2APUF2w7nrVdH/15rp5jskDBzLNn4e1KUkQyKAuN6e8YnjbKR0m5
         eNuc4i4rqVZkesuVfcd3cAmPECqYnerpIr0zvhkGyngU2Qqv6+R1nG+BAg0QPmnxzTID
         iekg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cO8DvYBn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id bf1-20020a056808190100b003c1e7ccb8f2si1808823oib.1.2024.03.13.11.20.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Mar 2024 11:20:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id 71dfb90a1353d-4d41d198211so40217e0c.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Mar 2024 11:20:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXe1pBLHcVOrFqqk7CJKRNRg8W+ohPMbOaD2oNz1epasKq5t5Sui9S9lBb9LbpzO+ZtHQcDN9o1MSLQASzpAgKMpM0T6J+IbkCeTA==
X-Received: by 2002:a05:6122:3d13:b0:4d4:5b5:5287 with SMTP id
 ga19-20020a0561223d1300b004d405b55287mr977068vkb.7.1710354002256; Wed, 13 Mar
 2024 11:20:02 -0700 (PDT)
MIME-Version: 1.0
References: <20240313181217.work.263-kees@kernel.org>
In-Reply-To: <20240313181217.work.263-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Mar 2024 19:19:23 +0100
Message-ID: <CANpmjNPxHkSe6iG+=D84Zk8=d6tTwTxDgR=nX+4QWirv4avS_A@mail.gmail.com>
Subject: Re: [PATCH] ubsan: Disable signed integer overflow sanitizer on GCC < 8
To: Kees Cook <keescook@chromium.org>
Cc: kernel test robot <lkp@intel.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cO8DvYBn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Wed, 13 Mar 2024 at 19:12, Kees Cook <keescook@chromium.org> wrote:
>
> For opting functions out of sanitizer coverage, the "no_sanitize"
> attribute is used, but in GCC this wasn't introduced until GCC 8.
> Disable the sanitizer unless we're not using GCC, or it is GCC
> version 8 or higher.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202403110643.27JXEVCI-lkp@intel.com/
> Signed-off-by: Kees Cook <keescook@chromium.org>

Looks reasonable:

Reviewed-by: Marco Elver <elver@google.com>

Thanks,
-- Marco

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  lib/Kconfig.ubsan | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 48a67058f84e..e81e1ac4a919 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -119,6 +119,8 @@ config UBSAN_SIGNED_WRAP
>         bool "Perform checking for signed arithmetic wrap-around"
>         default UBSAN
>         depends on !COMPILE_TEST
> +       # The no_sanitize attribute was introduced in GCC with version 8.
> +       depends on !CC_IS_GCC || GCC_VERSION >= 80000
>         depends on $(cc-option,-fsanitize=signed-integer-overflow)
>         help
>           This option enables -fsanitize=signed-integer-overflow which checks
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240313181217.work.263-kees%40kernel.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxHkSe6iG%2B%3DD84Zk8%3Dd6tTwTxDgR%3DnX%2B4QWirv4avS_A%40mail.gmail.com.
