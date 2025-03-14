Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXFZW7AMGQEVAJPTKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 096C2A60660
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 01:04:32 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-600ebc0bf2asf661058eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Mar 2025 17:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741910670; cv=pass;
        d=google.com; s=arc-20240605;
        b=ecxDvGSYKesMnnj7XNOcCuqa/FQjuzkkfoQzkXN+5PGcDhpnZT2UY8rF07zazCamka
         vy1azsd1uB3C8hJdeuuHXjJgG+PEavE6f3iXcsEtCwDCMYKIKlXQSViEk8Z+d8L1EkAe
         i8QL0QiN/K9YfusjDvOpdBXt2Fycb3JoQQTUeCUzgP0TPJlzSsWI7OFmQx65y2CaR6Qj
         s9J3vYcDVGxycgsfAjLSSM8BqZcH0qAmXdnNlgroxVlBk3uwfTTjd+GhWUGkTsmrE6jr
         1+brLqdboKF4P9izncUySDdLi8HJVkjwClVZM4/SfHwWTrY15azXsPmuagkuSHy29xly
         ifiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :references:in-reply-to:user-agent:subject:cc:to:from:date
         :dkim-signature;
        bh=l5iSKsNsMbpGKA9I2HRbobMLOTbmdLYdubQ1SvIUdKE=;
        fh=/iVfUJrmTpIB7aqaaf+bIJ4LrERcEaV3EclC4GlJeu0=;
        b=gV0MxnvdOXQ+KdpPEYpZSGaxJnjo+d3xwvavPmIkHM5uKXdXsORXga2j13lBYUs35+
         YXpnb1oqDLxYXUqw3uVCc/NDWyqm7GjWxjUYQIS9hAna6NzqrjU9bHVy3YulmlJXhdwx
         q0yl+7YHcu61DnrsfPMEcvhfWa5498xnR9McntpbFL6eUlEOUCm24Gj4ujzfs5NrDuJX
         40177uuLCtm/MwCAE14rv06nj3yvcpMyQwG+iLSq/tScAlU4UElhuYmLtz9+hpx01Ja+
         ZOP7NgI3aqAC1b6cjlE1J8jXk3/EUkVqlsYwDvrLoBYOWM30XEgBt51vWYjFFpRECFyd
         YuPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=taviz52E;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741910670; x=1742515470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=l5iSKsNsMbpGKA9I2HRbobMLOTbmdLYdubQ1SvIUdKE=;
        b=bHeOklgOIwMxmPM42MHOjZaqeetfjcFaTvJd0N9wv4YPTTBxBsmtFDYVsxxIf019Nq
         JsNeAX710o5+5r3pDaRVCcQZUJjQdzn/3vq1TMKnVhVeqPtLyaSc+SiLkktDd/XQ2XAh
         7JvFWYTaPBh/f5bINQRm10IZk5P7L11IMx5vD5SqAmaPDVb5C+V9NOGW0hWTdY6c0jyG
         v6oyqdq3DY8uMN54Il9IUA97Ozf81NHjEjnm6JIDHIVV9GoggDu8nYrpNppF4bZlAYqh
         6SfY3yguLizoR85GLS6qW5AfSSlDaM6PoIF75vB6YMbm/p/RJFACJxYAj6wzoARxpZgu
         go+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741910670; x=1742515470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l5iSKsNsMbpGKA9I2HRbobMLOTbmdLYdubQ1SvIUdKE=;
        b=HCVuH+wboPj+1xHWx+nIqAf6WhMOSCaSbv7wXQVm9tUFiQiSqQOfvmAKbhnt6XDtGg
         HqQ2swhW52tlm39doI44OLyDABJxR2SZ5v6/IfTkES2/3qEZxPn1kJgS6iqwanegkP/t
         Egf3ocNVcpe25FPjEZypu95c7gIpQgNmFo8lEDRjjLKolD8MUXeu5sECu1UFNEpzJbU0
         mEEsHDMiHGZOxodU4PowlcnC5YR0+vSBSySpEariS3SnBuNgGiquhL3qYb4c3BKSKTUo
         27KOcKaIukmVybkhG57txhTtFsCj2jNiEQXLQpCsprcGU/JZw6yxrAb6i4VSzQ1ZKeW9
         IpEA==
X-Forwarded-Encrypted: i=2; AJvYcCUf9QJNh163Da268LSxOo+qXrJTBOV/1kCSKlt9nhllUfvz5yPnUREK+kIWH5IDX9DcQviq6w==@lfdr.de
X-Gm-Message-State: AOJu0YwDPwcCXjil7syV8xr6HkLWVZhvsy2loqcTn3qwkqeDMBYZFk2L
	731qWYJRaCrwEyabqLURzLCtMqp+TcvNrNzytPCDLM4b5Xwvt5T7
X-Google-Smtp-Source: AGHT+IH6gtPqfyAL5j/mkea8hL8OQlgBh4PQDILLrfrK5JPLFFtz3x3k+i0e8SIv0NYneuEGKK8ZWA==
X-Received: by 2002:a05:6820:2781:b0:601:af96:36eb with SMTP id 006d021491bc7-601e46075ffmr271045eaf.4.1741910670383;
        Thu, 13 Mar 2025 17:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHtBKqtc9M48psBtgRIj3XgjfhANk0PyPraHmtTn3slQQ==
Received: by 2002:a4a:cf0f:0:b0:601:b5da:c4eb with SMTP id 006d021491bc7-601d87da158ls404294eaf.0.-pod-prod-05-us;
 Thu, 13 Mar 2025 17:04:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUw5nGifmJX7wUqJilvrzPCKQRoiHnkNBBPHxUDTL7dxvawQM26h8NkfBo+PzB0Cgoba4kSB81cg0=@googlegroups.com
X-Received: by 2002:a05:6808:1902:b0:3f7:ccac:287f with SMTP id 5614622812f47-3fdf026dc8amr137820b6e.27.1741910668778;
        Thu, 13 Mar 2025 17:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741910668; cv=none;
        d=google.com; s=arc-20240605;
        b=VNT2QAe0nNfS4TvCjq0socSmyaCYNVTNFAXiGsfwwvEVT2QrlRkcDLt4cTgiR1+OVx
         MFRc3DnQbourjYHUjBERYZFnvMZnPR66LZdgkVe1h4bHCuKBwsUnwtR6LRinEaTYqWiu
         fP8087YY4Cja/zrG5+9+hxdKocHw5BNZFv1DkrUEauJKos5z612CI5xtvh+RxdlFHjZB
         +tqF4+yn9qniXYTiHEa8sHuV3l+eoVC/Cnvigr7bv/GAmEguQhxXEVh5wEvB0qwVlY2k
         eLk4vN9xySGUX48zGwhZ7cfGcQis/d9LzIhx/+p+ySXdMOz90C6hDy6ygXKJyDXFH39g
         vw7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=PZhzbpn3pfNwUKevDLaO0+qk00VqEfdpu+6DuDASVns=;
        fh=TxLslrDMDPwCHhD1G/kOTlqWCCTVgzyZcJxjbGCK6Zs=;
        b=aF9I2Hd+aHYZ110hbuVbuehBlD+Tx8snEBhV8di09/qSBdkEC18QupGAOWcq7nvLZP
         +5ZNr21XhevKBD5fFAMQhWIyJcRXTr5mj6mkjRm8koatGKrUb5RqXrFj5s2Q5rlTrRCH
         4ljoFMlSy9HnTwODHo7SFbZi3WqRQGuzKHeFgB1MU5n/0SDSuX36S/WII7ehRmYT6N+t
         ijo+R6HJMznzPF4XegmI4wybOQqXWNkh7eEuKGg/N6bvUWRyU4HHiYfcDOMNTx5q5zYU
         pC7vwirXvyuN3paT2vP1vJXlfZMO8QwgyrFzumvTHmybVyqZJBLSBc1CpDzKOHadZvWe
         17Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=taviz52E;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3fcd5df4578si130683b6e.4.2025.03.13.17.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Mar 2025 17:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A90865C57B8;
	Fri, 14 Mar 2025 00:02:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2CB50C4CEEE;
	Fri, 14 Mar 2025 00:04:28 +0000 (UTC)
Date: Thu, 13 Mar 2025 17:04:24 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: Justin Stitt <justinstitt@google.com>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>,
 Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>,
 Hao Luo <haoluo@google.com>, Przemek Kitszel <przemyslaw.kitszel@intel.com>,
 linux-hardening@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kbuild@vger.kernel.org, Bill Wendling <morbo@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Tony Ambardar <tony.ambardar@gmail.com>,
 Alexander Potapenko <glider@google.com>, Jan Hendrik Farr <kernel@jfarr.cc>,
 Alexander Lobakin <aleksander.lobakin@intel.com>,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: =?US-ASCII?Q?Re=3A_=5BPATCH_1/3=5D_ubsan/overflow=3A_Rework_integer_?=
 =?US-ASCII?Q?overflow_sanitizer_option_to_turn_on_everything?=
User-Agent: K-9 Mail for Android
In-Reply-To: <CANpmjNOHSanxX7EyXhia4AuVd+6q5v1mXQMTM_k0Rj20P_ASAA@mail.gmail.com>
References: <20250307040948.work.791-kees@kernel.org> <20250307041914.937329-1-kees@kernel.org> <CANpmjNOHSanxX7EyXhia4AuVd+6q5v1mXQMTM_k0Rj20P_ASAA@mail.gmail.com>
Message-ID: <2AACDA6E-F7EF-4962-937A-C9511E4E2930@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=taviz52E;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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



On March 13, 2025 8:29:29 AM PDT, Marco Elver <elver@google.com> wrote:
>On Thu, 6 Mar 2025 at 23:19, Kees Cook <kees@kernel.org> wrote:
>>
>> Since we're going to approach integer overflow mitigation a type at a
>> time, we need to enable all of the associated sanitizers, and then opt
>> into types one at a time.
>>
>> Rename the existing "signed wrap" sanitizer to just the entire topic area:
>> "integer wrap". Enable the implicit integer truncation sanitizers, with
>> required callbacks and tests.
>>
>> Notably, this requires features (currently) only available in Clang,
>> so we can depend on the cc-option tests to determine availability
>> instead of doing version tests.
>>
>> Signed-off-by: Kees Cook <kees@kernel.org>
>> ---
>> Cc: Justin Stitt <justinstitt@google.com>
>> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Cc: Marco Elver <elver@google.com>
>> Cc: Andrey Konovalov <andreyknvl@gmail.com>
>> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>> Cc: Masahiro Yamada <masahiroy@kernel.org>
>> Cc: Nathan Chancellor <nathan@kernel.org>
>> Cc: Nicolas Schier <nicolas@fjasle.eu>
>> Cc: Miguel Ojeda <ojeda@kernel.org>
>> Cc: Nick Desaulniers <ndesaulniers@google.com>
>> Cc: Hao Luo <haoluo@google.com>
>> Cc: Przemek Kitszel <przemyslaw.kitszel@intel.com>
>> Cc: linux-hardening@vger.kernel.org
>> Cc: kasan-dev@googlegroups.com
>> Cc: linux-kbuild@vger.kernel.org
>> ---
>>  include/linux/compiler_types.h  |  2 +-
>>  kernel/configs/hardening.config |  2 +-
>>  lib/Kconfig.ubsan               | 23 +++++++++++------------
>>  lib/test_ubsan.c                | 18 ++++++++++++++----
>>  lib/ubsan.c                     | 28 ++++++++++++++++++++++++++--
>>  lib/ubsan.h                     |  8 ++++++++
>>  scripts/Makefile.lib            |  4 ++--
>>  scripts/Makefile.ubsan          |  8 ++++++--
>>  8 files changed, 69 insertions(+), 24 deletions(-)
>>
>> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
>> index f59393464ea7..4ad3e900bc3d 100644
>> --- a/include/linux/compiler_types.h
>> +++ b/include/linux/compiler_types.h
>> @@ -360,7 +360,7 @@ struct ftrace_likely_data {
>>  #endif
>>
>>  /* Do not trap wrapping arithmetic within an annotated function. */
>> -#ifdef CONFIG_UBSAN_SIGNED_WRAP
>> +#ifdef CONFIG_UBSAN_INTEGER_WRAP
>>  # define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
>>  #else
>>  # define __signed_wrap
>> diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
>> index 3fabb8f55ef6..dd7c32fb5ac1 100644
>> --- a/kernel/configs/hardening.config
>> +++ b/kernel/configs/hardening.config
>> @@ -46,7 +46,7 @@ CONFIG_UBSAN_BOUNDS=y
>>  # CONFIG_UBSAN_SHIFT is not set
>>  # CONFIG_UBSAN_DIV_ZERO is not set
>>  # CONFIG_UBSAN_UNREACHABLE is not set
>> -# CONFIG_UBSAN_SIGNED_WRAP is not set
>> +# CONFIG_UBSAN_INTEGER_WRAP is not set
>>  # CONFIG_UBSAN_BOOL is not set
>>  # CONFIG_UBSAN_ENUM is not set
>>  # CONFIG_UBSAN_ALIGNMENT is not set
>> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
>> index 1d4aa7a83b3a..63e5622010e0 100644
>> --- a/lib/Kconfig.ubsan
>> +++ b/lib/Kconfig.ubsan
>> @@ -116,21 +116,20 @@ config UBSAN_UNREACHABLE
>>           This option enables -fsanitize=unreachable which checks for control
>>           flow reaching an expected-to-be-unreachable position.
>>
>> -config UBSAN_SIGNED_WRAP
>> -       bool "Perform checking for signed arithmetic wrap-around"
>> +config UBSAN_INTEGER_WRAP
>> +       bool "Perform checking for integer arithmetic wrap-around"
>>         default UBSAN
>>         depends on !COMPILE_TEST
>> -       # The no_sanitize attribute was introduced in GCC with version 8.
>> -       depends on !CC_IS_GCC || GCC_VERSION >= 80000
>>         depends on $(cc-option,-fsanitize=signed-integer-overflow)
>> -       help
>> -         This option enables -fsanitize=signed-integer-overflow which checks
>> -         for wrap-around of any arithmetic operations with signed integers.
>> -         This currently performs nearly no instrumentation due to the
>> -         kernel's use of -fno-strict-overflow which converts all would-be
>> -         arithmetic undefined behavior into wrap-around arithmetic. Future
>> -         sanitizer versions will allow for wrap-around checking (rather than
>> -         exclusively undefined behavior).
>> +       depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
>> +       depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
>> +       depends on $(cc-option,-fsanitize=implicit-unsigned-integer-truncation)
>
>Can these be in 1 cc-option? I know it might look slightly more ugly,
>but having 3 different ones will shell out to the compiler 3 times,
>which is a little less efficient. At some point it might noticeably
>increase the build initialization latency.

Yeah, good point. I could probably just test the most recently added option, as it implies all the rest, too. I'll send an update!

-Kees


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2AACDA6E-F7EF-4962-937A-C9511E4E2930%40kernel.org.
