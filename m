Return-Path: <kasan-dev+bncBDW2JDUY5AORBQGEZOWQMGQEMWRIG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0509783CF77
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 23:35:46 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50ec9529001sf6971219e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 14:35:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706222145; cv=pass;
        d=google.com; s=arc-20160816;
        b=W6pOyf8+SyqxRd2JUXSAWFhQCRKW0KAfTf9zNXLUgONA377ngAVKu2VwyuhHx6/IpE
         hZ9fkMctaRpRN6OMlDwdK/YuFmvJb49ZGXRmGvZ7wlDVHYWjaUNJIIXMuPT9DWs4kCWb
         euxwONNMlUcftyV1hMhgtpqQ3sjr+XvyPTSlgnhXr0gZtHL+onytEmDuzAnZbOSnja0I
         rHc88xUn5db9/2T0eKXYiglzRKwiPutPAtjengIrCkA/4diRLQF+tU0KS3WPn9dVwtWV
         WmADniZcuSmv2AdJhJ3SjgZlhXgVGSEADWGoHupgqGqU7SWmMLlQpkkSrF27FOaMpKaK
         wi6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2CG/xfZg4v1aw7pc7CfQIhpm4Ws4von+vtNkKu57DkE=;
        fh=TelzYXsKV/XCvET+MX8e3uiDLq8TTlJn2KvxhnaIHPw=;
        b=YRTr78eBZvl3bF64YmQemseBJ822oapFz4GCQ4yl2TR3a4Cu+QIUbYbD967vQBlIHl
         AhsNDohcT4fbHr7BKyy4MqDoPcNeQdLnzUoBmyvHK1QsXcfZ9H+c9BZGbKZvHaGwlwoV
         ADsF4EYIWgDopF/9SszJpqY+ilN8MMrd8IIpPDa4jXqEhBZ+2ZSOd2xNG+pYJAvwmxcR
         FBmX6Un5vcZP5q8bhQEFd48k/m/Kk7YbFGM1qNE5qE/jbMCXNwWQKqCcaV/cm7waTq8B
         Rpr6kLLexCEairI7D4URqi3vYmLD0hDlSJjak0dFVpwWUHzsSZFt7FqdZl5fxoJYs3i/
         YXkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ulnebp6G;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706222145; x=1706826945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2CG/xfZg4v1aw7pc7CfQIhpm4Ws4von+vtNkKu57DkE=;
        b=Hf/aWX8SKNVvAzqojD65j7Yn5h77p7p/ct9ZQmrSr2c/LGyLeKTvKEFlzviqLcbUKV
         7mlUi8/TgKf5RG/9h7l5r2JuTOFlMsg2GC05DhwoyjWjDS3pK4TSf+rDyDEatxXmLyip
         q6z8XzndBxbRxHvAGoqCgyK5G6Exh9LOGQp3UaO2AWWoenJApZe0HErYr0wmeUE5lT1I
         tgOx4BC9Ut7biyrUcsEPlm/IzMDl/VQCAhr3qeBPaC9X/ZS574BXmUrbEQAwml4fhcgp
         DlZIuw6Z2uF1T8GBW8G+sFn/tZIE5Ti6IQqClUh4qGP6s7PfULs/2JKNPiF88NJvtgBX
         JfYg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706222145; x=1706826945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2CG/xfZg4v1aw7pc7CfQIhpm4Ws4von+vtNkKu57DkE=;
        b=Kg/VTKwjJ4r43GffKwsnEl0XTEh5kX8fQqzkT69yRvAjDhYQIGzjpoAmv9CG7fnK6D
         1DtJCURIebKq/ndVYm1TGk1AbRcFpz9imrQe551HWql3yRVcVFHyAMWwF5AbPY5y/QvJ
         IPWT+UG3PFGl3onyck/2O/Zdxl0GYeoB43e2hfBKEDe1L34KjGbhM5BmGGZ5s2S1DCv9
         vOSZP65pD19zTDVzOa9dnkdtR1G64059d2248HlQGh1nspPAO1ffZaGrNvKsOd8glIou
         XeRT98REjN82mj1seX5vTL7w0gRN6JSMn2/YTec2csABN42EkiiTcOLUysS6wuyKQ9JL
         Nwag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706222145; x=1706826945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2CG/xfZg4v1aw7pc7CfQIhpm4Ws4von+vtNkKu57DkE=;
        b=xQz7N70cyZUrnV1Q9dYTkci3gMxwV1CP1wZQsn6B9XjK9EmFK9ZkR4RrwGocW8vFDx
         96tCuC/hqv/ylVd4e04quK6j/ths/3o0tx2mf0sQgFM0wrn74X9QgrVc19zxmazvyk8Y
         Z80pT3VhsPVcBxyye96DmlgjZKaXkI09ERDkjaBVWrkeA5ivHMhXM35/cMiAk19dott9
         YCEiyYZHt3Cy5InH3G744c7Kxm4eBsKEzSSenHt3mkRJJz9RF86sznuLyjAaViu9nh+E
         NGb5WzltxXNKL0AB61n009a73IQdRN0YZzPmslWw6aNmapjMhpsJNH0+ros6ayywqc2x
         UsNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwOkxl067oHbupYm4VNJzU443S1+3MV+1w/OISEUkRRqIbc/5r+
	ZzlKf3RRn6JW/SuFor74ikgRcpxbg0EkdjO+bLJhVDaE2302lVAo
X-Google-Smtp-Source: AGHT+IEcvjIhUnEPUNP79pMduFmqcxIJMAJHVwricjxRWgj2LpR5LNO6PcrI3KmVk8STEh6VzgcjiQ==
X-Received: by 2002:ac2:43c8:0:b0:50e:7479:79da with SMTP id u8-20020ac243c8000000b0050e747979damr534669lfl.24.1706222144649;
        Thu, 25 Jan 2024 14:35:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ef:0:b0:510:2176:d89b with SMTP id v15-20020ac258ef000000b005102176d89bls43926lfo.2.-pod-prod-09-eu;
 Thu, 25 Jan 2024 14:35:43 -0800 (PST)
X-Received: by 2002:a2e:9f4c:0:b0:2cf:3006:6dce with SMTP id v12-20020a2e9f4c000000b002cf30066dcemr322855ljk.15.1706222142661;
        Thu, 25 Jan 2024 14:35:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706222142; cv=none;
        d=google.com; s=arc-20160816;
        b=Uruxkhbb5figseJUf9En2gQrhLB56I5MQyHWydY0/trDEZ1zTL9pTAFQVq3GBFeDEX
         9aSjVj4dupiRwXmDA7aNCoDlPsrmwPj9X1b3i+NKdHMGMIGb7cpWHyS3kczDoi4Q9o0o
         nOvRQ+j0c+3Easu3gf4jChkTMun5M04YcKNt03rNBbbVss2rJ4g4hSZwtwWGLq5U6kip
         9BYfQyzyDh2gH/iUKjioFoAZj+niuzfpG67oMElZZKc4aY3YUtoUx540xCC0w2z0eWQo
         S7KZam7G8WAz6E46RSIypTy8r6t3mqNGI3STO8POMEEZbJ7F8Fb+HsqK0NoaoA39pqiE
         M7qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FMyr1t75aVIHFmn0P1+tdWxst8vu4zQ4wyJGjRe6tPg=;
        fh=TelzYXsKV/XCvET+MX8e3uiDLq8TTlJn2KvxhnaIHPw=;
        b=FdNl3S3VadxfYZkmgdKugsV+OnKuiDeSVvJMgo4xjwTFfdUolBpBLIieY4k9XZq3I5
         G1lJiD24TJpt55jqNtPaH6f7pK0J96uyd4uNGlIuT0jJb3UXM8JMhBh7GedE5OyUyJO9
         +fIcKwfyWD818ygD1h09K2jyHhKQ/0G5pxVlXs+cywEB4URrG9CNJSynCCE26XV9s7Bh
         3tQWDi032zf7jDhgHrOl3SXb64/kX1oY2a6nzCbsI6yQKwxmJ2XtyG9xOiO88p6cU3LV
         07/9WCRLn5E4xESzrz038im2+lRih7ks1+uRFOYTnOovMeOyRtNX7dY4rOzfTLe5DMfS
         sNiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ulnebp6G;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id b7-20020a2e8947000000b002cf233737dbsi115270ljk.6.2024.01.25.14.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jan 2024 14:35:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-33937dd1b43so3527669f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 25 Jan 2024 14:35:42 -0800 (PST)
X-Received: by 2002:adf:e350:0:b0:339:2b28:32dc with SMTP id
 n16-20020adfe350000000b003392b2832dcmr314421wrj.53.1706222141699; Thu, 25 Jan
 2024 14:35:41 -0800 (PST)
MIME-Version: 1.0
References: <20240122235208.work.748-kees@kernel.org> <20240123002814.1396804-55-keescook@chromium.org>
In-Reply-To: <20240123002814.1396804-55-keescook@chromium.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 25 Jan 2024 23:35:30 +0100
Message-ID: <CA+fCnZdiLCDTcOmc7x_eHV9oNQhNq_sU1_w+rafoBA1FVEbwrA@mail.gmail.com>
Subject: Re: [PATCH 55/82] kasan: Refactor intentional wrap-around test
To: Kees Cook <keescook@chromium.org>
Cc: linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ulnebp6G;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 23, 2024 at 1:29=E2=80=AFAM Kees Cook <keescook@chromium.org> w=
rote:
>
> In an effort to separate intentional arithmetic wrap-around from
> unexpected wrap-around, we need to refactor places that depend on this
> kind of math. One of the most common code patterns of this is:
>
>         VAR + value < VAR
>
> Notably, this is considered "undefined behavior" for signed and pointer
> types, which the kernel works around by using the -fno-strict-overflow
> option in the build[1] (which used to just be -fwrapv). Regardless, we
> want to get the kernel source to the position where we can meaningfully
> instrument arithmetic wrap-around conditions and catch them when they
> are unexpected, regardless of whether they are signed[2], unsigned[3],
> or pointer[4] types.
>
> Refactor open-coded wrap-around addition test to use add_would_overflow()=
.
> This paves the way to enabling the wrap-around sanitizers in the future.
>
> Link: https://git.kernel.org/linus/68df3755e383e6fecf2354a67b08f92f185365=
94 [1]
> Link: https://github.com/KSPP/linux/issues/26 [2]
> Link: https://github.com/KSPP/linux/issues/27 [3]
> Link: https://github.com/KSPP/linux/issues/344 [4]
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  mm/kasan/generic.c | 2 +-
>  mm/kasan/sw_tags.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..f9bc29ae09bd 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -171,7 +171,7 @@ static __always_inline bool check_region_inline(const=
 void *addr,
>         if (unlikely(size =3D=3D 0))
>                 return true;
>
> -       if (unlikely(addr + size < addr))
> +       if (unlikely(add_would_overflow(addr, size)))
>                 return !kasan_report(addr, size, write, ret_ip);
>
>         if (unlikely(!addr_has_metadata(addr)))
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 220b5d4c6876..79a3bbd66c32 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -80,7 +80,7 @@ bool kasan_check_range(const void *addr, size_t size, b=
ool write,
>         if (unlikely(size =3D=3D 0))
>                 return true;
>
> -       if (unlikely(addr + size < addr))
> +       if (unlikely(add_would_overflow(addr, size)))
>                 return !kasan_report(addr, size, write, ret_ip);
>
>         tag =3D get_tag((const void *)addr);
> --
> 2.34.1
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdiLCDTcOmc7x_eHV9oNQhNq_sU1_w%2BrafoBA1FVEbwrA%40mail.gm=
ail.com.
