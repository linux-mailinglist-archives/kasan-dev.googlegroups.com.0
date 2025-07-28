Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLNOTXCAMGQEMDOIDLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B696B13954
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 12:55:43 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-41c66de9ac8sf1861455b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 03:55:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753700142; cv=pass;
        d=google.com; s=arc-20240605;
        b=YrBC9AfIWjlg8tWKA26BW1t9R/oaZDgghycvnkMx2j4jaWwaji7QQk+fTocsMyOZh5
         nj7if1m0IMxVPU/8dV3JqeCczIMjecMjawOETNRMbAe0wWZLztafyxHyqU6rxJGgIJ7F
         vgpsYDMsuxgqPvxhLyNapuO5cbWLXlrq6VLmbwR0PmyHpi4VhMjCO2QsXBaisFm8Abgv
         ddYC8Yw57pfGyKodVNPtr9qFer+a/ABB1FuuMYEhOdN6sZenhQgM0V+PH9H2w7W3FxIt
         +cDnpVGxTQ+3J0GbfesI6lh0VxafMIIb+A4mJWtbhxWJbIF86YzfA4yrzFPitkgc3fh3
         NQTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LYugQM7a4vqYmfNDAjSDQAvWLfHBHigk5M6bDMERiXs=;
        fh=l+yrK0lkn8igfQ6bo035p0k9bX+V+B8QHdQhppzRFtg=;
        b=WMo61csvBcR5RXmYSE8Ne1myXNp5w7nR9wQSbhqkR/gx0cyd7XDIdr1rxN2F0Y/SaS
         mrTTmf9KnwVeDYduAX7qgW7WNllTM0FNmVb5PKKNSUyUICVsnvujNcaHGAzZTrcGxasn
         Pw16F7jTN6ZWxiWjICNyn66MNU0MmNYh4ivVtwncE4ZqhyWYXGcVgiJzSI4sgL0ALVNo
         9Hk8OYFpilGIEd2F8bKt5zKjxZaRg+6UVy1M59k7CTGDcfd4FicvoTJuPquzB0GLQuWi
         tUv9YLr4+BVXEJiHpo/COp/f/LVVAX9YkaL8/QCpOf/XFKGIMotY0cq2mnZ4h+sMLp3V
         uwPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UkBq0HLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753700142; x=1754304942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LYugQM7a4vqYmfNDAjSDQAvWLfHBHigk5M6bDMERiXs=;
        b=Yd45n8nRLass2XVgslWG5eUs4+OXlJQFgUmOrKpG4xsH+9X38MXCeusHQZt6c8p7md
         brYUY5S2a35X6yNL21QL6OEmYASl9dv/b41ZtluYLdJ8eXMA4tesgo2vukg/FOimhmor
         1nnroJrWSQeitrguXJCQ5EqnVGj6rsHhMg623Hky0z7v69Gk5kiXaFuie4YKr/GxGGM4
         NRYc9VEsApWB3ELeGW8ykgv7E6dZC/b4GCvbLQ26k98JlHlP1ewC+0yb0dJmp/Kd274H
         FPzIX5Uj+0R/7wyXpG7xbAW2VgIIA2y49h9mYxT20WsybW65irJWW9t04HiONmsiwSB/
         hnXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753700142; x=1754304942;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LYugQM7a4vqYmfNDAjSDQAvWLfHBHigk5M6bDMERiXs=;
        b=gaczpJX6Bk/9HQJG4mBDdL0rSMSmDATfwkOWPD4DDBUYS1YJwdnf86a4osRKVgdrjF
         xGmAoyp2TqNF2djzLFcaQUBMBUgShtgrFchU7H2Fy5d32yBAR3yM43qJcwC2lT0o4JS2
         AC5uhiM89kXNrbTkNcbTvy7TyS4MsfYfsDD0/Bh+C9uK3QAWDURvg42sVxzJyml8Q0d0
         w9XhU/8jAtkQk5ml/Fh0T3ZVhQFPkQz/fWnqvMZ9qANw3GgV3zMyEQlfAyC6OAMFpGhG
         dChqUjj5Cs1cU5rlOgt7HAjl5CI/T6dJf0utG/2vPVO/5oZGXHrQH/k6f5/Um0URj4YQ
         KImg==
X-Forwarded-Encrypted: i=2; AJvYcCUmml97uf8F+JEbQXHTi2Wgw4Z3KduTPEGPvxWarcgnNgA4+kG9NTjySoc5Tdd1DCkwmL7k7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzSrd6dumJhuQCJgCJ9X3hEkUGkEApxcvqVUKbca7LP2SMlkJNP
	zECnib6PmRlCdxFIyxePrfVssIdO0Ko1tFoVfZycg3+u8CH+wiLXmxMa
X-Google-Smtp-Source: AGHT+IFdBuNRsFnetA2CldOkVjcF+vMdShVNYmAPnIN/uIBqW5XCEQ/7MqXEMqCub2FsuAsQYUaH/Q==
X-Received: by 2002:a05:6808:1a0e:b0:406:5a47:a081 with SMTP id 5614622812f47-42bb7bc39cbmr7313474b6e.13.1753700141830;
        Mon, 28 Jul 2025 03:55:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCcbnemfKKcTd+IFBS+i4YYGT9FbO/JTK54khkx1WlIg==
Received: by 2002:a05:6820:7707:b0:611:78ba:54b7 with SMTP id
 006d021491bc7-618fa0bb8b5ls1302761eaf.0.-pod-prod-06-us; Mon, 28 Jul 2025
 03:55:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCoPt3YUEWKjk9XoRnkfQt4AwRosaj++ImhKUMiM03FXrBpsPXOQuFjOAXxe7rKxbCjVRvV6Nei4c=@googlegroups.com
X-Received: by 2002:a05:6830:718a:b0:73e:9fea:f2c1 with SMTP id 46e09a7af769-7413dd38056mr7637441a34.5.1753700140783;
        Mon, 28 Jul 2025 03:55:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753700140; cv=none;
        d=google.com; s=arc-20240605;
        b=HGUpYB8DO6iE9beJa2ojguSUuasU1QaNOFQm13szsuoDdOk8g2w5dRsmSDnOI2QK+f
         G1STqtXFybX29y5VSqOuOBoKcMssnOvJIZg243g7Nt6OL0rHpEq9EuQKwQFxvw1xKzBE
         lhkSZ2tK/6V9AOwa2NX1nPmvOuInZdg0uK2/nFenNlp2A67/utzAKCg4YBYjwQkkJN00
         hTKu9yOL9Swuin8Ubh2qH0VEa3CINHdkw+oI7xVgTo6TCzjwrKc0dW53KNpPGxgjNilv
         d5+1GpuKQqjRWyakz2SjlCQyJQXnExQA5tHO9t/4V4MepF+fYy7XbsZAA+Pcip7GES2i
         CHGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Adsk8sZq9q3h5/nndLVo9ECCof8eNE45Q3IOI8YE3aM=;
        fh=Zp7ex8WJ/xr27Aqj64qoNSkPBq2xT1nb82HwbjEriOA=;
        b=WTTv4Sk2oCiA7qT5Rze8tDCFb9sbGPkX59wEox//OITP6x6gyNDVAfPx3gF80j2kxF
         979YgSXj2zIC9Tz6PeASIrKxUrxeYFcOvyISMhniBTcX+972gULq7QEQY1NMh7tFqpVb
         y6wmnDIld3a+MzKdlCSDc2bQhEdrFifxkfG/vYpYOrJH0vBZDUOW5Gc3Q+lXW7BUG+3k
         xZSFMYmmsuWDZu7Y3Jlt5wE9Z6Zfh73xQ62WKiaiRRmsXdE8b6wTacIKvZbQHKfV8kCW
         hYSuIhnUr1vKybWfLCui3C3XX+zCZC687AE3GIJnroXhMTVnV734+wVaKn6sgd5YmiT/
         sm/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UkBq0HLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74147f901f6si264065a34.1.2025.07.28.03.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 03:55:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-3134c67a173so4535806a91.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 03:55:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJ52nVREo+zf9IJkH9dZMXrXFqNPDzm3N+2fmz/1/MvNGFI7mSYPKdMW/RlEKsKeyPxz2QYQY5xn4=@googlegroups.com
X-Gm-Gg: ASbGnctAXeINMgL6r9lBWDODgSBy+Q7pkpn2tvMlNQ8Fds7C8X9/JkogI47lauLWzyV
	DWPmwgR5Y7kJItD1+rY4WwV6R/iIeqVaI/CUoLJpKbyvFvZXtDTxtjMXXnG7b0KhDFIorqmy46c
	GmOT62X9tO1fC8rume+elePcC+R+eDmT7vVOPea47YvQDO+N6bpa/ejYQeS3esippAE7RePrDi1
	tC0Tn0Z9/BL9iynBXjP4pAizcHsxq1Zayh0UR8=
X-Received: by 2002:a17:90b:2fcb:b0:31f:168f:c0b5 with SMTP id
 98e67ed59e1d1-31f168fc27fmr749827a91.30.1753700139773; Mon, 28 Jul 2025
 03:55:39 -0700 (PDT)
MIME-Version: 1.0
References: <20250728104327.48469-1-jogidishank503@gmail.com>
In-Reply-To: <20250728104327.48469-1-jogidishank503@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 12:55:03 +0200
X-Gm-Features: Ac12FXyBK8DcCBqGyQPdxNkl9Qg0JHmvrSElApqOqMPaILY5OOBqZMtidrJDC3o
Message-ID: <CANpmjNN-xAqYrPUoC5Vka=uohtJzhOfJsD9hhqhPJzQGt=CHGQ@mail.gmail.com>
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
To: Dishank Jogi <jogidishank503@gmail.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, rathod.darshan.0896@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UkBq0HLD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
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

On Mon, 28 Jul 2025 at 12:43, Dishank Jogi <jogidishank503@gmail.com> wrote:
>
> ---------------------------------------------------------
>
> - Removed unnecessary trailing commas from DEFINE_TSAN_ATOMIC_RMW() macro
>   calls within DEFINE_TSAN_ATOMIC_OPS() in kernel/kcsan/core.c
>
> - It passes checkpatch.pl with no errors or warnings and
>   introduces no functional changes.
>
> ---------------------------------------------------------
>
> Signed-off-by: Dishank Jogi <jogidishank503@gmail.com>

Nack.

Did you compile the kernel with this?

> ---
>  kernel/kcsan/core.c | 12 ++++++------
>  1 file changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 8a7baf4e332e..f2ec7fa4a44d 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -1257,12 +1257,12 @@ static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
>  #define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
>         DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
>         DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );                                                 \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );                                                 \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );                                                 \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );                                                  \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );                                                 \
> -       DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );                                                \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>         DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
>         DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
>         DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
> --
> 2.43.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-xAqYrPUoC5Vka%3DuohtJzhOfJsD9hhqhPJzQGt%3DCHGQ%40mail.gmail.com.
