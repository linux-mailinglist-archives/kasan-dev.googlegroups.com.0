Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJM7TCBAMGQEG6QC3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B61330CAE
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:51:03 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id o7sf7170337ilt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:51:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615204261; cv=pass;
        d=google.com; s=arc-20160816;
        b=UtzqKfbljN0F3/8FUF335xoaE7UE6Z+xq38MZNNB17IaucLJXysXFmaRnDApAAXJIc
         SD0v4iz9nczB/BzVk3un4QdGxmPM211KC1LKHqaD/u6a7833B8xlvDscT6x+62d0kgbJ
         CX5cKGQl4iDZZy2Y1xNNXamZJKeGQv045QNZY8d7bkytv+fOaHedYH2uCXuVjSkFZixu
         kAzxRr7TQUEEb2XfFlER8WR6uqvYNwo64wLRrRnagLZop3OCaUWEbWGIqMoZIg2M12Gj
         Fm52NgByUQs2bQuK6M8r7m2/A3lqNOwcH1fTY7sibqgf2v9olQjHqrDbNkgScoFbhdyd
         1XrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OaPseDgfIk8B0Iq3RW70dJPXcWGvJASOyQ+Q9LZX4fw=;
        b=Gqd8/G2V4seeuWqpVKaXSp1i1asfsTLuMLShZqfj5+1YYjgvVrtqGxGiFR+UeRv6/d
         3ffHNU3Z03iEBzA5UamAQUmXKoEG3IrayFUOFYg+IcluaxWkEsTjRr4McmXFtD4q8VhN
         Q8pxw6v8YYI0TYJjUrPGQFXBGu+dvb+cdzxJ9c+gXcwvrgnifDztabZsPYYJ0unG8U7m
         UdrQzUUf9nOU/6tXCeBeMNgKFsba8gC7MV+4HK8bllWHxQrfHgaksmA2epbX2clE6sR8
         U9IYamPfTkSU2YernkoZogN3egbEIH8GWKkbOWyeiIz9HDoAspxl72M9d1bu1rdGYKXM
         drvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PS5NN6DU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaPseDgfIk8B0Iq3RW70dJPXcWGvJASOyQ+Q9LZX4fw=;
        b=pnP6Mdu6VnifM+UkdWs5ZNVHgpiQV+rPIeV799TbwC2ZSF9f4Jwf/rnZ6R1N/VhzG+
         uj0jk4Z7nHmc2b33zvnGYJKaXu0XdEQmeCmxwg3WSSRbRzP99rlruYXSseTevHeLZcz6
         +yBnX3MQIA95gUI14IhDwRQSy3g3lkqixka9HrkYa936OCN80E6jblaJpZOuM2tXpo+N
         iH5TZoORBKyoVsI9u0Ko+GFNF3HIhPnfhlRucDh8uLp6oJARNtJMgfT0Wpn6WxNpJRg0
         H83U+pWuFRg2hyQiuICPFOBf+c3lOfIarHBrc8mYSACjDLqL+nlkDZw9DwcvTTaS+9uz
         el6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaPseDgfIk8B0Iq3RW70dJPXcWGvJASOyQ+Q9LZX4fw=;
        b=Gvs0bNw28yxM0bC50pSizPBvqI/JzyrGBuTySs/WagSgvAzNCRyJt2R7cEO9x4828W
         YHK6CAm9S2yDIPrfya9D3eJxaZ/n6UM3t34d0d43oLLguM7J7MODtvtool/e2cl/o38I
         9qGfFU0bmwMZ7OtUZZZmFkwbbP7/2KiB/lYmA2f7RV3VHsnoorxvakQiDwpTv8rl7NLe
         ltFPQipqTylhRjdu7Z71XsAhHNKcpZvCF0q/rofEfMH2A4AgziCs6LMLzOLByzir/KKH
         FjsyjWAVV7FzDYMNMU0TX2qZ/QYcCCn/a9zKKnpWi1B+kQ2cNOEiFdbLsUTIgreV/vIC
         DZhA==
X-Gm-Message-State: AOAM531Q5U7qOBoa04frMEYdWuMC+Ib+YTq/mAmkwQVXDYn+qbQ8RxkQ
	YDT81ujZbJjuFwN0zqLTJvQ=
X-Google-Smtp-Source: ABdhPJzeutU1a5y8K18Rn/gKD8y8licAiZPOe1DSPyF01c0XL5/hQYI6oGP9oCdS+MZzoelNN+vNeA==
X-Received: by 2002:a05:6e02:1aa9:: with SMTP id l9mr19847310ilv.108.1615204261706;
        Mon, 08 Mar 2021 03:51:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c6a2:: with SMTP id o2ls2383967jan.6.gmail; Mon, 08 Mar
 2021 03:51:01 -0800 (PST)
X-Received: by 2002:a02:a506:: with SMTP id e6mr22746051jam.56.1615204261412;
        Mon, 08 Mar 2021 03:51:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615204261; cv=none;
        d=google.com; s=arc-20160816;
        b=tbrnGj5KzqwE6XiCFkpWFdiyfyzHCx6GGehD8laRXV6t729bC4gV+IB0aLhPsLDVk6
         ngYUebn9L22FboMih1eVL5ZAH+gVlXTv9lnaOXW8cG7P5y5/WNM6ELX+hkAEYLWau3dW
         RA9gmyFMl8q92YoDbj/2d7OYjVQ1KbAcDRrG9OqR+6dG2WYAR0j4oLqVthIRNh2huJ1w
         fuPvUmz0mQ15g0Uwy+8ByB7/Vg2xd4b5SU82Wm01hIHJaz78qK0+WhHTvdCjC3fGiN6H
         P/80N1YL50V1W0gFdQmPvqe2UbLw7V8aVgMDEi4DY0MwRtDV5eydiwazAtN/g/0CaXaZ
         if5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JbNCPfQ/roqFMvfDVCK/GyRFnn05PPWL4s16p+iljKg=;
        b=VWAAog28URmq6YPBsByHUDIvr/d13VERExPFdMSL9gwrFm0EbNdWBlld5aR8s72yt5
         wCOsMY5nOjhvQbG4/1qX4ScUUY6gUveGGjGdMf9WqsOBr6cxdOwAD+kpu0C/Q9FR/LLc
         x+twu9WSE3CfYodMeSOhv6TSiBnqzZ3j2z9hVy5E0q81lU/EFi0dlNb/Gfk+KVucuyhS
         q1Hr4fMo1QIyKju280FOCzAv/JSzJypmn98VYQ7P0vwkkQ41h2k2FSF3ZAn3N/dc58i6
         OyvFboD3PQGMzDm2BxPpqLeVq5sGVKbHZg+VM2grf2nHNnCcKwBK9Qi24qFeAqWYmTy4
         vLmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PS5NN6DU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id i2si647136iov.2.2021.03.08.03.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:51:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id 75so5617718otn.4
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:51:01 -0800 (PST)
X-Received: by 2002:a9d:644a:: with SMTP id m10mr19849951otl.233.1615204260958;
 Mon, 08 Mar 2021 03:51:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com> <a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl@google.com>
 <YEYMDn/9zQI8g+3o@elver.google.com>
In-Reply-To: <YEYMDn/9zQI8g+3o@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Mar 2021 12:50:49 +0100
Message-ID: <CANpmjNM+CoExcw=19VOtXT5KMnSboTUCska1tmR_WZVMeE49sQ@mail.gmail.com>
Subject: Re: [PATCH 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PS5NN6DU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Mon, 8 Mar 2021 at 12:35, Marco Elver <elver@google.com> wrote:
[...]
> Could we instead add a static inline helper to <linux/kasan.h>, e.g.
> kasan_supports_init() or so?

Hmm, KASAN certainly "supports" memory initialization always. So maybe
"kasan_has_accelerated_init()" is more accurate?  I leave it to you to
decide what the best option is.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%2BCoExcw%3D19VOtXT5KMnSboTUCska1tmR_WZVMeE49sQ%40mail.gmail.com.
