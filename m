Return-Path: <kasan-dev+bncBCF5XGNWYQBRBU56UOOAMGQE6SLUJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 40ABB63F5EE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Dec 2022 18:07:33 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id bq9-20020a056a000e0900b00571802a2eaasf2474291pfb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Dec 2022 09:07:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669914451; cv=pass;
        d=google.com; s=arc-20160816;
        b=bsH0TIgkjw50byaqEbDWNK249vghKDRN+d6kCFdXNj+8cRC90f/ZEinRIIaoB+adQm
         89bN4eLavQi2uXNqSGZN94X+VA5lRYbK2AZO2W4xUv8gZh02X5NhM0oMV3feXYBF+FKK
         uVngDthbu6vmIzQ/vtLJDNCFetmlkcwr8Q+QJwC1AABi/6X7nneHX9bt9CVzaiwJpmA/
         MlqI+JwplsZcnAxxGJCOgl47qt9Kgr6sc/MO4PKg9zsKa0XQKvYLu6C1wBcSdYMLKVGf
         Lx+v95KDHPFpZ69uasRqTASN+pwFa1LhFmjBYe+OU7FqosUDYRdHWKyAVZqXGR4brbqf
         ivUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kONnUD4U9t7KZVjwNtaiR19O54kgmNqn5PXqSPhTE2U=;
        b=peJT29npvYuTKFQtUQGEiJdmniMBWfESEWj4G3dir183wji7gAIy/9GpYGDgSZ07OD
         Ls3CbPIohqngUVIOa0kEgclQtSTBPKARyPdW2saaxW1XxVgvVII3DhNjXrSUloosQwAI
         eOSRlZH3xaaUooDsgy+Fe9XN5423p1B/UBBHGm0oouszRn5AfseX6erzd4FGZbE5pCcR
         K5XaFSmpOl2rwZ0q1z5DF75OFN31nyo7CxRl0RoL3Z5bBjWH4AUBrZ3EUHmQefWoaXFE
         18q3VfHwtFZ9V0TtBgo6WII/MjhwrFuvWc2GMtPTSSJ/WZqPlhqeKcecWotIsxjjoQO1
         2Q/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BB+tP7Kc;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kONnUD4U9t7KZVjwNtaiR19O54kgmNqn5PXqSPhTE2U=;
        b=HYXoUMyfkMpchv6pbcZXqYSpOa+OPAyWVkqwFI81ymOwocLydAMdRDEsO8s2IGqJY7
         twbd2ApekolH9DqRu7JVWPK4uIozJbufgSiKkAjrtOpa/HzHZ3bcB+dPM9qHL2wonCI+
         CDrWZJlJWf1qjhJxHqFN8kDHu/3Kh/bIARBBGbgx75jwUpnz1sESoERYPCnEHf4S4FaY
         1mCVqAKKKxQ5SA39uR291YAerKw6poJBkS5BCrQMLR3lbvW8Rg/J1g/88xIspXYgap92
         CZu/Tv8xBnbTtB+vFgUoYmSLPwHLTISZ61LnHvXvgV0t4gUCLdAcLUzfCmbM3AiwheH3
         KWRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kONnUD4U9t7KZVjwNtaiR19O54kgmNqn5PXqSPhTE2U=;
        b=XdghD6g71AqROMn2wsB8BuLq6y2SeTO88xukUu+hdcvt1QLQXL3LnXL/BSTSc2oMnd
         YkzSUDxOjrKcWH++spEkoeiF1K4byUVfg5t+uGiiWDc+/dn/RN1SOTFs1dKGYGNtcYiu
         QZ2egwk/kUN0h3TuybARLRyGROCjFTZanyEpM2TfyIgeHXFlYgaxp9DcoDJQsdjl4zYI
         Dto2OGhq+w2sgvZFb5xzbfqJ0vEZorsWv7pXM6UbYCp4qUo1jLmXFU/sfLxXlT6+lRKi
         XpqVbtVwiw282j8CGznCXhccNNeAh9s3Litd6axtrYB+0hh+7XyNwdzv1J2G0TGrPgWl
         rDyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnQ9c8BwEzxeeHAYeN2pdy8gxWQrEhp8cz57EbZNFlWAVAIlc36
	MLKIl8+llxtAY1yIl+SPa9w=
X-Google-Smtp-Source: AA0mqf6vPZp9Qpt+QBNLcjyncbgtp86E3MLbRGoyBDh8eiXFjkwYZiFsC+PDvTGclLNvol9C8GSrYg==
X-Received: by 2002:aa7:93a3:0:b0:575:c993:d318 with SMTP id x3-20020aa793a3000000b00575c993d318mr10694739pff.78.1669914451384;
        Thu, 01 Dec 2022 09:07:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7789:b0:178:3881:c7e3 with SMTP id
 o9-20020a170902778900b001783881c7e3ls2399153pll.11.-pod-prod-gmail; Thu, 01
 Dec 2022 09:07:30 -0800 (PST)
X-Received: by 2002:a17:902:bcc7:b0:188:f42e:6a90 with SMTP id o7-20020a170902bcc700b00188f42e6a90mr52951542pls.127.1669914450651;
        Thu, 01 Dec 2022 09:07:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669914450; cv=none;
        d=google.com; s=arc-20160816;
        b=v0sMxcAiT8ly3rSMPeNu9nILe5QNIuLhvxtP1RMnyZ+prrr/DwvoX9bhhYzqkatqO8
         9U6ALup3n+PuukuZAhnkXPUkOi0XzrU3QTV+SRgz3Ms4CYKD9AVPO0Zl0/ORa3A8D+ib
         Rr5G5ZAb7+DwWo/PtboiogZHt3g5HcByTyUZ2ASsvmCsbwfRFSAB2lm8MDkb9PtN0tp7
         3PklGvA6+YafbAHS3HiSNaNA4PVQFdv2doyg6YjbH37wttBe8Q+Cc8XBvTyts3mhyR1G
         QiFfrqZX0t1LOUZRP2XcXLkrGbSbCtDrwuV8zQ149pMb8XJUWUt1hdAYe9/TTTeWpn9W
         JDuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2h6V7XvvjPy1lxD6pcJR/fFIby5mlqq6VvEqNgaJZlA=;
        b=JsMVvMwpykHk85V5pc36HjJSf2Y7lxtgj3fg75O0PeaKT5jFlU8AAp0bhTYQfo2fVD
         OXafcmLnv7pkU7SddgLIiOvjWTGB/kHZWJMaf6vxRjuSW+bFFJJPrmpBf16uHTqRmvRq
         qGI+qRVFeSFvF7H+82XmUW5EoIWa3agrgxJY4exQ+V5oZdNtZI4XAIX3HmkGsVUWpZBe
         P1yxOuUiV0A1OI/tySvKufxRVy0gfNqwyIP1rFMQrrum9xxsiGH/cG5JUrX3FrBP6LnV
         hoQl2Fy8xcLrcUB1A1Mi4JcPuOg0IKBDjoGR3/2u46+Kxw5xVmLsPi+zQ4T3BxhwkJ6q
         7HSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BB+tP7Kc;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id a7-20020a170902ecc700b0017824ebedc5si267080plh.1.2022.12.01.09.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Dec 2022 09:07:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id t17so2418496pjo.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Dec 2022 09:07:30 -0800 (PST)
X-Received: by 2002:a17:90a:29e4:b0:219:4056:720c with SMTP id h91-20020a17090a29e400b002194056720cmr20051470pjd.53.1669914450359;
        Thu, 01 Dec 2022 09:07:30 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h15-20020a056a00000f00b0056ba7ce4d5asm3531488pfk.52.2022.12.01.09.07.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Dec 2022 09:07:29 -0800 (PST)
Date: Thu, 1 Dec 2022 09:07:28 -0800
From: Kees Cook <keescook@chromium.org>
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Kees Cook <kees@kernel.org>, akpm@linux-foundation.org,
	elver@google.com, kasan-dev@googlegroups.com, davidgow@google.com,
	Jason@zx2c4.com, Arnd Bergmann <arnd@arndb.de>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/2] lib: fortify_kunit: build without structleak plugin
Message-ID: <202212010906.0CE64E9CD@keescook>
References: <20221128104403.2660703-1-anders.roxell@linaro.org>
 <5FC4A1FD-9631-43B2-AE93-EFC059F892D3@kernel.org>
 <CADYN=9LT7xWScSiprwgB2DhTN-Mws7rxG33BRZwLktK7P_jzkQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CADYN=9LT7xWScSiprwgB2DhTN-Mws7rxG33BRZwLktK7P_jzkQ@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BB+tP7Kc;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Nov 28, 2022 at 03:20:13PM +0100, Anders Roxell wrote:
> On Mon, 28 Nov 2022 at 15:09, Kees Cook <kees@kernel.org> wrote:
> >
> > On November 28, 2022 2:44:03 AM PST, Anders Roxell <anders.roxell@linaro.org> wrote:
> > >Building fortify_kunit with strucleak plugin enabled makes the stack
> > >frame size to grow.
> > >
> > >lib/fortify_kunit.c:140:1: error: the frame size of 2368 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]

(It seems like lkml never got this email? Or at least I didn't find it
on lore, so "b4" was unhappy...)

> > Under what config
> 
> I saw this with a arm64 allmodconfig build [1],
> 
> > and compiler version do you see these warnings?
> 
> Toolchain
> aarch64-linux-gnu-gcc (Debian 11.3.0-6) 11.3.0

Thanks! I've applied this to my tree.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202212010906.0CE64E9CD%40keescook.
