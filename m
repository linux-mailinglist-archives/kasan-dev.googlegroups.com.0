Return-Path: <kasan-dev+bncBCF5XGNWYQBRB74HV7UAKGQEK7UGRPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6A2A4D555
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2019 19:36:00 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id h203sf1555642ywb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2019 10:36:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561052159; cv=pass;
        d=google.com; s=arc-20160816;
        b=PAvOfnyjXgqpDy1H4mCCLWKBuuFee4m9oFjn8joeVr8wwPmSYO1Lobk210MqfjYl+0
         Dcw/3aiXJUxjW2h2xiNCwk96k4/5Guu/Zgd8OUP3FwYmjnrd49SJe3c2LfnWzjuUeZp3
         uY/ceFQOAmNSfsV5nzwKX+vK0qXw6E6WmN51t8aLolE02DyScDQ3aVMG4znCrJbk+N8p
         CTHG8XrSzVLEo+EzTG6T1jCOO4fjEDHf8bJmBG8Xt/Cg+p9kVBRdiVWws5RHWg/zBtlT
         y1e5l15XEcWulvc+tBam6Wlwy6HC7UtTszXmw7X48g211IfgbA+3H0VUM7e3vWYhhZSc
         zNOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xqDb27WwRZLGY1LWqJ4J6E6XBc5qPNlas1Th5ptvDXI=;
        b=Q/ZsgwT8taMrTsMYO4fuVIbqFhPgUJLGTDY0X6u6WtCExYksZ2R8ub3h6ZvKj4wKMc
         DKHfeYpUQfux5Ri8O8s6vbD24/xR9dTRteSbYxZ4Yt3Qd1cxWN7yGKcb9pkWAvOevouN
         cql32w7tmg2aZJCYuZ3wf/w3DmXsfDZo1DMh2ukIOudjzL/lhb2facR8OsL296ZqW9Qm
         Xw2oIwG8/NKZcc9CUJmIIZ0CLLsDYi33B+HHVXuQ/C6TEtJ/8+Q+KxP64HSUq6su2GlO
         FRSdb/bUWOvteNsndEPpxOdsNixHI14x0WqGvQWNQmfjmfKf4xekPTLhx8CX+vpGmtoJ
         KHbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NUMqYmFw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xqDb27WwRZLGY1LWqJ4J6E6XBc5qPNlas1Th5ptvDXI=;
        b=MAO8/PqNvLniq+S+aMPeXhnLFUjPF12OwBiv7L2/s0eg7uBHTDJZxjgCB6gib9W4FO
         AtK2gaDyZmVRCo7KFN5zOni7DyWpNCeWXqmnMA1usHjH+2Rm18khow9Oh+VrPbzlkH7u
         R+cbQDUJJ1wOjgIeh3UAKjVkZMK/GfhKzxVhz8GigB531O/CQfGVvR1YVnouZ+zG7QwY
         ZAsp1UEZ15DdYziIjvuio2HxJ947S8b3R3NErm/p81Jxs123qK0SN2GTxOXpzQ5j6GF2
         AuIEwmR29IILsgi0JmRf+ioOnpwOpKvvrRjgZbKqPqJqawVIB9pKuoqub2/A5Vv3hcB7
         N+BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xqDb27WwRZLGY1LWqJ4J6E6XBc5qPNlas1Th5ptvDXI=;
        b=FNBZKFuKUYuYUc/TzGRd6TjyMzFFIVSLJ83RkCdwHuCdBg37N0UFw/QZJAc4QNakvF
         Okd0Nx8n7N0wA7itkipg6k1dx+tJ5dVGP66l+bPHV6qMsWJbhhuZ/AjkwfsL135wF/7R
         Tjx4FtXDSu4Ldxg9n8YH7/hLpZ2RZaazTxc0B457s/hjq3rRv5wVkDE37jTiIkk4zILK
         B4NUX7WruTa8mTIEIIDjaHgi1KIJdt7A7uWT/ptlNVkqPdHvzPXIzn2UmWhKgG9o7nuE
         424U9OXzH88tPajY0vHQIOLiNt9N7r2OZjfucnYOKlYenWqHAucaLFt/iXXV/n7FbuSU
         aHuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXwmnQDwoh838TvGRHfZWlWbMjULqojJ71cAF2czuU0tsjgnrLo
	n1+ULS8ypkwjXleS2TdPkJM=
X-Google-Smtp-Source: APXvYqzqcnaPjc4k9kEGhsVHaJoo0LL2vHkrYDhZCcigj+8DazzSAvX+QlRJlnVrgsJdBrf5vBJyCA==
X-Received: by 2002:a81:1f44:: with SMTP id f65mr50271162ywf.217.1561052159493;
        Thu, 20 Jun 2019 10:35:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5c4:: with SMTP id 187ls884134ybf.7.gmail; Thu, 20 Jun
 2019 10:35:59 -0700 (PDT)
X-Received: by 2002:a25:3b50:: with SMTP id i77mr1207115yba.500.1561052159197;
        Thu, 20 Jun 2019 10:35:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561052159; cv=none;
        d=google.com; s=arc-20160816;
        b=sHY5bjMPG9Gj7mXsHBdbupFkA1BKnSlKU1XmmkACx1pKWINR3wdmvcAPWxeB/Ntk6N
         kcNusFb4RBR99c2xxxkf3lrXQvmhEny7NSOj+Km6RXFaJWAtQppc6tnspD5PYmTbDuwF
         5np+7Bc3WiS6paPFxyOzxkoUpFS2xr7Swkb5y1j6Abo3eYToqX4f13uR/UdtCUrA0hT0
         s6UfiG/IbB/LYo17Y0tKlt6O5lXimheAF5LoBrD/ZZnPuUHTUg1MFYzEDVf7cOhNwrqS
         58+2vj+02Bn4+EWXz7OrATmsc+yjcJjD05UUOFOmH79hiRg5ZN6y3uXbyDvxCjIXou7T
         sCcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Y//CKAUCmu4Z+CNgNicaVzKkv82IaCbCxrJa7F0wZn4=;
        b=l8imj6uNXgfcbaVJsIu+dCJ2qtCKv5I+2BZtAh+i177FoCZge5O25gEFopVn6MW/0m
         nZDRkZ78G2tnzwI1Y90sn5/g5JVqaQxD5z3kTIHjuSxiehSa956JducegAn9TM7BNTZI
         ZANHFiXUV/4FZHutQHgO5CJhxGmjyhvWHugUOcT5wOaAL/oVe567RS8JGPDIxg+1wxOu
         h/wT+ZKjI9JQLVlnKNoDDcIUXO4JGernfLlB2T8ygHuL9uqgUhTmoPCfyoH/qLQvp5Gb
         4nEdCtms2at3Lcu69FFXn+oy/H3d/edt9E009nEbFwq27xOaPXxa1IhwrrPsXJfpZsAh
         9K9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NUMqYmFw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s12si9428ywg.0.2019.06.20.10.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2019 10:35:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id r7so2067856pfl.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2019 10:35:59 -0700 (PDT)
X-Received: by 2002:aa7:8083:: with SMTP id v3mr54261815pff.69.1561052158492;
        Thu, 20 Jun 2019 10:35:58 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 128sm89983pfd.66.2019.06.20.10.35.57
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 20 Jun 2019 10:35:57 -0700 (PDT)
Date: Thu, 20 Jun 2019 10:35:56 -0700
From: Kees Cook <keescook@chromium.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Alexander Popov <alex.popov@linux.com>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with
 KASAN_STACK
Message-ID: <201906201034.9E44D8A2A8@keescook>
References: <20190618094731.3677294-1-arnd@arndb.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190618094731.3677294-1-arnd@arndb.de>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=NUMqYmFw;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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

On Tue, Jun 18, 2019 at 11:47:13AM +0200, Arnd Bergmann wrote:
> The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> leads to much larger kernel stack usage, as seen from the warnings
> about functions that now exceed the 2048 byte limit:

Is the preference that this go into v5.2 (there's not much time left),
or should this be v5.3? (You didn't mark it as Cc: stable?)

> one. I picked the dependency in GCC_PLUGIN_STRUCTLEAK_BYREF_ALL, as
> this option is designed to make uninitialized stack usage less harmful
> when enabled on its own, but it also prevents KASAN from detecting those
> cases in which it was in fact needed.

Right -- there's not much sense in both being enabled. I'd agree with
this rationale.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201906201034.9E44D8A2A8%40keescook.
For more options, visit https://groups.google.com/d/optout.
