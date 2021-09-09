Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB5XU5CEQMGQEQGWARKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E85405B2D
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 18:46:46 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id q15-20020a17090622cf00b005c42d287e6asf1089282eja.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 09:46:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631206006; cv=pass;
        d=google.com; s=arc-20160816;
        b=PrIXQHNeLlLYhbHNQ651cfWkFykhHgbcTUOR5HRvQ4pv0rADjDjZz/P3vFVHUq2fwr
         g10OrfIEosJqtqJsfPgYshqpzcV24IdY5l9QuvPjDIoRqvhhe1zZu2NJbxEfOIF0h2j4
         C72R0S/wereseXwME3rWnza1CtJGiPieX3Y6YZaZJhzW7QxhW5RIJc2L09EkULi9JTuT
         YKsDOs6m7IYyt4lWDxxael2snS3evAD7wj6C5nZM1DkMNVCizkZqFG994ns7tvpoE7kn
         boBP+B7A7SMrm5x/dZ8stPrAkzE16QFOUqqUng+HlsvfVNHT3dMdPtMk1FpfpOhEfMyP
         QpBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=IT1DAWEM4WIiM8x+zGPg0aBdRpMe7uHnNo/7Ju2xrWs=;
        b=oR8zPlHUq984Zi9W1G5GjUP+kaTwl6vMKowVMGw72004rWDI0h3HP3/F14wsGwCKOG
         pntV1YoXWjYSwG/xCNQHEPY6LJKyUvpiZcjCkAhVCaPaaBvPLT1lmnr4bYA7PNgqBBg2
         uaWoxIqqNAU9E/zG7eKEP4UYB+ZFlRkhSKqew8nQePyNk0fALWyYw4Wg1tByJDyO5akx
         j6IMCDkla/CICgP+JjF2m73fi8SI1O7xvRyy1v7QcJse5dxOqHE/j/g0XKpgpC8lfZ20
         zoJHgmqy/OzVxdeAHMZSXh8yODEnGMWPGoZ8Wjl+oDJSaa/T5HUkrUtwEEWV9nZr/Ix2
         QIFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=c3sO1BQB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IT1DAWEM4WIiM8x+zGPg0aBdRpMe7uHnNo/7Ju2xrWs=;
        b=csUMhgK023gEojYMupd6nJPYJdB+UCbyTLvb19GAWc6YZTwrw8UH0uTmx2Pp5hKl/f
         7YVHdyJhNFji6u9mIKBCnIbm+1SRXkOHSben+87A6nAxM2rjj32kHixJ3gmn9ubakNtp
         TLnN4/VzabNA7Moz6gIz+8SqQA5yliIk0YiLYdYs4JWmUwMECuVpZ0pkFDMWRzAMDwX0
         HRcTZzwL1MQhx/YsHgNW6L38kVpio83AZHlfewEONRPgqa8XS9ItPF4UcrltEOHrBVA1
         KBJ9unNi3KGj0HY9iAF7FHjpiSUh/eOi/LUudFrG+qruu3vu9PiGyeM4HNZ9Cuu/5pF3
         oOYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IT1DAWEM4WIiM8x+zGPg0aBdRpMe7uHnNo/7Ju2xrWs=;
        b=FD9/0pHhT5ukipl6o6GWAshvwviTIgXXUWXwwFqjOzDgczKYTUFWOiEDRQ6sB1dxJu
         6iLLPH3zi81y0wx4i6fiWmfEqA8YWRFd+oI4+VaOo+74pH4hd/DJppyBuMSt7fqaBi0A
         NVbR3h30T48wWmfy+bpiQ3BMsAdnLP0VBLpvWvB3LPV2q7cqVGQShTu0VOKqUlZwO0Qe
         MW5D7mndjakB/iqVpL6/kRpviZCxrOm86sqrn8qGGoXhGB4a5f0RNiMrrt03f1KBOyUD
         jxM7QKyPnXUm1qN8aUkHBPylWiC1JA78sHJoD2iWn+cs8hOwyndgfESEjVNDsk7SDl/j
         glfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PMeYCmzReRTU9Z8IkK1B4t8BSUWTC0SFsuK0M2bqIeaCG8nH+
	thPGKXDi8KDrjso6SEAntU8=
X-Google-Smtp-Source: ABdhPJw1VRlCot18FzyUBt7ewZFduBK78pRZb0lfYDuY88ttHOB5NkCBFD3ZXtx2pQiUKSWQUrVKyQ==
X-Received: by 2002:a17:906:e51:: with SMTP id q17mr4552717eji.76.1631206006395;
        Thu, 09 Sep 2021 09:46:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bb62:: with SMTP id y89ls2723598ede.2.gmail; Thu, 09 Sep
 2021 09:46:45 -0700 (PDT)
X-Received: by 2002:a50:fe8b:: with SMTP id d11mr4087422edt.330.1631206005408;
        Thu, 09 Sep 2021 09:46:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631206005; cv=none;
        d=google.com; s=arc-20160816;
        b=zLaKJ4HwwL0r602j5z9cnYJWzkYRKrawb128bsY1BQqQMqxPRk4jmfU8WHBW0LY4m8
         fQZrySBisIxG/lPR6Hfj0/aRVSqiYvAAx2xBjxh17VgS1VX88/s+3q2IeI/5edWwSNat
         fRfmBoDs5QwTwOAUX8OqVXqaYl/C1yvF1GvWYgx/RUXoNw+jY8CSOeUdu0IWsOeUWVy/
         Q53/k+bbH48ZbPQ236XEpUfMg2J9dUlA3Ggpiob113UcWsYvHMRKL98SWvQDmw0Kpj2d
         j3LX+BXZIfDSRX45kOS/TnHuCduOOnnang9QagCyylmlkade5r7r0rIKbMJvRQt7DQjs
         la4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6u9UXBJqq0DvpwbwzhX2UgLgOMc73mPLE0iuNkQUyLg=;
        b=mKCnC+agxCjXzEDmPbxBw1gpTrdz/QlmWQMjbyLwwevFOZ6JTxxDI5/KYWDCZ4QADp
         AFjeDaOYu4zFZMNp5YuWYK0EFzyjNf+iCJiy4/TBVuGp/RtV3DLErx/+pnxjtdBiWkpo
         QTPmu8+qjFRpDfmfb3LmZmwDAv+7WzjNEchNWNQ2q9YkZFl8MWiJMxZEpfx53SfZ2kc1
         WeAtmbXI7s5xsamdAmiyaFS8yg+HzC9iQ79caLQCqEnrElofRiyJizmSXm7DE9+MLW8U
         iB62NeMlrH85SjfgPoSuY4uLSz5WFrzNHiYbLVMnTo175uajNwO7gbCgIM8onEYOofxd
         fDCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=c3sO1BQB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id e20si157690eds.4.2021.09.09.09.46.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 09:46:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id f2so4008800ljn.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 09:46:45 -0700 (PDT)
X-Received: by 2002:a2e:7018:: with SMTP id l24mr618661ljc.277.1631206004109;
        Thu, 09 Sep 2021 09:46:44 -0700 (PDT)
Received: from mail-lf1-f49.google.com (mail-lf1-f49.google.com. [209.85.167.49])
        by smtp.gmail.com with ESMTPSA id x17sm250604lfe.204.2021.09.09.09.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 09:46:41 -0700 (PDT)
Received: by mail-lf1-f49.google.com with SMTP id a4so4926209lfg.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 09:46:41 -0700 (PDT)
X-Received: by 2002:a05:6512:1112:: with SMTP id l18mr609222lfg.402.1631206001151;
 Thu, 09 Sep 2021 09:46:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
In-Reply-To: <YTmidYBdchAv/vpS@infradead.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 9 Sep 2021 09:46:25 -0700
X-Gmail-Original-Message-ID: <CAHk-=whsicuPaicXWh5je6unQYRKwoazuNLzB-9PRXpSY3CZ-g@mail.gmail.com>
Message-ID: <CAHk-=whsicuPaicXWh5je6unQYRKwoazuNLzB-9PRXpSY3CZ-g@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Christoph Hellwig <hch@infradead.org>
Cc: Marco Elver <elver@google.com>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx@lists.freedesktop.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=c3sO1BQB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Wed, Sep 8, 2021 at 10:59 PM Christoph Hellwig <hch@infradead.org> wrote:
>
> While we're at it, with -Werror something like this is really futile:

Yeah, I'm thinking we could do

 -Wno-error=cpp

to at least allow the cpp warnings to come through without being fatal.

Because while they can be annoying too, they are most definitely under
our direct control, so..

I didn't actually test that, but I think it should work.

That said, maybe they should just be removed. They might be better off
just as Kconfig rules, rather than as a "hey, you screwed up your
Kconfig" warning after the fact.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhsicuPaicXWh5je6unQYRKwoazuNLzB-9PRXpSY3CZ-g%40mail.gmail.com.
