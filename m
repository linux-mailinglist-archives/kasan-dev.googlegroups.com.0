Return-Path: <kasan-dev+bncBC7M5BFO7YCRBQGJ42EQMGQESUEJFWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC5E404567
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 08:08:01 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id jz9-20020a0562140e6900b0037795ee01absf4156617qvb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Sep 2021 23:08:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631167680; cv=pass;
        d=google.com; s=arc-20160816;
        b=Np75Z2+r/+BdVvsUSRc4msYZARoJiaAshMh8pRSkI9yx02VepoWO8r4DaKafeH9RJh
         cJOGpVIrAxXV2DLgwVEBBGeS3m8EUN/AcTYqmO/hYBckVCD077JN32Dbvel+9wKRB7Pp
         ObqcbWlYN7825gGO1166NM87TD38kXkdVCnF/r5HdjLgXoDMS+R1Y7dcPMPW8tkohNkL
         jW7LaSw2FK2dmx6i8/IOXVHV2ZjWW+Gr+khZSF5AuTI+MxU5qa3nI0xcqhOeetwe/YVk
         6KRcKnhmhGDPocB38BnsoxYFdyQW7pUVdEdzM2YOkEWAeuuD8ep7ayLmQpQXCKyo58R8
         CY3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=5IOdNA4sqqIXlIBsX0TR6wokC46QxHg+sr58yC83r9Y=;
        b=ah53Qt7E4ZT8p0uNeggpurPt0XOte8Y43c+yJnnK/O4FI8l1yYbV7ezuGfv5AGSzw6
         3bylx16eZZdtWIWskqIT+6sH0j5rW/y9hOm+1sKZtnBLB38eKNTmyvkiA/n3TCWU/1Qq
         NcTylfgE/Tvr9mdacoCeTy2FsI7TfOlL0O2LVmqfB02bdnPtx6eRfxjKg2IfDOm56Nvn
         fYoUs6utXzu/w9GTOunAKpG61nDfIUySuI8wsAUwer25GfL9kU6uP6SxtWbROIkNICns
         TKqJ3rv9H+jKAnLe56MOspiTJiadQXH/eqh/z5E54VodXPfsshrB8syXxA3JjJp3HoQT
         Qxnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Uby1UFSq;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5IOdNA4sqqIXlIBsX0TR6wokC46QxHg+sr58yC83r9Y=;
        b=IRLO5rmlPElSHwQTKNNGYgFZ0lm1wIGGDeCarcUwU03S0oJ8qb/4bOtMoYJksqlDCS
         8qhc+pgpi8V5NpQm0aKABCvITuE49+KSjtQMiu5s2UxMEI5ARyricMMkqb1RwZDQ1hJ9
         i8C6uW3fU47o+HH0c8hx/+IyCZYEUDQ8F8fA7tTx0TDRkYYRVWLbMXoLOOt7wfg77Qeb
         m63UvwFRaBu1hYarWZXKHMzpFc8xsAfnMTemvD4dJx9eaZSvgeVoSLAa9cZ0XeGCMf1k
         hb/lPpQIpCrbX8ouCRknEnzQQZjiX1MEwpF3YL9jluYknkty9SXoNDSM/9bv9qeAO2bv
         NnIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5IOdNA4sqqIXlIBsX0TR6wokC46QxHg+sr58yC83r9Y=;
        b=h0lIvgZOSCJbaYDPoTkN/HD8Fw4Y/K+LZ92O1wycOgjJ8gUZxu0/SKKmcZvAePE/aL
         V/huvXTejYsywoPNG+aZNzcHJM8yFQkSObZUF+XKBf2wH69U5HuZg1WmnmO9uUtyAjoO
         dZeLEFKffiNIp6JhrNMQzImHZM4sXZRTTp7OqupVLhoWc3nt41jDGeb8LJUUbdawWEqB
         AeEihYw7Q3BckAzaAWAAZy2A4e4LuTIP/xoMCpGZAk/gHhI8EqRq71UZGbvBvp/JppU9
         5gCFwHgXfC3ybQtnNqj8tCd8zd89UakUMB9kX2UsUQ1iVCEeoG1LRozy72gjo0tgB/TP
         ZR8A==
X-Gm-Message-State: AOAM5329vTI0KUVs+0diD+AekJjJHaq7gNqUsA72TITCwsy8j+xHlTCn
	YlH/IaR+iisGPjDV41dm83k=
X-Google-Smtp-Source: ABdhPJxqeBbKB7flj6UE5T+KmBFX0D1T/6w5ErBG3ZNYDohfWtQiDelonjuwXR4dVjnZZm/41fFbZw==
X-Received: by 2002:a05:620a:2094:: with SMTP id e20mr1221421qka.171.1631167680758;
        Wed, 08 Sep 2021 23:08:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5016:: with SMTP id jo22ls292114qvb.3.gmail; Wed,
 08 Sep 2021 23:08:00 -0700 (PDT)
X-Received: by 2002:a05:6214:268e:: with SMTP id gm14mr1241116qvb.51.1631167680241;
        Wed, 08 Sep 2021 23:08:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631167680; cv=none;
        d=google.com; s=arc-20160816;
        b=ctwvpacSgoL7zsU7LLMaxbvyaxnadyuOwLh4hR4NwXxILJR2SsApe4jGn8LUfb9DCY
         zxkTnv54POiurKfUhK2BgsGAv4Z2bYTg5fiHShRiaePg0WPUFOwOLxCT9UnXXPAmKmZv
         TXNbEDOs0D1IuYcfUV/p/2P/8oj38xQDvL//nKTEcQCPlkxAhwqVJDJX/sJAfBNcEyM2
         XAFlWDX+bdrs6Y6fUkt4efNgxjKmzdsdwC4xzprY6KRF5RdDukHHN9gHNdXXddwVCxtV
         vfjxlJTm3ozc5O+AY/wcbMWrg5RxkcrhbIAJ1+bn83xWn391D4caYwJ0pBceMi9013m5
         3Zkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=5IZhKmYjWyUNxqS/JWropfkc5GoYoPNRqG2FrnyCWSw=;
        b=LFS9PFfO0x0dElPJL/j0H2kIBrg//1/JFbz1rLfps+2yyaFw83MnsrimH4zNEnTn97
         posfxaXshKpSO2KlzpbIo3vIhRP/Yx2zMaSlmc5nd/J32oZnlC9TVlaxMNxkKBUvsPYY
         1+g6B9RH4JCBvreVzpatLAz8ZMgfR2a2kx1DWbibTrKYuPMohbl4WThHbuCi30fQJSLR
         70XZPYqq2wuAutC19tetrMHiutoMqV38BcGEh4bM27D0s8j2zt+jmcycrIe+X4V+WVES
         FBgzpCdcPsLa1/C509wyEaN2/Ufr8NtI1UFURCre85FSIz3NRGSIr4XRnNvbAUmGFsD9
         8LmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Uby1UFSq;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 6si63519qkh.3.2021.09.08.23.08.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Sep 2021 23:08:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id m7-20020a9d4c87000000b0051875f56b95so1138143otf.6
        for <kasan-dev@googlegroups.com>; Wed, 08 Sep 2021 23:08:00 -0700 (PDT)
X-Received: by 2002:a05:6830:4084:: with SMTP id x4mr1039349ott.280.1631167679964;
        Wed, 08 Sep 2021 23:07:59 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id y7sm180455oov.36.2021.09.08.23.07.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Sep 2021 23:07:59 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Christoph Hellwig <hch@infradead.org>, Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 Christian =?unknown-8bit?B?S8O2bmln?= <christian.koenig@amd.com>,
 "Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx@lists.freedesktop.org
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
 <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
From: Guenter Roeck <linux@roeck-us.net>
Message-ID: <a04c4c37-7151-ef7e-09ce-a61ac7b12106@roeck-us.net>
Date: Wed, 8 Sep 2021 23:07:55 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YTmidYBdchAv/vpS@infradead.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Uby1UFSq;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::336 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On 9/8/21 10:58 PM, Christoph Hellwig wrote:
> On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
>> It'd be good to avoid. It has helped uncover build issues with KASAN in
>> the past. Or at least make it dependent on the problematic architecture.
>> For example if arm is a problem, something like this:
>=20
> I'm also seeing quite a few stack size warnings with KASAN on x86_64
> without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
> few warnings without KASAN, but with KASAN there are a lot more.
> I'll try to find some time to dig into them.
>=20
> While we're at it, with -Werror something like this is really futile:
>=20
> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c: In function =E2=80=98amdgpu_b=
o_support_uswc=E2=80=99:
> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c:493:2: warning: #warning
> Please enable CONFIG_MTRR and CONFIG_X86_PAT for better performance thank=
s to write-combining [-Wcpp
>    493 | #warning Please enable CONFIG_MTRR and CONFIG_X86_PAT for better=
 performance \
>        |  ^~~~~~~
>=20

I have been wondering if all those #warning "errors" should either
be removed or be replaced with "#pragma message".

Guenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a04c4c37-7151-ef7e-09ce-a61ac7b12106%40roeck-us.net.
