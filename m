Return-Path: <kasan-dev+bncBC7M5BFO7YCRB4GC5CEQMGQE5VRQKXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C612E4059D4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 17:00:01 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id p10-20020a92d28a000000b0022b5f9140f7sf2286396ilp.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 08:00:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631199600; cv=pass;
        d=google.com; s=arc-20160816;
        b=gfBT9Zkagahm7X7TXQZ3EEPl1JR87MAe2jOdpRipX2weJrxWyyhwfqvzpT3Zp7wrQh
         IBrKOujpOumwYKkbCJ7/Rp1bcdO3wht6MkDMVhC4+VLyFcaA7Jp1M0lInu4OUGHDAwZm
         diICtPZ5xhGea4xM5/cfXy5y+ukK5lLRrh862U0R29Vf6lp9TJxkzWBlkk7zqkio0YsJ
         HdfMmwM6R9aDUO/MUdJ0UWK9DeK0OtNAEM4IH5w8eUb+CEMM3V5a9SF2O0wMQFTb6oSY
         Q43So2EEQuCJhEwpwnK2dYWmfs/Gv5UnSA9KsYcqe/dXIdOJ1q/E8fiB9P/dDVsxh5eV
         cHTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=rAk2fCweDlylNMdnGipjV0DhSoBCsc7RDCESmV2kYvQ=;
        b=cRZLpDyOK+fBHUAUP7vMPHNwTInMqPFZZsyupOPrMYlq9rWFRtb6Liirk6q+3g3cT/
         Bj0e/WG/fHYUAAa/iSHwyNSId9sWHOrAGuvJk0kcshuFDrAZWRvEm8NL/e4JJbPIE5ir
         0hxq868LsXkiSMZ4Qjra0JxaSAFQTxnMrqVykwjdDwVZ2LFc0++3jWCppYZRVW86TQw5
         KeB6qEVvrxy/bggdF7rMjOgF/5XHKO6juzG8WZ7kGZ9xwTgMUJnqJhgOBSKg5zhrwYBB
         +6+OD9WtjjpTCgEIi8eYE8fAexPOG8X87uxoCtxKowHC5+DyZ5nw6Dsr9oPxpmvJvAKU
         dv0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jDgnkGSK;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rAk2fCweDlylNMdnGipjV0DhSoBCsc7RDCESmV2kYvQ=;
        b=RnquL4lnC8dIzaQySeb/ZNKLmJxTDAcC7ylbvLp6v3mQOWqoF49PDgRqmxYn+tvy/m
         x2T1J/rggj88dqHG3YjwbJGXjEmHLkMozEJrzysZs7BRRfm7y+bPcJOPHgQsjtgDnrtG
         3tGo5pfWBViCUszh6HetrifY8rOrH2QW3kipghYma9OE6pBIO8PxgFcnfd6sCLO0JPWg
         O8dHL+r5ZOGGVuAI5BJ3xbvrxoaekga1QHQ5QrWNOfpVZ2nGKh+XfiSPi2RWtSJ0Ugqo
         +xE5tqf2x9viiiMgiFhe+gYAnMwghohbPkHncKdd1YCbOH4aQJvRefrn27GJ4dQXGcmA
         4hcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rAk2fCweDlylNMdnGipjV0DhSoBCsc7RDCESmV2kYvQ=;
        b=Pbq9X2rWV8Xcv/u91dCOgTiXc501WCKw78mZWzjmz23lmLTJPqqNIne8C1vXTPFS/H
         SyW1IAc6T8jmBJBYHT4B0Pw/0Fv3UwQzogUiDKUAPoWxjTRgLIms3j4rmrlsQRjd3rLM
         blfOBrjegqd/u2xbDXauHUOphCufX2NdFFduKOTL5782gJlFD2iZNpD4jzSyRUQlLjWB
         Fse3HDVV4rOKN3DGNiwbwuHelbMZ7YSpzcsbYoLmU0h969tdkPq6I0jvIVHN2bc1NGWI
         xkUTjEJHVLi10WX2ZDsty4gssLEPoe/uecSLAexhp4uaDpGkpnbEu6uMuJrVRnmR1eeL
         QfHg==
X-Gm-Message-State: AOAM532OhFgc2yGYXQXCSm7MdInXhSAK3+dJY3cySZoSdUCpmzbptIq0
	HiJS8Qx7/eOe1+wHh+UqvcI=
X-Google-Smtp-Source: ABdhPJwc5qtTqkGe2rW7LAmo84QBJkQOKLfmU38GfhXgKDPhCBcijiR9HreE03qL7acVspUmaXH1Eg==
X-Received: by 2002:a02:c64a:: with SMTP id k10mr239422jan.112.1631199600708;
        Thu, 09 Sep 2021 08:00:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:901:: with SMTP id t1ls362399ioi.0.gmail; Thu, 09 Sep
 2021 08:00:00 -0700 (PDT)
X-Received: by 2002:a5e:da01:: with SMTP id x1mr3175971ioj.43.1631199600250;
        Thu, 09 Sep 2021 08:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631199600; cv=none;
        d=google.com; s=arc-20160816;
        b=HugFIOFUxWgqGEC4S7TPsiWd/t3Ns0LNt2WeczvPvcZcYPY5v/kj6EYp7vWo5fNrCO
         Em/AA6gaYtqr1tZv48hcxc0YRcBR2bFbTdfkq/xlONDe61xw34uw3YQ2MJoTIUTH9SrG
         2I9M8cPrwa6AMWaDjm2fD13PYQ1qZKv/UMa8bUAiEg4xdO0tIsFFsXjqb+fKy80RI+sN
         4WFrP4RIHXsR1wqE5sZofstaQr2OzUgjFHbWamNZf0yT20rYyUUIVRHc8GfCUay+FgAc
         4sYOLJ73KCmnSePIUO7xlSEAN19i4I4I4UppaED7r5SL0cFEXnZZtdHDj97Lkwcwo4Oj
         4/SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=cdZ5UReirNbJCz4qtRz9jPX8lIr89503B9bA6FIRuzQ=;
        b=l1qWQzwjFOkUzK5Owj91Cx8jjhOA7UQF4PbWu6e8woKHlblA/4TyszVk1P9YGGPpi7
         A64cVcqxH6NVQR6tkFZLin/OvtBOzMo4TyZz6FiLPAcu9bV6c0H+ZufhKAK739gLfbz9
         SO9MK4IFswH7Ga+bcBo5xnEG0KE8rvD7iDi0vvidW8M4fmWbjSBwwpFwoVf/D2zmdmVI
         yuuzpcAMUX5EsVTwXwT5PTeCiXDoN5y4wVU/bWuEhtKHCwKWJibXCLt/8OHCZaIt38AP
         9omUtdxO0NrxqEQguX/Xsh/nKg12Vd7RQS8J0Hp0GexCvx30ImU8fVnmFt81Nz8SXL2P
         UTqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jDgnkGSK;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id y129si157675iof.3.2021.09.09.08.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 08:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id v2so2827275oie.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 08:00:00 -0700 (PDT)
X-Received: by 2002:aca:1709:: with SMTP id j9mr233084oii.120.1631199599971;
        Thu, 09 Sep 2021 07:59:59 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id l44sm475368otv.81.2021.09.09.07.59.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 07:59:59 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: =?UTF-8?Q?Christian_K=c3=b6nig?= <christian.koenig@amd.com>,
 Christoph Hellwig <hch@infradead.org>, Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 "Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx@lists.freedesktop.org
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
 <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
 <a04c4c37-7151-ef7e-09ce-a61ac7b12106@roeck-us.net>
 <78aeab09-de88-966f-9f03-a2d56a0a6064@amd.com>
From: Guenter Roeck <linux@roeck-us.net>
Message-ID: <80a56a5a-5351-1897-b87e-3c3cd84bb13c@roeck-us.net>
Date: Thu, 9 Sep 2021 07:59:56 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <78aeab09-de88-966f-9f03-a2d56a0a6064@amd.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jDgnkGSK;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::230 as
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

On 9/9/21 12:30 AM, Christian K=C3=B6nig wrote:
> Am 09.09.21 um 08:07 schrieb Guenter Roeck:
>> On 9/8/21 10:58 PM, Christoph Hellwig wrote:
>>> On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
>>>> It'd be good to avoid. It has helped uncover build issues with KASAN i=
n
>>>> the past. Or at least make it dependent on the problematic architectur=
e.
>>>> For example if arm is a problem, something like this:
>>>
>>> I'm also seeing quite a few stack size warnings with KASAN on x86_64
>>> without COMPILT_TEST using gcc 10.2.1 from Debian.=C2=A0 In fact there =
are a
>>> few warnings without KASAN, but with KASAN there are a lot more.
>>> I'll try to find some time to dig into them.
>>>
>>> While we're at it, with -Werror something like this is really futile:
>>>
>>> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c: In function =E2=80=98amdgpu=
_bo_support_uswc=E2=80=99:
>>> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c:493:2: warning: #warning
>>> Please enable CONFIG_MTRR and CONFIG_X86_PAT for better performance tha=
nks to write-combining [-Wcpp
>>> =C2=A0=C2=A0 493 | #warning Please enable CONFIG_MTRR and CONFIG_X86_PA=
T for better performance \
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 ^~~~~~~
>=20
> Ah, yes good point!
>=20
>>
>> I have been wondering if all those #warning "errors" should either
>> be removed or be replaced with "#pragma message".
>=20
> Well we started to add those warnings because people compiled their kerne=
l with CONFIG_MTRR and CONFIG_X86_PAT and was then wondering why the perfor=
mance of the display driver was so crappy.
>=20
> When those warning now generate an error which you have to disable explic=
itly then that might not be bad at all.
>=20
> It at least points people to this setting and makes it really clear that =
they are doing something very unusual and need to keep in mind that it migh=
t not have the desired result.
>=20

That specific warning is surrounded with "#ifndef CONFIG_COMPILE_TEST"
so it doesn't really matter because it doesn't cause test build failures.
Of course, we could do the same for any #warning which does now
cause a test build failure.

Guenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/80a56a5a-5351-1897-b87e-3c3cd84bb13c%40roeck-us.net.
