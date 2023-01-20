Return-Path: <kasan-dev+bncBD5Z5HO46YDBBJ4QVCPAMGQEPFYMHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id CBE0A6749F6
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 04:19:04 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id br6-20020a05620a460600b007021e1a5c48sf2608354qkb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 19:19:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674184743; cv=pass;
        d=google.com; s=arc-20160816;
        b=NE5rwnYXGqI/9Il5WvwKmf3jIuz7s+oX3D6YddOHE1M2wwroMyVoUhS9UwJTh0RB2R
         1d1+pu5jyBjS806pU6qH/h2OmBWsXRznrRW/sHm6RaAubu1WBb+RfTNaIDP6f++0BoA1
         rW0uZra6frVNwgo4yzI3AnQkvUKk4P+HueKeB1Rf6nxKbLZpoaS/f/dO6kOSWxzhqKr2
         +rwJd+YWoWkFVEfv4sIlI9eICuNx615iN4O5AXdp3+Zg/unDl+Dtm2aXgtFJCUuyvaiJ
         WLUWdhyn9qIbclpYonwW+uNN7AMFYjyRw8gQRDMsc3MdrmfVEYcVIZ1/VbwPLPMJHVOr
         Zklw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=w9ATUZUsy9IElXXW1bCVeBExuJ25Io1RkMeelBGX/6E=;
        b=rLkxo24Aj3s7bMccYgZr0jZcrNxpGt0og0+as5zzxTRxkGX3CR7c1sjXtDCxbNgwpb
         cnht7QSA8CXk15zGkhQJmxYBsr2cNxHAFeLJ/jcWtzl3690xUMHQHyjvgIB0WvyGQFpy
         69pkuBWLW2jt6Z/GVFCgP0xobzyQSjlpQp71O99d7u/lMUO7CjTWqUCTVsIlGRlEruGz
         Qd4LVUSPZV/neKEHawEYEhsv/oiTmyp3Od+J5KD6akZwm8iOuiCAWAISI4QWfX+RLZyZ
         tfGn8DHcMFyGAc/D63nuawiknwHMljh0kdfMRJ876Hqxn4nUk+/y7h1aJ4GHKVi29PfI
         qT2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@landley-net.20210112.gappssmtp.com header.s=20210112 header.b=195AXt9o;
       spf=neutral (google.com: 2607:f8b0:4864:20::333 is neither permitted nor denied by best guess record for domain of rob@landley.net) smtp.mailfrom=rob@landley.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w9ATUZUsy9IElXXW1bCVeBExuJ25Io1RkMeelBGX/6E=;
        b=Hv3TOBoOJBjHuhs87ZWg0Ekx4KU8FCbZ11TS6+k1LKIjJY8IzmWtSs6nHPgq1KJM3e
         3qI1zFYeSBQeT09PtgQzGhC5xqmaRcPmMv6quLOOxad8vAoTgTYpt5CTm+/KDr5o4Qsl
         IPDAgRQgQutEdu68S/1jCJmYWuQbuZG4Eh8O45cT6NW6/bYFRfK81LZZQEEUOOl0TaZ9
         JuEoQLWuJt670eOT305uKrvhAqsoDUwFt7m0o66Tq+66zQPlvId1H9k9oaR9LLHvZsKc
         SLH81c8k5kag9ZiR9Ca+rReRTUzVJU29bRC76rDEt74W2WHq06NMj+2KjZtpzkSyeaa9
         AhUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w9ATUZUsy9IElXXW1bCVeBExuJ25Io1RkMeelBGX/6E=;
        b=IJ+gkFVKrFy77eSM6iiz5OnUegpRwELSjLqYcMCWpTjFi7PYQr0lECqIq3GhiVn8LC
         h6gc02UubATriSEkSS8dGNJ1puxavuAX+MClBgq37zamX0U9iojLdSyYReSCxuanNy8M
         URLzARCOOJeiWIM04xdXpFUUNaRUkf2Y7KzbG035i5R4FionP9TXyU+J0sJkeuJ9eBzj
         5f7JwwQXcVfWYe50Q+zSDhDrPIpus90bG+p5iHicSQYdStp7Wq+2vKCW+MbSdXVWXjSS
         5dgipzC/O9x41quoQP1THf8CInPztgih3H2/sRarA6YoT83HjlXoG9hkXtGMD2wcfVar
         QWmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpnP+JjbLjmAkoDhcjLcFSrqbDV6yYTYi3Q8WasTOiGPvKV1/Al
	qXGk9WazSuqcGI+Q14Plr70=
X-Google-Smtp-Source: AMrXdXtRaLmz1h7xWGAODfmBK8otMW8ydH4/kKvmzT1E6wEVIQtYhX9MZL90ki7opayxgVuCVQnq0Q==
X-Received: by 2002:a05:6214:d05:b0:534:ef2d:eefa with SMTP id 5-20020a0562140d0500b00534ef2deefamr836646qvh.125.1674184743637;
        Thu, 19 Jan 2023 19:19:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8e88:0:b0:531:bf3a:f1dd with SMTP id x8-20020a0c8e88000000b00531bf3af1ddls1894270qvb.1.-pod-prod-gmail;
 Thu, 19 Jan 2023 19:19:03 -0800 (PST)
X-Received: by 2002:ad4:5a13:0:b0:531:9a05:415 with SMTP id ei19-20020ad45a13000000b005319a050415mr16292201qvb.6.1674184743038;
        Thu, 19 Jan 2023 19:19:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674184743; cv=none;
        d=google.com; s=arc-20160816;
        b=k0wN2iybfFXAWaIO8eb+Bw3wFweYELReQBUsVbRFcFXL3sKZzV4ri9+ai6RTc+zbsf
         wL9ywNEyHFqiO0SdDMFAhT0WCSahq4UY4M5H8hx6rIliMWEflOewi61T3EOwyxA/g2hl
         qKf6rcGD2YuX3XlaiEF7aGAHc1zHftU/sAGCtMWAmcfL+dYiMWjlDIZ1vq7MKdgNuYMr
         VXeoSI4bqr3+uOw3PT3wVVyPhi5uD277akuACzAKXq3a0lB0Zm+AEY02ZskD/kOYW0oN
         +0N3QeHl8fMkDYQAMOMBkWBRLTJhgkuRGZGpq4hLnIeaduv1G9VuFwJeV5uT9Bj2NbRl
         z2SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=WxJtcfmjg8bDlWo77QXfqDNdo8CBClhx9W/RQtlqbwY=;
        b=EUJYcoyPh296tG0IC/rltGd8yphHtOJKHKEcH4h6X0DoGjCEwgda3Z8y7y/ENa7Zcp
         Z+sr1zKZf0c9oZSvyseJQAeuI358+5JRv831mdxAufKj4j+k362zxOUqQDocny7kWWaE
         rErFUGsabPzRO+LxOCybYaIycUZpw7eNp9AD1Vb/4BQIyWu1KdpUXzoSLtu6nnDsCC9A
         AGVPzZCYy0DzWjtTNECHjxtM4sVscT7bgk4lvHzMDugjDS1hhnn4LF52T7IIyf+bWKdy
         5CP0fbGLj8Tvbkzqu3lAPLxZSJzG7B8CC7SYqwjmqtlvZjqbar/WC2k3ZSBVzcSD7hU3
         tlOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@landley-net.20210112.gappssmtp.com header.s=20210112 header.b=195AXt9o;
       spf=neutral (google.com: 2607:f8b0:4864:20::333 is neither permitted nor denied by best guess record for domain of rob@landley.net) smtp.mailfrom=rob@landley.net
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id j14-20020a05620a146e00b007066299ced4si1057158qkl.5.2023.01.19.19.19.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 19:19:02 -0800 (PST)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::333 is neither permitted nor denied by best guess record for domain of rob@landley.net) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id f5-20020a9d5f05000000b00684c0c2eb3fso2386198oti.10
        for <kasan-dev@googlegroups.com>; Thu, 19 Jan 2023 19:19:02 -0800 (PST)
X-Received: by 2002:a9d:704f:0:b0:685:579f:918e with SMTP id x15-20020a9d704f000000b00685579f918emr6930248otj.0.1674184742349;
        Thu, 19 Jan 2023 19:19:02 -0800 (PST)
Received: from ?IPV6:2607:fb90:f20b:1885:28a8:1eff:fe1b:3320? ([2607:fb90:f20b:1885:28a8:1eff:fe1b:3320])
        by smtp.gmail.com with ESMTPSA id m6-20020a9d73c6000000b006860be3a43fsm7631822otk.14.2023.01.19.19.19.01
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 19:19:01 -0800 (PST)
Message-ID: <0f51dac4-836b-0ff2-38c6-5521745c1c88@landley.net>
Date: Thu, 19 Jan 2023 21:31:21 -0600
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Content-Language: en-US
To: "Michael.Karcher" <Michael.Karcher@fu-berlin.de>,
 John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
 Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org,
 Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
 Arnd Bergmann <arnd@arndb.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
 <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
 <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
From: Rob Landley <rob@landley.net>
In-Reply-To: <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rob@landley.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@landley-net.20210112.gappssmtp.com header.s=20210112
 header.b=195AXt9o;       spf=neutral (google.com: 2607:f8b0:4864:20::333 is
 neither permitted nor denied by best guess record for domain of
 rob@landley.net) smtp.mailfrom=rob@landley.net
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



On 1/19/23 16:11, Michael.Karcher wrote:
> Isn't this supposed to be caught by this check:
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 a, __same_type(a, NUL=
L)
>>>>
>>>> ?
>>>
>>> Yeah, but gcc thinks it is smarter than us...
>>> Probably it drops the test, assuming UB cannot happen.
>> Hmm, sounds like a GGC bug to me then. Not sure how to fix this then.
>=20
>=20
> I don't see a clear bug at this point. We are talking about the C express=
ion
>=20
>  =C2=A0 __same_type((void*)0, (void*)0)? 0 : sizeof((void*)0)/sizeof(*((v=
oid*0))

*(void*) is type "void" which does not have a size.

The problem is gcc "optimizing out" an earlier type check, the same way it
"optimizes out" checks for signed integer math overflowing, or "optimizes o=
ut" a
comparison to pointers from two different local variables from different
function calls trying to calculate the amount of stack used, or "optimizes =
out"
using char *x =3D (char *)1; as a flag value and then doing "if (!(x-1)) be=
cause
it can "never happen"...
> I suggest to file a bug against gcc complaining about a "spurious=20
> warning", and using "-Werror -Wno-error-sizeof-pointer-div" until gcc is=
=20
> adapted to not emit the warning about the pointer division if the result=
=20
> is not used.

Remember when gcc got rewritten in c++ starting in 2007?

Historically the main marketing push of C++ was that it contains the whole =
of C
and therefore MUST be just as good a language, the same way a mud pie conta=
ins
an entire glass of water and therefore MUST be just as good a beverage. Any=
thing
C can do that C++ _can't_ do is seen as an existential threat by C++ develo=
pers.
They've worked dilligently to "fix" C not being a giant pile of "undefined
behavior" the way C++ is for 15 years now.

I have... opinions on this.

> Regards,
>  =C2=A0 Michael Karcher

Rob

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0f51dac4-836b-0ff2-38c6-5521745c1c88%40landley.net.
