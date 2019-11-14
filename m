Return-Path: <kasan-dev+bncBCH67JWTV4DBBSVZW7XAKGQEPZC6ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93773FD13F
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 00:01:30 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id f16sf4666950wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 15:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573772490; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q/VMD1b6WSvME/p+6XzkbbkDEG4b1JYxvVTkwLTw1NkeG6CPnAYzj44ReyKtbwQ9ME
         cRNOKcVJv4+a4bekLaq2z0C8qOiwKBwlAbsiwsIbgbxSC53OsH3NKlmjBoWqkXkEM0Ar
         FhxS7daP+1zIJ0IpJI+mtMmNwm9zIOagwhhbEav+ejo1WE8VNrNg0R4rxTU/e0WGCqva
         LKG6vCnXpveNQX5XEzwK7oNFlfH01jlkm5TRldwrCAtWYyFBDfnk/Nz2Qr3AJP7uoZCm
         Z9WLyo0CYaMvkklkMJEsPpa3u53w37vWXfMdgTW/wIWW9X/MTjG3WQoWs3VA2PjeT+9H
         z5fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=qJ2ta/tt6hZvG4QR/2I2DVrkp6TDoXaEacojDD0RZgM=;
        b=fb3hs+aIdJMwJOq4Ys4Q2YnY+WQnp5WwNh7c0ys5U2Mcjrfm3kj4G3IN2NSgDtzbhh
         zn72EvSuxoFY4iaCXGbqLWlohHtCiInJQvGtU6aPUeeOKYuxhulNLU5MB+vlgrVWE8xB
         aP2wqw+W7CDgdwDe5wlpZkiSrdB4QCC/9KUTJ6INoq6ASpnk7ihVMpVgcnfYyRJDlfYu
         WUgUJEXJ9uZ2zIgDeWGt9LYE+7q8dKNWWlQY1FM74GY4jQa2kc4wmlnUGPue3+PZZAm0
         H6i8CTPi7aoSexYMOP26sWTPFng/CYSDS7xnhWavGFSHjD1GldfZwfBrwvddX6LgLKHh
         55fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LUduz5Xw;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJ2ta/tt6hZvG4QR/2I2DVrkp6TDoXaEacojDD0RZgM=;
        b=Hup5PdoNhzDYtV0qbwFUxDbNzbua3iwYmQWRqdcgUfnjHYI9QkA1uQQE+/3HThWzb0
         F0PcmPWxs/OmkU14ygM+PU15Ojb+ahzmlQjVgns7neO4MsD23C3o1mGFKtuEPK8h9FKs
         Aco/QYKu2mU6UxzEDtHtuEmj8dH/H+czvu+mg7EvzfpSW/pYzVyu8+I+275zEK3/0gEX
         9P/c/Ovk9llfYbZVtjrA1Plqqy+pXL8nVfT2oR+YKDzLvglpK//EgvwJaxMdgR14YWIJ
         wbWzojDvZ1Wj26qFaJauq2w7wgJ7yqdLUpW8zvbImAyfrLvE7koCYQx8B+0jztG0vfV3
         DXZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJ2ta/tt6hZvG4QR/2I2DVrkp6TDoXaEacojDD0RZgM=;
        b=NyaZumH2u2GFev7pjTWRuiLZjVZ/B/h8fwN6YWtJbz2ZKM4aoNst05fBoBxe2YwJDX
         skRTsIp2sUE/2V4bnyFpu+VnMWPTWkWbKup8H0OcENmyHiECgbt2VuqIa0I8tN5r9Pzq
         gnHPGXkcJhW6miteKQkrSz5oMrky9GZO6HoRA73RbZLQKIHPSskiS+yrhOYb414SdV28
         W7ep6/tdIs1j2TA4i6k02SHWdRgvZtmYX2RTeU+Dkt5WaUd64yCBurwMJFIMjSMA8Gvp
         HpGZLy8klh9Nw/U72wQt4INLNXur1/yA21gH6XEkA6G8nhN0L1kdYomrkMuDB6hi1Q5G
         Wb1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJ2ta/tt6hZvG4QR/2I2DVrkp6TDoXaEacojDD0RZgM=;
        b=foYCMwMKDnIgdj23yPJ/776AgMmut0F7UKJrXPtSCOod9QmcSL5Pify3+MB0zkNR65
         wCUWmmf4c5CzpzkxGDdOOZUehXY6105N5LJK7fWlkYRY1NaAv9z+D7Ox+EoPpvLPT2D+
         JV1Oz8Pxa+/PbFLu042maAUbONcUDa3D5z1RQEZAkODHCTgCwOEuBOFSm1Fyf3pdff5e
         CxbZ0nLd8wOzp6JeVRC0/TtckqQOj9wFM1UgcxUp7kbngh9USgQ2ZzznDHsGWSw1GkI0
         8ce1yaXZJhmN/2HPSlOC+B9rdAH4TmO9c6F7lLlQmX7mWzYkidPabClbHZmHIQkycOnm
         1bpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9mZDbMnhpU2y1EdjgUAzT1g8eq/MkMC1QAV2zhqFkdYVEx/PN
	XeRwhoeEinuq0/I6pN24Kk0=
X-Google-Smtp-Source: APXvYqwnu7Y9upkCD7wxxXwUvCTUCmFrfbWA0S0CB/g0jF353Xgv6ruKnkirpkNkdK7DnmyU878ZAw==
X-Received: by 2002:a1c:2e8f:: with SMTP id u137mr11276920wmu.105.1573772490204;
        Thu, 14 Nov 2019 15:01:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7704:: with SMTP id t4ls12827361wmi.4.canary-gmail; Thu,
 14 Nov 2019 15:01:29 -0800 (PST)
X-Received: by 2002:a1c:e08a:: with SMTP id x132mr11399881wmg.146.1573772489587;
        Thu, 14 Nov 2019 15:01:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573772489; cv=none;
        d=google.com; s=arc-20160816;
        b=UFw+6Oyhe4xOjzpHvGSEr6rCq6Z8xWEoRGk7RcXNRpDWuNxXjqkLG0o/9gmbpm0rcT
         XVpg1G7ui0JqfxchDAKsoZcmAI4HgEYCz3ya1N3cM+QhOGFlmmUnX7OWy7teYNM5GR6N
         Q4SyU2cSoFynC+fAkbhMAy1D7MHI0ZGg7Sj8k+DcxjO0UD4vP7KeyVW7JvThDBXQxvFa
         PUSCz+x6CizxapUtAbALHPoPm/WHs2wRxDNDZk1pYYjw/fwJv+6r5ATMAusSA/QnrBY8
         5uBQzKz6kySD7V2ewHlu0SD4k0l+59IWzUQelk87U+8xqbYx/EPTac46L1e/cHTfSUow
         4mpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=vMb2gGIGBy8Y4g8q0F79Vcw8ulQafQxvuTBGmskEwT4=;
        b=bmVYY+dZ9rNCSCu3ZR5OhVl0BgShVz0LZAKC3P0lXe9xalXHb/0JGMXVc0EYHjpNY5
         kzQHbCLDXyhGofncRxLh81WJl+aUPShbHxhzfZI2ZPKh55aZg0xt/mHfaK8JZaT++18f
         EQUSxDn6EDAnl1InLaCy13gXGOdbeNhRNYs6a7W0ImPYKGQ9mwFlQ8Vlhbt4AW6s6AN6
         eQ2LYzA4dfr0I4LD/AAuzRWSW6xiuB+gdxjM1004F+HpIpCclIYfZnkstViJHcH3vuD0
         dukD6moRxCdvyF14PIYD1iNNdsqlkMStVe6NSdXtHC2iZFtc6EyYurTN/oAAR/ueh0wP
         Cxcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LUduz5Xw;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id b66si377679wme.2.2019.11.14.15.01.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 15:01:29 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id a17so8679752wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 15:01:29 -0800 (PST)
X-Received: by 2002:a7b:ca4d:: with SMTP id m13mr10745475wml.21.1573772489081;
        Thu, 14 Nov 2019 15:01:29 -0800 (PST)
Received: from [10.67.50.53] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id s8sm467507edj.6.2019.11.14.15.01.21
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 15:01:28 -0800 (PST)
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Marco Felsch <m.felsch@pengutronix.de>
Cc: linux-arm-kernel@lists.infradead.org, mark.rutland@arm.com,
 alexandre.belloni@bootlin.com, mhocko@suse.com, julien.thierry@arm.com,
 catalin.marinas@arm.com, linux-kernel@vger.kernel.org, dhowells@redhat.com,
 yamada.masahiro@socionext.com, ryabinin.a.a@gmail.com, glider@google.com,
 kvmarm@lists.cs.columbia.edu, corbet@lwn.net, liuwenliang@huawei.com,
 daniel.lezcano@linaro.org, linux@armlinux.org.uk,
 kasan-dev@googlegroups.com, bcm-kernel-feedback-list@broadcom.com,
 geert@linux-m68k.org, drjones@redhat.com, vladimir.murzin@arm.com,
 keescook@chromium.org, arnd@arndb.de, marc.zyngier@arm.com,
 andre.przywara@arm.com, philip@cog.systems, jinb.park7@gmail.com,
 tglx@linutronix.de, dvyukov@google.com, nico@fluxnic.net,
 gregkh@linuxfoundation.org, ard.biesheuvel@linaro.org,
 linux-doc@vger.kernel.org, christoffer.dall@arm.com, rob@landley.net,
 pombredanne@nexb.com, akpm@linux-foundation.org, thgarnie@google.com,
 kirill.shutemov@linux.intel.com, kernel@pengutronix.de
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
From: Florian Fainelli <f.fainelli@gmail.com>
Openpgp: preference=signencrypt
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 mQGiBEjPuBIRBACW9MxSJU9fvEOCTnRNqG/13rAGsj+vJqontvoDSNxRgmafP8d3nesnqPyR
 xGlkaOSDuu09rxuW+69Y2f1TzjFuGpBk4ysWOR85O2Nx8AJ6fYGCoeTbovrNlGT1M9obSFGQ
 X3IzRnWoqlfudjTO5TKoqkbOgpYqIo5n1QbEjCCwCwCg3DOH/4ug2AUUlcIT9/l3pGvoRJ0E
 AICDzi3l7pmC5IWn2n1mvP5247urtHFs/uusE827DDj3K8Upn2vYiOFMBhGsxAk6YKV6IP0d
 ZdWX6fqkJJlu9cSDvWtO1hXeHIfQIE/xcqvlRH783KrihLcsmnBqOiS6rJDO2x1eAgC8meAX
 SAgsrBhcgGl2Rl5gh/jkeA5ykwbxA/9u1eEuL70Qzt5APJmqVXR+kWvrqdBVPoUNy/tQ8mYc
 nzJJ63ng3tHhnwHXZOu8hL4nqwlYHRa9eeglXYhBqja4ZvIvCEqSmEukfivk+DlIgVoOAJbh
 qIWgvr3SIEuR6ayY3f5j0f2ejUMYlYYnKdiHXFlF9uXm1ELrb0YX4GMHz7QnRmxvcmlhbiBG
 YWluZWxsaSA8Zi5mYWluZWxsaUBnbWFpbC5jb20+iGYEExECACYCGyMGCwkIBwMCBBUCCAME
 FgIDAQIeAQIXgAUCVF/S8QUJHlwd3wAKCRBhV5kVtWN2DvCVAJ4u4/bPF4P3jxb4qEY8I2gS
 6hG0gACffNWlqJ2T4wSSn+3o7CCZNd7SLSC5BA0ESM+4EhAQAL/o09boR9D3Vk1Tt7+gpYr3
 WQ6hgYVON905q2ndEoA2J0dQxJNRw3snabHDDzQBAcqOvdi7YidfBVdKi0wxHhSuRBfuOppu
 pdXkb7zxuPQuSveCLqqZWRQ+Cc2QgF7SBqgznbe6Ngout5qXY5Dcagk9LqFNGhJQzUGHAsIs
 hap1f0B1PoUyUNeEInV98D8Xd/edM3mhO9nRpUXRK9Bvt4iEZUXGuVtZLT52nK6Wv2EZ1TiT
 OiqZlf1P+vxYLBx9eKmabPdm3yjalhY8yr1S1vL0gSA/C6W1o/TowdieF1rWN/MYHlkpyj9c
 Rpc281gAO0AP3V1G00YzBEdYyi0gaJbCEQnq8Vz1vDXFxHzyhgGz7umBsVKmYwZgA8DrrB0M
 oaP35wuGR3RJcaG30AnJpEDkBYHznI2apxdcuTPOHZyEilIRrBGzDwGtAhldzlBoBwE3Z3MY
 31TOpACu1ZpNOMysZ6xiE35pWkwc0KYm4hJA5GFfmWSN6DniimW3pmdDIiw4Ifcx8b3mFrRO
 BbDIW13E51j9RjbO/nAaK9ndZ5LRO1B/8Fwat7bLzmsCiEXOJY7NNpIEpkoNoEUfCcZwmLrU
 +eOTPzaF6drw6ayewEi5yzPg3TAT6FV3oBsNg3xlwU0gPK3v6gYPX5w9+ovPZ1/qqNfOrbsE
 FRuiSVsZQ5s3AAMFD/9XjlnnVDh9GX/r/6hjmr4U9tEsM+VQXaVXqZuHKaSmojOLUCP/YVQo
 7IiYaNssCS4FCPe4yrL4FJJfJAsbeyDykMN7wAnBcOkbZ9BPJPNCbqU6dowLOiy8AuTYQ48m
 vIyQ4Ijnb6GTrtxIUDQeOBNuQC/gyyx3nbL/lVlHbxr4tb6YkhkO6shjXhQh7nQb33FjGO4P
 WU11Nr9i/qoV8QCo12MQEo244RRA6VMud06y/E449rWZFSTwGqb0FS0seTcYNvxt8PB2izX+
 HZA8SL54j479ubxhfuoTu5nXdtFYFj5Lj5x34LKPx7MpgAmj0H7SDhpFWF2FzcC1bjiW9mjW
 HaKaX23Awt97AqQZXegbfkJwX2Y53ufq8Np3e1542lh3/mpiGSilCsaTahEGrHK+lIusl6mz
 Joil+u3k01ofvJMK0ZdzGUZ/aPMZ16LofjFA+MNxWrZFrkYmiGdv+LG45zSlZyIvzSiG2lKy
 kuVag+IijCIom78P9jRtB1q1Q5lwZp2TLAJlz92DmFwBg1hyFzwDADjZ2nrDxKUiybXIgZp9
 aU2d++ptEGCVJOfEW4qpWCCLPbOT7XBr+g/4H3qWbs3j/cDDq7LuVYIe+wchy/iXEJaQVeTC
 y5arMQorqTFWlEOgRA8OP47L9knl9i4xuR0euV6DChDrguup2aJVU4hPBBgRAgAPAhsMBQJU
 X9LxBQkeXB3fAAoJEGFXmRW1Y3YOj4UAn3nrFLPZekMeqX5aD/aq/dsbXSfyAKC45Go0YyxV
 HGuUuzv+GKZ6nsysJ7kCDQRXG8fwARAA6q/pqBi5PjHcOAUgk2/2LR5LjjesK50bCaD4JuNc
 YDhFR7Vs108diBtsho3w8WRd9viOqDrhLJTroVckkk74OY8r+3t1E0Dd4wHWHQZsAeUvOwDM
 PQMqTUBFuMi6ydzTZpFA2wBR9x6ofl8Ax+zaGBcFrRlQnhsuXLnM1uuvS39+pmzIjasZBP2H
 UPk5ifigXcpelKmj6iskP3c8QN6x6GjUSmYx+xUfs/GNVSU1XOZn61wgPDbgINJd/THGdqiO
 iJxCLuTMqlSsmh1+E1dSdfYkCb93R/0ZHvMKWlAx7MnaFgBfsG8FqNtZu3PCLfizyVYYjXbV
 WO1A23riZKqwrSJAATo5iTS65BuYxrFsFNPrf7TitM8E76BEBZk0OZBvZxMuOs6Z1qI8YKVK
 UrHVGFq3NbuPWCdRul9SX3VfOunr9Gv0GABnJ0ET+K7nspax0xqq7zgnM71QEaiaH17IFYGS
 sG34V7Wo3vyQzsk7qLf9Ajno0DhJ+VX43g8+AjxOMNVrGCt9RNXSBVpyv2AMTlWCdJ5KI6V4
 KEzWM4HJm7QlNKE6RPoBxJVbSQLPd9St3h7mxLcne4l7NK9eNgNnneT7QZL8fL//s9K8Ns1W
 t60uQNYvbhKDG7+/yLcmJgjF74XkGvxCmTA1rW2bsUriM533nG9gAOUFQjURkwI8jvMAEQEA
 AYkCaAQYEQIACQUCVxvH8AIbAgIpCRBhV5kVtWN2DsFdIAQZAQIABgUCVxvH8AAKCRCH0Jac
 RAcHBIkHD/9nmfog7X2ZXMzL9ktT++7x+W/QBrSTCTmq8PK+69+INN1ZDOrY8uz6htfTLV9+
 e2W6G8/7zIvODuHk7r+yQ585XbplgP0V5Xc8iBHdBgXbqnY5zBrcH+Q/oQ2STalEvaGHqNoD
 UGyLQ/fiKoLZTPMur57Fy1c9rTuKiSdMgnT0FPfWVDfpR2Ds0gpqWePlRuRGOoCln5GnREA/
 2MW2rWf+CO9kbIR+66j8b4RUJqIK3dWn9xbENh/aqxfonGTCZQ2zC4sLd25DQA4w1itPo+f5
 V/SQxuhnlQkTOCdJ7b/mby/pNRz1lsLkjnXueLILj7gNjwTabZXYtL16z24qkDTI1x3g98R/
 xunb3/fQwR8FY5/zRvXJq5us/nLvIvOmVwZFkwXc+AF+LSIajqQz9XbXeIP/BDjlBNXRZNdo
 dVuSU51ENcMcilPr2EUnqEAqeczsCGpnvRCLfVQeSZr2L9N4svNhhfPOEscYhhpHTh0VPyxI
 pPBNKq+byuYPMyk3nj814NKhImK0O4gTyCK9b+gZAVvQcYAXvSouCnTZeJRrNHJFTgTgu6E0
 caxTGgc5zzQHeX67eMzrGomG3ZnIxmd1sAbgvJUDaD2GrYlulfwGWwWyTNbWRvMighVdPkSF
 6XFgQaosWxkV0OELLy2N485YrTr2Uq64VKyxpncLh50e2RnyAJ9Za0Dx0yyp44iD1OvHtkEI
 M5kY0ACeNhCZJvZ5g4C2Lc9fcTHu8jxmEkI=
Message-ID: <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
Date: Thu, 14 Nov 2019 15:01:19 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=LUduz5Xw;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::342
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
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

Hello Marco,

On 11/14/19 10:12 AM, Marco Felsch wrote:
> Hi Florian,
> 
> first of all, many thanks for your work on this series =) I picked your
> and Arnd patches to make it compilable. Now it's compiling but my imx6q
> board didn't boot anymore. I debugged the code and found that the branch
> to 'start_kernel' won't be reached
> 
> 8<------- arch/arm/kernel/head-common.S -------
> ....
> 
> #ifdef CONFIG_KASAN
>         bl      kasan_early_init
> #endif
> 	mov     lr, #0
> 	b       start_kernel
> ENDPROC(__mmap_switched)
> 
> ....
> 8<----------------------------------------------
> 
> Now, I found also that 'KASAN_SHADOW_OFFSET' isn't set due to missing
> 'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=xxxxx' is
> added. Can that be the reason why my board isn't booted anymore?

The latest that I have is here, though not yet submitted since I needed
to solve one issue on a specific platform with a lot of memory:

https://github.com/ffainelli/linux/pull/new/kasan-v7

Can you share your branch as well? I did not pick all of Arnd's patches
since some appeared to be seemingly independent from KASan on ARM. This
is the KASAN related options that are set in my configuration:

grep KASAN build/linux-custom/.config
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=1
CONFIG_TEST_KASAN=m

are you using something different by any chance?
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7322163f-e08e-a6b7-b143-e9d59917ee5b%40gmail.com.
