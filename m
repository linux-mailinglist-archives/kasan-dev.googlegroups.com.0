Return-Path: <kasan-dev+bncBCH67JWTV4DBBN6TTXUQKGQEXKWNL3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80D2365DF1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 18:54:15 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v7sf2887611wrt.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 09:54:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562864055; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZorN50FcwwNWEc/mvaEg65/Jly+qJakh98tZr3rA5UMHXJ30AhCp9B4OBaB93PXpXr
         TWtiqbWhm8vapy7hj73zaB1TtIycs5jI5oDr3bRJpTdB8fJTUAGX7zc4KC3XMjs7APyF
         Pvms5fUn4nhdgo//LzLUqQhnYXzIYoqk7BLeg9nVfWw7R9B7k5b3GIfnPK6hd75JI6Ju
         1n31Pcua/5LoQz/o5BRzacUprtz3vUGRV77d4AW6S0xHYRV4qLWDVykNPd7tNxtdZdbQ
         rW7obAGVnEImn4BUfgtjvarlvAbfiI4S8plJr/A4aiEjLCOQUjsVq17qsAasAci9OGV5
         Qi8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=BiZadY+tcyeW256aGX+qhBUvaIPhhXuw2X9VeEg80gs=;
        b=fSCplZ2RN8p0uxgdDj4vMP9bmiR4/vda3PDe4PdvpyYX6IG5zzM1J/aBQvq1rQsGFV
         9L6d5AMoe/7KFtWRsAM16RSLpxK2hWSTS8sBQOyn0hWbRg5ZWx8GMtiA0U46NhGLW2cE
         uay4Mk710QAeYwZ7GYEpRJXB6/m2yxGCGJHgN5SmrIddfGmxeutFYZOKtmYbGL+De1WP
         0GtRL1TR7p+7NVRM14+CL5KW7b3BQCHWaX9DL81920gSCDL27BgFMRcC09qk4HwVfoQX
         CNVzfb5Lmyn9V3evp9U6WOLRy+MeT1vGithchjwCQNVVeUa3rJpm3qi/5v0q384XEynj
         TvvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VE858to2;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BiZadY+tcyeW256aGX+qhBUvaIPhhXuw2X9VeEg80gs=;
        b=kqHlRzia9VuzXPznTLoTYYU7kb4sKRWq9yXic3kNKJtiE6bVqZhap6tRKnN3usOdcu
         DQr3qbApJBgdoPoHq9KMq6qCsFZiU8yB8cU5QWffQiGa0jyKtB3wBs5XuGpajbVsadoy
         HOzyvuA9GwCCHqbggTOJq13xnX7vIT2L1Pp9FDY/0orv78X9aE1q/z6rrVZa2UTn/suy
         rSK/MZbs+iyiLM+O3QWy6Cv9VQbb2BxGT3gIn496x/5Pd8n4cvsHymXvyiCOwEKeocC6
         0bh3TvqU8+XjmzR2X7HdXrwiW2cC7kvcTVW4ythHORcW1DQC+NtUnmI2DDqGhZNSnVci
         2DCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BiZadY+tcyeW256aGX+qhBUvaIPhhXuw2X9VeEg80gs=;
        b=IC04a+sFMkJx6lVuD/dIqsln/V3pk5nwe++kQ+JJtUwU6jX3e1h1jbZwuYP/q8fF0j
         8INtzIDfJZ7j6BbhSXfZS2wNQVvKrBKTMFVNofKT0Bo0uEajZbiSZBwUPeuY6l+0Qjgm
         oj7OcSpvrNXP4rnL0PL+wUGoVkuubpcSzpUyvrOuImEEWFtNX0dvhoH9y9/7zrLaFjD8
         8kfS0/G+djTaJV5d98bYBFbFl0VG0J+xN3k8I8mWL3H5x7ZvixEhXrhxaU7+oGysc/1P
         H5Od+7nUWn+y8tqIKqjLUOeGRjeZXUi1IL/GgkRMSmMEZiatW1jfEuz9dtP28UkL2gyM
         bZ0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BiZadY+tcyeW256aGX+qhBUvaIPhhXuw2X9VeEg80gs=;
        b=Cv7do33+QDGzbDoY7geT1i6lKmATZyZyv/lo21EjV72h4Tty2wBaBRFT33HeZd3VKt
         9WKDgQfzq8uZVJA4lPDrOEiZLJl2siRcITIJpeh+2C6m9PTtDLdMqCQKu4t2/BjmvnNE
         hpsOReUTuYwBTCtRjk9fa14dY0jKQJQIJmibv9UgUse2v80cGtHZffE+g5BZgLLdRayn
         c0Pef8t1yKMvUg6uvSDR/jeR+CLlFLfnfzk3Mex4eFpNiLu2orCru1l4msv7Fcrz1QVZ
         r2VSh2M1sV1p4D7TLFp+YAMFQGtX3dyRHM0ARdKSDLWjOYgHZKheBk+y3+TTcI6uMDbI
         Hg6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXwb/l2Lbn36pgaUH7p0B40du33cc31oxvOgzg/B03R6XbN6y26
	r1LdJ07paPKPU63KxBhwBmM=
X-Google-Smtp-Source: APXvYqzdGCb5m8r2zaR0V9fNuh4T2TvV2BjaIAnnqHQgHydhnrBaga0R7aWE2LPBdQJ5jA5EJJmDCQ==
X-Received: by 2002:a1c:7a15:: with SMTP id v21mr5099629wmc.82.1562864055164;
        Thu, 11 Jul 2019 09:54:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec02:: with SMTP id x2ls2158770wrn.6.gmail; Thu, 11 Jul
 2019 09:54:14 -0700 (PDT)
X-Received: by 2002:adf:e442:: with SMTP id t2mr6270188wrm.286.1562864054642;
        Thu, 11 Jul 2019 09:54:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562864054; cv=none;
        d=google.com; s=arc-20160816;
        b=i0Gvfnp8bZAyx+hYpW/D4/S4ufqTZDai716wLLiG7vbzPq7cJAeJ7+rX1EtS96M/XG
         YzwxVCbXQq9qSX8VKm0qmJugPVPIZ89JGrVBhowZQIkX5aBlTQrQRcKSKSBkZ8VaBc/V
         upkEnm7WQiI7zuuE03CQ0gVtPu4eWNms/YyYj4v0BXLGh2I5jY8aoaB9Fa956h/egju+
         uTuSvXhp93vCW6HI1G2gVALIGPw7zaTy3+ZX6vKvh6T3xz8NejxYOPMfaVBcNCeeGwTa
         DEtaMQbDTKmIZR+el/puf1QK3qGqoYa90JGLe6VEtmCq2mrpnYMuYn80WF3WWjL/Dr38
         7ZGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=NesWXuGbkASvqkB3OfHXJkarfZRKXQiML61VfYbpfEw=;
        b=rgnJD1VHY5uBnk5OKQ1FyecPyzbJrTbiqUUXM+PfLOdBOdsApWgYNCludZgtuVbHrH
         MuoOPA/1zD5q76Ypwz0CglzchhNnweZHG9MgVWD6NzSZKs38AiTiEMbvwgyr6jr5RFkT
         V0Ax4dwWGfYckfY1HdNeisWpMt7pC2eXdL8JghU4uAOSG5L+iAjdLPR21cxJX6p1/vQN
         3+aHo+kxV/ZtRowp3ADWvuP6kgnGWOhe/FatVKTLxJAMyE4gimT7UJXCJwrCusmJeadR
         IW5QHiovCf6qmnM10aPo3XNEn2JiaP0vWocrDZXVAuDPEiknVCskbjb7D4xJAQ/tkR5q
         NkDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VE858to2;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v21si639533wmc.1.2019.07.11.09.54.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 09:54:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id 31so7099378wrm.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Jul 2019 09:54:14 -0700 (PDT)
X-Received: by 2002:adf:e941:: with SMTP id m1mr6267917wrn.279.1562864054220;
        Thu, 11 Jul 2019 09:54:14 -0700 (PDT)
Received: from [10.67.49.31] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id d16sm4577249wrv.55.2019.07.11.09.54.01
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 09:54:13 -0700 (PDT)
Subject: Re: [PATCH v6 2/6] ARM: Disable instrumentation for some code
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Abbott Liu <liuwenliang@huawei.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Russell King <linux@armlinux.org.uk>,
 christoffer.dall@arm.com, Marc Zyngier <marc.zyngier@arm.com>,
 Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>,
 Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook
 <keescook@chromium.org>, jinb.park7@gmail.com,
 Alexandre Belloni <alexandre.belloni@bootlin.com>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Daniel Lezcano <daniel.lezcano@linaro.org>,
 Philippe Ombredanne <pombredanne@nexb.com>, Rob Landley <rob@landley.net>,
 Greg KH <gregkh@linuxfoundation.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Masahiro Yamada <yamada.masahiro@socionext.com>,
 Thomas Gleixner <tglx@linutronix.de>, thgarnie@google.com,
 David Howells <dhowells@redhat.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>,
 Andre Przywara <andre.przywara@arm.com>, julien.thierry@arm.com,
 drjones@redhat.com, philip@cog.systems, mhocko@suse.com,
 kirill.shutemov@linux.intel.com, kasan-dev@googlegroups.com,
 Linux Doc Mailing List <linux-doc@vger.kernel.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 kvmarm@lists.cs.columbia.edu, Andrey Ryabinin <ryabinin.a.a@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20190617221134.9930-3-f.fainelli@gmail.com>
 <CACRpkdb3P6oQTK9FGUkMj4kax8us3rKH6c36pX=HD1_wMqcoJQ@mail.gmail.com>
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
Message-ID: <aa45795c-7fa1-ebb8-5d26-cce4c8a60e1a@gmail.com>
Date: Thu, 11 Jul 2019 09:53:51 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <CACRpkdb3P6oQTK9FGUkMj4kax8us3rKH6c36pX=HD1_wMqcoJQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VE858to2;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441
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

On 7/2/19 2:56 PM, Linus Walleij wrote:
> On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:
> 
>> @@ -236,7 +236,8 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
>>                 if (*vsp >= (unsigned long *)ctrl->sp_high)
>>                         return -URC_FAILURE;
>>
>> -       ctrl->vrs[reg] = *(*vsp)++;
>> +       ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
>> +       (*vsp)++;
> 
> I would probably even put in a comment here so it is clear why we
> do this. Passers-by may not know that READ_ONCE_NOCHECK() is
> even related to KASan.

Makes sense, I will add that, thanks!

> 
> Other than that,
> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
> 
> Yours,
> Linus Walleij
> 


-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aa45795c-7fa1-ebb8-5d26-cce4c8a60e1a%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
