Return-Path: <kasan-dev+bncBDW2JDUY5AORBMHKZPEQMGQEHVKJZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA979CA8170
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 16:07:30 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-597d583f5ecsf1251678e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 07:07:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764947250; cv=pass;
        d=google.com; s=arc-20240605;
        b=RVCIu9JmUJr/RyGdk5emmYlzaAzXbf6h7QLuJFaT6UIZXf8iCakAzfqoQk2A1ozP1z
         AS4TPotHInyDkFFdWWcQDxMbK6MDh3Nn9sYx6x0IAj5jK1n9rqTUl8dKiPLSLeyQx1WS
         J11uNkkZRwD1AwczD2POMs5zkOnHH9k9osx5eMiJGIg0g6IRomRTYbvU5yc7ZyWZkelp
         iLwGS86xRlmDkI+BJdFhKIkSw7skFL7M7WMGAeKJfbO/3PVvRm5BKdpg2rMRobimVtmF
         YvZo2UlWaEbQU1JoEi3hC7oKZi966XGf+OCcLuoX5OGHiFkv8TPIqWiXdjyO5ASQQDGs
         0Iyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JqDWer2bpgRA9tgIjaURFocyuIDnG2CfOwI9HqDD9tk=;
        fh=vrmrmTe3N8Gp10Gz+1mGhlJwMctciQuN92j833IH6Bs=;
        b=bXb6zwQ6g3Z1dYFzeNorDkJ/JYTvR8qTmVyFhEny7PPAMEDylyTcdPPfFKDsfExTjq
         MOtNH7lH/qUWAX+K6EW9VIgKS0vL3B6DQeiYn2L70ggtUcmz+eREhyWareYCYQrjV3+F
         L+XOpvtP/KqNGX7A33kISTygDiuo8cnYzyXpEuYFSBGKKsMcHQ/wNQuTqMCPBhkbYuTF
         X0wMUoM4JxPJH4fbF/V1sHIw0AJpVNszNSmlANxMXPlKP75WPrLn2ci0TDKibyJd7ovx
         Ra3C29oWpu/EU6gTtK4ZQx6+NXuZfgxkT8nElZZWdkgg+fDSetXPtx6+webh+LYzKC8j
         +1+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TxtIbHBI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764947250; x=1765552050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JqDWer2bpgRA9tgIjaURFocyuIDnG2CfOwI9HqDD9tk=;
        b=Bk7ZYgX6WoOKv5B+LaeiB5r5q596hRFcdRTYdlD1FVAkiOiAHoUYcDVdsEbtf8pd9T
         hu9Y7vzooqmz+cbYXoz2WXqWtFj0sjw1DU/I6VtjP5sG3M6hIAIpkEll8k9iASY9Soiu
         ifvAa3Y5G46KgN7bEwrlEUCfP/zO8+Hik0wuz650JjULqyFBY+sGHwMK7bdSbNDniN0D
         g3vWOksScS9s5OrU4rsDr8ZNTzOqVUytMWUon61g5CDqTfUYCOgCeSOb9sVwjfyqPHu2
         XccS/ygUly7IOdUebTYSDACkSDy0e0g0Yw7VVj/EnWWgh5pzOx70kKPPVTzFZS6g3wEb
         wqjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764947250; x=1765552050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JqDWer2bpgRA9tgIjaURFocyuIDnG2CfOwI9HqDD9tk=;
        b=hZ2muzjzE6qHYsS6ZKrhvzb+vsPFuys/zv43/EDMnWeF/rXBbTjcg+uuehVYjOPJO4
         CAxrkqp/x8gPfMj6g4untyIOu48KrdCfbVDAa4xQl0jN/JkN19Zneo5c0wLKYJpQNKRJ
         VF1SbLouBVUVH11HZDpkPt9IJVEJ1yAeEo7fGn6XUnCFWwXBDJTRhlZ4i22WYc0RGQ9r
         myCgDsUu0V7lQbw3I9bljTSsUwaYopyFS1Qx8KoHFKAL24/4NoJhFEY+W+L1wGoO91rY
         ud+55nWsF78eTTXNlfks31RjPPikhUXct/hZ+I5TnQ4gm+w6GHgePqek4MrbTQuww77G
         6REg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764947250; x=1765552050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JqDWer2bpgRA9tgIjaURFocyuIDnG2CfOwI9HqDD9tk=;
        b=qJG+mUhpvLRFB2JuBaOFfSpZetPoJBvhxRGlZ1cFnMUzbf1LNopf93X4XpeGY6fsVm
         rVVm8L1lzI+SRdO7vKyN16lXYbz4/n4ax41W0ENTcSx2agMrgAT4NJXmKqD7NJVoh85q
         kvn4Lr0edHAt91pk5b8EatEP45X4hFkAGRCmqFAbCBkvvA/9DqPD7prSZE3Y866WDVbg
         E8tBGcATlXsySyZ7h5CUyPtX12l3/OfYQbzDupmLwCobmcqM7ej8ZLYI7OfauLw1bQuI
         axHiqxoH3SVAkc5e5/oPMegi3Vm23gHyQSjuHDTqjxSRKBVwsGfqoo7l79cgWtEHwFuK
         B/jQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRGUzRJQiFKopW0chFTXXfdHxFIIRC17RtAJAY3uf0cl5hRl1vVQagZHsUo6BIqfPS4wzKDg==@lfdr.de
X-Gm-Message-State: AOJu0Yx16R6nvWLL+3ewwv0w0xhAXL7ydAA5aHR73tWQhd2kVvrJz303
	lq+yXRegfdSPx8mL8dApLAAOL4fZpgOMJdpY06l/EiOYsA/RB6w2Aw0r
X-Google-Smtp-Source: AGHT+IGZBWQjimU5oLB/1Dg6AdJMf9hWu4PMJVOncrXnW+TKJC+6UKJ11LVt7uxkmVFfylgV/d2y3w==
X-Received: by 2002:a05:6512:4017:b0:594:3004:ce37 with SMTP id 2adb3069b0e04-597d3feba48mr3967655e87.44.1764947249384;
        Fri, 05 Dec 2025 07:07:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYRV5MZoO+0S4CfuUeJVtgDTbFjHrnPWHi0gro6dkcVlQ=="
Received: by 2002:a05:6512:350e:b0:597:d700:d686 with SMTP id
 2adb3069b0e04-597d700d6f1ls445735e87.2.-pod-prod-06-eu; Fri, 05 Dec 2025
 07:07:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjddwPmog/8KnLylAjqaFfUnriF4cJlffSzUyGmDM1xIZsXPxyaEJALWiiTfaUZnL1mHqszi8jJAc=@googlegroups.com
X-Received: by 2002:a05:6512:3ba2:b0:595:91dc:72a5 with SMTP id 2adb3069b0e04-597d3fe887bmr3696572e87.40.1764947246386;
        Fri, 05 Dec 2025 07:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764947246; cv=none;
        d=google.com; s=arc-20240605;
        b=cE4SqbcGo6D5D+vTE3zzWSdpxi+xq4nQ1xjcwRKI6VFxRp7NaMLTXviG0IRuk/i3gu
         jvoGNBg8vaRl4wDQm4bhWAP0TjCcNw5LTKiWhO7ig8rxNEhdjVHnWLwkyEXWuHLqU6uU
         fiUFgg6WdASYw9UhgGXxXsspoAMArlh4bp/UvP2rIvE2fluMNPvDhUZkJieNSuXeixSy
         b3RdjO/FG+9q/NUaX9zImA3Z9XYA7Hhce8+76H3NP9P1B1qsVjzdfmllurxXV1mNQFx7
         a34ZInokGaYUUjAtLfm4csOoyc/ooNrPgqYfftTCQwnMak1DhMf2pGOlI5fVaHbEyePW
         ImPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=u9Sh1gr9sSQ2OQz4zUzJ40SzpPcpTrnjv9Hty5mB8+A=;
        fh=W9M4eVtTq18zEZnPjsApl8Lvj18VvB9uiddJgMQc7nI=;
        b=Ih9KWFEAi2V7PWkFQ+UwXq0uha10DR46wA/TRwnKHJ1HCyyn6dSyTg82Bc+MLT1Ei1
         gl4Ur26QjfQ0NJegsfzdURkSXRcHVXxIUtz2kpal8STe7D6/ar3ehr/BLWogxykuW/bg
         ZcvrCO6xYCiHMp9UTQ6TE6WGQfAuvKAnYLlWxFWT3367SYWKB7fWL3P+JQV9iq+pVK8N
         gYVLDjoRn+AMDR4bRyTllRGZg9tpemStJlcvxsaHmU8AT9GGPo1iGdo8zJ2Jlhjo2TXS
         oQ4rFZRumQnU06OElOItRmrIAHZzVnf8tC6krHkMbq1kdEkbNM9VG7BxbLbK6ByACmMo
         f7lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TxtIbHBI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7be3d45si71960e87.3.2025.12.05.07.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Dec 2025 07:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-42e2e3c3a83so1081758f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Dec 2025 07:07:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVonU/qrn0cLTWbdolXVAKQptV94qwiZs78cG2kkDtaTNrdC7/U/+0SQRh6f0j6TXK1rPopc+50Il4=@googlegroups.com
X-Gm-Gg: ASbGncvkGP9vJUb5B1FZ4Ei9NdrzXYrSzljI2CDl9zocK6GEiBPL7BIAQl2WRKf0gta
	arjRcHMA0x77WvQfQjBjLbFriHcIClsEs1Oq2GBCNmptC6rUrUmoCY2IM1IfKxOq2FrfPPNECeg
	NuJTQDfSkBAdEFxZVNCFcbit8ewv0GmWCr1dGmaY26B8RYSeDdPyOsuJTiiAhWMP5jCGovL4QTT
	TUKg/+gOnATRtkb2LAWkUp0FxnME9GmUJYMoXp86B2wMlbsO8nXOSG/GnPcNQbspMzGGLrADhTR
	W9iw6xAPRvPvXUefV9TAMrRU79YBauNVxQ==
X-Received: by 2002:a05:6000:2c09:b0:429:8b01:c08d with SMTP id
 ffacd0b85a97d-42f731bc24dmr11041756f8f.41.1764947245574; Fri, 05 Dec 2025
 07:07:25 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
 <aTKGYzREbj/6Hwz6@fedora>
In-Reply-To: <aTKGYzREbj/6Hwz6@fedora>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 16:07:14 +0100
X-Gm-Features: AQt7F2pv1BpZjdGZf4uiwOOKMqx6h_y-AphkDn6MuXmCXnyvxBMukG84fsup2wA
Message-ID: <CA+fCnZewpfDzdo51s6eGPzNohdQ6xHkBwX-Sxo1qty8pBgHZ4w@mail.gmail.com>
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TxtIbHBI;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Dec 5, 2025 at 8:14=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> > I also wonder if we should keep this kasan=3Doff functionality
> > conservative and limit it to x86 and arm64 (since these are the only
> > two tested architectures).
>
> We may not need to do that. I tested on arm64 because it has sw_tags and
> hw_tags. And if x86_64 and arm64 works well with kasan=3Doff in generic
> mode, it should be fine on other architectures. I am a little more
> familiar with operations on x86/arm64 than others.  I can manage to get
> power system to test kasan=3Doff in generic mode, if that is required.
> From my side, I would like to see x86_64/arm64/s390/power to have
> kasan=3Doff because RHEL support these architectures. I need consult peop=
le
> to make clear how to change in s390. Will post patch later or ask other
> people to help do that.
>
> While there seems to be no reason we don't let other arch-es have this
> benefit if the underlying code has paved the way, the arch side only need=
s
> two lines of judgement code. Personal opinion.

OK, but it would be great if the arch maintainers could review and
test the changes.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZewpfDzdo51s6eGPzNohdQ6xHkBwX-Sxo1qty8pBgHZ4w%40mail.gmail.com.
