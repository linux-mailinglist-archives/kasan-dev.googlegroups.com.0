Return-Path: <kasan-dev+bncBCH67JWTV4DBBC6753WAKGQEPE7N7OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EA17CEE72
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 23:35:07 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id d7sf9829506edp.23
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 14:35:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570484107; cv=pass;
        d=google.com; s=arc-20160816;
        b=x87Sf6nw3AZL1IWJUfoZO/2bLc/q4ynpcYk7wDYrijjj/kq8DZQMIJdWYC7tqy5Ghr
         uFb5KctM1D5e0dG19G2mk3cSF5XNeNIP82L3fuypPi3bVfvf1TlCKbkL+Ea0JYUTlK8f
         wfCV6aK+fR1fQViANf3nyiNQEdTv/g987ntgOahKigCs/ApjU5uQsCRu0n+jq95xaTkE
         kwaRRommRF9ce6R2Ty97VpjjCP4gMcru9eoUHoJMt5xSVVPU6wbQEUySAIYQyZ60I7+a
         U4uUqsO2QX8kM+j/KXrncxvcMvvRfbIFTJlFPBnKRCxdFqyGr9gCPTu9n/hAjVm8jBZ4
         kSPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=qZUHJXbHO9OWrt9TxyxQDlCRsxrjoDCZhokwJaqZLcc=;
        b=kRAB/pqmX6WXTh/7UB9ylCU5jk8xMWE4aEenASctcGIh+3IKcl7OrwHmA1mm4nX8ao
         EtnK5eZiVFen83vvkceydk1mHufepHLX0Rvyh5fM3TAFCxN4v9KJfuKlZgEI14cuPL/R
         Blh+PQekQtk+LPR79vy3VbnL+Aat+mv/+gdrhEgNRHj86oBg5rflYQUwOuct3TdmWo5t
         jhVL55bIsEWObISBkIv4hOH0no1Lo0hyPgvAWJwTsa1eV66vNRZJOmJuK44MtQAhlPqx
         TH+f1YgYH2bM3ig0J7BIhQane8G+ZNq5DXqlOglsiFGxdkTTb/KGPCnDfB/8vXkKpwxF
         EX1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Fk6hrgHG;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qZUHJXbHO9OWrt9TxyxQDlCRsxrjoDCZhokwJaqZLcc=;
        b=boJSccKJ6Rnjd6HmZHVNrqKIEEn3uH8SPIeJsAN/oCyzM44vpagDpCkSr4ZIRDoEW5
         lU+IB6XtEuRhSiI5cgYYre010uSQ+hxOYSOn79lZeKaZRF1NJcHM63RpyWdUCzEsF5ut
         YKkI5JlWpf5B8u8BYxFM5SFAy4MOh2IOQR381tpn1BaRS6cJPgMtxp7zWWKfqEeZAK0g
         dTdR8QBtQuQGqzq8W4OGWybCTG/nBTa6Xrr+Q4SdJ1F0bDDTa2R1CjKj20gTHW4prPwL
         gz1JyfSIunXmRv5uQ4KHQlOLZhdZrOoCpnX+KQhGS/GRXSKMEr9ny9TtiGWGIrL91f3k
         id0A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qZUHJXbHO9OWrt9TxyxQDlCRsxrjoDCZhokwJaqZLcc=;
        b=oyFNWKRO3VTT55dtFFs52u6Jb3PeT3p9xnSbYgwsRNMuZVCSnAmu0hrXdMh5jUyBcf
         07iIJXRpdqeJbrTJmzSIVBLH2iZvMGt/P4zyHlYHQSQl3mGUEc3ZjsU6Ka7ZrbL1HYOc
         5rKvKJbO0ncYuPK3WA3f6u/Y7J/wQAJWxakIQ5ulgYKsKm15wslSAscSidreuhuhGbbL
         JqMCwJTkU48X4d2VR8HcyAkrFpe3yHzrWUjZi9YgfJ3T/64dYty40rpnxZuQYQogreiH
         h5wr2xo11W/Ymp6MzUcO+LZczha51TByHcRhzIP7JsfUjgUtuk/BjsZonqsCTm7I4S63
         en4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qZUHJXbHO9OWrt9TxyxQDlCRsxrjoDCZhokwJaqZLcc=;
        b=ANoPPMR8RNeGn1NK2tJp/gb5Q5mC2A7KyW26U9Ggf1KlHLiLmUS5FRy4ksr+ykP0Ax
         LdLf2acZVfUzTHH4QEY6AX/Zu5m++GMsy6xdEG+rBDDLHQJG/6pHOe2Dqi3QawgOZ+Lo
         Lmcfc5vXBMpPIiboPPu/QeIj51AMJ5jINi53GDwBDn3XyNDMRO4CeqbJjzkecyDnDTxI
         6bjGQY15Qeo9x8lDKw/XBfLxPxI0rAZ15z3cn1Au/H6Nn70YSGDlDXfAOwcR8MHaH5B6
         v8Ee98UfteCxz9EnRNPARsH7AAP4k+Hkm48JUqHlwYQtIIZW+wY38UALlGnYa1AYPYmZ
         YiVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU28Ypt0BCJrkV4xoohFMyuUp3mpVtAe8rnu319Vp8RtVaUDquJ
	4ynBG18iCuJU2M3wsO2tyUg=
X-Google-Smtp-Source: APXvYqxvcZZLLKE/3qtOcILOve7K2PKX1OU8u+Xeb1qxKXFM2gL0ucFeH7s6dzQVV+YqUehmkgKhKQ==
X-Received: by 2002:a17:906:1853:: with SMTP id w19mr25703645eje.232.1570484107236;
        Mon, 07 Oct 2019 14:35:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:a572:: with SMTP id z47ls303914edb.2.gmail; Mon, 07 Oct
 2019 14:35:06 -0700 (PDT)
X-Received: by 2002:aa7:dc57:: with SMTP id g23mr31481134edu.38.1570484106654;
        Mon, 07 Oct 2019 14:35:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570484106; cv=none;
        d=google.com; s=arc-20160816;
        b=bjwBLYdCABIK6CqMFAE42MQZ4IwEBaRqZVE/N/OGe+6MkWO8TU/lQ9oEraPfSMibb4
         wOi7HrXOw2n4WPg8SVE7ISpQ2i4JCuOUBgqiERGfSk6g8bSDEhrE28Sp8huTNQBNR0QE
         0+RbGQL0o38U1KiWl+chJwj2pgcYvFywRdHadstkU+wa7f/TGUGZUUEMPHDrhWiey1t7
         zu4GTGEEHecIQvXAr0HG+YNyDF8bXon7XnMjGBF8ynKk83Fr7TADb4Ia935y9crVtYKB
         esBPeen1h/LW09wS9KXpJnJAZa6n8yRFoLT2eeYRi85zqOC+evPUoqE+F5Z5Mn9DVPGR
         de1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=OyhiovIjMKJKHgMLTz6N4LKz78G59FFqcnuV5MZGZ7g=;
        b=b9gVPVLyLFfjdGm08XVwo5ziZl8QxD6NTz8CqHhMAl2bMQ1NbrArhEbLPZMl4QPo97
         FNEQD4PtcqHkUI3I4q425XphxEPfhz9Ewo0RbodiDaz/5HgOiEPFQBAikUcfs9JrHr7r
         PBVi3uP4XbXOW0yKGhoHT5iX9dlvzGZadOvXVgh5jo6uYbPBrYOXWhvZ6cVfmrCgGONQ
         83aUuhtu5ENfq9+wWVOCNsPHkANOO0l0+HpSvOy8sUSHOS5f2oyk7Zm7Je6Ca6KsMtWF
         ixTNDnNqAS9WMVVgRoVLqwc4gV8wU8scxthHZNApvtgiy24dXyhT46vzV8PfkRbTRnFx
         0Dwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Fk6hrgHG;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id a15si809457ejj.0.2019.10.07.14.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 14:35:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id r3so17000819wrj.6
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 14:35:06 -0700 (PDT)
X-Received: by 2002:adf:df0d:: with SMTP id y13mr26056785wrl.342.1570484106216;
        Mon, 07 Oct 2019 14:35:06 -0700 (PDT)
Received: from [10.67.50.53] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id o4sm33715301wre.91.2019.10.07.14.34.54
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 14:35:05 -0700 (PDT)
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Arnd Bergmann <arnd@arndb.de>
Cc: Linus Walleij <linus.walleij@linaro.org>,
 Florian Fainelli <f.fainelli@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>,
 Michal Hocko <mhocko@suse.com>, Julien Thierry <julien.thierry@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 David Howells <dhowells@redhat.com>,
 Masahiro Yamada <yamada.masahiro@socionext.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu,
 Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>,
 Daniel Lezcano <daniel.lezcano@linaro.org>,
 Russell King <linux@armlinux.org.uk>, kasan-dev
 <kasan-dev@googlegroups.com>,
 bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
 Dmitry Vyukov <dvyukov@google.com>, Geert Uytterhoeven
 <geert@linux-m68k.org>, drjones@redhat.com,
 Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook
 <keescook@chromium.org>, Marc Zyngier <marc.zyngier@arm.com>,
 Andre Przywara <andre.przywara@arm.com>, philip@cog.systems,
 Jinbum Park <jinb.park7@gmail.com>, Thomas Gleixner <tglx@linutronix.de>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Linux Doc Mailing List <linux-doc@vger.kernel.org>,
 Christoffer Dall <christoffer.dall@arm.com>, Rob Landley <rob@landley.net>,
 Philippe Ombredanne <pombredanne@nexb.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Thomas Garnier <thgarnie@google.com>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
 <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com>
 <CAK8P3a2QBQrBU+bBBL20kR+qJfmspCNjiw05jHTa-q6EDfodMg@mail.gmail.com>
From: Florian Fainelli <f.fainelli@gmail.com>
Openpgp: preference=signencrypt
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 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
 M5kY0ACeNhCZJvZ5g4C2Lc9fcTHu8jxmEkI=
Message-ID: <fbdc3788-3a24-2885-b61b-8480e8464a51@gmail.com>
Date: Mon, 7 Oct 2019 14:34:45 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <CAK8P3a2QBQrBU+bBBL20kR+qJfmspCNjiw05jHTa-q6EDfodMg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Fk6hrgHG;       spf=pass
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

On 7/18/19 12:51 AM, Arnd Bergmann wrote:
> On Thu, Jul 11, 2019 at 7:00 PM Florian Fainelli
> <florian.fainelli@broadcom.com> wrote:
>> On 7/2/19 2:06 PM, Linus Walleij wrote:
> 
>>
>> Great, thanks a lot for taking a look. FYI, I will be on holiday from
>> July 19th till August 12th, if you think you have more feedback between
>> now and then, I can try to pick it up and submit a v7 with that feedback
>> addressed, or it will happen when I return, or you can pick it up if you
>> refer, all options are possible!
>>
>> @Arnd, should we squash your patches in as well?
> 
> Yes, please do. I don't remember if I sent you all of them already,
> here is the list of patches that I have applied locally on top of your
> series to get a clean randconfig build:
> 
> 123c3262f872 KASAN: push back KASAN_STACK to clang-10

This one seems to have received some feedback, not sure if it was
addressed or not in a subsequent patch?

> d63dd9e2afd9 [HACK] ARM: disable KASAN+XIP_KERNEL

That one has been squashed, we could always lift the XIP_KERNEL
restriction later once someone with suitable hardware confirms it works.

> 879eb3c22240 kasan: increase 32-bit stack frame warning limit

That one should be pushed separately.

> 053555034bdf kasan: disable CONFIG_KASAN_STACK with clang on arm32

This one I did not take based on Linus' feedback that is breaks booting
on his RealView board.

> 6c1a78a448c2 ARM: fix kasan link failures

This one was squashed relevant and will be sent out as v7.
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbdc3788-3a24-2885-b61b-8480e8464a51%40gmail.com.
