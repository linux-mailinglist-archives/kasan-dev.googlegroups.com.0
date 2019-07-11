Return-Path: <kasan-dev+bncBDP6DZOSRENBBLOWTXUQKGQET47723Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BD3665E17
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 19:00:30 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id p193sf2732325vkd.7
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 10:00:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562864429; cv=pass;
        d=google.com; s=arc-20160816;
        b=KX7np2z+sAKMVbB9ksxpy9mTTYue7UTrObtE9LQrYKA4vGAJAhSMlJ0d/tYvIvPOEl
         ngOus/uzPdM7X3iiEiJIqLKOwpC8iCTHavCVbdbdQcixvy2D8EynyqPaiMyBpl/sSkQA
         UdePuMFt2KGi6lCkPdvHEPTPczYDO1/cR5ASmAibeQvC4R2gnhND05Vum3BgZGeKaIhl
         17JTg5Y07IPclSQOXTKzxp+yoOzzhlXzk4uFVljc+hhHh/9Jw+cETgv2GGMfsq9vjBwP
         +CkIKfNp1XFs9jLQh8mEyMJbeLOb6oDXNG8C5ROsRZgbh9OFjvVIhqF5U85xynqLDXiN
         jakg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:autocrypt
         :openpgp:from:references:cc:to:subject:dkim-signature;
        bh=IOqpgwgOOxyiHG0SlRQ8jm0cBgaNlvKtOGh/eFbLcqY=;
        b=Sw/Rl6l8uQDCgLrxYCwGMr/c2mRUgPSVhB+A3KqLn306hPVC4quQAMQU/OvbwF7bbs
         +lxzhHGpzzFvWHe8vZSxaevxnWBYnKtwvT4h25oGyVdUNLv8yVoaBN2LgiC0ykzUX9WL
         anD2fvWAY2Wn+B5mFT5PRpgZygJxEvY6cGbctATA3kc6q7dC0D4+h/NbkWMCRAuiJmTZ
         Ec4jmPIuhqOYdfdRUyX0bbGRz5IvxJAYxb675rJP2A9lloKW9yFqImKMT6gVfBmIXXpO
         ib0Frii/71EjSKzd1sJyrnvJtondNBQ4+226HaF1gMgUry2n/imUWplOv46vHWSx18a4
         oHYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=QtY5LSfY;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IOqpgwgOOxyiHG0SlRQ8jm0cBgaNlvKtOGh/eFbLcqY=;
        b=MONvnnPllaIxjFv+EL4/SMhJee5mR4GO6t920A43MvRQoDpu/PIU+PbQ7WTFU6++za
         eXxWzCAmcVNbQOhMmYN2FYwUv3UpIedygtxZoNuOvPAAJwuXlSeDm9Z1VXL671p8wUDW
         SoN7H6K/xtROOJID1L1jXgz8m8d98asPOuE8VrR1b9v7D0agRlLhuGmrOgSnBhKoEMX7
         YtXn2RdQgSbdnsjFqD8zWEaYrtCNObB0Jr9D92LQ0cEut3la1bLb1nJEQ6ayUg07DX8A
         TFN+gTNaYWwgV+PfXfSObUJ8JF5FGDD6p8pLMiRaECZnVBlYULxwPcsbZl39bfqQULtr
         mrCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:subject:to:cc:references:from:openpgp:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IOqpgwgOOxyiHG0SlRQ8jm0cBgaNlvKtOGh/eFbLcqY=;
        b=jfe+3ftrSYF4QkQ5w0N2+YayGyb7ZlfvGBnhXKpTduDDmBWthGN9tKepeOdrf0mCrj
         3DaK+w+siVHGVmQNkjLmFs3JrtOZx8Ahrxes2RvZLs2YkDmGHY533nZFO0rrIccruu29
         iwk+16BieLOmr+e6Tsqsd0W5XyDOiqKR5lluZA6m/TAjA2NPm17IK2RXION1cfJja+OX
         lG1DJJWz6UK3nLygtIf7qZMG0FjiNqfAVq9rcYmRZu7xTMkOBnF1d8TC2VfVLGqnnYPM
         yrytU/Nw6geUxbj8qCFUZxPPyaUqfJlxaT/ud3j/DGinBJuFJEbRgwZrR9eGV9OMal0r
         4afg==
X-Gm-Message-State: APjAAAVp3Lkx757BQV7dJX4UdUcC9d4w5tju2FN9Fuo9G/Ezk+m4Fpy1
	uVKbQbnZ4DB1VciJz8JuFMM=
X-Google-Smtp-Source: APXvYqz1Lch7iPplZqVfChC3YZ4yK3VPl/qFNwLknSCdlmjQUMLRuu4o/lGLEBJ77BQaeJgS+ylcJA==
X-Received: by 2002:ab0:b99:: with SMTP id c25mr5657745uak.53.1562864429292;
        Thu, 11 Jul 2019 10:00:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6043:: with SMTP id o3ls636360ual.1.gmail; Thu, 11 Jul
 2019 10:00:28 -0700 (PDT)
X-Received: by 2002:ab0:2a0c:: with SMTP id o12mr5795664uar.122.1562864428882;
        Thu, 11 Jul 2019 10:00:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562864428; cv=none;
        d=google.com; s=arc-20160816;
        b=qG0I2RiI/xi6/owHezDW0pghcgbAMNNodVLsIf7vf+El+Dmp43x/n/H9Seb5p0Qabs
         jmWsE9cJlnvoqbVcXXImdF8u0VA5AR+ciu4reVAKE9q0wXRWmJ5OF2+xDN+PEIHHioTm
         Q/BUB1yDjCkfpOVLeUBpCUJZBbbX4K4vaV33yX6BgODlhpR2NYGJsWeWUkHb4DxHXkte
         L7JBOnwgw6HnT38gWn0entWSMX39jinApeU8g56bwmsetNheUTrLkI3USpbLsJrwbSqt
         /sJrJWFDRg29Brwk3vL982QQ7ke6kaAqbDdk0fyhMsrmxEiYsw82Xcbs9bG7nkVz/qtF
         8YDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=GU/67RfZIGaVv3I1gykKW+OAEzbKYvssQxM3jRxvovg=;
        b=Lqi1/H/8IUHhZeva1df17eyHVg34wE5H406To8pQeAp3T8YArge1+Oj0BECSnSS0n6
         R6DoF9E1u2HdW8xhQpRdhI+CmrAt/O54wtLujwVuwlEo3cj5tjv021HcxxP3qN1ZXPll
         u/kr2Pyup4u2pJALotbSvDhd0GNVszMCD02/PZH3IIO0dt+D7wyVMAarLq/jfIPP9ui8
         NXEGWN2jAXSqZlBdw0pUFNmp1vq9XgCYcvyrEefiUZZzKvxgh4Lfgob8E0bkLIPnKA7c
         UO4Rvfel/n1ReI96/9z/9z7mLelgFqwjgJCAhNMqAD7v4E/96/w5bSH+jAi514m3d+5I
         iASQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=QtY5LSfY;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id i9si400037vsj.0.2019.07.11.10.00.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 10:00:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id s27so3244126pgl.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Jul 2019 10:00:28 -0700 (PDT)
X-Received: by 2002:a17:90a:d998:: with SMTP id d24mr5929058pjv.89.1562864427900;
        Thu, 11 Jul 2019 10:00:27 -0700 (PDT)
Received: from [10.67.49.31] ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id r13sm7233865pfr.25.2019.07.11.10.00.19
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 10:00:27 -0700 (PDT)
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Linus Walleij <linus.walleij@linaro.org>,
 Florian Fainelli <f.fainelli@gmail.com>, Arnd Bergmann <arnd@arndb.de>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Russell King <linux@armlinux.org.uk>,
 christoffer.dall@arm.com, Marc Zyngier <marc.zyngier@arm.com>,
 Nicolas Pitre <nico@fluxnic.net>, Vladimir Murzin <vladimir.murzin@arm.com>,
 Kees Cook <keescook@chromium.org>, jinb.park7@gmail.com,
 Alexandre Belloni <alexandre.belloni@bootlin.com>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Daniel Lezcano <daniel.lezcano@linaro.org>,
 Philippe Ombredanne <pombredanne@nexb.com>, liuwenliang@huawei.com,
 Rob Landley <rob@landley.net>, Greg KH <gregkh@linuxfoundation.org>,
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
 <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
From: "'Florian Fainelli' via kasan-dev" <kasan-dev@googlegroups.com>
Openpgp: preference=signencrypt
Autocrypt: addr=florian.fainelli@broadcom.com; prefer-encrypt=mutual; keydata=
 mQENBFPAG8ABCAC3EO02urEwipgbUNJ1r6oI2Vr/+uE389lSEShN2PmL3MVnzhViSAtrYxeT
 M0Txqn1tOWoIc4QUl6Ggqf5KP6FoRkCrgMMTnUAINsINYXK+3OLe7HjP10h2jDRX4Ajs4Ghs
 JrZOBru6rH0YrgAhr6O5gG7NE1jhly+EsOa2MpwOiXO4DE/YKZGuVe6Bh87WqmILs9KvnNrQ
 PcycQnYKTVpqE95d4M824M5cuRB6D1GrYovCsjA9uxo22kPdOoQRAu5gBBn3AdtALFyQj9DQ
 KQuc39/i/Kt6XLZ/RsBc6qLs+p+JnEuPJngTSfWvzGjpx0nkwCMi4yBb+xk7Hki4kEslABEB
 AAG0MEZsb3JpYW4gRmFpbmVsbGkgPGZsb3JpYW4uZmFpbmVsbGlAYnJvYWRjb20uY29tPokB
 xAQQAQgArgUCXJvPrRcKAAG/SMv+fS3xUQWa0NryPuoRGjsA3SAUAAAAAAAWAAFrZXktdXNh
 Z2UtbWFza0BwZ3AuY29tjDAUgAAAAAAgAAdwcmVmZXJyZWQtZW1haWwtZW5jb2RpbmdAcGdw
 LmNvbXBncG1pbWUICwkIBwMCAQoFF4AAAAAZGGxkYXA6Ly9rZXlzLmJyb2FkY29tLmNvbQUb
 AwAAAAMWAgEFHgEAAAAEFQgJCgAKCRCBMbXEKbxmoE4DB/9JySDRt/ArjeOHOwGA2sLR1DV6
 Mv6RuStiefNvJ14BRfMkt9EV/dBp9CsI+slwj9/ZlBotQXlAoGr4uivZvcnQ9dWDjTExXsRJ
 WcBwUlSUPYJc/kPWFnTxF8JFBNMIQSZSR2dBrDqRP0UWYJ5XaiTbVRpd8nka9BQu4QB8d/Bx
 VcEJEth3JF42LSF9DPZlyKUTHOj4l1iZ/Gy3AiP9jxN50qol9OT37adOJXGEbix8zxoCAn2W
 +grt1ickvUo95hYDxE6TSj4b8+b0N/XT5j3ds1wDd/B5ZzL9fgBjNCRzp8McBLM5tXIeTYu9
 mJ1F5OW89WvDTwUXtT19P1r+qRqKuQENBFPAG8EBCACsa+9aKnvtPjGAnO1mn1hHKUBxVML2
 C3HQaDp5iT8Q8A0ab1OS4akj75P8iXYfZOMVA0Lt65taiFtiPT7pOZ/yc/5WbKhsPE9dwysr
 vHjHL2gP4q5vZV/RJduwzx8v9KrMZsVZlKbvcvUvgZmjG9gjPSLssTFhJfa7lhUtowFof0fA
 q3Zy+vsy5OtEe1xs5kiahdPb2DZSegXW7DFg15GFlj+VG9WSRjSUOKk+4PCDdKl8cy0LJs+r
 W4CzBB2ARsfNGwRfAJHU4Xeki4a3gje1ISEf+TVxqqLQGWqNsZQ6SS7jjELaB/VlTbrsUEGR
 1XfIn/sqeskSeQwJiFLeQgj3ABEBAAGJAkEEGAECASsFAlPAG8IFGwwAAADAXSAEGQEIAAYF
 AlPAG8EACgkQk2AGqJgvD1UNFQgAlpN5/qGxQARKeUYOkL7KYvZFl3MAnH2VeNTiGFoVzKHO
 e7LIwmp3eZ6GYvGyoNG8cOKrIPvXDYGdzzfwxVnDSnAE92dv+H05yanSUv/2HBIZa/LhrPmV
 hXKgD27XhQjOHRg0a7qOvSKx38skBsderAnBZazfLw9OukSnrxXqW/5pe3mBHTeUkQC8hHUD
 Cngkn95nnLXaBAhKnRfzFqX1iGENYRH3Zgtis7ZvodzZLfWUC6nN8LDyWZmw/U9HPUaYX8qY
 MP0n039vwh6GFZCqsFCMyOfYrZeS83vkecAwcoVh8dlHdke0rnZk/VytXtMe1u2uc9dUOr68
 7hA+Z0L5IQAKCRCBMbXEKbxmoLoHCACXeRGHuijOmOkbyOk7x6fkIG1OXcb46kokr2ptDLN0
 Ky4nQrWp7XBk9ls/9j5W2apKCcTEHONK2312uMUEryWI9BlqWnawyVL1LtyxLLpwwsXVq5m5
 sBkSqma2ldqBu2BHXZg6jntF5vzcXkqG3DCJZ2hOldFPH+czRwe2OOsiY42E/w7NUyaN6b8H
 rw1j77+q3QXldOw/bON361EusWHdbhcRwu3WWFiY2ZslH+Xr69VtYAoMC1xtDxIvZ96ps9ZX
 pUPJUqHJr8QSrTG1/zioQH7j/4iMJ07MMPeQNkmj4kGQOdTcsFfDhYLDdCE5dj5WeE6fYRxE
 Q3up0ArDSP1L
Message-ID: <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com>
Date: Thu, 11 Jul 2019 10:00:18 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=google header.b=QtY5LSfY;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
X-Original-From: Florian Fainelli <florian.fainelli@broadcom.com>
Reply-To: Florian Fainelli <florian.fainelli@broadcom.com>
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

On 7/2/19 2:06 PM, Linus Walleij wrote:
> Hi Florian,
> 
> On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:
> 
>> Abbott submitted a v5 about a year ago here:
>>
>> and the series was not picked up since then, so I rebased it against
>> v5.2-rc4 and re-tested it on a Brahma-B53 (ARMv8 running AArch32 mode)
>> and Brahma-B15, both LPAE and test-kasan is consistent with the ARM64
>> counter part.
>>
>> We were in a fairly good shape last time with a few different people
>> having tested it, so I am hoping we can get that included for 5.4 if
>> everything goes well.
> 
> Thanks for picking this up. I was trying out KASan in the past,
> got sidetracked and honestly lost interest a bit because it was
> boring. But I do realize that it is really neat, so I will try to help
> out with some review and test on a bunch of hardware I have.
> 
> At one point I even had this running on the ARMv4 SA1100
> (no joke!) and if I recall correctly, I got stuck because of things
> that might very well have been related to using a very fragile
> Arm testchip that later broke down completely in the l2cache
> when we added the spectre/meltdown fixes.

A blast from the past!

> 
> I start reviewing and testing.

Great, thanks a lot for taking a look. FYI, I will be on holiday from
July 19th till August 12th, if you think you have more feedback between
now and then, I can try to pick it up and submit a v7 with that feedback
addressed, or it will happen when I return, or you can pick it up if you
refer, all options are possible!

@Arnd, should we squash your patches in as well?
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ba50ae2-be09-f633-ab1f-860e8b053882%40broadcom.com.
For more options, visit https://groups.google.com/d/optout.
