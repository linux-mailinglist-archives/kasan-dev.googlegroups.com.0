Return-Path: <kasan-dev+bncBCH67JWTV4DBB5GTTXUQKGQET6HJSRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9200865DFC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 18:55:16 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id c18sf1662243lji.19
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2019 09:55:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562864116; cv=pass;
        d=google.com; s=arc-20160816;
        b=spugYs8HHn6m1DP4zhuzjOyfl7h39vFwJNO8wfotbXgYeaEN12eMZG3mK5Npn4F6PB
         XyK3kPIF1QSu9nG+JUmMTJYiq6Mg4K9QKFcL4A6sv0xnf4KFYlwOlAv/mdD/VVm+m0BK
         +eiE253pNP5yMi4ZGxu90ayIjgOBf3NGqhK2ielKq4dlOfqwH1ywhowFCH/SzUzLb9ZM
         XIJWu+JKGNLSJLM+TdoqgIkQ8c9ScavnKTEmcm9jlo8nZeCm32CGaLhPraaQKk+DrgSE
         b1lJn3DLg09uUqFx66Aikbwm6yVBHGOBd97vxlaNqVzD1wPgi/7bAMAq8MyG4IQ0JT0f
         u8hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=gOKJWniSQuJAf5edsxfo4+3ga8+/BPIgQOOIyIkgFNc=;
        b=lzcJr11u0tfQjsOv/kFO3fU44IrCkUr6Bxd6nS0M2gHnPlnqelMkWo+0EzpZ8+tihR
         ZE1SXgFq1Z0y1iHm6DQ7o+3UdyXpTLc/BH2WazRjaTRWzlQVgSNXd3j6NT/pP5ke6RUh
         kbeS4RzJhxG8za/V/PhBDlE8BwIO+rvgMYwiij2NTz4elttTqTjpZ2UoFLmpOKQTeNX3
         qzVptihIWdT0UeX3c8chd4mpoLNgN1NyeZv9UYvJr9wQij9wgO3s2q9DrHwvR4hI4t5+
         xYRUg9HttGCa0bKUQqewzekWy5b/5h8W6/kZcu+1v4waesWLxaQAfxKc0foWWZ2v07RF
         3+4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oFX9gEXD;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gOKJWniSQuJAf5edsxfo4+3ga8+/BPIgQOOIyIkgFNc=;
        b=Ibe9KFCmERICPTGxu1ljGekWlk5WvvT9JS6RzpdUOA5/uIR1VUZ0EidA4iliqzjNN+
         2JGLPEgZcO03IjcY+9IkOYYQdZozHamO0gIZqEX91cQby8kBbsELD++Hh5u+CFWw+3QZ
         9CP0vTElijOS/6oXIUCoMZkoJLRiF970ewYLJOr/pQH3MVfrMucgohvsX79TONsM8up5
         R2SJckn3WyHIZn/FUsaW1t/uCDPUf8610nbmYtc9uVlkAnD7UGjc/iuoodgez4WIK0mJ
         WQFgGmHrtnh/Y1escBTj6hQ9c2ZUkSChIdPe3coT4JQMAMAzDqIMMq7xcD5BiltpBW9j
         k6mA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gOKJWniSQuJAf5edsxfo4+3ga8+/BPIgQOOIyIkgFNc=;
        b=khNlBiBYL5WnpaQ57a63GNY55YZ7BjeC3a0pN/DppmvHSd7ORQKPwHXGdP2DOg6O5O
         RcsKLJ5sBv9xe3eC1+7tSUx2DL+Aq186YC0IQ52+yZ9u69qNcjg9mUua7Ym40Lf8McEZ
         X2yLM1EbEmQ2+KMM+8NNqr3LwVxrZFYZ4ciNZhwR3Kopm6RYjP2o8V0YvbJ1bqs+z0pk
         iNitbgYWIkDBDaiCtb0pfpZTSzDN0sve1OHzA1KtX/taBC7kFwv27qKg+4idQDNWH++4
         LZgayEtISvRbSyA/W+6afus362wR+RK2q7kBtMeUo5yCRlelRP73jDUAXYK4VrtQSvEU
         flzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gOKJWniSQuJAf5edsxfo4+3ga8+/BPIgQOOIyIkgFNc=;
        b=tokUTF+k2ZdLweNa8D8DhMCBrX+/r4JboH2SBSy9iOO3MzV+aUHsmiIE3GWnsPX8mY
         943CiCOxozQIVJmjYtnkEFLMhOv+1sPcnrUm2Hfgf9aExy6x/wdxVOQ/day+bEYDiKvn
         L77Nt+aMXRxbijje6LLYTo4wpWvNpEgpKvGzj08RGP6QxaUXX4CwgQC1kpL7VOrqArQW
         Od6YA51QJdrezYe05sAf+wy0wjfrQkHJfHF3XRaLIDHCFWwAar43cEOQk+dMR0CrWS1F
         Aa9zd3VTxboGo/uoBYHBzQyJ4c8K05qptrUEZBK0MHpGu0jmhgdm/0jPbOjCrFgQBawZ
         ubMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3oABdGkdbRoIPRC5tPVr3WTgRpXYb17eg+QjsdU427imDAi0p
	swL5PG2BMBQbox+i+hs7Hjs=
X-Google-Smtp-Source: APXvYqxVPCK6W+g+SKR17PY+NqDfr18E9kNjJkyNxO3DeEl+fcQCqveR7h1kmjjxmZJYnIxHYIFLeQ==
X-Received: by 2002:ac2:4ace:: with SMTP id m14mr2171527lfp.99.1562864116100;
        Thu, 11 Jul 2019 09:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9445:: with SMTP id o5ls813620ljh.9.gmail; Thu, 11 Jul
 2019 09:55:15 -0700 (PDT)
X-Received: by 2002:a2e:87d0:: with SMTP id v16mr3219185ljj.24.1562864115524;
        Thu, 11 Jul 2019 09:55:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562864115; cv=none;
        d=google.com; s=arc-20160816;
        b=cWO20CsT68YbFqybqPEJ/JgEpxOWoo0540q2fWg1LwvBGGnX7KGGoWjIXwiY+skya5
         lU08DGCzLDTWoFhRMJ249y4gaVTXl5D1urI5Cuf+EtdKVCdxitUIKNJjsPCZ2Ygi0l94
         qQL5cb7uL/wPXWUkGMTZq7wF7dxh5jEh2cseEefeEpSIbWhGgxuhmVgpl+ctyMRZv1Z0
         hZG0UzBIKzVJ6dnqKk8MPHT5VhXiiE6x1JcRY2Flsu8nKyyR8ABto0zRlcJIzbLkm+b5
         y/ohyWA1/VdL2nvfFPHoNKHUn2NbPkPxsLFrU0l2i5OUP+p2NcA3vkNlVjxklpfOVhjD
         VsoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=cW9evuaNHUhu3xKoRblEDbGLej8PzYak53HB5pCVWjU=;
        b=uWZvsNW4V1ENa3p6S7hOSSQOS9VgpsaFSs3wS0XIJQE+jDKzSutcrdtwsixCpi2TF3
         nZdldrwvNkQC5Xug0AvjUWSicHn3joTS1QLR0jWq3xsOERY7YiKEdEutdyvQNdmsBEdN
         fZDwWhiUYUKuQazvT4KCeKRPeT3ZcQ3UAzV00+hF+1g1qPg0DNMmkp7wiwdpMAZLDXAD
         yh4rwq4LOCcJpxxzMGnad2MPCXS/w4Lf2JaWQaxTqv/R0Jcg5QER/FBl3u0a8Zwm0K4n
         79hDG+tHOYJxoKgAJQYxj2jyCSaFD7c17zeq7UmLZJb+bk1zskibskgrH1VRm5wnZQdT
         NVwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oFX9gEXD;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s14si412229ljg.4.2019.07.11.09.55.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 09:55:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id j8so2982516wrj.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Jul 2019 09:55:15 -0700 (PDT)
X-Received: by 2002:a5d:4a46:: with SMTP id v6mr6165469wrs.105.1562864114874;
        Thu, 11 Jul 2019 09:55:14 -0700 (PDT)
Received: from [10.67.49.31] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id n5sm5189493wmi.21.2019.07.11.09.54.54
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2019 09:55:14 -0700 (PDT)
Subject: Re: [PATCH v6 1/6] ARM: Add TTBR operator for kasan_init
To: Linus Walleij <linus.walleij@linaro.org>,
 Russell King <rmk+kernel@armlinux.org.uk>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
 Abbott Liu <liuwenliang@huawei.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
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
 <20190617221134.9930-2-f.fainelli@gmail.com>
 <CACRpkdZGqiiax2m5L1y3=Enw0Q5cLc-idAQNae34uenf-drHDw@mail.gmail.com>
From: Florian Fainelli <f.fainelli@gmail.com>
Openpgp: preference=signencrypt
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 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
 M5kY0ACeNhCZJvZ5g4C2Lc9fcTHu8jxmEkI=
Message-ID: <0ad02a64-9470-936c-1db9-0079c0926cfb@gmail.com>
Date: Thu, 11 Jul 2019 09:54:50 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <CACRpkdZGqiiax2m5L1y3=Enw0Q5cLc-idAQNae34uenf-drHDw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=oFX9gEXD;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::443
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

On 7/2/19 2:03 PM, Linus Walleij wrote:
> Hi Florian!
> 
> thanks for your patch!
> 
> On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:
> 
>> From: Abbott Liu <liuwenliang@huawei.com>
>>
>> The purpose of this patch is to provide set_ttbr0/get_ttbr0 to
>> kasan_init function. The definitions of cp15 registers should be in
>> arch/arm/include/asm/cp15.h rather than arch/arm/include/asm/kvm_hyp.h,
>> so move them.
>>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Reported-by: Marc Zyngier <marc.zyngier@arm.com>
>> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
>> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> 
>> +#include <linux/stringify.h>
> 
> What is this for? I think it can be dropped.

Indeed, that can be dropped came from an earlier version of the patch.

> 
> This stuff adding a whole bunch of accessors:
> 
>> +static inline void set_par(u64 val)
>> +{
>> +       if (IS_ENABLED(CONFIG_ARM_LPAE))
>> +               write_sysreg(val, PAR_64);
>> +       else
>> +               write_sysreg(val, PAR_32);
>> +}
> 
> Can we put that in a separate patch since it is not
> adding any users, so this is a pure refactoring patch for
> the current code?

Sure, that makes sense, first move all definitions, then add helper
functions, finally make use of them.
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ad02a64-9470-936c-1db9-0079c0926cfb%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
