Return-Path: <kasan-dev+bncBC447XVYUEMRBY5A32AQMGQE7FTXENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 408A7324F8C
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 12:56:20 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id n25sf2323277ejd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 03:56:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614254180; cv=pass;
        d=google.com; s=arc-20160816;
        b=iWJcR9bAUODB1+xaxZzxh88+69E2/vfKZJZCGcgqyM6nq5GVrqUO43PHHJqewbB/+N
         /fLtLlD2kBSaDpsiC3TYMQGRsQwP/0fu38jFNbo9qyyOD0tSvLDyu9rCCXG30wGgGe9Y
         UdohlOVtIUDw1eFJO8I6GVj7DEmCcH02CDDV7/IfbyD1kNmFR0HA9Io8+myw4MlQibMw
         iq7kCveD9zSICQhZ0CQdYUY/GvkD/J0n1FvJD0X9RwBxQ4NzuPAJyVVTV1E+JsIIkmWY
         /OJBC3di/cL/eniS/plxofaTgGFpnohnSaBHk+sqrCiwdWeEyaaZ+vQ56ehdapfQjZiO
         JIaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=C8J6Mufi82gxlYGbOVe0dsAXmYlVOqe74I2dVFsEYiA=;
        b=bAWSFb6saD1nzcb6t5ZBLeusZByZmdbQGkmLdmHmmJCfPNznIr7fN9FjlK7YOeqXsY
         HmYHB4qoZ64J3lPrUHIDSObrAjuvOnY9wAQhBJeLAOPMXIAoZoxucUWgeC7Vm20GRK5z
         7c1TIp01sinV+oqcMatUIfpUVTScpEbkK5IyTxIK4v7oIEPvt7yRQ/xEFuhQADV27tbX
         M+z/Z4ou3UBACZseBFfiXrwHI0WDSRoWRifPrtjF5es+goLqn92EmDYnpW8iyZzTWpcn
         9bpXt0/Zp1/pv3+4kAzFnS6/bgLmSv5zpnFd4vR3Whqi7wQMa5vk7b14XL/vn7Nm8NOf
         QfnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C8J6Mufi82gxlYGbOVe0dsAXmYlVOqe74I2dVFsEYiA=;
        b=fdHvVA106dcI1gHXolsP94G1V7Y9YVzKnIal5tNtnRwE2BWVj3PofnOmgULQo7ygW8
         mFYaFjwjueITJ6h/zJJmeGsSnBeyQPHi0La6xb+2z+CQiRDfw235MLMf7IkaHHvP+E+Q
         i/9upjwwDWfFfQK3BzxkGv9wNJPxVoy+r+iFDhXyFqq69UYw+dCOIjX7hs00kCQ/gNGg
         XH0ezi4PxUsyQIYvVTmUg/cVA5Rf61bHRlyxkdfXVXb5KlJeFFbkjPeHjVWkICo1+k1v
         EM7rscTs4YEHpMQuxXTw60pmX6lCZGcqVHyx+fUO2sHnPbzILoBJLXMTJqkV4XJ2WI6i
         F4ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C8J6Mufi82gxlYGbOVe0dsAXmYlVOqe74I2dVFsEYiA=;
        b=Hr09p9aFw47rLHM3wYSwgI+RH5yjE84DtCrpETOQ8SefZhi9b9V9qE9lU1Adj6qx7V
         5shZpBXZGWIOsz6jnxuIaGJhZ1v2/s/uyqwF6ZId/OUXAFQF3TVPdURFjrhV0g0BsfWY
         /a7KkgGKxf+E/NG436VoZjvLghuyNy3ClhSHLmVOuY0Ef3KAvinWxGR34MeRPBZ8zKch
         VYLdYBi78ohPwxzkmTB0ROaQmIx/QWkKZl8+I296ls6j35YADkZ9ges0/YX5gx3TRS3T
         6uzGLgLWkvm/r1hKJeczyBoQwArMv0f6ysb/cUi0UycbPhpNfEgaNcTTbyzz7OM7q/iW
         47OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531chzg2jvRrcTCqvlCyWUYy7APelrpmab/IrBmXaaKE+tNCgyQg
	RNKouOjejxc+9+4eVBKCfI8=
X-Google-Smtp-Source: ABdhPJwc7bWpyK8KWtz2gtflvfcLJgWGDU+ldBARlHeRRBerdM54MJbi5EnPg5OLRepssBtdc7xf2g==
X-Received: by 2002:a17:906:1cc2:: with SMTP id i2mr2403166ejh.320.1614254180023;
        Thu, 25 Feb 2021 03:56:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls578047edx.0.gmail; Thu, 25
 Feb 2021 03:56:19 -0800 (PST)
X-Received: by 2002:aa7:d295:: with SMTP id w21mr2501953edq.159.1614254179132;
        Thu, 25 Feb 2021 03:56:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614254179; cv=none;
        d=google.com; s=arc-20160816;
        b=zkNEBktzbjx1pz6kin/2nkfqCTqA/rSlwAwxcjrIFAzgjJdMZ6YyQdDRUgTDDuim6+
         MMXZX0Nhf4ZYPM4knTG5+NIn8T507HVnKHH4rEnhkvQZ9jlaF0R8bi5VrFZ8bTLGOXo9
         Nqemzb8BpY4gyWKCPzeXHfnS2myHyiJXn1ZyIAKL+AE4TK0KaPgqxv4mCqQkICh5Vz2K
         BrBuj14GqmT5VuEJuBe4V3UIVpOEUOch5DZ+WNTpd0AMsECRycnXYTaPpbPIqj4G+jBO
         QP5N+SDVO5lOTqn8GqHfF8N29h3k7AmXbiJqiKtqP8sRDpNE69TDRY0I1CYAZInIstR6
         bhfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=zwduXP5vUYpN7zzbGcf3mAgbWi8/OXQBZa0aHvNuo50=;
        b=nkx9UCx13ThIuHSDWfI0hhXOGrputadP9KfgVZJw2dJxigp4HrhD1SoCc4bOFUzg4U
         Ow6G8+fe3RvN5FLLzM/XnSN1Uf7QhriVh1m1zHu4+EHON9ho4wjwEKImOb/WBwx7fG0P
         t/QvQ0NCaysSFIzlZdcWdEa0s3Qw3ZldIU6p9hImwC3HvA/A9LVEyBdMpLq1NHi39lMf
         guJon8TOyw6WCCrCCuR3SS8yeeT9IhqZWeo8Vfb9zUIFBtBBOpo+hIgh2D/PSLy0a6BA
         wbDYcSXguvQ7+u0b+pRGN1zDfe9W3pQlqomdHQzIlEbGrNFovhTVE4sQhdRZv6n0sqxM
         1KPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id c12si250094edw.3.2021.02.25.03.56.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Feb 2021 03:56:19 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from [192.168.43.237] (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id 85E2B200008;
	Thu, 25 Feb 2021 11:56:12 +0000 (UTC)
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <20210225080453.1314-1-alex@ghiti.fr>
 <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
Date: Thu, 25 Feb 2021 06:56:11 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Le 2/25/21 =C3=A0 5:34 AM, David Hildenbrand a =C3=A9crit=C2=A0:
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |> +=20
> ffffffc000000000 | -256=C2=A0=C2=A0=C2=A0 GB | ffffffc7ffffffff |=C2=A0=
=C2=A0 32 GB | kasan
>> +=C2=A0=C2=A0 ffffffcefee00000 | -196=C2=A0=C2=A0=C2=A0 GB | ffffffcefef=
fffff |=C2=A0=C2=A0=C2=A0 2 MB | fixmap
>> +=C2=A0=C2=A0 ffffffceff000000 | -196=C2=A0=C2=A0=C2=A0 GB | ffffffcefff=
fffff |=C2=A0=C2=A0 16 MB | PCI io
>> +=C2=A0=C2=A0 ffffffcf00000000 | -196=C2=A0=C2=A0=C2=A0 GB | ffffffcffff=
fffff |=C2=A0=C2=A0=C2=A0 4 GB | vmemmap
>> +=C2=A0=C2=A0 ffffffd000000000 | -192=C2=A0=C2=A0=C2=A0 GB | ffffffdffff=
fffff |=C2=A0=C2=A0 64 GB |=20
>> vmalloc/ioremap space
>> +=C2=A0=C2=A0 ffffffe000000000 | -128=C2=A0=C2=A0=C2=A0 GB | ffffffff7ff=
fffff |=C2=A0 126 GB |=20
>> direct mapping of all physical memory
>=20
> ^ So you could never ever have more than 126 GB, correct?
>=20
> I assume that's nothing new.
>=20

Before this patch, the limit was 128GB, so in my sense, there is nothing=20
new. If ever we want to increase that limit, we'll just have to lower=20
PAGE_OFFSET, there is still some unused virtual addresses after kasan=20
for example.

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7d9036d9-488b-47cc-4673-1b10c11baad0%40ghiti.fr.
