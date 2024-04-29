Return-Path: <kasan-dev+bncBCSL7B6LWYHBBFFTX2YQMGQEZGSSNZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0604E8B5938
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 14:59:02 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-41c05870db9sf1962575e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 05:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714395541; cv=pass;
        d=google.com; s=arc-20160816;
        b=haqhHjV6IJHKZsB6TfyTK1zKgXbyQemMcBNG1lmJ3inf2o2UkD8r/lo0afVmQPgK2f
         exyB2TqyVLoPDIWFLgmas3tGValtfxQXSOYJFxX150pUTDRAuel9Ip9lJi97wHj1wHo8
         rR1mTCECnRSo5GphCDmKkkARXtbMuu1Z14GWq1qRLIhGIlTQpC7xmPbABgpxPShZLIHS
         3JjikylAme+taHAVWhFDkRtnyv5kSddT1ltQDBdm9mj1dDSGnVcKKshpmwrzHPwtnhrk
         7xrIy1U36FSL8rzpRqHoy+9ErqKYCfef82K1esmpyHfkfpvHYuMhTM2GowDRJE2/mgA4
         g9eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=vwOf+TJiVn8nr6sx9Y3bTvYulOf/tExZ61rLeMjYGFc=;
        fh=AwiGPgKC09clQ2v5J7vWyyGQcI1DpUnbOsIUv6wUEXo=;
        b=PYyk50G4EtNp00d3QybL7GMRFeDDQnsiEUmDzm1VgzBHRqsKU7JrCYOJBU2WZwm5tD
         5o3YOyTlMfjiI/tXm/9FdS2Rw7olgANYj6h8WEcraToaa8VSKmGghBODQ1QQcqzkKMUG
         L8b+rA1mb+OMmCmekp7QaHBgkfIxzAAqtPVuaX7LgrEuZfB9SvJ7kwL68zGNgt3QFXpB
         3NYhpQyzLj2DycYHHf3t6Hcil323+H3j0eEr4XM5JIUHFRS3cnBy3Cz1ntDfS0Wig62t
         BR42W/KjpCTLqHdFZLwn8z+xg1D/zAr0Pt3oSrEwNu3yEr0G1yAuPwp55/dIhJgvMhvD
         tCAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jpa1ptzQ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714395541; x=1715000341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vwOf+TJiVn8nr6sx9Y3bTvYulOf/tExZ61rLeMjYGFc=;
        b=rWPdXL3qUyqV/4Q+NiS7VnsMOsae8FD6oTFt3Y3Nkgply/ti67YDnTqFYGysQH6dfb
         Z02boACfnc08quVeHm+i+jMBumcW3fmDOeF8g2QFSyqk+QSQnjzd2DphZB99skgIHG9H
         i4hoNgIqQGfRufoClRWoVWbzgAb9LbL56jwWQzgl8ohtbXKL8sK3LTJ5jJczpliKRl5n
         eVJpDNp2HqUOqxVtYswK9VIcdEXDdu+HvB7B19frj/tZXlZ8Wjdx85S6ZWYfRcR4tYdh
         AH/vdnUcD2LAzEfZOlPP1hs38fEEu2psC6mXTQsr1APrmbN1fVA5Qx4UXXSWfHIT56zx
         kTuw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1714395541; x=1715000341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=vwOf+TJiVn8nr6sx9Y3bTvYulOf/tExZ61rLeMjYGFc=;
        b=MUVc3kK+95x5RH/B9quM7HLW8Ea4LuSLtvIk8ShAyMz7IHBizmTElOOWEH1/Q6QwYJ
         xHZRIcukE39UBN3SwUybaIYN7mDLQvJFamvKXcccpe38xd7Pdr5RCgTW8VcM+EbhcnfX
         X69NYIMOORUHgL1/WbzT7I3EixHKhf5OQJUqS/CZK+66YHlNnDKuvFU8noshRlLeuO1W
         6rTmjC5v9lHOEULfuD6HYAaI1VxO0NJAbXa1Fd9Dp1+lqBkwM2/lBgGMW6fhlZ1UJXlH
         voEHx+qd/TK4IZ/5Vr+pQczfiHfsYomENf6rjFCehzjfdQSs7kbd4frHjR6sZneDFQRo
         CQPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714395541; x=1715000341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vwOf+TJiVn8nr6sx9Y3bTvYulOf/tExZ61rLeMjYGFc=;
        b=fbnv4X+2mm3S7nPgyiE7f1DiUNIGvDf/of4LBDGnAazYCJLK2HO/3Z/fDM+m/odslZ
         ZpHYslfeCFq4xNst7OVFhV515y+sf/H0dNBKzOdrVL4g5RiRuDZVOyPQ0LHMQimtcWRC
         CgIcCkzJox0X8P9m0xRxe9WwY+2hosb/LTCs4KdxIf3izgRMEMzcoVjeFZYJH+Xf8193
         CuTQ+kt2+foMxyvXbVBXWnpW3oiUI84yaKUuTPOOQAs3SUlttS+hDHWTfDgCynvv3zwu
         nFcp6AzbD7z134fzuRfucw9e81YlBC3oFCDIfLp/F9MO6p74Y/g1RNBdW/VwdjaWauwp
         uOZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAmpbjPYa/RlyWdYry1pITD94UuKGWesezwPuIt57Rm3OFxSCoo4r71FjJmfdk6uWWKyybvTx5DbJXNt3f/uXtfaiSltX4OQ==
X-Gm-Message-State: AOJu0Yy7WWQw5UD7T8bccoz7hA9t1ES64krhvmvGoFUDjefhSp5ddtuK
	LDMLXpZQxk8CcmPWJ6Aikh+rbX/u3uT8JVtuEOIzQm0wX/EabRNo
X-Google-Smtp-Source: AGHT+IEJCVpgp+vmmmvoD1za73MZjZq76puCbOnp9EqdFH+5xWhluW/YPlo73ayaG9BaTkZ/5diuPQ==
X-Received: by 2002:a05:600c:470a:b0:41b:ff4e:c8a4 with SMTP id v10-20020a05600c470a00b0041bff4ec8a4mr238183wmo.0.1714395540647;
        Mon, 29 Apr 2024 05:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c29:b0:416:51a2:5f53 with SMTP id
 5b1f17b1804b1-41b2f9adeabls3220435e9.1.-pod-prod-05-eu; Mon, 29 Apr 2024
 05:58:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/cnkSLTNw8vatxK3rvSW03RJ0+lWa7ZyqLDm0BgD9qO7+zmCx3mhoEoR1pZQKYaKQu84+0uOgGlIdUhZ6JJQ//484WeAX8d4W5w==
X-Received: by 2002:a05:600c:4f07:b0:419:f911:680a with SMTP id l7-20020a05600c4f0700b00419f911680amr9081251wmq.1.1714395538492;
        Mon, 29 Apr 2024 05:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714395538; cv=none;
        d=google.com; s=arc-20160816;
        b=OF26cWBcVQJHABTb1JjT5ORf2N3a2/YYAISEYkjaG1BrApOmJKCUUh5468T8HZ+13I
         l6Sqbu7vAxJ7vLsZ2AJW5IQLOnny+utEXEIsE/2IA4j9FvPDvMPycsp5F9793UyjuYMR
         +HyqDIFL8wbYZ3S+61XgRO66/99rbnNtYhzKBmagqra8ZGDxF6qBOsHe/GqOvfYtHtZj
         /e3fylWany5hRhLFz2fTprLOE1/IDevdX09vCsH+XCPs/y5hJCC9U7NNIM+4mipVPzgV
         kgwSasbWVWoAG4uxInWJ3PaJJrRqKQIUc+cd9dgfO6YIpE8Nqt4X1AbwwArbTkZwbcQW
         QomA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7EKWBgytODZQU31rywUVJiOdjv7GH+YZfkGd8P3Apls=;
        fh=ZEfiw0PbTnJD9GbVM1gTBf3ApAq8pA3zXMxK4UmrxJg=;
        b=iN8yvCCyyc373pitNkSQ2Hrqi3HU2wHQaEJEF22svnmfYz7vfyIAfFTPEFv6Y3eFep
         f1Lte9jHYnA3OeGIyn3aPsSiDzz3Vyrs9IEtcrSjO6sZsHpRckSL/ifm2I3tud1b4w14
         Pm1Rr4C6H4VxyNRjcB8f15pVm7gz8zcyd5142PrMqtZR+kmRF8Aw+epdkIW+yKRzebnG
         eOA3gtxM0WuVy1JJg/jzI22i2JuctYxg7GKlTUGNrWl3hWf3FJgB70vnHyfPjuJIXFga
         XNcZfvVSx8xiirSjF3cnSnYhlqBfwU/4rND+kx32sgLZlNCxwjcJRH/f2QNLCadQtDRT
         WElA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Jpa1ptzQ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id p3-20020a05600c468300b0041c42b455e2si79926wmo.0.2024.04.29.05.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Apr 2024 05:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-51abd9fcbf6so7311398e87.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Apr 2024 05:58:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/DgEy0YyoqjSAKGPEHohLB9/jSXOv3tIHgxk3xBpdP73/EcMN/fgTV5ETFymt2wlTMmvEcLjQ6DyMzXfmg1v8QzV2EOHFnvTbuw==
X-Received: by 2002:ac2:5b9c:0:b0:51d:3acb:1d8b with SMTP id o28-20020ac25b9c000000b0051d3acb1d8bmr4865274lfn.62.1714395537432;
        Mon, 29 Apr 2024 05:58:57 -0700 (PDT)
Received: from [10.214.35.248] ([109.245.231.121])
        by smtp.gmail.com with ESMTPSA id v12-20020a056512348c00b0051af75b5b93sm3037276lfr.226.2024.04.29.05.58.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Apr 2024 05:58:57 -0700 (PDT)
Message-ID: <f90f5352-30ed-419f-803b-7885b4298868@gmail.com>
Date: Mon, 29 Apr 2024 14:57:35 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
To: "Russell King (Oracle)" <linux@armlinux.org.uk>,
 =?UTF-8?B?Qm95IFd1ICjlkLPli4Poqrwp?= <Boy.Wu@mediatek.com>
Cc: "linus.walleij@linaro.org" <linus.walleij@linaro.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
 "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
 "dvyukov@google.com" <dvyukov@google.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?SXZlcmxpbiBXYW5nICjnjovoi7PpnJYp?= <Iverlin.Wang@mediatek.com>,
 "mark.rutland@arm.com" <mark.rutland@arm.com>,
 =?UTF-8?B?TGlnaHQgQ2hlbiAo6Zmz5pix5YWJKQ==?= <Light.Chen@mediatek.com>,
 "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>, "glider@google.com"
 <glider@google.com>, "matthias.bgg@gmail.com" <matthias.bgg@gmail.com>,
 "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
 "angelogioacchino.delregno@collabora.com"
 <angelogioacchino.delregno@collabora.com>
References: <20240410073044.23294-1-boy.wu@mediatek.com>
 <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
 <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
 <292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel@mediatek.com>
 <Zi+Vu29rmNZ0MIFG@shell.armlinux.org.uk>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <Zi+Vu29rmNZ0MIFG@shell.armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Jpa1ptzQ;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 4/29/24 14:42, Russell King (Oracle) wrote:
> On Mon, Apr 29, 2024 at 07:51:49AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=
=AA=BC) wrote:
>> On Sun, 2024-04-28 at 15:45 +0100, Russell King (Oracle) wrote:
>>>  On Fri, Apr 12, 2024 at 10:37:06AM +0200, Linus Walleij wrote:
>>>> On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com> w=
rote:
>>>>
>>>>> From: Boy Wu <boy.wu@mediatek.com>
>>>>>
>>>>> We found below OOB crash:
>>>>
>>>> Thanks for digging in!
>>>>
>>>> Pleas put this patch into Russell's patch tracker so he can apply
>>> it:
>>>> https://www.armlinux.org.uk/developer/patches/
>>>
>>> Is this a bug fix? If so, having a Fixes: tag would be nice...
>>>
>>
>> This is a patch for cpuidle flow when KASAN enable, that is in ARM64
>> but not in ARM, so add to ARM.
>>
>> The reference commits did not mention fix any commits.
>> [1] commit 0d97e6d8024c ("arm64: kasan: clear stale stack poison")
>> [2] commit d56a9ef84bd0 ("kasan, arm64: unpoison stack only with
>> CONFIG_KASAN_STACK")
>=20
> These are not suitable for use as a Fixes: tag because these commits
> refer to code in another part of the tree that has nothing to do with
> the BUG() dump that is contained within your commit message.
>=20
> I ask again... Is this a bug fix?
>=20
> Is it a regression?
>=20
> Is it something that used to work that no longer works?
>=20
> When did it break?
>=20
> Has it always been broken?
>=20
> Has it been broken since KASAN was introduced on 32-bit ARM?
>=20

Yes, this is a bug fix and it has been broken since KASAN was introduced on=
 32-bit ARM.
So, I think this should be
	Fixes: 5615f69bc209 ("ARM: 9016/2: Initialize the mapping of KASan shadow =
memory")

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f90f5352-30ed-419f-803b-7885b4298868%40gmail.com.
