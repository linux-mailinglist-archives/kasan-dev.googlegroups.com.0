Return-Path: <kasan-dev+bncBC447XVYUEMRB27OUGFQMGQEMQ65FZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C249142E146
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 20:31:07 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id s10-20020a1cf20a000000b0030d66991388sf107554wmc.7
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 11:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634236267; cv=pass;
        d=google.com; s=arc-20160816;
        b=nu9vpwioFK4DtCGxPwMguUjvlnODT4/UY07IpYfcUnS+FqKwzBPiZlCzvST+68kset
         jtK1hFleHFx0viStNxqYPeCpB4w8UbOoXcjtyQNUEVvsfb3bXXsOs9TIRMvmSBlhzhKJ
         kLkwun5iU37sc1PGvtzGR4FIYi+zcENuzEwA4YE6ePHl6uyRy3RsERo/nAlE49x5HqQl
         IuMUTGC6VPWxwXcbkvOU7dlvyXqj2KUfiEGDhpNnQkC/tM6mUM8Njy28PdFEv7ibhRjn
         RVWC6cy/l8ANo0CW9lpICL/IZHkuY7UkhcozWRMY73FKacYD756DT8QnuWm+Og3tvM+C
         cUyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=LYhvUdDEmqKTejuVRRk913xYaaSjTU98QvDYxHpKwhg=;
        b=Hn13j8ES1t7MEm3UwzmSvLEIMgkftElHjyYcetHB+NNsMhxgsS5WL1jqS/OayawErl
         w/KFQUUZfb6GQcmm3Hr2N/a+sCe2ueGv+Aq8zAxe1K5mt55B8DFZDIP5Mn/YSpz6/QbB
         iWHG5S0efai/ussx21u0OHZX4wkcqveVIn8hzHuTBYm13NZKmWOHm4DlCbu6oeTEsPi0
         6C3IMZnnuYBd14KrRIKx+cPzgdYmBcC8EJH+mv894WVHd83cO83Y178JPz+7u0qptWyv
         LHmo6Up/FfNt0ALESwMKvF5NGXHQbOkFyafEsAWbBrdZgnjaH9pS8PvHxj5htzxsUK2U
         nBkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.201 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LYhvUdDEmqKTejuVRRk913xYaaSjTU98QvDYxHpKwhg=;
        b=jTVqA9Z0PL2DdifG+ywMxToMn2Kn8uZhrx/khD2KsMp1WqhlRCt9ArSzimiG/HEc87
         qn0yYvBtUR1pAOeNgioIcTViTnuo3UKmN4oWWk3pc+6kDUyIE2Pvpv2G6GBSGecElVkU
         OZq90Oxynhx40JlotWI3aIW1d4vGPD5t66iKTum2PsBaWRdB4R7JOFXGxyRKCQR7Rr6x
         BHiMH5BPdpGSlK6O2DllqzFYJWvIr1dq4o3TTuKImkAzHe1EEwHjiN100/WJws0gCzvW
         pXhon1/UboHqA38tjX7p6rQUmGqXBL78L4UIhhZMPxtTPGU/fyl1c1gZkns0+40KGrym
         thNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LYhvUdDEmqKTejuVRRk913xYaaSjTU98QvDYxHpKwhg=;
        b=vL/Jv3a5tb5jLi2s660XLfy/CnMWslA/kWD86ShDlSJDy0IyLDTUN3LIDhD+3Uih9l
         wftSkhxGmNVtHdmJMiVcV/ax8Xi0IcSA43YWbRVXaD8r7xsAog0sGwS395X6wlWxcARV
         n2+WXa4wBIDETMm9tSVJ/7/hnTYrkcemNh8cEDjjlW2q0vri0Nhs1EWQL/+yfp9T6gbP
         4N9KotCzywcpvRNuWiLUEpVu7uieGvvj0JoUSjZ5v480Dtkzui46vPYLsXQgSXthw63N
         UYu9phaZTv4SQUZHINp6IvoT/Hybufxl3z9HSN4G0vCExGhA4ml7qQ8LdHJ7QFj1AkLP
         WRmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wThd1Hc1VECvmzXEXKnRc2fnzIUfb2VpXyNWvqG/BRGDj8zYu
	Oyzz0eT41wxGx9vfMNpSS/c=
X-Google-Smtp-Source: ABdhPJyl+SgfKrluZFLfMdvc0lR2ZajZFASwUej5IimePKuOssNP6HV1TpTEoADorVFaIHe7DmXBfA==
X-Received: by 2002:adf:ef4d:: with SMTP id c13mr8544345wrp.17.1634236267529;
        Thu, 14 Oct 2021 11:31:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2983:: with SMTP id p125ls5204494wmp.2.canary-gmail;
 Thu, 14 Oct 2021 11:31:06 -0700 (PDT)
X-Received: by 2002:a7b:c05a:: with SMTP id u26mr13809332wmc.37.1634236266615;
        Thu, 14 Oct 2021 11:31:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634236266; cv=none;
        d=google.com; s=arc-20160816;
        b=P78GFp4w9Qcw4JnN7bSrkDo5ksG2V73HMLAxeVCXL5q7txmtg6h/t5zuHFO68vksqW
         pmNzPZj24tSI9NTN/d9fzPtJn834OGMLhDnDTOxckhiyk2HUN4n5zOt80rC6L+AHv2mS
         k/B0ndivBFlKE7yzB04gRN6fzehwCTOkWh0S8io6u3Fa7tG9I7xL9rorzb1oovxk7HJk
         6ATu8PijQF7plOoDLjh0fOdVJNOqSqbhFVbO3Hxq4DmyXfh3R9sSpZg4RJHLfjU7MfG+
         XfHIp+YG0AWn2KBECz3a8ovn/0GQEHuR2FMEzsBC52TvKMLLnwjRYa1Yd6veTYrfKBxY
         B1xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=c9sIGNB1YYKo6jsojgAAERZfJifXh9rg9e1toQNE+80=;
        b=jUH697rgk2dHORsvPyo+9acovtqgNIXsT6BB6B+dPhVcmG0Wb+JPyeh7evp3TzsmwO
         kabtY1q1kgWWIW/kNCwa6jaN4nTOkbRrL++dKQk1qW+F2d2JaiIQ4qRPWEDsjo5oh1ED
         nHD9iqDBhPBwJ9Cb0PCE4iKHGyaDio3eCy5JI7/6PbVKO/0ZmFZh73oG7jjheYMXLVKF
         UwzhM+l+fzZB0IX17PTK0Fyfrwgad0JsbjNTwbYZcMwotjYr7K0dQBh+ZVtcSvBv7axh
         xPSOrlf+XZxlTzB+0iYWiXm64El2NsVlgsiPoZIrjWWbhdZ7QBc8vtCa+lgBwPEdGnjA
         12OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.201 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay8-d.mail.gandi.net (relay8-d.mail.gandi.net. [217.70.183.201])
        by gmr-mx.google.com with ESMTPS id k32si322330wms.2.2021.10.14.11.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 14 Oct 2021 11:31:06 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.201 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.201;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay8-d.mail.gandi.net (Postfix) with ESMTPSA id 9666D1BF205;
	Thu, 14 Oct 2021 18:31:00 +0000 (UTC)
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Nathan Chancellor <nathan@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>
Cc: elver@google.com, akpm@linux-foundation.org, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 ndesaulniers@google.com, Arnd Bergmann <arnd@arndb.de>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, linux-riscv@lists.infradead.org,
 Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 linux-mm@kvack.org
References: <YUyWYpDl2Dmegz0a@archlinux-ax161>
 <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
 <YWhg8/UzjJsB51Gd@archlinux-ax161>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
Date: Thu, 14 Oct 2021 20:31:00 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.14.0
MIME-Version: 1.0
In-Reply-To: <YWhg8/UzjJsB51Gd@archlinux-ax161>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.201 is neither permitted nor denied by best guess
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

Hi Nathan,

Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit=C2=A0:
> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> w=
rote:
>>>>> Currently, the asan-stack parameter is only passed along if
>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET =
to
>>>>> be defined in Kconfig so that the value can be checked. In RISC-V's
>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
>>>>> asan-stack does not get disabled with clang even when CONFIG_KASAN_ST=
ACK
>>>>> is disabled, resulting in large stack warnings with allmodconfig:
>>>>>
>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:=
117:12:
>>>>> error: stack frame size (14400) exceeds limit (2048) in function
>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
>>>>>             ^
>>>>> 1 error generated.
>>>>>
>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed along to
>>>>> the compiler so that these warnings do not happen when
>>>>> CONFIG_KASAN_STACK is disabled.
>>>>>
>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and=
 earlier")
>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>>>>
>>>> Reviewed-by: Marco Elver <elver@google.com>
>>>
>>> Thanks!
>>>
>>>> [ Which tree are you planning to take it through? ]
>>>
>>> Gah, I was intending for it to go through -mm, then I cc'd neither
>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
>>> grab it from LKML?
>>
>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
>>
>> (assuming you still want it through somewhere else)
>=20
> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
> respect CONFIG_KASAN_STACK").
>=20
>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
>>>> comment (copied from arm64). Did RISC-V just forget to copy over the
>>>> Kconfig option?
>>>
>>> I do see it defined in that file as well but you are right that they di=
d
>>> not copy the Kconfig logic, even though it was present in the tree when
>>> RISC-V KASAN was implemented. Perhaps they should so that they get
>>> access to the other flags in the "else" branch?
>>
>> Ya, looks like we just screwed this up.  I'm seeing some warnings like
>>
>>     cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 with sta=
ck protection is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=
=80=99 for this target
>=20
> Hmmm, I thought I did a GCC build with this change but I must not have
> :/
>=20
>> which is how I ended up here, I'm assuming that's what you're talking ab=
out
>> here?  LMK if you were planning on sending along a fix or if you want me=
 to
>> go figure it out.
>=20
> I took a look at moving the logic into Kconfig like arm64 before sending
> this change and I did not really understand it well enough to do so. I
> think it would be best if you were able to do that so that nothing gets
> messed up.
>=20

I'll do it tomorrow, I'm the last one who touched kasan on riscv :)

Thanks,

Alex

> Cheers,
> Nathan
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/afeaea5f-70f2-330f-f032-fb0c8b5d0aa5%40ghiti.fr.
