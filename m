Return-Path: <kasan-dev+bncBC447XVYUEMRB6XYUWFQMGQE6VI2KDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E3DC42F1AD
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 15:04:59 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id o22-20020a1c7516000000b0030d6f9c7f5fsf653382wmc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 06:04:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634303099; cv=pass;
        d=google.com; s=arc-20160816;
        b=QSfG7XmcMPP4I7qt1rTVxEvEZhpBkI8ImyEJrqPLG/W2mabiZsU0mwp7xJu0RQxbnW
         wuWrJ+CPjSBermA6uIkmf94h1HDPoxgv4hp5BbvP6GovRIO5FGoatIJ0qtXlNJH0RF87
         dWINLz2lskoGlUFPxui190WF0IZBTToW6zP6i08NnKJ066nA8o+guIg9LbMCa2t+BS+5
         2My0+yE1fgP/gjVEmLDp5GH52vuD+brHC+1QIz+a0Yuved20D85eKlau5oNcCu3LSon2
         DfD4LwPnSnxxxEWnW0k2KKwXfVkeSJAVvbT3ivNiMqndJuwdMHqnrLlIZTIvKavJbw67
         9piA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=yZxuqgSVHWE/oVo/Ec9xmnmZtiHaq0F/DzU3ODvQzv8=;
        b=I6di7q56NsiELoPRfx7ZXcwomoQQkCdPInAz5IzrhlkznTVcrnD1WMPaBUBmSIXVAP
         afxSFoKCUcwMGln1juhnJJjOFWNK6+ZncPIvecyMqXFMlLqiqvqvfBASQx3zGr5H5O+u
         HiohzXlL9CZLlvJVRoC0wuXyghkWnApdsv8+JOxCqj0MxKzMx3/nLKELDSZyr2EbJm03
         3xwWUuQzSkRPSI0NrK4uso4/onNOlTtsNSivSMCFUgQUzWMBlRDzpH9diKEYV3Sx4wer
         F+Wv9nc5Ghel14aESkGMLfEl/fV5yZG3bxBMyZS0hgM2y6xOyskCarmsXZxzSAvygVnD
         SWwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yZxuqgSVHWE/oVo/Ec9xmnmZtiHaq0F/DzU3ODvQzv8=;
        b=WM1LHBN+9+xdKh+gb1kPQKKLYguwweOxLvj2qtlnbX3G5pqu1NnUifigMj3gLK5KYe
         gXczHDibFm36uOMPLihke4PFYZbhAz1OejR24a7PYEyBqe4Gyy3MIMqnhw8xAu2khSZs
         shkMRYzcBibDktKg+Pn4vLfYQvaToN4nAL1lYpGAtsvwGsAIZjsIxP/w6SdNmR7tZAog
         fxduLoWZsYMnsP00MLY9ZnWPxiGlpHGdc4bbDz4iUwWoqqK9d4MzPEI0CaA/c1zNhXWE
         5kyZAnnS/TWS+9nBU04yTmWo041A/vSLybAptyb24o9ef12LpVCbssDPQrRMx3Ocma6D
         nqlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yZxuqgSVHWE/oVo/Ec9xmnmZtiHaq0F/DzU3ODvQzv8=;
        b=5eDyP+bDMfV7wJknkTfNDN5Y3HDkhS9qXKyjtjhV1djNhd5OmNkXnRpx3ABE/DAg7N
         dVpvkeKIZTFJaHh7jNU7tdfCpKKZOdDKG/dpLbXEI+Gjsoq5SefQ2yD1KWIHVjG01kzu
         5b83tifH+pgywi5HHxWPMNClFFYMDutdsimeW4dh3wROk8344qqzl+8d48SD7HeQYIR5
         fB9TpUnbk2+X5n8BBARsFt1FyGiLMfs60yht1XDXFNiJ3DavyS/F+eoZp3dKXuYLUyVA
         91vaEsullEK5sUsWM4388EcWBD/3Ddm2R85oWe+1ncFIckK0ZuqI1/QBSUAptvn1geN6
         PYUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Glb83vQY0iyql1RZDZ83ZHLybAtbRHkQB1Y1ReAQMNslDRXqK
	6HN88bYoIuVkzFGLcDQZV3s=
X-Google-Smtp-Source: ABdhPJzllA9ziLQtiUR7a+q22zmqQKBLadN4zge3NIVUDEVIAe28Tw7R1MmXHtWLxwt4IfNqvxbOvA==
X-Received: by 2002:a7b:c4c8:: with SMTP id g8mr12358785wmk.101.1634303099139;
        Fri, 15 Oct 2021 06:04:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35cd:: with SMTP id r13ls4310388wmq.2.gmail; Fri,
 15 Oct 2021 06:04:58 -0700 (PDT)
X-Received: by 2002:a1c:2309:: with SMTP id j9mr25675051wmj.189.1634303098227;
        Fri, 15 Oct 2021 06:04:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634303098; cv=none;
        d=google.com; s=arc-20160816;
        b=m/amLsbWijczCu1BrM0ZQTi1fmCDW4SyvoA8JsiB5Mx0FUh0OmDjppEZSt5U1FFS52
         krO7n6yROlfVAojnWkQx0YiS9H/EAns2DgnQm+wjmOtPQrqhsAWjdPY1nygaETMG40uH
         P5q7Q1lmLfhZHUFAxiRZE5gA3JwqCOLu/y0OC+IS6ZmH97lO+Jzud671VBeMYv0OodAR
         mV9iCZV5zNd1SxfMTsU1fdXbWwowKYSHk1858AcpiREEutdXQ4GHBcmEkdFOJcbwlnUC
         TkMIVaBosls3kkIc0NlifzNIJvhKocKQQ8JfO7hsx1ywHgujxawojUm8c373Pdv+mzpx
         YWFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=acOWkHtRjZbKJzBgy7A+CmS93t7WEGIYbwk2wpbgJM4=;
        b=dG6GjCCuZbq7lgju4Z0WHZDfJ5NJJGTvZQcPiRBj24bgkem7OwiWFg1rA2pP+AlQ8B
         kQT8OHv20+99YoJjxNwxvuCwXFVGHZrkQbznWeRyPnR1nTUspd7871foadumx7CxdXJ9
         dc9BbFWdq9dA7A4DwdNq5lmlPWfrYrKmflcLtYBIs1XDyBsBu1RAbOUCSn5u8/UMoa7j
         Mxf7MjjB319WpBhjW8dWKEC1vqSTFat1XjZy6H34/BExdPatHQqeipXGcVxp3hFt/SUN
         tkUbGrUoLD3bGSg7EY16vBzyLYkJMTfHC+MPF7C9b2Gr4+AABg02ifbNdyMx2pMkNehv
         Ld0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [217.70.183.197])
        by gmr-mx.google.com with ESMTPS id f9si1076706wmg.2.2021.10.15.06.04.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 15 Oct 2021 06:04:57 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.197;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay5-d.mail.gandi.net (Postfix) with ESMTPSA id 401031C0007;
	Fri, 15 Oct 2021 13:04:51 +0000 (UTC)
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
From: Alexandre ghiti <alex@ghiti.fr>
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
 <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
Message-ID: <990a894c-1806-5ab2-775e-a6f2355c2299@ghiti.fr>
Date: Fri, 15 Oct 2021 15:04:51 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.13.0
MIME-Version: 1.0
In-Reply-To: <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.197 is neither permitted nor denied by best guess
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

On 10/14/21 8:31 PM, Alex Ghiti wrote:
> Hi Nathan,
>
> Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit=C2=A0:
>> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
>>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
>>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
>>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor
>>>>> <nathan@kernel.org> wrote:
>>>>>> Currently, the asan-stack parameter is only passed along if
>>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires
>>>>>> KASAN_SHADOW_OFFSET to
>>>>>> be defined in Kconfig so that the value can be checked. In RISC-V's
>>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means
>>>>>> that
>>>>>> asan-stack does not get disabled with clang even when
>>>>>> CONFIG_KASAN_STACK
>>>>>> is disabled, resulting in large stack warnings with allmodconfig:
>>>>>>
>>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c=
:117:12:
>>>>>>
>>>>>> error: stack frame size (14400) exceeds limit (2048) in function
>>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
>>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
>>>>>> 1 error generated.
>>>>>>
>>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed
>>>>>> along to
>>>>>> the compiler so that these warnings do not happen when
>>>>>> CONFIG_KASAN_STACK is disabled.
>>>>>>
>>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
>>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8
>>>>>> and earlier")
>>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>>>>>
>>>>> Reviewed-by: Marco Elver <elver@google.com>
>>>>
>>>> Thanks!
>>>>
>>>>> [ Which tree are you planning to take it through? ]
>>>>
>>>> Gah, I was intending for it to go through -mm, then I cc'd neither
>>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
>>>> grab it from LKML?
>>>
>>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
>>>
>>> (assuming you still want it through somewhere else)
>>
>> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
>> respect CONFIG_KASAN_STACK").
>>
>>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
>>>>> comment (copied from arm64). Did RISC-V just forget to copy over the
>>>>> Kconfig option?
>>>>
>>>> I do see it defined in that file as well but you are right that
>>>> they did
>>>> not copy the Kconfig logic, even though it was present in the tree
>>>> when
>>>> RISC-V KASAN was implemented. Perhaps they should so that they get
>>>> access to the other flags in the "else" branch?
>>>
>>> Ya, looks like we just screwed this up.=C2=A0 I'm seeing some warnings =
like
>>>
>>> =C2=A0=C2=A0=C2=A0 cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=
=E2=80=99 with stack protection
>>> is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=99 for =
this target
>>
>> Hmmm, I thought I did a GCC build with this change but I must not have
>> :/
>>
>>> which is how I ended up here, I'm assuming that's what you're
>>> talking about
>>> here?=C2=A0 LMK if you were planning on sending along a fix or if you
>>> want me to
>>> go figure it out.
>>
>> I took a look at moving the logic into Kconfig like arm64 before sending
>> this change and I did not really understand it well enough to do so. I
>> think it would be best if you were able to do that so that nothing gets
>> messed up.
>>
>
> I'll do it tomorrow, I'm the last one who touched kasan on riscv :)
>

Adding KASAN_SHADOW_OFFSET config makes kasan kernel fails to boot.
It receives a *write* fault at the beginning of a memblock_alloc
function while populating the kernel shadow memory: the trap address is
in the kasan shadow virtual address range and this corresponds to a
kernel address in init_stack. The question is: how do I populate the
stack shadow mapping without using memblock API? It's weird, I don't
find anything on other architectures.

And just a short note: I have realized this will break with the sv48
patchset as we decide at runtime the address space width and the kasan
shadow start address is different between sv39 and sv48. I will have to
do like x86 and move the kasan shadow start at the end of the address
space so that it is the same for both sv39 and sv48.

Thanks,

Alex


> Thanks,
>
> Alex
>
>> Cheers,
>> Nathan
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/990a894c-1806-5ab2-775e-a6f2355c2299%40ghiti.fr.
