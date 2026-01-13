Return-Path: <kasan-dev+bncBAABBOGYTHFQMGQESUSRZSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54D62D1A0E9
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 17:01:01 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b6a97e566sf5672531e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 08:01:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768320061; cv=pass;
        d=google.com; s=arc-20240605;
        b=C11dPC3al8cQRzJFtJQQPos2sLG7U9M+t3zWIuBpldqX6tX37NxlJ2mV8Pu+nWgcul
         mEryS3TIfKjmEpCx7qMBB7Ehd+/dlkXQSIzvG5s/WAeSIZbBJtILdtBeKX5rZ7bEmDvH
         Umukr30YaSa3EfL+82zP1npGurXZeD5ZmUlSV0uvOa+jqBtAHRks7UQu3sH0N03c7Vbk
         CMZy3Z2HiHrXvxnBcV6pwrXXx8kZpl4Vb4xsDEKySkaem8linQUlXFeGAqgA2ccwTv9b
         D58FbKT1lvZEoun+hX1Tt0DCC7c+D2cIzyU9E6ieNk2Ph4GSYwXrT48TWJPvoNbKK2OV
         6ELA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=mqfpXLhHOVa2LPkC9Neos80meqTEsR6PNeNE0ZAl9S4=;
        fh=NWtvVocBS9PNnpm/VkpIWZrJEm0qjf1WaKHl4TtSxj8=;
        b=Y0DXpogHpd8yWZFFm36pR4pcFm7UeVqCM5yR3/RK/lpPgljxz/A1zdATLFwFfwllhI
         DB48CALKj9hRInsHcfGUsmOva0xm6YKCCBqo4icQIAOy+Pg0QT7jLEv08maxhafF6WRI
         rH+3JpvR/IcXrLpIpQLzRJ60HieRBg872UY4vgEbuykGDPc3xDvLyIvMpk4xJB9PW7SE
         CS4NJp446PoPW2Chc2g3ILOaGISzEH8uph5onKzhe3VCw5KHemNPpQvjUulNqvMpQpIU
         WQvCkmk7rsp8H0J7PKKQDYD9yUeGjJUyT8D7BES/Dx1iqGO10SClsXqnCMFysGC0s5Ov
         QWgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=WIPKkONR;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768320061; x=1768924861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mqfpXLhHOVa2LPkC9Neos80meqTEsR6PNeNE0ZAl9S4=;
        b=Y3EjI+hVskKEPSJE/SuVfbhdG2PT1NYzMyo3qD9P3Jh9tcP/3Kx+YFLFlCRXYMPVVd
         XkbilV4tOIkWfVyNnzk7BNGtCS3JRli9Ws9pkJtu7btkzqpU3CLdk4Z+g4fCnYTTEa9c
         m0oEt8IuyHYqv3IkrBWgvpsOGw87jSJMY1Hf5sYVyjFmNcqJveWWWujVtGbOY9NLTfus
         Np4HKRzY6q+wil8q37jPN7NEhNY/+27rc9m66UsvE4JHbZAaGUHXdL7MqGmy9LVEzpSZ
         XjwAalHbzxwC6DnDuAloUo6Dy8DHPAIbh8h4e7ncIb0kCZxoq7apeMBWO10ZfWGbShT+
         NMwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768320061; x=1768924861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mqfpXLhHOVa2LPkC9Neos80meqTEsR6PNeNE0ZAl9S4=;
        b=L1PV7u3Q8cnWQNEDvIlpKeK53M8W3tfC0IQLKOIfeDhescud7fwblwXoPLBrXOVKFV
         ZQoR5LmCEkZMfvtZVijZhdnbm947uEGX0op6XB15P1Pb/QXzUdGnT1AWLIXSnNoFOgMK
         VrSQ56OqQxJ2wrrLgvpd9NinFndZ7lDQpmTHI/Gc4hTxM3tHFXRBF9rQxnlVXtWFhBOw
         2+77CqkiowKp8D7H2DngzB6yZOdj/WNg/+3dIBGmqSpDDXjKjd85qnWqvPr993d72ZTn
         fnO5FacDvDXx4zE/x1jfKyEj2yMcaVHKVM24BUyjYRMCSZLPH+GB6Or7vlRPm0Qka5Qw
         vcNw==
X-Forwarded-Encrypted: i=2; AJvYcCWddDNA4q/zo9QomeKSYpIItqCdCKg4hhUqGRiCRu6r/YzBclw7WfNqpefVuOJDhSW89tlOBg==@lfdr.de
X-Gm-Message-State: AOJu0Yy7Ma4E043DXhIvPQNSefTQgARcijNlrun0Jc2gH1UEkgVCSFV6
	KctnCBAxSSdWZNBdr9FaexC170Bi3YKYCy8/DfkT4O5z/KizV2K9tIZt
X-Google-Smtp-Source: AGHT+IGI+5/m72cuo8me7rOB4Wh1wAD0PcplHPNIZmXPwIgMPac+fFpqLELqKd4maV7pvSseNY1NRw==
X-Received: by 2002:a05:6512:4010:b0:59b:7aa9:35fa with SMTP id 2adb3069b0e04-59b7aa93644mr5694457e87.44.1768320057272;
        Tue, 13 Jan 2026 08:00:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gycgr3Huvc+MeZlqqNtNVPSB2vyIWgdNUyGdo5eGSOFQ=="
Received: by 2002:a05:6512:1042:b0:598:e361:cc93 with SMTP id
 2adb3069b0e04-59b6cba0ff2ls2664696e87.0.-pod-prod-05-eu; Tue, 13 Jan 2026
 08:00:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX2ksDv8IK6COrV3tw7HiOSpUOG2WZPnz6+9QxvD7ezN+f0g2DJQS4PxnF2f2AMLnKqAMLPiTrricU=@googlegroups.com
X-Received: by 2002:a05:6512:34c4:b0:59b:6fa8:bc80 with SMTP id 2adb3069b0e04-59b6fa8bf87mr4664310e87.32.1768320054797;
        Tue, 13 Jan 2026 08:00:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768320054; cv=none;
        d=google.com; s=arc-20240605;
        b=NwsOtmatb09z3or3wdw3upwrcMNn7An0z/okNaecSo6BzpXOs4Kt7jPb1/2hzktHlN
         hl/xv+3OW8WzUJvO7v5uXuj4VOijZRo9oUN4V1Qt5DLochSS8426PlurT2oIl6b2bK7N
         hFneKRIFrojZ0Nygt7M4xQp78R7sJVGFpLCvONVdYnxpOZUp1TZzPXzacwf1/EnA5Enz
         G208UsvcQ5gjjODWY6HzrSSv2VQIsyh2T2i/qSFdDJYGCZl3xIqtUR+JJ2XbQTl9+qUd
         6sCV5fBYR8UQxqmph9cSoRf4iuI117Ti3QbVbaadplP5jdJHgnZ8MYAz33hlLFgGPOhW
         shlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=hFHCrVEHjXRF7hyUvHIW1j8LKpUAszN9uEePsrS4udM=;
        fh=65vZcx55jeWm1wcJtzwIioTsH5cMnUyp/oR9NseI7W0=;
        b=EmeDsA1krtDQ+HALTwybNoGrwQTuA0copcNJxUMKW8BZr1b0Pq1UiTmZ0/MO+WunYf
         hH8kTWyrPsQGRSLqCxEi+7SJeqCSG/NctQe06nDypICXvBPt6AqRHiY5n6bih61Zf4HU
         OV2QrxL0zNogINzoE8HFu/1DVfoqiDGfQt8S3DrgM6rrVWpF5Op5HqTdQCQXY85ACEfb
         wbF601RCf8O2OPGPp7LFMdpH70ny+nY+VB4ksP5mH/HQbvNyH48iMJBH0vnCmZfDIKHX
         9ScPmdAFdeankAhjqN1wsdcF/Vl/Y14ie5zzot4/pRAzif1x6oA6JkHNuHKFX3+GGxgs
         hviQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=WIPKkONR;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b662c0faesi304873e87.1.2026.01.13.08.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 08:00:54 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Tue, 13 Jan 2026 16:00:47 +0000
To: Borislav Petkov <bp@alien8.de>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan available
Message-ID: <aWZlpjwMXgdtZGMQ@wieczorr-mobl1.localdomain>
In-Reply-To: <20260113114539.GIaWYwY9q4QuC-J66e@fat_crate.local>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me> <20260113114539.GIaWYwY9q4QuC-J66e@fat_crate.local>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 9480566bf693106aafa213f58581fafcda1e4f76
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=WIPKkONR;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-13 at 12:45:39 +0100, Borislav Petkov wrote:
>For all your $Subjects: make sure they have a verb in the name.
>
>For that consult:
>
>https://kernel.org/doc/html/latest/process/maintainer-tip.html#patch-subje=
ct
>
>and the following "Changelog" section.

Sure, I'll revise these.

>
>On Mon, Jan 12, 2026 at 05:28:35PM +0000, Maciej Wieczor-Retman wrote:
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
>...
>
>>  Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
>>  arch/x86/Kconfig                     | 4 ++++
>>  arch/x86/boot/compressed/misc.h      | 1 +
>>  arch/x86/include/asm/kasan.h         | 5 +++++
>>  arch/x86/mm/kasan_init_64.c          | 6 ++++++
>>  lib/Kconfig.kasan                    | 3 ++-
>>  6 files changed, 22 insertions(+), 3 deletions(-)
>>
>> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x=
86/x86_64/mm.rst
>> index a6cf05d51bd8..ccbdbb4cda36 100644
>> --- a/Documentation/arch/x86/x86_64/mm.rst
>> +++ b/Documentation/arch/x86/x86_64/mm.rst
>> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unu=
sed hole
>>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual=
 memory map (vmemmap_base)
>>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unu=
sed hole
>> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory
>> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory (generic mode)
>> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN s=
hadow memory (software tag-based mode)
>
>These here are non-overlapping ranges. Yours are overlapping. Why?

The two added lines are two alternative ranges based on which mode is chose=
n
during compile time. Is there some neater way to note this down here?

>> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory (generic mode)
>> +   or
>> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN s=
hadow memory (software tag-based mode)

Something like this maybe ^ ? Or is the first take okay?

>
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>>                                                                |
>>                                                                | Identic=
al layout to the 56-bit one from here on:
>> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unu=
sed hole
>>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual=
 memory map (vmemmap_base)
>>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unu=
sed hole
>> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory
>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory (generic mode)
>> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>>                                                                |
>
>...
>
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 7f5c11328ec1..3a5577341805 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -465,4 +465,10 @@ void __init kasan_init(void)
>>
>>  	init_task.kasan_depth =3D 0;
>>  	kasan_init_generic();
>> +	pr_info("KernelAddressSanitizer initialized\n");
>
>Why?

My mistake, that string is already printed by kasan_init_generic(), I'll re=
move
it.

>
>> +
>> +	if (boot_cpu_has(X86_FEATURE_LAM))
>
>cpu_feature_enabled()

Sure, thanks!

>
>> +		kasan_init_sw_tags();
>> +	else
>> +		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware d=
oesn't support LAM\n");
>
>You just said "initialized". Now it is not? How about we make up our minds
>first and then issue one single true statement?

Yes, I'll keep this one since the "initialized" pr_info() are called from i=
nside
kasan_init_generic() and kasan_init_sw_tags().

>
>--
>Regards/Gruss,
>    Boris.
>
>https://people.kernel.org/tglx/notes-about-netiquette

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WZlpjwMXgdtZGMQ%40wieczorr-mobl1.localdomain.
