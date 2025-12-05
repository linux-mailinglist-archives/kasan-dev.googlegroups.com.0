Return-Path: <kasan-dev+bncBAABBZNCZLEQMGQE4VR3B5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 79602CA6943
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 09:01:43 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3e1383751f1sf5202491fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 00:01:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764921702; cv=pass;
        d=google.com; s=arc-20240605;
        b=GL0hVh4pci2F7b30mqDhxQDudmaCTsrBYpJ2whQaxf6p4xFXViA2uv+CQGcwNsHp9N
         1G+01jD2DWkFS/oN0b2TGNISICfOI/70DRtNMOyaYnBT5abu53wRTmafxLAy28Jvki3o
         dHA09o8qZL/jPbzWTN7MU3QgP5zBsKWC/mhe0tzCU6La+bX4xu6KehNBTlQNhjPgECVD
         4OUMg/4MSSKeeki5wU1SFup2Df+ktsWazscD7GmtxguVLq5IDWkVdw5lBQ9IsAjw2ouF
         YMQJdVxt5e8JCYUT0igh+5sY8jFT4YEhYA/gMmkemeetj2T9wkLeFhmglhtnRl8oMIMW
         FyOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=uatHKcJDUd70bWIZOitom5Dl+ItFqcX+vxTlKnLGxhQ=;
        fh=vYLhbe9epM2mq5O9VFHPBfp/S3icl334Mib3EkAMGJU=;
        b=a1ToQKM4Ia3Yxi5b5F7eDZxwH3mZCVS9VNMZzDK+F2ZVgrawjoAwalGbAP6c+eapoF
         B8lE+lxbYVSESxh/e1XXmzSCLL5voBgq9/SV9g7mf+mnlOf6033yzmQvbRbugvkPXqKM
         P0NnvvbCpHR8d/hfBRlzlX8WAEHVGQsK04P2TQqTi6CMKQi0N2dgZ/BdfsbzSJpyBNnq
         lGNWJgoahdPlJZkvXAFFSitYGyazXMdEarGdwOk/wXBo5jQ3OKkNVyNUtIS7ixzRtl0+
         HSvI7Lwt630HQzJohwuejvpXgCHf/XcDLE5lQ+yp0lNe6fDSNG0uuvkZGh5gYj6/9LGl
         a3+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mwzwteWz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764921702; x=1765526502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uatHKcJDUd70bWIZOitom5Dl+ItFqcX+vxTlKnLGxhQ=;
        b=dkQwrzJ4+gFJOfuT1JAp1fmt4xRHOy8iQ1r2jKXEHO78sRY9rIIyyY8n2acvoV8sfr
         ROZ2cs10Z6YrcLeOOFKWFS9hI4SIt+Ri6WBSXFzcBesCxdUsCFJurSGvi1/Ia/P4FLMO
         Z5aXmqaPWu2VwiI0Ve19EXEFnaOaOVrAOdFQRKmP8KZlByVNfOCRgYAomvYGGH3teZ7o
         vRO/kbERLA+H7mo5vvVYenNAoptKUwNjrjvYNlOJOJmRa3Yqez/xb3hpLuH7r7XIcFh1
         id3U/e4viLXahjwF2Z92v7GbrRFth4CN+ZuZrvQSdrhRYX4r/VA+hH4ttmGuP1mUBc20
         MNUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764921702; x=1765526502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uatHKcJDUd70bWIZOitom5Dl+ItFqcX+vxTlKnLGxhQ=;
        b=L+a83LeCYa1PuGS5YKRaN4iPZjCahk8DxGH3NjBZY5KLxsJYzwlGyXD87s5PwD1lY8
         Zs4U8u8Ohly8DRwrh/tT/JCeO3VwbFp0UeDq8bA60sRsiIV/n7B/MH6sOstM6llOMJjn
         c+0RhpxtaDznlJYbdf9+3iAiBdJIaiNcUM12I1xQjWlUbsdVKVPgcEAdSQymSSJAhLXe
         WGqCZjE3uaFYhkQGhyZPfyo67koR1xzAhT0j31nH2t+D1wKPL1DQqIABa+6mMIa6uPnD
         1kuUNITXaTw5VIYMoItohd3mTYi2EZSGxXosiymLFblL3BurDAoG1id3xSZMj6LFkK9e
         IX8Q==
X-Forwarded-Encrypted: i=2; AJvYcCWPDvRd4ip9JzglHS/pkAdsRrw59O6jDVLOYoFVV/8Na4nLepueADwdxy+yZFtFuYeuxCB2mw==@lfdr.de
X-Gm-Message-State: AOJu0YxK9wEVdCUYwYafkvWA975a2VY2kDCBYCx/SoK8J9ZVwYbQh5Va
	9dYO8rTYzbs8BHeQnR6wab6AQ6W1x+ivzvNKd1Wt1mTaAagiwAOtvd63
X-Google-Smtp-Source: AGHT+IGXvtxrvLCsnMrU7PSMdOBHsoVyApE1CAFI76s8LacMNeSivL0vlCgTcn7j/Ds4Yy3/wS4y6g==
X-Received: by 2002:a05:6870:cb98:b0:3e8:97ab:d06e with SMTP id 586e51a60fabf-3f502e0a58amr3307074fac.9.1764921701798;
        Fri, 05 Dec 2025 00:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zpp9SokZBuQCZJj51QvOSd6ax5nSlt9j+wBkNdd7gxXQ=="
Received: by 2002:a05:6870:1704:b0:3ec:31da:bbc4 with SMTP id
 586e51a60fabf-3f163d675abls1060846fac.0.-pod-prod-00-us-canary; Fri, 05 Dec
 2025 00:01:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYD6Av5oKPPGtTmu/u6mkV+e9KOtwFrvd3v8ajT+46lkH6Zi2rGnbkRizdEkCt0JPXyZIzJyjPuD4=@googlegroups.com
X-Received: by 2002:a05:6808:c307:b0:453:7a13:4eae with SMTP id 5614622812f47-4537a1362a9mr3189520b6e.4.1764921700960;
        Fri, 05 Dec 2025 00:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764921700; cv=none;
        d=google.com; s=arc-20240605;
        b=I4108soVJifA4Sv9t8cGI7KZftWFRbbmy5xtooB6/lZAukMK2cWeWBH7J7Rn41BYA7
         XHHEwhVsO4K7guEeSO5e7PtXVpGdG8SM9eeDYEcqwMs+daXuzelxQiTFV66ieRFFozZl
         HOiY4xqIMNpPfSVORfUcW1ZK8SEi30zmdDx6OrLC9jyU6AhjsJVDAJpR2zntJlhfpvUM
         T34D/MulbRJ3Jdx2iyByz0NsG8PbBX7A2aT2tPJLreWWcLtB+d0XRar7ZgANnWAa4Q/m
         VBXxWpUiKQz+p5iljq2OG8/8jMnR6JfJEu8U+lQx1lb1a/at21+fCgpU/8t7SbuH1yhk
         iv6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=Zgc5Bfim5kR7lSEF9D/3QfXneWnjNYTl3zLRKpUUg0w=;
        fh=BgweZgXcr8s8ASZZT27bbogIwMQ2G3Pi7TMRLd/khEA=;
        b=TkDRHwNnbqZl7G9IkmYe0rZsLhj5bHapSvwSuOG4rQdXJZi2RICD5Tgpo2dq/tN2sU
         s9HmyzuZfHDlH7nGc5mrH9WLkqPNQHnncjWEUoi5YOkZnC04R6j9H+6vVoSuFhf2eRm7
         S7N6ThQC18bgvpcTFJJp33a6l84kgL9tfqjtziOFz5moOiWU4Meg6RXBvdjK307xUCJK
         LHwK+PraKKepMtpbJBdoqfOBPcBBhkjlNWZkEyzGV7/9/RS0gKUpa9py5kUnAtO2zLGX
         4ytjZOIFpGHVX/lOMqQd9ucKa7YdPmVMhGfvEhrCfyKiVXa//0JrP97o6gUN5fsqaNVM
         aC9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mwzwteWz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45380135d00si145220b6e.6.2025.12.05.00.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 00:01:40 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Fri, 05 Dec 2025 08:01:34 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v3 2/3] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <mtfitb3vqbcqzezrckjlo2vyszb3ufqgimmpmfhnybrkjt7m6f@3ovjldsuitwc>
In-Reply-To: <CA+fCnZfRTyNbRcU9jNB2O2EeXuoT0T2dY9atFyXy5P0jT1-QWw@mail.gmail.com>
References: <cover.1764874575.git.m.wieczorretman@pm.me> <eb61d93b907e262eefcaa130261a08bcb6c5ce51.1764874575.git.m.wieczorretman@pm.me> <CA+fCnZfRTyNbRcU9jNB2O2EeXuoT0T2dY9atFyXy5P0jT1-QWw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 2cea9ea5c467759ad35e9323c2a7e8e0c5500488
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=mwzwteWz;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-05 at 02:09:02 +0100, Andrey Konovalov wrote:
>On Thu, Dec 4, 2025 at 8:00=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
>> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
>> It was reported on arm64 and reproduced on x86. It can be explained in
>> the following points:
>>
>>         1. There can be more than one virtual memory chunk.
>>         2. Chunk's base address has a tag.
>>         3. The base address points at the first chunk and thus inherits
>>            the tag of the first chunk.
>>         4. The subsequent chunks will be accessed with the tag from the
>>            first chunk.
>>         5. Thus, the subsequent chunks need to have their tag set to
>>            match that of the first chunk.
>>
>> Refactor code by reusing __kasan_unpoison_vmalloc in a new helper in
>> preparation for the actual fix.
>>
>> Changelog v1 (after splitting of from the KASAN series):
>> - Rewrite first paragraph of the patch message to point at the user
>>   impact of the issue.
>> - Move helper to common.c so it can be compiled in all KASAN modes.
>
>Nit: Can put this part after ---.

Thanks for noticing that, guess I need to revise my script that moves
these under the three dashes

...

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/m=
tfitb3vqbcqzezrckjlo2vyszb3ufqgimmpmfhnybrkjt7m6f%403ovjldsuitwc.
