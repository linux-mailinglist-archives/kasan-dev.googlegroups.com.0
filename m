Return-Path: <kasan-dev+bncBAABBC6OX7EQMGQEXVDZCLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 49536C9E0B6
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 08:30:22 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-34566e62f16sf6623932a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 23:30:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764747020; cv=pass;
        d=google.com; s=arc-20240605;
        b=kh0+Yj/qy0yXT//AMgezl3NRuEA7qg+5ZmBvCCAFqzuzE7QHmL6Z5YJsTDbpPBXf2l
         b80x/ls2vxe2W+E05rwJcRiTy6wNqF9zlsiauPsKBSgDWxhgp6szEKO7o3jzPBqSLC81
         gCBDEjlpsybzOB8EmCR2wuMRFcHFhPl99x9EXzhXul9zIZA95AE75uh6o/+r0pVKGZmW
         wTHbgo85SftU37QA47d3mffUmSU/baTcNiG8YxljbY5UJOBMVzKeLQtlF/6tWJdEs6cC
         LvqU4UOOKQYQ1MmMqjlcCSM6dc3YRMb54DFICZMTuCn77JRKFMuMOD9XKjCfe7INlmRy
         iKSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=WhvRnXKe4Tcus+C2wOASgt4N+WW2sm/zoI8d2lIWurg=;
        fh=yhhMdHsi72PRb4i+2+jEeM749jTplqDxWiI5QsvbIwM=;
        b=gGld2vjHwHCgtKzH22gl93uhxABgxbiD+k7+Sbo8N2M9H8HbIGSDHDKQVPeICzwvQ9
         55Mgn9grWfv9mCSg94GwuLLe2sN6L1oe2wR73PUcYDfnEAYnXUHlndkVpF/mJ3tjw9Qr
         Eewq/iIAaK4p6xN+7yVE6BkG+qAEcl16wRr8KxmFMTUgxe3NoEWHjtVRFDThwxIzUi8x
         ZA9Dlx/WfJwePlKSp3TVeCv8qN3HueMMKRFhWtA2LlpdH3ucZAoA39dPOBTKJYFuWKhw
         TcTy59qeYjOluzsFjxJq5oySIoofokGb9eYjs+pmnPm0RMMBbmdbqin+UllPkAwjKQK+
         mveA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OOAew4S9;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764747020; x=1765351820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WhvRnXKe4Tcus+C2wOASgt4N+WW2sm/zoI8d2lIWurg=;
        b=gBZ0ckVuJsAT6wR7QM0/zVsVVLnd+AB7QBYf0eNZO1PNg0SczAdeH3XAMOIfIQ2HZz
         SZB/LwBaqqEOmlOK1Gur+ToevpUOHpfxHMS+gOZbYtJSJPmD7Agw67P1GUynppD4pW0Q
         dj8TYRVRmH1fk/4l8BoNIcfxvfetOYPintBTMNq52puTf4uRyzMpjd/Q+nzVWoKkl5io
         xxCmoZ42gGPbJ5aGPKCUX9WyfoQFQ5t/tpNMusWE0pcV4syBUqwhrCIXvzHAp/SNI3Qi
         eHSuPhmP98ZvmBiZFje5+mbB9uSe+6RGEC65xYw726NXNevNvcuiyoQR4Xs4hpxjIvgw
         3Nzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764747020; x=1765351820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WhvRnXKe4Tcus+C2wOASgt4N+WW2sm/zoI8d2lIWurg=;
        b=Vit7rYuNJ0hfI81W3sdTHEzxlhJpogupPO2YmPgffEiLh6RiufQE4DZl4kzPwobPaO
         Ii152jNQXy8KPJEj6J2xNfw5zeaqFwnaUiVTH0nIfZee3gTGUWOyZO8TaknBetb3hwQF
         jkrF7kcrmdX63Z9zTXAOpa6IadbpMkgzheh252NnMCozSrb1O0nMsHy4x+4OhQv4CJ1Q
         WyaVW85DdbTTGFnxLnSk3RhCMNS9yff83NR9VG5D8rawtdceAUpe5VlzTbyMqITMciLm
         uELxO16M6cJ8447ubyXalzGNTgx1Tm7pO5E+NpWNloJoxKXeLostTec78ZqdL3yu4awl
         OdmA==
X-Forwarded-Encrypted: i=2; AJvYcCX9Owy4NzSduBlgLyXS38YCp8QUZmEob8o4D1QWd0jC3oo/jw+hYhePEjhQcX+eAX+uATHCoQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxhj+whmnqDVhENXy6USs9R0zCJs/kn7JjPipfJzgNKqDc232xy
	ncmOa/8VePU9tdutMtFu2cI+aL6ucp+DnoHYxf+jWyfV9lGT11Q271DO
X-Google-Smtp-Source: AGHT+IFYyCaLjrpdllyFhmFRB73rIKV3OcEL0JkFIxGVDARY6lSXcM+JoKUb9OhYx1JjBFCCbCgzoQ==
X-Received: by 2002:a17:90b:534b:b0:330:bca5:13d9 with SMTP id 98e67ed59e1d1-349126fb6a2mr1226032a91.32.1764747020577;
        Tue, 02 Dec 2025 23:30:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bM3cKqGldIWtcHjtfjlIta/I/hWeWBrkOYgyrJszYinA=="
Received: by 2002:a17:90a:d812:b0:343:caae:43 with SMTP id 98e67ed59e1d1-347770cecf0ls4505471a91.1.-pod-prod-04-us;
 Tue, 02 Dec 2025 23:30:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYukOWbGs4tP4BArrNZNr+VHTaIBwUNJuNvYeorzbiDFdhMFGrN65C1cAWh6XmPxhrceIZBvARXEo=@googlegroups.com
X-Received: by 2002:a17:902:ef0f:b0:295:57cc:cfb5 with SMTP id d9443c01a7336-29d6839781dmr19161405ad.37.1764747018600;
        Tue, 02 Dec 2025 23:30:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764747018; cv=none;
        d=google.com; s=arc-20240605;
        b=Qu0qyXN6CjLB0Xb33MGPg2R4iMqLlDSNGUAjCxdI5SR2NXXylB/ojz3bBNaGzl3s82
         Clv3sXKx+h3RQf9URprvVD4QjgssXp89qtY/z8E32DoVikd5fFf94FkvLh272IYr0Ry7
         zBpxe0KtL0xUhjDSvnqbOX73Nve0gmzydWU8hxSjxYtRHN8IpkYMF8hLH6jmA3QE3vDL
         gurrMPSZ/gLl1WzLSiX6PUr0cqhN/KTpW1CRAPFpM4QfRVvqhR+4+LsZzfOLmjjWWYfU
         Na9DdvghvdIIqcTDsNjKCF4sVB99hSl2hOox+z2hBqa49/DeTbyfd4zYgZ4kvTZCZTf7
         1Stw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=CDRU707d2INpmwpTAfBR2VrUuDWM3CQSFKF4zJkZLpc=;
        fh=i2t8z26IQvGJ7iyUcSnxdbY3r6+ayQmIC3mAzIr7w3s=;
        b=Kn9d4dFR5TO52axyVDtSM9llLbXoM80iJhtfsuIxKLvUYYbHP8Rvssnm957H3Vs0GB
         dP8XOykSRRbbB/YwdEMtir28/ApJ6RLqhu6JXBZ/S/U4DdT2mHhy4cb9ASXxgvVq/eJj
         14WH3AafBrU5df9BeVoXPWP6qfckGQy/RiXPS1JHr2XJqPsQ6G/8Z4Q6PVW/4N4cKHZY
         mqmJoi43FTKHC2ojZao5QHp05ym+0An/+ajEOYhSNQRjgBoL/EBfBXIpTirqGFhbMneC
         3ts1BMFIIWbGJs7hIyAYKjtM3UD1i9m8vZVCGx27lBrYLzLG1GbDID7hQoLJVUBykatO
         HHCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OOAew4S9;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29bcea92fbcsi5972565ad.5.2025.12.02.23.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 23:30:18 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Wed, 03 Dec 2025 07:30:10 +0000
To: Jiayuan Chen <jiayuan.chen@linux.dev>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-mm@kvack.org, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
Message-ID: <wkcpaobuckopokvqfyb37ugox24bpcyzl6pztaz42s6byzf4pg@z4ndbjoxbjq7>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 4c6696efba181766eb8a1fc4beeaf0a6b1777034
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=OOAew4S9;       spf=pass
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

On 2025-12-03 at 02:05:11 +0000, Jiayuan Chen wrote:
>December 3, 2025 at 04:48, "Maciej Wieczor-Retman"
><maciej.wieczor-retman@intel.com
>mailto:maciej.wieczor-retman@intel.com?to=3D%22Maciej%20Wieczor-Retman%22%=
20%3Cmaciej.wieczor-retman%40intel.com%3E
>> wrote:
>>=20
>> Hi, I'm working on [1]. As Andrew pointed out to me the patches are quit=
e
>> similar. I was wondering if you mind if the reuse_tag was an actual tag =
value?
>> Instead of just bool toggling the usage of kasan_random_tag()?
>>=20
>> I tested the problem I'm seeing, with your patch and the tags end up bei=
ng reset.
>> That's because the vms[area] pointers that I want to unpoison don't have=
 a tag
>> set, but generating a different random tag for each vms[] pointer crashe=
s the
>> kernel down the line. So __kasan_unpoison_vmalloc() needs to be called o=
n each
>> one but with the same tag.
>>=20
>> Arguably I noticed my series also just resets the tags right now, but I'=
m
>> working to correct it at the moment. I can send a fixed version tomorrow=
. Just
>> wanted to ask if having __kasan_unpoison_vmalloc() set an actual predefi=
ned tag
>> is a problem from your point of view?
>>=20
>> [1] https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman@pm.=
me/
>>=20
>
>
>Hi Maciej,
>
>It seems we're focusing on different issues, but feel free to reuse or mod=
ify the 'reuse_tag'.
>It's intended to preserve the tag in one 'vma'.
>
>I'd also be happy to help reproduce and test your changes to ensure the is=
sue I encountered
>isn't regressed once you send a patch based on mine.=20
>
>Thanks.

Yes, the final issues are different, just we both want to use
__kasan_unpoison_vmalloc slightly differently.

Okay, then I'll rebase my patches onto your patch, restest on my end and
resubmit my series. I'll add you to CC and reply in this thread too.
Thanks :)

kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/w=
kcpaobuckopokvqfyb37ugox24bpcyzl6pztaz42s6byzf4pg%40z4ndbjoxbjq7.
