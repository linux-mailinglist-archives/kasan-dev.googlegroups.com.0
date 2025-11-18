Return-Path: <kasan-dev+bncBAABBGVL6LEAMGQEGKCAR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 10B71C6A65B
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 16:49:48 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-640b8d02165sf7417625a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 07:49:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763480987; cv=pass;
        d=google.com; s=arc-20240605;
        b=RgYenSmM4JmslvL7Aw5vJnucnky0WFp7v3rV8o8QtzWmIoUfLZDxANuiD9tf8FRKRj
         wT6vMu4++f9coCMUQrJLuOvWd+rpjeCva1F90DSzy3TSf2VIsZNV+YOgcZsePXhfw9P8
         SgBsCmsRHQLPmzdfYesP5cbFJ1dChVxpqnt6pYFUye5Rh6skisZZ2WIkos250oT3k7G4
         ChsBTvKg17Jzqi5wCyeLhAfbpi7ulC1FMKxbgsZv7980A526FOFCSfHMX2YbPRXRIOL6
         dEc1NhLUmWX2Mk6NNoWIJU7tURkRcG9qcHsQHSYdfx5ujTbkxq1hYfDkPMhdzmnCT6EJ
         wuag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :from:to:date:dkim-signature;
        bh=/aTBql+A/bdoFAYcAmGiGxbZeeB0sZvGVTSPX2v7dT8=;
        fh=vMQeiZ5pmks2H2mpXhq9HRvEspHNDFwgDgqFDf6hhWY=;
        b=YYmAfnB0CM9c3cFtqRyvyS4p/rEG1L9fAHIBadPw5km5MNacMgB6Nqy0Mr89Zb/kH8
         jUrETl+yrRhcIdwyjoju9+50+bDN91gTanY1MwH9nCSYBm6nQ+h15IY5AAszc3ebfob2
         1zjptYaJINm9HuDBloeW4phe9QbscihWncYxVb+hXSIV/M0v6KHgLvfmTpQJ8ZGM6t6G
         o0JtB/ld8oP5F08ihwU0RHYNI/zzEXEXa3eHr+d6ltRsmwEtLHvDSLccjnkC064B6FSS
         ysEoEtdKEHDgZpYYLeligvGVFQQfQtzxA3dNnOYsGzEU0v4c9EwUVLMNzmen7ds7gMFv
         6YZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="VU/bLwEu";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763480987; x=1764085787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:from:to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/aTBql+A/bdoFAYcAmGiGxbZeeB0sZvGVTSPX2v7dT8=;
        b=Z8yZj55kYUUKkwm4lZp5bir3d5WfFLGciyCmh4A4u5CIEOjm/jqII9W2aqewdkC8RY
         Q27OpLpofuo4gZZ7CjWZ7ntv/FcY/Zth2bwhZYqTA+EtNn5dRXJ3VaumbBqxRpX1VMbX
         YtRtek4YGvnB8FjwRIuyg6ohs7Ry8AsXNsTNn04mZm5jySjqHwwse4h/Qujnprrwtbie
         VzBnzCNTLCpOI/0RSkpmFMSRuQ3C48PvsWt4y0492H+WnbKA0ih5atSVBXkgGtn0e6Ws
         BLcF/GnMyY57G3HGkP43CnrUqp+LhV03N35hapk561aLJwbzFtPz9TWkORImixg4vLTx
         OXpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763480987; x=1764085787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/aTBql+A/bdoFAYcAmGiGxbZeeB0sZvGVTSPX2v7dT8=;
        b=ghrLd9uBHLolxKT4VJesLIZj/hPnjwqW//ux5KLAzA1UQk1ltsl3wYhEW6WYF4dFgZ
         Cfrhb/xHYtNcAbEpK69RTDtJwf+lhJqEM5i38nJ2s/YiXCpSeGl9P56Lw5kIUhy3gGEa
         5/L74EiBxfgL2ZFtYk4t8iuovZvUEehrHaHmD5MuOmuE4QAVf8FmWGMCXW2EmadG6THf
         0ujLqWxT82dmRWbUfnoDJ07bVXCXTLA/maPNUpAIS1kLPV1TS0LvGIA4dQ9BW7s6enUo
         untaI0bp1YHSUsGK3jS2r/6sTo3WAoOTdX3ETwIDlPguX/rryaEnxXJWA8RiuvE8K/mJ
         PiLg==
X-Forwarded-Encrypted: i=2; AJvYcCVSBPsw28DM2noEZbYvAzwlarqcvHj7B+TWr9ZT5YmEDFhol+fInP/rLGhzEp9y17NHcloEsg==@lfdr.de
X-Gm-Message-State: AOJu0YxlxGeAuMqTXx/wDKaZVKcY1r3/sKfClgB8LgciwtWlesTEx9xu
	FP3TUyDAjUMic0UXoxmwhfRuKOENqpm1b754j74x87tcWKSiYn062hjL
X-Google-Smtp-Source: AGHT+IHMpJr/7uR+jCv8UFCZPhRM6gYfa86GbHGM0XFBRs9lZDSAatDAIaN47McMqenZ9b6WfYG/iw==
X-Received: by 2002:a05:6402:210d:b0:643:9df:4993 with SMTP id 4fb4d7f45d1cf-64350deef70mr15029162a12.4.1763480987139;
        Tue, 18 Nov 2025 07:49:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Yz5c8NhtVJjA2V8b/63R2BhIGkZbhpHOaRy3rVHFVA5A=="
Received: by 2002:a50:fb98:0:b0:644:fc0e:254 with SMTP id 4fb4d7f45d1cf-644fc0e0397ls331546a12.0.-pod-prod-04-eu;
 Tue, 18 Nov 2025 07:49:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXulkHDJO8hUWu/ka0ibRtvYNPVIwesX47e9rldzrBUlxllb6mPLu+ZpHFIyBdB1aCyc2U5QOxiaMY=@googlegroups.com
X-Received: by 2002:a17:907:80d:b0:b73:21af:c0e7 with SMTP id a640c23a62f3a-b7367bd8c7cmr1963449166b.53.1763480985146;
        Tue, 18 Nov 2025 07:49:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763480985; cv=none;
        d=google.com; s=arc-20240605;
        b=a1hktWMgcR8Sz2qJbzrrWcyNG9d3knQoiKcx0atP0wTHhdPqC1oeR6ieic0PZa2h26
         6keysEeyLZqwg9S11UhiDPv6JVuSkuaN+dzSt0Ak1lV4I/OhaKkAzPF8VEMbtxKzojx8
         qwVNyqoTsRlyn41WTRjGy28XpCrgLlcvjDKAVkPw9woiJjffYWwdrIFb50xsmvOWsfWl
         N8lw5QzB7nits5N/L/EDQUsO28Xfu/GA0dfmEBS432fO0+MFfJAUUwMUxA4aR30VNscV
         yiY2A7Zy2GCpp5iiS7DT4Dig/1u3Dvvk5EdDQD8/+bAmFiVwNEUBB27hM3Wy9B7Kyjm4
         gQNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:from:to:date:dkim-signature;
        bh=a9ZfR2miDizST+NAQHBsA4FP50QJXQbD9wrCS0aDhy8=;
        fh=AX2KGP/L4mdXEw2vYYNDcLVfCsTHnUdqzXBAPG6LY2c=;
        b=W1Ot8SApD0IWFiFBDG7GjITeQqzNzjpDtYCrj8/Kp1bcNVFP9cWG85ZyUaZ6dEfNCK
         JzeTFXMr5p28Y5juu+FktUobtDztINV20KFcVXmcGZerfwee/4L6SvbYHb1UBoQVIdEm
         X58N3GVuyeqEdp6XvmLqyCeJvb1Mo2Po8rOMHHSZl2rGWWuoiIQczoHb11X2deXcZtDv
         aKiuaMFB7O7wHGG0WzQevqGA3SGMqJspTD8eNy+bUNCiKmGcOH4GoGSSaCudAfHtPj97
         J/9aMdOiQq01y79OCcMWTJg11g1aTXuTlq7opbjddiW/yjeKvilRniA1M67KHHVBotpA
         6PMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="VU/bLwEu";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b734ff14f42si32915166b.0.2025.11.18.07.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Nov 2025 07:49:45 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Tue, 18 Nov 2025 15:49:28 +0000
To: Alexander Potapenko <glider@google.com>, xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de,
	surenb@google.com, ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v6 06/18] x86/kasan: Add arch specific kasan functions
Message-ID: <tide3xvqthah7m7ji6bfzb5i3ofabgwf45bn3qvvzsurnswh6z@wjxzriavwlp5>
In-Reply-To: <6nifmxti2xfbnrdtxbosojfw52sofc7zkyjcbcyeawz5lt372f@h6ksdfqddk4z>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=XFXFAvKS2+bc66FR+gw7rfSybETAOBUR_vneaVdF5F9A@mail.gmail.com> <6nifmxti2xfbnrdtxbosojfw52sofc7zkyjcbcyeawz5lt372f@h6ksdfqddk4z>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 2d31863a5f203112dd7296a62db9ab5faf481d58
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="VU/bLwEu";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
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

On 2025-11-17 at 18:41:35 +0000, Maciej Wiecz=C3=B3r-Retman wrote:
>On 2025-11-11 at 10:31:13 +0100, Alexander Potapenko wrote:
>>> +#ifdef CONFIG_64BIT
>>> +static inline void *__tag_set(const void *__addr, u8 tag)
>>> +{
>>> +       u64 addr =3D (u64)__addr;
>>> +
>>> +       addr &=3D ~__tag_shifted(KASAN_TAG_MASK);
>>
>>KASAN_TAG_MASK is only defined in Patch 07, does this patch compile?
>
>Seems I forgot to remove it from patch 7. It's originally defined
>in the mmzone.h file and looked cleaner there according to Andrey.
>
>Thanks for noticing it's still in patch 7, I'll get rid of it.

You were right before, after removing that define in patch 7 it doesn't
compile. I think I'll just open code this definition here:

>>> +       addr &=3D ~__tag_shifted((1UL << KASAN_TAG_WIDTH) - 1);

I don't see a nicer solution here if taking things from mmzone.h is out
of the question. I suppose a #ifndef KASAN_TAG_MASK placed here that
would just shadow the one in mmzone.h could work too?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/t=
ide3xvqthah7m7ji6bfzb5i3ofabgwf45bn3qvvzsurnswh6z%40wjxzriavwlp5.
