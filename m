Return-Path: <kasan-dev+bncBAABBDF26HEAMGQEH62B3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A10DFC692E2
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 12:48:30 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88046bc20fasf12232036d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 03:48:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763466509; cv=pass;
        d=google.com; s=arc-20240605;
        b=HVo2cYEAJbOVZd9SrMaRM3r2UM4BodESkmiGlRrGZBJyidxosBsaa/5qNYcr73aGCM
         oVufcgNdkxnUQWI511HJ+OVaHI+SQi8ubDLY/kqjzugI43LAVQaxC9tEuVLoLmbCqP3w
         C27s8ts65qYjA3XfVeibQxzPmaGV2l5f1XYVZOC2IvhO/y2lCcQHa5T06jDYPtqQxskS
         3TUFB+uHygCM3TxTWBi3ftyGdMixqALHPTkyTIfEtxGOp6T+2ITdMqAIUeVgL3oIkPqK
         Ux4RRE4Xr0o4ngRU/N7nPYfnNRPnTtud3ngxsCIc2GhMXi4/K/h00qssJuJFQ9NPhCA8
         qQwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=JAthX2j/1SEKbBcIHnw2zUFL6jhoD0KlcWzoVgQqgdM=;
        fh=4B90nQIaKZkD4Vi3LgkgrrjnQ3/Wzc29Mm+8m0MSdPY=;
        b=XUtN9r4Sliu6SPKGMlPs5eUBKV1e3sJUV454okU7HHP3uE11IUV5VMB4N51vgbL7pz
         9Luh5+hNH9IYgD787sVub9RMenilz1i1iF+i2DSE2DTSpGmnyZdmRRM0KqmFWg00PWt7
         +yN7BWPMHss03TQoJusSDrbHWQ7sJ+Kj2zJalmeyh+JNCsWburEc8GaxCWJxUxdTsr/R
         dhtWyJhIPMTdB7YWj3ENXge51hbOP5TabQCXVEiYX/XamylRxa5U1hORNFhZTrK8O1ij
         M2oaoO1tBD6lsqDV1NGy81QJvzjqx+iHJPuH2Aoid291z5wtbZTpELAFmEf7rY8j2krz
         afgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=gQzkmSZT;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763466509; x=1764071309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JAthX2j/1SEKbBcIHnw2zUFL6jhoD0KlcWzoVgQqgdM=;
        b=YbTejHp84quXgSCmsjC6JbYkfIcdlV1mzEHzFyExYnLd77iTrJVEEMqY7EANtoXeF3
         HRp3Z0Hv4uD+dwt2DCmIJDMOqV8jFw8pTrdHaJG2R39vVDP2l8T7WcXEVnuSl1bIrjiX
         s2lvXXyL/t1douWDmpTRhp0xIZqwD8yP2OliN0LtZ7yMQ6RTw8BvY6vl0U/hyDMg1bjY
         LiIvQgpqijAtzgx73P/oHk2Csje5PCl+JS+bUv7cnHP8uOAJKpuySAh/NcdkbMIgrAQu
         qlImDnZlpGSmJchQmYyVf+J80OOZiTxCHGQgSCyzyjx2SHnmIaVCjzy6GS9I8Qbem8Xm
         KgEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763466509; x=1764071309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JAthX2j/1SEKbBcIHnw2zUFL6jhoD0KlcWzoVgQqgdM=;
        b=iTEIOCZLFNCkXDT7DxW4bV1yPFjEIhq5STN3uujiJUzpz8Gdy0qT2ou8diZrh7w3FQ
         a+Qw6ZRpHLDlODt1jK2Axyf59ZlHxIiTl+eJcMdqf5pwyAgJpFrNOq4lI/RpSwCLqDlH
         /RmwGTuTmCGP+vvA4QA/xn+DJVzVsr8ZMfQ2SwVR+YsyfribryjZWD80XvfRXfjXjHAh
         HE2BCxUHmo9gMIsgKuPv8CZ825O1eWyXZ9zT/tU/l/mrdIWgDaGCp9T/SeGNAsjTBsFe
         8iQIURqJLEVwHbtEzQ3cYsYuGTdkZ2MaF9eS8hBv2/zfvp+gPaJtJOCV0Mgom3qfCHyd
         tU0A==
X-Forwarded-Encrypted: i=2; AJvYcCWVzvt2+SQ2A6+ww+hem/sHlKeK8U1ZNipYP+lyKkQSs7WrVZt4uzFmkAZm4WusQEV0n7geow==@lfdr.de
X-Gm-Message-State: AOJu0Yx8votWK1d22W4gFJR5tM6ROrW+2KtidcfTt+OBIRmvE2NhqvPv
	yF6rs5n5cILZXV+NpVkPgIgjZWBo2Ivrbz6jPA2bUcXg3zlGBXOA37yt
X-Google-Smtp-Source: AGHT+IFP/9ApiGAa8RTxl2JsE6U8NEhygUQpVxMB8ki+7UUpFZJQVb6Bwor83AbPv9TbLZlpluQJrg==
X-Received: by 2002:ad4:5d44:0:b0:87c:21db:cbbf with SMTP id 6a1803df08f44-88453c2a232mr21205046d6.4.1763466509258;
        Tue, 18 Nov 2025 03:48:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b8g18nkPW6ewjKLNpET27T3T+WT2KDqZd2jvHRtqaHhQ=="
Received: by 2002:a05:6214:f64:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-88281ae923cls108031776d6.1.-pod-prod-03-us; Tue, 18 Nov 2025
 03:48:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXhElxB0aw7kyFADI8rnIphqIdwO1wr5EPgqU08mjWI7s4OgTxDS/uNFKP02OWKqCB7MbWVtaAZ0kU=@googlegroups.com
X-Received: by 2002:a05:6214:5014:b0:882:4be6:9ab9 with SMTP id 6a1803df08f44-88292705010mr211099256d6.54.1763466507836;
        Tue, 18 Nov 2025 03:48:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763466507; cv=none;
        d=google.com; s=arc-20240605;
        b=ONjnF+6Ca5/EHaf5T2/aJDOImtfvd2C/TvM882R6N7TGQygCqLV58t6rZA3wvE8a+X
         2mmEfgHE10UzPFUY8Mez/BlHvZh3d5ww5AeX4xs4dxslXk/j8we7xoJZmuvq0cYQxqed
         8dmddMlI5ovYpCAwm5XarQBe5+opDVDLtTe2RgCl+xofEfp7IsvGdLSxhj+jDlzPgyWL
         NnmNPy89W7iQwhazclj7ZXJ2ycJt8GxdRXYXcOemDgaF80oDyCcKiI6lAQ8GwljTEXRa
         WdEo9184GVMknD7eWeYOC+ytnGtSC2l1uuZeBaplOl1RbB+H1gUiJwLiKoCmKR/dgJb5
         Pw4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=n6/kLrRa2f455JqtRCfVFIsy+tm9Wn1NEx703c9jG7s=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=hNbbvhMooOB0v4daniOAaYFJHhNQGMm2mU5Wd0AOe7tzieFcnfyI8yoZYxV4a/g7eD
         269g+n/zqLlkwK52zPGEmXC/u3hWtIYh57KGuVZjacIT33f29vGW5bGQXntmdSj6Fozh
         QgnbvWHgF7lowfr7p4n9/JdpJ6u33Nba+YZVNpncRyfr6jLuKZLeM8501zFUbjFQ2vDC
         AZSwi8HxDxzAXrq0L1wVHQtQRPOnYfzBAsb9ec0q9NJzfKND0mfLxMDkXKgKEul7BzZh
         kYiciaKS8TOxzVaV3PbY4INKG1TncUM9Fp2+Payb3ksXqGwrgBMaeundph0bNEdDXdA9
         wRrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=gQzkmSZT;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244123.protonmail.ch (mail-244123.protonmail.ch. [109.224.244.123])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88437db599dsi3344066d6.10.2025.11.18.03.48.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Nov 2025 03:48:27 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) client-ip=109.224.244.123;
Date: Tue, 18 Nov 2025 11:48:19 +0000
To: Alexander Potapenko <glider@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 18/18] x86/kasan: Make software tag-based kasan available
Message-ID: <bpyudbe6kvzlj37j7c6zo33zxfc537gos3fn5cbr32yz7ebu23@oeaxjofxyeao>
In-Reply-To: <CAG_fn=WPQZ4ti3Lb+A3jSXFWLtn6291sTKJBwKBiLD2E9YbuKA@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <d98f04754c3f37f153493c13966c1e02852f551d.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=WPQZ4ti3Lb+A3jSXFWLtn6291sTKJBwKBiLD2E9YbuKA@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 1f509888f40154949953d5f9b6464c2363ca1311
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=gQzkmSZT;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as
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

On 2025-11-11 at 10:00:59 +0100, Alexander Potapenko wrote:
>On Wed, Oct 29, 2025 at 9:11=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>
>> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory
>> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory (generic mode)
>> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>
>
>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory (generic mode)
>> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>
>> +       default 0xeffffc0000000000 if KASAN_SW_TAGS
>>         default 0xdffffc0000000000
>
>Please elaborate in the patch description how these values were picked.

Sure, will do :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
pyudbe6kvzlj37j7c6zo33zxfc537gos3fn5cbr32yz7ebu23%40oeaxjofxyeao.
