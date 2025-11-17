Return-Path: <kasan-dev+bncBAABBHOB5XEAMGQE32I4EHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 41A71C659C6
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 18:51:27 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-37a35d16347sf31740361fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 09:51:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763401886; cv=pass;
        d=google.com; s=arc-20240605;
        b=dKKrw89FDBJ31GP+SkXjavn8KOc3xFnSUPP27BtTJ43ep6UonDzjHGzWSyhAzYf+/q
         WAxGTB9uUZVxVxH0AM1UjDK8i9caRgKSlgj9utow2Y7/+MW1uB2nD2bvsiNSA+gNVM4M
         v52Z4AJeTpRl/s2hdUJE1FflF02L1qTBDOIMuiTayP5stRI2ePDKFUi9d91LYpLRdK2D
         fcFR/LlYUhG74Qp5gjM1/FZphn1ap8dlBQ/gtLePaLdLiPABiXbxrRnwCJnMmlkRtXtE
         c8nvXau3J5qYdujYLMA6wfpeNb06CNFG4NrQACZj2XeS1t6fT1ibzMS3FIWl43Lokf4W
         Im9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=aUSqK1iBtuuILxiUw1yhGxvFyAivwRXyEdybjzTsz4A=;
        fh=4j+iAg9+Sgo/YIIMPZpKIBymRl/UwKSmL80jvYRUM6s=;
        b=P5ivBLiqGSwGfF7bOjADlQtmPwToevBUgyKaG329EuHEH6+KJv4zTTv2mf8Ob4wi2+
         5ZGM7hMoiellnlXdUhxz/9zFl6U4yHQIpMsSpJ4RwNNr/c1iPwX0/wErCqZV6HRzceui
         TBo6i74+wezGOMjOE4QDZeTLMZ1TVYpKu8qvLVIbhH/VTeEEUpSQsTyZmrS7XcDVb3Kj
         7uZxTUthf03EZRUynbWtxqOWUCPag480ppB6fcdj1bxx0pjGdbnW7J0XQo61HtWwkhqy
         0QMnXXOHy5E+gRVlCjLTypK3qGv+Magu4JB202jqkYgQkMraMiNPT8pVYk1aaUPgP4pf
         3PlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=oQBqUjSf;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.191 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763401886; x=1764006686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=aUSqK1iBtuuILxiUw1yhGxvFyAivwRXyEdybjzTsz4A=;
        b=oAMN/SgeDmlej805R+xchML4x2r0AuAqiC/eASOy1QxqyHbUc/9XQb2YukgUYotGwe
         YOPmA9UZ9b/RW2agN4ImNQDw2a/AVSOUlzTJmchFMrpGfOVUBE53EMDnpvO0vMnrjNgY
         82+Q9UGYuCDe5EcQW+vOmH/v5vT1AnBXI+cDLIDWayUitbiuCHCixcB0yLx73fDLnNvA
         hBdPO1iHcE/nd25YDqrU97EhZT1sV+NKQoYTZZz6qJH79cVcd/5FEluLELpozYbpskvW
         HWx0mY1LUaP1JLK3fMFdaLS/5yXKUcNXkiM1Rut7HRAKyVSSP+P00510jsun2NC7zUcq
         ugHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763401886; x=1764006686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aUSqK1iBtuuILxiUw1yhGxvFyAivwRXyEdybjzTsz4A=;
        b=mU3RL+hr08SBL7JLXOI+KPCEOPb9T3HglcWGnAdJCPVbc/ITKcWp2nCRK3nGmdswYr
         z5iaPOK9YYLaWSyyVNByh3vuDCGID1RqRHOnHrjtXqEN9j2RNvHy7H0oAXVq//ZX8WRl
         WUXdHIlBqlkVTxJ5g0nOB9cI1eVvr0XNZC0eRUx/U/G9pP0JypXx5YHgHOGNwwAmmLt9
         87NJ+RBkvhZqD8AmJ2Rhy8u+5z1oeCJa1wWcBTlDQn4s0lwLBKdUa3x5UYn40OMKJyOj
         sQe8aOCHdOhurdASAwSFax8UxGepG+ggUBZrDiAtX6qtghIeiwaWGhoQq40EuiE4VJEH
         /ryg==
X-Forwarded-Encrypted: i=2; AJvYcCUqg8Y5qgg2c+vWfdarvyGRLci8mJOklqedmQ/XMUKuu00pKGrcmC0e0wRhOWmP1ElqO2ycxQ==@lfdr.de
X-Gm-Message-State: AOJu0YziY1obqGrUSB0hAa/co9vYLxyMsMQLTVjlm35viHGF555AQnak
	nMZH6znR8aStAqhQtHk7KXqIVRRZGGdW9feArBXRS9vfungBRAMPcS6M
X-Google-Smtp-Source: AGHT+IGq8OTFaNn/Fj6iOCawti/g0kn7EwSB4Icrq/GuQOS2Grgq5f6o6YszzjNPiJ84wpWF09AI0Q==
X-Received: by 2002:a2e:b5b0:0:b0:373:a5ad:639 with SMTP id 38308e7fff4ca-37babb47678mr27296931fa.8.1763401886198;
        Mon, 17 Nov 2025 09:51:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bykMH6d16c/WYXOoKY0ybgL9U7sZnDtYS4K4NYvNflgQ=="
Received: by 2002:a2e:9d47:0:b0:37a:2b02:35d0 with SMTP id 38308e7fff4ca-37b9aacbe85ls11902651fa.2.-pod-prod-02-eu;
 Mon, 17 Nov 2025 09:51:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXdmwceyiJjNyzcJebYxfozllb2r3km2FMrB7m5zFVzyGoSKGRIt2kmwpfMyFxP2Wr8Fp8kIQa9AWE=@googlegroups.com
X-Received: by 2002:a05:6512:e9d:b0:594:364b:821a with SMTP id 2adb3069b0e04-59584208956mr4340549e87.52.1763401883949;
        Mon, 17 Nov 2025 09:51:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763401883; cv=none;
        d=google.com; s=arc-20240605;
        b=i6+6+WzfTbQR1ua1jUogGBu3L06Rz1iicPUN4P9GFSBCbKsCOAi1W3QujkuQEfAYAm
         Hm+xp+hGhGnc7eaO4Nus4jA/mrf5mAmxErosOy0wz56w3KPXtSkrwe2Yv/af+nYQJf72
         lLyS62scrpideNVkrOkkd5bQVN+e2SNYFIivAqO9TBb7D9LBwtvd32L5lHFGngsbO7Zf
         iLIYEEZOI2O9vlPW6/CHMM+JSAtN/bJfO7l5gufrRY4JyvDZUvKPKYofB+PCaZ4lxeKC
         a71N+pkSCFNsCzCZRRaQSd6leFYmy0zkmbYP7/6cV03DJy2c1WNc38Q4LRuqr1Ejth5k
         lMTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=8JHRGFc+rtU8gXb3Jyiztx9jQrUCtKtMFdopnkmvtTw=;
        fh=pQ1vhkk/efomAOaPxL/2ZLjFi2oxtwiOflVCStB+2no=;
        b=Pk5lzEtcpJU9KK91V8lmdKa8NCXT46KjEugLrHfOTqlmpfS5rxXnH7leBqjBolL2Ow
         ItrRuGm2zoli1vKN+xXofi0m4u96EjbY2c53wKdDhkiZdcZHQbaZ1/Qf0dcLrUPVrsOQ
         gCZG+MUuTkANZUjQ3sQsO93RSyd6aoilDjxJyBLjx8VrRgcSrNthd/deKWTOoidaY8q6
         FNZEtWT0xjBhYvMIOW/J/ED6CWRNMu7W58a1gZdZghvSTxIsgftsip5GTYHzD33NNxhe
         AUQqPH2R/RTLoen2W0rLX9gtUqL8lu8FsJbFnBciQk5UfYFxT7WAoo3N4oCw1hD8nF0D
         M0PA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=oQBqUjSf;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.191 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43191.protonmail.ch (mail-43191.protonmail.ch. [185.70.43.191])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-595803e7403si334449e87.8.2025.11.17.09.51.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 09:51:23 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.191 as permitted sender) client-ip=185.70.43.191;
Date: Mon, 17 Nov 2025 17:51:13 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, stable@vger.kernel.org, Baoquan He <bhe@redhat.com>
Subject: Re: [PATCH v6 01/18] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <ha5gz3hfjtfrmldzbscrbbtptecyqkwzkwdkjxnc2puqzquurl@nthv7frvqatw>
In-Reply-To: <CAG_fn=Wj9rB0jHKT3QKjZsPYce1JFcb1e72QBOBP52Ybs3_qgQ@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <fbce40a59b0a22a5735cb6e9b95c5a45a34b23cb.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=Wj9rB0jHKT3QKjZsPYce1JFcb1e72QBOBP52Ybs3_qgQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 7b84ae9accb4bc7551e617e5e7661cf28649358a
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=oQBqUjSf;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.191 as
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

On 2025-11-10 at 18:32:21 +0100, Alexander Potapenko wrote:
>On Wed, Oct 29, 2025 at 8:05=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> The problem presented here is related to NUMA systems and tag-based
>> KASAN modes - software and hardware ones. It can be explained in the
>> following points:
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
>> Refactor code by moving it into a helper in preparation for the actual
>> fix.
>
>The code in the helper function:
>
>> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>> +{
>> +       int area;
>> +
>> +       for (area =3D 0 ; area < nr_vms ; area++) {
>> +               kasan_poison(vms[area]->addr, vms[area]->size,
>> +                            arch_kasan_get_tag(vms[area]->addr), false)=
;
>> +       }
>> +}
>
>is different from what was originally called:
>
>> -       for (area =3D 0; area < nr_vms; area++)
>> -               vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->ad=
dr,
>> -                               vms[area]->size, KASAN_VMALLOC_PROT_NORM=
AL);
>> +       kasan_unpoison_vmap_areas(vms, nr_vms);
>
>, so the patch description is a bit misleading.
>
>Please also ensure you fix the errors reported by kbuild test robot.

Thanks for looking at the series! Yes, I'll fix these two patches, I've
split them off into a separate 'fixes' series and I'm trying to make
sure it's an acutal refactor this time.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/h=
a5gz3hfjtfrmldzbscrbbtptecyqkwzkwdkjxnc2puqzquurl%40nthv7frvqatw.
