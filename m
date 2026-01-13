Return-Path: <kasan-dev+bncBDW2JDUY5AORBON4S3FQMGQEP74GAXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D4C21D16256
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:22:02 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b686eafcfsf4197029e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:22:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768267322; cv=pass;
        d=google.com; s=arc-20240605;
        b=GEcORyCdPraeP/xjiKlk9bGwK1ES/vjPoiRqAYImE2UXj7invmuuQWnGVs08DhO2Y9
         kC9+gAV4gFbED0thVfxIjJbg+KQ94fFIcIWh5g2Wdjn79al/JScZaSpUQUaV+grIzHHB
         AvWiKmf1pVOrrWv01cPIKBi0PuetCTTXmUIhbXOSQaZ5dcJDf/PHcp/IyCiUfJrjVHkF
         0Z8hU3T7kjxD2qXrJ/Conmf/D8Kjea9Rx4pdKErKh8PMSwAPH3X23R4BfJdowMeR4z5c
         UyJKKStgKz88PDCStmyzi9JZ4QDTy3dpv4MqlUIFN3me3+rc2w+iF2/C3X6FtXhRUSSy
         eBRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=mQl5fJWLE8cLVvDf6Mfq0VDGnUepvvs/1729gxFpl6I=;
        fh=OYcvy3UDfgIH8ZmJYR4v3YkCuygrou9ysgYGKVjyDdY=;
        b=P7YyQ8pzB5vWVHosY6+51irIhG5ZQzS7HPyDnD/l1a6VRV7tRB3Spv9EyI5yrMTXAt
         GtCBZKJJkLqxxcVO62O3afY5NvdCbt/6sZmmtCK9WYcV6aXphjHMt+FWo/1NbKsYooPJ
         QaqR4ZIom9ZYFxsRVfJ0ghxujxk+hlYpQINeoMs5F+0gMzXyXAJi9GqeWRGb6mLTn2Gf
         udScmfsxptKQ/CtlqGgT5W/yHPS662g523z9xDgbflakmXvRq5APqAN7SEAwjTMr1XiL
         KUg3yzkv3xEWx6pOVfDQ0THhqTgPjfaUXTaS3Li8oLM8z8vTCkuECyfOWD1REzVmneSC
         30Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AeiTMRhe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768267322; x=1768872122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mQl5fJWLE8cLVvDf6Mfq0VDGnUepvvs/1729gxFpl6I=;
        b=U6J1cesm1E/NQwwfgk8lHe+BnD8VjueDZItCTv9jCxklLkWc2zwJL0wmDi13Er3epR
         LolxNKn7EsW4WN9SSEANJitSQM2YLdcokL7W9IEgk3GRH7OqKdktIGrQNr6PBTNkQLYh
         yTEma6kTZzXn4kamY814J6ELmH8AC29xiXZK33uu8KeyuE4bHd6epBafVjGJT0fdJxGD
         jZM7yfxCTR8PuHbGkn21ytiiJr/VLgaZnGg/9DlWWZlo28mIS5VUrjHG1Gh5rTMq99le
         3tvRG8KqT7Gxi54CXCMc04TSlu3YEJB089h5UXi/HOmxAtW+Vb2Rd8WGUISWx+cEv9qn
         vzIQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768267322; x=1768872122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mQl5fJWLE8cLVvDf6Mfq0VDGnUepvvs/1729gxFpl6I=;
        b=c76weDi9zHVehWArHBK2q70rpoaRc+draBj6fwHYqSnrmV8I2fAPnZq3cg3RkUw6gE
         oxxeJYNbykMhBBJAb3amE7mQV84CnnPFZh1z5iJys6YUItI/gr262anQ9evISRaa7Dmn
         yenHMQnH4Q9alF8zuVsOqBHtu7CarmMhjlbYxhqakYyx4TKZPhoilVje72DZOMKDkodE
         KBQXfR2IgbfEeslp0AF7BatArXOUFu4nkiTq9/Dl7SBCfKuPpha9eSW0IUaX8SZOrhTW
         jcazl6JNL5a4LU9oY89k3DNdBY/yWBb5ujzDlLWPh3eKBaAw3e0SL95805sHazpfzyo7
         BmsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768267322; x=1768872122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mQl5fJWLE8cLVvDf6Mfq0VDGnUepvvs/1729gxFpl6I=;
        b=O0ZfeDr9kNMrN/bIORHuRajMvuHUMpYd3sbBW90SeU5YfVMdnrrwj4hisMwtBEJ9oG
         nwlIEVzWYUXl6hrjQAzj9LSfc4JTnaqtqOtrm6ZHIOnhQySDEX4PFcvxKBkKBhF8W8wb
         QLqXwLoRZGYMwGB5Wdq8YWhsB45HY06NVz/FqJ4tj56u/fxGIrPqHR/CX8UgGIeNnTy4
         hTpnB2UygeDSPrDJrZoe/NWu+PkxeyV3eCuDD5H/lzg5X9S3F6o4WQ45mNNxDgSK++4I
         h/439TDjz2l0+h2WWWHoH21WQPSZyGPCnQXSuPMEFWi9i424m8Uto8BcHvOujzw7XFlA
         PBEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUU3OULBiyxS8zxtpZFroqgmdyjanScOc16v6eM4KgcAg02ns7sR2rf8pZafJaDE6fo1ix9rQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYnGx4DSD8igWyxE/B7ub+jIzEafTO+yh03OSYoEKVUYJQxMpK
	6MN24LJz6UxXkORkBjQrw04WwUU0VJ38RyvcvZA1BgeYaFA/8MhVsqGY
X-Google-Smtp-Source: AGHT+IEoWZe85an5gO7fZ0pu6vif+rw3ve4/1bTPQY2g74VrvY7+ak+fnYXPdmofJaT/IGjYei0+Kg==
X-Received: by 2002:a05:6512:1509:20b0:59b:6f3a:9c5d with SMTP id 2adb3069b0e04-59b6f3a9dd9mr4135373e87.6.1768267321804;
        Mon, 12 Jan 2026 17:22:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E9ZqWTvaSiOTK6raelyLnoisLb8zOY8L5ZlYaixrjpdg=="
Received: by 2002:a05:6512:1042:b0:598:e361:cc93 with SMTP id
 2adb3069b0e04-59b6cba0ff2ls2331909e87.0.-pod-prod-05-eu; Mon, 12 Jan 2026
 17:21:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjNsMNSwfzASRr44gqrH46XicQvuyMHJum7R5LbS+hDuwXwkID2PaP5Rd0xoLLCrdMshHFV7Kwstw=@googlegroups.com
X-Received: by 2002:ac2:4e0c:0:b0:59b:7b86:44d2 with SMTP id 2adb3069b0e04-59b7b864515mr4071867e87.18.1768267318890;
        Mon, 12 Jan 2026 17:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768267318; cv=none;
        d=google.com; s=arc-20240605;
        b=L8dHSFVFFWow860cO65VgMxIVrFk+W1HQiUkGySqKmw0tfCF11IA58zO829X/QN1sh
         6d+bRtlm03Lmmv4MYe01i687rL/GqHBQTZZzXZzbKEj4t6r4/8VvCv35qPLG48oU/SB2
         IAp7lFM7OthYj2wnnVPHx9Y9epsHl9EUE7P/i5qNcuE9DP6hb7SRjNFTp2CZiN9i/KnJ
         ZBdWmT74gAugY71CN72zTDOpIHMMNYn0/bb4K4TzaSay9gnpWYjsGnCYAMm9Jtkf5ZK7
         SU0gmcMIvU0i2k3zN6ceRN+P3VxHqzGRlQQdEX4uIdoXZXdvgMvf+HzUQY5iRT+BqYM3
         gfzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V98bbCaXhvCSK3ORMF0ddg8nJ4GMw1PJ4T3czKQPpIM=;
        fh=6otsKiCLBnDxEW+zllAy3waH254NdmlW8oHpg5iXdc4=;
        b=QrbTjrOQ3ftY/0eS51BRrWIqfRlqX/JNccHHkKTSP1Zy7dZYrOUGRZRT23RVr1HnB5
         KYQWrVv7PfXfpBrPI5GKFp7zDB2u8CmW0qPnKyLD9YB7r5f30BhC0WXAc/M/50xE7TrZ
         Ck/rNSBQU222Z8xXAp16MJigUjqRyRQ7Og9i5qJbwxRv6pC6SkMjIhKX7wjVvK8SF+I/
         q+LGsgHorFUGnTjRH23vBUc20VpjSiJIaY33BuBxa9n5bJkdgZ5THoDG7C2SD9NTeEpZ
         iHlb94UpgJ4VW13w8COHuqE0wJWy/wNi0TVTq6DIhcukO+pz96CH8hdIZNdXa41NzfY2
         uR6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AeiTMRhe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38319fff95asi2047651fa.1.2026.01.12.17.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:21:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-47ed987d51aso1651185e9.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:21:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUMCWsSo5kqA+VyaUv8D9PV1dy6BbtkZsIDER7hX1NDZkQLt/Wdc6JC9eNausAWWLjuvXMScdxtE24=@googlegroups.com
X-Gm-Gg: AY/fxX4pFKemkW4jJI2Tk6Usd+0jCJk7367XvgOyYnwZckmY7meWYKu+LmopCwyribC
	EQoAodqxxX0CN5/v+SIX8wp19a4nnZKyvh6PXfTrx18fpOMfiOivoDIeKj/v+E4uWhRoTNXVBWl
	eh813XHvK43TYeCDsQ6dEHMrwXJEWrG9dgqw8BINURx1HyRcrqLXpvGfZSZ1dQJafvV7APDzcLM
	SDUPvquvBOXcDZiW6g8oLX36WhSdND/8ijFK16TamPBqQKQSL2AqOyKr1795WbVxRMZYlXzlgIp
	meYfXLpflfz7LdHhvg+chexCEoMy+SsnA3NFWUq3
X-Received: by 2002:a05:600c:1392:b0:46e:37fe:f0e6 with SMTP id
 5b1f17b1804b1-47d84b3b724mr253049155e9.30.1768267318036; Mon, 12 Jan 2026
 17:21:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:21:47 +0100
X-Gm-Features: AZwV_Qi5qDo_RW3GUl03sUQLy4_9JT9vPGqPKV7l-vPxKwl8DzaLwsGyVKGsEyg
Message-ID: <CA+fCnZeVEDwojqUfT1CC10sLZiY8MVN-7S7R6FP_OHkU3TH+0g@mail.gmail.com>
Subject: Re: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan available
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AeiTMRhe;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jan 12, 2026 at 6:28=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
> ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
> (TBI) that allows the software tag-based mode on arm64 platform.
>
> The value for sw_tags KASAN_SHADOW_OFFSET was calculated by rearranging
> the formulas for KASAN_SHADOW_START and KASAN_SHADOW_END from
> arch/x86/include/asm/kasan.h - the only prerequisites being
> KASAN_SHADOW_SCALE_SHIFT of 4, and KASAN_SHADOW_END equal to the
> one from KASAN generic mode.
>
> Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
> of memory map to one shadow byte and 8 in generic mode.
>
> Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
> CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
> support is available.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v7:
> - Add a paragraph to the patch message explaining how the various
>   addresses and the KASAN_SHADOW_OFFSET were calculated.
>
> Changelog v6:
> - Don't enable KASAN if LAM is not supported.
> - Move kasan_init_tags() to kasan_init_64.c to not clutter the setup.c
>   file.
> - Move the #ifdef for the KASAN scale shift here.
> - Move the gdb code to patch "Use arithmetic shift for shadow
>   computation".
> - Return "depends on KASAN" line to Kconfig.
> - Add the defer kasan config option so KASAN can be disabled on hardware
>   that doesn't have LAM.
>
> Changelog v4:
> - Add x86 specific kasan_mem_to_shadow().
> - Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
>   KASAN_SHADOW_START/END.
> - Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
> - Disable inline and stack support when software tags are enabled on
>   x86.
>
> Changelog v3:
> - Remove runtime_const from previous patch and merge the rest here.
> - Move scale shift definition back to header file.
> - Add new kasan offset for software tag based mode.
> - Fix patch message typo 32 -> 16, and 16 -> 8.
> - Update lib/Kconfig.kasan with x86 now having software tag-based
>   support.
>
> Changelog v2:
> - Remove KASAN dense code.
>
>  Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
>  arch/x86/Kconfig                     | 4 ++++
>  arch/x86/boot/compressed/misc.h      | 1 +
>  arch/x86/include/asm/kasan.h         | 5 +++++
>  arch/x86/mm/kasan_init_64.c          | 6 ++++++
>  lib/Kconfig.kasan                    | 3 ++-
>  6 files changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x8=
6/x86_64/mm.rst
> index a6cf05d51bd8..ccbdbb4cda36 100644
> --- a/Documentation/arch/x86/x86_64/mm.rst
> +++ b/Documentation/arch/x86/x86_64/mm.rst
> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unus=
ed hole
>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual =
memory map (vmemmap_base)
>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unus=
ed hole
> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory
> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory (generic mode)
> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 56-bit one from here on:
> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unus=
ed hole
>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual =
memory map (vmemmap_base)
>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unus=
ed hole
> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory
> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory (generic mode)
> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 47-bit one from here on:
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 80527299f859..21c71d9e0698 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -67,6 +67,7 @@ config X86
>         select ARCH_CLOCKSOURCE_INIT
>         select ARCH_CONFIGURES_CPU_MITIGATIONS
>         select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
> +       select ARCH_DISABLE_KASAN_INLINE        if X86_64 && KASAN_SW_TAG=
S
>         select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE &=
& MIGRATION
>         select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
>         select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
> @@ -196,6 +197,8 @@ config X86
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN                  if X86_64
>         select HAVE_ARCH_KASAN_VMALLOC          if X86_64
> +       select HAVE_ARCH_KASAN_SW_TAGS          if ADDRESS_MASKING
> +       select ARCH_NEEDS_DEFER_KASAN           if ADDRESS_MASKING

Do we need this?

>         select HAVE_ARCH_KFENCE
>         select HAVE_ARCH_KMSAN                  if X86_64
>         select HAVE_ARCH_KGDB
> @@ -410,6 +413,7 @@ config AUDIT_ARCH
>  config KASAN_SHADOW_OFFSET
>         hex
>         depends on KASAN
> +       default 0xeffffc0000000000 if KASAN_SW_TAGS
>         default 0xdffffc0000000000
>
>  config HAVE_INTEL_TXT
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/m=
isc.h
> index fd855e32c9b9..ba70036c2abd 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -13,6 +13,7 @@
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
>  #undef CONFIG_KASAN_GENERIC
> +#undef CONFIG_KASAN_SW_TAGS
>
>  #define __NO_FORTIFY
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 9b7951a79753..b38a1a83af96 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -6,7 +6,12 @@
>  #include <linux/kasan-tags.h>
>  #include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define KASAN_SHADOW_SCALE_SHIFT 4
> +#else
>  #define KASAN_SHADOW_SCALE_SHIFT 3
> +#endif
>
>  /*
>   * Compiler uses shadow offset assuming that addresses start
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 7f5c11328ec1..3a5577341805 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -465,4 +465,10 @@ void __init kasan_init(void)
>
>         init_task.kasan_depth =3D 0;
>         kasan_init_generic();
> +       pr_info("KernelAddressSanitizer initialized\n");

This pr_info is not needed, kasan_init_generic already prints the message.



> +
> +       if (boot_cpu_has(X86_FEATURE_LAM))
> +               kasan_init_sw_tags();
> +       else
> +               pr_info("KernelAddressSanitizer not initialized (sw-tags)=
: hardware doesn't support LAM\n");
>  }
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index a4bb610a7a6f..d13ea8da7bfd 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -112,7 +112,8 @@ config KASAN_SW_TAGS
>
>           Requires GCC 11+ or Clang.
>
> -         Supported only on arm64 CPUs and relies on Top Byte Ignore.
> +         Supported on arm64 CPUs that support Top Byte Ignore and on x86=
 CPUs
> +         that support Linear Address Masking.
>
>           Consumes about 1/16th of available memory at kernel start and
>           add an overhead of ~20% for dynamic allocations.
> --
> 2.52.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeVEDwojqUfT1CC10sLZiY8MVN-7S7R6FP_OHkU3TH%2B0g%40mail.gmail.com.
