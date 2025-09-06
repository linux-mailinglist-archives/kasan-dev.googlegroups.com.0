Return-Path: <kasan-dev+bncBDW2JDUY5AORBROZ6HCQMGQECYE73PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 139AEB47573
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:17:59 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45dd9a66cfbsf19670075e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179078; cv=pass;
        d=google.com; s=arc-20240605;
        b=jletLeY4QwgFSWOdNqYx8uOCzeJWWmV67nyKjtyp8rUnDNXA34bHykQa0M9HXm39EV
         Yzrc/ptsSo4YUfz3jY6Fm9+jn0sKhaVkGMkSkinjHDVA4OlKQ3VkECBk+wqkHpsaQBrF
         xKkMDM1lJPQX8wvfQMP14zA6vP6Sel6u39X78QhO0oCMfy2GapJAXH4I/xvtFT3vZ5iQ
         Dr5mVQe8q+DFNijMTFZXLnmdtsm9iT+dxsfdNVWkylkIOKXyBUuPpLLIjytPqBXKVq6J
         HCjKaMbEWe6+yOrgpRizdvhbEq/yVwDje54rK/He1iWqt+qMYiZNpsJY/Q3X43AVruQG
         Efog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+S/rDFwubDxhDoghRVS8F5cjZzunbOA1WFwlTDCCdn8=;
        fh=9UU0Q/So/fWA0RE3+KwtCIeQ1CZ7VPMZhE3Dlr++VCY=;
        b=AjmJmnyngAi2MyM3vFxDtVPgwTUNuWx8debkxxZL1Aa4d7qWDEAMB2Z+y+IkXLcoPN
         5CXH9xMB49gKStQA18iPPJgVjCzB0txTJ2EW5e0ZFnVdgMlRA7lzIqisycltHCHoHUM3
         LIqQlghehA4X0meC+SSXyGvQ7mFcjnwzW8w6GjhF0qVSX+HsUxcYsNwiVbIbnoMLdGh7
         jMDkrAuo4dwudqQLxe383oFb7PdqMT3dbzfV3NKnzOtetMKdt8xVzXfgw5jFcNn3nXAr
         xt+qDW53Ga3lD4vTwRUcGvO+c/6FAGSPRqnoAZ6sp+vFspjFjeFCuc1EHi9QwoCsRurY
         KA9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jRPk4VQ2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179078; x=1757783878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+S/rDFwubDxhDoghRVS8F5cjZzunbOA1WFwlTDCCdn8=;
        b=Mts4acd/yJqdg6NFb3rMQUBdAGe5ftK7p7rdUbVKh0xwObs1FXyYE4Ab2ou7xymr0A
         dUmc3gYTmtvfdj/sZJQRZDlOr6o3xD+dD7qpJG6kCFmSFZ0B+P00q9u7Gd88GXhyv+RJ
         OuBIUciyhq9uma85ookp3X4dJ2V1qqXCJk8ARHYcYtxSxBPGuh6HdAHbVY9W18UWodpX
         qSrfZcmoZWMm40sZGhONyK6X0b/0hEe6AjPKXDzN71+ibT/oFW9SH5dh07wJUhZiYWUL
         lvnAM/0KvJpZQLCVkZXCLrcftPBnVHsjeBw7S8Yf/zrQW5rVeLBJSoKRe0priD8TTk0T
         eSaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179078; x=1757783878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+S/rDFwubDxhDoghRVS8F5cjZzunbOA1WFwlTDCCdn8=;
        b=ehzd2B45iCOadYgvk0J86x4zk5RJf61g/RqjelS5IeAy2Y7IN79Xayr3TQfoujZzVP
         8ezejBz9fNv5vNfFfjMvrHo8q6LXeG2acTaBqQa3Gxd1agWXUUy+YEOea+usnHAq+dmO
         Z4wKsavgLa709/eV2d1Y+hd5KE2RrFdJI+TdxwvV6MZhM/xl+J50pf9WTzKEyWmB8hEM
         P6aA2pqlCyQfSYlBcTu1q4DfGTESO9R2SDDSmROgncpNLaUCkQbjVJNOOJShVPMNcq8/
         Ptn80hWOvxow2gyzNkq/HZSxNR4+sEeorXns91KXfiYUyoQ7QSE6VSW+jOAKOMLIXdAz
         /UyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179078; x=1757783878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+S/rDFwubDxhDoghRVS8F5cjZzunbOA1WFwlTDCCdn8=;
        b=Vz1JqC9jReDswLhZA+DyEnbOCMZ2lokNvKNoH0g7TmQESZDmjLvNNXzM6rlM+XSYSt
         Q4D9H5diLRF8RZK470wF7y7t5ERCDjHXTxDy58uzA9/kKBlI7QAQnO9Arj1Tt+YgAfQ+
         162EF7KHYPAoefcXLRfLbh4GhraI6CoQNYuLvQyyo53jC+MrljesGeyR2V38SFGAUrTY
         NolktqaTH5Sq11j09h2DiBQYNbvtNntc/kGshzrdaRy4N86x2+o6MXeQzdjZ1wCvJRLa
         kyZntTl3kwEnKOV34Uz0lsRPpN7HAVSxLQuy585Igx6iQZU94jAbbbiEhe7hwZ24Bw1Y
         MPNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7Yqr7zOCnhZCo+D8mr8oAEUE/43vTGmqYmKUfx/sUXNUlODbJB8r47QfxB6x3p8nc2TNGCQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAKNgqIsPL65WDSERv3gPLmv9KRI+uV2gouUoeo2nrqwFnPmOI
	k4wFXfiSZPnD9yx94hv2ona3u5/mRA6CMjReSfQwW5H+rRxEsN/ENahm
X-Google-Smtp-Source: AGHT+IH/1zXCm6WYj1EGYlGjX0SzcpXDU2XmFVFEYpYB0aS/K7IzPkH4V1RTPkFNp2O8cF/47IoKnA==
X-Received: by 2002:a05:600c:3acf:b0:45d:dd9c:4467 with SMTP id 5b1f17b1804b1-45dde86719fmr19941925e9.7.1757179078297;
        Sat, 06 Sep 2025 10:17:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+UOE7TxvKRIsgEpqJJQ1aLSq3S3qY83PUy2n9tC8FRg==
Received: by 2002:a05:600c:5394:b0:459:d92a:8496 with SMTP id
 5b1f17b1804b1-45dd80547a2ls11953385e9.0.-pod-prod-07-eu; Sat, 06 Sep 2025
 10:17:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQUnhyqx/47oUb+b3G1CeEXrG8bY9LZqm2zmGlGjPRLY88BQov0dlRGaHjPOY6H01G5YMxV6xmsyY=@googlegroups.com
X-Received: by 2002:a05:600c:6610:b0:45d:d286:6e06 with SMTP id 5b1f17b1804b1-45dddebf879mr26077005e9.17.1757179075587;
        Sat, 06 Sep 2025 10:17:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179075; cv=none;
        d=google.com; s=arc-20240605;
        b=C8bMTfidTbs2Z57b4t4El0hKOIughf1uZ6GM3t8JhS/TV0h3ST2kNSCzNRwmJdwZvC
         XUnVgP04zLmhNAq5s96aHrJ8xObxbegVZhF2n4VxYdKS3D1xU8yQ4JW3WJCzfuDt1QZI
         WtvS4X5t/8B2qLsCZHffYSh9YkSHg/SkEfXd+Kx1TNKONI/OsM4bF5LaRAgoV3Giaxg+
         IGVcbR1xX/xqQRCtVLUXB29I3oIK11vXdaLlfihn7B2QHvDMpGOkZIMCujCtgD+DYN1O
         dEfIwLhILVEyg/z5Z9Ld0yguNqC/g8FvwGsjYfp9jyqGTn5icuHtlywr6UvPan0zlIGG
         oRxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8m7gNbOiJ7wFumA8eH5KhxcoFHJTBnL28AX35/mxZ5k=;
        fh=aAwfgHvM1NYn2d6sLrZ71Wqaxv5SrnFbylg8cj+6u6E=;
        b=RtKCu7U6t5MWwLfkY1o3rSbaubzk5Cbr0b8RP+ZHgqK8o6xtsW4nEqzM5psIEQy+To
         mpRcEuRGhBKVPGC+CsrF2NHOAjqbsaVEc+eAdIAXXlD6V3Dv/2KIM7GQ5EZZH5XTNTv/
         ayTv4PzNc8JnHCdzH++XTp1TSnhWVf0fzSPQ+NEe2fL4Ep4ETL28qdCMxdPzqlJ52bKz
         OEMJ4mcHVJ1sAOGOzpABmyX4cb3DL83ldskpUwAaQO6mtX6xeIR/K57NXcYd2TiHV6S9
         0opXcMDcqznO4leidqisIctz+rl8vVvcLc/JbLtgc3AidYbu4sR0mEdQ61rI+upeH/L1
         ShOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jRPk4VQ2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dda4558a8si846625e9.0.2025.09.06.10.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:17:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3e537dc30c7so1144789f8f.3
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:17:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVC+mHIe2t3yuEokNqDLLOTpN70KJsd8jVPnk7bg5j949g7kL7YKoRpyZnCPRmOlfYacY/sA/m6yc4=@googlegroups.com
X-Gm-Gg: ASbGncvOtcoqh5+psB2LePh0p7ZSe1Su5NFd6QvEB3GY22rfRDt/A4jbzTLsF/imguo
	C7XMq7H6iTcSPljFumH1BycilY8wXNOl0as2YkAz4zVJScld4Y26QaixDqq9jQw1pIxRDf3JwH4
	Qh4qqiG9r391v3NYUC+wPx4qL5Q3Cn1vsHGA+Ubj9myKJjpz63jCDzUd4TxTtFsSANqOasdnLbz
	1hHzjNz
X-Received: by 2002:a5d:5886:0:b0:3e4:64b0:a760 with SMTP id
 ffacd0b85a97d-3e642026e72mr1764739f8f.18.1757179074706; Sat, 06 Sep 2025
 10:17:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:17:43 +0200
X-Gm-Features: AS18NWAccC9JiiN3oBmxBjTrrK8-6qYxZFkRTV1lkD1J_h60FmCfpfZ83r4hey8
Message-ID: <CA+fCnZd7tM5i5jOriaYyR1GgjgREv0PhyxpFuEC5506FkndzAg@mail.gmail.com>
Subject: Re: [PATCH v5 04/19] x86: Add arch specific kasan functions
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jRPk4VQ2;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Mon, Aug 25, 2025 at 10:27=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> KASAN's software tag-based mode needs multiple macros/functions to
> handle tag and pointer interactions - to set, retrieve and reset tags
> from the top bits of a pointer.
>
> Mimic functions currently used by arm64 but change the tag's position to
> bits [60:57] in the pointer.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Rewrite __tag_set() without pointless casts and make it more readable.
>
> Changelog v3:
> - Reorder functions so that __tag_*() etc are above the
>   arch_kasan_*() ones.
> - Remove CONFIG_KASAN condition from __tag_set()
>
>  arch/x86/include/asm/kasan.h | 36 ++++++++++++++++++++++++++++++++++--
>  1 file changed, 34 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index d7e33c7f096b..1963eb2fcff3 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -3,6 +3,8 @@
>  #define _ASM_X86_KASAN_H
>
>  #include <linux/const.h>
> +#include <linux/kasan-tags.h>
> +#include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #define KASAN_SHADOW_SCALE_SHIFT 3
>
> @@ -24,8 +26,37 @@
>                                                   KASAN_SHADOW_SCALE_SHIF=
T)))
>
>  #ifndef __ASSEMBLER__
> +#include <linux/bitops.h>
> +#include <linux/bitfield.h>
> +#include <linux/bits.h>
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +

Nit: can remove this empty line.

> +#define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
> +#define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
> +#define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> +#else
> +#define __tag_shifted(tag)             0UL
> +#define __tag_reset(addr)              (addr)
> +#define __tag_get(addr)                        0
> +#endif /* CONFIG_KASAN_SW_TAGS */
> +
> +static inline void *__tag_set(const void *__addr, u8 tag)
> +{
> +       u64 addr =3D (u64)__addr;
> +
> +       addr &=3D ~__tag_shifted(KASAN_TAG_MASK);
> +       addr |=3D __tag_shifted(tag);
> +
> +       return (void *)addr;
> +}
> +
> +#define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
> +#define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> +#define arch_kasan_get_tag(addr)       __tag_get(addr)
>
>  #ifdef CONFIG_KASAN
> +
>  void __init kasan_early_init(void);
>  void __init kasan_init(void);
>  void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int n=
id);
> @@ -34,8 +65,9 @@ static inline void kasan_early_init(void) { }
>  static inline void kasan_init(void) { }
>  static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size=
,
>                                                    int nid) { }
> -#endif
>
> -#endif
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASSEMBLER__ */
>
>  #endif
> --
> 2.50.1
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd7tM5i5jOriaYyR1GgjgREv0PhyxpFuEC5506FkndzAg%40mail.gmail.com.
