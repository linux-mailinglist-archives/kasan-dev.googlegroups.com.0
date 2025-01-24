Return-Path: <kasan-dev+bncBC7OBJGL2MHBBENUZW6AMGQEUQUKI7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE819A1B26D
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 10:14:59 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-21650d4612esf51540205ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 01:14:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737710098; cv=pass;
        d=google.com; s=arc-20240605;
        b=XNjmJYwleClUQsFalwWdpKQj6bIrjkahp/of8smFd5WSUf1RrsNLskMF9TUxT4rkys
         /lUFwuy1H8v36k5TBISLDQ+FcqE+Q1Rw6SU+Uh5ZNziQK5TXS5Y9JdORO88eZ2Ws0oXi
         bF7WYMhuZssmIenm7i+q5XiCrJ1k9cbkRTQHke58a9IHNWq5oNB9e/gIA+FIEtao4tCE
         DVt9dIo4IUPKqYel93/ZC3W6CfSK/zBbO2CN6WFwUVv2vJ1jbZ7/jaLUW2GTAwEaN15M
         c7fhbt0XLZhiZGt4tN25CyD0eQNfLoku+rFfwhtNZaQ0lbvJaidsQxuk0jJE12dO/z1O
         ljlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2ODua8M1qbAvJJiziFc8ZSam5cG+jzGJLOcqR9LNK3s=;
        fh=k79GOPxXghG2iWexTBJcep37kP/NODiZK78qeVGssvw=;
        b=UHIwTUNm0kUkaWmOkj8MoAddKM/PyI43A0C1eCTIKgMnm54KZ3MUPHA3+IgoMpkuhO
         wFcu4vVqDudKhK/JrE8yz90SyY4x7WOeh0Aowa/gUFQWKGAaOxaty9U5O46viNl7m4bl
         Qw0oAYR6wxGrPcpKyM0VH7yeAFDqP7xyHm0dtdzk+Xi+GDuwMUQp9rjCg69lihwI2M+0
         sOd/H6VReZaRUPLEi6X8MEnrW41sQB6p6ij8qIK5z3RHjmv8HmgWw7R061u1CK5RaCle
         4GDKkIpeL8CmHy/ES4tvrYLmJlrPebHNju6ahjk5FbjzrrC/9Jchl2HjSsgn7rXv8qzU
         zJDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tVu0aBxv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737710098; x=1738314898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ODua8M1qbAvJJiziFc8ZSam5cG+jzGJLOcqR9LNK3s=;
        b=M35bo+IWhDiNx+Q/z1+tXVQZBzwAWq34gVzauk3NEQLavLancJPqUjayeqJ6SE2K8P
         +0+WAV6h6hLHnPnWc7PrtjCwbPXHn2b8QjcGITntY7OmEMAeeBLx5p29AQ2HLePZogrl
         DDx8MCtjWchO8J1Ctk2JJfZj7/1Vf710uSgjpeOc+4hmCs87KYsrk5UGu2LeLyS0lyUg
         KsoB1QHYX5mwgC4XPxbvmxQLhg6e1JzkWVD7uwxSb5u1wMuVJzkgSNQipa58yS0YbL1+
         K0GZ4VXTgWFDiANjxKyzNOltVcPbHguD3rKtZj97RvMam3+olXAMg1KJCN6G1WC+JLme
         LV2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737710098; x=1738314898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2ODua8M1qbAvJJiziFc8ZSam5cG+jzGJLOcqR9LNK3s=;
        b=kkPbbKWsR+05BuBPK4XaCCmuDoZ2iOha6gWGFGpzDrMxYVHRhHr8NwIum6yr/yNUVx
         Srn4Tl5Mj/VXtcJqoIDP/eiFmq4Nyw5HVshnT2aqp67lyMfB48Z1lXNV1eIKW9AEA2gr
         ajUENjmPJs1CFmw9AlYIMoRrzKLti8Qj/AZCCPlGW3Aid1BAAYu6zASYVBtasUj5K1GM
         o8WP6p8V4cbzHr355tvG2ceKl0H+aiTOxs2RD7Mpp9vs3KWjtR4ioM0XkpnzUBFM8oBq
         SB9xvpGJmTs5XLGLuZeKJFMom/gZxotmJxZxnEy/RE2Zh0j+OUsrxb7ttfOvFPcSKoO9
         N2yQ==
X-Forwarded-Encrypted: i=2; AJvYcCXIloYpD+/5T7uk0pz06allTFecNkqV+5mZLZ944w+GodtPD7xp1Fo3N726z/bAegyjWDkFYA==@lfdr.de
X-Gm-Message-State: AOJu0YzkSJt81aI0ig2RVnrFLoTTH9Z20gyNKP1lrP1Mro4QeHsto0qF
	u219sM21B8yqUOU2a+vU/xe4vROpy2Ps/mG4ZXr3uub+qwBECrFm
X-Google-Smtp-Source: AGHT+IHyNIYn1p7iutXUfcFNFQN5REsCcygd+l7K+BveEo7JckpWWB9s2P/lFFGo+mblGT72mEcScQ==
X-Received: by 2002:a17:902:ecc7:b0:215:6489:cfbf with SMTP id d9443c01a7336-21c352de2d6mr416474555ad.11.1737710097951;
        Fri, 24 Jan 2025 01:14:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:bca:b0:21c:ca7:3fe3 with SMTP id d9443c01a7336-21d994dde9cls15270315ad.1.-pod-prod-06-us;
 Fri, 24 Jan 2025 01:14:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWTmSkQlLY8Nm9waJwqwncH5/LLbe4nKl2dpyB9vGcKzF71z2WnfT/gGUyf2coOmXSYFTaHXHNaCxI=@googlegroups.com
X-Received: by 2002:a05:6a21:99a2:b0:1db:eb82:b22f with SMTP id adf61e73a8af0-1eb21476705mr41093677637.5.1737710096452;
        Fri, 24 Jan 2025 01:14:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737710096; cv=none;
        d=google.com; s=arc-20240605;
        b=f2CLuXbuOHwmq7SmOoEA5gtfvUeiu/WKAhsmBpYigCG44MgDTsaMKXY1fU+ijuFNWb
         4z8DfS5lwfYspfI9YF6ZFMnR8d6C7iryJfn/iKMacCL3ayMnOzG7649Ei7WLbRn7+N60
         kFtDb0mObE0d02WzpecqbkWFZ/swL7Z26Pa0DvLeo5ltLZtfJlrAgKtoApkQxxxhqvL/
         J6xHS1wSDputwkLqjg0uvEevboZNuTyzH4NWRdmrsjj3SDX8861iBH93djAB1+R2J8S8
         AzXNLklrRvbS6OHTYbcCYJYHcyipcJp/nLVDEplSmD628lC/3ZGhTSVc5CUeLK6aR+sU
         wx4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BfJugkHmmfDQH4XzuB71/6BlU/7LvV7l26SCjxzi4Ds=;
        fh=ErVLTN6PQzjVUPUD5BUOrvTyjCIMfyGUT7g0q2N7emI=;
        b=iN/ixzEJLEgYh7WfMsVgtgXf4sjjMbBEkD7S0BQMq7gBldBhHIQPAInDytD3r7cdom
         RIHaA3I2u6dWgaurlHxyY7zyyfZFWYFhbVHwOxFDhP0k3a1Wl1RFXp3TmyRdDg5uWKbg
         m3AeTd7RQzFNmnffY7d1SP5pQgu9hdEAyptT0arYPBAveg9vef2LWET+wQZGuMWHBLqJ
         Y9lRbHzXkgVBOAO9jmtGlI5zUof9rDCd04I7eVYOP4Hfl/5rX50rEKnqiBzFHieGHN+a
         5qsFOCqg3EGMBHSHee0sTYFpMSNKWnmMLW+80Kd1jsAyee5xcx4mAx608qBHteknu9GG
         lYRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tVu0aBxv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72f8a73e2cbsi72036b3a.3.2025.01.24.01.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2025 01:14:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2eeb4d643a5so3525750a91.3
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2025 01:14:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUxsobGeOQWsgQtjWYUgPdNmbSqOelGcIfIZ3HPxPqL/HDj3FCWJ2p1vsU5gxfIfbYwy8l9fHwM4Xs=@googlegroups.com
X-Gm-Gg: ASbGnctI4PyvAzzdV7c4dWcS17+AxomzTBqRqz9lQrWCMiIV5zDS8HTXGhFJiwdvWwk
	FmX2hSCWjDJOdisodzX4HsElik7sQzxOIXVxF3xAc/PnYGrUhEcZziwrKDzRz2ahGhr0Kf+6u2j
	EjQOKU8ElpvItvJ0p+NA==
X-Received: by 2002:a17:90a:c883:b0:2ee:f46f:4d5f with SMTP id
 98e67ed59e1d1-2f782c669admr39138288a91.6.1737710095835; Fri, 24 Jan 2025
 01:14:55 -0800 (PST)
MIME-Version: 1.0
References: <20250123-kfence_doc_update-v2-1-e80efaccc0d4@gentwo.org>
In-Reply-To: <20250123-kfence_doc_update-v2-1-e80efaccc0d4@gentwo.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jan 2025 10:14:19 +0100
X-Gm-Features: AWEUYZkWVGLKJhEO4MuQJscF4LBBjUtoFnkHM6vXTs2MTpAdzInzcHd7Q89BN1Q
Message-ID: <CANpmjNO9L6gv9rK-WntLgAPde5Se8WjQqNLHZNGQFXZXRG2S7w@mail.gmail.com>
Subject: Re: [PATCH v2] KFENCE: Clarify that sample allocations are not
 following NUMA or memory policies
To: cl@gentwo.org
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Huang Shijie <shijie@os.amperecomputing.com>, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Christoph Lameter <cl@linux.com>, Yang Shi <shy828301@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tVu0aBxv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 24 Jan 2025 at 03:06, Christoph Lameter via B4 Relay
<devnull+cl.gentwo.org@kernel.org> wrote:
>
> From: Christoph Lameter <cl@linux.com>
>
> KFENCE manages its own pools and redirects regular memory allocations
> to those pools in a sporadic way. The usual memory allocator features
> like NUMA, memory policies and pfmemalloc are not supported.
> This means that one gets surprising object placement with KFENCE that
> may impact performance on some NUMA systems.
>
> Update the description and make KFENCE depend on VM debugging
> having been enabled.

The commit message still incorrectly says "depend on VM debugging".

> Signed-off-by: Christoph Lameter <cl@linux.com>
> ---
> Reviewed-by: Yang Shi <shy828301@gmail.com>

If it's after '---', it will be ignored.

> ---
> Changes in v2:
> - Remove dependency on CONFIG_DEBUG_VM.
> - Spelling fixes.
> - Link to v1: https://lore.kernel.org/r/20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org
> ---
>  Documentation/dev-tools/kfence.rst | 4 +++-
>  lib/Kconfig.kfence                 | 8 +++++---
>  2 files changed, 8 insertions(+), 4 deletions(-)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> index 541899353865..03062d0941dc 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
>  error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
>  invalid-free errors.
>
> -KFENCE is designed to be enabled in production kernels, and has near zero
> +KFENCE is designed to be low overhead but does not implement the typical
> +memory allocation features for its samples like memory policies, NUMA and
> +management of emergency memory pools. It has near zero
>  performance overhead. Compared to KASAN, KFENCE trades performance for
>  precision. The main motivation behind KFENCE's design, is that with enough
>  total uptime KFENCE will detect bugs in code paths not typically exercised by
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 6fbbebec683a..1f9f79df2d0a 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -11,8 +11,8 @@ menuconfig KFENCE
>         help
>           KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
>           access, use-after-free, and invalid-free errors. KFENCE is designed
> -         to have negligible cost to permit enabling it in production
> -         environments.
> +         to have negligible cost. KFENCE does not support NUMA features
> +         and other memory allocator features for it sample allocations.

This still doesn't parse: "for its sample allocations" ?

>           See <file:Documentation/dev-tools/kfence.rst> for more details.
>
> @@ -21,7 +21,9 @@ menuconfig KFENCE
>           detect, albeit at very different performance profiles. If you can
>           afford to use KASAN, continue using KASAN, for example in test
>           environments. If your kernel targets production use, and cannot
> -         enable KASAN due to its cost, consider using KFENCE.
> +         enable KASAN due to its cost and you are not using NUMA and have
> +         no use of the memory reserve logic of the memory allocators,
> +         consider using KFENCE.

This doesn't read well. As I said in the other mail, this is repeating
what you say above, but is mostly irrelevant in this context. The main
point of this paragraph is that KFENCE is no substitute for KASAN, but
can be a reasonable alternative if KASAN can't be used at all (in the
beginning, we had some folks thinking KFENCE is like KASAN, but faster
- but that's very wrong).

If you don't like the last sentence because of the "production"
reference, I'd suggest to just remove the whole sentence starting with
"If your kernel targets production use, ...".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9L6gv9rK-WntLgAPde5Se8WjQqNLHZNGQFXZXRG2S7w%40mail.gmail.com.
