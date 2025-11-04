Return-Path: <kasan-dev+bncBAABBMVEVDEAMGQE72KRMRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 001F0C319A8
	for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 15:48:19 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-470fd92ad57sf66483875e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 06:48:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762267699; cv=pass;
        d=google.com; s=arc-20240605;
        b=a6C+fjcojHI3By9YN3MlbWd9u3zzMwP/8fhpmPZxoz+ZMpldXrs9pkMkLRN/1iXOQa
         vqVuhAHwR3PKfcUcYf+fBumiPo0JS3vchznaGvKi01zJ+D6nGMBGJbdDWm0Xl39ra462
         M+kRBi6fvgooukbGJsSZbKRxiEI8UYdSeyVozRKzvHDtcyaL0zxhGLko2fFE4nZIhIVb
         ojTA559u+NvrF/HWUrmjIBWC+I/FyImok53nZ19FFGQiJepUIjVvgzte+kjEmv0cxTMh
         hQJwguBQDwd/+VQGMuhAk4GjMav67DRCRU0zRssPGDXsJnFKd0Ia2YojfFLnYYbGWHJD
         Va3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=RlEaFtuGPIpFBHCNv1LWO+s35eHlQvU1zpuTMGosrmw=;
        fh=1ZL0i4Pu87gwHvmZ0cxfZjOdpLrFHqbnBcNMu9/FpGs=;
        b=BwBFHSGrP28jL9bRNizgstGeQaOl3ypM4U17rgbQ8bzfkivXT7wF+fI9DIPGhUCHKq
         pPhYv3saeC1Gf+iPzIiueTgn0mFt33tu5onO/4UsOvfo+2vuS3+WTsriw/RiNlrWiu4M
         cdeUOxxGIdYkf+9nCIM6a2JkC10h8ZhVzcFNWRY8js2wmhROL586+VPId1g7OJqRlkPO
         2XzurwCFgsacZmvqXjuNg1FWvqG/PCtTl84kjJAVbbgc+ADjhNJKMuGoOONLiGTQubFT
         aqIAENsVCXd3xdV+MrEPFCr1UzuDYbKoviEuOmLzE0mI1T3bsSu4fvF3hypB9xqGfdqP
         1XJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DjjSxPdz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762267699; x=1762872499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=RlEaFtuGPIpFBHCNv1LWO+s35eHlQvU1zpuTMGosrmw=;
        b=DrqRgybRqBEveuDq4uw6pzn2f1MyrecfnNdXmQdNx2cwTAVmQTEMNLYTWLcrgKRyuB
         pkfVYzwKV266jXAuIpjv8gZBeMq1gL5qCHaSpScxXERjKS4EHUwEw3VoRHE5At0mfBvy
         CDzH29kQFZpkd2GuU3ABtiCefHgPEhgmnzzYr0R9eFigRyUT8GCq/DrMbT3DslgC8U0Q
         0NtJUxDmG+9jJ3om5OUkLfLh3LtZuXY5YWju3cIfXdp+f1OUnqsb2qA5xSbBHGKo6+/N
         Nc6bvW+vElf4TSYjebzI9B3SugNGmt5MyXnmK9evqvKbGjKzPjgbXuuY8gNoeDktuR3i
         Sp4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762267699; x=1762872499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=RlEaFtuGPIpFBHCNv1LWO+s35eHlQvU1zpuTMGosrmw=;
        b=Jka66EgwJ0Pi46n810CWtG3o9UTMfvmoPG8J2ug5/5fAwaAq0KUbQiK92c9QuGGuSU
         MXU26+zR1r+2Bd2reuTY6aqehcZslmHIwNYKY6bdQwU3/kprD86QX0KFKqNwUhWLdiLM
         Zku7u4S1ZsjTTn/x07t9VSyt7ZXz2kcDwqreZlga48vXtzQ76gz7xJxMJme0e4IY65Bn
         33AGlMyBj9axG+5n/xeYKLgNtNazOap6bZqcfFwzULFwomsy8KPOjPwRPwWStjM2nLC4
         wLdMxqc2SA29aaukevry32cjj8NuISh4nUoLwuOmLiCiA2qTDo5wxrudKwneOD3dZzgu
         IG6Q==
X-Forwarded-Encrypted: i=2; AJvYcCUxNCkGsiMSXf3PmNQ8Im1b011WzLVRwfOsy3wZF2AKOrcCQ1VZctnHZrB3LkHb+/9DpTWcIw==@lfdr.de
X-Gm-Message-State: AOJu0Yzz7CY+nPA0NWhzFwnMG+mPAH+4KxlLIiqgDP367W1nU7YUrQok
	REr2GYsUxT11um05Gr9TpZKKTutuR0uYdm4nJUqGqDdbUjM69K7ymrt+
X-Google-Smtp-Source: AGHT+IG7ij0VtYMkKku0ZVgj2xfNDa+lhyRDJ7xwa9Ejx9Ojua8NMmN8jlaZ5hMkypJqrEVE8IuAYg==
X-Received: by 2002:a05:600c:468f:b0:477:59f0:5b68 with SMTP id 5b1f17b1804b1-47759f05cebmr11698745e9.6.1762267698959;
        Tue, 04 Nov 2025 06:48:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bEBdUPBvNCAQJU2HOrbWtaC7x5nnFxcuVA1HCA99T2+w=="
Received: by 2002:a05:600c:1c9e:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-477279fa89bls820085e9.2.-pod-prod-05-eu; Tue, 04 Nov 2025
 06:48:16 -0800 (PST)
X-Received: by 2002:a05:600c:314d:b0:475:d7b7:580c with SMTP id 5b1f17b1804b1-477307e489bmr157874575e9.12.1762267696728;
        Tue, 04 Nov 2025 06:48:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762267696; cv=none;
        d=google.com; s=arc-20240605;
        b=YRvJdWk6t9r5u2BBwtzAQeVrgFUGWqiMnAFLsHEzu0OwW7LBLv3ao9eROgDBcpRfeg
         twlXQf40nZ29P5m+FkwyTWrEMP9Rf3BJONer0rs6MJA8TKWxteuuYLVekHIHBCSM/NAr
         Zbq9dyyQeTU7Qtuk2mVGXoNFeiB9OEVrPdEBWg1041MJH0ze9x2JkAeCA6giGbcWHnFs
         EjcA76PsI8/LcOXsu9pO6DUABuHr/IwGldrcLxg55zJJ7sZ3uJIHNBxxBKHuR+GaR7xr
         T/bbKArbgAg9jkEqAxzrukaekW+y+e5m/gMrU6vrGluSFWHkOXHcXcGLcU926JFWAEgS
         VYCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=My0lcXrG8cShyz59I5w5UE8WjsZYKZx5nmyqC76eTx4=;
        fh=d4yOoBkjJVdCiBEQ1/v1l1UuitwPL+ulSXPEgL6p13M=;
        b=g4zlPLGg4tP9iVWfu9QLd0PMHX2ksN3ex2pZdx+8nY9IECSelGFEVXkCJWjt8xmE3y
         XhLvl2JN/hlLLTUErWmmN3sfGaxiJdb+exoeDdYRq5bBuzluJ8uL2pAULxfuzrFzKXzL
         cGh7tQ8WNU2Ti6x0Jrh+y3J1W4bH29OnzlPkSm0zDHzu0MYf7kUpBl+3lWhpDZOY0YRZ
         F6Io7qUiTKNCI6lCnsqpCgd62FZBUcWULLqE/nT+7mqDeORSxqYooADY7GVLOv+VrM3m
         uoebSNBSlXPrrFkxlt8uWqlFZFAKgD6ztc9V8miekw8gP8j55zdpP9/K3BPlhDBiwZgE
         tPgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DjjSxPdz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4775587d2casi287915e9.0.2025.11.04.06.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Nov 2025 06:48:16 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Tue, 04 Nov 2025 14:48:07 +0000
To: andreyknvl@gmail.com, akpm@linux-foundation.org, ryabinin.a.a@gmail.com, elver@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, urezki@gmail.com, glider@google.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v1 0/2] kasan: vmalloc: Fix incorrect tag assignment with multiple vm_structs
Message-ID: <cover.1762267022.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 6755a8c21333141e5fc9d41deffd2e258c429b93
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=DjjSxPdz;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
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

A KASAN tag mismatch, possibly resulting in a kernel panic, can be
observed on systems with a tag-based KASAN enabled and with multiple
NUMA nodes. Initially it was only noticed on x86 [1] but later a similar
issue was also reported on arm64 [2].

Specifically the problem is related to how vm_structs interact with
pcpu_chunks - both when they are allocated, assigned and when pcpu_chunk
addresses are derived.

When vm_structs are allocated they are tagged if vmalloc support is
enabled along the KASAN mode. Later when first pcpu chunk is allocated
it gets its 'base_addr' field set to the first allocated vm_struct.
With that it inherits that vm_struct's tag.

When pcpu_chunk addresses are later derived (by pcpu_chunk_addr(), for
example in pcpu_alloc_noprof()) the base_addr field is used and offsets
are added to it. If the initial conditions are satisfied then some of
the offsets will point into memory allocated with a different vm_struct.
So while the lower bits will get accurately derived the tag bits in the
top of the pointer won't match the shadow memory contents.

The solution (proposed at v2 of the x86 KASAN series [3]) is to tag the
vm_structs the same when allocating them for the per cpu allocator (in
pcpu_get_vm_areas()).

Originally these patches were part of the x86 KASAN series [4].

The series is based on 6.18-rc4.

[1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
[2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
[3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
[4] https://lore.kernel.org/all/cover.1761763681.git.m.wieczorretman@pm.me/

Maciej Wieczor-Retman (2):
  kasan: Unpoison pcpu chunks with base address tag
  kasan: Unpoison vms[area] addresses with a common tag

 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/common.c     | 19 +++++++++++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 30 insertions(+), 3 deletions(-)

-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1762267022.git.m.wieczorretman%40pm.me.
