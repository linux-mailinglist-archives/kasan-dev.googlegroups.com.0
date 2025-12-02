Return-Path: <kasan-dev+bncBAABB5POXPEQMGQEDU2AONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3C9C9BC67
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 15:28:08 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-47777158a85sf48871935e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 06:28:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764685687; cv=pass;
        d=google.com; s=arc-20240605;
        b=CezrU/3b69f9of/ksnA6twNyOwI5e6Qgvxluyd4UNzf4pb6nAOzqfHCWHFMksX9ibx
         PH8s7Tv6hqScQzgLg2Mbt8CYEKFMmQObcaNPn44UUwabIVdmE5p/CjniJKxsXLs9NM4D
         Z6e+OxdZjaD0X/XE8LFlJ1ZMS5uafS1M4LJbuKhzfXQDZ11e/7lU0A1T4UzYraEri3de
         WVx/MODO/s8AmdHpeFmy9mfVr7kUCLtrjRMoWZDmzre2T+VHr8/aRhAkqe7Gt5mkKvC7
         MQvS1RKYdGkKyrm4rDognd+NY6EEaM59Gi9SOwMDEGoHqGdLHl8apqQqAZjyKvyQSpf/
         wRrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=QljvmnKp7m97J8M+ijzcxiSNPiRaIaJq5fbRIZvSbK4=;
        fh=3N/4cAQ6818owlOHbYxoh0kOLvGBBx4HYRkXqnxDvQg=;
        b=Sh0DQeI5RLUTCXAkD9ABTpgdJpjT1wa43q+NyiycCeT0PkRH/otA14ZqSxDzX+DB7T
         QKz6yhF60m8yEiyam2Nn1m98PV22R5PM2O72lxt/gc3SiY0JtsQjlT2vYcFTVEYvM/Ds
         lwpOSFV3Q2iE/+J843xrvQJMJjOW0+Ymryg0eicdWbrk7xWMh73M/4rS/nv5EuXuxfeU
         9KkWB0aXCS4rmyuGLKzkN9oTgz1htTrk7DPDjR43MKa7iP29M5KY3ntZ6OZT1Lf1TUyS
         DEDQ+6qPJbF8+Uik/SwjLehR83tjmxGsez5qeMVbfoKxe9yUAwzysXIY9XAhv7OEYtsN
         3F5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=hi1S9ZUC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764685687; x=1765290487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=QljvmnKp7m97J8M+ijzcxiSNPiRaIaJq5fbRIZvSbK4=;
        b=J0eZk4QZXvu9vvenq3NC6/GtGYjg+ro08Sz9J5yKFqXuUoZtSrj9RA7VMSx0HQ+Iuf
         Pcuclb+Qnqb8mR8Uy5QtAcyS4JjcexCpIwPGOZc0avPki2yddfMOa/SJfUmDXzFMKHHO
         e4PyzFldeOSxuggZnwroqH9CAQVjYMZaOtIfQWFOsBmJjSoKOQUKqTM8zTeEVFAGSfJ4
         X0mg92uDoYJCd4t3+wGltPX9CiBo4rKlhdCVjLnyBWFuQ/BJji6b+JCWevIheuamB26P
         rfGVg9kK4tZJ6iAzxGYZcRMQ9K7hYm9oWRV2sftluBWROg5poLl3YhZKHGPDwJra2eV9
         wIkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764685687; x=1765290487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=QljvmnKp7m97J8M+ijzcxiSNPiRaIaJq5fbRIZvSbK4=;
        b=p2Jne0dJkxn1JnHB9Pg7kpwScMyLU4vA87VYZwaUQYipfSxPAHu0VkK9cH4cIvVMGY
         Pi0rzRE94wp0pBaQyc7foDU8z2MJMwzv68tgI85Lx0CjFexPfeKEvLgKSgBYbPm/tkxN
         DL+zMBuQneiGUF4woPPbFKKdRGJjpoG3cvKbAE25qpoVum55pQ20riC7tNZ8lAQV8rlv
         HtjGjUXRIoErlZOX54bYpEcS6m4DN1vQfVFgqT3RWUKE3tyAnMXVWX2a6o7i3MvSJlkJ
         Lwe9PXhGMH5rw7IB23gAb2SlEUXfiHLbVFSM8P1+akqIAUSLdtNl1GNxM2FUvsH6RTd6
         LN1A==
X-Forwarded-Encrypted: i=2; AJvYcCU8qtwQcRmWEcptnoriHIp0w/2A/XeXOc+WNgzBWuxtvmGDBVLon4vVac7RczdY7JtafJO0WA==@lfdr.de
X-Gm-Message-State: AOJu0YxD0Az87m/EpBzMpAykjAOtawKmV7AU6tT8klG7NuEunJCnR/7L
	X9j1TZ0fb+JJbEw9jpJ9B0PTkEfSheEsdfAmupa0xzDqSynXM00ZGl1I
X-Google-Smtp-Source: AGHT+IGREydB4wMuUbW4b1ByiIoQAHBs8RLI+cZRLJE1sCK3xWavWsMnQQKl0+BGotPcfewhNQVOAQ==
X-Received: by 2002:a05:600c:3b01:b0:477:7c45:87b2 with SMTP id 5b1f17b1804b1-477c111607fmr474925525e9.16.1764685687148;
        Tue, 02 Dec 2025 06:28:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YzbXax95W7lm79JlyFDq+wHPgqVodocHag1iwjO7zUcw=="
Received: by 2002:a05:600c:3152:b0:477:980b:bae9 with SMTP id
 5b1f17b1804b1-4790fd18682ls34477145e9.0.-pod-prod-05-eu; Tue, 02 Dec 2025
 06:28:04 -0800 (PST)
X-Received: by 2002:a05:600c:4691:b0:477:58af:a91d with SMTP id 5b1f17b1804b1-477c10c8e61mr400430065e9.5.1764685684071;
        Tue, 02 Dec 2025 06:28:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764685684; cv=none;
        d=google.com; s=arc-20240605;
        b=U/UGVwxCyCtlmaZE7ACQLnjNety/H5xxX27K47gQZQmQB1TEhEkOxuI3PL53MMpqMb
         uzbqZsgVMJlsxHLBwp2t+4016Ocjc6QU6fDcAlatL0/OA5H8z+Z7mgGj+FydukprXv4V
         7PTUzwK33hMns9LPVoLX/EbVkd6c2HA2NMgFtFPy0PBFfPKSqUxHkMd6p+MKVOZu/jnt
         FPb/J0YA8nTf4OhjkD98xkTjzTMTiyW1INWxy7somqrdpFYiIopTyosgyg0XJ9o97rHG
         HTwoVhT6e4eRJVOiCwNSW/LnBaDpDSE/i2/CB/m+ANYWmfwGV+Z2fijdme9coAs2wBQR
         JDPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=gnRx6DH/kHtIbGyXyRe/fabVRjG6utJSkpf40juEPlY=;
        fh=pIsZ/4YRL1gNdj/gl0Hmp8gY8RINKv/592C5y0sGNR4=;
        b=WOM1U6bgRPc1iemZnT1bnjQ9xJAt8Yhptt0VN1n6aOIjMRyHn4NXVsoLZV+q8zGKbD
         JYtqDcozjg6sp8V+VHAAyMUVAFeVfhmdEVASPSjCP/PUmG2ili177KyCtwAocfl//AEX
         FfzK4ascyQVyoA/43PKAW15jzArOgm41EcP71VvRJAeX9zYl0sqKoQijy06SyHjbPQsZ
         SiVivzvz4vJ9Z9DlWi2iDE2oCcTHUH2cgkakQKgXfHNJve3R40XmHLGn4PvOSUkX5jbV
         p5ay4z2eY6VZR9yG9HgexWCP57LvFToJr8XDFQnmhq7GCvoMmd8vPsxrqHfj969A7tvB
         q91g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=hi1S9ZUC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106120.protonmail.ch (mail-106120.protonmail.ch. [79.135.106.120])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42e1ca335adsi283821f8f.6.2025.12.02.06.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 06:28:04 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) client-ip=79.135.106.120;
Date: Tue, 02 Dec 2025 14:27:56 +0000
To: urezki@gmail.com, akpm@linux-foundation.org, elver@google.com, vincenzo.frascino@arm.com, glider@google.com, dvyukov@google.com, ryabinin.a.a@gmail.com, andreyknvl@gmail.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, maciej.wieczor-retman@intel.com, m.wieczorretman@pm.me
Subject: [PATCH v2 0/2] kasan: vmalloc: Fix incorrect tag assignment with multiple vm_structs
Message-ID: <cover.1764685296.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: d9334a187d17bcde8e960ee9982dde07d7c67d37
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=hi1S9ZUC;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as
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

The series is based on 6.18.

[1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
[2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
[3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
[4] https://lore.kernel.org/all/cover.1761763681.git.m.wieczorretman@pm.me/

Changes v2:
- Redid the patches since last version wasn't an actual refactor as the
  patch promised.
- Also fixed multiple mistakes and retested everything.

Maciej Wieczor-Retman (2):
  kasan: Refactor pcpu kasan vmalloc unpoison
  kasan: Unpoison vms[area] addresses with a common tag

 include/linux/kasan.h | 16 +++++++++++++---
 mm/kasan/common.c     | 18 ++++++++++++++++++
 mm/kasan/hw_tags.c    | 21 ++++++++++++++++++---
 mm/kasan/shadow.c     | 25 ++++++++++++++++++++++---
 mm/vmalloc.c          |  4 +---
 5 files changed, 72 insertions(+), 12 deletions(-)

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1764685296.git.m.wieczorretman%40pm.me.
