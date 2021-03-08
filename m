Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2URTGBAMGQENZNPSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C290233129F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 16:55:23 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id e9sf5030140oiw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 07:55:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615218922; cv=pass;
        d=google.com; s=arc-20160816;
        b=PNr3clooShE++oeff2L5bfb/+K17P2PAEjNjjHCkSGhGi0eVtho4FzsgsJrqUM7R7l
         aXeiAqE4B9fcddJ3OHNsBzEIicdRiHNwyJSshIzTQwjfw4Br5cMbs7G5hLHEHZpTLQyK
         AeFPXGXDbjTFiOOTm+yRjZcT/OSG6uqNUWEUQEJqGTaJPoui/s76tr1TNDNx3I13moam
         ALhlud+DDFXm70uA/9nPDkV6w02dPqD9VO0AV12q/SJeEVLPlKXhzuMBOQYEtYtoKTqj
         j7+SHXgpFF8CNf7mkSuQsaYFCjt6FG1t56ipPSkEnLz0ia1/ZtMzdYyC4MTt6Om/x6yn
         KpvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=EAKPWmd0s5oAgd+w5G6KIlqK/F3b4wDo0cmDAYLc660=;
        b=n95lWdjrLvg0dBxd9MlYnct/f6nKr+NISamuC8g4MUOkWo8igHdsITPZ5DuuPXL8bY
         hQ3sCBkcWcspAareWO2C9QNLpyxpPjEFsfBGjSpcOSh0GPF/X0cNz64auoNcDyGPglhv
         V/1zfgoMHhlmE/2yzNoZWY2CBWP8wWuPciulHCeWbYV3JLVl1DcCobDVUDGLgwZAa6rQ
         FACcYbOLSRRk6q6Dr3eITNT7EX8p7jDfJdQb/hR2QIJiIDn0ZqHmSJfGsCNjCTV/oBuY
         yTMmwXP4XU7eqrGnHXTzHsSrk4FZfBPUBGmll7BfMIaqrmo22yH/3/mNxc+W52rzLOOE
         5+RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJjqv60K;
       spf=pass (google.com: domain of 36uhgyaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=36UhGYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EAKPWmd0s5oAgd+w5G6KIlqK/F3b4wDo0cmDAYLc660=;
        b=XhRxt0Fsr48NiD/Exa9ltjAVX+c/ydXFg3NTY62g3fRw7HynZ5mfJPGm573DdegSNK
         bEng5mO/5uIKStzENopkARMPK62WyUE7DtIdvhm7vE4D/xLZZGwDAyNMYyZRJGnE2+H3
         nb9RuyrItIuXxGQUw9tcyyKf2MThePFPHwMMQzXeupcb1Q2Qm7IMf70nQDxievQ6kAPy
         s0cOQX8BP86aoOWlrUH99s0PWMl1my+aAVCvTw3ll92MSbp3vtr9FgD8qltP1/gal64s
         zrysPlcA/hSxJZJ7f4M26BKYmdBMId65ep+whHvNFwVmleoOI1S9x3O/6EjP0wYueILn
         Oywg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EAKPWmd0s5oAgd+w5G6KIlqK/F3b4wDo0cmDAYLc660=;
        b=IHVjxAtYlU3cGXChRUXvamWNa2FWvWSS3R1h9Un+FrBTuqzoK+HLCt0+TrD9V2X6gc
         Wk/BOfXx9sbh3xj762LR6NlBxhviBP67jOyTOzIK8gKllPiA3rpju1wx7jr8hDY6Adl1
         MX6ku0Y5Ot08wAfq5r29KevDvTwo5K45NZ9IlUZtBU1oR4JCZkP4Jh+tB5e5zuZZ20hG
         OXafRnw730lZD+hsALosH6JKTtKWkepxO1MXXUzTPQmO1kU6Sv/ZQYcmFBaPVfjxa+n1
         ax15H2m4VnOIfvtd/uuegMB2+96S9yYUZEY5DLZNRnaJAqFZnRaIQk35hyP+lpiFb5Ts
         N9Xw==
X-Gm-Message-State: AOAM530E0xbnjgoOVE07B+1+vZhiJBLCeMhbUPiK7lwnJmY60u8HXC7G
	fE6JlOOQ933D/4cieuHsp6g=
X-Google-Smtp-Source: ABdhPJwO8mJpccdZdsQb85er35+nkl9RL9Vaxx4ATQljtR6AIHB6MxKV8RzzxpyTa83hirVHTREJMQ==
X-Received: by 2002:a9d:226a:: with SMTP id o97mr20392814ota.362.1615218922449;
        Mon, 08 Mar 2021 07:55:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4390:: with SMTP id u16ls975222oiv.9.gmail; Mon, 08 Mar
 2021 07:55:22 -0800 (PST)
X-Received: by 2002:a05:6808:214:: with SMTP id l20mr17888074oie.178.1615218922118;
        Mon, 08 Mar 2021 07:55:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615218922; cv=none;
        d=google.com; s=arc-20160816;
        b=WcJksn0YuksUZPvrilvHeOuKOCQ04Q8q0aMQVDNo3W638yiaeB8uhAevaF5g5vecvo
         wDS0cOPHUvXuJe1AZiI5fC7ZIj7jh+MzDzFoa3+gh4qnXCl2cFcT3TbDFpcN9jo46EFi
         6cBP9YjF9zYkECbY1d4X136DSEcjmPFIy/qnVCU1w1ChxOHhunD3N+u8aAMl5TR9GfCW
         aVhhAduqqZv9dtq9d5rIrvfHNMoXdVF2O0s0Y3drmpQl0w1z1Wn/6Gz+++Y+2YpSetBg
         G7kL7oUQcqZ8TZPQ41/mWLeV02VTWJtmH6qFcrKz/QvBTqya6A2DHqKGDGxyGiUX8yRa
         SDzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=FoMoOBBpWzT75wmFJ4xJzRk+FU5MgOdLV7/pA36y50w=;
        b=ax4v9yQHcA4yC0490IS1y5yapoNzdvbRRGAFeXdNhowHJ/zIw4zaNvxK28duJh8Vvc
         4jTHARfrnkKISmVoSXUbv+yKgddfqQlu8Z7hgvtYIabHrYRJJlCrnd7L84if/L1I896h
         4Fp0BLmaFUitIeg3g6sdx+ST59H8Ud7ghcvPR6/M93jhl880CSmEYmw6ukVFlYp9i14L
         FSJrL/olry9gc8M+33fK7v9SrhE/+bEskqcnBG64uL/Ew20nfiNquVzQpdB8lCzr2kbf
         I8R32SmMGfBVzW+h2ldxviHhE6sK5d547rhe/vzlg6DptCVdjGRHUQn65y8c8zsnIp8i
         2KLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJjqv60K;
       spf=pass (google.com: domain of 36uhgyaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=36UhGYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id s7si650639ois.0.2021.03.08.07.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 07:55:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 36uhgyaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id a11so3292094qtd.4
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 07:55:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1870:: with SMTP id
 eh16mr8647655qvb.23.1615218921580; Mon, 08 Mar 2021 07:55:21 -0800 (PST)
Date: Mon,  8 Mar 2021 16:55:13 +0100
Message-Id: <cover.1615218180.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2 0/5] kasan: integrate with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gJjqv60K;       spf=pass
 (google.com: domain of 36uhgyaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=36UhGYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch series integrates HW_TAGS KASAN with init_on_alloc/free
by initializing memory via the same arm64 instruction that sets memory
tags.

This is expected to improve HW_TAGS KASAN performance when
init_on_alloc/free is enabled. The exact perfomance numbers are unknown
as MTE-enabled hardware doesn't exist yet.

Changes v1->v2:
- Add and use kasan_has_integrated_init() helper.
- Update comments to not explicitly mention relation between
  HW_TAGS KASAN and memory init.
- Fix non initting memory with kasan=off by checking kasan_enabled()
  instead of IS_ENABLED(CONFIG_KASAN_HW_TAGS).

Andrey Konovalov (5):
  arm64: kasan: allow to init memory when setting tags
  kasan: init memory in kasan_(un)poison for HW_TAGS
  kasan, mm: integrate page_alloc init with HW_TAGS
  kasan, mm: integrate slab init_on_alloc with HW_TAGS
  kasan, mm: integrate slab init_on_free with HW_TAGS

 arch/arm64/include/asm/memory.h    |  4 +-
 arch/arm64/include/asm/mte-kasan.h | 20 ++++++---
 include/linux/kasan.h              | 48 +++++++++++++-------
 lib/test_kasan.c                   |  4 +-
 mm/kasan/common.c                  | 45 +++++++++----------
 mm/kasan/generic.c                 | 12 ++---
 mm/kasan/kasan.h                   | 19 ++++----
 mm/kasan/shadow.c                  | 10 ++---
 mm/kasan/sw_tags.c                 |  2 +-
 mm/mempool.c                       |  4 +-
 mm/page_alloc.c                    | 37 +++++++++++-----
 mm/slab.c                          | 43 ++++++++++--------
 mm/slab.h                          | 17 ++++++--
 mm/slub.c                          | 70 +++++++++++++++---------------
 14 files changed, 196 insertions(+), 139 deletions(-)

-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1615218180.git.andreyknvl%40google.com.
