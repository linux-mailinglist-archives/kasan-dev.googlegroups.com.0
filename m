Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG7OTWBAMGQEVAIPNAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CC7D3326FC
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:44 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id i1sf10168706qvu.12
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296283; cv=pass;
        d=google.com; s=arc-20160816;
        b=tyfqloZSOB4PwYXyvuHGgkcjHHxG04DrAgzwcGu5WkA22NCj7pA0Kx6YyXeEpNfbgg
         jU+rm/u05EEmO47gjYRAyrKEWQQCeVK1LdrXWOgns9y4Z3/F1VXFil6+ITd+lzCTlIVr
         M3bfR9NRiSE8PC5k/DlUfKQlTo9TsrYQoYCSqpOvHs3oHKm4+CTpNjcHGGMBa7sz29eD
         HhtGrOlWfyzTPgQ/W21mm1kMi1oSdh7LwIxkltnap0vN9+pAMrJ15giAvIzu3DIysR5k
         9BdqsqdXclERnXrT4T4c7VNg334e2tQuPUQjf2PTxMj/LdZkHTUUioHFpEo+IPK/3G98
         TE4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=vEslFIROqbS7SPA6SKv9IievoZ83TEQ106cyfeBycXQ=;
        b=wTKIK7sVeE6ik9FHcH6FIB6dt6K/4a6WosT4zK6dsVnp6K4RT/UH08hKZbF2SX8Yl0
         BKMepHEilDqmtbYY/WTTMD3H2G4s60KTKRuELNPnNkonnlD9yZyt7fa3WgRgdEn/Ncog
         lzxVb4A/zJP8Ek2PQ0cWEqKYq2f7AoGIDAPr0xSnt7f4Ki0RWcf/FFsH6GjZoE+5toZv
         qMfEm7vdus2v+dutFgeXwpBvUhUV5QNUDxV82cl6e5yeYxNx4r0nUQRJUPHqqF9+VK1t
         sh18/SSK5h8jiCQOy0FCP+v2Y16rfYA9Ge73TD2nZW1QvdIwlSIvokH1SLlTZOw9wV07
         rFIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gTizBqst;
       spf=pass (google.com: domain of 3gndhyaokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GndHYAoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vEslFIROqbS7SPA6SKv9IievoZ83TEQ106cyfeBycXQ=;
        b=X3zkKO3RCIT5n/nnEodo8dMjpgSW42yRM7hPw9Mmln6SSzeBGJneNZnCKUA6DWsUqA
         y+Jtm85PUv7/bRqSXr9+cSn/T7y3BPVeD7Tja8+NbBQ/Hrz+gt17ZQGBgz6lcVZsVd2F
         IRz5r0ouaaOksmIWMViF8cUmICNEGVSL+j6rAc9F1u2SeP73Alg85ukPjke4qx1mUQ6+
         puJjCDm7fpGpWk6sSGb3eh/KLwhYtKbomucf4gVSMUULSkCtVZ5/SbKdg7QeTKn9Rv9S
         MWXBUJIqlcCUH5kbGe/HpqMcnwLxFLEpU7T9LFg+1fkELeavxR+h2JvhcXtzYmnpJpkS
         jkbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vEslFIROqbS7SPA6SKv9IievoZ83TEQ106cyfeBycXQ=;
        b=mSlNPcNik+9jihWj45mIzMoq7eMdmm5Ogdx+eTcg6jfKFmIndKXxarznTd/sRCU93q
         pFcZN+QUYG02Oett8GVUUdytXr5SnfqrtUDnx1JmsFJ+gC6zKjYbnLO8o5dJaFinnLOA
         oDGeh3IkogfGtAYmVQxmEJJblk1r3uHdSeFH4JxeQibzDHePxW1TYwJaI+sWVqBo7ZEG
         zxEB3QZA4fiURGDNpedSpBKTnAh7LuQ0VfG1cl9qzS7LkFQeUZnR1DXGti9vGKK9ablO
         A/NwtXECKCE8ZzOnB6MVvbY+RTYvTylGFbWA8lRcn11/DPp8U980vOXiBfff/u+FxAyx
         DZuA==
X-Gm-Message-State: AOAM533/cWZ6exicYI+Nr4WCHHKxHhrxeCJ23b1cpSnFh8Jt8PMoTOdK
	Lwk5NsyvMxo7hD+kxelnbRg=
X-Google-Smtp-Source: ABdhPJwg4QK2t8P0Vuz9VG3bbAQubRAhUpf1fQ8+oRGrnZdKLvEJcMno/oHiSDTDcWa0SO1aMn+SWQ==
X-Received: by 2002:a05:620a:c8d:: with SMTP id q13mr24925598qki.238.1615296283345;
        Tue, 09 Mar 2021 05:24:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5189:: with SMTP id b9ls5253815qvp.7.gmail; Tue, 09 Mar
 2021 05:24:43 -0800 (PST)
X-Received: by 2002:a0c:a954:: with SMTP id z20mr3599902qva.29.1615296282955;
        Tue, 09 Mar 2021 05:24:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296282; cv=none;
        d=google.com; s=arc-20160816;
        b=B/sW0XcQwMnBES14FJtICASNRx2nOm5a8ZpN84a8N1jOTj93ikzhSBI9Uc0DA0r9bL
         D+qnPxcTAsLP8fm34mZyxlOMDSAxuSSK9mhVWReLgFudKbihmMkm8FHigDR1iiTeFzF0
         QDmPgkJZLxDV1WbSayjlkPqFknXr1T9kJhOg8lrSLxEbN/+UQT8Wt0BlpRudhoBDTeda
         H+lSA6MAqYqYiPymcp6mRusCfijSwGjSiNJjyuVk5UeSsmEhtqs37G074QZ87b7gFtmv
         SzytwyZvn7WQqypkqdM0Mr+voMxK9tgvyXTTUSxik7wAHM0Dx46VSaar6TqGsxaw5Y5a
         KBqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=mcTFS30JyBp5UEIivUihex+f+ayULWtQ0lH68CQCZDA=;
        b=SiSixMwhlsgBDGGNP7UbP7UWW0QYIICiGF2tUMJuwvlRnUGPS+CMMvzDUNVQo/HtwA
         z/GyfqxZMQPCpr5PLb76/eoreEHTZVFCaNCya5nh+h+o9esOYFgRA48tNnnVPP0i3XOd
         S9BZ22zRiG8fWjX/6sQDkk9GfRnBllyXoADfxEQEktS+4y1SCay7lirKDqS3jUKJgc4p
         XiEq2VtwbOUfmvzJDITwWY9vKBvyPOb140Fuh/t7kWZkEwp0frHuufUy8EgqSmN+nZxI
         gLVqXvUDi37wWy2vef3q7nQb93MLJL83og1YF/cIM/hu2LAFVuGnPxISwyu0jAIRtEqo
         HGvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gTizBqst;
       spf=pass (google.com: domain of 3gndhyaokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GndHYAoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id w19si1051250qto.4.2021.03.09.05.24.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gndhyaokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id x20so1048170qvd.21
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1909:: with SMTP id
 er9mr25819084qvb.5.1615296282586; Tue, 09 Mar 2021 05:24:42 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:34 +0100
Message-Id: <cover.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 0/5] kasan: integrate with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gTizBqst;       spf=pass
 (google.com: domain of 3gndhyaokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3GndHYAoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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

Changes v2->v3:
- Move init variable check out of initialization loop in
  mte_set_mem_tag_range().

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
 arch/arm64/include/asm/mte-kasan.h | 39 +++++++++++------
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
 14 files changed, 207 insertions(+), 147 deletions(-)

-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1615296150.git.andreyknvl%40google.com.
