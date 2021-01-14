Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLNZQKAAMGQEGCGK3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8A172F6B06
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:34:05 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id l10sf2638121wry.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:34:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610652845; cv=pass;
        d=google.com; s=arc-20160816;
        b=p8EfxFKVq5p/gpWYnCqZ5SU68qgKz8buFShpevuPEtSJHgt6bB8gmgbxjcPC39YWw3
         zmP1C/AVBAFBT5Ejj0i7VcIDJFuWOs1mukZ/GOFOxBIypgYUI1T2mlfZo8M04G7lFdck
         4GERr8maT2P8VnHsSq4JYP4tU3Oo7QDg3TX+IinpOWUe3mAIqMSt67M2bn8+csJLKqCj
         oWl2jtQ+Pd55J5aFDfd1O+HOEbAMlCJHW5bycF61C3QQ08yCINJoo4uihgW9pXhnFX01
         /DS1KhBO28AV3u+oGgsEXVmc/3LLrtYdZZ3/OuANp+ZvXN0t0rLkluv+czStGV64y8pL
         rxsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=i4GJ/KrMmdAR4swG1RoaddbPJosZrrn+hRO1bUTMAgo=;
        b=u36DwQXcxTDp1pQD+1BJYH9I13xGAiiUER9837dODDAs+gAFN4PgdOPZEBFea7fYfZ
         KPFr46j/as+r1Opcz02C+wvQbLigJNBaeN0V7VjQZ1SIswMKiFJpFR7xqZ++EJVBfsoE
         37aLLf8Pwb0KB8DzAuSUU2Uloga49o5vxLgHBfLx8FPA7GsGXZzXElYqwOG2bJiNrqyB
         mDybVQrAMuPMSth8fnYmeZqaSKpF7gcaAVppFopBo5Ey3nAk401pbDqaxQ2bX3drZiGx
         +A79XQIIoP+O3nuu1y0/CR3Q4fx2Mk7T+Y/ETkcc3MG3SFj41CZe84h5XLPMqsIoEewk
         WFQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MaPtjIwr;
       spf=pass (google.com: domain of 3rjwayaokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rJwAYAoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4GJ/KrMmdAR4swG1RoaddbPJosZrrn+hRO1bUTMAgo=;
        b=MMchxDELNVj7qD5VpEtccdU46+2y7G3A6pbXyGEU9nV2hV0hyA/GyC2Y1/4a0i461t
         3vxmTR5NQfPk6mi0kPEtoezhFmbchWTSUUSZsPHLWhBaBPLitOZuAoWGv9N8sUpU1AKF
         sWprxE6D6RmCXH3S8GJPOG7zkIFrYF6AutNN28HQvuGtkYjdS/Eh+kPzE8PzaJFRZ0ia
         YkdEech/TiR3fkvqVgJR6+qbNUDIy5DW2uFzgprKxg5o+b3ddOtRGxIzzCNnn56R/uNd
         jsvi+9GuQ86nl3S0rpojHzlm9kgvF5zJSh3sCvw12dH8GCVJmnzMp6vTW27gCrR7udCv
         a2zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i4GJ/KrMmdAR4swG1RoaddbPJosZrrn+hRO1bUTMAgo=;
        b=tVsql9PDJSAlqo0IN4zL7Nuk0UHV8AUWSRAfz9wMdQB+bRcZpuL/PIps26CFw5WNzo
         Wx8ZD7hv6kQLuV6Tli3RAG6IklomFXAkPBFB3/T2QLOZTT55CB4Gm2fc42STQuit32tv
         Pk7AUsJImW/MoLZYHSjJacD3X77JFoX92bMYzBYjYWZg6x35DsbkcIPpRhXVl982z5NH
         CmRjMDpHpyTTbCZBwn8wvNGIov0GKtJne+YQ+VVX36lMjMLkWQDQ13ZEKp7KUJwGg2RQ
         9GZDjrG5ohBvFnLYTGl8ADPJ3E8G/5S8mgHRQ6xw5KXJuiNNHfwu1wbwcOmTNqS9IQVm
         J9Ng==
X-Gm-Message-State: AOAM532lf7czOcfBiSyVHli852P7cXaIQEiCuYI0GULQaURxRRuAAB5O
	LC4wtJqg7bvbl21ta26Fvbc=
X-Google-Smtp-Source: ABdhPJxJKmnIBVBkIxx2XWliM8L6y0qFMxXZj2PFSPcFhJymaR1qd5kTM+KaH6co8Jos8XeWo9T52w==
X-Received: by 2002:a1c:4c11:: with SMTP id z17mr5141556wmf.13.1610652845666;
        Thu, 14 Jan 2021 11:34:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9916:: with SMTP id b22ls3188493wme.2.canary-gmail; Thu,
 14 Jan 2021 11:34:04 -0800 (PST)
X-Received: by 2002:a05:600c:d1:: with SMTP id u17mr2720351wmm.20.1610652844759;
        Thu, 14 Jan 2021 11:34:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610652844; cv=none;
        d=google.com; s=arc-20160816;
        b=a8Se9lYiMPEpgavISCfZB9jgg8Ta6+tbGHvm1ZtG8xzSrpcpFi3PBtHq6UTbOBmWxR
         K3bpbI+wOa8cbZH2il0/eNF3uwA2Va7ybIrPWfiNlpQnjt+HbHXmYVc0HGKRapQkpG55
         UFmuyxa65EMZYslqEJ/Py8qRslXooCRxCIdrXtxsRtedLVFrg2tkyRQwic7++ugCMYVq
         w6PofpXcdJvLNMMUMi1tt9LUVzzPmJTgLFpxdbYTeiXPoD89Mmd//If88kqiyIlJWq9E
         t4M80NZn9FGYb5E7bvfjMn8NvuI3/fiE3h4NXTvxgPT+KaeZRbEr9cBpMCxsh/SGwLKI
         4Jfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=To/bHcfhJEpjAdXg3S5DdT78e7w3setGkq3dXznXdGw=;
        b=MxhFf563kI3TgkMObYgBd/wvWw9AmYVHMlcI8xuNnGX5B1C3gjXTqbKsQF611h2ZAo
         er9MkSXPtoIErnO2dds6++7FStJxmSFnU8AKolUgcglRHB3G25xjymr5UKHnLFZDlL/J
         0GioYHZlvGigT0xcDU1O8AiGw9haeuKNvuxsJrYavxp5UAqLJYN8lXHjYgBSyYv/rYzP
         8Io6MYaN+/HzyS2EqsEU0gaBkwn9HlcHPUmQjyvmsY96TptMFngbB1P+IpmbCkEgU3u/
         DrHIeeBpIctMbej7glWTejJcuXc3ycuJd2hhr1LOsNjw7gSCrXf+l1zr1QJoYEegojY+
         zqAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MaPtjIwr;
       spf=pass (google.com: domain of 3rjwayaokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rJwAYAoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d17si459543wma.4.2021.01.14.11.34.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:34:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rjwayaokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id o17so3052123wra.8
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:34:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cd91:: with SMTP id
 y17mr5139113wmj.171.1610652844285; Thu, 14 Jan 2021 11:34:04 -0800 (PST)
Date: Thu, 14 Jan 2021 20:33:55 +0100
Message-Id: <cover.1610652791.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 0/2] kasan: fixes for 5.11-rc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MaPtjIwr;       spf=pass
 (google.com: domain of 3rjwayaokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rJwAYAoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

Changes v1->v2:
- Update changelog of patch #1.

Andrey Konovalov (2):
  kasan, mm: fix conflicts with init_on_alloc/free
  kasan, arm64: fix pointer tags in KASAN reports

 arch/arm64/mm/fault.c | 2 ++
 mm/slub.c             | 7 ++++---
 2 files changed, 6 insertions(+), 3 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610652791.git.andreyknvl%40google.com.
