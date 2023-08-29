Return-Path: <kasan-dev+bncBAABBSONXCTQMGQE44DCCLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C26C78CA51
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:38 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2b9e014111fsf51728991fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329098; cv=pass;
        d=google.com; s=arc-20160816;
        b=EtsaEwnZhecd/8RMWC0XH/8NspGf8aEmEX4oGIg2D+7UHHVJlsVV8CgFse9lVLCjXN
         uttYAz9ZQyQUcltBoJyPJMo93qDj9TC3+eNN6pqYGeSMbn0eUtvN3jv2xC7DdJyTnpKp
         wNYtukGR/g+LAxOyh/Pmw06MlcS+RjRY85q92ZJ9Ng0KJDOJ7aGLsi9cDo+E7/4HoObj
         d6K038DcQpBYaHOMUHpoR8IGCYC2CreOScMjj6BjnyyLGWIYuYwv9ChOEylCrf4Ix9yb
         gwHe3U3tx0UN1RcNkDn/teAveMoNZfkiZqwkRbbxR32wV5RVapEvgyTf1HjW6qnmO+FA
         K4HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=DZ0zapXXF/DjggcMiwMXBEH7Kq2Z/ia9xVAoe+Hbjgc=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=DSP5isnCIR5lYzJ5sdyVMq9GGWkLzglWpHZw5nkPpI25dSyp+qGEwR8maM45DU3D85
         BmAWw0pZrrP94u1XUpifkH3AIwDg+C1+/644mE6HcW05ivTpa0gKBmVMH6kJaeH1Qnyg
         w1mCEiuPNQB5BKUgUoeTAZrARzkn+wzYt6SaTO7QToQ6HK+CgOgB2Toww5aBnYrKxGzi
         fHq52TRziMjBu6J9HnodkMlf1lLnORishJjoli/vf8Gl/u2ilKv2yR/5T8+/dIYpIaXS
         WCB6iQIBY98KP/0U3/PDxoEmHJNlBtU3TGkxpB1PFo6v1/qSfDilPAI+wvcxhainNtm1
         JgWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dnT146Mf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.251 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DZ0zapXXF/DjggcMiwMXBEH7Kq2Z/ia9xVAoe+Hbjgc=;
        b=tdxvb/dL4pnFJMtcNnCLpBRdLpqPojwyy+FX1OwXhqiCPGkufu/vTxau46qOMETmCB
         mo5l1qZsg2uP4K5x+oXVreM9uNoI4Tavezd8qAtC2ywQNRGolW+KhUA3/aGWWxtVqHt7
         AmofqETOWBnyWhsYSQUL9EPJNcMYdwmll1KaaYRxW1RU169npaR6reWfdlLXE1yesu+I
         c4CI6v4ZGehnK+OfGvfXYHDgoaE6O9tX/Un8jrQ95x/rxrarE8+8qRV3NjWh22zHZEGu
         Ho3Umm2De6FX56hJx8FgaMDHErT8jzfNSi4ag9D948Rg64FLO4EitvhtXKnrLFWt7vui
         ePDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DZ0zapXXF/DjggcMiwMXBEH7Kq2Z/ia9xVAoe+Hbjgc=;
        b=j/m9xxy8QVSbM2cmOpeH3j+WDauXZDt06ymCpSFJleAdAuIlQhVPA2g9vr87r17/Sa
         GCDBvJQa8di+2FEJP2dSbD2ytHbYrbJMZHQQMajbqDlWgdVNpLGsmCocRN8NERX264td
         L+LUEFpKKG97V12a2P6sqLSDUZSiRHPcNtIN0sqL+yVzqQSbJgqn72db4xCjdFIGEhYA
         fYjfR8cNfjxeLKzSv+bd03bLz+cMQF61FAFB9wCWEGVkmLHMh5GOK8+Ea/NMA/6Aa/dB
         4oXlJiBorNl+MGpUrnYXnelIFOvaaaY4NkGFX3w0Q9at3foa4eC24Jo3sTjap4ZGLlxM
         dFWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxBUWmoTvPV9Xev7OFv5KjTQIeOY6UYTTNznrqJAeSN5ibQU5ba
	bvlDSv1a2EOZtpNcqDLQDxo=
X-Google-Smtp-Source: AGHT+IG4JD7NPX5nkt5NqfSvs0umc9STFEm88QlCLPXxuTGGnbM5pXik4AHeYcWtM+LdC9wTVsQfZQ==
X-Received: by 2002:a2e:9843:0:b0:2bc:daa2:7838 with SMTP id e3-20020a2e9843000000b002bcdaa27838mr14213449ljj.19.1693329097352;
        Tue, 29 Aug 2023 10:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b522:0:b0:2b9:bbc2:1e15 with SMTP id z2-20020a2eb522000000b002b9bbc21e15ls203909ljm.2.-pod-prod-06-eu;
 Tue, 29 Aug 2023 10:11:36 -0700 (PDT)
X-Received: by 2002:a2e:8697:0:b0:2bc:f245:a38 with SMTP id l23-20020a2e8697000000b002bcf2450a38mr9491986lji.4.1693329095902;
        Tue, 29 Aug 2023 10:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329095; cv=none;
        d=google.com; s=arc-20160816;
        b=Jz+KJcOE2tk0Df3rmmaPS1p9jMi8rEN88NRROEumLSlnlHAxgr/8yITBsOncqPs4ne
         LJpKbmykDowfOy9+ecFh1VRdaFFCphSTQr8qFa9OA2BBj8EH3t/0vjXjuYvBMOIBBwzO
         zlS1ODUXpmoArFPHydAUPNzE6YcHXFQsl3n4pnM91qabtS+sHVNZecKqrVpuzL1jjObm
         DILPa3Zrli8f1fSk1ScSvHpltunRZUZ96n729mtV666TO+gNJLHoMT1XHykv6FckmcRX
         0FAhPFBlwX6BXChcgC7pn9fgyZ6aByTwZG+O4O44BsvCjY2Y0DjKNZOdg4eQNu9/xoMO
         QDGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4p8eo+KqdaDj4APbJngGg5i5hNM+Az1Zd3d9hROUHxc=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=HsBAK7swZxn/7bzrEiLs86NQHlpUAhUpA+xVbDM3qiy3JUrVg3jb2lnZOkweqCgQbu
         eJMVFrCX0XN9VFTK297qzgdNaGvrXjDE0d1lzZdqGQ9YvCaAuWVy55PJWHSSIM7XbXCt
         1KWmn/QNJ6SR1ulYK8DBHFjTQYvwLlOq89aMfX9lu8jMulxknk9D1aHTAT+MjbtGb/2A
         d3kO52uyurmAPsxh9BjfbjMaqaybON1m2DBPgItYN7HK1bdebgZIfia9Qe0IbRdjRBtB
         +O+7e/kf85io/Mym7C9BmLMFty5YhjNaPhCHPasd9W4QGv88FdmTrk7N6kXaerwVNPPm
         TZSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dnT146Mf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.251 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-251.mta1.migadu.com (out-251.mta1.migadu.com. [95.215.58.251])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e5418000000b002b9e701adbfsi1120063ljb.1.2023.08.29.10.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.251 as permitted sender) client-ip=95.215.58.251;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 00/15] stackdepot: allow evicting stack traces
Date: Tue, 29 Aug 2023 19:11:10 +0200
Message-Id: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dnT146Mf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.251 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Currently, the stack depot grows indefinitely until it reaches its
capacity. Once that happens, the stack depot stops saving new stack
traces.

This creates a problem for using the stack depot for in-field testing
and in production.

For such uses, an ideal stack trace storage should:

1. Allow saving fresh stack traces on systems with a large uptime while
   limiting the amount of memory used to store the traces;
2. Have a low performance impact.

Implementing #1 in the stack depot is impossible with the current
keep-forever approach. This series targets to address that. Issue #2 is
left to be addressed in a future series.

This series changes the stack depot implementation to allow evicting
unneeded stack traces from the stack depot. The users of the stack depot
can do that via a new stack_depot_evict API.

Internal changes to the stack depot code include:

1. Storing stack traces in 32-frame-sized slots (vs precisely-sized slots
   in the current implementation);
2. Keeping available slots in a freelist (vs keeping an offset to the next
   free slot);
3. Using a read/write lock for synchronization (vs a lock-free approach
   combined with a spinlock).

This series also integrates the eviction functionality in the tag-based
KASAN modes. (I will investigate integrating it into the Generic mode as
well in the following iterations of this series.)

Despite wasting some space on rounding up the size of each stack record
to 32 frames, with this change, the tag-based KASAN modes end up
consuming ~5% less memory in stack depot during boot (with the default
stack ring size of 32k entries). The reason for this is the eviction of
irrelevant stack traces from the stack depot, which frees up space for
other stack traces.

For other tools that heavily rely on the stack depot, like Generic KASAN
and KMSAN, this change leads to the stack depot capacity being reached
sooner than before. However, as these tools are mainly used in fuzzing
scenarios where the kernel is frequently rebooted, this outcome should
be acceptable.

There is no measurable boot time performace impact of these changes for
KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
depot without performance optimizations is not suitable for intended use
of those anyway), but I expect a similar result. Obtaining and copying
stack trace frames when saving them into stack depot is what takes the
most time.

This series does not yet provide a way to configure the maximum size of
the stack depot externally (e.g. via a command-line parameter). This will
either be added in the following iterations of this series (if the used
approach gets approval) or will be added together with the performance
improvement changes.

Andrey Konovalov (15):
  stackdepot: check disabled flag when fetching
  stackdepot: simplify __stack_depot_save
  stackdepot: drop valid bit from handles
  stackdepot: add depot_fetch_stack helper
  stackdepot: use fixed-sized slots for stack records
  stackdepot: fix and clean-up atomic annotations
  stackdepot: rework helpers for depot_alloc_stack
  stackdepot: rename next_pool_required to new_pool_required
  stackdepot: store next pool pointer in new_pool
  stackdepot: store free stack records in a freelist
  stackdepot: use read/write lock
  stackdepot: add refcount for records
  stackdepot: add backwards links to hash table buckets
  stackdepot: allow users to evict stack traces
  kasan: use stack_depot_evict for tag-based modes

 include/linux/stackdepot.h |  11 ++
 lib/stackdepot.c           | 361 ++++++++++++++++++++++++-------------
 mm/kasan/tags.c            |   7 +-
 3 files changed, 249 insertions(+), 130 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1693328501.git.andreyknvl%40google.com.
