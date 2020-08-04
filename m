Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7VOUX4QKGQE233QAXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D95523BA84
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:35 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id k1sf15307046qtp.20
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544894; cv=pass;
        d=google.com; s=arc-20160816;
        b=EEpxkvhdFsPpo0BocsfS0IAixHbcj/Do5aJhieI9QVdOzT0DLfEVZeL6CkQlU3Qb3s
         /e+YXxzJoUjsbkmRm9tDIhJZxwfhULk6hNMh5gh4zQRxu/y7h2wLJ3fJN/93JPkz/Co8
         CQvleP+7+gPyVYXAQscSIGpOB/zbgMS5YYpl2h2+EIkX7dPM2Wl1+EQdU/vH3bqxgMsf
         5M88E5Sz4orUxZ8tgvTZRIiHQ6nLXTeRKp1Vk9RvaqQJ5piwCHvjN0jFBM6CKoAO/Lc2
         XKyt57AGcbQ4IgKHuuH3d3qD7y5rMA3t2+Nbx7Vrb1Ac7wHfgIJgc68mPZMslc+nchFL
         +/Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=xvGz03xwnejg6O0lKTmkKEU9mx1AjB9fF9wAU4Doq+4=;
        b=N1wUqMyMnw82aLEnLS8mpAbEs2thbkLG696gQv3gEDaf1Bp3KA2tBzGh1GVkY7LJhT
         LZrBm2G/sgCuA2iWW95TMZ++j0Hihf8XrakcmGI/bZXMpuhrrWxjNb9srRHYiur/7i1h
         lrM3PYq4nFcqDIu4V+FSupfj2koX2ZF82FfYO2ghnrsMHPfnF6988Msp5wphNvs4Bp9u
         D3ysWDm0VzArMk4sBlUecDxY4lxJgYO2u0EpY9QM/JkZ/PlzobhTetT1HW5GKmVfAzMk
         OdUcWdsiclHzYki0F9DibD+T0A2yhTeC73oOLbXgjdeMqNb7B2aypk4kS8R0kSHjbbjT
         2NrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qRIWjL/a";
       spf=pass (google.com: domain of 3fvcpxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3fVcpXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xvGz03xwnejg6O0lKTmkKEU9mx1AjB9fF9wAU4Doq+4=;
        b=P3wsZoZxYEWo2h0JSaxmIPSXO5qLwtJOOGbSUo0ix+75ollYGIJexuEUFzJiGANBXA
         R6la8NjCD+9u2NrNSCzIWLt0//xTgY0KigS+WpF3K8Z6DoFyxlxwkZ8JaHsmwxjTv+7f
         vNImswcZACYrP23CfmtT8U1jEj8BMVVuiqxutvQzvii5N0Sv7HFFOTyOQ7T1obphvvyW
         6FIcmmz6eA3stCLdn2X+1KZgyrmh4YrLnept8b5Rzvmx4+BNfIalF6E73ZVcRSIpwcJC
         9FXCyaKtoeFwEWUPRWdo9m+MQ7VN7Pt8xMLhvQ8wfH9DS7bZe1ddGyfQOgyyqaCqejmm
         lUew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xvGz03xwnejg6O0lKTmkKEU9mx1AjB9fF9wAU4Doq+4=;
        b=CdMhL+Djo/GkFh0kX5Yx1/N6Q3e/RGcD9fB1TZqICZLHXVwet/goTOG5un0JBWIXak
         t1DwA3HsXU5kAa8zdp/VRizKD5F3j96wEwbkIzb1etmD3qfln55BMJsNBoY1zltymP/8
         9RJTlLd6tocwwV4WKJ8jlzEfw87AWm8K6FIV3J0oncPudY6eVZfNGXW54iFNxRjBqvX5
         tmnk8V9hLZQbfbZVu9WzzIQtp1o2XFdjAEJXxHKZykYTtOCzeEOVM3Lu/6cKxBdsQ2jJ
         +Nmio0X9UNxJ4yyKN93IswNa7Yrh7ebNcECUoD68DUhDFG9w44i8uThh+syf6W9HmjHa
         Ws8w==
X-Gm-Message-State: AOAM533fKttwDzVO2QaDjbnl2L1es6TKQLjXulBD5QQjdiN3tfaPilaY
	k/2YCe+1up/utAWUOWGN/K0=
X-Google-Smtp-Source: ABdhPJzfoNYRaEREskXByEDqU7UPKX3scPCwWhtpKyL4juIWqtMkZ3QuV/ONfKwIWzZVWtlguUNw9Q==
X-Received: by 2002:a05:620a:13c9:: with SMTP id g9mr13680315qkl.436.1596544894278;
        Tue, 04 Aug 2020 05:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:346:: with SMTP id t6ls493895qkm.1.gmail; Tue, 04
 Aug 2020 05:41:34 -0700 (PDT)
X-Received: by 2002:a05:620a:16c4:: with SMTP id a4mr21541160qkn.333.1596544893957;
        Tue, 04 Aug 2020 05:41:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544893; cv=none;
        d=google.com; s=arc-20160816;
        b=fFoB67EAdgKDhswE5g7RVu/5wK4MkNJC3zIuhQ5ys8EyrGNUauEhqZ8mB9uoQp+WeF
         YiPQOVn+oYldhfh5hNyRHsb8yCnzvU2Bw0uJ4zAhdMOCDxPa+PAns6sHNTEn69/sa9hI
         B0+3OskPiCNW0i2lH1j8gTueaZllT9VnwHoTcCgJ1SSqyAhJjJHkWapkNuYrKil+8PLd
         K7kyAEGuypPr3AsAWHBYEVkCOe9vegmvmkX/Mll7pW1Zd5ZvTHQNqgXTr0tMHCDPink2
         Eib5ApSmF/Fo2dfyi4ycKVu9yQZ9YsgvXi3tPJWYr19hkGcNyCNqvElJ03Y4c4+gZ/5q
         Q+aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EW4ws3cnCq+yc75UdLo6m+LVSSHzgz4WkI84lcOYn3g=;
        b=E6lA7cb9/DZJWUTgtmep0ITgbSKCozTNJeU0q6cRAqLA/aXDKS1gykuzRefZyHtbKz
         WWFONdUwz0mKV4uRaLvlmjLXcsVf1CFn5UbhUXmk+PIuK4UErBX2w1e0yB4QSLb3B02S
         TAC5taH0DhIfymCqF2tCoD3R6zd7zEZa/L4T2KFbE/tysRsmnCAvQw6iwrttovNYO468
         D4F1c373enKc8MdIeJM/V/z6nuHcU/eUsEmd2NJos5glI5vWgmuuUvVXnJnDXIy37ing
         engdRQGnCKct1WsqxT3GINSUVSF9I+Msc65//V2sTYuxSHBVUXRLOwfHW5K+pKdKbRHN
         uCfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qRIWjL/a";
       spf=pass (google.com: domain of 3fvcpxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3fVcpXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id f38si1000447qte.4.2020.08.04.05.41.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fvcpxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id u189so51824808ybg.17
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:33 -0700 (PDT)
X-Received: by 2002:a25:cc07:: with SMTP id l7mr33304214ybf.440.1596544893505;
 Tue, 04 Aug 2020 05:41:33 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:23 +0200
Message-Id: <cover.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 0/5] kasan: support stack instrumentation for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="qRIWjL/a";       spf=pass
 (google.com: domain of 3fvcpxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3fVcpXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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

This goes on top of Walter's patch titled "kasan: fix KASAN unit tests
for tag-based KASAN" (already in mm tree).

Bugzilla link: https://bugzilla.kernel.org/show_bug.cgi?id=203497

Thanks to Walter Wu for debugging and testing.

Changes v1 -> v2:
- Add efi patch to undefined reference to `efi_enter_virtual_mode'.
- Reorder attributes for start_kernel().

Andrey Konovalov (5):
  kasan: don't tag stacks allocated with pagealloc
  efi: provide empty efi_enter_virtual_mode implementation
  kasan, arm64: don't instrument functions that enable kasan
  kasan: allow enabling stack tagging for tag-based mode
  kasan: adjust kasan_stack_oob for tag-based mode

 arch/arm64/kernel/setup.c | 2 +-
 include/linux/efi.h       | 4 ++++
 init/main.c               | 2 +-
 kernel/fork.c             | 3 ++-
 lib/test_kasan.c          | 2 +-
 scripts/Makefile.kasan    | 3 ++-
 6 files changed, 11 insertions(+), 5 deletions(-)

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1596544734.git.andreyknvl%40google.com.
