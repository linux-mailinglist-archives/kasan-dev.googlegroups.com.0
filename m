Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNVVSD4QKGQEQASGEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 038AF2346B9
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:20:56 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id o26sf836633vkn.21
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:20:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201655; cv=pass;
        d=google.com; s=arc-20160816;
        b=KrZn8tpyMdI09kwEQYXZs2fOY8/8A1defwfbXAtJVu4f2cQJ4T5+3/DPkhu5+9oGK4
         nmH1WLfuZi6gPj+a4atS6Am3OJCJV76Mdlbfn6xAOq2XagNijGgK3AJKj0RdV9uZxBKS
         HcCJ9pb7ahrFdyAWqeLxOprNj9Z5aUMWhNFbgy+UtqgLrnhZ2Cn36qd47E3sLtv5p7tf
         9cdbeSP6vC71PkefhlgJAku3P3hTvQcZ4/f4EMOCnZj7dYy7lyNdEneUz2DZCvjffdtK
         wgYfVVV7iiRtBblJ/0yzkfs0tk7B8++QRPXsEjDK/aovLuLFUPduMHIE6Wbgf3KHBKkJ
         JZTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6cD8H1bsEg0TqVQ41mVuGYnP0BL+zj3G/91jS149x5E=;
        b=bUNy6wSUo9l8vQCGaf5NKH4UYkrgwWRYML3NM/jpwLoop/7Js9flIEldxQza3UVsMs
         354HQurao/EkccEXAeKJWWh8DnOKIyA+yLJCOM2Wz+5h8M5/TmNYkjILnj0Th1Ho7nsK
         keiYfCJN9m9Liq34FULYlB7GCOTlBssk4veNwXTog775KSoPZJtmmfhWFo8bAYEPRpUn
         4ZNh46z5ZGYItZwMpf2hxyFhYpufyHWGFPg0PCJcH2RI1o6xaRLFXPiPcl/pVxwL8aYl
         tRcDSnF8HHanlmCvuh9tg6NV+VMSZrH6dEmgLiMBorjktN3OiHvv/1ZCrUKl860zA7ak
         am5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o7VdKgxQ;
       spf=pass (google.com: domain of 3thokxwokcxszmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3thokXwoKCXsZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cD8H1bsEg0TqVQ41mVuGYnP0BL+zj3G/91jS149x5E=;
        b=q8PreTSjoZlNLvUGSsSS7HtN8fVSTBp2J3dvRTTVGh3uePF5Fp5f4Q+BB1S6oUJg1N
         S1uhRzndVImA9Xd33uNYEISYwfgTVSxW5Iyx66FXTi64SQJZdpSHG+LjOoFaEY9xUEHS
         K1rJNhftvnxcl3A+kZ/xtX34n5Fx91De1jP47qvVFNHJ1JHdOF53KknfhjQY15Dq026a
         CvOmb7O16U1mF2OazFXJ1vQfXROxEe7NbIBSRVGB0hGBRYPbghQWOFDItxIHnRMfu8n6
         nlanOJcukZdNrw5/niv0+/bGPYJCTObcV3Sy3OD31VKBMHJSiP79oD9Vb3vvEWONuFia
         Eq6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cD8H1bsEg0TqVQ41mVuGYnP0BL+zj3G/91jS149x5E=;
        b=D66Ryjtbo0dz4FtDTES0bjMv6zwygR7QEpHsc7uZAYZCIAe8BcC/aWPEIVbG38wa1Y
         2GfGVjKVv9kINaeJXHrtjOHvACPbHlHPOIxFY4k1Q/shpoqO32Ocbb18jXo7QQusshIK
         SRDckbAqcjpz7lgbjeHLcp3i2WMqdz8Po1sKLOXBwcTzP0t6z/vhHiOSD+HhvttNwXD/
         yh8Su8/xporxaHcRc02YOVNeq+rxOgVbDtpxyjkc3SY9OzMQBHUCEBV1tVYTiD1+67Tp
         2UkQOIiSe6wTy4m4B/dNq0k0MXeGpv25mplgJtPqDd/2n9Ff4gKLwoHeJPlBFRIfnpr6
         ZSnQ==
X-Gm-Message-State: AOAM530BDhB4YkqzMR6Iiqr1KvTc99IcumApCoEmfvSgGq0VfoAZU6Z7
	dJ7U3RQWtMFDG/IBriaOiyI=
X-Google-Smtp-Source: ABdhPJz4kZ6Tgzl88xu+X/l1M31Up9w9LT5dIlI1HDCJ1m9J1jwN3k3wFFV/rPVK2DCGEsTD6BgJZQ==
X-Received: by 2002:a67:fc04:: with SMTP id o4mr3077127vsq.29.1596201654922;
        Fri, 31 Jul 2020 06:20:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:6e0b:: with SMTP id j11ls456864vkc.1.gmail; Fri, 31 Jul
 2020 06:20:54 -0700 (PDT)
X-Received: by 2002:a05:6122:2c:: with SMTP id q12mr2762249vkd.39.1596201654570;
        Fri, 31 Jul 2020 06:20:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201654; cv=none;
        d=google.com; s=arc-20160816;
        b=ahSM5p0+Ab3W9JeEVPR5ui45/RPiU35XFqf2E7uw0ZvR3JZDBsA6eEIbuQ+bpf1KPg
         xZD9FzmsnpCXIY9/uC82utO5y4P6iT0X0pvmf8H226LvPN7U9s52xdkQYnsxYmXKXp5C
         qHmp6HTd9PYq+sDawtl+wjD/kkyfTVMZpZ+T42097M/TMiL9EDbUkDscNCXtTNZ8hLSX
         URnp9YC7GJF6LcsRqMs7HMWKXxLO7QgzczE5i5Qr4xm+jRVAgwIp9d+v4eJQ7QY5/fd0
         Vw5LYT0DGCHlTaq9sdzs9xcAS+xgl4fc2JJOWFDmdptgGIUcbAgvEEgpTFcDCoQJS5K0
         wK7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=evCrDeDl40PK8tQYA287KciiJFZ+88x9kt3Qo3tXcbw=;
        b=HWZ9ZGsXiHqgTYEiT1Qt97086SOqx2YTsKy95xAOaTkqG9B63cAvCd4uVbdPXZ1cA6
         jO0BDqaubjcaavxNbXayzzWvgYde5LWk9KUJZLO0SJ4XY/Kl66DwD5pXeptlGV5FcdZd
         /PxARBC9gwJmEoV0Crjph53QzVWPgXJpSCK74M1+q3nkOLWT1vKSMb6vPEUixENxVT0K
         6wHQG+JaXmO4U1M4K545pSCwWSCiBWkqyUFsZ8FaaJ7H2PmpzLd4tJOEAroqMEepVyV5
         sa4MglmVWiv4oY1pFgmFSqTgrOY7qHyexLPE9ltx+XX2/2Emfg/JvGSbLHIeneEUCr2A
         Dcdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o7VdKgxQ;
       spf=pass (google.com: domain of 3thokxwokcxszmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3thokXwoKCXsZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id t72si521947vkd.5.2020.07.31.06.20.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:20:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3thokxwokcxszmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x190so20785053qke.16
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:20:54 -0700 (PDT)
X-Received: by 2002:a0c:aac8:: with SMTP id g8mr4080160qvb.70.1596201654097;
 Fri, 31 Jul 2020 06:20:54 -0700 (PDT)
Date: Fri, 31 Jul 2020 15:20:39 +0200
In-Reply-To: <cover.1596199677.git.andreyknvl@google.com>
Message-Id: <55d432671a92e931ab8234b03dc36b14d4c21bfb.1596199677.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596199677.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 2/4] kasan, arm64: don't instrument functions that enable kasan
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o7VdKgxQ;       spf=pass
 (google.com: domain of 3thokxwokcxszmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3thokXwoKCXsZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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

This patch prepares Software Tag-Based KASAN for stack tagging support.

With stack tagging enabled, KASAN tags stack variable in each function
in its prologue. In start_kernel() stack variables get tagged before KASAN
is enabled via setup_arch()->kasan_init(). As the result the tags for
start_kernel()'s stack variables end up in the temporary shadow memory.
Later when KASAN gets enabled, switched to normal shadow, and starts
checking tags, this leads to false-positive reports, as proper tags are
missing in normal shadow.

Disable KASAN instrumentation for start_kernel(). Also disable it for
arm64's setup_arch() as a precaution (it doesn't have any stack variables
right now).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/setup.c | 2 +-
 init/main.c               | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index c793276ec7ad..87e81d29e6fb 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -276,7 +276,7 @@ arch_initcall(reserve_memblock_reserved_regions);
 
 u64 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = INVALID_HWID };
 
-void __init setup_arch(char **cmdline_p)
+void __init __no_sanitize_address setup_arch(char **cmdline_p)
 {
 	init_mm.start_code = (unsigned long) _text;
 	init_mm.end_code   = (unsigned long) _etext;
diff --git a/init/main.c b/init/main.c
index 2d74985e09b1..c73a16ff213e 100644
--- a/init/main.c
+++ b/init/main.c
@@ -829,7 +829,7 @@ void __init __weak arch_call_rest_init(void)
 	rest_init();
 }
 
-asmlinkage __visible void __init start_kernel(void)
+asmlinkage __visible __no_sanitize_address void __init start_kernel(void)
 {
 	char *command_line;
 	char *after_dashes;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55d432671a92e931ab8234b03dc36b14d4c21bfb.1596199677.git.andreyknvl%40google.com.
