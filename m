Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBNPUX4QKGQE2CSVFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D540E23BA89
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:41 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id k11sf12080259wrv.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544901; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQWI7wIhbHss7gaUSw3BYkiAxRFu5d6rHoLhAzttURMTSMxQCja8Eu4diZo6QHYp7+
         8Md3zH4EClWNwmT41+swXsfkdF92gdhaXJ+wBsFhXlQ/svYmSzqINx/76q/3A6sVNFCq
         h3jg02T1c577n+hUS4l1SWam0Ekv5arWu72hD3MTP1ZoVDCDlANlPyfaHVaTA0/axwRR
         gqqB9ZgGnrjLu2KrZISfdT1tklCYs7mFwhnUV7TfAlJVwHqAzmD0+popLUL1HQaDx38D
         MONduTBgRc97dGmCfCvPSWMmCUyiGF6Q11/P+iIIdihIC1JU8hWtljV+ORYKN7YxA6jI
         dDJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=U3UKf2NloAsuBhnw+c7fywqfrlVDi2nt+2Cu5WBytNw=;
        b=bdm6KKaiRGiLMpFX72Ar/yurdBLL2YYwWfWAvWJhW32P64oiwuyBwFjJfHmpRymWGf
         ppjMK7VfRtBN0+UN15/GYaatiVlx8FPAipSOL+nrZsDi/Dnd5ywYbmLkhDkvigId6lx0
         VK1KjY19IKK8jPm0+AhVQQXSefBqqXtBs1oSsrZmsfS0ZNvx1lxuD63Idwap6a9s1VZF
         p8iDh3UOb02vcCHx3VxAQQbkcnQ06e3d10jRcMsOiaNJ/63DcMoiEOGakDMpCSLCzJW2
         vK6JL3HB6fQokoArugIaEyX6BSL9AuiJJY7UlRouESbCDAIk+wxmANk22dA632/d+eRE
         9ESw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=epaWaJlt;
       spf=pass (google.com: domain of 3hfcpxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hFcpXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U3UKf2NloAsuBhnw+c7fywqfrlVDi2nt+2Cu5WBytNw=;
        b=R4iX4NDLuB1h/q2MadPmA1QRg9yuea8LJ3SkOAzZqZ5VfXtbh9hikRPTpIxh0+qq7C
         81i1eif2+qZJ54gDujD3X9MZ7ePQE9X/a1mqiuKdg924Hix3Hxq5jB9aYHbRccmTwWlJ
         F/D+7coy62znqRjIh+DlIN08iXb8jyPghXnFA28CmPqoGZKpQM9iZSzCjgc71N3zxhuI
         4gQL8wjdsN0tYUfi3i+q3G2QPf1/nm0wwK9k0bIUMw3HpFgCWsrhnWS28r1W08wr1AFb
         hJ+QfQgH+dFoz6psJUPCy5AWW6PrzDVP+xBMEyDV0WjIze2tsxw6P9/P39ML5mrXiQQB
         JNYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U3UKf2NloAsuBhnw+c7fywqfrlVDi2nt+2Cu5WBytNw=;
        b=Zfo5O7dTsXI8L8nmDTqGoJLV6eFBCFNjGi/zwmdmPIcRjreUpiWgEQbMSalwqQdgPl
         MtSGijbespOnSrUrb/mMZaPqao188a565JJW7qmyoKcH/HvWj11ERAbZuM6bUzN1MxyC
         WgqIhGxjVeJxVGZE38UGLpNbfk6RT4DnMI1TtuBjE1U+3mu8YDJA+YXnDa2ntYzkuxpp
         qKqbsM6sFcvV/0Fx0FsQWZAP81jIvaSx0mnBIWexe9fi17zdQMrefirXSyb2NW5Zy43F
         JxOCJUa4VOzQ4VlDxtAUcJGX0Rkt59Uczskl+TNKpEHcl+BP8/jTVG4GZqF2IqpDEpXC
         7LlQ==
X-Gm-Message-State: AOAM532PnIDUPn9zorLGptOH9/vhxBgxPg68ow5hbSpkJJMsovOWRUfQ
	OCDjnNBn0EQIdAlFeLjQdRE=
X-Google-Smtp-Source: ABdhPJwpFnXfIAhiKpPtyrmsmaEQ+wAokz3moA7NQWAfzrtnlBM4kQvKtynzUQgX5gR+1x0nCxeWsA==
X-Received: by 2002:a1c:750f:: with SMTP id o15mr4112588wmc.182.1596544901612;
        Tue, 04 Aug 2020 05:41:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:804f:: with SMTP id b76ls1455165wmd.2.gmail; Tue, 04 Aug
 2020 05:41:41 -0700 (PDT)
X-Received: by 2002:a1c:4844:: with SMTP id v65mr4037347wma.149.1596544900990;
        Tue, 04 Aug 2020 05:41:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544900; cv=none;
        d=google.com; s=arc-20160816;
        b=JUPbytTDci+jbL3G8ytUWsqKvTq/vxQRSFREZmWvyYEkmDx7xEVhCt/i7DUYboIZ3v
         tfmX7njltkOEYjACRBDL96AaSoIoLnNAnpcEcufe6ZiZN5Hll6iS2FqrTZD6R0F13Stl
         sRWRe3IWroYfAFnn3QGN9j715CbZQVESTYhLI1bFqTwnQ82+jxlD9450R4u8LVIAYqjT
         DuNElmlIFsm/TY9y4gtllCzRCsl4v+S8XG4pm+bj4t1d/n1hQe2uvNsSZ25HZ6yCvKoy
         nFiwJiZPzvFkkJsVOYCTticJALU+SFqqR9cysrMCuoidmdt6lnX+bAco0nWXMnsKkdVS
         zZzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KTaExCeIbMBtrg6f3KaFtKJ9kXln1IxZOo4x1K8ywoo=;
        b=e7Rw76YkU0z57kNIK4Y33wNvg0hnuC57FsCQ7FEPB09Fp8Nb2XEfg3BLrFANwNM35T
         xvJKD8bYcwNStv1CkuCaq0WNo/OZWoTx0/Ll4CDeyG6TTfPiMbe2mR8oL14kFqOuvLSW
         5lKwTT/DENz4O2JxGNDZ4qW9jZsZtskFrfV4rcgoSlbswCwTjTeLaBm0alMqKOGx7CMJ
         huEadDJSsanVL++CAHQqUR2qBdpPD6t5tMaKETc2kak805as3JKVd4bgSHmS/VYTXmnx
         Gw4OoQEQh0Lwz87xNfrdCLHzX+IdvZMZPFJzA1lVDllaXyxkgmeLOk52PggYrqB7ZHZu
         AbWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=epaWaJlt;
       spf=pass (google.com: domain of 3hfcpxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hFcpXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j83si225024wmj.0.2020.08.04.05.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hfcpxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w1so10620363wro.4
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:40 -0700 (PDT)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr492659wmj.0.1596544900281;
 Tue, 04 Aug 2020 05:41:40 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:26 +0200
In-Reply-To: <cover.1596544734.git.andreyknvl@google.com>
Message-Id: <26fb6165a17abcf61222eda5184c030fb6b133d1.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 3/5] kasan, arm64: don't instrument functions that enable kasan
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
 header.i=@google.com header.s=20161025 header.b=epaWaJlt;       spf=pass
 (google.com: domain of 3hfcpxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hFcpXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
index 93b3844cf442..575da075a2b9 100644
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
index 0ead83e86b5a..7e5e25d9fe42 100644
--- a/init/main.c
+++ b/init/main.c
@@ -827,7 +827,7 @@ void __init __weak arch_call_rest_init(void)
 	rest_init();
 }
 
-asmlinkage __visible void __init start_kernel(void)
+asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
 {
 	char *command_line;
 	char *after_dashes;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/26fb6165a17abcf61222eda5184c030fb6b133d1.1596544734.git.andreyknvl%40google.com.
