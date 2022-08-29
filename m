Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7LWKMAMGQENYYCD2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 075CE5A4C3C
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:20 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x7-20020a056512130700b00492c545b3cfsf2019940lfu.11
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777299; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mi2OtXHq6DhMYdo6Xbhmc2a22/NSqM6vMUk4i3Il2Q4cOF4lBuFFPKDvUtk1DAaIe4
         Q6qbeuQtD7EJEEzSMW/V7Vwc6OwbxFEvjcgo/SacxeHyhXQeMZkEFOYW0I3BQTIDU9KH
         yPKnNTvdR0GqL5dGAnfJdoIDjsotfyEYB/lzDeYukhgkVgZXLnfag+nc0AHPIVPQyXBi
         HGRjh3HgUH/FqC/hmVkS/qW3WgvE8KD3TkwPvVSNrn1pGvBH4O6JhGWKnLgezZkR/4+4
         mHjP4oFX/pEJKf2Old1g452ep+QmQIqtquoa8Od6og8JXlp0ErLB0m5AlKBC2+9oHq46
         gogQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nStN2SZnAFQQIWMppObYrpXjTbPxM8KraLIa4Cz08YQ=;
        b=1AU0VTo3d2H1w0zOfZ4WitsFyux275RsW52JSfcPaOpVRKhlbuHUOZqy1zkaFOiiy7
         zu/kqu2bQPt5KA0C0vCyjqOkkPcoooiRqDPyvFoI4sXfPWhM+j9ch8xP9SxQBbz4+sEm
         7G0Ce0u9vFSocNGY5Ycf7Z5mTscIsYYl9ll9sHfsKzNtVLTVa8p4hHB/Zp8FKSIJAHea
         6kpJ40Em/QucKrAleUpc9dfTNqVAeSyUQPZ39nZlSq7DJnp0qnXJTJHui3UObWYq3+W0
         P9VV4xt5Opehc92MExSRn/PAeCLar4Lmwlfnny2uXRWxp0NBo/UH8BYykbI9WSVUJwD/
         kkXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Oei65SiB;
       spf=pass (google.com: domain of 3kbumywukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kbUMYwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=nStN2SZnAFQQIWMppObYrpXjTbPxM8KraLIa4Cz08YQ=;
        b=kknvSGXYf2g1MpNh8kxbVrt4yo2x8/XCwsL+HDSPQsbyCK6fpEhKfTMeUYmCi1iyji
         31CkH4RjA2300N+2jGEViDtLxjc0sjSYZSJhAuAJJUINm/2bBseuNVpNqj5QUR3SBM3n
         gRTdGooAbgsZR8Kvw2qoJ+YL1BJ35Rdoq/iKTMrLwR6AMqaRQPkwMuw6fgS0O7KoKOBD
         LN98/jDtdpXQtom4zm+hxHt31y62e6F7rhEt1r1uC5T8s3Q6CMNsShkNooaYRZpo+NHr
         ORc+dDu+kTNoR5XudXMkU4zBlbZVgXH+/i+CirGeKSRkKQryP5AHOGocTOLeFvrbn1qA
         l9Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=nStN2SZnAFQQIWMppObYrpXjTbPxM8KraLIa4Cz08YQ=;
        b=CVFrp1fG38ZFySjSTSuoATvsBnwELV4o1HBWE2LooQjEQ/bdXH++stbZH/YavNj+Vi
         S2zJf/p5+/DUPDeXmRl7+mGqCB8zGCbviuTbpyFmEGqjIMSrQKBMQXBHyckIzVl9W2XO
         lEW1ifheX+fLSAIUYxU9+Q92cWbil8vHuJIMj8uhw1UcVp7ap7HVCP3RPSu+I7q+Tmmb
         bRlxLW9yirPIaIgvYStfHzcJYmAbBxrsF11HlqD9jVU0ALEEn0ujOeanmvwKLllJQ0MQ
         ztrFVk4y8plcxPR4fcdRwD9XjyYXwWsNcHZv2hl2sqz1AD71SlnyUz0H7qCT+az+2luO
         i/7A==
X-Gm-Message-State: ACgBeo0fe8TS+QboB8RF/TvVjHQrNQ7UK2wEmQPOdV35u7wzDAXwdb5O
	NQ2tfY3uUYuaI1ggAEebksU=
X-Google-Smtp-Source: AA6agR54naafqG42VdY3T/HzhmK6D8NYTmopcCcZu2U7tnwEGWljLiehHplrXZLQB6+DQLS6Km+Dow==
X-Received: by 2002:a05:6512:4025:b0:492:c165:ab3b with SMTP id br37-20020a056512402500b00492c165ab3bmr6673777lfb.235.1661777299555;
        Mon, 29 Aug 2022 05:48:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a78c:0:b0:25f:dcd4:53b4 with SMTP id c12-20020a2ea78c000000b0025fdcd453b4ls1522395ljf.3.-pod-prod-gmail;
 Mon, 29 Aug 2022 05:48:18 -0700 (PDT)
X-Received: by 2002:a2e:864d:0:b0:266:20a7:eba with SMTP id i13-20020a2e864d000000b0026620a70ebamr674901ljj.304.1661777298142;
        Mon, 29 Aug 2022 05:48:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777298; cv=none;
        d=google.com; s=arc-20160816;
        b=gdFtYWnbL3jRkdtMh2wJoyOk5XiWP7+em7tXEW8jkDuj3+5PBkU5qNy6YsozFAt3Al
         z2/k1vwcdJ7bOF+WdRYttdQlEQpM2NWL4DQ98ytiws1530Mc8hsDw5QXJxCQ4Dt+aFuG
         j/doWIoOeFdfEuVmRbQnLuhdv2PbP1CkuLdrKa85dIX70BT7UwNrUswEOSfrCLSS39Uf
         RW58bdJqjtbYeZa65RHxIwIDRfpT31iKLOM8AjvJS91/25QvMpgs/Y8yhRh1INXV0R3s
         awmJCiz3wylnIthwu0YvC1v90QMsP4eLPfNcmoS0FpFhVwwwvrB+VtaXIFs121ArnEVP
         nLdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=T2C4sxYRs2lEzCnHUaLRTNKBKI12YQqfPe+dPUrodjM=;
        b=fRvGazUdhe9h4UeVZgrGh+JsICLAyplIBCzNdbU4m5ooSIHmHk6K4GOcvdtU1Wd600
         pxdL3N7bGtoZsGBHk4lzGGBWk2SecZmstqrbsNKjnlZoh/p1126AdBWuEIgh45IdGZ5w
         H+AEK2ZuAxe7SYAOKQyVnCK2joEMnXlVULPZM1HUJ5sAqCNZngJ3hZdmZer8lYd4bzoR
         5IPR3vSKWw9ObOgcVB9VRGWSe7SfqoETMZqfzlII8qH6pY0rcl4zgRraXbqVRDmKlp0m
         LJ2UAgprdPDWnFTfU/BXoOCbKyhi20Ft35nc2xcu9kCo4uhRmLbqoJ+yRtzUBuXzLqaq
         Ho/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Oei65SiB;
       spf=pass (google.com: domain of 3kbumywukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kbUMYwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id bd15-20020a05651c168f00b002663282f080si78869ljb.5.2022.08.29.05.48.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kbumywukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id ee47-20020a056402292f00b004486550972aso2032677edb.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:18 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:907:3f97:b0:741:84b4:8356 with SMTP id
 hr23-20020a1709073f9700b0074184b48356mr3916826ejc.148.1661777297695; Mon, 29
 Aug 2022 05:48:17 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:12 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-8-elver@google.com>
Subject: [PATCH v4 07/14] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Oei65SiB;       spf=pass
 (google.com: domain of 3kbumywukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kbUMYwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Due to being a __weak function, hw_breakpoint_weight() will cause the
compiler to always emit a call to it. This generates unnecessarily bad
code (register spills etc.) for no good reason; in fact it appears in
profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:

    ...
    0.70%  [kernel]       [k] hw_breakpoint_weight
    ...

While a small percentage, no architecture defines its own
hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
which makes the fact it is currently __weak a poor choice.

Change hw_breakpoint_weight()'s definition to follow a similar protocol
to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
hw_breakpoint_weight(), we'll use it instead.

The result is that it is inlined and no longer shows up in profiles.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
 include/linux/hw_breakpoint.h | 1 -
 kernel/events/hw_breakpoint.c | 4 +++-
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index a3fb846705eb..f319bd26b030 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -80,7 +80,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
 extern int reserve_bp_slot(struct perf_event *bp);
 extern void release_bp_slot(struct perf_event *bp);
-int hw_breakpoint_weight(struct perf_event *bp);
 int arch_reserve_bp_slot(struct perf_event *bp);
 void arch_release_bp_slot(struct perf_event *bp);
 void arch_unregister_hw_breakpoint(struct perf_event *bp);
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 9fb66d358d81..9c9bf17666a5 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -124,10 +124,12 @@ static __init int init_breakpoint_slots(void)
 }
 #endif
 
-__weak int hw_breakpoint_weight(struct perf_event *bp)
+#ifndef hw_breakpoint_weight
+static inline int hw_breakpoint_weight(struct perf_event *bp)
 {
 	return 1;
 }
+#endif
 
 static inline enum bp_type_idx find_slot_idx(u64 bp_type)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-8-elver%40google.com.
