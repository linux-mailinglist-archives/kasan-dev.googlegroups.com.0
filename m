Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45B5OKQMGQE4AU5R2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 08F7E55BFF8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:17 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id m15-20020a05620a290f00b006a74cf760b2sf12925542qkp.20
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410356; cv=pass;
        d=google.com; s=arc-20160816;
        b=cIL96jMzccVtouBrQiBbVZwU8tQpfwjWDGQea4z10LzmtoaSnHKlKotBU5vnBNVba0
         EupXnP/yGBx1DTFHgN1Edipsz2U59s1T7UIK/ioeiQSJCGtH2YwT0qLTgvGMxXygBJkf
         lvDmJzB+zq8VHzw3YwyW8Y09MwIhajfYWC8FCejAD7/30gXhmefoiyd95ld5shT1dmEF
         S3ebVSVTSjcrpxNfZ5r5iHuNAw0hhRbiJ6MbAV8nJkYAI+MyN7JrpsEyUEtMbX7Uxtxy
         HpoZjTHd+9SayGRFWpTYZhFC7en8Udn+429tlbzsIyFO4fjuTYpyWbIr6tjQyiPTGT/E
         ASbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=IOIw3mkXlauSvKG+aE39YhnqFq5Bk1m+ouF6KSCk6Nk=;
        b=HaiKW55i8WQPuGjMIDeKjOfMVltggvdLeq2NyDt4xw77X9S1Jgyv6LSR8syDDWsv4W
         ZXu5MUXIX8Vm35QFuy0flRe2pMHT7AQIEBUQIKJZW+5aoYlczIoObiCt0+n7rQQNoLDs
         HkamdJNYi98tqBMBtRoEnjSekjpkhibJih/zdQFNHBtARgSVSRLkJbZ96CTgxUYR8hiT
         DA6fw4SaXww8VnMYvuMUfAAgM75MptgVwO35pQR2y6z458xhw3U3rmE65tT3ZxXZqj1S
         033kc1YxxIsYiD9bodgqGbuLOxRNwEHRxLmh/MJN0RJP+vAjhbMjJlAjS340xUXVB6OQ
         pwrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QDaFAZbF;
       spf=pass (google.com: domain of 389c6ygukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=389C6YgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IOIw3mkXlauSvKG+aE39YhnqFq5Bk1m+ouF6KSCk6Nk=;
        b=oa1aGKU6eHSRDutQrQmbDYdJ7I4T0Q4yOgEj7NW5L9DDR7lHKViQzPyzTPlG85vBMh
         jW0VQ9CK5tZT3eWfo7/eC9OoM/BNLmTUzvdwsFaj/QC/Mk6KoLHoIyLUSWCkU6OVN7FU
         H5HTYCWJCZfUxNlwwpGXF3jwLghnZaYrKfpfDB3rS9uVA19PXd9z/lxHz6ZvjEDeCTdr
         2q9KZtgouMPABLTNrGWf2a9Bceuj+zQBRt2j7DVJbiJ7clDKg76BuuTLJLGCYLd34l3y
         V6zWiIlABp0+nGpt3lZNaaS/DCRuS1V3/JFaMLXIhzp6X8sLUMwyuD1i3mfi/ujCvlK9
         0fiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IOIw3mkXlauSvKG+aE39YhnqFq5Bk1m+ouF6KSCk6Nk=;
        b=QpdwNYfor1KB7bI7z5lnnEQByOYLfURjufNQRBJH+JyZZkTAcYXiiasguajJwkGF2C
         kt7432gaLQqkLGWfh/XmXGfVrQsx6RkklcBI7BT3X1JglsR5YmMJfvdl0g3bISZU/MsA
         PX06ekjMJIJnN3BWaxCvLC1ddyPoxw7cO4syz486te1LM+V6Ck2QUfyD+CXGLnbQn5yL
         PS5QsBk3lMxZfVYZ0U9p+l3TlhPn+e19sYQhgQLUIsxya2zCFmBFwvc+551I6xLdNxpT
         10ahZcY8KNsB99u2jWfmvsZh8rW1IlCBT0T65sUuBRhHUmXSwjAHLhbZN0dkAwbt84NA
         Xsgg==
X-Gm-Message-State: AJIora9PC7GT7LaMjoESR0rymRW5R2VLQHlAO5CdclFH4H83zJlPaovw
	EUy4hsx9ENo4pKhvnciXWA0=
X-Google-Smtp-Source: AGRyM1vVlG9NLUPg9ftFVPVqb6L15bi6QlOSY71ihnIQjyax0i21w1bqUGaYEry41RaxysjZbR5z0w==
X-Received: by 2002:a0c:b456:0:b0:470:7aff:7e8c with SMTP id e22-20020a0cb456000000b004707aff7e8cmr2736059qvf.53.1656410355944;
        Tue, 28 Jun 2022 02:59:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:3721:b0:6a7:591f:2ced with SMTP id
 de33-20020a05620a372100b006a7591f2cedls19380265qkb.4.gmail; Tue, 28 Jun 2022
 02:59:15 -0700 (PDT)
X-Received: by 2002:a05:620a:1275:b0:6af:e17:3dcf with SMTP id b21-20020a05620a127500b006af0e173dcfmr9148936qkl.215.1656410355431;
        Tue, 28 Jun 2022 02:59:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410355; cv=none;
        d=google.com; s=arc-20160816;
        b=vrD8jKDCeho7YsNGtCkW0HFOd574gQO45cmkde/J4M5eaNHYL6TZOtm58/X6K0i3TB
         ykKKN+CsnSDytTb0zf6FD6sESLv30COVRgGYH7r21SEoO5+sNULuqvtd6Z9u/1V8WbK/
         KVNobqK1c5tOCc9dannzzatHCa/dMkyU5RabxN7sjIkt+R5GV7zXKoeko8e3/aYylCbh
         NELJDbLT+StBfCetIb5LZDLxocjLD4AJZGzs1KV0ZqTCCKYSu/69Avg7gPpgegO8WK6d
         w0iU49RYWuGTekVvrWA9OFqmn6VKNwueyO/1kPvIPyizPcM5K5xEPkTAak6L5J8CLwQq
         Ha3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ar0tQaDtQRVxSK1L64O5LGBBBeYgKP9H/0S8vYb7eY0=;
        b=m87R3Hj/WYjkW8F9DumxCA6AlUGgP/lWHIWIW+IpakZuzlCFNeErrlVSSyw4s25jNN
         GsYN8BFWUfyyUsg7Ixrce64oSOOMXYkNUyyZTzTd3bpuJ3XwKmaHwsiJbIcGHLHSovvL
         re+plGDU/Fg4hcbNmU+yNjtA7arUrZBtDz4TyMW58EFOwJxSp5L9+m7pEv0IFpYuclD4
         SuzJNlDi0w5T7PNtpg/j8gjdlkrWBLiSnrqV5KvQqHQr/nOMt5oRiO1D2RfPR881SwRi
         NP0StwI19opAkG5MisOo0kuFjpRU+U/mNuHcjMJo28IRDgL+yXrza1lAau6C30OADmPd
         qj1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QDaFAZbF;
       spf=pass (google.com: domain of 389c6ygukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=389C6YgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y18-20020ac87c92000000b003051a3c189asi469615qtv.4.2022.06.28.02.59.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 389c6ygukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id j11-20020a05690212cb00b006454988d225so10641467ybu.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a81:6603:0:b0:317:8d2f:e255 with SMTP id
 a3-20020a816603000000b003178d2fe255mr20169767ywc.166.1656410355202; Tue, 28
 Jun 2022 02:59:15 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:26 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-7-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 06/13] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QDaFAZbF;       spf=pass
 (google.com: domain of 389c6ygukczwahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=389C6YgUKCZwAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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
---
 include/linux/hw_breakpoint.h | 1 -
 kernel/events/hw_breakpoint.c | 4 +++-
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index 78dd7035d1e5..9fa3547acd87 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
 extern int reserve_bp_slot(struct perf_event *bp);
 extern void release_bp_slot(struct perf_event *bp);
-int hw_breakpoint_weight(struct perf_event *bp);
 int arch_reserve_bp_slot(struct perf_event *bp);
 void arch_release_bp_slot(struct perf_event *bp);
 void arch_unregister_hw_breakpoint(struct perf_event *bp);
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index a089302ddf59..a124786e3ade 100644
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-7-elver%40google.com.
