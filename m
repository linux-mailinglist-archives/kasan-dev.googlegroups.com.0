Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6GV26MAMGQEL2TQWNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A4C95AD26F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:33 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id f18-20020a05600c4e9200b003a5f81299casf5303198wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380792; cv=pass;
        d=google.com; s=arc-20160816;
        b=o8TdEDg8yxHRNkza77/jIDJmT/fEp0hql6oAefLYjxkjmLkhydBzmGW0CL4/vlW3ez
         WLUY1rwgervVtzUBNbpcgGhHL7l4pHzLMW/NUaEqrX2UFJjzr0TTjgZcnrWQ8ev209wG
         cQUY7+z4TdjKZjebud/goSman8EilYa1TLVdTUsIG5h1Qog3hi7sFHvDSqaPh5T8Q2Z+
         NtcqwMR5bnq53NzQ8WFaEKUiAJbfE+9G1cd3jFrwNXgrq91BoWLfrZ3kC5PNvr+j/Fj7
         zc57Ncvruj8v6bQnI3IhYNiwOLTYyMzvr0QrcnVhmxNAbgZO2nXF8flLZJbuS1Uv9nB9
         rh0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wWFYmwXc88ibTvyxR/os62MzqEgtAHA1agkooZxdgY4=;
        b=AvhdnFnOUhk3zGrS23mI9DDSxjSvJwMaxZZT0yDICo+NeDhaNeH32eC+AB+bXs0kiS
         qAb/jpAbJ2uDDLsTkhFKDQ67ZeAfVST3kgK6R8BCgjGJq7gTvrlw96KaWwGgsYEMRcVk
         VKzvbR+y4pjmVHgCZej7PbRJRUcDz7XMbQFKo3KybPxryIYIV40Jfcqi9iInMKAc2q6Q
         XIvg0+vzx7PX4YfmEqdZKUJcQCNhYkl1p94YHWtv+/3zL9rwfflkOHkhv+jp/n73mU5i
         3eaj1eLoQgCO79QjzRB4C30wcqiIFzZPWv/M5PDpL2PvYPkA03pZ0o9KTtPjmAI2P6u+
         U3UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FaysfHPU;
       spf=pass (google.com: domain of 39uovywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39uoVYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=wWFYmwXc88ibTvyxR/os62MzqEgtAHA1agkooZxdgY4=;
        b=aQyt25LOGJkepWHAuG5xwNDw5LKFO1RDCUsmpzGByGD3uLEPiisjaeNkv04/gjhswS
         UbQ0GMfZYviQjOsXTFptPN73UybLaNeRGmfAKqfR9gHCeND2+JDWb4DWie7odlU4fakM
         MljM+dfzzmBWGWhCTYKUfQLWp+J2xf/02JoyuEmBQjAdtAJhk3Ni7dxMHisAri6lJmRT
         UHz5qtr2oe+JVmOipQ9vRN1/ycxSCq9igIi5pr5ZbIQ7RrFOuqGPhfeg7b0yPDkYaFAB
         2dtb3DT7Tng4Iqdf1Bt4ZOxXGWRXWpoXh6fI0rMSg4auPpsTTFPB/y/MYOdyjZ5p75ET
         XAfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=wWFYmwXc88ibTvyxR/os62MzqEgtAHA1agkooZxdgY4=;
        b=1TJEGV7O1pnKvsC1nfYfk3zBywHdkGEF3gtKgBxMfA3uspU1MQUMzHj7p8TaMgaf3R
         QcIY+JHZSG80Ae7fN4E3layJfPJvUA0kUQSyLiyThs88kjiaazCTvQLY0clc37AqOjus
         qvIGTaRCgAJq1CNAwgrwCJT9FhcWvGsFaGQOPAubZ6jaADAxE+QV+RXoi2bgZABQQJQq
         S/2f1BMPVEG7UP46Cs9vjPbg2ivi61XDD7ZFbsE3YuNkZ0Zf92JVCSYtUBX04+BxI5Aq
         ASSYbzu42R4lBpEAMcBIQ9VtGW3Yhjg5E8mFdBALR0IddncTZmEZFmgqqS1kBO4F0uvk
         i2Ow==
X-Gm-Message-State: ACgBeo0blIx7qSTbwWn52yDvyvfXf/E2E+fZlvroJujuRKZZidL3Ydtx
	7TjHNtlL4m/P/Rd31Bd7/Rw=
X-Google-Smtp-Source: AA6agR6r/sV0g1OUinzuFVfwey5nORbaQ14lQOtNtOCQhFi+amtSncQKD1WAsHf99goulEEQ7kVOug==
X-Received: by 2002:a5d:48c7:0:b0:228:62d5:2818 with SMTP id p7-20020a5d48c7000000b0022862d52818mr4902994wrs.13.1662380792766;
        Mon, 05 Sep 2022 05:26:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c343:0:b0:3a5:22da:8671 with SMTP id l3-20020a7bc343000000b003a522da8671ls3816713wmj.1.-pod-control-gmail;
 Mon, 05 Sep 2022 05:26:31 -0700 (PDT)
X-Received: by 2002:a1c:4c18:0:b0:3a5:3ddd:2f29 with SMTP id z24-20020a1c4c18000000b003a53ddd2f29mr10508456wmf.91.1662380791458;
        Mon, 05 Sep 2022 05:26:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380791; cv=none;
        d=google.com; s=arc-20160816;
        b=eATUaf8ky03rJnXaSrWCYrSLcq/qYrsIuW9tUxp2Ut2vpjH3mdbgB8xu/qpI69WdAK
         g9T3PMoqLCAVfH7jexMBV80oKK6tV9Gxp1kcFFEuTgDkti73E9yfNrn2onB78WM0wATy
         wYfCy9VB/te3PYHwtNcgwRlz2/a4ZGgX+6LTEQsD68DrV4Krcdt76iCqSN6gBLUDiXcC
         nl1Q5IbxQZa0FWgyAhdiL+HjX1t4wV1CpkKjFNNRmr5cOXO9adjww+H7e0mSjd2/kc+2
         hAzazmDKLVOTxkILdjjMlb5TONcqr1VSNYK7MjcU+sMJuv8AENi8JlR+mazWDIxh8Ry8
         jsuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VswCSWA+rV4PC5eDv8SsttMbBbTb1fmAEKvfw1RwEtM=;
        b=rLu8iZZKdhUf0HDxsHgkjSJsooBM6Kk2QA0yoDX9vhZb+SC5nOCPfBJrq1uzu1zbMS
         4qKwY3tY30yzk7MNLkfMkrVa502LVK/2AjyI3RoPU28A6bULXO4td6jJqoQHOR+T4TIL
         8tTtktmXp83UtejegTgqJnsdWXD2XFHfEQEsZ7sPOiErlnyRRr8KgReT0qcC28ewzhjg
         LSYhGXfp+ZVSzM+agrusQ4cokHdvGpc9G8TziSJKvY5zi4h4d3byv/drAnuo8l6xYmbu
         O3qd8we5cdfXizo3Fmq90FkoYCbaRy8JsbMZdkVDRarYnMMcvpSwjn/9wzTzqneVXM1g
         w4VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FaysfHPU;
       spf=pass (google.com: domain of 39uovywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39uoVYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si498830wmr.2.2022.09.05.05.26.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39uovywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365so7387354wms.9
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a5d:4448:0:b0:226:82ff:f3e6 with SMTP id
 x8-20020a5d4448000000b0022682fff3e6mr25180706wrr.115.1662380790918; Mon, 05
 Sep 2022 05:26:30 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:42 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-35-glider@google.com>
Subject: [PATCH v6 34/44] x86: kmsan: skip shadow checks in __switch_to()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FaysfHPU;       spf=pass
 (google.com: domain of 39uovywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39uoVYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When instrumenting functions, KMSAN obtains the per-task state (mostly
pointers to metadata for function arguments and return values) once per
function at its beginning, using the `current` pointer.

Every time the instrumented function calls another function, this state
(`struct kmsan_context_state`) is updated with shadow/origin data of the
passed and returned values.

When `current` changes in the low-level arch code, instrumented code can
not notice that, and will still refer to the old state, possibly corrupting
it or using stale data. This may result in false positive reports.

To deal with that, we need to apply __no_kmsan_checks to the functions
performing context switching - this will result in skipping all KMSAN
shadow checks and marking newly created values as initialized,
preventing all false positive reports in those functions. False negatives
are still possible, but we expect them to be rare and impersistent.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- This patch was previously called "kmsan: skip shadow checks in files
    doing context switches". Per Mark Rutland's suggestion, we now only
    skip checks in low-level arch-specific code, as context switches in
    common code should be invisible to KMSAN. We also apply the checks
    to precisely the functions performing the context switch instead of
    the whole file.

v5:
 -- Replace KMSAN_ENABLE_CHECKS_process_64.o with __no_kmsan_checks

Link: https://linux-review.googlesource.com/id/I45e3ed9c5f66ee79b0409d1673d66ae419029bcb
---
 arch/x86/kernel/process_64.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index 1962008fe7437..6b3418bff3261 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -553,6 +553,7 @@ void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp, bool x32)
  * Kprobes not supported here. Set the probe on schedule instead.
  * Function graph tracer not supported too.
  */
+__no_kmsan_checks
 __visible __notrace_funcgraph struct task_struct *
 __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
 {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-35-glider%40google.com.
