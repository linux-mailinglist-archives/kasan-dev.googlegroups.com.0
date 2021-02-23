Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEFF2SAQMGQEA5Y5Y4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C830322C6D
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:34:56 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id c9sf7391129wrq.18
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090896; cv=pass;
        d=google.com; s=arc-20160816;
        b=MHtCwv92gd7TCkGPmNuOylnkdDd6Lt7lbGn54KAfjjzRngdjzi6lqy9pDHXLFOTBUm
         yumIa2zmCt12falwYA0lPYGkhjGtyCjMCBfwNXUCmDBo7Z1qzMdIZR7A4z6XIVC8D4FY
         vEaH8VSOjfiEJWwm5r2iaCBLzo5LfbYBZIzA6TIOjCeWrNe3MuODEVgD/eA9cakguOR9
         VwjlS9JkJNcgPFoXZJ2/shgvlHq8xP4/Iyn7xxCSWEIuDMpUL7USDSkpsb5Ua2Ido/tG
         ntYXIMBm0k5fWv90jkuRP0UMgHyvIxCarrmtqWf0mRJ+QmZ3rwJALdFD19LynGpyOSPN
         nasQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Bw5hykut4xjSiFBiQ4AULNekhLPThat6IkBYSrl0QjI=;
        b=gZbktWyUg3OD+/2dvaW6njo26nqeufafZUC6fpGSPmn9Jsi3lj3vtImbSxKfw8xhkw
         GBjqvyHOM5o+nyf5qniwb04RK9IVszu7MkZuLj5TE9CII2TcJ8Z0DeIOYlS5flzNukuD
         s9zlVk7hfnpLTa1tBM6C7WDwai6suJTdr8k9texL0aex80Llob/klvmP7vAP2cGc+k5f
         BncL9SHTtk0EOuDCy1uMz9CNv3r6UtaEGI/Iib+Ju7KPdDNVwzreeZAb0tgdedkq6f9W
         sYwzL9QASfG/p72k9S0TC+E6MLblcNje+EkBWTW3BT6tV1mTjvvFcR21+6mGTF5QziM2
         9PWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fq2+eMK4;
       spf=pass (google.com: domain of 3jhi1yaukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhI1YAUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bw5hykut4xjSiFBiQ4AULNekhLPThat6IkBYSrl0QjI=;
        b=RI5/+lH8X85M+eP/OPdKhMqar7CTzVvvd96LAKt5myNNppzOrARIBSfapHiLMbLW16
         4j984PL+SnahBFDmcy3KzmbLiXg09sh7V154vgaskeZeNdj9uTW0YtKNPqTvT8T1fDUj
         KiwZfOu1vb8Vg5MWcU6IoGHQS6qXj3ytcJ5JmcpvBWJdSzZ4f4NiCCgbgkuYHywJgZsh
         KLAJc2YN1zLNWDlskMcjbyx+o4LtCMNFm5NWNXxan1+RaWkZqgIExhiTaAsDHm7Iq1nC
         6BFQHri50Tegff1csKUA2KQmtsTmtlbqD1uK8zEMYKnbtsAX9JV8bn+hEZvirFmn/PF4
         evtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bw5hykut4xjSiFBiQ4AULNekhLPThat6IkBYSrl0QjI=;
        b=OcEYeUsbHvW5Ho08707D8QGVJEIU2z2vexXja/SdY18FAkQ9yvLhWonZUVgPIUJKnx
         Dgi0PAmqGvyVY9o3gUvi+yWNpjobxKs057t9picbaDdImSoEdAIqLX9Kpu1XqTW1DTw8
         KleuO7ruzTr4HWVwV2gteTEjDZbmwE/T0Rwy4YFz9ZZoD30Rx0rCjSt+yzB8lyYIQAIx
         ifFYGvdodmx4HFG+pxpYDiblBQiYEXtABYg7Jf3zkSQuELZweQam84JEPE5cJH72Aj6Z
         NJct47bqoACI4fmNkymzhXOHww2hZbm0TaVB0tT5VcmjBZ0uX405Mr4Joj8xyuFvOV9u
         u+uQ==
X-Gm-Message-State: AOAM53108abtmIbJCVndvz+yORE65hJ0Oyzd+KMIiDe0hLxW8woX1ZT3
	iNDSD/GDucpVhdSUDT38Ji0=
X-Google-Smtp-Source: ABdhPJz4vPJZITRRvS4+zFctd3KHOxmLUzCnQKuVgILKujPC+mMq3Y8pixbyD8EWn2/KbS1zzg95Og==
X-Received: by 2002:a1c:e905:: with SMTP id q5mr25563176wmc.84.1614090896168;
        Tue, 23 Feb 2021 06:34:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f207:: with SMTP id p7ls5848384wro.0.gmail; Tue, 23 Feb
 2021 06:34:55 -0800 (PST)
X-Received: by 2002:a5d:6181:: with SMTP id j1mr26148909wru.11.1614090895321;
        Tue, 23 Feb 2021 06:34:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090895; cv=none;
        d=google.com; s=arc-20160816;
        b=pBRQ5O5ttGPUUDjBZaq4wjlW8Fr60V9zJnm/OuhCsYZN97XddZg7mmd421B4g5ugiw
         W0UP3HJNRVr5aQfWGKGmX9UsU7SYKoLyI45vKhAAZagS053cBptawlZbmC6ft4fu6Tq6
         /EWe3HmTdXtLkvx9K0WDGC5O3JS2TG8ryHPhTiUECFpGJBPK8e5dQjTxz4EZEb/sPCbL
         ZjSkeqAZryZR/5agw45ev5NAdePXuq4qbp9vmqyABPG/rgeWRjt7KIbqMGrVz6U4NovT
         JmF0ZRxdn6FLNpBgJNYngSCLzT2TSI7s5La2ljSpoHuDaSIaFA1uORQcilq4bL4rHbQn
         9qOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S0g1Gw0V8LQdKC7HpmWoNe9UXx0KjO/uwYjAYtfhLeU=;
        b=F6+toHhrTy/36FoaWD4b+nIoTffGs+0rawWkVt9k4vl39lAUUKyQF6ze1nsEgWRlEd
         yQpjfH8W/NQBJI2MDeCEaepw0tSINdw5XzSoTc525HtG+VjJQO6NQ8k247h3Tnm+rsEF
         NSxoO+x64dsIGyuB9jCKDFJWOSKCMNGayijidAsDYFY5VDIJm/mQ/6khSmHJ0eszNAJd
         63hYZ4MhhOupEFWl0HM0WP96ZPTig4qLhoV5OMteqtlDH8fGPz4+09ekNf7KXcALS2lz
         pEHl81SWr0J4OiWCu3y/RNTE8EKeNpeae3Hsm9BjNol2qyyNPsGoE7N5pfl2v5ixCej2
         uBGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fq2+eMK4;
       spf=pass (google.com: domain of 3jhi1yaukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhI1YAUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m19si114122wmg.0.2021.02.23.06.34.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:34:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jhi1yaukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l10so7414900wry.16
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:34:55 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:a1c:2e90:: with SMTP id u138mr587498wmu.0.1614090894574;
 Tue, 23 Feb 2021 06:34:54 -0800 (PST)
Date: Tue, 23 Feb 2021 15:34:26 +0100
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
Message-Id: <20210223143426.2412737-5-elver@google.com>
Mime-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH RFC 4/4] perf/core: Add breakpoint information to siginfo on SIGTRAP
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-m68k@lists.linux-m68k.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fq2+eMK4;       spf=pass
 (google.com: domain of 3jhi1yaukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jhI1YAUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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

Encode information from breakpoint attributes into siginfo_t, which
helps disambiguate which breakpoint fired.

Note, providing the event fd may be unreliable, since the event may have
been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
triggering and the signal being delivered to user space.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 8718763045fd..d7908322d796 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6296,6 +6296,17 @@ static void perf_sigtrap(struct perf_event *event)
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;
 	info.si_errno = event->attr.type;
+
+	switch (event->attr.type) {
+	case PERF_TYPE_BREAKPOINT:
+		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
+		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
+		break;
+	default:
+		/* No additional info set. */
+		break;
+	}
+
 	force_sig_info(&info);
 }
 
-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223143426.2412737-5-elver%40google.com.
