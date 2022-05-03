Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGFYYOJQMGQEN6ZFCFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 23732517F0F
	for <lists+kasan-dev@lfdr.de>; Tue,  3 May 2022 09:39:05 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 26-20020a05600c021a00b003940660c053sf5349897wmi.2
        for <lists+kasan-dev@lfdr.de>; Tue, 03 May 2022 00:39:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651563544; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yn5yJZemDSf92ioUZ4aPUw4rEqT/UbHz5Q+ktlBXLI5NizhicKyf2FECtdMuVAbcri
         4CqPDSREvPSXC/DgKVaX1Rxgb/Mp133erw71NQe+wmqxW0ZWeyfvZr/6itEYV9BTqNjO
         E5BXtJMzDaVzc5J1Ll/9xCxSsV1WsJrfg9Lx7BCzMb/fUa//U8RPfvjaJuRWEcGd9Dqk
         Qye19H3pAz6OKIDpg5uZTiVtq6vXCHKRaSyzWILFnxj+/J1s1ciwvcpco+PQhJpw9tKA
         nk+EwtcSXSmxM3orC1fsgWFungbV8MeOqc0oJSlo+Q2kmE3MGOvXX2sXiFTmokjPoJ/C
         X/PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=yMi+AfOFC/Gyr8XKIFTc+TuYMBD99AoDN54eGB6lON8=;
        b=gE/mMtOUkbhpFA17nbwBhktys3/6V7XECtJ3ZYgiXQ/pATWY8R2zN/QRBxNoMNJONo
         GtBaqcydY22cLrKtDul/CaGKHvUBoMbTRwe5MO3xMCIWFNwN+GoPXdP06cKorfB+zOli
         RKH1vzbJ+6tsTvvUNAOv2mmaJcxM6SBWlGuFy7XG058wVJOUuJcmM1ghTJZ5muk/DH91
         hiXREEsQcfYoHZna/Qv8s1YoLXC09o3j0iEBZ6aZQwhSoPtHHyhFsfMemPDArMo4UEwD
         aHTg00dGWNx756D9umGe1qq0QkfZUMnfyr28o2v4Xrct48/mWEt9/lcoTV9CJR49hvH9
         YFXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WL2UUkfw;
       spf=pass (google.com: domain of 3ftxwygukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FtxwYgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yMi+AfOFC/Gyr8XKIFTc+TuYMBD99AoDN54eGB6lON8=;
        b=HfEPjemYZxwbUM9jb+Jn96jejTqoWQYb2/vOadWsxGQhMauQj7F+D/7IWqVxUIiXz2
         fdrNoUZI5DYZBgiNnYCfaCAGJqDw8qMv/NUpyjTEoRypqspi6GOaShntXDM+LycqSJTE
         DnMpnUsqS8wXYphs8qoJ4wuKmPNABhVKaUyQ5a/7JPi+zbKMIv13tEgj+QxSR86u0tX4
         fXTABBPBfXC3g4LTgkJldnjEWbbS0av77cyU/bcfoVEOrZK44xXY535sLKvLCfaM51mP
         bXOuA0PMuo++ejrzThi9+bJ1m7AurUpohBzHdWPxl9DDXY+AeonSbMiHXSgCqrlIiMuv
         YFRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yMi+AfOFC/Gyr8XKIFTc+TuYMBD99AoDN54eGB6lON8=;
        b=MZVwOwiUj6pyEHEveiKLksUlWj6PEuMZTXcA7UViT3iAqpxJ62FDEv8HtMkNG3wND4
         8u8yL+bDF0+fNdvFl7E06LLY0dpDnUWyi90wAKn9sOC1+CoieG51p2FeEngRWVYpJ785
         1Q1RDZbC3/8oaCx5igPMREf7AcQPS8zhMAxwrCif1zMl2W8v2x3dNCF7qP/sn0tp/udD
         /FnJBdjUiaOeSA+Em+7WtyvRaecXrJWYExW2+1x0lGIJzVE2rhLLJK+GQmDBR+I8ya5v
         Lq568/nFqOhk3TgTRvRZefWK9J6gEOtFaDsQNlHbtTuR2eSk1aDhCrHMsVTypijaepob
         qFIg==
X-Gm-Message-State: AOAM531vVWV51iBdVhm5u68wTJjY1zitWzQNBUmwtvCGtqSA2MaeUdpY
	PUuuSr2D88Fnoi1iNMf6i2k=
X-Google-Smtp-Source: ABdhPJw79fOQfp7u/xzvLddjyzY9/x3VmsEGYo7U0Dv3OcQ6l9x89xFT9J47grEttBK3NjvNr+AkxQ==
X-Received: by 2002:a7b:cb47:0:b0:393:dd9f:e64a with SMTP id v7-20020a7bcb47000000b00393dd9fe64amr2163191wmj.170.1651563544726;
        Tue, 03 May 2022 00:39:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els575132wrz.1.gmail; Tue, 03 May 2022
 00:39:03 -0700 (PDT)
X-Received: by 2002:a05:6000:186f:b0:20c:5f3d:44a4 with SMTP id d15-20020a056000186f00b0020c5f3d44a4mr7275275wri.152.1651563543523;
        Tue, 03 May 2022 00:39:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651563543; cv=none;
        d=google.com; s=arc-20160816;
        b=lrdmUTBMPehAWKIuLVZGgp1khCn3iR2Cr/vct7RqFLZjN0KIDxVMB/KfF+e3OurW/7
         9oVdUSwwXnafYUgWH33nj3apWcLY6xSsgmufaWcFKCWb5BCJXqTKDseMEdsINN4B5EjZ
         p6ja86L8850mxC+PmT7Qc3qF8m1uBxEQ+iY3TlmVQqXri+4KtGgte5Rp58kzXK4qHX0Q
         G4dXs59kct4FEEngQGpvy/ppF1tV7YCU7v/iRRmscLk8aigp2SZIlcYXw09QiQidV+j1
         cA4CVrmUwhfJwcAL/g2c1inrHi8h4v6Mr9jmxHiowOD0CTclkYYvr5nexswyCrDpeU3I
         q+hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=kkO/dWNNM89/72XXalUPVAWHtnC41R6OkxWseT3mGWc=;
        b=gjx0ZVA+Q6cjTde5F5C4nXJasSGx9spMpoa2xv3DrTfZHWtdo1IFuChzO4Nl9jkCPC
         Wu2xqt2t+y5Rh0dXsfpq/bWbvyiXiFxeVvZ6qI3Bh9Cdurpf2VoVGWuPRPza/+PKssYl
         EZ2CVlWxWuY0cBwlx500GCDk7MS6bg3hMn5avPXMegmwhVmGn6fSXoXfd3KoU8pkrwXX
         7Dd4NdnkIp94VSfmIhJNImAR02UfcOlJeIqSJ93lK6nIamLERIe5x28YQk+58p/Xmg5K
         7C1gdSNlzaCyARAqjMZuE5Cd6RVNtqZ+ocE4dwl58lVSvy39LLXjm5ToDUBymqLPfVhy
         R7pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WL2UUkfw;
       spf=pass (google.com: domain of 3ftxwygukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FtxwYgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bg13-20020a05600c3c8d00b00393e80e70c9si76856wmb.1.2022.05.03.00.39.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 May 2022 00:39:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ftxwygukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sc20-20020a1709078a1400b006f4a358c817so63515ejc.16
        for <kasan-dev@googlegroups.com>; Tue, 03 May 2022 00:39:03 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bdb8:d8d3:6904:292f])
 (user=elver job=sendgmr) by 2002:a17:906:c0e:b0:6f0:2b1e:9077 with SMTP id
 s14-20020a1709060c0e00b006f02b1e9077mr14448413ejf.411.1651563542771; Tue, 03
 May 2022 00:39:02 -0700 (PDT)
Date: Tue,  3 May 2022 09:38:44 +0200
Message-Id: <20220503073844.4148944-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.464.gb9c8b46e94-goog
Subject: [PATCH -printk] printk, tracing: fix console tracepoint
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, John Ogness <john.ogness@linutronix.de>, 
	Petr Mladek <pmladek@suse.com>
Cc: Sergey Senozhatsky <senozhatsky@chromium.org>, Steven Rostedt <rostedt@goodmis.org>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Thomas Gleixner <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WL2UUkfw;       spf=pass
 (google.com: domain of 3ftxwygukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FtxwYgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

The original intent of the 'console' tracepoint per 95100358491a
("printk/tracing: Add console output tracing") had been to "[...] record
any printk messages into the trace, regardless of the current console
loglevel. This can help correlate (existing) printk debugging with other
tracing."

Petr points out [1] that calling trace_console_rcuidle() in
call_console_driver() had been the wrong thing for a while, because
"printk() always used console_trylock() and the message was flushed to
the console only when the trylock succeeded. And it was always deferred
in NMI or when printed via printk_deferred()."

With 09c5ba0aa2fc ("printk: add kthread console printers"), things only
got worse, and calls to call_console_driver() no longer happen with
typical printk() calls but always appear deferred [2].

As such, the tracepoint can no longer serve its purpose to clearly
correlate printk() calls and other tracing, as well as breaks usecases
that expect every printk() call to result in a callback of the console
tracepoint. Notably, the KFENCE and KCSAN test suites, which want to
capture console output and assume a printk() immediately gives us a
callback to the console tracepoint.

Fix the console tracepoint by moving it into printk_sprint() [3].

One notable difference is that by moving tracing into printk_sprint(),
the 'text' will no longer include the "header" (loglevel and timestamp),
but only the raw message. Arguably this is less of a problem now that
the console tracepoint happens on the printk() call and isn't delayed.

Link: https://lore.kernel.org/all/Ym+WqKStCg%2FEHfh3@alley/ [1]
Link: https://lore.kernel.org/all/CA+G9fYu2kS0wR4WqMRsj2rePKV9XLgOU1PiXnMvpT+Z=c2ucHA@mail.gmail.com/ [2]
Link: https://lore.kernel.org/all/87fslup9dx.fsf@jogness.linutronix.de/ [3]
Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Signed-off-by: Marco Elver <elver@google.com>
Cc: John Ogness <john.ogness@linutronix.de>
Cc: Petr Mladek <pmladek@suse.com>
---
 kernel/printk/printk.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index f66d6e72a642..a3e1035929b0 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -2064,8 +2064,6 @@ static void call_console_driver(struct console *con, const char *text, size_t le
 {
 	size_t dropped_len;
 
-	trace_console_rcuidle(text, len);
-
 	if (con->dropped && dropped_text) {
 		dropped_len = snprintf(dropped_text, DROPPED_TEXT_MAX,
 				       "** %lu printk messages dropped **\n",
@@ -2240,6 +2238,8 @@ static u16 printk_sprint(char *text, u16 size, int facility,
 		}
 	}
 
+	trace_console_rcuidle(text, text_len);
+
 	return text_len;
 }
 
-- 
2.36.0.464.gb9c8b46e94-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220503073844.4148944-1-elver%40google.com.
