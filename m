Return-Path: <kasan-dev+bncBDZKHAFW3AGBBRNOYWLAMGQEG7ZHUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB9C576118
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 14:02:14 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id v14-20020a6b5b0e000000b0067bc967a6c0sf2159963ioh.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 05:02:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657886533; cv=pass;
        d=google.com; s=arc-20160816;
        b=UeXQ8V46EtkrLhOjzUar6ohgQhBqyuYXmpHoSwDcxl8+0iTVBfemUdHWdEMYAC93FB
         VfDftOFpSf+hxC2c1UiqlpvpgIUZ5RCdXe+5OlztRBOFgHoGbp64Ne7X7+A2S96/zszo
         HE+XbwfjWWOqTuKBQvoWwHo6tuTNhiKhU31eInEInxAhtZXbdfTJaBxBc7iCG2HE8XOn
         LSZCTVPWNtO9+Lx8VnzkqY1f/TD54eyU5tW9V7eUU9jmCuzglwbCG0aOV9x3/Nx3wiVC
         XOtqk7ZDeehl5NWYc+bXeq4F4tqu/o8vXenEWl0SFU4Ue1mjOgb62Xtf5N0XyV49mKS5
         lsTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=R3PWfEMYnaXwS41m8EAhbq3zuwLuffgFUUftA8V2190=;
        b=T1IqxHAVYQyI90LpwpPGxT4C0cg4v7VfuoBbgC0L2ymhozJTb2U9ULmlB89d7MkFpC
         kqE7+CJ80E978DNv5cSEGbWSZxfJjLO4mp3iBkDPTm2MkSZfIynuOstAUD3Uoe6lkhxJ
         ygYxiqrvXBgMGso3WgFBX90Q3ypHiVpd/aR/hQvDwmWmMmfHgw4LV4Epr5QO7EhFF1O8
         bhyDkLPdyql+lRiHyiZt5N/l6w8sRoeaw8+3GbFNWXZuIgjzEw9WRoK1EwwxLBZZSq+i
         k1m9Yef1WZvEo6RMObP+VyEMn8zNwm2Xk50iriAejnHRvHsfuCBJnXRBVQbCWbnzJQ/Z
         WTag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mbm6gSwb;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=R3PWfEMYnaXwS41m8EAhbq3zuwLuffgFUUftA8V2190=;
        b=bFIVlqZpLdKeS+Tmqn1Lqs4xyG60/mbbE/S3SD6V4ySK7jB33JvTSZinualiD1oGg8
         KPDTS2MswNWnCCCfHcFHZWMAvRmwcnvwYhoWHpMtW6WNkhg5OhOVHJC2hGwv/Ez0qfy/
         EnTnQSsCeQ18SV1U8pOkvklroFF7f4hlHirexjXf5kCq2/IWYslfeaJ71IBHxcx6PfF4
         OG7B150XD+GfHr4SNJ5+S8ya3qUsEd9koEB3KPAYFvut0qegC9zX+4JhWWjYJQofnAKF
         2p9NfSGh759BQXuUupuhmNCZ6zZxmnIG6OOVAaQ2HNu4cUB35ggA6uUT1PKAEJTO1HCn
         oBDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R3PWfEMYnaXwS41m8EAhbq3zuwLuffgFUUftA8V2190=;
        b=LTZrQA5xyRjCBE35pcqE57Kh/15qnC22upyngG34xN3PcSeZo4/gvZg6m7Mb3ysJQH
         q6xHrvN8FcjYX9Jc42cM1rzW2xCNCYqKLAmZv6Bvdu6WJnyOZYfQNaJDI6ZMjnkcXOJH
         4Gz4R44QdgIaPf2fNK75YWzCgMncehhbV4YnJpFq3eZr/+rZ6WG0A3ac248oEyXUC4nV
         Uic1bnv9QValjSoLn5B1wmxtxCSWLCdgLsT3qe3FmVVIRmz99bNYPtxVZGpovaFureAa
         SEkKZLdTM05cU3pFSi4+fI3SLrKK+gqNK3Y5Bqd3jOV/TWwCe9LKNsXKNZqc+/+f3XM3
         jC0w==
X-Gm-Message-State: AJIora+tYiX7w3IBdSgZiyKLMW3/+cPKwjRGhin+uNBAUa2lI5vlhhh/
	inwpf+P31uN8gzRRHwbQYMs=
X-Google-Smtp-Source: AGRyM1taYPJvxK5SuCattMUUJPD6488mMZQ2+xdPVbMNgdPZF1FE18LWGCHzSpUw4T6IA7lllH6r7w==
X-Received: by 2002:a05:6e02:156c:b0:2dc:902a:5b6 with SMTP id k12-20020a056e02156c00b002dc902a05b6mr7364615ilu.59.1657886533379;
        Fri, 15 Jul 2022 05:02:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a47:b0:2dc:5d54:88f7 with SMTP id
 u7-20020a056e021a4700b002dc5d5488f7ls188430ilv.6.-pod-prod-gmail; Fri, 15 Jul
 2022 05:02:12 -0700 (PDT)
X-Received: by 2002:a92:2a0a:0:b0:2d9:2571:f57e with SMTP id r10-20020a922a0a000000b002d92571f57emr6879156ile.154.1657886532914;
        Fri, 15 Jul 2022 05:02:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657886532; cv=none;
        d=google.com; s=arc-20160816;
        b=cLdo+k4Vyh6/kYSlO0RNQJXOZkO2IFFiAaJAxpRwRurEaBwlYAcGpQ9v4yDhxmWmS0
         EkhlEnPQBZwvbxRtVEX8sgxHvKti4WgPM2qtmxGiWtFPx72KkQ6N1iLJCvF7N/LhM03a
         aZbJ6BNpQlM4l8iUEkMHOV6GNpuz8lp6PW7QBEvEE7aP2zmuLhkm6WH8zibdx0XdGl63
         7tGyE+/n/3RtGIADDbu6x/ADA5z+Fn1IXFJuetmxsJV5Q0935K83t7nrNqy6OQfUGz8/
         aWU/MYAuDPDhq+cNUERvlIxDswwP5MX0tjM/lYV1wB6cvv8IcSV9Va22OiH4oFcVix8k
         RW1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=L8s/D1PNvngtvRc/fSkA0pXDsyv9MWiwhDTw8Ussffc=;
        b=t7EkHUWJzK5duA0JJowd263Xg/0uphnmgH3Q8yYyFHH3USdZMjhTjNc+g5Qla+6g5s
         EJ1+Si+yQR5qLT1sFMd3TR8hIoqtqTuJ6BIVCcoLAT3O0n6k9MrKPubp4/SLTUGLo62n
         x38q3NTijXSpmsKPkn0wCNBf356QrnTLDU8cnHSpKugC73ntaGJxN2IeQHUkifiAwnyq
         hhDjOavZPT75275rRYohtnYaQ4qlbqYrGCmBICD2TiURag7HIhIa5h7dSXmgkfzpA5RB
         fO8uCNUY2Byl3wINML5ToBdLpDB15EXyCSp6FOr3XcnuDaoG/rg7dte/oKcy4wkAuGwm
         NGgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=mbm6gSwb;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id e17-20020a056602045100b0067898a22fbfsi187790iov.3.2022.07.15.05.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jul 2022 05:02:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id A926834D7B;
	Fri, 15 Jul 2022 12:02:11 +0000 (UTC)
Received: from pathway.suse.cz (pathway.suse.cz [10.100.12.24])
	by relay2.suse.de (Postfix) with ESMTP id 416502C141;
	Fri, 15 Jul 2022 12:02:11 +0000 (UTC)
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	John Ogness <john.ogness@linutronix.de>
Cc: Sergey Senozhatsky <senozhatsky@chromium.org>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	linux-kernel@vger.kernel.org,
	Petr Mladek <pmladek@suse.com>
Subject: [PATCH] printk: Make console tracepoint safe in NMI() context
Date: Fri, 15 Jul 2022 14:01:52 +0200
Message-Id: <20220715120152.17760-1-pmladek@suse.com>
X-Mailer: git-send-email 2.35.3
MIME-Version: 1.0
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=mbm6gSwb;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.28 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

The commit 701850dc0c31bfadf75a0 ("printk, tracing: fix console
tracepoint") moved the tracepoint from console_unlock() to
vprintk_store(). As a result, it might be called in any
context and triggered the following warning:

  WARNING: CPU: 1 PID: 16462 at include/trace/events/printk.h:10 printk_sprint+0x81/0xda
  Modules linked in: ppdev parport_pc parport
  CPU: 1 PID: 16462 Comm: event_benchmark Not tainted 5.19.0-rc5-test+ #5
  Hardware name: MSI MS-7823/CSM-H87M-G43 (MS-7823), BIOS V1.6 02/22/2014
  EIP: printk_sprint+0x81/0xda
  Code: 89 d8 e8 88 fc 33 00 e9 02 00 00 00 eb 6b 64 a1 a4 b8 91 c1 e8 fd d6 ff ff 84 c0 74 5c 64 a1 14 08 92 c1 a9 00 00 f0 00 74 02 <0f> 0b 64 ff 05 14 08 92 c1 b8 e0 c4 6b c1 e8 a5 dc 00 00 89 c7 e8
  EAX: 80110001 EBX: c20a52f8 ECX: 0000000c EDX: 6d203036
  ESI: 3df6004c EDI: 00000000 EBP: c61fbd7c ESP: c61fbd70
  DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010006
  CR0: 80050033 CR2: b7efc000 CR3: 05b80000 CR4: 001506f0
  Call Trace:
   vprintk_store+0x24b/0x2ff
   vprintk+0x37/0x4d
   _printk+0x14/0x16
   nmi_handle+0x1ef/0x24e
   ? find_next_bit.part.0+0x13/0x13
   ? find_next_bit.part.0+0x13/0x13
   ? function_trace_call+0xd8/0xd9
   default_do_nmi+0x57/0x1af
   ? trace_hardirqs_off_finish+0x2a/0xd9
   ? to_kthread+0xf/0xf
   exc_nmi+0x9b/0xf4
   asm_exc_nmi+0xae/0x29c

It comes from:

  #define __DO_TRACE(name, args, cond, rcuidle) \
  [...]
		/* srcu can't be used from NMI */	\
		WARN_ON_ONCE(rcuidle && in_nmi());	\

It might be possible to make srcu working in NMI. But it
would be slower on some architectures. It is not worth
doing it just because of this tracepoint.

It would be possible to disable this tracepoint in NMI
or in rcuidle context. Where the rcuidle context looks
more rare and thus more acceptable to be ignored.

Alternative solution would be to move the tracepoint
back to console code. But the location is less reliable
by definition. Also the synchronization against other
tracing messages is much worse.

Let's ignore the tracepoint in rcuidle context as the least
evil solution.

Link: https://lore.kernel.org/r/20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1

Suggested-by: Steven Rostedt <rostedt@goodmis.org>
Signed-off-by: Petr Mladek <pmladek@suse.com>
---
 include/trace/events/printk.h | 11 ++++++++++-
 kernel/printk/printk.c        |  2 +-
 2 files changed, 11 insertions(+), 2 deletions(-)

diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
index 13d405b2fd8b..a3ee720f41b5 100644
--- a/include/trace/events/printk.h
+++ b/include/trace/events/printk.h
@@ -7,11 +7,20 @@
 
 #include <linux/tracepoint.h>
 
-TRACE_EVENT(console,
+TRACE_EVENT_CONDITION(console,
 	TP_PROTO(const char *text, size_t len),
 
 	TP_ARGS(text, len),
 
+	/*
+	 * trace_console_rcuidle() is not working in NMI. printk()
+	 * is used more often in NMI than in rcuidle context.
+	 * Choose the less evil solution here.
+	 *
+	 * raw_smp_processor_id() is reliable in rcuidle context.
+	 */
+	TP_CONDITION(!rcu_is_idle_cpu(raw_smp_processor_id())),
+
 	TP_STRUCT__entry(
 		__dynamic_array(char, msg, len + 1)
 	),
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index b49c6ff6dca0..bd76a45ecc7f 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -2108,7 +2108,7 @@ static u16 printk_sprint(char *text, u16 size, int facility,
 		}
 	}
 
-	trace_console_rcuidle(text, text_len);
+	trace_console(text, text_len);
 
 	return text_len;
 }
-- 
2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715120152.17760-1-pmladek%40suse.com.
