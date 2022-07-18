Return-Path: <kasan-dev+bncBDZKHAFW3AGBB3PQ2WLAMGQEDBT2LHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7542578611
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:49 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf2072467ljj.19
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 08:12:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658157167; cv=pass;
        d=google.com; s=arc-20160816;
        b=hO6sLMGiOGz+MhYQQFJ2xK7OHDp9MpxowyMLIvtMWT9qV5o2ySKw80w2PmOpg+WC5C
         yqMpmjUzPt3XoJA4YTgpN+q8rX+AunLwWVtt7bOUr3iKFXN1Dtv5M3JC4l2HrexuilbZ
         /liG2ZA0n2L+Su8NotNChfiYYrdp+3bxan877B9HLvBNDDV4Xtx1X/328DJCpZKKa0wi
         8Ihd1MNW+RIaIAbWS7nh/u4JAvuxAA91pfjzAKYMY5IM3vvqy9JX76vpTRvJUAm2HsQ1
         2U9X8/PA18dTYqUSRprt8jI0lRgCdCDdRe3sMihw9gB8eif4u0H0XCaB98QiIo4mEzA4
         jiWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=jpjx6kWfYXdw4agkyuF72O/jAwwRompE8qdgmnO09qc=;
        b=CcnQVYKZ2U0FPaPrZH5bHKMVW9RrFQjMxhdho0rF+oW9Owo4KLT/2v80VOQEAY+giw
         /RqY3vTStt8VpQHUlTeQ9/OCRJbnveK/ZTd7oX8fJPt5bn85Ta+86CNxwUVXAydU4Z51
         wlo7HiXqoA4S1SpGlnCLVg5Rvm9yiUsGISWBEv3mN24zYOgrAPcrzIiX7bqNBxnUdcVn
         Pm7+jEFamZFVlYQdUIJqmBnSb9PWDExn1bTXhdugURQzn9QmziGzZk5NrBg44efwPiAn
         eRu3MFbGTwCfw27/yd4iLtN0oggF5qaehD6Xy1Vzz2Zur7kfJ+ogulq7Rwq5KpgMW83o
         0Mog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=YW1yP+oS;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jpjx6kWfYXdw4agkyuF72O/jAwwRompE8qdgmnO09qc=;
        b=sn3BhE8IcBt70w0mVIrgwkZGNHyPu7sF1PdF6PEVQQARBPWTQL1iG+KemeugwEW/Sg
         nAbLhkfXnA+dT1EVMdXpE9gTiceW1yWX14ocY6T5p0wH2ixlLSJJke5xTBY+rugmvdxu
         NvZLwkKdqBvgVSlsihVf4jO7ZBKvASIyDYPiVy88qXlGdraKjvYGGa8QX8Tvo6V+x0Wk
         4yqXBnkVxKSi1D88VdpwuSqGn6a/M8V77JzpVxXWkeP0JDcQw7/9Zq4AAQQ6sBmDtVJ4
         eHsN6wZXxRhVWwjRCDaeJAj5ciwgF3Io5JBrFpy5tgIEzNsOIwUchNibMMxYqtPbaWi1
         oQUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jpjx6kWfYXdw4agkyuF72O/jAwwRompE8qdgmnO09qc=;
        b=WBMvO/7DmD791y+Nqztj2hB7vB5pHaIUqyf+oqBwv6WQFPKGdgrH0AePukPPvS/tlj
         ghB5jjvaVb5yzGMDyDcTG0knz7iQUTxnPnfduQHyX7wimth1XENERx7yEr5f7mikaJ8k
         a4zva/o45ZqlrplZRu2ZnEVAReVAHR+ZR3XTtkOuqB/LZ9y7LwshD8jPt8mj/fDxb2PZ
         cHro9xYcAen5u8VDb056L+3b7NOGmsTokdnsbgTqM4zjTuXuisbwls+aZLq311nuW37v
         DaIgjs6geXHuR/2ZayV2xYYacw2z3O1YZ2jEKhS2m2Jw/tNxlhuvBq1Y3PyElO44X7aE
         bqBw==
X-Gm-Message-State: AJIora9PF9XINXVVQN1iMKYEPbPWUK90bVrr+ZOT5iID777PMFES8sTI
	ugEnIZLj1UICM2Z9L+Lyzrk=
X-Google-Smtp-Source: AGRyM1uN/JFliKpGm3DgjGHloPDU5/sdmCiqQfusaWm8SurT/8tiRh6tLi5eMKNs0pynWSAbScFTVA==
X-Received: by 2002:a05:6512:3053:b0:489:c4d4:ba12 with SMTP id b19-20020a056512305300b00489c4d4ba12mr15464889lfb.476.1658157166166;
        Mon, 18 Jul 2022 08:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4da6:0:b0:48a:15f0:80b2 with SMTP id h6-20020ac24da6000000b0048a15f080b2ls842446lfe.3.gmail;
 Mon, 18 Jul 2022 08:12:45 -0700 (PDT)
X-Received: by 2002:ac2:4c55:0:b0:489:e012:62e5 with SMTP id o21-20020ac24c55000000b00489e01262e5mr14325878lfk.123.1658157164933;
        Mon, 18 Jul 2022 08:12:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658157164; cv=none;
        d=google.com; s=arc-20160816;
        b=AMNPDNnvrmWH+FnZkleQL6YLmp4Clo79reOilmcqfKgoWmtN/VNjy9dPDHMquQtgTI
         zvb+UQ90Vauo4SIPrWoHNP8xdPCB+qGk7yBCvUf5ll2ObsgnhMf1sEBtFbC/RTeFWtTR
         03jX9NpSyN1LyYWzACbOsX35DFDJLpiYUd9dlr0KLVb1pd2YzsTRVetI4phJHAGGZjEf
         M+QgIS/Ysi3XA16K5Enow8UFNXAGv5slnbQ/ejryNPk28BfGoypeTbP3ZNr9Sh4vnDBH
         T3oxoLakjSUctUGnKAxNGQA6Wp/2nBS84l1zaqTNAijDyq/ewPLVVDO+6ImNzrkHQesq
         JKiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=n6LVjaU4a6ZqK4u6O9u+Kak/7hh30ZC7LW8h15/5TNQ=;
        b=oCUU1nYUzjJRWJaA8W7sm3ywrk/g/S9yz+obYvo5EeTZ30JNwVZmRi+IkK8dHfUSfZ
         KtZpfHwAF/YcloM5XopfOJlbi9cJOc/CZNv1h2bThUkT6D0LAO6YzMy9gMKv7L9UUBip
         wLItGV1BaWHrPxrDoHgC5yN8+QEUSp69gM/ojsW2SFzbg4c1It4/hyurkahhDHmwAqRc
         fCq3mvDQMizoB4WH85Z1SAzeUtHQ6cSNvTeaRZ9EFcLIvqZxHtgZmUn038plOUBDmr1L
         ShbZlKbp/y44ckB54/ncKIWpoq/3CIOp3h7RSMpKSmkl2ufhrvRsH0HQot13aAqKvTpy
         mx4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=YW1yP+oS;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id k7-20020a2eb747000000b0025d5ccbc5c7si443793ljo.1.2022.07.18.08.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Jul 2022 08:12:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 1769E20113;
	Mon, 18 Jul 2022 15:12:44 +0000 (UTC)
Received: from alley.suse.cz (unknown [10.100.201.202])
	by relay2.suse.de (Postfix) with ESMTP id B962E2C141;
	Mon, 18 Jul 2022 15:12:42 +0000 (UTC)
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
Subject: [PATCH v2] printk: Make console tracepoint safe in NMI() context
Date: Mon, 18 Jul 2022 17:11:43 +0200
Message-Id: <20220718151143.32112-1-pmladek@suse.com>
X-Mailer: git-send-email 2.35.3
MIME-Version: 1.0
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=YW1yP+oS;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
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
Changes against v1:

  + use rcu_is_watching() instead of rcu_is_idle_cpu()


 include/trace/events/printk.h | 9 ++++++++-
 kernel/printk/printk.c        | 2 +-
 2 files changed, 9 insertions(+), 2 deletions(-)

diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
index 13d405b2fd8b..5485513d8838 100644
--- a/include/trace/events/printk.h
+++ b/include/trace/events/printk.h
@@ -7,11 +7,18 @@
 
 #include <linux/tracepoint.h>
 
-TRACE_EVENT(console,
+TRACE_EVENT_CONDITION(console,
 	TP_PROTO(const char *text, size_t len),
 
 	TP_ARGS(text, len),
 
+	/*
+	 * trace_console_rcuidle() is not working in NMI. printk()
+	 * is used more often in NMI than in rcuidle context.
+	 * Choose the less evil solution here.
+	 */
+	TP_CONDITION(rcu_is_watching()),
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220718151143.32112-1-pmladek%40suse.com.
