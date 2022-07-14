Return-Path: <kasan-dev+bncBDZKHAFW3AGBBZ63YCLAMGQEAGPMJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E910057511B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 16:53:28 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1015d202b74sf1239091fac.20
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 07:53:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657810407; cv=pass;
        d=google.com; s=arc-20160816;
        b=G2Qj+bycPpsZlgUnNwmzz8ajcwp3HDq0ktfRpNNG5NfVARLGa+iPnP4uJjOGmpSYzu
         JZMZ5txtw/QfHH73di6zhfogJ0/fzrfGoGNTHdSHjEMqioSEmCtLAsstN2aBACzr9xD8
         yicXbLcmnbei7C6Qy2RlbnQHbu8qj7fTN2xPXcUfTfmFiVM9GzpMn2aY931Or2Bl0JnT
         0LKlkywXDbY8fRRZFvTo0zWGY2iJgaZYpbNiUfBJAqW+Yk8zu266nRsTmVPiLLnDI3IO
         PIFOkVfbq99wZc7b0cgeAzDMLeGpTK1mYPSJyfaNgqKbP0Bo6NqWC8feI2L4Qst/12ZS
         mo9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=czVqQEL6Pz4pyzlvnAJR8I0z5SFtm0S6sE95RBScfL8=;
        b=fxj2uMHU6dob89c35zuyGny4noXbDilR9BI4C6yW3K1wydaOsA94lEOSrLS9ASlhIt
         mPRFFz67BAWp+hTtssHFkoLHTyVXWLQrl6hWwuaNjSJ4rv+6lPxA2Q8DTZy3dVORSoav
         tDQLSohobMJBi+ktxZ21a/jNAvwvaZFTSBC+IX6tBusnYynccECca+m9R8KQBYGFATTx
         XT8kNYJO3Iqc3s4O9d9mSvUouYtaNXt85oj3oBXmPT9kKUTZhzkx311/wt4NYO+Hf/Wp
         VhVDPIVTMW7h8IfMKkWFZeqZcdosr3CQKbLk1WCrsz0D/km4xFy2fKmKI6Q3pnTVCBq/
         9NjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Ue6EhNVJ;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=czVqQEL6Pz4pyzlvnAJR8I0z5SFtm0S6sE95RBScfL8=;
        b=ozciDwiQwvilIq5fWme3EBtL+7W6OxKTrJzShKZoTt4tcjlH5kFAZrwwFvaoigSlNl
         Qx47bYIQ2O6fIcb6Qa5xl8pyAXV4aSix1qtklmjZ/j+6K7D+kFA7E1cvCk2xiPTIdSLe
         GqP/GWCZrc356iiswR7Y4IQ8Ug/Axq1vLrW99RY6uh1ChU/lQfu7Y4kFJNRBC2C2mJFf
         xIEMMjzJwSc8+znyoTfhl2WR795HBTa8IlGUM5WWwCnTl92MwqMNQbkCQfMYUiwTRAMa
         uebUfEXZxCjtHtIaZ4k7RS+PxuLXqi8ABl8uu72sgGKHWKQALNMurIvXQj//NZsUElr4
         CV2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=czVqQEL6Pz4pyzlvnAJR8I0z5SFtm0S6sE95RBScfL8=;
        b=xnpuW8RnHm86JFG9hxzm2V1A7Dk2F1M7pSWFdvcxNvBsPwcOSh9qBMIPM3Dx/I+YND
         wSRg+bsTrQJP140aIDqZUhbAzjKk5BCX/RU4e0pRGEvIB2lGFGmpMSI/uXHSN5Gqlx3A
         Dv1xgmahAQtD3VZsECL3nfTfykSccsWM+iON/HRH2V5T0GytPA/oOE5+fnw7Xd9KiM8I
         6/JKk87q3xqi93nypsCXL281Qw4MriLmUc5rql2y6x0Gb7SrFlUp3Dkavv4zeir92UHO
         tOD5G4Dk394wgFTn/o1Q35FDM2aB2zqlGw/Tl2xutEkMTs60cpqYVUx7OPsPAeXtEIyg
         9cXg==
X-Gm-Message-State: AJIora97dfr0CXoNpauYey0DzyVdnQ+UqqUMNyR0spYKzy3vjuoYzJAL
	AHtwiekWIloEycMjnHgunDM=
X-Google-Smtp-Source: AGRyM1sBHel7aciWRYlnttO3V4EQhLH2yvHD4OlmDR2V8MnOrGxQrRq83/7GXnJi0z8PRd5hBOxUvQ==
X-Received: by 2002:a05:6808:f8b:b0:339:e10e:46ff with SMTP id o11-20020a0568080f8b00b00339e10e46ffmr4737857oiw.179.1657810407351;
        Thu, 14 Jul 2022 07:53:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4e0e:0:b0:32e:9a41:a817 with SMTP id a14-20020a544e0e000000b0032e9a41a817ls91560oiy.2.-pod-prod-gmail;
 Thu, 14 Jul 2022 07:53:26 -0700 (PDT)
X-Received: by 2002:a05:6808:1644:b0:2f7:4de5:3c53 with SMTP id az4-20020a056808164400b002f74de53c53mr7470912oib.225.1657810406807;
        Thu, 14 Jul 2022 07:53:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657810406; cv=none;
        d=google.com; s=arc-20160816;
        b=aCpBm+sCP7WVVOWbzcMTdQy56DO9bJ64SjQZT1Zey9aNlGJftFhGYiT4G7ONMgfQdc
         Xg7DDYJbYTF8KtK8zdvTbiF8SOGpFSXd0tojMnkB+jNTYw/a+CTYfaKXul2bWZK15IBV
         3DP7PQneyh6JCDr0T04tY6WaA0n+UguBh6UhIJG6Bi9XwFU+aeIifaIPxdCQzC2zEgfk
         XtUIkYhrU0D714IkCFwEt5p44X9BZnnKVXYOYFZaVfE32awZf79XPgUXEVJhrgL4SRv1
         AaWKweOt9ZP991tdGIK9Y+xK7nZsXpp96dP9YWyxImiubUtlhiTWcoeEGVAkNS+o9sSu
         KK9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=73o1eBzbI3qd0v81oY29I4k1KUoL3xZ73b9t7xZ4knA=;
        b=VIPJc8w4ne3tmZNawuCh1ETXcMoNNS0YTlnYft/0SFBpkdvHI8h687h2CybSQBQLmt
         73ScdAUnIoqytWA0lPnuuWxKgSg1RawjXnW24CJHbxWbomPNx4xPVEniulRA5OSqJu0Y
         3ARO65IrnrsGIXHeTouRjQe9vJJKnZPhB5GupH0gyTpEEE8+2lW67pQR11pEMjV4mgFU
         Ojg6elihRG/mhg6xreZFgOLKrg5CySIIXZ+ibkNYfNnUHKgbgTaXJYa5pA6OxO0w8vHC
         WIhwVItnH9+wH0RsI+9lczcfX6DY61lIV9N1l4eadaSIo6rwZCJ5Lrw8KzN1R5eYFUKr
         KMBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Ue6EhNVJ;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id k22-20020a056870959600b000e217d47668si178850oao.5.2022.07.14.07.53.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Jul 2022 07:53:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 812911FB5E;
	Thu, 14 Jul 2022 14:53:25 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 15FC42C141;
	Thu, 14 Jul 2022 14:53:25 +0000 (UTC)
Date: Thu, 14 Jul 2022 16:53:24 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220714145324.GA24338@pathway.suse.cz>
References: <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
 <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220713112541.GB2737@pathway.suse.cz>
 <20220713140550.GK1790663@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220713140550.GK1790663@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=Ue6EhNVJ;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Wed 2022-07-13 07:05:50, Paul E. McKenney wrote:
> On Wed, Jul 13, 2022 at 01:25:41PM +0200, Petr Mladek wrote:
> > On Tue 2022-07-12 08:16:55, Paul E. McKenney wrote:
> > > Maybe printk() is supposed to be invoked from noinstr.  It might be a
> > > special case in the tooling.  I have no idea.  ;-)
> > 
> > I think that it is ok to do _not_ support printk() in noinstr parts.
> > 
> > > However, the current SRCU read-side algorithm will tolerate being invoked
> > > from noinstr as long as it is not also an NMI handler.  Much though
> > > debugging tools might (or might not) complain.
> > > 
> > > Don't get me wrong, I can make SRCU tolerate being called while RCU is
> > > not watching.  It is not even all that complicated.  The cost is that
> > > architectures that have NMIs but do not have NMI-safe this_cpu*()
> > > operations have an SRCU reader switch from explicit smp_mb() and
> > > interrupt disabling to a cmpxchg() loop relying on the implicit barriers
> > > in cmpxchg().
> > > 
> > > For arm64, this was reportedly a win.
> > 
> > IMHO, the tracepoint in printk() is not worth slowing down other
> > important fast paths.
> > 
> > The tracepoint was moved into vprintk_store() in 5.19-rc1. It used
> > to be in console_unlock() before. The previous location was not
> > reliable by definition. Old messages might be overridden by new
> > ones before they reach console. Also messages in NMI context
> > used to be stored in per-CPU buffers. There was even bigger
> > risk that they would not reach the console.
> 
> Fair enough, works for me!

The remaining question is how to make the code safe and calm
down the warning.

My understanding is that Peter Zijlstra wants to reduce the scope
of the rcuidle code even more in the future. So, we could
do something like:

From 24c3517dedf2a30efabe72871c188fbfffffd397 Mon Sep 17 00:00:00 2001
From: Petr Mladek <pmladek@suse.com>
Date: Thu, 14 Jul 2022 14:54:12 +0200
Subject: [PATCH] printk: Make console tracepoint safe in NMI() context

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

There seems to be three possibilities.
Link: https://lore.kernel.org/r/20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1

Signed-off-by: Petr Mladek <pmladek@suse.com>
---
 kernel/printk/printk.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index b49c6ff6dca0..a13cf3310204 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -2108,7 +2108,15 @@ static u16 printk_sprint(char *text, u16 size, int facility,
 		}
 	}
 
-	trace_console_rcuidle(text, text_len);
+	/*
+	 * trace_console_idle() is not working in NMI. printk()
+	 * is used more often in NMI than in rcuidle context.
+	 * Choose the less evil solution here.
+	 *
+	 * smp_processor_id() is reliable in rcuidle context.
+	 */
+	if (!rcu_is_idle_cpu(smp_processor_id()))
+		trace_console(text, text_len);
 
 	return text_len;
 }
-- 
2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220714145324.GA24338%40pathway.suse.cz.
