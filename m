Return-Path: <kasan-dev+bncBCU73AEHRQBBBQ6IWKLAMGQE2LXO7PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 06CE3570D4D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 00:29:25 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id qw8-20020a1709066a0800b0072abb95c0casf1582961ejc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 15:29:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657578564; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5GGk9hn5VWx56bYAvtUdP+41oJ2P4ufh+B3ve1+Oclvi6kv3wHdV+QmPWZh9b9Qg1
         U5GRcr+exI6NpKZougErPRHKdv6AJHIB1njrWnuyfHQ5FBAo0ZYPPF9sd5Xm34L1tfDj
         6ot5zRQfv9MZBMuwfxSh74ene80Vx5dk5Xj0YtOokQlv4BGTqX75Y1DTjs8VaSkY+7fq
         afwtidae1ZGALnOUQcBqZLyEf2QOytR3UQbuuPUEUhW5iTRnp0+uYOReHXirsZRtvIzN
         zXCGvt8xiI5KsGOjURDwkF/W7uKrUf85e+nEqQzeeFHObzgRhEQzxXKRIwH65ggQIK0H
         8UIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YKMhqO16v6O5QOXEyvAbt5W66oDzBw+UF9lzaHEkr0U=;
        b=kZEFFJJr+qda7AmajLaaL+TxnYzjTkxAd8sUmKv7M2r3sFq31fxI9FRXQn572HN08F
         zrXW3t3OqF6kZz4VHHixjVypIGUeViMv2iAeNlxrA3+iNvrPotSMobmbkvlEcqUVZd49
         +GXoS5f24MfB+fzoD7/2t+Iqewo7kUXRT/+4Rv5lGQngrgyDtQKeOf7VPlv7xSYXbYsa
         gyZwES5MAzKIf3TpYRnxODVVcCWrg4QPABlQtQ90L7y1R35lHviDwCfONbTc0nJMv49p
         okSws9ztnizSMXEOTJjoXeI5thADaIjXjjRsUERjjUCZU0g+qqWMh51o+I6yEjOCXGLG
         8w/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iw9/=xq=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=IW9/=XQ=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YKMhqO16v6O5QOXEyvAbt5W66oDzBw+UF9lzaHEkr0U=;
        b=rHnV0G4wZx3Ut49XfUjyca3XDZI+34MPVAhmkOcOwuHHwP4QMWw1hZOs/jBmBG7HQV
         AHw7vuF6fR/+ypXDUfgryM80EqvFN7GpAm1Jk3ZCpRBAv+MZD8o+UdDmnT5+iQVnv03E
         XSeanf3GKFiacyQ2vBHgWfHwOciKpU4elb7CdNp72zf8lls528tRUa42dV30zlgpEqzc
         /nbCfObLU9I37zKfVmOamoqmMyiZgqlXY1a4lmS3vA2cYTK+gl31MxTOEAWCnkCd1kgV
         DoSOsHoe7zSvLJP26y26y+gDFclU8D4AH19hbShsyNQFY96SDI8EZlCFpgWwnNcDCdRn
         0DPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YKMhqO16v6O5QOXEyvAbt5W66oDzBw+UF9lzaHEkr0U=;
        b=FwsZwsNfCHfobep537Ni766eLzuB3PZklgr60/FMsOZLfgdqWPiTWR5zf9/HtQzTu+
         DuwqU4I+T9F1hEScRC9F75mEGocK8zLCEOA9eOqcKzGip1gC/Q1a7Zb6R9fRFCg7Jp9x
         yZ0wVZ7UN74OHCZQtBG1oavffZft4geXC6CVRYpG8L/m7nRK0bm38ipP3ct3eb3bM4cQ
         QVR98reRDw6tZ9Aem9VVlGd/gVkQnfxd26z4IXpE+WCLd9qVBxQ1J8TWnJH6UPNkRv4K
         vVvuLisG0F17g/zNpNZm47nNTdRcNw+ZF+gQgOKw1LX+bzSnyA9ltpkv2ILy4m8+HBT2
         n22g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora807f2tHJhfD2ncF19KFwWvxjicQZPYGm8q6tsWd6Gu/EY7MT7F
	ktwOjfdGeoyN1eBSpjU+iPw=
X-Google-Smtp-Source: AGRyM1t/6Rb5KdgArfSXG0N9ozndrGOjbC9n6I/2bUK7DkP85Us7zofZzOzZ7h0qU0Lx3k6RXIz0bQ==
X-Received: by 2002:a05:6402:4411:b0:437:b723:72 with SMTP id y17-20020a056402441100b00437b7230072mr28053725eda.38.1657578563995;
        Mon, 11 Jul 2022 15:29:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2ad6:b0:6fe:976a:7a5 with SMTP id
 m22-20020a1709062ad600b006fe976a07a5ls503105eje.7.gmail; Mon, 11 Jul 2022
 15:29:23 -0700 (PDT)
X-Received: by 2002:a17:907:60cb:b0:726:a69a:c7a with SMTP id hv11-20020a17090760cb00b00726a69a0c7amr21457362ejc.156.1657578563043;
        Mon, 11 Jul 2022 15:29:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657578563; cv=none;
        d=google.com; s=arc-20160816;
        b=NG3UEfvP4KEnXWCQx7fdEmvnJA2w2c8lZabeZ8RpQbTG0FpuKNJBom2Rt3rjftpP6s
         +gooxlADsil17TedYgnHVLiB1OsyXioaHxdzX3GijhPSepfdn+eFqMRJrlqhjGJo6Mj4
         ZirAmKvNdqoULj8vt6t5otycp48h2RLkDi9bJSyjoca5+Qy7Z6L5oRHl4kYJQnoV0/fC
         6vUMisIxNz3fMzp2rRgOkPqQA3e4VOb5gXx2uAA+MMdlit/1HpiD/Oj8gxIp6udS59e6
         5JSHIvfdWjzbmxhZZUU4JRvsa2zbfT66ub81eeJmlB+3EYfCwU2L7rNHBauCSZAexC5Y
         qPow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=KC8nJVCZYlFizOhBExKnQcu8+GgOnpx88YOiuGC3UF4=;
        b=IpA0P1zzMJ9Vn5iMfMS83mRrGTyUKkQlQtogBaprByi7dIgyLjyGMheKH2Uc7i0xZ8
         pJeybnOBSLuCfrpBEbxLrQXAShCXYLL3Dpbu4YxhOX4GOoIGVjsxFdBy+44x3Q5sY1oK
         OkYLPLr+dE2lXXVad4y6JjdV/JyL6XCBeBOHMfJyokjmk//sCOBY2WdhuTbftWZkksyu
         gnfNl2zrl75czS7nyXWIPGctZJa3Vw6rMWLhpOFR03xHw0eNYvtDSunb8WPfdWqaOFmZ
         Il43NquUyoRRYJZ2p+C84XJ609Ou+t9axOXnte6jPv2RC8/9pmy2bBAyaog00/f2AzVu
         sNCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iw9/=xq=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=IW9/=XQ=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id d2-20020aa7d682000000b0043780485814si268418edr.2.2022.07.11.15.29.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Jul 2022 15:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iw9/=xq=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9BEB5B815F8;
	Mon, 11 Jul 2022 22:29:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 080A1C3411C;
	Mon, 11 Jul 2022 22:29:19 +0000 (UTC)
Date: Mon, 11 Jul 2022 18:29:18 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: John Ogness <john.ogness@linutronix.de>, Petr Mladek <pmladek@suse.com>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, Thomas Gleixner
 <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Naresh
 Kamboju <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220711182918.338f000f@gandalf.local.home>
In-Reply-To: <20220503073844.4148944-1-elver@google.com>
References: <20220503073844.4148944-1-elver@google.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iw9/=xq=goodmis.org=rostedt@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=IW9/=XQ=goodmis.org=rostedt@kernel.org"
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


I know I acked this, but I finally got a tree where it is included in my
testing, and I hit this:

INFO: NMI handler (perf_event_nmi_handler) took too long to run: 9.860 msecs
------------[ cut here ]------------
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
perf: interrupt took too long (7980 > 7977), lowering kernel.perf_event_max_sample_rate to 25000
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


On Tue,  3 May 2022 09:38:44 +0200
Marco Elver <elver@google.com> wrote:

> Petr points out [1] that calling trace_console_rcuidle() in
> call_console_driver() had been the wrong thing for a while, because
> "printk() always used console_trylock() and the message was flushed to
> the console only when the trylock succeeded. And it was always deferred
> in NMI or when printed via printk_deferred()."

The issue is that we use "trace_console_rcuidle()" where the "_rcuidle()"
version uses srcu, which the last I knew is not safe in NMI context.

Paul, has that changed?

Thus, we need to make sure that printk() is always called when "rcu is
watching" and remove the _rcuidle() part, or we do not call it from nmi
context. Or make srcu nmi safe.

For now, I'm reverting this in my local tree.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220711182918.338f000f%40gandalf.local.home.
