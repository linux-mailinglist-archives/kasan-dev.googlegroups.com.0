Return-Path: <kasan-dev+bncBCALX3WVYQORB3N57X5AKGQETVSUECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C104268AB7
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:15:43 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 135sf3557315pfu.9
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:15:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600085741; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y1NZ47iVyj/8BfxUkpD/rrCqsSI68y4NiwIfFz09mIsalKLJf3aB7JlnlpbeWi/h9p
         dF6FCDnbhqRHvY7IK9aWH2qYPEpnAWFMk6hlLIVpdYDH6WstP+Z+ljpF9QCmQrlBlrZJ
         W8smcrJX0/g59yqPaNgJ7ZFRfgEJPLu50AU1DHjGKn+0fnxx9d600iQ803og/9LbFMEk
         x/NzXswj0onHMPlGMn49tGJ36s7ln8fhHnYefqn7ErOlrpel0ffF9EksD43ZoLU2RMJR
         xqCwLwq5T8LuoYfAsmov3W1e+2B5W/dD7iIR5QiTqC2D5CjQY3jXp+exyTyX7Og9aNyJ
         nOmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=zU7bJpkF3dtTNsVtIzlzeM9GMufFW67Vve8ee7ERgLg=;
        b=MTG7E3lNXrl/2Crv7Fc4rHkXQJj7fXc0uoipobrm3UB4zaH4FwcT9NpMVbmFiUWi1J
         R+ESBcX8JfThZewmtgo1nt+ApPEPUGVE7FTlT+kq42elWapGyXe1sChIo+MjV9o8LX7O
         mJsM0DBgI0luLOEzFzdN8nZ8BWpSJ+HwP3Q3N/8DBJ6fMt1i447gZ1SNXrgvZMwmvY6G
         LdfuFf9SsKdZVAN55Vc5f4Rv7yJJ5cCe0EfxXPguZCIYElfcmjkYmXrpTRGgaXkpj0yq
         wL5WkcTPdYIANLztxNCN4Wsk6EE8TwZFPBc2JybxU9vdANBUQWp6lvPT9t5+r9l/XQaE
         6Kvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zU7bJpkF3dtTNsVtIzlzeM9GMufFW67Vve8ee7ERgLg=;
        b=mWiOTUx9STu+bWQEiW8EUHUKhK0Ltut53eDuuF40iwmwjsBlY3S+OZmNjJDLrermNS
         1vERNVFq0SLQ0YWFGbN+ffsnLdGrZAK7GnEf1UgBFBUTkbf257APGXgEy7nu6cmATfuM
         rJVApwSkPe2/sY6UCLg0wgheUaJ4GOMli7C4lW+7FO/w+kuExtQ3CT2PalBjxwEoSJ+y
         GCqCca5Iy1UlpnC4Cz2bg2LVz9h8tqMEHDmFr001gChOTgfz3mzi38rwj+mDlI5uqbNq
         Azmr4rTST3jxvXARS2D0OF4KrOYEc28UFPHyRQONYP6f4ju7WlYkZvwbepmvmpip/eOp
         o1tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zU7bJpkF3dtTNsVtIzlzeM9GMufFW67Vve8ee7ERgLg=;
        b=qTiwl4dy2DYq9SgHAMmSxq+V9TvjLhR954dwo22g5nF8nlBieH+uy8wP/lf9OdYmOi
         lff3TRpXoba6naTIX4f79b7PXyPfQrROyKvyCK83AcsRbvIy4sxAzL7Jc37Nz1sclDRj
         qDDRyDELmdREbLuiI665SQ7vq6pWMcutUfvMC/RHJ0+1ONzhgKZzNdwmeDQPNXRzJUKv
         E/5tKo8JHFuQEPV6Yp3z3XZG2tPcbvULlcF1cMC238DAk2QCwTEPgQgQKKwEosSznu55
         rytYsAyhIMUbtP7Ir+6asd7jNWUkY+HQT3LS7m/92DQNPcSA8C9rut5SGwaQFqdRNv+a
         KjYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wtr7O8JtIMoKnSlQNKHMgQoXLzeJl2FjMKLl6V+nGnBDtFZx6
	dAUKSAoTXS4SJCqkfQmWoM0=
X-Google-Smtp-Source: ABdhPJz6yEWDWSSTWEGhYQsAO+fO2Z8LrYjFrVbXj9PubZC/wGwIxdOgZJZDiJOFz02zjzuzrCuslA==
X-Received: by 2002:a63:e741:: with SMTP id j1mr10761125pgk.422.1600085741478;
        Mon, 14 Sep 2020 05:15:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d89:: with SMTP id v9ls4852167plo.4.gmail; Mon, 14
 Sep 2020 05:15:40 -0700 (PDT)
X-Received: by 2002:a17:902:7d95:b029:d1:c91f:5675 with SMTP id a21-20020a1709027d95b02900d1c91f5675mr4392762plm.34.1600085740828;
        Mon, 14 Sep 2020 05:15:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600085740; cv=none;
        d=google.com; s=arc-20160816;
        b=CMAhCpbgEU42YazWNVLQu3bXPVdkpKvZB1IVOMC1fioBSvqXWYrTQsS2KYfb4McXTR
         ZQKgYXkmqFUCoYwHh0pNdkBMqVFhOqnzIImzcaE0ca23JdQMpMy7Ku8Xis6W7Y4ZJ7PZ
         J0EhTCk1CCex9jWBOSiyQj7Sk6HjLSWPKhyzdqrr6ztU33BJzexdj9HSR1y5CV/TLzTU
         81zkBculie2O+U9aQv+lVGBc7+Uw2a6ykkUH8KXVsA5e0shI86XMjEUjRvM6MypExIKW
         2JcxwXfyKqrqa9c/s8cR2VnLMhSOXM4X7rXY4iv6mYqeLg9XMC1ci8Yy/hMMUSOXoHPw
         J2hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=wLQwOmzE85IiPBuLBFhPLxTybt1avGAt+HnhTR/viPw=;
        b=P4/g/KmnEu/d1p7aHSQemc+J2e9QaIvHTQ7NQZPxT8T+etJ0+9dY1EQVsJUJVdBsLP
         E2dl+z1h8AKS+mTBnZy3w0VtlRzJ5ORRtl2+ELkR3EfE5t0IIX2ZE/PrIeZuCjOLMmBG
         mQL5Hm733ZSzHiVega4PznKpESaxqOzads8Kfi8jLGYMW7pcaTzstTdJKzsmMlSbHeXZ
         eTL4ETtEp4T0G11FzvHhefKfCf89JGci6PnT1tT10KUV+f4IeeC96CjSwBClJ7dj9Z0N
         sa3QB+2IxnwAXjdCkOU0bvrHpWCSAasklnj57jfvqDiw9iTAtg4E+enbu7SPAggRLr0V
         nXHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id w15si572574pfu.6.2020.09.14.05.15.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 05:15:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1kHnOL-008gH1-8y; Mon, 14 Sep 2020 06:15:29 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:56556 helo=x220.xmission.com)
	by in02.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1kHnOK-00075s-47; Mon, 14 Sep 2020 06:15:29 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org,  christian@brauner.io,  linux-kernel@vger.kernel.org,  mingo@kernel.org,  peterz@infradead.org,  syzkaller-bugs@googlegroups.com,  tglx@linutronix.de,  Eric Sandeen <sandeen@sandeen.net>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <00000000000005f0b605af42ab4e@google.com>
Date: Mon, 14 Sep 2020 07:15:07 -0500
In-Reply-To: <00000000000005f0b605af42ab4e@google.com> (syzbot's message of
	"Mon, 14 Sep 2020 02:29:15 -0700")
Message-ID: <87zh5stv04.fsf@x220.int.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1kHnOK-00075s-47;;;mid=<87zh5stv04.fsf@x220.int.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18B+cBqqvytF6PuLq3hLPyIGnQyI2PO/dI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.2 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.3685]
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 749 ms - load_scoreonly_sql: 0.14 (0.0%),
	signal_user_changed: 14 (1.9%), b_tie_ro: 12 (1.6%), parse: 1.82
	(0.2%), extract_message_metadata: 27 (3.6%), get_uri_detail_list: 6
	(0.7%), tests_pri_-1000: 20 (2.7%), tests_pri_-950: 1.40 (0.2%),
	tests_pri_-900: 1.55 (0.2%), tests_pri_-90: 197 (26.3%), check_bayes:
	190 (25.4%), b_tokenize: 14 (1.8%), b_tok_get_all: 74 (9.9%),
	b_comp_prob: 3.6 (0.5%), b_tok_touch_all: 94 (12.5%), b_finish: 1.20
	(0.2%), tests_pri_0: 472 (63.1%), check_dkim_signature: 0.66 (0.1%),
	check_dkim_adsp: 2.4 (0.3%), poll_dns_idle: 0.50 (0.1%), tests_pri_10:
	2.2 (0.3%), tests_pri_500: 6 (0.8%), rewrite_mail: 0.00 (0.0%)
Subject: Re: KASAN: unknown-crash Read in do_exit
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com> writes:

> Hello,
>
> syzbot found the following issue on:

Skimming the code it appears this is a feature not a bug.

The stack_not_used code deliberately reads the unused/unitiailized
portion of the stack, to see if that part of the stack was used.

Perhaps someone wants to make this play nice with KASAN?

KASAN should be able to provide better information than reading the
stack to see if it is still zeroed out.

Eric

> HEAD commit:    729e3d09 Merge tag 'ceph-for-5.9-rc5' of git://github.com/..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=170a7cf1900000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=c61610091f4ca8c4
> dashboard link: https://syzkaller.appspot.com/bug?extid=d9ae84069cff753e94bf
> compiler:       gcc (GCC) 10.1.0-syz 20200507
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=10642545900000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=141f2bed900000
>
> Bisection is inconclusive: the issue happens on the oldest tested release.
>
> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17b9ffcd900000
> final oops:     https://syzkaller.appspot.com/x/report.txt?x=1479ffcd900000
> console output: https://syzkaller.appspot.com/x/log.txt?x=1079ffcd900000
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com
>
> ==================================================================
> BUG: KASAN: unknown-crash in stack_not_used include/linux/sched/task_stack.h:101 [inline]
> BUG: KASAN: unknown-crash in check_stack_usage kernel/exit.c:692 [inline]
> BUG: KASAN: unknown-crash in do_exit+0x24a6/0x29f0 kernel/exit.c:849
> Read of size 8 at addr ffffc9000cf30130 by task syz-executor624/10359
>
> CPU: 1 PID: 10359 Comm: syz-executor624 Not tainted 5.9.0-rc4-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> Call Trace:
>  __dump_stack lib/dump_stack.c:77 [inline]
>  dump_stack+0x198/0x1fd lib/dump_stack.c:118
>  print_address_description.constprop.0.cold+0x5/0x497 mm/kasan/report.c:383
>  __kasan_report mm/kasan/report.c:513 [inline]
>  kasan_report.cold+0x1f/0x37 mm/kasan/report.c:530
>  stack_not_used include/linux/sched/task_stack.h:101 [inline]
>  check_stack_usage kernel/exit.c:692 [inline]
>  do_exit+0x24a6/0x29f0 kernel/exit.c:849
>  do_group_exit+0x125/0x310 kernel/exit.c:903
>  get_signal+0x428/0x1f00 kernel/signal.c:2757
>  arch_do_signal+0x82/0x2520 arch/x86/kernel/signal.c:811
>  exit_to_user_mode_loop kernel/entry/common.c:159 [inline]
>  exit_to_user_mode_prepare+0x1ae/0x200 kernel/entry/common.c:190
>  syscall_exit_to_user_mode+0x7e/0x2e0 kernel/entry/common.c:265
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> RIP: 0033:0x446b99
> Code: Bad RIP value.
> RSP: 002b:00007f70f5ed9d18 EFLAGS: 00000246 ORIG_RAX: 0000000000000038
> RAX: 0000000000002878 RBX: 00000000006dbc58 RCX: 0000000000446b99
> RDX: 9999999999999999 RSI: 0000000000000000 RDI: 0000020002004ffc
> RBP: 00000000006dbc50 R08: ffffffffffffffff R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000246 R12: 00000000006dbc5c
> R13: 00007f70f5ed9d20 R14: 00007f70f5ed9d20 R15: 000000000000002d
>
>
> Memory state around the buggy address:
>  ffffc9000cf30000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  ffffc9000cf30080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>>ffffc9000cf30100: 00 00 00 00 00 00 70 07 00 00 77 00 00 00 00 00
>                                      ^
>  ffffc9000cf30180: 00 00 70 07 00 00 70 07 00 00 00 00 77 00 70 07
>  ffffc9000cf30200: 00 70 07 00 77 00 00 00 00 00 70 07 00 00 00 00
> ==================================================================
>
>
> ---
> This report is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this issue. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> For information about bisection process see: https://goo.gl/tpsmEJ#bisection
> syzbot can test patches for this issue, for details see:
> https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zh5stv04.fsf%40x220.int.ebiederm.org.
