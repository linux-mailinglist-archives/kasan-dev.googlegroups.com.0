Return-Path: <kasan-dev+bncBCALX3WVYQORB66M7X5AKGQEG6ITW4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BE1C268B65
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:47:57 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id p6sf8652917ooo.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600087675; cv=pass;
        d=google.com; s=arc-20160816;
        b=HcsobT1tnngZqrwwW/4rSw/eRzhW2VOXheF0Syrbpk8V8I6ZNOtrOxRjJNDiZnTan+
         u9oyy+gphtjrXwAzIflv2r/kruDv4RZoHeUTbf8AhsE3nMD/XzDDUJkYdQWTfYKF+oiY
         5NVu0nQxsc1qt3iHGtGdi0W5oZHDSvHHernO8gFbTozXy9oDGU4eXhhJpm5knCsj2/gu
         GrAnXq7po/z9HETKj1OtUOPlsclQ4xDhMsRtuRtPMms12we7pV7Oz/Wu1rHmnTIkFe5t
         TcqY5Zwd0EZNkGxyMw8XEuhIw+rH10oaDPWc3puoaiN1U0qBkD0lQpjI4Y845LrCVDHt
         7AdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=4ykzStL0bVAmurieZYK8/iU/3v2f5kMrMqwzn9g09yA=;
        b=d9JqGsek1pY3dD4T3UkYq6Y3GtDufO2FzZ6aa4CXgCykvDKenw6dppD+EMF0mvF6H4
         OZn9tmvseYFB3W9WJ6Kz3Pw47lbC9N5yRkCi/d1BgA3EtZZnmq7PA7Tpaj1Y8Kkt3MQN
         uY+SEd+TzavYSHn57t11jzLX6Pa0piMLbvp6sLvD07ahHezti+htbN7D3TsVEnoztr+f
         vmMe44Jo9OetBti66V40J/dbvZAsDoKjxFm1LLSkrduRd9G46mZr2Un3OaRXJ1A2yML4
         DHAAcvIkaCFqswKIeePwEGOHxUNp2nB20tihN5QqEoUp+WZyaSinNbm1y0pBlnxWXuKZ
         PHFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4ykzStL0bVAmurieZYK8/iU/3v2f5kMrMqwzn9g09yA=;
        b=j6zJVqHTETQUBPSWErV+KR0dNgxu/bGBjxF+A89HzhbHuoqYV78yQs1D5tyTfZcr4t
         cEWUdY5sMYXb8b8GmS/gdSi8TMeUdeyZL18/4Oy5O0SZPzn1u9mJdlVg1yg6aTeYTyQG
         wfb2h1+bTEOekd2eU01SgQbKM7mlibaKLpvMmnZjQY6kYZoWScD9d70/uP0xeLZnkPEZ
         SNc6ilFBYgs6lc842xj2OxYYvH3md8+DguwNmO8Hm7iFQs3y6kKYlv3yB3evLLb5Yw/4
         tPDRnW/JoSS2CN50UtyK/29cPFgoB/o5syIHq/ZLlXocx+MUd51qLeMgmPJz6IpD1Oys
         +2Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ykzStL0bVAmurieZYK8/iU/3v2f5kMrMqwzn9g09yA=;
        b=f3M9zLTxXht1Qu/YULc1uFqsLnLkB8Zo25LTq/8WoMG8HrzDnf9fbQ4yiTtfcmf5c7
         WwldmiEZ9EOK5YEy98BA2Xm/pLbtMQyjvJ7Upc2alfmRppcMX+PXhXMWcux4xd8auvLp
         psOG/jvyz5VyVdjZNqGFkT0yIsSHIIHPBLeQKJ1ytKo558YprqjGeLGcPNlllpQ/Yyey
         6su/M/7LTz25V4PWDzp458WHvJa+fQw4CWanFHvM7mdtDgjgzLdO1WCYpP0KxmD8V592
         l0+SZOegwQKBTdBmhP6cTVxzyRnBKbN2OPbLboL1sh3DZT/9jOOjZCfHTHHeQhjiRWYz
         jbxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vO8qbgp5nMEaNTtJjUNom/jJX/Fs9azuNBWxaDH1fgidOM2mH
	eXgwwhgPFRWaWWalV4p4rb4=
X-Google-Smtp-Source: ABdhPJyOLOVwwUoP0yPJFuiRnLT4tIx1ks1ChfEqLsFuMd7k1gs6gCbl8iAMBVaUzRFPHrif/XznHQ==
X-Received: by 2002:a05:6830:1d1:: with SMTP id r17mr9480663ota.311.1600087675504;
        Mon, 14 Sep 2020 05:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4d2:: with SMTP id s18ls1983928otd.0.gmail; Mon, 14
 Sep 2020 05:47:55 -0700 (PDT)
X-Received: by 2002:a9d:65c8:: with SMTP id z8mr8959896oth.5.1600087675046;
        Mon, 14 Sep 2020 05:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600087675; cv=none;
        d=google.com; s=arc-20160816;
        b=ldtrVkee3OrCH+M8GVLp9v69jULSmfODKzqmCgVPsXUkM17jDHXB6Esy7tXnpM5evG
         m1WwOQX7pmgquT6VdXjxTMKCuh+wdjBq1hObhXpG+zuH80I/n6CtPgw5Dc+Ftn1MdeHf
         2TvMM7jFdz1FkLGvX9QokiYD/pjhqlA0A7FaF8oXxtmE72GICRbA1i78RIrUFyzaELns
         AEpvP7IcB/HkTq4Z8dfa99lWOa/+VGFg7jgB5QfaPYaAFNgzSjCEAMnzdSJz1Bre/X1r
         lAOhGghkfw7wp755Uj52CNLgVNRnl2U/WXNT5EKrRpteCb7PVxEwN3kEVeFDX4gDZ0iH
         UYSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=Z20YkbdU3tZLOy0vv7fIkkuQc2taLYZHhNDQUINED+M=;
        b=ucV6wolbhro6Kt22jSZO5GS8GZt/JFI2nlVyl2HRXR7Cu03F1k8r9QZ7gCdMg/bWMh
         qcS0AaRxEM1BAvH+A8lnKoMvPor81FpSj33ypdny+Y/xzwE7+SqElbfYejdIYka27PUf
         s9/b8HzkdS9t7v5Z731+aMVNJMYb9bKdSv5WntEVtbwtI+/JsUiSLGUuKib68kCOV27E
         /uzS1syh2K2+CCi3iUJmyEcQQ/lc35hcHFRgD/GhpNp7na0+9j/7tMJU9o7NLWPAZbUC
         cy+00JDmjIeU+TAxuk/seFFusi3mniRLu2/r+gIcsy4CPzuWVzGHmk6d5rRQb/aBXnz7
         Rxxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id m3si871187otk.4.2020.09.14.05.47.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 05:47:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out03.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1kHntg-00ABqm-0Z; Mon, 14 Sep 2020 06:47:52 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=x220.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1kHnte-0002Hj-Mj; Mon, 14 Sep 2020 06:47:51 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>,  Andrew Morton <akpm@linux-foundation.org>,  Christian Brauner <christian@brauner.io>,  LKML <linux-kernel@vger.kernel.org>,  Ingo Molnar <mingo@kernel.org>,  Peter Zijlstra <peterz@infradead.org>,  syzkaller-bugs <syzkaller-bugs@googlegroups.com>,  Thomas Gleixner <tglx@linutronix.de>,  Eric Sandeen <sandeen@sandeen.net>,  Andrey Ryabinin <aryabinin@virtuozzo.com>,  Alexander Potapenko <glider@google.com>,  kasan-dev <kasan-dev@googlegroups.com>
References: <00000000000005f0b605af42ab4e@google.com>
	<87zh5stv04.fsf@x220.int.ebiederm.org>
	<CACT4Y+ZcrHFS45-NFxZKWdoesCdLwk-_1YvMJr01FRL1sG-ZeQ@mail.gmail.com>
Date: Mon, 14 Sep 2020 07:47:30 -0500
In-Reply-To: <CACT4Y+ZcrHFS45-NFxZKWdoesCdLwk-_1YvMJr01FRL1sG-ZeQ@mail.gmail.com>
	(Dmitry Vyukov's message of "Mon, 14 Sep 2020 14:23:01 +0200")
Message-ID: <87imcgtti5.fsf@x220.int.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1kHnte-0002Hj-Mj;;;mid=<87imcgtti5.fsf@x220.int.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19LXviMypYNBasGVGCTSKwCdfsubmY84mc=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa05.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.2 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,
	XM_B_SpammyWords,XM_B_SpammyWords2 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.3594]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa05 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.8 XM_B_SpammyWords2 Two or more commony used spammy words
	*  0.2 XM_B_SpammyWords One or more commonly used spammy words
X-Spam-DCC: XMission; sa05 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Dmitry Vyukov <dvyukov@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 979 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 12 (1.2%), b_tie_ro: 10 (1.1%), parse: 1.46
	(0.1%), extract_message_metadata: 35 (3.6%), get_uri_detail_list: 9
	(0.9%), tests_pri_-1000: 30 (3.1%), tests_pri_-950: 1.38 (0.1%),
	tests_pri_-900: 1.08 (0.1%), tests_pri_-90: 231 (23.6%), check_bayes:
	218 (22.3%), b_tokenize: 25 (2.6%), b_tok_get_all: 14 (1.4%),
	b_comp_prob: 5 (0.5%), b_tok_touch_all: 168 (17.2%), b_finish: 2.7
	(0.3%), tests_pri_0: 648 (66.2%), check_dkim_signature: 1.07 (0.1%),
	check_dkim_adsp: 2.4 (0.2%), poll_dns_idle: 0.58 (0.1%), tests_pri_10:
	2.2 (0.2%), tests_pri_500: 12 (1.3%), rewrite_mail: 0.00 (0.0%)
Subject: Re: KASAN: unknown-crash Read in do_exit
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
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

Dmitry Vyukov <dvyukov@google.com> writes:

> On Mon, Sep 14, 2020 at 2:15 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com> writes:
>>
>> > Hello,
>> >
>> > syzbot found the following issue on:
>>
>> Skimming the code it appears this is a feature not a bug.
>>
>> The stack_not_used code deliberately reads the unused/unitiailized
>> portion of the stack, to see if that part of the stack was used.
>>
>> Perhaps someone wants to make this play nice with KASAN?
>>
>> KASAN should be able to provide better information than reading the
>> stack to see if it is still zeroed out.
>>
>> Eric
>
> Hi Eric,
>
> Thanks for looking into this.
>
> There may be something else in play here. Unused parts of the stack
> are supposed to have zero shadow. The stack instrumentation code
> assumes that. If there is some garbage left in the shadow (like these
> "70 07 00 00 77" in this case), then it will lead to very obscure
> false positives later (e.g. some out-of-bounds on stack which can't be
> explained easily).
> If some code does something like "jongjmp", then we should clear the
> stack at the point of longjmp. I think we did something similar for
> something called jprobles, but jprobes were removed at some point.
>
> Oh, wait, the reproducer uses /dev/fb. And as far as I understand
> /dev/fd smashes kernel memory left and right. So most likely it's some
> wild out of bounds write in /dev/fb.

So I am confused.  The output in the console does not match the log
below.  Further the memory addresses in the report don't make a bit
of sense.  Incrementing by 0x80 and only printing 16 bytes which is 0x10.

I am simply responding to the fact that KASAN is complaining about an
out of bounds/uniitialized access in stack_not_used.

Which seems a legitimate thing to do, but that seems to indicate
two debugging primitives are fighting each other.

So why we have several very different traces I don't understand.
Unless you are right and something is causing corruption.

At which point this needs to be delivered to whomever can dig into this.


Eric

>> > HEAD commit:    729e3d09 Merge tag 'ceph-for-5.9-rc5' of git://github.com/..
>> > git tree:       upstream
>> > console output: https://syzkaller.appspot.com/x/log.txt?x=170a7cf1900000
>> > kernel config:  https://syzkaller.appspot.com/x/.config?x=c61610091f4ca8c4
>> > dashboard link: https://syzkaller.appspot.com/bug?extid=d9ae84069cff753e94bf
>> > compiler:       gcc (GCC) 10.1.0-syz 20200507
>> > syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=10642545900000
>> > C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=141f2bed900000
>> >
>> > Bisection is inconclusive: the issue happens on the oldest tested release.
>> >
>> > bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17b9ffcd900000
>> > final oops:     https://syzkaller.appspot.com/x/report.txt?x=1479ffcd900000
>> > console output: https://syzkaller.appspot.com/x/log.txt?x=1079ffcd900000
>> >
>> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
>> > Reported-by: syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com
>> >
>> > ==================================================================
>> > BUG: KASAN: unknown-crash in stack_not_used include/linux/sched/task_stack.h:101 [inline]
>> > BUG: KASAN: unknown-crash in check_stack_usage kernel/exit.c:692 [inline]
>> > BUG: KASAN: unknown-crash in do_exit+0x24a6/0x29f0 kernel/exit.c:849
>> > Read of size 8 at addr ffffc9000cf30130 by task syz-executor624/10359
>> >
>> > CPU: 1 PID: 10359 Comm: syz-executor624 Not tainted 5.9.0-rc4-syzkaller #0
>> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
>> > Call Trace:
>> >  __dump_stack lib/dump_stack.c:77 [inline]
>> >  dump_stack+0x198/0x1fd lib/dump_stack.c:118
>> >  print_address_description.constprop.0.cold+0x5/0x497 mm/kasan/report.c:383
>> >  __kasan_report mm/kasan/report.c:513 [inline]
>> >  kasan_report.cold+0x1f/0x37 mm/kasan/report.c:530
>> >  stack_not_used include/linux/sched/task_stack.h:101 [inline]
>> >  check_stack_usage kernel/exit.c:692 [inline]
>> >  do_exit+0x24a6/0x29f0 kernel/exit.c:849
>> >  do_group_exit+0x125/0x310 kernel/exit.c:903
>> >  get_signal+0x428/0x1f00 kernel/signal.c:2757
>> >  arch_do_signal+0x82/0x2520 arch/x86/kernel/signal.c:811
>> >  exit_to_user_mode_loop kernel/entry/common.c:159 [inline]
>> >  exit_to_user_mode_prepare+0x1ae/0x200 kernel/entry/common.c:190
>> >  syscall_exit_to_user_mode+0x7e/0x2e0 kernel/entry/common.c:265
>> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> > RIP: 0033:0x446b99
>> > Code: Bad RIP value.
>> > RSP: 002b:00007f70f5ed9d18 EFLAGS: 00000246 ORIG_RAX: 0000000000000038
>> > RAX: 0000000000002878 RBX: 00000000006dbc58 RCX: 0000000000446b99
>> > RDX: 9999999999999999 RSI: 0000000000000000 RDI: 0000020002004ffc
>> > RBP: 00000000006dbc50 R08: ffffffffffffffff R09: 0000000000000000
>> > R10: 0000000000000000 R11: 0000000000000246 R12: 00000000006dbc5c
>> > R13: 00007f70f5ed9d20 R14: 00007f70f5ed9d20 R15: 000000000000002d
>> >
>> >
>> > Memory state around the buggy address:
>> >  ffffc9000cf30000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> >  ffffc9000cf30080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> >>ffffc9000cf30100: 00 00 00 00 00 00 70 07 00 00 77 00 00 00 00 00
>> >                                      ^
>> >  ffffc9000cf30180: 00 00 70 07 00 00 70 07 00 00 00 00 77 00 70 07
>> >  ffffc9000cf30200: 00 70 07 00 77 00 00 00 00 00 70 07 00 00 00 00
>> > ==================================================================
>> >
>> >
>> > ---
>> > This report is generated by a bot. It may contain errors.
>> > See https://goo.gl/tpsmEJ for more information about syzbot.
>> > syzbot engineers can be reached at syzkaller@googlegroups.com.
>> >
>> > syzbot will keep track of this issue. See:
>> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>> > For information about bisection process see: https://goo.gl/tpsmEJ#bisection
>> > syzbot can test patches for this issue, for details see:
>> > https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87imcgtti5.fsf%40x220.int.ebiederm.org.
