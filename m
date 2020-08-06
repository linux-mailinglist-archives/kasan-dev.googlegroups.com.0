Return-Path: <kasan-dev+bncBAABBE66WH4QKGQES6LZWLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F81B23E357
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 22:59:00 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id h10sf19781qtc.4
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 13:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596747539; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqfyUBcTZBGyTLHWdzx4Qv2A+P9yeaVRQCoiYDpHDJDFaWtD2TUglo08+eGTOgsocO
         rUQdNF8xTE0q/NfwjV8q8eXqnlrqFQnZubNEanPdQKeOfuVQac5ZxtRMg53wqKiMeRtI
         JSoUI4Ktbaks+VopWVnSX+W/P0pY7lU6nuqwbuZwPOVk4Csp6dbZyImtxGp5u7ViiZRJ
         B8klfFDP4L6da3AkXvy5IClhTOyF3hMo0ZWLFVEMbjFlysuJxvw05PML0um/04i91DWB
         Rq5OEVQkcF/rzX1GkdxkcEojwNw5Z2tRNcLJz+blXGQD5Rq7AQvDQmt3Pxf6H/qaAmph
         MgYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=77e2q7l17AphsXuJS7vOHayOzJOJsceTrFh0OlNIQeQ=;
        b=0PmFHmEoeDmH4qpJsTCesXrCSq2TxbmDeO+JM8EAR6+aHkkew20YHASSG1W5UTZoBj
         gcv2KpdDo1vt1677dhqHSK6nq4jUvL1Pb+zbHWSJbN5sztuxOlTYwe9N/fjkzM1EEPer
         kS3Frif3YEAoK3Z2gdxfKiaHmQTXwtmLt1jw+gTXKmSUV1YIk1+F72DXade2i3ccXTt8
         K7cihQNT0mZP0+rHWzBOhO0XUj7CR6FeLgywiqeOtaKav4H1wnB5A6iJxDjamniztpk+
         MDrMlFV539pYAuEdJidMVOUqNkfkQmpLAKIB/gKEUhPjgBLduLdGlMgvBP3K9x7yZesj
         KHgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EDy+qKRo;
       spf=pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=77e2q7l17AphsXuJS7vOHayOzJOJsceTrFh0OlNIQeQ=;
        b=Lc+uHUOJWZlXoo6uASt8TMH3rHnl6xhbHHXNKRYx/NumgEXwMV0YG1qTojvBCOt4xS
         7OWDEE4392bbsD7IFOlxEED9+pcWzeXph2HHiRd8VODpEBES/d79SjhI+UygN9hx8vxL
         ML8R9gnX6C3YTUUUzCcPUxyWTAdqtYY3nYU/d1eiszDlAswLTIBMMgYJP8M3QMgoW+10
         fx1DvMCNpraoB8NHEYU0qzNah0LdUHGfNfSZTyv9/GJm3XbQyVS3+sV1MDLhGkMWR2kY
         YH5GcyXceHRzIqTyQgREPSiqBLKokokYvGZRnZzPR65CnC+O5fw7mr+1zNycchIECAae
         w9/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=77e2q7l17AphsXuJS7vOHayOzJOJsceTrFh0OlNIQeQ=;
        b=p890XvANiRwBBE6rWZHP8DhucsiDlvHsbS6TQ60dS+5ObR74WdiyaDWNm0Hfjbg/7i
         5Jin6vKEDHmVjTFl8IOdlPcHaJa/Gd2Ms5Dcw31M369tUawLt4Fd6tgUcBcohkdD7q/l
         umsqzkO5EBFIN9GiXxISVzo8VC4D7JTPlW9Ev0HOKX+c4HZ5BJo1DHUt8mtbWtazLqsl
         6JFIe0H5vavVyF91YtTMGaUGt/mpDBzjNvUixCGGHVlALHkm49oZj1m+3lifoDnhgvlL
         L/6G86PXXUHWu0JHG2UcNEoj65hbdoaMKQE3BcM8iPmjAZ/kkuys5sdagn/afa9a2nh+
         PSKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bqcwaw+5C2gPthF7M9n6++3hz6IbyKCFhs60xPKRbBCLwg+5N
	c2aNCSQqmt1PSij7GWw8ABw=
X-Google-Smtp-Source: ABdhPJx8JxGCXIAv8eFnchRT4fxzBaakq5uGZEqEtIB+UIRkAalmkSOp8YPO+2rWBU23ZW82+3QwoA==
X-Received: by 2002:ac8:4519:: with SMTP id q25mr11054113qtn.29.1596747539274;
        Thu, 06 Aug 2020 13:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fd27:: with SMTP id i7ls1814515qvs.3.gmail; Thu, 06 Aug
 2020 13:58:59 -0700 (PDT)
X-Received: by 2002:a0c:c1cf:: with SMTP id v15mr10755006qvh.192.1596747538984;
        Thu, 06 Aug 2020 13:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596747538; cv=none;
        d=google.com; s=arc-20160816;
        b=GFAgipQ400ISI1irUkvyLoGkHNA++b3vRjJ/oqBD5E8xrXhgT9Isbj0wkxRoc96Dpq
         X1Z0HOwIpX1lT4jLL3WAVkZLd2ZBH74i++5pKhEPvbtosVIe2A2vDXzYNx5bX+PQkg8u
         fpZmrqfAsmsAFKAZrgP4pUQWPG22oAo0OOqtN1+4tc0NjgdPTfH8JOpfUq0JV9LEP2h/
         L65stuxTT6jj+9aQ/hC2dnrtdZ586U+8qwHGY/XJIBQK+crxpkHZFiKhSnionUTAhtFJ
         hWjFANCdlxKWe5xGisrtFMf+enLdKOalrwFiZZ+ukp2EITQK+eeFE3uajcJUJHxLpbX7
         MlVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=mlp0o+ruv2rIPY195pG6X1dFUIRtDICCg11ITjkMUs4=;
        b=fa9dZE+uGvNccnLg7RXOBm5/e8NGMXNl36f1cHCCQ1LaVz8dte4WaYdE0f9mrhfmU5
         nQevQR27DZgApXbVUDUK5bRRxpk4M5p02X/1aog16Iedp5clVIcyhhc86twmBcQ/AMwX
         BZOi3mzzi6Kf/QM/5lk2500IwXLyT31huZz+m04fUzilwiKY6sA0k2tDlGVVSZ8vTThI
         MB1wY3y4Z7A7k7QdSU2l1++nW5Z2MYqCeclTxz8vcpGnCxmEKL45dHs3TsiYFkaV7j0o
         7iHPzeCTdo0QvKCwXKwtLLsmgvxb1gMTuDvoieHGMctronyhjx/UM9/uScJBk4PuR1N4
         NkvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EDy+qKRo;
       spf=pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e16si264097qto.5.2020.08.06.13.58.58
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Aug 2020 13:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02ADA221E2;
	Thu,  6 Aug 2020 20:58:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id BAD2F3520734; Thu,  6 Aug 2020 13:58:57 -0700 (PDT)
Date: Thu, 6 Aug 2020 13:58:57 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Kostya Serebryany <kcc@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	'Dmitry Vyukov' via syzkaller-upstream-moderation <syzkaller-upstream-moderation@googlegroups.com>,
	Jann Horn <jannh@google.com>
Subject: Re: Finally starting on short RCU grace periods, but...
Message-ID: <20200806205857.GA29087@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200805230852.GA28727@paulmck-ThinkPad-P72>
 <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
 <CACT4Y+Ye7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ@mail.gmail.com>
 <CACT4Y+aF=Y-b7Lm7+UAD7Zb1kS1uWF+G_3yBbXsY6YO3k2dBuw@mail.gmail.com>
 <20200806133557.GM4295@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200806133557.GM4295@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=EDy+qKRo;       spf=pass
 (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Aug 06, 2020 at 06:35:57AM -0700, Paul E. McKenney wrote:
> On Thu, Aug 06, 2020 at 03:25:57PM +0200, Dmitry Vyukov wrote:
> > On Thu, Aug 6, 2020 at 3:22 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Aug 6, 2020 at 12:31 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > +Cc kasan-dev
> 
> Thank you!
> 
> > > > On Thu, 6 Aug 2020 at 01:08, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > Hello!
> > > > >
> > > > > If I remember correctly, one of you asked for a way to shorten RCU
> > > > > grace periods so that KASAN would have a better chance of detecting bugs
> > > > > such as pointers being leaked out of RCU read-side critical sections.
> > > > > I am finally starting entering and testing code for this, but realized
> > > > > that I had forgotten a couple of things:
> > > > >
> > > > > 1.      I don't remember exactly who asked, but I suspect that it was
> > > > >         Kostya.  I am using his Reported-by as a placeholder for the
> > > > >         moment, but please let me know if this should be adjusted.
> > > >
> > > > It certainly was not me.
> > > >
> > > > > 2.      Although this work is necessary to detect situtions where
> > > > >         call_rcu() is used to initiate a grace period, there already
> > > > >         exists a way to make short grace periods that are initiated by
> > > > >         synchronize_rcu(), namely, the rcupdate.rcu_expedited kernel
> > > > >         boot parameter.  This will cause all calls to synchronize_rcu()
> > > > >         to act like synchronize_rcu_expedited(), resulting in about 2-3
> > > > >         orders of magnitude reduction in grace-period latency on small
> > > > >         systems (say 16 CPUs).
> > > > >
> > > > > In addition, I plan to make a few other adjustments that will
> > > > > increase the probability of KASAN spotting a pointer leak even in the
> > > > > rcupdate.rcu_expedited case.
> > > >
> > > > Thank you, that'll be useful I think.
> > > >
> > > > > But if you would like to start this sort of testing on current mainline,
> > > > > rcupdate.rcu_expedited is your friend!
> > >
> > > Hi Paul,
> > >
> > > This is great!
> > >
> > > I understand it's not a sufficiently challenging way of tracking
> > > things, but it's simply here ;)
> > > https://bugzilla.kernel.org/show_bug.cgi?id=208299
> > > (now we also know who asked for this, +Jann)
> 
> Thank you, and I will update the Reported-by lines accordingly.
> 
> > > I've tested on the latest mainline and with rcupdate.rcu_expedited=1
> > > it boots to ssh successfully and I see:
> > > [    0.369258][    T0] All grace periods are expedited (rcu_expedited).
> > >
> > > I have created https://github.com/google/syzkaller/pull/2021 to enable
> > > it on syzbot.
> > > On syzbot we generally use only 2-4 CPUs per VM, so it should be even better.
> 
> Sounds good, and perhaps this will answer Marco's question below.  ;-)
> 
> > > > Do any of you remember some bugs we missed due to this? Can we find
> > > > them if we add this option?
> > >
> > > The problem is that it's hard to remember bugs that were not caught :)
> > > Here is an approximation of UAFs with free in rcu callback:
> > > https://groups.google.com/forum/#!searchin/syzkaller-bugs/KASAN$20use-after-free$20rcu_do_batch%7Csort:date
> > > The ones with low hit count are the ones that we almost did not catch.
> > > That's the best estimation I can think of. Also potentially we can get
> > > reproducers for such bugs without reproducers.
> > > Maybe we will be able to correlate some bugs/reproducers that appear
> > > soon with this change.
> > 
> > Wait, it was added in 2012?
> > https://github.com/torvalds/linux/commit/3705b88db0d7cc4
> 
> Indeed it was, which is my current excuse for having failed to immediately
> mention it to Jann during our IRC discussion.
> 
> The purpose back then was to make battery-powered systems go faster,
> I think mostly focused on CPU hotplug operations.  At least that would
> explain the commit log being indefinite on the exact benefit.  ;-)

And don't look now, but my current intermediate state seems to make the
following splat happen semi-reliably from within rcutorture when running
scenario TREE01 with "--kconfig "CONFIG_RCU_STRICT_GRACE_PERIOD=y".
The current changes cause this scenario to process more than double the
number of RCU grace periods per unit time, so who knows?

I am not reporting this one yet because it is of course quite possible
that it is due to my changes being messed up.

							Thanx, Paul

------------------------------------------------------------------------

[   99.769536] ------------[ cut here ]------------
[   99.770052] WARNING: CPU: 5 PID: 36 at kernel/irq_work.c:95 irq_work_queue_on+0x73/0x90
[   99.770905] Modules linked in:
[   99.771239] CPU: 5 PID: 36 Comm: migration/5 Not tainted 5.8.0-rc3+ #2153
[   99.771964] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.10.2-1ubuntu1 04/01/2014
[   99.772898] RIP: 0010:irq_work_queue_on+0x73/0x90
[   99.773405] Code: 89 ee 89 df e8 fe 4a fa ff bf 01 00 00 00 e8 24 32 f3 ff 65 8b 05 6d 48 6b 59 85 c0 ba 01 00 00 00 75 b6 e8 16 f9 e9 ff eb af <0f> 0b eb 9d 48 89 ef e8 b1 fe ff ff eb d1 0f 0b eb c3 90 66 2e 0f
[   99.775384] RSP: 0018:ffffae4200197d58 EFLAGS: 00010002
[   99.775944] RAX: 0000000000000005 RBX: 0000000000000005 RCX: 0000000000000001
[   99.776708] RDX: 0000000000000000 RSI: 0000000000000005 RDI: ffff96fe9f36a270
[   99.777466] RBP: ffff96fe9f36a270 R08: 00000019b750dcec R09: 0000000000000000
[   99.778224] R10: 0000000000000008 R11: ffffffffa7c550a8 R12: 0000000000000046
[   99.778981] R13: 0000000000000000 R14: 0000000000000000 R15: ffff96fe9ee51580
[   99.779740] FS:  0000000000000000(0000) GS:ffff96fe9f340000(0000) knlGS:0000000000000000
[   99.780694] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   99.781318] CR2: 00000000ffffffff CR3: 000000000fe0a000 CR4: 00000000000006e0
[   99.782076] Call Trace:
[   99.782356]  __rcu_read_unlock+0x118/0x140
[   99.782802]  sched_cpu_dying+0x157/0x230
[   99.783228]  ? sched_cpu_starting+0x30/0x30
[   99.783678]  cpuhp_invoke_callback+0x81/0x610
[   99.784159]  ? cpu_disable_common+0x28f/0x2b0
[   99.784630]  take_cpu_down+0x62/0xa0
[   99.785018]  multi_cpu_stop+0x5f/0xe0
[   99.785417]  ? stop_machine_yield+0x10/0x10
[   99.785869]  cpu_stopper_thread+0x80/0x100
[   99.786310]  ? sort_range+0x20/0x20
[   99.786689]  smpboot_thread_fn+0x199/0x230
[   99.787131]  kthread+0x139/0x160
[   99.787484]  ? kthread_park+0x80/0x80
[   99.787881]  ret_from_fork+0x22/0x30
[   99.788278] ---[ end trace 0b90671b542e1746 ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200806205857.GA29087%40paulmck-ThinkPad-P72.
