Return-Path: <kasan-dev+bncBCALX3WVYQORB2GKWGCAMGQEGFRY6CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7425B3701EB
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 22:15:37 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id x186-20020a25e0c30000b02904f0d007a955sf9889045ybg.12
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 13:15:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619813736; cv=pass;
        d=google.com; s=arc-20160816;
        b=Moo6u3KDjUUHkS3DuqbG93nppWiGwUdtFvjFx418Wvl52lzmdgK9G++j2WmTS/R5Zv
         H3iDGzztCnkEUCo8YMQ1bp8yEbCc86Cl53GYFG6ViiMrCI4Qgs+BpmDURAAdf/Gh9mEY
         EEXwr3VwBzFQstqjhBCEng3GckPQ6bKY1PQrUeS5ct+Su0h++6PSnGIQtF1unSK8t02Y
         Mc3vsQ2N0+UHIxCfn8T56PjPA5IjBVDBbYYqq46OW/G2n/ru+FZHO8WTuA+PTKg4YRv5
         GOVD5fnHroR2T6qRNmHWVQuJ7wrYweBAfN+HPuZYX5mA2PaGs6kBa0i/Sr+RNyv5f3/s
         aevw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=EQ+Jfp+P7Ms9l8xvMChHs3/Qf3QmvdG1rg0eaVTjC9c=;
        b=mwp+1bcGsn3onFcCHMmKyvlCo+o+C6mFE5cMwBsWN8ORmrtlJpPYbSQXVykaUm6oBZ
         VzWJo1cFa2CDM1OzgdQRJYHFt/y0A1pr654h4QBaFbIF0vmg6z2cCArwRp4ABLSim3mw
         OjnUfWYfUalc6BQg2kEGlrqgct77vYl0UlwKyNvtlo3M2gTPYV0II+zCCcy+ZD17HT/b
         Vv4h+oEKcJ8O6HtCMdsueTsPFN6VXZ+IcgmEdjoQ3wkRcKIfZ7fo3LnvmB8cDEYNrjdw
         V9K8g+1pfIBy6ccByy35ICM8RjKVF+THsQ18HHQ4bzQ1witY6Iwqz9MDNPLtUwoXP0Fn
         XRfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EQ+Jfp+P7Ms9l8xvMChHs3/Qf3QmvdG1rg0eaVTjC9c=;
        b=r/98CbDI+Ql+oE1/q8j+E7927SiRgr4eoL714FOlDr29Rv/0hqqbjrp4qAirLk8kx0
         rEktRZ8KVY4wtjz1tpu3o8qRSwr/LZEPuxMyGR7nMG9ZNxjXPV2NKXv04EmQFLFcwL+9
         BB5KQRcN5l+SHqEuCOrAYx+VM0E26nsWUhg/kJSc7Z00RccD6OLDdwh0eKVuyvWcycSA
         76ZzXVenvkqb6stjPQ0fIUFhH5ck5dZqP+7oo7XnKIjiop8Ww709UOnZne5v2cIQ+1g5
         cxtf0TqSPSqRTPFI9O6xq8YSZM6XjT04df1WjK4jKrV/j+jvIVYEvnrazlDLA146t+k5
         EgSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQ+Jfp+P7Ms9l8xvMChHs3/Qf3QmvdG1rg0eaVTjC9c=;
        b=cO69pDnypDGYsGW/yUkyE+Z5r2rJBdYVikg7ouVqLBQ+AW9WD3oRKQd/MUzJVbjfor
         YVYCHLiF7xrMVEyaXF1aZEZt/6LJbFZbxxjT1+K2illgdgpCTav0y+VeFWCwyYD/1FeD
         a6ixqFF8SJGwewjRAkMg/d23LrK2H1U5Fvr/yNToGZDyq+Wv4ND3Lv35gCM20waN/qrv
         UIOzFs7ndsLpyNnH02sQ+6iQkKPLBYLzqrhGN0rFvYBzeK0CU/xzgTbLpzqB6msAc+Ac
         z4ANJRBEN13AsyPvT0s2CWjCL7NfD/6uYa/1J9/8Cn9oqzn5coPbt5rqt6Zhq/sKdH1l
         zWvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Q0RVi5a0dUrBaVHRwlfRKUUUE/fXBCilkFyasyqIedqKlYUre
	Ft+SO0IxlP4NEyXBlp3fxVc=
X-Google-Smtp-Source: ABdhPJwCft9QGWHPvSXm/YohQZsgul+dpzoj2XLfxWOEjnU1wSIc8h4iujKEQPKpulZ/eIfniSrpRA==
X-Received: by 2002:a25:b34c:: with SMTP id k12mr4728485ybg.6.1619813736349;
        Fri, 30 Apr 2021 13:15:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:643:: with SMTP id o3ls1150920ybq.7.gmail; Fri, 30 Apr
 2021 13:15:35 -0700 (PDT)
X-Received: by 2002:a25:f504:: with SMTP id a4mr9433958ybe.503.1619813735834;
        Fri, 30 Apr 2021 13:15:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619813735; cv=none;
        d=google.com; s=arc-20160816;
        b=HqJujbvQCO7iUV7pBQkMHKjKE5f+OMRwMdVPR1yUgwddWJjSxvfxEIyLeTgQhQ6RDb
         qJo/VR6JRnmH/xCgLqg4ik8Fz8H4uGP5fJRr3vlVEUKoX/MVAfHrTnFtRyUJHqEsiLoE
         Bz5nMHKW05G9QGqwf7Rp2WONIZPbQ4+tGEYQeXK7zqG/RCOOPGkQoMuC3lJD7+mryVhC
         tR1oVMoIRkzL83Zl21r/FMF7DB4oxs47wFfYNQL2ZtFaBKXP3ib1uKAWwhiFMSfpDYHV
         uCpZXsiGYLYeEZLNHiBAFd9m8tTNwBGHGn4gFt1nWzyEQNf4QxEs2zUJADqlLRFozmFq
         K8tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=4sk3dQxGT1syJwtSMpXC/062H0IUqu/Ss/tgBRlWEnM=;
        b=UAm5+zEah7BHz8aZ40WyMygIuiMhvtHKFaj4gSWVnpKPCxto6AwGY7L6iEZYNlUEBR
         VBdKgxn35gAjEO+ZlCvS/yRBiYGi/Bx0ziVTCXKtbqI+8BrU1auNpfDZH0eNiEb5bha9
         p5SIpv8VVhALBDJu21AZPlUHT0nX+rJIUWATzrpcA1E4+Mzic2O1ps1WFAZfck81esjV
         iZMDavSKUOeyj+p2OjM54IyoPUJEvERGOal/ip+jRiRhLu0MNmRPo8RtHX+1w5fSxzCc
         qjgAI7ncyudqEX8my9xq85PV2XVGvEVvIKKTq+BdaRWq1IsO7+R42FLLwT/RkH41BaKG
         jkFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id l14si711069ybp.4.2021.04.30.13.15.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 13:15:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcZXv-00CEwB-EO; Fri, 30 Apr 2021 14:15:31 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcZXp-0000S1-Nv; Fri, 30 Apr 2021 14:15:30 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
Date: Fri, 30 Apr 2021 15:15:20 -0500
In-Reply-To: <YIxVWkT03TqcJLY3@elver.google.com> (Marco Elver's message of
	"Fri, 30 Apr 2021 21:07:06 +0200")
Message-ID: <m17dkjttpj.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcZXp-0000S1-Nv;;;mid=<m17dkjttpj.fsf@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+N6RHdIHHOmi2pb7aC1y1Z6j2yxh0sqxg=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.3 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.3510]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 5048 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 10 (0.2%), b_tie_ro: 9 (0.2%), parse: 1.11 (0.0%),
	 extract_message_metadata: 15 (0.3%), get_uri_detail_list: 3.5 (0.1%),
	tests_pri_-1000: 6 (0.1%), tests_pri_-950: 1.15 (0.0%),
	tests_pri_-900: 0.93 (0.0%), tests_pri_-90: 127 (2.5%), check_bayes:
	125 (2.5%), b_tokenize: 12 (0.2%), b_tok_get_all: 13 (0.3%),
	b_comp_prob: 3.5 (0.1%), b_tok_touch_all: 92 (1.8%), b_finish: 0.90
	(0.0%), tests_pri_0: 1445 (28.6%), check_dkim_signature: 0.63 (0.0%),
	check_dkim_adsp: 2.5 (0.0%), poll_dns_idle: 3410 (67.5%),
	tests_pri_10: 4.6 (0.1%), tests_pri_500: 3434 (68.0%), rewrite_mail:
	0.00 (0.0%)
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
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

Marco Elver <elver@google.com> writes:

> On Fri, Apr 30, 2021 at 12:08PM -0500, Eric W. Biederman wrote:
>> Arnd Bergmann <arnd@arndb.de> writes:
> [...] 
>> >> I did a quick search and the architectures that define __ARCH_SI_TRAPNO
>> >> are sparc, mips, and alpha.  All have 64bit implementations.  A further
>> >> quick search shows that none of those architectures have faults that
>> >> use BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR, nor do
>> >> they appear to use mm/memory-failure.c
>> >>
>> >> So it doesn't look like we have an ABI regression to fix.
>> >
>> > Even better!
>> >
>> > So if sparc is the only user of _trapno and it uses none of the later
>> > fields in _sigfault, I wonder if we could take even more liberty at
>> > trying to have a slightly saner definition. Can you think of anything that
>> > might break if we put _trapno inside of the union along with _perf
>> > and _addr_lsb?
>> 
>> On sparc si_trapno is only set when SIGILL ILL_TRP is set.  So we can
>> limit si_trapno to that combination, and it should not be a problem for
>> a new signal/si_code pair to use that storage.  Precisely because it is
>> new.
>> 
>> Similarly on alpha si_trapno is only set for:
>> 
>> SIGFPE {FPE_INTOVF, FPE_INTDIV, FPE_FLTOVF, FPE_FLTDIV, FPE_FLTUND,
>> FPE_FLTINV, FPE_FLTRES, FPE_FLTUNK} and SIGTRAP {TRAP_UNK}.
>> 
>> Placing si_trapno into the union would also make the problem that the
>> union is pointer aligned a non-problem as then the union immediate
>> follows a pointer.
>> 
>> I hadn't had a chance to look before but we must deal with this.  The
>> definition of perf_sigtrap in 42dec9a936e7696bea1f27d3c5a0068cd9aa95fd
>> is broken on sparc, alpha, and ia64 as it bypasses the code in
>> kernel/signal.c that ensures the si_trapno or the ia64 special fields
>> are set.
>> 
>> Not to mention that perf_sigtrap appears to abuse si_errno.
>
> There are a few other places in the kernel that repurpose si_errno
> similarly, e.g. arch/arm64/kernel/ptrace.c, kernel/seccomp.c -- it was
> either that or introduce another field or not have it. It is likely we
> could do without, but if there are different event types the user would
> have to sacrifice a few bits of si_perf to encode the event type, and
> I'd rather keep those bits for something else. Thus the decision fell to
> use si_errno.

arm64 only abuses si_errno in compat code for bug compatibility with
arm32.

> Given it'd be wasted space otherwise, and we define the semantics of
> whatever is stored in siginfo on the new signal, it'd be good to keep.

Except you don't completely.  You are not defining a new signal.  You
are extending the definition of SIGTRAP.  Anything generic that
responds to all SIGTRAPs can reasonably be looking at si_errno.

Further you are already adding a field with si_perf you can just as
easily add a second field with well defined semantics for that data.

>> The code is only safe if the analysis that says we can move si_trapno
>> and perhaps the ia64 fields into the union is correct.  It looks like
>> ia64 much more actively uses it's signal extension fields including for
>> SIGTRAP, so I am not at all certain the generic definition of
>> perf_sigtrap is safe on ia64.
>
> Trying to understand the requirements of si_trapno myself: safe here
> would mean that si_trapno is not required if we fire our SIGTRAP /
> TRAP_PERF.
>
> As far as I can tell that is the case -- see below.
>
>> > I suppose in theory sparc64 or alpha might start using the other
>> > fields in the future, and an application might be compiled against
>> > mismatched headers, but that is unlikely and is already broken
>> > with the current headers.
>> 
>> If we localize the use of si_trapno to just a few special cases on alpha
>> and sparc I think we don't even need to worry about breaking userspace
>> on any architecture.  It will complicate siginfo_layout, but it is a
>> complication that reflects reality.
>> 
>> I don't have a clue how any of this affects ia64.  Does perf work on
>> ia64?  Does perf work on sparc, and alpha?
>> 
>> If perf works on ia64 we need to take a hard look at what is going on
>> there as well.
>
> No perf on ia64, but it seems alpha and sparc have perf:
>
> 	$ git grep 'select.*HAVE_PERF_EVENTS$' -- arch/
> 	arch/alpha/Kconfig:	select HAVE_PERF_EVENTS    <--
> 	arch/arc/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/arm/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/arm64/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/csky/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/hexagon/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/mips/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/nds32/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/parisc/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/powerpc/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/riscv/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/s390/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/sh/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/sparc/Kconfig:	select HAVE_PERF_EVENTS    <--
> 	arch/x86/Kconfig:	select HAVE_PERF_EVENTS
> 	arch/xtensa/Kconfig:	select HAVE_PERF_EVENTS
>
> Now, given ia64 is not an issue, I wanted to understand the semantics of
> si_trapno. Per https://man7.org/linux/man-pages/man2/sigaction.2.html, I
> see:
>
> 	int si_trapno;    /* Trap number that caused
> 			     hardware-generated signal
> 			     (unused on most architectures) */
>
> ... its intended semantics seem to suggest it would only be used by some
> architecture-specific signal like you identified above. So if the
> semantics is some code of a hardware trap/fault, then we're fine and do
> not need to set it.
>
> Also bearing in mind we define the semantics any new signal, and given
> most architectures do not have si_trapno, definitions of new generic
> signals should probably not include odd architecture specific details
> related to old architectures.
>
> From all this, my understanding now is that we can move si_trapno into
> the union, correct? What else did you have in mind?

Yes.  Let's move si_trapno into the union.

That implies a few things like siginfo_layout needs to change.

The helpers in kernel/signal.c can change to not imply that
if you define __ARCH_SI_TRAPNO you must always define and
pass in si_trapno.  A force_sig_trapno could be defined instead
to handle the cases that alpha and sparc use si_trapno.

It would be nice if a force_sig_perf_trap could be factored
out of perf_trap and placed in kernel/signal.c.

My experience (especially this round) is that it becomes much easier to
audit the users of siginfo if there is a dedicated function in
kernel/signal.c that is simply passed the parameters that need
to be placed in siginfo.

So I would very much like to see if I can make force_sig_info static.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m17dkjttpj.fsf%40fess.ebiederm.org.
