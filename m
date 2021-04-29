Return-Path: <kasan-dev+bncBCALX3WVYQORBNGXVOCAMGQEZV4Y2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C29EA36EED1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 19:24:06 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id az20-20020a17090b0294b029014daeb09222sf33384152pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 10:24:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619717045; cv=pass;
        d=google.com; s=arc-20160816;
        b=KTN4WBJ7ogvdSD5yPgsMMKXmysMYNI36KFbIPHgrmv/29EwbElglRD2SrpMqBdaVqD
         MJvEtMw1gzHkLp9tGtu8MCiXwoihf33vbfMr22E4g6xzERVzxI1D4vl4Q6pSr5umrqFh
         iTd7+wsVFD1rHS+oAUobaWUlt7LFGXSJlbSAJeJw3VQ5ZOLRgHZlSp7Jy4tyZ4mQ3aID
         K7lhWV/rcBgIIbiaJZSibFHUE5p4aFru8Jek7DFQ8ka66Gm+NtjBxqiOsp6UhgPZZJd1
         VxvP3tRJowUolZNjiQj584oqQ1od+jI2c9PGfMh0vZjw2CFDlgUSvPO/WnLpgSKWx4zK
         0pGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=VVuCwjFsOVkBdR00PeKjQ7byFdgxJubLKVHLQc2BduU=;
        b=J4QzAu95lNdHBbBVfUIQGwfqtPqn6K2uMnrJD1T/3Tb2UASd033v5kNSRqY33hti4N
         uPPYgKwPfkxJNEE2lzZBXxhimOFYAeIpUmTvH54RMszqr+EIuyarXDpmlc0lzSnGFxC8
         9Cfdn8JJK1SyZF9FbDBDUsfCh5d67iUmTO5AkKJ0ydnYhWGKkBy77SwdsYeGPhzrew2S
         JXm9vU5mwNfZEnacvFX71Kp91j3OkTBOCOL9rzjB3Ar1c8UDJSfximHt3oniIy1/HgSG
         moebPd67wg1zExzbNR+DNoxsGZcfCq0Oo8QR1hlju+++vkjKBforN9KG7/BQepbgcxGh
         jApA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VVuCwjFsOVkBdR00PeKjQ7byFdgxJubLKVHLQc2BduU=;
        b=O2xQFVbYgcxrCtIkhKcjsDD6vfE7OLJkfPrD/4ajjFNi8sccSE5IrBqG9ArMnyl7xz
         /XAwQfeYlUBr2OMCjBJapU8/U/mb9Fu4CfIBZLBYz4Thi1mf+ZodhwPMFlrNfb7B6q+N
         DgqpF5cG0K5j+ap4K1rZhGW3jq0M12wSFZ0TvBS5sGLLdBfa0DHGCKEPa9OUL19HU4Bi
         bEmegq1iaDYeznn4mQdA90vu2+sccJ0sskkVV2Mjyqxbcd9RnLIhZnGtRUaFe2IsZqqT
         nwHFCuv87+0CxM/CPp4uGR49ScF1fCvmmEJLodx7060yjqX+4HSVjwL4j5p5lPx1aQMi
         qDYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVuCwjFsOVkBdR00PeKjQ7byFdgxJubLKVHLQc2BduU=;
        b=AFS2toS8/mJ6Sg26py26b0mK3l2BA6vNnsnnxutjF7ZliELB+OOxnoN3sNMdOiSKms
         hMuCpUpZNBZcUAmBYrOdhDB/ZAaT0jENMOnguBD548U07fc5Xin0GiDlmeIg+ZT5FgpP
         JUGso/adtdNdcTPviqnQxy4/KdH70mx75m1giWqCDj/mvN+y/yD8P5c3P0sKehLNbVay
         db5QJxk5rhXtoECCzQw1+L/HnCSuWCjwQsN4LIJLxl++TMzb0au4WEo7rmj/4Qq2NitW
         v8IKdM6BLJiiHAVbPyHpaY4gTMD6MdkwMdKwAO7H38FfQa/rjRe5xdjdAtNrDBX5B4F0
         Gs0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530olF6theFoAQQbvtyf9O5CegTE0k6m8CDL1gMDusqe33ijtuav
	J+BPmfJL4/iOp3i/DbeYut8=
X-Google-Smtp-Source: ABdhPJxQy9+0CGWvgG4LPKe/894o4hmPLoKUn7FFWm1tJvtND2Ll02hN5iH1bCuEBPghKhOkXktvng==
X-Received: by 2002:a17:90a:f2d7:: with SMTP id gt23mr10506549pjb.199.1619717045433;
        Thu, 29 Apr 2021 10:24:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ff18:: with SMTP id f24ls1938672plj.0.gmail; Thu, 29
 Apr 2021 10:24:04 -0700 (PDT)
X-Received: by 2002:a17:902:da86:b029:ec:ad63:5ab with SMTP id j6-20020a170902da86b02900ecad6305abmr778549plx.28.1619717044532;
        Thu, 29 Apr 2021 10:24:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619717044; cv=none;
        d=google.com; s=arc-20160816;
        b=gHvduAa3pGNMbvA74XRhQjXDT7lVXeFdYvWcNaLU8AwdGjJc5gEc+CwktThYacjYw+
         3atWaGjuFdi+Iv5iAj0ZbJoTOkZ64dPA8bsTQ8SV/j4kvXcwVpBOAxxYHvpYZyB3v2OD
         tC6yXJN6DyUFzS+l5wpWvwyCBd3rRDFRneC8pAPJrS8rNVpv/GQMtDKO77T6i7fDafyc
         DnRHhXZymbwwuhxVTbdiS0Y14e30NrLOzWKcS0g9SVnJAjN2SWgmMEt5fYQLSN5G5uE5
         abpDgGRU57LaoA+M0mNi8esNilJNqOFyyO7ISkt71tgY7bLM68m9X6MhNMYMKVL/pbhL
         jlNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=NTpglfO4r43Y0AIH+Uy4vsn33+MHBHlsTWBYxmqcWvc=;
        b=EV9vAAbfqGlTwCh7nJjj/uqfTmFGLVPJGuRRsx9MyKaQskj6d4u7o34TIWFHbYtZOk
         Ae3UwU49HZYJu5jn1Wfch2vbV0YiAkax117B3yAKfFJho/3Dh4NsYFPTf21J7EdnPuPq
         8XohC9AVjU89fTO5ELTJtcaxh0SVlRPKzV9KIW8n8bdFgdxY2dCjOHRrVToNxKFWTf8u
         Av/uTdb461UiOeCu1ADWOuUuozTT80WIBKtSoLbQ8I405bg8ONeDYZgBCBEXRzlzFnc7
         qjfQzLs2oUhd445DpsBrNs1qLX5vamFUrb9nqtbmTnAXFLJCnF/P28nK7RMrVFgLPDf4
         tB1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id y17si303203plr.4.2021.04.29.10.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Apr 2021 10:24:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out02.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcAOP-00A9RZ-9c; Thu, 29 Apr 2021 11:24:01 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcAON-003grI-4Z; Thu, 29 Apr 2021 11:24:00 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Arnd Bergmann <arnd@arndb.de>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux@vger.kernel.org,  linux-arch@vger.kernel.org,  linux-kernel@vger.kernel.org,  linux-api@vger.kernel.org,  kasan-dev@googlegroups.com
References: <YIpkvGrBFGlB5vNj@elver.google.com>
Date: Thu, 29 Apr 2021 12:23:54 -0500
In-Reply-To: <YIpkvGrBFGlB5vNj@elver.google.com> (Marco Elver's message of
	"Thu, 29 Apr 2021 09:48:12 +0200")
Message-ID: <m11rat9f85.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcAON-003grI-4Z;;;mid=<m11rat9f85.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/NeTTsYSLfDWkTV21ICkdFJSQGTcmp1BQ=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa02.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.3 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.0855]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa02 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa02 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1595 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 4.3 (0.3%), b_tie_ro: 3.0 (0.2%), parse: 1.23
	(0.1%), extract_message_metadata: 6 (0.4%), get_uri_detail_list: 3.9
	(0.2%), tests_pri_-1000: 3.4 (0.2%), tests_pri_-950: 1.03 (0.1%),
	tests_pri_-900: 0.88 (0.1%), tests_pri_-90: 67 (4.2%), check_bayes: 65
	(4.1%), b_tokenize: 10 (0.6%), b_tok_get_all: 11 (0.7%), b_comp_prob:
	3.1 (0.2%), b_tok_touch_all: 38 (2.4%), b_finish: 0.68 (0.0%),
	tests_pri_0: 1497 (93.9%), check_dkim_signature: 0.43 (0.0%),
	check_dkim_adsp: 2.4 (0.2%), poll_dns_idle: 0.97 (0.1%), tests_pri_10:
	1.81 (0.1%), tests_pri_500: 6 (0.4%), rewrite_mail: 0.00 (0.0%)
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
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

Marco Elver <elver@google.com> writes:

> Hello,  Eric,
>
> By inspecting the logs I've seen that about 3 years ago there had been a
> number of siginfo_t cleanups. This included moving si_addr_lsb:
>
> 	b68a68d3dcc1 ("signal: Move addr_lsb into the _sigfault union for clarity")
> 	859d880cf544 ("signal: Correct the offset of si_pkey in struct siginfo")
>  	8420f71943ae ("signal: Correct the offset of si_pkey and si_lower in struct siginfo on m68k")
>
> In an ideal world, we could just have si_addr + the union in _sigfault,
> but it seems there are more corner cases. :-/
>
> The reason I've stumbled upon this is that I wanted to add the just
> merged si_perf [1] field to glibc. But what I noticed is that glibc's
> definition and ours are vastly different around si_addr_lsb, si_lower,
> si_upper, and si_pkey.
>
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=42dec9a936e7696bea1f27d3c5a0068cd9aa95fd
>
> In our current definition of siginfo_t, si_addr_lsb is placed into the
> same union as si_lower, si_upper, and si_pkey (and now si_perf). From
> the logs I see that si_lower, si_upper, and si_pkey are padded because
> si_addr_lsb used to be outside the union, which goes back to
> "signal: Move addr_lsb into the _sigfault union for clarity".
>
> Since then, si_addr_lsb must also be pointer-aligned, because the union
> containing it must be pointer-aligned (because si_upper, si_lower). On
> all architectures where si_addr_lsb is right after si_addr, this is
> perfectly fine, because si_addr itself is a pointer...
>
> ... except for the anomaly that are 64-bit architectures that define
> __ARCH_SI_TRAPNO and want that 'int si_trapno'. Like, for example
> sparc64, which means siginfo_t's ABI has been subtly broken on sparc64
> since v4.16.
>
> The following static asserts illustrate this:
>
> --- a/arch/sparc/kernel/signal_64.c
> +++ b/arch/sparc/kernel/signal_64.c
> @@ -556,3 +556,37 @@ void do_notify_resume(struct pt_regs *regs, unsigned long orig_i0, unsigned long
>  	user_enter();
>  }
>  
> +static_assert(offsetof(siginfo_t, si_signo)	== 0);
> +static_assert(offsetof(siginfo_t, si_errno)	== 4);
> +static_assert(offsetof(siginfo_t, si_code)	== 8);
> +static_assert(offsetof(siginfo_t, si_pid)	== 16);
> +static_assert(offsetof(siginfo_t, si_uid)	== 20);
> +static_assert(offsetof(siginfo_t, si_tid)	== 16);
> +static_assert(offsetof(siginfo_t, si_overrun)	== 20);
> +static_assert(offsetof(siginfo_t, si_status)	== 24);
> +static_assert(offsetof(siginfo_t, si_utime)	== 32);
> +static_assert(offsetof(siginfo_t, si_stime)	== 40);
> +static_assert(offsetof(siginfo_t, si_value)	== 24);
> +static_assert(offsetof(siginfo_t, si_int)	== 24);
> +static_assert(offsetof(siginfo_t, si_ptr)	== 24);
> +static_assert(offsetof(siginfo_t, si_addr)	== 16);
> +static_assert(offsetof(siginfo_t, si_trapno)	== 24);
> +#if 1 /* Correct offsets, obtained from v4.14 */
> +static_assert(offsetof(siginfo_t, si_addr_lsb)	== 28);
> +static_assert(offsetof(siginfo_t, si_lower)	== 32);
> +static_assert(offsetof(siginfo_t, si_upper)	== 40);
> +static_assert(offsetof(siginfo_t, si_pkey)	== 32);
> +#else /* Current offsets, as of v4.16 */
> +static_assert(offsetof(siginfo_t, si_addr_lsb)	== 32);
> +static_assert(offsetof(siginfo_t, si_lower)	== 40);
> +static_assert(offsetof(siginfo_t, si_upper)	== 48);
> +static_assert(offsetof(siginfo_t, si_pkey)	== 40);
> +#endif
> +static_assert(offsetof(siginfo_t, si_band)	== 16);
> +static_assert(offsetof(siginfo_t, si_fd)	== 20);
>
> ---
>
> Granted, nobody seems to have noticed because I don't even know if these
> fields have use on sparc64. But I don't yet see this as justification to
> leave things as-is...
>
> The collateral damage of this, and the acute problem that I'm having is
> defining si_perf in a sort-of readable and portable way in siginfo_t
> definitions that live outside the kernel, where sparc64 does not yet
> have broken si_addr_lsb. And the same difficulty applies to the kernel
> if we want to unbreak sparc64, while not wanting to move si_perf for
> other architectures.
>
> There are 2 options I see to solve this:
>
> 1. Make things simple again. We could just revert the change moving
>    si_addr_lsb into the union, and sadly accept we'll have to live with
>    that legacy "design" mistake. (si_perf stays in the union, but will
>    unfortunately change its offset for all architectures... this one-off
>    move might be ok because it's new.)
>
> 2. Add special cases to retain si_addr_lsb in the union on architectures
>    that do not have __ARCH_SI_TRAPNO (the majority). I have added a
>    draft patch that would do this below (with some refactoring so that
>    it remains sort-of readable), as an experiment to see how complicated
>    this gets.
>
> Which option do you prefer? Are there better options?

Personally the most important thing to have is a single definition
shared by all architectures so that we consolidate testing.

A little piece of me cries a little whenever I see how badly we
implemented the POSIX design.  As specified by POSIX the fields can be
place in siginfo such that 32bit and 64bit share a common definition.
Unfortunately we did not addpadding after si_addr on 32bit to
accommodate a 64bit si_addr.

I find it unfortunate that we are adding yet another definition that
requires translation between 32bit and 64bit, but I am glad
that at least the translation is not architecture specific.  That common
definition is what has allowed this potential issue to be caught
and that makes me very happy to see.

Let's go with Option 3.

Confirm BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR are not
in use on any architecture that defines __ARCH_SI_TRAPNO, and then fixup
the userspace definitions of these fields.

To the kernel I would add some BUILD_BUG_ON's to whatever the best
maintained architecture (sparc64?) that implements __ARCH_SI_TRAPNO just
to confirm we don't create future regressions by accident.

I did a quick search and the architectures that define __ARCH_SI_TRAPNO
are sparc, mips, and alpha.  All have 64bit implementations.  A further
quick search shows that none of those architectures have faults that
use BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR, nor do
they appear to use mm/memory-failure.c

So it doesn't look like we have an ABI regression to fix.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m11rat9f85.fsf%40fess.ebiederm.org.
