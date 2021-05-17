Return-Path: <kasan-dev+bncBCALX3WVYQORBSUVROCQMGQEKUGP54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 112C0383DEB
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 21:58:04 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id t3-20020a170902e843b02900eec200979asf2345357plg.9
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 12:58:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621281482; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJ678JOE9u3cCRKtYN1urLmh7JXEHmm6z+6dajSc2/p2v1otQXC5795HheOEa5gwC0
         3PYJzkYegq5mLckYNZ7KpNxP2j+AZxpgGgZRtZIwmdqF67uILrVWgabm51j9lbGef8R9
         foFvKYWZFRbEa7e/0DOKCQriwtCgdCk1Td2YQ91F0Ibe2iU3z5dKXLtkllSfz4Z1KMCl
         vVphKM5tddndcC9oXsqQCebwf2zMUiJOTu3M5KCNY++Kc53ccM3SWPTWy4q6K7rG/IO7
         fj2hhbRGHLQXFiGN2vXJDK/cTybYi900wNpXd2DdW6oKXdWN9cSiVTcAsfKXroCQH0IG
         Bdpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=thgQbM13BESd+zmJHwGhyE1X2vYy4bXm/zKTa0bg/zQ=;
        b=vyR0e/cF8jvgLQcf/0N1S3ZJ1938Ljbjl2r8XQX/1NRr5YWYXxXm9St5weYdcdZzMI
         zFmwqrwUP4yMtHwtoADLONoYca+47YwaxxHx/XtGH91MdJqah4giAU1zzP80WGReQD4H
         tZRGtErSqxNbU4UBsQ/2DT/BeHAtklH70znM620bXH27uO91lznbp0f8tVVTHI08NvaD
         d9F/bO2a1naPAFCNX/rv48xdF24an93Hti6/DsUajAb2hylxS92XsGSD4Ftfjuv/KptY
         Midlw4B7OihhZzoRbhYwvRx+YyXgunfkZwcKJq1xpK18FE1SWJO3dKsZOz8z9//Ukj6/
         2nbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=thgQbM13BESd+zmJHwGhyE1X2vYy4bXm/zKTa0bg/zQ=;
        b=Opao6hLX8XPVi5U/QDGCS5FWq0hMQIn30N0OvhtcUgsDNmTsR9cLSk6HOEg746FLGc
         SODonpdKAEyGqulX5LyPeNrOucHLKzqpXtdtCZK2aR/qCZG2MX/I9qpD1BMXIaFU20UB
         bSByNQMXXq9IVfI6mxfvmlVPLZ5fLkxq66rrKIkHEyrwwdmu5ZlTzB0eQBFiWejSDha3
         rpwkA0PEyaWRJD9qd9vqyMMBnYDmgWqali7bx1ZSYtv7gnW7T3ZCxP1SZOdl3HuKpdrl
         I3qtf29md1PQrP5G49SVPWpJ66ClZhYNMFzoqleQzbQJ2FpSr+x3ZfbxTdbwEh/WXsL/
         FQwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=thgQbM13BESd+zmJHwGhyE1X2vYy4bXm/zKTa0bg/zQ=;
        b=HPCCDuItLKLhKPyBWszcV1r8B0NIEouZvB3jDDMR5tGb2/NPC2jVJD5qsz2rr5hmZ3
         uWr0Egazg6F/JgoRCDteC3XwI5xKZi7JHZN5KMga3rH3CbUy74jUiUKVEMJLz0XS71Rk
         QG4+118QZjnhhqFNG2/oyMeM2j5zG4hhSiIJ14a3FeNskZBajVRZKvn9/XxwoqPBVxas
         UfUBB+rrs7ynJg4RKyhjwcJZv2gL7WpNC9Ks8Z0zeQBEK2kR1CSl3v/EVMBN92XZnvuM
         bhIKOyyVt6/cxE9eh2CTi70JrCRS2+rntIGnPaF/I/oL1ca31OTleHqZo5H5dVrfw3H2
         182A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317H/+670FgMv8TBpBdjxWvu21RBSLrLgbaHMM3zIJ/U0dXy0mf
	LKX5wot4rjs6r8B7g1pcruE=
X-Google-Smtp-Source: ABdhPJyrrK9xLcC/d4VwRbRy71Yl9do6QAGgTDS8bOl7gwcmMS++O1GDyzMa8c6kE2emYYI226cbtg==
X-Received: by 2002:a17:90a:2844:: with SMTP id p4mr842379pjf.89.1621281482809;
        Mon, 17 May 2021 12:58:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8184:: with SMTP id g4ls7143460pfi.4.gmail; Mon, 17 May
 2021 12:58:02 -0700 (PDT)
X-Received: by 2002:aa7:8f37:0:b029:2db:551f:ed8e with SMTP id y23-20020aa78f370000b02902db551fed8emr1316567pfr.43.1621281482284;
        Mon, 17 May 2021 12:58:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621281482; cv=none;
        d=google.com; s=arc-20160816;
        b=phSKe8qZ4QhdC4yhMNDZ4E90cs+H89owlLqlLKISNa4NsTqOui4/GA63O+5KL4w8zt
         t2njGWrxORtEY/O8l4w/Ru/mXG3vkfVEHlUFD9GJFwHiphT0/opvU9BJOkqD56eRZWxP
         taOxdeDaPh04MBnZ/x5QNZSCmd73jIUAAJlosZLAwbeQTofOEldsiFgDHiUOUrYsayHx
         4NNv3qleWuCttDyc+MCtLWHmUyPhRlqUPHTUlFgSuMHJvW4VFVuJEwITs/4D5VvY8QnG
         6FkEFn/ZuaMxMHRgHu5z2wysIAk34eCRU2NIqujdZVlsvBgL7NK/oI5jCTfc27vYDgd9
         CZag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=XXfThX2oSG7gKlRxOP/ywOwrWKAMRz99hREMrKBfn/8=;
        b=WW+sefbpLHS5PgNT5DDg74VDZ18LzLgDEbbiZCyPm30WpKXl9qTpZQYeXMNjpiRqf5
         4DUaMsInD3fDsUB2uSfFZ3qlIwx+dsxGwdIKTgxbzdyCQebU8YJFT+dcXfu/0yWbF0Cy
         7ZQC5kA5UvDJO/6IwnFQKo9Yrl92aATX6SUAcneYVbDepw6QseWdp28zTNkvCqYS0r6+
         ykiHOn0c1f9gRq1j5UYJ6ccDClcoNbqrws8tMhSWrLj7b/aM6o/IJmxba/RaxOPJwJiA
         n064htFnud60Mcl0kLvB1NOiihTE1Jpms0PI9KYxtpiCgI5aO605svLIGu6mixg/2SOd
         N6zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id a8si59345pju.2.2021.05.17.12.58.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 12:58:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijNH-009gqy-Gb; Mon, 17 May 2021 13:57:59 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lijMX-0001ch-UG; Mon, 17 May 2021 13:57:16 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1r1irpc5v.fsf@fess.ebiederm.org>
	<CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
	<m1czuapjpx.fsf@fess.ebiederm.org>
	<CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
	<m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<m1tuni8ano.fsf_-_@fess.ebiederm.org>
Date: Mon, 17 May 2021 14:56:54 -0500
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Tue, 04 May 2021 16:13:47 -0500")
Message-ID: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lijMX-0001ch-UG;;;mid=<m1a6ot5e2h.fsf_-_@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19wgF5urIEeuZov1TyNkbEl+ZRf8d7DJfI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa01.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01 autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4155]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa01 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa01 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 379 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.6 (1.2%), b_tie_ro: 3.1 (0.8%), parse: 1.13
	(0.3%), extract_message_metadata: 4.9 (1.3%), get_uri_detail_list: 2.6
	(0.7%), tests_pri_-1000: 3.5 (0.9%), tests_pri_-950: 1.07 (0.3%),
	tests_pri_-900: 0.89 (0.2%), tests_pri_-90: 53 (14.1%), check_bayes:
	52 (13.7%), b_tokenize: 7 (1.7%), b_tok_get_all: 9 (2.4%),
	b_comp_prob: 1.89 (0.5%), b_tok_touch_all: 32 (8.3%), b_finish: 0.72
	(0.2%), tests_pri_0: 293 (77.5%), check_dkim_signature: 0.39 (0.1%),
	check_dkim_adsp: 2.5 (0.7%), poll_dns_idle: 1.16 (0.3%), tests_pri_10:
	2.7 (0.7%), tests_pri_500: 7 (1.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v4 0/5] siginfo: ABI fixes for TRAP_PERF
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
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


During the merge window an issue with si_perf and the siginfo ABI came
up.  The alpha and sparc siginfo structure layout had changed with the
addition of SIGTRAP TRAP_PERF and the new field si_perf.

The reason only alpha and sparc were affected is that they are the
only architectures that use si_trapno.

Looking deeper it was discovered that si_trapno is used for only
a few select signals on alpha and sparc, and that none of the
other _sigfault fields past si_addr are used at all.  Which means
technically no regression on alpha and sparc.

While the alignment concerns might be dismissed the abuse of
si_errno by SIGTRAP TRAP_PERF does have the potential to cause
regressions in existing userspace.

While we still have time before userspace starts using and depending on
the new definition siginfo for SIGTRAP TRAP_PERF this set of changes
cleans up siginfo_t.

- The si_trapno field is demoted from magic alpha and sparc status and
  made an ordinary union member of the _sigfault member of siginfo_t.
  Without moving it of course.

- si_perf is replaced with si_perf_data and si_perf_type ending the
  abuse of si_errno.

- Unnecessary additions to signalfd_siginfo are removed.

v3: https://lkml.kernel.org/r/m1tuni8ano.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org

This version drops the tests and fine grained handling of si_trapno
on alpha and sparc (replaced assuming si_trapno is valid for
all but the faults that defined different data).

Eric W. Biederman (5):
      siginfo: Move si_trapno inside the union inside _si_fault
      signal: Implement SIL_FAULT_TRAPNO
      signal: Factor force_sig_perf out of perf_sigtrap
      signal: Deliver all of the siginfo perf data in _perf
      signalfd: Remove SIL_PERF_EVENT fields from signalfd_siginfo


 arch/m68k/kernel/signal.c                          |  3 +-
 arch/x86/kernel/signal_compat.c                    |  9 +++-
 fs/signalfd.c                                      | 23 ++++-----
 include/linux/compat.h                             | 10 ++--
 include/linux/sched/signal.h                       |  1 +
 include/linux/signal.h                             |  1 +
 include/uapi/asm-generic/siginfo.h                 | 15 +++---
 include/uapi/linux/perf_event.h                    |  2 +-
 include/uapi/linux/signalfd.h                      |  4 +-
 kernel/events/core.c                               | 11 +---
 kernel/signal.c                                    | 59 +++++++++++++---------
 .../selftests/perf_events/sigtrap_threads.c        | 14 ++---
 12 files changed, 79 insertions(+), 73 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1a6ot5e2h.fsf_-_%40fess.ebiederm.org.
