Return-Path: <kasan-dev+bncBCALX3WVYQORBLMF7CCAMGQEZ4NVY3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 442F0380326
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 06:55:11 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id x194-20020a6286cb0000b029027b2c6cb53esf19183636pfd.19
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 21:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620968110; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwlEtcfjB+VW8BuvYxgRW6DvOp19rwXPqDr2HUWThEEBqSiTwA+ZpsDvUEJdLa00LS
         e4E0tvaTuaiirkBg2+2o3bRhJUntSNtqp9lM2QwD9jBlw1sjrsxn1txhoIocuigzDLDP
         SNSzHkIgeZw/Kh7RWPWaB7FipaFzz4yXqKHlrWVXf5XRcjmVVn1vz37a2oWEb95iFi6R
         pliPN3ZLAvrrUgS63oY3p1BcApgrsXzxH7KS562anpvDW+wQoay7NZa8cFNhox3ulu/v
         L5Z/RsfyKGf3iEoqMhtD9SAlLxENSbcSpsy/1PylVe3y4XLkDCaUaEQiXmDa0CFThueL
         C6Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=nKol6T2+/Hz0xcruggmZEBiIY2Fdz8P0YTjOHcNInB0=;
        b=wK8wsKnS3VvYq+Cq9DtLIgRcIvVqufob2dxYHtyBYGs9wZrNu+k1JVvaoAzsN8oL5u
         3H5WhYgJmgk0Tl2VM/84nRkckebfD7NGan6R0bCYihOFoE2B4V+tRdIx5BSM1K0NZE56
         nXxPvRNEkOqRKIExVUsma4juFrSo+am9dQwWEiRDKRK4BKfhJpn4h4gMBOrguJvuet/V
         RvQ5C5kFJdH1yNrXv8cSmaPF0I+hDV96WlBXBBJxUPYXgdkyJabHXLMdW6FjCPKW3O6S
         RWWL1GU40dV2jvNLTXYyEY/rmKOxLxNkvXVKbu/RpL0TBoYVDCK3GdKeF+OLi+4iKmtv
         5IZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nKol6T2+/Hz0xcruggmZEBiIY2Fdz8P0YTjOHcNInB0=;
        b=gFaTGeOkvpVFcLVPUXxADPDdZhY0YL/Ltetgt5QC1vPjOOC6B3H7aojFMJlpDLGZ1O
         YPDdmJ5T13cNvAVKEVIQT/2DYLJB+LHVcaF4wwsNBs3mkC22qWu8aEGnmUjGAw9Rycbp
         gQdff7ifx5R2FnzXz/O3d604Y2LzVOodoe6dMG0FZq27Muw2XDgaMp7IUeZfwWQho6fb
         uRd2RqCJzYHr0GiYmMEgW0Vjkc01skRjGGxHs7ncSFblI9Hj3uogJRF9ovpLIJrMsBCT
         UOdC10jobY6eZPiQXH+A9ylxymB5DgOdZmLr7q8FUEFKyBaO+HIJpWq4CF/Hth+qTe3z
         k5FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nKol6T2+/Hz0xcruggmZEBiIY2Fdz8P0YTjOHcNInB0=;
        b=ExtA4WcusLdskXJCEalAS0eXNQEsm/lPy1jFwvNZ3aW4XPSj0mU+nhHWkl2o2k1GeL
         5miLza+HaEjL6iJOXqJ3CiK7FqrQauSrRsWN7T1Os1vbNYr1rEEGCv9nY/RVFnI87aT1
         Y+DFOpu9bFPS00oMAAhcK0CWTd13JP5vm+UU93u3hkPyR4WyRNvKLZkyIR1NWhUu3U5f
         d2hikn4DAHskPJGtQwkRKsGz9O4oNls8u6CS/U/ObLyXP+b5pqI1uW2zLiQNp+5KyVF9
         5bEvBfUTRiv9Uth6uOY7uN3h1DUDpIipvsf3Gn9ajj71aeoI+FbyQ4QbqsNuEmXXom74
         3TSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+2eAU+Wj3qeITIGOttq4133A9zHa1fT9/q5Bb/jmSHMeqmfiM
	P3xAvf/insnqH9ZIYyd/skg=
X-Google-Smtp-Source: ABdhPJypllDYzw9ruPB+zXd2Elf0c2cftRnyMQEY/7ZT9w7gDQLauFHS9tWBkwVGcJVZNllwrbxFvQ==
X-Received: by 2002:a17:902:6805:b029:f0:a36b:72f8 with SMTP id h5-20020a1709026805b02900f0a36b72f8mr270451plk.22.1620968109880;
        Thu, 13 May 2021 21:55:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7e1c:: with SMTP id z28ls3614282pgc.3.gmail; Thu, 13 May
 2021 21:55:09 -0700 (PDT)
X-Received: by 2002:a05:6a00:882:b029:24b:afda:acfa with SMTP id q2-20020a056a000882b029024bafdaacfamr43940827pfj.72.1620968109303;
        Thu, 13 May 2021 21:55:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620968109; cv=none;
        d=google.com; s=arc-20160816;
        b=OldL6xc0nsabaS2staWCJmTNuYu3W3tAaYQnOKhi0VxnNd++zDeOAxnaHgjzMZSTKf
         +HFLzAES7b3o7rQH7+/s2oUCuBB0JRiTtOMNII8qQ3Wd7KHzoTQ4Cl73AK5H5XhU7diL
         dp3404BhXDy/lP3+la6oV3mXzh5fgR0/CBv2NM35v9F/CvHlTurJBjcYqMAVlEtdFn8y
         07vnHmUiDck8ZwAmC4jH6HZGxzrbm75TQrExkMHWiE9Z3rtynYZD6STRfcvRWXlCc+fv
         2j4jtG6T+IzKVed8qmhVUE63v1SJxBJsPHlJ/Hc6BjC1J35gRFT6HBNfIGGJ29JuP+VK
         RRVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=/yGOIo8wPEiX4tw0CVCsdpTL1vcmvUpxGMjDii3uMeI=;
        b=OgKbqyUmIutwraKUqT8nYaTJWXQ3YLh3DxIRd2kUW9FjjnPC9kSF7pLdHl3GFmX8LM
         8XYPwkMOni56Z70i9PKidln+UmN/nL7zdR7m22ij3iSlItKpw4JFOd/hztQ4bngnxBrs
         ULucy4iGlUplOdE+KgRqfMgXsrao2XnTBPgaXsdN52sku+z6VBCENhlT6gdK26jyDejg
         FCOABacrjuEpaycNw31JHxsRjFc7cH7oFuBkcUUQs01IRwNedu9naNcLK8dI/zVGffov
         5EABnKqy2+vlebgondt1pglXex5pXCr1UVXfp8Oc5zL9nL5pGj3CvlwT2sBLVQ9tPO0Z
         Z87g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id w3si452552plz.2.2021.05.13.21.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 May 2021 21:55:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhPqq-00BoLN-Ng; Thu, 13 May 2021 22:55:04 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhPqo-001pPq-NE; Thu, 13 May 2021 22:55:03 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
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
Date: Thu, 13 May 2021 23:54:57 -0500
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Tue, 04 May 2021 16:13:47 -0500")
Message-ID: <m1a6oxewym.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lhPqo-001pPq-NE;;;mid=<m1a6oxewym.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18LwkDtE9Oj161KN5+izzXCHEVxEw+wP90=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,XMSubMetaSxObfu_03,XMSubMetaSx_00 autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4974]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 XMSubMetaSx_00 1+ Sexy Words
	*  1.2 XMSubMetaSxObfu_03 Obfuscated Sexy Noun-People
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Linus Torvalds <torvalds@linux-foundation.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 565 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 10 (1.8%), b_tie_ro: 9 (1.6%), parse: 0.95 (0.2%),
	 extract_message_metadata: 4.9 (0.9%), get_uri_detail_list: 3.0 (0.5%),
	 tests_pri_-1000: 4.3 (0.8%), tests_pri_-950: 1.23 (0.2%),
	tests_pri_-900: 1.05 (0.2%), tests_pri_-90: 69 (12.2%), check_bayes:
	68 (11.9%), b_tokenize: 12 (2.2%), b_tok_get_all: 12 (2.1%),
	b_comp_prob: 3.5 (0.6%), b_tok_touch_all: 37 (6.5%), b_finish: 0.94
	(0.2%), tests_pri_0: 447 (79.0%), check_dkim_signature: 0.71 (0.1%),
	check_dkim_adsp: 2.8 (0.5%), poll_dns_idle: 0.83 (0.1%), tests_pri_10:
	3.7 (0.6%), tests_pri_500: 15 (2.6%), rewrite_mail: 0.00 (0.0%)
Subject: [GIT PULL] siginfo: ABI fixes for v5.13-rc2
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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


Linus,

Please pull the for-v5.13-rc2 branch from the git tree:

  git://git.kernel.org/pub/scm/linux/kernel/git/ebiederm/user-namespace.git for-v5.13-rc2

  HEAD: addd6821190ebf1e9fece0b7848db667fd280e2e signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo

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

- BUILD_BUG_ONs are added and various helpers are modified to
  accommodate this change.

- Unnecessary additions to signalfd_siginfo are removed.

v3: https://lkml.kernel.org/r/m1tuni8ano.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org

You might notice a recent rebase.  This code has been sitting in
linux-next as  ef566ba2d7d9 ("signal: Remove the last few si_perf
references").  Which results in the exact same code as the branch
I am sending you but the commits differ to keep git bisect working.

The difference is that I squashed a fix for a mips BUILD_BUG_ON about
si_perf into the commit that replaces si_perf with si_perf_data and
si_perf_type.  This keeps the kernel building on all architectures for
all commits keeping git-bisect working for everyone.

Eric W. Biederman (9):
      signal: Verify the alignment and size of siginfo_t
      siginfo: Move si_trapno inside the union inside _si_fault
      signal: Implement SIL_FAULT_TRAPNO
      signal: Use dedicated helpers to send signals with si_trapno set
      signal: Remove __ARCH_SI_TRAPNO
      signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
      signal: Factor force_sig_perf out of perf_sigtrap
      signal: Deliver all of the siginfo perf data in _perf
      signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo

Marco Elver (3):
      sparc64: Add compile-time asserts for siginfo_t offsets
      arm: Add compile-time asserts for siginfo_t offsets
      arm64: Add compile-time asserts for siginfo_t offsets

 arch/alpha/include/uapi/asm/siginfo.h              |   2 -
 arch/alpha/kernel/osf_sys.c                        |   2 +-
 arch/alpha/kernel/signal.c                         |   4 +-
 arch/alpha/kernel/traps.c                          |  24 ++---
 arch/alpha/mm/fault.c                              |   4 +-
 arch/arm/kernel/signal.c                           |  39 +++++++
 arch/arm64/kernel/signal.c                         |  39 +++++++
 arch/arm64/kernel/signal32.c                       |  39 +++++++
 arch/m68k/kernel/signal.c                          |   3 +-
 arch/mips/include/uapi/asm/siginfo.h               |   2 -
 arch/sparc/include/uapi/asm/siginfo.h              |   3 -
 arch/sparc/kernel/process_64.c                     |   2 +-
 arch/sparc/kernel/signal32.c                       |  37 +++++++
 arch/sparc/kernel/signal_64.c                      |  36 +++++++
 arch/sparc/kernel/sys_sparc_32.c                   |   2 +-
 arch/sparc/kernel/sys_sparc_64.c                   |   2 +-
 arch/sparc/kernel/traps_32.c                       |  22 ++--
 arch/sparc/kernel/traps_64.c                       |  44 ++++----
 arch/sparc/kernel/unaligned_32.c                   |   2 +-
 arch/sparc/mm/fault_32.c                           |   2 +-
 arch/sparc/mm/fault_64.c                           |   2 +-
 arch/x86/kernel/signal_compat.c                    |  15 ++-
 fs/signalfd.c                                      |  23 ++---
 include/linux/compat.h                             |  10 +-
 include/linux/sched/signal.h                       |  13 +--
 include/linux/signal.h                             |   3 +-
 include/uapi/asm-generic/siginfo.h                 |  20 ++--
 include/uapi/linux/perf_event.h                    |   2 +-
 include/uapi/linux/signalfd.h                      |   4 +-
 kernel/events/core.c                               |  11 +-
 kernel/signal.c                                    | 113 +++++++++++++--------
 .../selftests/perf_events/sigtrap_threads.c        |  14 +--
 32 files changed, 377 insertions(+), 163 deletions(-)

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1a6oxewym.fsf_-_%40fess.ebiederm.org.
