Return-Path: <kasan-dev+bncBCALX3WVYQORBM5YYGCAMGQETEE72ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B25B37213F
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:25:24 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id a7-20020a62bd070000b029025434d5ead4sf3541297pff.0
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620073523; cv=pass;
        d=google.com; s=arc-20160816;
        b=IJBBurs3sYMlemENDodU6Llgw9zfc7p1zjv8F0XQzBOVhP7Rvjj0TrY7HtINMjy1UT
         UsyDUFJsZ8dcTdg1kK3iOjN/KSejZklXN6NSdPy2eG3dj83Y/HfaVKOV5Bn2AHr4jfit
         R5eFU/GjhP9J6sfU0rANTNVU3Ig3xC+uZZSUJA6E4gay3ydm9vHuWtBhmhHMo/4sz5zV
         SKPrc0OeP5XYNprgZtBgc/gtr+2MBmu0jdihepO5WfUK4KV7oIy/r72NqTsSw0BR1yF7
         KVX/Mm0V9oE41ZBK3ktQ3Z6mC56iOJMUgYMptNXGb1My+gnjTmQN0Zf7feIle/gqpOWj
         jWEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=b758KpzeSkui+GgQAO9uluNX6IP/2B/fF+zLxJ8ZLAM=;
        b=Sch3XqRliwut9tDDHelv+mkxilc+ac4PaQBH/bfvSMIiP9+RLWpnFXVWAyGiBJZRmw
         b6TtRvM1lDAjUwyr4PiC7nsJIg8IzCbj0qcNsTPchaLwghGrnHMbLxNiOfxJDE2u1iU+
         Dhd93JfygzpdXv3Sb/w/9wWDdj38Tvc5833+yG7alalYwvCFaZ8081IgXvMNy4RcOsj3
         SmUG7fnwuuR+uY53y7SYXaMP1nHOJQD/6mqnw2sqIopQnf8Ep5PwtbSaOYd6id3ttr+i
         PaT870SEMpKennHaf/fBbqS4w3Yzm++5z0JbqHbfbHJ28wpGWCkLReW3CSksghmM4OrB
         dYvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b758KpzeSkui+GgQAO9uluNX6IP/2B/fF+zLxJ8ZLAM=;
        b=rsERyrde8mbz5zIiyfc3PrE3KWpUAAW0/4mfCb70d2j2FPKo95GZOgzXRdUr0BivHu
         Nd2cUwekH4ik+MiYdRgcMLyinTHe755EBN4QwW+B5DlaoxXPhN2oH5wLf/ZsEo2B5MCn
         nc2AeqSOuiTeyFx0j94Sg1iOExCDRyFDL4AjozlM81LM0w3mvT0v6nFxIj5zPYRme3JT
         UULY0e4HeWcn38mVndKPCEVZUJM0VPRE9KZp4fJrOeWaf2LsOvxUQYAGN+mMcuYlgVsQ
         pLmONBvBbaeLfCld0wqgg+fBojpVt+idjRNcw71qFL7dIIWIDgXZYkRYBB9W+j4aWpKh
         EcjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b758KpzeSkui+GgQAO9uluNX6IP/2B/fF+zLxJ8ZLAM=;
        b=kG8U/Xk95KWCDbBxp0BMd49aDhgoiwlmdqsvMR4AVteJ+/p3trDx17fjrJwi/jNcCk
         9sblGsRrUZhrtSTRzpyXYdUxiYjNNTb5VAe8uWTDj4hpDsgdyrDIFAq0QDr6E0C+bwGG
         zleFOqw+TQvRG3D7IZbWc0MERCYos7yhv/3KUMAqO6qtQ+xCHLaph9CH1ENmXe6hXm7h
         X6c1tdSkWOET+1oQYIyWUbWy4089Gi+Y5as7Ja+JSQ7746Tg/sTBLuI3qOjKyrapGJHH
         XcBusvCAgxuAl8vFjw7Mft+EZ/vDO/QIXHzf5J20yFoFIrKilSg/yQ7sdqkphQvZLI9g
         uHBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JXHMChCIItx2uJLyWLzPDHhP5JixxiVA29nzmmc5DN6KhFaL8
	MEft9L0PPaegXqXc6cmZ0ZA=
X-Google-Smtp-Source: ABdhPJz4i//IKHQdyeMY13Ihzq7cOgXJpMW3GUofjnPSA3Isah8Fa7G+L00Tbdxh2Q1W/b9+wdO1Uw==
X-Received: by 2002:a17:902:e74b:b029:ed:8636:c532 with SMTP id p11-20020a170902e74bb02900ed8636c532mr22686360plf.51.1620073523251;
        Mon, 03 May 2021 13:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7e1c:: with SMTP id z28ls5660608pgc.3.gmail; Mon, 03 May
 2021 13:25:22 -0700 (PDT)
X-Received: by 2002:a65:48c5:: with SMTP id o5mr19885856pgs.101.1620073522726;
        Mon, 03 May 2021 13:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620073522; cv=none;
        d=google.com; s=arc-20160816;
        b=X5xnjKA1Uo6A4tgla5XWXIfOu3Af22pEk5koCD8gP05JYJdvK5qzMwsgz0t88O15Nx
         arfNbU4/bKyIh6j5Zy+RCHgW5oyKSDr1pb7/zQH8A5CAKWENvnc4nTja1EnTFNDypk6I
         w9I9QvyYODY0Fv72/OpAyHup7B5WFXtosxqGIBhtA96NOsCnZ8LguJHrKouG5Nx9yCyE
         R74WTZnBG/HBlOCDTx+AzA8L0mWIl1swJOA0OxlJzlyekpAG28r8KqGjM4Jc1Q1XdPqa
         hx8J2fimHHTCGNfEQDKZ1D/kMUHOha+rei5d4HvFTjpxEbrtec5q+iuTXwQ95VIIqkhb
         bqSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=fXOXunkdkKH9V6YsV+KbqwvPHFtbzEbPktEQuSJNipA=;
        b=nVmoS23Nm6M2oSkt1CixHU8+JvxNFSOJr3VnFdl4Kl/DS5S7+NJqkyCACYMOGrARH4
         uDoodY3uxEj//BN4d9k1dYkp6YOXGiPBK5WxGbinzZr8L4A2fHQXcCaEV2iGPH7EtAje
         yTFFMTz+ma7VSMkZjJXMspOeuQL/wLvwhvoTDC22WcstN2vOqaIHD3dYuklL4Opk6zQF
         1UguSyu0/QSMTfDCdovGaUxAA/xUkVYpAFJQMceB3+trbK1PPPUNkPxjRo4WteH10EPr
         sK2BB/M+HwIdHptzk9abMFy0WIgObY0Rn1J8qxgww+lT7UcXMCvu5JCpM9K3EW5OtZz6
         An5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id b17si83504pgs.1.2021.05.03.13.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldf84-00HHMf-1u; Mon, 03 May 2021 14:25:20 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldf82-00E4Fb-WD; Mon, 03 May 2021 14:25:19 -0600
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
Date: Mon, 03 May 2021 15:25:14 -0500
In-Reply-To: <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
	(Marco Elver's message of "Sat, 1 May 2021 18:24:24 +0200")
Message-ID: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldf82-00E4Fb-WD;;;mid=<m14kfjh8et.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18lnlSrS5P8asB0qraFg/G+UpSTOXbUemI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa01.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.9 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,XMNoVowels autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.2685]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa01 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
X-Spam-DCC: XMission; sa01 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 537 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.0 (0.7%), b_tie_ro: 2.8 (0.5%), parse: 0.71
	(0.1%), extract_message_metadata: 2.9 (0.5%), get_uri_detail_list:
	1.47 (0.3%), tests_pri_-1000: 3.2 (0.6%), tests_pri_-950: 1.04 (0.2%),
	tests_pri_-900: 0.83 (0.2%), tests_pri_-90: 210 (39.1%), check_bayes:
	209 (38.9%), b_tokenize: 7 (1.4%), b_tok_get_all: 6 (1.1%),
	b_comp_prob: 1.62 (0.3%), b_tok_touch_all: 191 (35.6%), b_finish: 0.64
	(0.1%), tests_pri_0: 301 (56.1%), check_dkim_signature: 0.39 (0.1%),
	check_dkim_adsp: 2.2 (0.4%), poll_dns_idle: 0.85 (0.2%), tests_pri_10:
	1.71 (0.3%), tests_pri_500: 6 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 00/12] signal: sort out si_trapno and si_perf
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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


This is my attempt to sort out the ABI issues with SIGTRAP TRAP_PERF
before any userspace code starts using the new ABI.

The big ideas are:
- Placing the asserts first to prevent unexpected ABI changes
- si_trapno can become an ordinary fault subfield.
- Reworking siginfo so that si_perf_data can be a 64bit field.
- struct signalfd_siginfo is almost full

Marco I have incorporated your static_assert changes and built
on them to prevent having unexpected ABI changes.

The field si_trapno is changed to become an ordinary extension of the
_sigfault member of siginfo.

The code is refactored a bit and then si_perf_data is made a 64bit,
and si_perf_type is made distinct from si_errno.

Finally the signalfd_siginfo fields are removed as they appear to be
filling up the structure without userspace actually being able to use
them.

v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org

Eric W. Biederman (9):
      siginfo: Move si_trapno inside the union inside _si_fault
      signal: Implement SIL_FAULT_TRAPNO
      signal: Use dedicated helpers to send signals with si_trapno set
      signal: Remove __ARCH_SI_TRAPNO
      signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
      signal: Factor force_sig_perf out of perf_sigtrap
      signal: Redefine signinfo so 64bit fields are possible
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
 arch/arm/kernel/signal.c                           |  37 +++++++
 arch/arm64/kernel/signal.c                         |  37 +++++++
 arch/arm64/kernel/signal32.c                       |  37 +++++++
 arch/mips/include/uapi/asm/siginfo.h               |   2 -
 arch/sparc/include/uapi/asm/siginfo.h              |   3 -
 arch/sparc/kernel/process_64.c                     |   2 +-
 arch/sparc/kernel/signal32.c                       |  35 +++++++
 arch/sparc/kernel/signal_64.c                      |  34 +++++++
 arch/sparc/kernel/sys_sparc_32.c                   |   2 +-
 arch/sparc/kernel/sys_sparc_64.c                   |   2 +-
 arch/sparc/kernel/traps_32.c                       |  22 ++--
 arch/sparc/kernel/traps_64.c                       |  44 ++++----
 arch/sparc/kernel/unaligned_32.c                   |   2 +-
 arch/sparc/mm/fault_32.c                           |   2 +-
 arch/sparc/mm/fault_64.c                           |   2 +-
 arch/x86/kernel/signal_compat.c                    |  20 ++--
 fs/signalfd.c                                      |  23 ++---
 include/linux/compat.h                             |  38 ++++---
 include/linux/sched/signal.h                       |  13 +--
 include/linux/signal.h                             |   3 +-
 include/uapi/asm-generic/siginfo.h                 |  57 +++++++----
 include/uapi/linux/signalfd.h                      |   4 +-
 kernel/events/core.c                               |  11 +-
 kernel/signal.c                                    | 113 +++++++++++++--------
 .../selftests/perf_events/sigtrap_threads.c        |  12 +--
 30 files changed, 402 insertions(+), 191 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m14kfjh8et.fsf_-_%40fess.ebiederm.org.
