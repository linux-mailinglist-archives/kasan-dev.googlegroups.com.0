Return-Path: <kasan-dev+bncBCALX3WVYQORBFHSY2CAMGQE755JMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 145BD3731CB
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 23:13:58 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id z12-20020a170903408cb02900ed5b2fa5edsf4942489plc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 14:13:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620162836; cv=pass;
        d=google.com; s=arc-20160816;
        b=XEEVuxLPQIE3JaJH9Jqsj6t1PSbVPx3rOy6C8XHtpXzNShMjC1oDed3/VbJ+qc+PrE
         lAksRV2EbGvjU7r/LfSYWi/xHo+NEQacnJ9xEv1+eO1lYMJr9AzlbqUaqbnBIDHwWFEG
         Csi6xSBNV1QbzBzuyq8iz9kNlaJu3+Pu1cKrUIWrDRRIEtxc1EfDpXxfXbz4av6CfQmP
         F3yV6PbeM7SLfVTAqQncs84RmvdcdhpdCm5MCzP0GFyF5OgbDpOz/9v0MMgSuBKzU8n7
         CDPmtnHFktJCQyvJoh4CkUqF1UizRNlv13GkOmkro9kLpdX/Ef9ifLJMgN/bgJDBP+2F
         PhDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=EiuZg6ks/zeUW6IB4izl0D9Xxz9TnxSFZwURhgHQO9I=;
        b=yqu2fARXmTzqpCk68yiVbzLI1ZGAKCjzjVfsBAGQMpzgZi3P3XQD1X4HqILPN4ZEQ8
         BE9VtjQ6btzTlhvH91vtmM3paSb2kLFFsKVz74PlTbyxTV8Nh7oYWwhO70prayBzLT3H
         ZegTMKn5c8tZdG7aWsqMCTLXhUewqzSDCjdXi1NS/og5tsF1VV/RiC4IL3wIQAGRiJ2L
         nBNCKpzmRHTxwRaTpcvGFXHCCpme2kblNb2o8g/VrC/jYjrTj8j2m5imgC4PA0dKGCF1
         YgvD2X/VR9uXI20YOhBDEnCJ9HAZxKT7ERbs6advx3DhNSlNZYkFDgYcdi3PfwHgLuF8
         P+FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EiuZg6ks/zeUW6IB4izl0D9Xxz9TnxSFZwURhgHQO9I=;
        b=kfKXLo1ccCWXZw9O4a8gdIm94hgWN0d9Qg8KJJwrysYrqBItdnV5Rq4m+s7FyuYhOq
         K8XSaEhEkL9zx4jLP/yVstPDV0kKKp/xkb5LDvsLuHhnoyaC/onNmKdoAfoq8vV/8doY
         co0iaNwLFNfdWPPM0H6T91/zw0rigjZAumLF4oqN5TwchIUfq46UfrwxosNWCAPNAZZg
         jTM3TYmqJVmUDZn+pZTnDPSp7ttwwxTZWI84cKmLaDptEadj8Gzi47yS/2FkfZSmcDk9
         7C0aVYqfShSVXzsbJtalxQirZXNX4nDsOP+1DttsO7usOgWvKw9bz19/7sDophiYeoz6
         hgBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EiuZg6ks/zeUW6IB4izl0D9Xxz9TnxSFZwURhgHQO9I=;
        b=GfCdFkBS10bDI9OBEI193uqLHX/ZLw4GlDDiFmk219itUiduqW5oVhgXI6RLro09RC
         qHqV26JYVqxVlX6X4SQEYh5JmBweShlcCGm5ZT+9d/t6vihlpBQrplV7Xo3s3xhGIqxD
         dp6emafZ7WzwkvAUjvNBHhLX4YSxhuCRW3WQDK2vdEBFMNFBbnU320ywCaTigaXte6mW
         V0aJx3y/iboBbLAh47pZQ/mnSBewTtJu9lfyxTGCqWnGCkrOQAZQRRDvHdE1yM2/WvQj
         6mL74UA9yh2ULstmdzV5zzgLWkWKd+B2SLiFixBkbdcC50slCq3VOIiLXjeMRhUOQFWL
         LQhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325UTecmSIEsw06n4N/8zoObK+ysbIDX8wQM7SaCtgeDKZwHc1q
	2cjnKxoLHXiZfljZELg4g3k=
X-Google-Smtp-Source: ABdhPJyXKkaMnt9kPYL9F9kX396a3i1tKa6psyq/pUHrgLtGOlL9ARXTNMdT/GzHqOkBhODTwwLK5A==
X-Received: by 2002:a62:754d:0:b029:289:11e7:4103 with SMTP id q74-20020a62754d0000b029028911e74103mr23696081pfc.25.1620162836814;
        Tue, 04 May 2021 14:13:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fb0e:: with SMTP id x14ls175630pfm.10.gmail; Tue, 04 May
 2021 14:13:56 -0700 (PDT)
X-Received: by 2002:a62:3892:0:b029:250:4fac:7e30 with SMTP id f140-20020a6238920000b02902504fac7e30mr25938549pfa.81.1620162836062;
        Tue, 04 May 2021 14:13:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620162836; cv=none;
        d=google.com; s=arc-20160816;
        b=LP5mzQFjEzaP6/8upcXiEmD5r92FMDI9iR8fDZGibug43v9Wj4gceHrE3B6mXzrxFo
         R3CPJpleJu72qVBBBB8/MvsAfgIztij+DS/HwI2DKfnCxNtqwFlL/Qx9w9zAusyvIZMC
         nkTLO5v12vPS/JhSPNDMiqIf2m2liDm5kTLTT58/wiUU/hxSVNN5arcbpObt5hQnzHTB
         LAoJtcIEiux+djB1xxUe0TQbgUoHEwtnvjeY0RKLVbFXeG3lgsQVrEBeBOkXofOt5gQL
         ND0/sFr3Y+0MBrVkjL7gJxeWwuAUHidSevZ5B2iiQrYoVUlA6pT0ssmEHtBB5yM9kRNv
         KgqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=IhjMgw04RGqhFiGBavtHi80cZg27f88mm87q/JGhnTs=;
        b=qfk6alNybFdFFlj1z/XyuJ9D4IIl0v04SahibCs/wKAPsqK0mXHkF8ks7GCcms1i4+
         7vSW3D5MALA5wYfoulnx6UoSRFUSz6tEc1QzUmnLiSWWTns8FoX/6bVeR+b+jfSTa0w8
         YnzrpuzcUcEaAJbw9OYu+pSMDUW/hlzgmVciK3JThTljX2T+O3bpWvTlx1ZAn6vs2xsh
         XMycVvbmoDf8sfoufxuhs7CtBlKHIEW6fhLNV+tseAShQzWD9z8VMeeT00fUQG12ziJy
         +ftQzcmCKJtmShqyAQgGX3HxpXx0tuxoGy1oK2OlFsVO7KUfog+HrJnfnI/4vymgSUoD
         mMYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id p8si318501pls.1.2021.05.04.14.13.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 May 2021 14:13:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1le2Ma-001fqZ-FW; Tue, 04 May 2021 15:13:52 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1le2MZ-00HGan-CR; Tue, 04 May 2021 15:13:52 -0600
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
Date: Tue, 04 May 2021 16:13:47 -0500
In-Reply-To: <m14kfjh8et.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Mon, 03 May 2021 15:25:14 -0500")
Message-ID: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1le2MZ-00HGan-CR;;;mid=<m1tuni8ano.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18t2On/7dJt0RgDhiKTS9M48FC5+jx0m4U=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.6 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.1758]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 470 ms - load_scoreonly_sql: 0.16 (0.0%),
	signal_user_changed: 15 (3.2%), b_tie_ro: 12 (2.6%), parse: 2.2 (0.5%),
	 extract_message_metadata: 8 (1.8%), get_uri_detail_list: 3.8 (0.8%),
	tests_pri_-1000: 7 (1.6%), tests_pri_-950: 2.1 (0.4%), tests_pri_-900:
	1.70 (0.4%), tests_pri_-90: 72 (15.3%), check_bayes: 69 (14.7%),
	b_tokenize: 14 (3.1%), b_tok_get_all: 10 (2.2%), b_comp_prob: 3.8
	(0.8%), b_tok_touch_all: 37 (7.8%), b_finish: 1.32 (0.3%),
	tests_pri_0: 333 (70.7%), check_dkim_signature: 1.09 (0.2%),
	check_dkim_adsp: 2.6 (0.6%), poll_dns_idle: 0.84 (0.2%), tests_pri_10:
	2.2 (0.5%), tests_pri_500: 12 (2.6%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
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


This set of changes sorts out the ABI issues with SIGTRAP TRAP_PERF, and
hopefully will can get merged before any userspace code starts using the
new ABI.

The big ideas are:
- Placing the asserts first to prevent unexpected ABI changes
- si_trapno becomming ordinary fault subfield.
- struct signalfd_siginfo is almost full

This set of changes starts out with Marco's static_assert changes and
additional one of my own that enforces the fact that the alignment of
siginfo_t is also part of the ABI.  Together these build time
checks verify there are no unexpected ABI changes in the changes
that follow.

The field si_trapno is changed to become an ordinary extension of the
_sigfault member of siginfo.

The code is refactored a bit and then si_perf_type is added along side
si_perf_data in the _perf subfield of _sigfault of siginfo_t.

Finally the signalfd_siginfo fields are removed as they appear to be
filling up the structure without userspace actually being able to use
them.

v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org

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
 include/uapi/linux/signalfd.h                      |   4 +-
 kernel/events/core.c                               |  11 +-
 kernel/signal.c                                    | 113 +++++++++++++--------
 .../selftests/perf_events/sigtrap_threads.c        |  12 +--
 30 files changed, 373 insertions(+), 160 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1tuni8ano.fsf_-_%40fess.ebiederm.org.
