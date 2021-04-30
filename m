Return-Path: <kasan-dev+bncBCALX3WVYQORBRVOWKCAMGQEZDPNO3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A1C7370438
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:48:23 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id k13-20020ac8140d0000b02901bad0e39d8fsf6398270qtj.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:48:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619826502; cv=pass;
        d=google.com; s=arc-20160816;
        b=gQ5eNaAlNmbzvOit78StHNiPNabFWDuL0e+QfDj5Ir3NVljwdn95jEC5Le/o9f33gO
         8XgSPqllbr/i7N18w5JdAOMqVZhXVVZARexUB+PicU/lsfFJ2mK8nH1xkMuPZV46HglC
         ixYH4DwDjRQzwyeJ1Gn7TPkhwcyQyO2sg9JgXIOYYY9IRUrcnZ0oA89JFoOAzAl7HrId
         UvxSnJwi/hcWzvinK9MpFj+g8nqnAGAdTyHLUuLzg+dnhATNJDxUYTM6YzRtqvdDVvAW
         hNGcsglW609TTZqjAjAsHz3HAY9KPrPJtkVuDixICOEmG2cNM+odKnVqrI82Og9V6A9q
         JBBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=Pit4xvd6K9yZn2ampH++6zXuUPpPlYmv63ADW3BAMzU=;
        b=bXnP31oP4cv5wjo/70VrIV/s5CDtU1MIMbEmdKK1pNsbvsK52IkZMA3xqLJWxiAps0
         qFbl1ktjIIiHEBCpFZXxojVaY3iiYmZd81J8ccvfcGPrBqq0LW9zsSVV5arnWfFfJb9z
         h9T1qYhWA8acwiD5O0vAs8NeYHLN/glIvzNlvJCyvfLuP5aS7d3tDqDGc7m4x3yhtr8f
         GTaCAj0goDp6oFK/H+mW4Hbx0Bb6zZgOReWkm5F7TG5Egv1ilAdU6qnN3ZwypJUalqO1
         lcy5Pui4RylZoBz7Y/U1RLUtqfrk9dtjw1JicVHJKBLANXSgjOoJK2CK7D88M0ZXRh3h
         104A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pit4xvd6K9yZn2ampH++6zXuUPpPlYmv63ADW3BAMzU=;
        b=CLvJQiZAL1OGBY8Jwhnoba7pNuVpPC0SwsJjYFosVldrdy/AHfuerh0ePEX9zGkU9N
         ILWFIvrRMxjQUyICnN2accHd+A5cXB3FGXojJ/JYLkJNPLVLnffRGdgLCzaiLCpoZirX
         M1wjuGU4o24IqDlzt3J84WPOtZWGoevEyO/5CqMw8gzeW6Sb7En4cn3DzrFHDv8rqXqJ
         cIBMkLvxFCPjZul6L75VvLdfGNKh9EjV1XaMc0xJk/UR12v/gdJNjnuxI8mQZ1EsHZ/z
         U0z14PbLcNLEfeV153hpo9OcT85/0TU4NOWE0zb8ZK0Ox3kgHxYO+pZS5wxfVGFFLCXJ
         L9Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pit4xvd6K9yZn2ampH++6zXuUPpPlYmv63ADW3BAMzU=;
        b=gFuqQCk2MEUaiH9aZs6hDeY8t7aAbWoD6W218Nz4L4xBptBqNuTIFTIS2oOp9AY9gP
         MXkhxsmxu14ORlMfcfS7P8VRQfH0QF9XEqpXwQCAhyIaQRJ3Q74sZdkrfP4J7+GXhZBm
         Tn2J57erBOeW1OH2KHbApVk5UjtBej83IAuzt8sRdY+/GTjM/ejCLp67gVe55F2DbO/e
         7ZVkUkAmcvnMhxuDe9v51Tlh8NqDmVi5PY0OBT90TSZPhz2qDMaBTZlSi2D94yR83rgo
         Gi2ZUgDHOxwWApLOLdlW9lG8nm7yhVCng80bm7QyA8teCZhSneu6sja6uFv2xvQnUbPn
         t/Ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jypCtGWJWBKETGq2YO6xWWYtQhsHpXiLAwnXdV9RbSFeCw5Lw
	eg84IJUKA4jmhaL2Yq0tRi4=
X-Google-Smtp-Source: ABdhPJzsZyolXPGtzAyHdt0NkWkK+u1iDjLSvmCF9mLlDWXX7r/AIou+SLn9azlR9OEYmH8AKHnS8w==
X-Received: by 2002:a05:620a:66a:: with SMTP id a10mr8236117qkh.272.1619826502569;
        Fri, 30 Apr 2021 16:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4446:: with SMTP id w6ls1932225qkp.1.gmail; Fri, 30
 Apr 2021 16:48:22 -0700 (PDT)
X-Received: by 2002:a37:ae85:: with SMTP id x127mr8072662qke.436.1619826502148;
        Fri, 30 Apr 2021 16:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619826502; cv=none;
        d=google.com; s=arc-20160816;
        b=AxhNyrcnFxAXmHA9xKq6+F6FOVlfPmv5+ZENxSXZ+pskKdnYLsH3anQCBQ90hRu6Mi
         +RuOU4ZxtfGZtMaLXomh9hqGWMujKhJvB5PV/urcgeQT24/MC/69mqqQwycxhTr4hjIT
         LrG/kqq8nXGnpYjz1HmxXUaAzKtrdtfh/IDQpv5Kjn/yMVAJZ1Ze7pwEMlcmBrJXYXOo
         kjDFUiQcDtrUpBRfBwu/fgIjhryc6e/EOVukP3K1K17St/AYWY/wBz6VZ4fHDb865K+G
         fA1cam19/ZA0SdCeB8Wt27jKzmHLQ8yjSdVCwYTHMd+ZK4mPHylrFgwLcejtKuNtJv/F
         dZdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=7TfPLs6hKGxCVJ6nkokWQzahHfn6nJxZ2cC42HDDRQU=;
        b=husQvAHm3kA6AbydOZNXGfRxeTkYlIzQKAXll5GyezLgpR1v7dpmdnucDXlHMtDG3L
         XPlbZwYXbt1Qg0g2W0lCMjvc9+KLXkldSsJjhDQrGkEwq5j6MCqIVoTGhv+kerb+eNLX
         wLmLEYsTMkuoyMXueVcSNh3c2DvQKnjP1mn372nFNFiVU3+gvyvKsZGwuQU7POkOy4L9
         t4D3+o3h4EvaWJCdvFM9EUSIyNhmm0XuG/P0SU2opCCl0NcsgR1Ayb1NGV+qJpqvKW0s
         CkAk5yd8B+PCF+BmLH86ND+Ha6Uuoxou1aKZodHMZIu6SZmnnHpAR0g4fbGWcYZg9q2f
         f3ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id y8si574237qti.5.2021.04.30.16.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:48:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccra-004FDQ-6Q; Fri, 30 Apr 2021 17:48:02 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccrY-007K7B-6o; Fri, 30 Apr 2021 17:48:01 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:47:56 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m1r1irpc5v.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccrY-007K7B-6o;;;mid=<m1r1irpc5v.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/ymAofLNxA6qk5cQWTdhMdZa83kQdvOUU=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.7 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,TR_Symld_Words,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01,T_XMDrugObfuBody_08,XMNoVowels,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.0820]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.5 TR_Symld_Words too many words that have symbols inside
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1371 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 11 (0.8%), b_tie_ro: 9 (0.7%), parse: 1.07 (0.1%),
	 extract_message_metadata: 3.6 (0.3%), get_uri_detail_list: 1.30
	(0.1%), tests_pri_-1000: 4.5 (0.3%), tests_pri_-950: 1.21 (0.1%),
	tests_pri_-900: 1.04 (0.1%), tests_pri_-90: 93 (6.8%), check_bayes: 91
	(6.6%), b_tokenize: 8 (0.6%), b_tok_get_all: 8 (0.6%), b_comp_prob:
	2.1 (0.2%), b_tok_touch_all: 71 (5.2%), b_finish: 0.81 (0.1%),
	tests_pri_0: 1234 (90.0%), check_dkim_signature: 0.50 (0.0%),
	check_dkim_adsp: 2.2 (0.2%), poll_dns_idle: 0.58 (0.0%), tests_pri_10:
	3.1 (0.2%), tests_pri_500: 9 (0.6%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [RFC][PATCH 0/3] signal: Move si_trapno into the _si_fault union
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


Well with 7 patches instead of 3 that was a little more than I thought
I was going to send.

However that does demonstrate what I am thinking, and I think most of
the changes are reasonable at this point.

I am very curious how synchronous this all is, because if this code
is truly synchronous updating signalfd to handle this class of signal
doesn't really make sense.

If the code is not synchronous using force_sig is questionable.

Eric W. Biederman (7):
      siginfo: Move si_trapno inside the union inside _si_fault
      signal: Implement SIL_FAULT_TRAPNO
      signal: Use dedicated helpers to send signals with si_trapno set
      signal: Remove __ARCH_SI_TRAPNO
      signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
      signal: Factor force_sig_perf out of perf_sigtrap
      signal: Deliver all of the perf_data in si_perf

 arch/alpha/include/uapi/asm/siginfo.h |   2 -
 arch/alpha/kernel/osf_sys.c           |   2 +-
 arch/alpha/kernel/signal.c            |   4 +-
 arch/alpha/kernel/traps.c             |  24 ++++----
 arch/alpha/mm/fault.c                 |   4 +-
 arch/mips/include/uapi/asm/siginfo.h  |   2 -
 arch/sparc/include/uapi/asm/siginfo.h |   3 -
 arch/sparc/kernel/process_64.c        |   2 +-
 arch/sparc/kernel/sys_sparc_32.c      |   2 +-
 arch/sparc/kernel/sys_sparc_64.c      |   2 +-
 arch/sparc/kernel/traps_32.c          |  22 +++----
 arch/sparc/kernel/traps_64.c          |  44 ++++++--------
 arch/sparc/kernel/unaligned_32.c      |   2 +-
 arch/sparc/mm/fault_32.c              |   2 +-
 arch/sparc/mm/fault_64.c              |   2 +-
 fs/signalfd.c                         |  13 ++--
 include/linux/compat.h                |   9 +--
 include/linux/sched/signal.h          |  13 ++--
 include/linux/signal.h                |   3 +-
 include/uapi/asm-generic/siginfo.h    |  11 ++--
 include/uapi/linux/signalfd.h         |   4 +-
 kernel/events/core.c                  |  11 +---
 kernel/signal.c                       | 108 ++++++++++++++++++++++------------
 23 files changed, 149 insertions(+), 142 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1r1irpc5v.fsf%40fess.ebiederm.org.
