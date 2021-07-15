Return-Path: <kasan-dev+bncBCALX3WVYQORBGXUYGDQMGQE5CFBNVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD583CA4FF
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:10:35 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id b10-20020a056a000ccab029032dc5f71f6asf4877825pfv.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:10:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372634; cv=pass;
        d=google.com; s=arc-20160816;
        b=t4r8Pr3Bkehp+NZBm6O54oorjxNWkBlOFpb1ToTsKugKb+gvjKhI0//jO6Kr69GZ/J
         4dEPx0Als5Io6SArsEIgDcfHLFy8Q2rR3XBryCpkLHNyBvo0hRC7LckUKPWADZN/MaMR
         Ucs5UhDvb7kGukMTxG3Qj+39b0q65K6CSeHkdgrZ5BwOsWLLjLxwTJtOC1BYvI9vYC87
         V6KRldX02BRJLZQfYExUsw6ZnjCDXFDx+LgEK71BvFQuz0sHP90p6UzXP2QXwqRsHx70
         kw6MGUGbNbxmGWsW4VvP/4xSPUuAQgfOwwBl5r2jE2r9vU9MaR3UivsfAvPodst1Lyi2
         XH3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=zO+FG9dEs4qp9yLeYFp2W16fPPUCIBNTsAviNgu5vr8=;
        b=yNzGZQglJJCZHx1mKJf0i6aNItd3L/GYsC5uPNNrGaJTjT95uKAuo3GtoeHWVoFo9S
         uUYJN5Y2/MDY9j0zpm0CltEp4G4iS3QZ2OkYrVfLf22ibB8cFTSMm4m52qunbGT0doPn
         4K9B1HfjSCVtpaanU5uPCWEVxkbCDD3U/gBvJL6fKVTcUFOp9vd1poGI2zw/Fq4BxQ5S
         Uwxs/UpDb5r8+eAvLQBsIJsIIrWaoVNjG5dL7g9ZLIMc0ZBhl77QcNMrg1b1Ukd/myRc
         Z8Wg6y5nsG62eoAyHSXSKpOmIns2aisXeW70CWPEwob4943KLxQjfa0N1lAN30V3II4N
         8QyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zO+FG9dEs4qp9yLeYFp2W16fPPUCIBNTsAviNgu5vr8=;
        b=nMYauyf/H43tcdnaLcShpjFGRjLJTjtKvThLlwD1aWvj1Yvjaku242A2jYbW2eMUnQ
         w7q1VkCvE/kR9kkIP1MQxmTZSvg5wb4ht16Z69tKL2pv7Aj81w4Sj1TQL3+qU+k9kaXt
         yTmLoKtW/ho7Ln1nWkc7sjHObHgGSApkJ+71tfcaqJndpXFa0/C5/gtqPQs4t6fyxeBf
         Enrrnx6HyHXph6Y8Ba161LgUQ6lPu3kgB6ION8zxOwZ4w0NxQ3lOqGxzcoILZ+ojCwj9
         upxcDVk2rwWvLyHAR/KOzFZncB/81NsNAumrLFN+bAI34ZnCOjBxAPDDz894RRXgTDog
         KX/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zO+FG9dEs4qp9yLeYFp2W16fPPUCIBNTsAviNgu5vr8=;
        b=qQ7RGyee41aU7E/MAo83atID4eLotq0SHd6+u/GmcMZJijvZ8AXS8wZHLLfflUBicR
         JU8osuYFoKCz5a4sGTo+tgEv4VCsrBIIFQyEn9rL0eVLf8vr0bAS7U94IxvPmrOdI3Qs
         cudv4BPGf5YnIbbBc0VfHVRFFFxm0VMJvw5DYLUmxkAR+XeYeOInskWnlY5IrAttqdDK
         RhY/mIF5QIouRRs0qbrG8xjXN4rjGmLvEzl7/IP7XAF2QvOLVSrfikkDA+yuyOKStpEW
         mUoZu0cJzk57b7mVtiuzpf5ri4T4rILg816L6PSCpUFS8+QHqTANFxyrt+yYVTOdmEBK
         Xb8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330iLzoMkeRvxknj1bvS8pkD/QSPrRiKqWQ6NcYO4ujgEnNi6GF
	47mAPuEfCE3uLzfdm8WWARo=
X-Google-Smtp-Source: ABdhPJxgVaHaXkrHODJHz8Lo41QgkDR3Gp3vdYxYNo2/ksJBRv58caY8ODb6+cDL9TV2zDCvaGajJg==
X-Received: by 2002:a17:90a:b398:: with SMTP id e24mr5382966pjr.151.1626372634559;
        Thu, 15 Jul 2021 11:10:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls3438667pgv.7.gmail; Thu, 15 Jul
 2021 11:10:34 -0700 (PDT)
X-Received: by 2002:aa7:8254:0:b029:2ed:b41:fefc with SMTP id e20-20020aa782540000b02902ed0b41fefcmr5882156pfn.42.1626372634007;
        Thu, 15 Jul 2021 11:10:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372634; cv=none;
        d=google.com; s=arc-20160816;
        b=M7K6xbhhzaPGkbwU0StOVeWHDZhP3ASsYbSSZPZ2QbTjUXynPuF4XQOwi22jdD8MYa
         EobgpSZgRe0kep2IEv3///twmo6ZHZEJgTppT7uUWXklOCpLR2TVSi2UiDlYmAkiQDrs
         lreaYn5szdk3x1iwU4hu/r+jfMuKBvh1PtpYaIUmE7SXR5K2/6Fk0aOTV+J7qVKaxjqo
         JA2eEZ5q3S/FhcfkbmWBKuGPDshsL/9QmO/un5kstrslkRSRUzFTgCYe/u4WC9BhyYAO
         9sWV72p+Ao+ynUjw3mxP77wtRHtz/qJEtS36tJnJNlolV4mGF9U3YysjWJSAlf+hp1vQ
         3MPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=Ww5AWcoKsbcCMvlAL16IO8d1awsCCUxNrPPkOWqNm6o=;
        b=0KCLfHmBemnFY8GJP7ndbeMe0AxVthkF22YrnrTijDbuwaALZ3K7Mrkn4bdH0eo2Po
         msHJE+fwLZ0rjggHSEVWYrkXu3IBc2CvVbDBAAZf0TX1p3TudRSjaE2KccoL+Kr6CLdh
         tBAnnIrlHh1BRl/JtelygvGb3dxQfVQwrOlJekEAcFPgMUm/ZaYhMtsYnepCtQ63Y+xk
         ziUWIhnLAnAe/q4pPp6TExDb7zQ7T6Q7hQousxR0ZyKe3+S4N2+4xI2TVw7V9wrYpSXb
         Uy8KADKbo+82iu1fGcVhTTzCHYX7pyUkBpXDkBErbTBElKDR5fIhhRA3nbN5wtpUby1G
         VrNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id q7si927039pgf.3.2021.07.15.11.10.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:10:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51]:32868)
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45oe-0027Qn-3X; Thu, 15 Jul 2021 12:10:32 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:56964 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45od-00CSsZ-3J; Thu, 15 Jul 2021 12:10:31 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Thu, 15 Jul 2021 13:09:45 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <87a6mnzbx2.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45od-00CSsZ-3J;;;mid=<87a6mnzbx2.fsf_-_@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19QOntclRPIA/u9ynQgdmZ9S2p6E+o6EFA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa02.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=8.0 tests=ALL_TRUSTED,BAYES_05,
	DCC_CHECK_NEGATIVE,T_TooManySym_01,XMNoVowels autolearn=disabled
	version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.5 BAYES_05 BODY: Bayes spam probability is 1 to 5%
	*      [score: 0.0415]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa02 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa02 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 428 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.6 (0.9%), b_tie_ro: 2.5 (0.6%), parse: 0.71
	(0.2%), extract_message_metadata: 2.6 (0.6%), get_uri_detail_list:
	1.07 (0.3%), tests_pri_-1000: 2.6 (0.6%), tests_pri_-950: 1.03 (0.2%),
	tests_pri_-900: 0.83 (0.2%), tests_pri_-90: 88 (20.6%), check_bayes:
	87 (20.2%), b_tokenize: 7 (1.6%), b_tok_get_all: 7 (1.7%),
	b_comp_prob: 1.62 (0.4%), b_tok_touch_all: 68 (15.9%), b_finish: 0.82
	(0.2%), tests_pri_0: 312 (72.9%), check_dkim_signature: 0.40 (0.1%),
	check_dkim_adsp: 4.6 (1.1%), poll_dns_idle: 1.21 (0.3%), tests_pri_10:
	2.9 (0.7%), tests_pri_500: 8 (1.8%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 0/6] Final si_trapno bits
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
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


As a part of a fix for the ABI of the newly added SIGTRAP TRAP_PERF a
si_trapno was reduced to an ordinary extention of the _sigfault case
of struct siginfo.

When Linus saw the complete set of changes come in as a fix he requested
that the set of changes be trimmed down to just what was necessary to
fix the SIGTRAP TRAP_PERF ABI.

I had intended to get the rest of the changes into the merge window for
v5.14 but I dropped the ball.

I have made the changes to stop using __ARCH_SI_TRAPNO be per
architecture so they are easier to review.  In doing so I found one
place on alpha where I used send_sig_fault instead of
send_sig_fault_trapno(... si_trapno = 0).  That would not have changed
the userspace behavior but it did make the kernel code less clear.

My rule in these patches is everywhere that siginfo layout calls
for SIL_FAULT_TRAPNO the code uses either force_sig_fault_trapno
or send_sig_fault_trapno.

And of course I have rebased and compile tested Marco's compile time
assert patches.

Eric


Eric W. Biederman (3):
      signal/sparc: si_trapno is only used with SIGILL ILL_ILLTRP
      signal/alpha: si_trapno is only used with SIGFPE and SIGTRAP TRAP_UNK
      signal: Remove the generic __ARCH_SI_TRAPNO support

Marco Elver (3):
      sparc64: Add compile-time asserts for siginfo_t offsets
      arm: Add compile-time asserts for siginfo_t offsets
      arm64: Add compile-time asserts for siginfo_t offsets

 arch/alpha/include/uapi/asm/siginfo.h |  2 --
 arch/alpha/kernel/osf_sys.c           |  2 +-
 arch/alpha/kernel/signal.c            |  4 +--
 arch/alpha/kernel/traps.c             | 26 +++++++++---------
 arch/alpha/mm/fault.c                 |  4 +--
 arch/arm/kernel/signal.c              | 37 +++++++++++++++++++++++++
 arch/arm64/kernel/signal.c            | 37 +++++++++++++++++++++++++
 arch/arm64/kernel/signal32.c          | 37 +++++++++++++++++++++++++
 arch/mips/include/uapi/asm/siginfo.h  |  2 --
 arch/sparc/include/uapi/asm/siginfo.h |  3 --
 arch/sparc/kernel/process_64.c        |  2 +-
 arch/sparc/kernel/signal32.c          | 35 +++++++++++++++++++++++
 arch/sparc/kernel/signal_64.c         | 34 +++++++++++++++++++++++
 arch/sparc/kernel/sys_sparc_32.c      |  2 +-
 arch/sparc/kernel/sys_sparc_64.c      |  2 +-
 arch/sparc/kernel/traps_32.c          | 22 +++++++--------
 arch/sparc/kernel/traps_64.c          | 44 +++++++++++++----------------
 arch/sparc/kernel/unaligned_32.c      |  2 +-
 arch/sparc/mm/fault_32.c              |  2 +-
 arch/sparc/mm/fault_64.c              |  2 +-
 include/linux/sched/signal.h          | 11 ++------
 kernel/signal.c                       | 52 ++++++++++++++++++++++++++---------
 22 files changed, 276 insertions(+), 88 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a6mnzbx2.fsf_-_%40disp2133.
