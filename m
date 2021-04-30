Return-Path: <kasan-dev+bncBCALX3WVYQORBEMTWKCAMGQEUWA5GEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 027FA3703B3
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 00:49:55 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id b1-20020a0c9b010000b02901c4bcfbaa53sf1628999qve.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 15:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619822994; cv=pass;
        d=google.com; s=arc-20160816;
        b=0m3wqQQBr8Rwlmjl9b0EVP2WAXgnj0rd6Q4+NCj8jvcMyZVhlpsuZu3MckMP0k7PIz
         zl5tG/O1v4Xza2EuKi60j5K19KUTOWHlWJZESmM1/WiPJgYthJQVmvaKGEaBTsGeC5Pm
         4SrXEwGy6iG46LBzS7QOnNKQLb3ssUXQo/2t/Z6SbCh60/UzPPwqCfqtftd0rGGQ4JwM
         AtsItf/btKMWvMlPCIuhYFYYVBX6HVFyyxOPNzHZLj2k3yd/VholZmujmxqUHT7msXVJ
         6pwqFN2rxVxF/zBeG9Q5se3VLaQbuI8/EhtEPFzLjPYk3W+U732INwvB5ywJtW9AQ/1+
         s5Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=sf2i0hHtHkXuj62T954WOkdJMMUpwNcuYACyg2AVDno=;
        b=INud0iRIOmC/MD4SQLHJgTLT+MoVbARqk+nBxTt/Mh/l51PqQYlYfPmWi7i0gORYGe
         YDRY0hlCw7YSCXKEtQ9ekpHqRXdI1jaExzrMz2AUv62B5ULAagnrXTsN2NMOmteY6CQb
         6xNbfD7mMeA7+kD11jVlmn+KbmlRQSlSWt3IjHNhsoOApzTK58Vlniu64IBDtJe3YUZz
         HJtISDhcNgpLb353Z9DaRJI/I6wvAvk8XjvbOqkY5GNyQ5oings5ETFvNmysPSKaZ+Mh
         JVRpEyPQ73zYwQ409MWw+Zqn/IScu8ng/tJsM9PiBP+HuOBaU15qf0vwdN1mjf2Gj2ul
         9aOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sf2i0hHtHkXuj62T954WOkdJMMUpwNcuYACyg2AVDno=;
        b=BZ0caN3i0hrejJXu0I4xUWPhuXFWe1yNxQZ6tA+/yguzdqFXbqvplCZDnb+P4gQOEH
         pqdzsUjrQWG6zbBt8/MYRxG/D/D8XVWXwd1zRc0KV3fAIYXpRjRKLRhN65mK5LRZvqad
         zmO2wuFDGeN9rSPsgorBUNm5dyTLOZaeDUqxqRJB8gfUfH+WI7a+X1ikGAQg2RRgk6ZN
         bvhh39cRJ7dFmjRyfg9lBmxNmrJPqwRaezrqhVNuSdJqaJCrPOfJ1zpm5JTc+nVVXCjK
         WY78iKayAm0cGJHaGWUmXJoKg2r4zkh/KZj/gZxzpTSmcu8xGeGabUGWDsbyJhbW6sCR
         Loxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sf2i0hHtHkXuj62T954WOkdJMMUpwNcuYACyg2AVDno=;
        b=IbNHaAcWo0L/d7GdwZ01s+8m6wDnWHfe0J44CynTXxDa/CpTKbTb16FD6i45BClb6X
         OcBMiarIyzk+OGWo1tSa3bvcyVNDNu3f0OvImiv/EmreUacGA4vP0nTWIADL6S6uyRDr
         hndT9EYE769+1CoWCGgqmI2t0iO/MOFP2IH+nmWfVir00D4dFwjK5G72GVkvoWX/9ZMr
         oGjJiaPjtKLKUENMODl3YozhaVWjs5YFmknILE4hw/QCWOCGlU7Y3+sX4pOy9ZRnQfCD
         4UbwZGibTOFJSVMGSx/puPZ0kT6vOf3MMUZwKgNdh7SRVydSU4zzKN5GKep2vNIRASUd
         8RPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BvZ467nYgzXnEbXJDUi9DoqnLGH+05GkzVdLJYlDu9Mvle/nY
	ZxTwSvM03wjpKcKitYTr5+w=
X-Google-Smtp-Source: ABdhPJzBt/iazc0oDERyKN5c5ePnN0BE1tVTMnvuMHOdST6jeZXVMniDHkcVtG5/ONwscovPwV7cWA==
X-Received: by 2002:a37:9547:: with SMTP id x68mr7821052qkd.474.1619822993970;
        Fri, 30 Apr 2021 15:49:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e652:: with SMTP id c18ls2356885qvn.9.gmail; Fri, 30 Apr
 2021 15:49:53 -0700 (PDT)
X-Received: by 2002:a0c:9ae9:: with SMTP id k41mr8188321qvf.40.1619822993593;
        Fri, 30 Apr 2021 15:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619822993; cv=none;
        d=google.com; s=arc-20160816;
        b=xUMcx/RnRICsB4OIBIG6DlZO52CMDPkOBrER8RYuknkZUV34ogB9AmpPrGGrSdRcXA
         ljByjWU4zv0tWP20vFuuEjdwPVju4bn4uP+FtdvmWtcrnHIm5TeCNTOCTEHQ+XXlR9X/
         AXeHF1GIuqQh45akTLGguTrEm715P6aCXAwEd9UHq16rDzhQgr9cV+JQBVTTpScwddkv
         vWjnxQMHi4gMpTHWXSPSih8npu7vEQrO4xtCFoMO4vFmXocIxsztjJVz3Nj7/COhr0rI
         7TKDO4+0MuvM8+/SK4Yw0mAfHp+6cTfyKTTHQag2trXF2MgfnnkvtQ5Xvvjh2cBvReHS
         xeHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=VPsKUXX+eMdF5gXemtftD/HiLoa5jxtxJtxijU0t9w0=;
        b=MTxFI0vqh/CNj+u1uXlBONR0TN9LbMpE0CsFnmClojQv96lHIgEud1GHefLZcRCZ3B
         PdGaMw2JOxF4UkchimUM0uJVnCcDBUAYEbW7GyBF5qnWzp+fyD3iJcRg8ph1uUyv455U
         ZSKrjLPdiH0zVX5pP/LcmUwZLEks6UtS5vpzHD5kn01a7XeprPnfKGJAfqYJGytFhcAZ
         aQ0hhZiceDwvgb9gyB3iWUIOBCAfnmlyULg6CHJBbKxZ6etET2Zbd88pnc7lB2tE1Q5Z
         zP2XAFPG1rpZOj7gLmFCfAY7jCn9zR6Wu/Db5XrG7OLr9RDxmc0aSLqu1DPRcRPND1u7
         UuJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id g22si715493qtx.4.2021.04.30.15.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 15:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out03.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcbxF-004Atp-LD; Fri, 30 Apr 2021 16:49:49 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcbxF-00038q-0D; Fri, 30 Apr 2021 16:49:49 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
Date: Fri, 30 Apr 2021 17:49:45 -0500
In-Reply-To: <YIxVWkT03TqcJLY3@elver.google.com> (Marco Elver's message of
	"Fri, 30 Apr 2021 21:07:06 +0200")
Message-ID: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcbxF-00038q-0D;;;mid=<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX194HKcbJ3hzROboO3aXmacGQftTa4VgQr0=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.7 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,TR_Symld_Words,T_TooManySym_01,XMNoVowels,XMSubLong
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.2038]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.5 TR_Symld_Words too many words that have symbols inside
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 317 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 11 (3.3%), b_tie_ro: 9 (2.9%), parse: 0.77 (0.2%),
	 extract_message_metadata: 2.4 (0.8%), get_uri_detail_list: 0.60
	(0.2%), tests_pri_-1000: 4.2 (1.3%), tests_pri_-950: 1.24 (0.4%),
	tests_pri_-900: 1.01 (0.3%), tests_pri_-90: 84 (26.5%), check_bayes:
	83 (26.0%), b_tokenize: 6 (2.0%), b_tok_get_all: 6 (1.9%),
	b_comp_prob: 1.54 (0.5%), b_tok_touch_all: 65 (20.5%), b_finish: 0.96
	(0.3%), tests_pri_0: 183 (57.8%), check_dkim_signature: 0.53 (0.2%),
	check_dkim_adsp: 2.6 (0.8%), poll_dns_idle: 0.48 (0.2%), tests_pri_10:
	7 (2.3%), tests_pri_500: 14 (4.5%), rewrite_mail: 0.00 (0.0%)
Subject: [RFC][PATCH 0/3] signal: Move si_trapno into the _si_fault union
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


Eric W. Biederman (3):
      siginfo: Move si_trapno inside the union inside _si_fault
      signal: Implement SIL_FAULT_TRAPNO
      signal: Use dedicated helpers to send signals with si_trapno set

 arch/alpha/kernel/osf_sys.c        |  2 +-
 arch/alpha/kernel/signal.c         |  4 +-
 arch/alpha/kernel/traps.c          | 24 ++++++------
 arch/alpha/mm/fault.c              |  4 +-
 arch/sparc/kernel/process_64.c     |  2 +-
 arch/sparc/kernel/sys_sparc_32.c   |  2 +-
 arch/sparc/kernel/sys_sparc_64.c   |  2 +-
 arch/sparc/kernel/traps_32.c       | 22 +++++------
 arch/sparc/kernel/traps_64.c       | 44 ++++++++++------------
 arch/sparc/kernel/unaligned_32.c   |  2 +-
 arch/sparc/mm/fault_32.c           |  2 +-
 arch/sparc/mm/fault_64.c           |  2 +-
 fs/signalfd.c                      |  7 +---
 include/linux/compat.h             |  4 +-
 include/linux/sched/signal.h       | 12 ++----
 include/linux/signal.h             |  1 +
 include/uapi/asm-generic/siginfo.h |  6 +--
 kernel/signal.c                    | 77 ++++++++++++++++++++++----------------
 18 files changed, 107 insertions(+), 112 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1zgxfs7zq.fsf_-_%40fess.ebiederm.org.
