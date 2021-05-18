Return-Path: <kasan-dev+bncBCALX3WVYQORBNPRRSCQMGQEIDSKFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A320F387055
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 05:47:02 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id g14-20020a926b0e0000b02901bb2deb9d71sf7939288ilc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 20:47:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621309621; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEghpqaRcEuANEgtdiph5h2AzhQK2eSdtqBgaXG82+F0O8ydyqiU9Ojhkj2lyfEklh
         qV3FA5E1HyVOTU5Cgc1aql03UPBIw0NmfsaxmAvchItByS/Wixmb8zLMgV5DKeaIWJws
         WdG+ZYKRE/RWx0KjBw1nl0YFRhiadaXK6mKtQbx2cnFh8FrLy86Jic9Tfc8dtrUOp0z5
         OAIB+IA3LgNyBhQa82K7fB+5a9yEq0E7EFn/CrSUT7X8DuqA4bEwkW0k8/UGqSykJtKK
         afqLLkatDVsLuMoPs5nAghm/gRCnYALeD4SILpQGRoiAVg3J2ffVJ+wzYqK/tpw8l0j1
         Um8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=vPqeI5tWsDD3YEnvLsMc5a2/datmv4BBrIEp84lnYhQ=;
        b=WfsVOExIt4znhOuxg37iMhZ5Ww1I+BPDeb25pCSQTvKLskRX4J7RxKYO4hYHOncmvG
         oMOUIhI00vMpFGEwWOWON10zZc5NBamzMWLXvhnNKZllyje65hr32adRxBiHFAYxeJbC
         qrHlOYXILqnMBg5Cmav+78IKt3NNcW6ZoNlzvWbK2yXYi+V2YrxyDjXcC27+mSWmZNlQ
         ecvaJqio9GDYp/LAtUwDq4r/Om6QxS3EvT60WJj6uru6smMEaeSu+JtdaAfrmLQCs00e
         2mDTAbGxnLi2sMpkI+3vbcDv3FDW7dcb/bmfUZQ6Az4JotjZ/UAyfwNIvzuaZ4K6i3uq
         A/zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vPqeI5tWsDD3YEnvLsMc5a2/datmv4BBrIEp84lnYhQ=;
        b=CvDpZNMKHOpaWpDGVWAy9LDAVpdQsddrp0tXnXirNowt47TnpczSt1/lbvlxdfHm6b
         p8ZHQJK399VQ40tnw4EEOY4vsksk6SpsL7thh+c7yDblupiilirKM9g/Es6P4gT3n/4H
         EGfuiu+dH8kqJoJE5a/zBQCT8RzaUrO5+bM/fWVuWagRGL9iKEbGenwU7lFqtA75oEUk
         gZ+MPqVMk7tFn2KLZ7ul8KOYrijq2tjEiIPSsOPP3zQ3Fg2J0BN1bUaN1SZMONBQLyMW
         72gx/JFeow7rysBZj+t2NMxoRiKRMcPVyDAedPTkyToCN+AAgIoJLyywCm156zYI5glw
         D1XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vPqeI5tWsDD3YEnvLsMc5a2/datmv4BBrIEp84lnYhQ=;
        b=El2aJGBhPK2BRmXfmxv2WKhUvspyf6A0AX0qGKRNQRFMkbToasPuKmvjgIwR6WrHjw
         rvldA1xWTrrb2yZPZrewvnDKThizPsMqzuO3p2JT8xA6w3aHr4lu4Mei/asWqpPuekJo
         FOft0/1CcAjAQpSiA6VY3amG1ecJV8k8DfbKmUKULLeQmlM72IYmsTdCotuBHsVzhOD/
         gz5YPdUYbRdOjpFWTnXABPq5VcllIuWS2ydhbmVlCqJ2obQmn0jf57ES9vEUSKI9W7+R
         hfgXxeVgjX1kZwN1PjUg8STxxhJpnDfrp6WYwRTTf5liIaU/9TE7+nY5wnURU+cVUndR
         dScQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ghrx1YnlxwkF2TsLB0/wcdrNnAHyI1vtUsFpJhVPC9rIZbKL0
	+9GmM+RMJwoUBgn6VnYJ+7s=
X-Google-Smtp-Source: ABdhPJxRA0CRNwCJ/Ln//WcJTnhLTPDL93g3EPMm0auCH4PkAC0wVACFudUJ4ZyQxWIdOA0fQKo0eg==
X-Received: by 2002:a92:dacf:: with SMTP id o15mr2527203ilq.236.1621309621434;
        Mon, 17 May 2021 20:47:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c7d2:: with SMTP id s18ls1165909jao.2.gmail; Mon, 17 May
 2021 20:47:01 -0700 (PDT)
X-Received: by 2002:a02:ca0d:: with SMTP id i13mr3264484jak.98.1621309620991;
        Mon, 17 May 2021 20:47:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621309620; cv=none;
        d=google.com; s=arc-20160816;
        b=FmPyZKO97j51nQw2p8mSf9efrV1ruq9KqDUFQjRlnROxNYbYMXzxWLVpjbeNBcny2+
         B97BscgYUu1C9KfXfChMD1fhn9bKE4+pLcJlqM3pERl0pHMHNDOaB8pxAZre5bMQ2tLs
         oZsSpSNad3ANvn4/FpvAm3SzNhnNqkFVBQsr4vWebn0PDKYqlWRDm/W52qPIyIquS4Zf
         +kh1Jlc9EaPFqRl8vhz+TKhj9+iC+UmnJY0zGQW+zkms2apIoidcDbU65vMTgvMgOja4
         KUoLbNE2G/2mDTi+LDQhRaDTTfgD1y/xn+Y/ezV41HSrlpxVEp02WUoh1UiJ4rNpH9DH
         6wIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=E7lpcPL4oN8ctxR6yRDvLm5glL8woT7S2Legk0iEQEM=;
        b=s2iPnnZK8nmRAdrn/mehj67aMslD0rlQGnEEq/ewnhjlzUYEmqpqc7AWtXKlwRQRRc
         nS6lvcTFQgM50C8G2+GXyCebTql1A0+4Q3KLj0oaqbJUm9cQBd/93fYy2brJYRTXj1FE
         fBVvWvQTAHkt2ZIolQiYP4fid/C51iRDbjFH9xo/bz4ekbDzpYmejCpKZoikcUPVQg41
         M9OppmRX8CRXna+jAmgVrzSkrgPuHRAzVqEjfJcgBs2Vt4TDvnr2X10a4JyxfDaQMsl/
         T2p7Y0LvBvLIZC38695yI+/vx9LCC4bl7xmLOybgHuMX1LNb6HZHusj55+hs8/9zVeg4
         qYbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id l25si924838ioh.2.2021.05.17.20.47.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 20:47:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1liqgi-00AIup-W9; Mon, 17 May 2021 21:46:38 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1liqgf-00DpMa-Cz; Mon, 17 May 2021 21:46:32 -0600
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
	<m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
	<CANpmjNM6rzyTp_+myecf8_773HLWDyJDbxFM6rWvzfKTLkXbhQ@mail.gmail.com>
Date: Mon, 17 May 2021 22:46:19 -0500
In-Reply-To: <CANpmjNM6rzyTp_+myecf8_773HLWDyJDbxFM6rWvzfKTLkXbhQ@mail.gmail.com>
	(Marco Elver's message of "Mon, 17 May 2021 22:53:20 +0200")
Message-ID: <m1lf8c4sc4.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1liqgf-00DpMa-Cz;;;mid=<m1lf8c4sc4.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+Pcm16K+cqYXv6QpoQzYfCpXsEiNIW9QY=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa08.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.6 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,T_TM2_M_HEADER_IN_MSG,
	T_TooManySym_01 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.2579]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa08 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
X-Spam-DCC: XMission; sa08 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 3037 ms - load_scoreonly_sql: 0.05 (0.0%),
	signal_user_changed: 14 (0.5%), b_tie_ro: 12 (0.4%), parse: 1.43
	(0.0%), extract_message_metadata: 14 (0.5%), get_uri_detail_list: 2.4
	(0.1%), tests_pri_-1000: 12 (0.4%), tests_pri_-950: 1.38 (0.0%),
	tests_pri_-900: 1.19 (0.0%), tests_pri_-90: 1552 (51.1%), check_bayes:
	1550 (51.0%), b_tokenize: 8 (0.3%), b_tok_get_all: 12 (0.4%),
	b_comp_prob: 3.1 (0.1%), b_tok_touch_all: 1521 (50.1%), b_finish: 1.57
	(0.1%), tests_pri_0: 1423 (46.8%), check_dkim_signature: 0.50 (0.0%),
	check_dkim_adsp: 152 (5.0%), poll_dns_idle: 149 (4.9%), tests_pri_10:
	3.8 (0.1%), tests_pri_500: 11 (0.4%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH v4 0/5] siginfo: ABI fixes for TRAP_PERF
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

Marco Elver <elver@google.com> writes:

> On Mon, 17 May 2021 at 21:58, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> During the merge window an issue with si_perf and the siginfo ABI came
>> up.  The alpha and sparc siginfo structure layout had changed with the
>> addition of SIGTRAP TRAP_PERF and the new field si_perf.
>>
>> The reason only alpha and sparc were affected is that they are the
>> only architectures that use si_trapno.
>>
>> Looking deeper it was discovered that si_trapno is used for only
>> a few select signals on alpha and sparc, and that none of the
>> other _sigfault fields past si_addr are used at all.  Which means
>> technically no regression on alpha and sparc.
>>
>> While the alignment concerns might be dismissed the abuse of
>> si_errno by SIGTRAP TRAP_PERF does have the potential to cause
>> regressions in existing userspace.
>>
>> While we still have time before userspace starts using and depending on
>> the new definition siginfo for SIGTRAP TRAP_PERF this set of changes
>> cleans up siginfo_t.
>>
>> - The si_trapno field is demoted from magic alpha and sparc status and
>>   made an ordinary union member of the _sigfault member of siginfo_t.
>>   Without moving it of course.
>>
>> - si_perf is replaced with si_perf_data and si_perf_type ending the
>>   abuse of si_errno.
>>
>> - Unnecessary additions to signalfd_siginfo are removed.
>>
>> v3: https://lkml.kernel.org/r/m1tuni8ano.fsf_-_@fess.ebiederm.org
>> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
>> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
>>
>> This version drops the tests and fine grained handling of si_trapno
>> on alpha and sparc (replaced assuming si_trapno is valid for
>> all but the faults that defined different data).
>
> And just to clarify, the rest of the series (including static-asserts)
> for the next merge-window will be sent once this series is all sorted,
> correct?

That is the plan.

I really wonder about alphas use of si_trapno, and alphas use send_sig
instead of force_sig.  It could be worth looking into those as it
has the potential to simplify the code.

>> Eric W. Biederman (5):
>>       siginfo: Move si_trapno inside the union inside _si_fault
>>       signal: Implement SIL_FAULT_TRAPNO
>>       signal: Factor force_sig_perf out of perf_sigtrap
>>       signal: Deliver all of the siginfo perf data in _perf
>>       signalfd: Remove SIL_PERF_EVENT fields from signalfd_siginfo
>
> Looks good, thank you! I build-tested (defconfig -- x86_64, i386, arm,
> arm64, m68k, sparc, alpha) this series together with a local patch to
> pull in the static asserts from v3. Also re-ran perf_events kselftests
> on x86_64 (native and 32bit compat).

Thanks,

Can I have your Tested-by?

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1lf8c4sc4.fsf%40fess.ebiederm.org.
