Return-Path: <kasan-dev+bncBCALX3WVYQORB5MXRKCQMGQENYWIYUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AAF0383610
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 17:29:59 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id j1-20020a6280010000b02902d9500b603fsf3350816pfd.16
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 08:29:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621265397; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUKPLKi5aOZCcG2WeffwgLJpiXVvY/pW9UTPpecjXHDHJR5d9bVdyWY9p0R0+HXvHW
         NCxWHgM0RevmVVeEHVPmZRrCJp7ScupaPpfTMmLsgpyxDpBD4Xu3SeMoTeMm9IQRlkpv
         AEurBkrZv2k9I3T6nEfI2BqTbWVBEocBWb1CXBoTiA5sv1Fc5kEdHP/xTctTvVya1kAQ
         fQ4MBHTN9spT8sK3XEPqYLvjgA4+DA25vIxoSubnLM6cvTQ53pINl0bpmj47ZTPPQe67
         0AnD5fyGGM4uSHye3w2XJcZ1oyyzJB1yLwlb39oQljYcXkDc258b5LdoxPg3mVywFvcs
         WvXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=s638DPNbJETga7UGF2trkxWkIonf7fhnt0Z6R/pdi1M=;
        b=a9ekzNrSWZnQ5QRs+CmYI0DnMgM2kNcDC1+2Vr7st0ZtDkxeoEW/jWJxxd9fBvxS2U
         TmbTqLXePNSWZta/8+ZOblt+QHg4133DKNxFtyrS7/HYQWJr72mQ2QnOLJDK87XY3uQ6
         NnmeRUpNYYykDB40fXml0HMUThAxp6Ho4g9F4Ssn6ZdsuzTXHcg/ZBRWzMLKRLmzvkCC
         vgnfUoX+0k6UqtYgJtKcbFRZSB6nWJv1+m3QgohHDZ8ymDPouFifh32NiLaThPbWTxcB
         3cW0xHwcBsFsGh+nNK4iqZ7NL8VeaOhbrtYoa89fvgZiec5KE5UgpnHIj8ynbDYBx66A
         ACZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s638DPNbJETga7UGF2trkxWkIonf7fhnt0Z6R/pdi1M=;
        b=sj/3pQizu4qr+C4pGFBT+7uMCmZu3uhAmN5o70ryMCDH0pLW7FUMlSYdEDrPv1I10J
         mCYJZdGFw+TP0aIQp2PkR59ePlfkSTCsNYmD3Oat4G1mAeHNs/YSxsaKydpDviqMBfAs
         idudLRMYjIlOJNjVhQRz+e8XnRSSOvpS3RZdJTXoKF/5nNNpLFEq/7Y/6vyevy7D4jTC
         mKq/objvBX/yMoQv+6CsAhCV/p1PNJOBWnzWeM/bXGmDxAfwT9t5J/fAwQVjMVPDf/e4
         y63XVAnxglM2z4w3hVnHNSbOwBRmIomvrt1xQfzIfXMWO/L0WU+AvHfi6dRzdKxw4Nuv
         s2gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s638DPNbJETga7UGF2trkxWkIonf7fhnt0Z6R/pdi1M=;
        b=ZvbLW9UgXTdZEzkRIj8M3yQT1wZZ/RXFeHgO0UzACFYeR1TpkEgzOWiw2AqV4r3jdP
         RdespO5ZcOcF7uLdddH9Qlfawrz0r4r8IM8V6hoX28cQhDRWOKxXfLnYbvzEDOVil0vQ
         72M4mlpfCQY35MDNPuiyWxpsDermyOcYrR430IuszVQPNcxBysA4KIbMr8LidyqzW7PN
         eFp9eRo5Eu12UHvhLt9e05fFnILbRyADwPwsfwH3oL6NqvOfeQJG2SpbdWfXabZiLI2K
         l/9jULGn8eO97eSp2bE+oioNV42hlOe8ODMOg90m5UHhKzAjNtkKxgVFktM1toZvFJQ8
         5qnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533f4VCQRYP198TzfvoUD+Hl1lAsWPcA5oOvU4mBTuuu43NptrHs
	+jUXe0ULvFvAmNlA6vGDxPQ=
X-Google-Smtp-Source: ABdhPJy9iPbferCEoW9H+mNwTcbk0kLvp6s15SaIqVkiSvSvZ4vQO8A/q/T6OIZhRjhsS6Hymg9ahg==
X-Received: by 2002:a17:90a:288:: with SMTP id w8mr27138pja.111.1621265397741;
        Mon, 17 May 2021 08:29:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:91ce:: with SMTP id z14ls4577795pfa.5.gmail; Mon, 17 May
 2021 08:29:57 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a90:b029:2dd:dd7a:bd7d with SMTP id e16-20020a056a001a90b02902dddd7abd7dmr342887pfv.34.1621265397169;
        Mon, 17 May 2021 08:29:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621265397; cv=none;
        d=google.com; s=arc-20160816;
        b=Qe86fdgNQt16/oxfsecqUL0Y6v/bHvtKshH33K81bjL4OEN1KaLvhdGijtPQGTEZJk
         PzoOYDRYUMMgMoQRz+XzbGqWf8De+dJ6Wk5n2yFIeAaXgrb4JKfWW4hb2dhtQ7ERirMV
         CRnqKibNSR6ztNZEnvXMDUh9/tcKstb6X4jMLnGkHOaIH+AKHInGWN8czd12YuMaDcxe
         LlQ5lZ9wsD00nllc6WCTrKMo80XR8JKWoWTgaKsBSDqSGIzsJXC98BCG3Y5tcNwizh6T
         qNThOhUI5DGVO/MmYh/qXJXxUcMSj7G7eN9cabAUVSLU2tBkOGKScEkyXuiMdiKbnu3t
         JnKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=ZwzPqDuP/RwbgdtrX3YBmhRF85u1fmwo/hNniAazYMw=;
        b=xM9qUzwNpetAhCpHouezFFOJLkBnhE0FWxBri8KVConcfL4r7SvE+TqjyeTbBG1IC1
         snLLddLjzFsWPwVGnS7RpCTtDjFIatWsUwhlu46xhtiCf9FDU8YVl6XjGchN0QsyZT8R
         OCvb2y4GYzzsuLh7r6aU9HsjBdi38ILtmMPUzZJ8/9+Z/BpX0xX9qAL+HSC43H/27Ru+
         X5ehxIYHTgl2dMqDbNyH3KNN8unxmgWSQypHCqXRl/OVyWYBfTL5fWSf/45/vDyaFGXr
         xy5SUAEJvWs8TvIdngBqYbElAa4/mS4/umkBh5T+/PyeuH8KlvVHECnVhx8tPvcel+4j
         ZavA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id o15si1199828pgu.4.2021.05.17.08.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 May 2021 08:29:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lifBk-0003MZ-KS; Mon, 17 May 2021 09:29:48 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lifBj-00BZOl-IR; Mon, 17 May 2021 09:29:48 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Ingo Molnar <mingo@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,  Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>,  Marco Elver <elver@google.com>
References: <m15z031z0a.fsf@fess.ebiederm.org>
	<YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1r1irpc5v.fsf@fess.ebiederm.org>
	<CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
	<m1czuapjpx.fsf@fess.ebiederm.org>
	<CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
	<m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<m1tuni8ano.fsf_-_@fess.ebiederm.org>
	<m1a6oxewym.fsf_-_@fess.ebiederm.org> <YKDMWXj2YDkDy1DG@gmail.com>
Date: Mon, 17 May 2021 10:29:39 -0500
In-Reply-To: <YKDMWXj2YDkDy1DG@gmail.com> (Ingo Molnar's message of "Sun, 16
	May 2021 09:40:09 +0200")
Message-ID: <m1wnrx750c.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lifBj-00BZOl-IR;;;mid=<m1wnrx750c.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX199lR/IyLLJ1RHiRf25MlrgYHNCCIjDaII=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa08.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.1 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMSubMetaSxObfu_03,XMSubMetaSx_00 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4536]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa08 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.2 XMSubMetaSxObfu_03 Obfuscated Sexy Noun-People
	*  1.0 XMSubMetaSx_00 1+ Sexy Words
X-Spam-DCC: XMission; sa08 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Ingo Molnar <mingo@kernel.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 436 ms - load_scoreonly_sql: 0.05 (0.0%),
	signal_user_changed: 13 (3.1%), b_tie_ro: 11 (2.6%), parse: 0.96
	(0.2%), extract_message_metadata: 15 (3.5%), get_uri_detail_list: 1.38
	(0.3%), tests_pri_-1000: 14 (3.2%), tests_pri_-950: 1.66 (0.4%),
	tests_pri_-900: 1.18 (0.3%), tests_pri_-90: 64 (14.6%), check_bayes:
	62 (14.1%), b_tokenize: 7 (1.6%), b_tok_get_all: 8 (1.9%),
	b_comp_prob: 2.9 (0.7%), b_tok_touch_all: 38 (8.8%), b_finish: 1.21
	(0.3%), tests_pri_0: 313 (71.8%), check_dkim_signature: 0.71 (0.2%),
	check_dkim_adsp: 2.8 (0.6%), poll_dns_idle: 1.10 (0.3%), tests_pri_10:
	2.2 (0.5%), tests_pri_500: 7 (1.7%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [GIT PULL] siginfo: ABI fixes for v5.13-rc2
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

Ingo Molnar <mingo@kernel.org> writes:

> * Eric W. Biederman <ebiederm@xmission.com> wrote:
>
>> Looking deeper it was discovered that si_trapno is used for only
>> a few select signals on alpha and sparc, and that none of the
>> other _sigfault fields past si_addr are used at all.  Which means
>> technically no regression on alpha and sparc.
>
> If there's no functional regression on any platform, could much of this 
> wait until v5.14, or do we want some of these cleanups right now?
>
> The fixes seem to be for long-existing bugs, not fresh regressions, AFAICS. 
> The asserts & cleanups are useful, but not regression fixes.
>
> I.e. this is a bit scary:

The new ABI for SIGTRAP TRAP perf that came in the merge window is
broken and wrong.  We need to revert/disable the new SIGTRAP TRAP_PERF
or have a fix before v5.13.

The issue is old crap getting in the way of a new addition.  I think I
might see a smaller code change on how to get to something compatible
with this.

>>  32 files changed, 377 insertions(+), 163 deletions(-)
>
> at -rc2 time.

The additions are all tests to make certain everything is fine.
The actual code change without the assertions (tests) is essentially
a wash.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1wnrx750c.fsf%40fess.ebiederm.org.
