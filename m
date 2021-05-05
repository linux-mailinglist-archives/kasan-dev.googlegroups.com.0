Return-Path: <kasan-dev+bncBCALX3WVYQORBXWPZKCAMGQEXY6LI4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E646373D61
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:12:47 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id z2-20020a9d62c20000b02902a51ba083a5sf1211720otk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:12:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223966; cv=pass;
        d=google.com; s=arc-20160816;
        b=RD0smN/CjM1/ZjvF7UDscE0YtJVAnS4MEmoKHj+ioGJmmzKqiH8EjdQKENqZKxZY/w
         hvZiYFWb936FYReUmrn60WGF0r/QnshTxyMkKmRfwt+WwcvnahdJTrWdGDC407dNMaLl
         YvXqm/6C+xlsc68alwVCUA4rp9KITo1fAGaoYW+GN2wePbc9CbIlsiG35FfdzF1BxjLd
         Re2EBSeZBuos9SeyK7eb5t1DvkF1i99BUVwZ3flgeA3Jh6Naupw/beTD47y9oj+5uYht
         KtkMuL80hYfJZlwmGzgi8WdyrY5sjFDl4mWUb0h8JrtRg1g/D4/vxirqeu7im9dj4np8
         ccNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=WfwuF9cEDEtb7t5PaiD3QImcwaqOdqpBkKwL143Ykso=;
        b=rRCOioS1K3xvjLPqb/d+q29tzjoAV0irzX2FHDlfVGjWP60RcazP1PAjXSAKZHANUP
         BeLGgP963k2CDbmUEiV6pftY71434t18B2vMqh/CpB+1n9aqj6O2V/j7FsVxnDELA9/G
         6czzpTprrh7RuSjft+yS108qfBHLVLVERGvtPiBy/27wVd8H8ZDLhn5Ti5vwVc20W2xO
         uoWutWegdIdvs3P1CoFE6O1vQtBPWqy4BaBFrvEqkbts/ht5R+p2t3H/UqpcBMtKdqeL
         Qj0Um5dofOorCeORWsmyzSUP+xXcsCAn3wScv4+/4ikRwHNwB3CXpYpivSDX2JaThscz
         /E6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WfwuF9cEDEtb7t5PaiD3QImcwaqOdqpBkKwL143Ykso=;
        b=HpK8Rt/6okUySnzDvQpytcNIt7IL/cGnQLGb9HwqXY13VZckd1jqovNju/PxGT7qcZ
         VKr0QMgXda2kA5o5T95ZeD+puktY5/uDspowJ9mPr2AstqhJhWxq1+H1zi3gFnnNk4Lr
         K9F2iGqkEgh8rrvQSk4uSbaa1Mfd90TQTN07R7rH7CjGJcgNLsLIhoeuLTQeajHoW5Y7
         GkrDX8dxmdaimLgK3WAit820biKWpmtkEahxuROM5HfF+d8xJrK/10l/3nImPyg4CHNg
         Usbiytp+WvFWVsTrmF1zlf41fkXvzEEYRW3kYtZwx/J6Td8n/TEgG6texx1i3LKmTDPy
         o5lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WfwuF9cEDEtb7t5PaiD3QImcwaqOdqpBkKwL143Ykso=;
        b=HuQNyJGP3cNAwtp0+bXhhCRALHmsxK3i/lMgAJmSNjlfqyvXTQWKmyeSkf837gv2ZW
         L9Djifn0wtfzkIRJyEaDOvmkLCsbajFllorJzWEnb4suy94ca1MfSIfg4KgnXZkqBkQQ
         WqqZpAM4mFFB2R6a19E+67rPzdoPNPF0niePSx5LhhPuQcAqDBArodgVyRpOnVQf2ADI
         hqmNCFg4JvhGd0PnlUZ8f/y3/nwMNhCGAaxJy0loLX+lPghiHdTMFR4aHt5RMho0KlEc
         7saXGwW1gDlnhf6lt/XnWL/X3XSw4mxp5GlSPf8Czeyg96BrGyy3Tee8teF7ouWUCu1C
         hByw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PIkyuoL74ZYIL9wl05MdfiOrIluVd7c+joojHRGsj18ArN6qU
	4HB1aOymoYS8eeSHuxOpq5c=
X-Google-Smtp-Source: ABdhPJz71c27BJU/XWhqFlmUheWGZe/e9+B0Ype6XWJMrky/IG3+kirYGuKo4iu0++n8ofgcLWK97Q==
X-Received: by 2002:a9d:7997:: with SMTP id h23mr15414607otm.366.1620223966083;
        Wed, 05 May 2021 07:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:f0d:: with SMTP id m13ls5881887oiw.4.gmail; Wed, 05
 May 2021 07:12:45 -0700 (PDT)
X-Received: by 2002:aca:6701:: with SMTP id z1mr6800727oix.167.1620223965685;
        Wed, 05 May 2021 07:12:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223965; cv=none;
        d=google.com; s=arc-20160816;
        b=hVYvqGQZuowtuYVe56JV/X2DZuDZjqyUzsuazoYI9Ryrz4wyxEX9XjHGfFo/R+3tsJ
         MFfZLAAkYhwv820WjrG+/evWp4bdEQeKygSQFQmfL9hGjKuSY9Q5i5YOjoArCySaZxSh
         +YTWsoRDEthB1CsOTw23iq7yXluMB3MkuMeS5i+5jlGVm61obGXzvPi3lU957IYFaZq9
         8GV2pG1j8jIKXPtrRIh66vTKzk2L8Tw1gP1iBsO954+iAKh8tYusAw6hJIpFFz/5Gbyu
         sTAOCKwWdG1YKIXxflvMRIFergtNzV8NHyFYcBgINHf5YoP5qb0QjVKL9KDtFWK7ydtS
         jvPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=swKJVwM0laqlaudtuQRNvlqkyTlatG6j0+TJJobzKqM=;
        b=TR4K/xvQyt+XX3c/lo9nEacRHNJV1F0NfIHJtLH3x2NFPVFPpz9+oJhOeCv6LErI2b
         i2EXy8JLjNWzo0J+c9wZIfziA4xUKPbxHEYxPbWr5WxdqtLH1z5fz3Efz56+w3ikWZMa
         62rZHxVRbnF/S6z0UKryQV5/dgbUnrQSSQmo4FaZHa+4A5MczCyMkyDIgTF9o6gM/Wm6
         iqaGdV/6CLMrWvKbmKjwIJfSk90/Mq7ahJCRxaGbEXR3Pblos2zyS/6Faczfou4T4rTF
         IkM9EPs/5r35rOt9RsDurCH2hCgrAR7vAnfPb2G4vzU82wIK2sJvBQgnfBBR++Y7YT0T
         B7og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id e13si706732oth.3.2021.05.05.07.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:12:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIGa-00CGlJ-DX; Wed, 05 May 2021 08:12:44 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIGX-002GvZ-Te; Wed, 05 May 2021 08:12:43 -0600
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
	<CANpmjNM5sYihM_9P5YHx06BooqLDhK96cMHGKaf61nCcoDJBdw@mail.gmail.com>
Date: Wed, 05 May 2021 09:12:38 -0500
In-Reply-To: <CANpmjNM5sYihM_9P5YHx06BooqLDhK96cMHGKaf61nCcoDJBdw@mail.gmail.com>
	(Marco Elver's message of "Wed, 5 May 2021 00:05:00 +0200")
Message-ID: <m1o8dp8e21.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1leIGX-002GvZ-Te;;;mid=<m1o8dp8e21.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19By7EuCGlSC+Hrh/+dmLFpw1rmZv8aoeM=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.4 required=8.0 tests=ALL_TRUSTED,BAYES_40,
	DCC_CHECK_NEGATIVE,FVGT_m_MULTI_ODD,TR_XM_PhishingBody,
	T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XM_B_Phish66 autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_40 BODY: Bayes spam probability is 20 to 40%
	*      [score: 0.3381]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  2.0 XM_B_Phish66 BODY: Obfuscated XMission
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.4 FVGT_m_MULTI_ODD Contains multiple odd letter combinations
	*  0.0 TR_XM_PhishingBody Phishing flag in body of message
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1887 ms - load_scoreonly_sql: 0.17 (0.0%),
	signal_user_changed: 15 (0.8%), b_tie_ro: 12 (0.6%), parse: 1.92
	(0.1%), extract_message_metadata: 20 (1.1%), get_uri_detail_list: 3.8
	(0.2%), tests_pri_-1000: 19 (1.0%), tests_pri_-950: 1.90 (0.1%),
	tests_pri_-900: 1.38 (0.1%), tests_pri_-90: 1228 (65.1%), check_bayes:
	1225 (64.9%), b_tokenize: 12 (0.6%), b_tok_get_all: 9 (0.5%),
	b_comp_prob: 3.1 (0.2%), b_tok_touch_all: 1197 (63.4%), b_finish: 1.32
	(0.1%), tests_pri_0: 579 (30.7%), check_dkim_signature: 0.87 (0.0%),
	check_dkim_adsp: 2.6 (0.1%), poll_dns_idle: 0.44 (0.0%), tests_pri_10:
	2.2 (0.1%), tests_pri_500: 13 (0.7%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
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

Marco Elver <elver@google.com> writes:

> On Tue, 4 May 2021 at 23:13, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> This set of changes sorts out the ABI issues with SIGTRAP TRAP_PERF, and
>> hopefully will can get merged before any userspace code starts using the
>> new ABI.
>>
>> The big ideas are:
>> - Placing the asserts first to prevent unexpected ABI changes
>> - si_trapno becomming ordinary fault subfield.
>> - struct signalfd_siginfo is almost full
>>
>> This set of changes starts out with Marco's static_assert changes and
>> additional one of my own that enforces the fact that the alignment of
>> siginfo_t is also part of the ABI.  Together these build time
>> checks verify there are no unexpected ABI changes in the changes
>> that follow.
>>
>> The field si_trapno is changed to become an ordinary extension of the
>> _sigfault member of siginfo.
>>
>> The code is refactored a bit and then si_perf_type is added along side
>> si_perf_data in the _perf subfield of _sigfault of siginfo_t.
>>
>> Finally the signalfd_siginfo fields are removed as they appear to be
>> filling up the structure without userspace actually being able to use
>> them.
>>
>> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
>> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
>>
>> Eric W. Biederman (9):
>>       signal: Verify the alignment and size of siginfo_t
>>       siginfo: Move si_trapno inside the union inside _si_fault
>>       signal: Implement SIL_FAULT_TRAPNO
>>       signal: Use dedicated helpers to send signals with si_trapno set
>>       signal: Remove __ARCH_SI_TRAPNO
>>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
>>       signal: Factor force_sig_perf out of perf_sigtrap
>>       signal: Deliver all of the siginfo perf data in _perf
>>       signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo
>>
>> Marco Elver (3):
>>       sparc64: Add compile-time asserts for siginfo_t offsets
>>       arm: Add compile-time asserts for siginfo_t offsets
>>       arm64: Add compile-time asserts for siginfo_t offsets
>
> I can't seem to see the rest of them in my inbox. LKML also is missing
> them: https://lore.kernel.org/linux-api/m1tuni8ano.fsf_-_@fess.ebiederm.org/
>
> Something must have swallowed them. Could you resend?
> I'll then test in the morning.

They got stuck going out you should see them any time now.
Sorry about that.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1o8dp8e21.fsf%40fess.ebiederm.org.
