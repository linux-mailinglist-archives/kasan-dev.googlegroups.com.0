Return-Path: <kasan-dev+bncBCALX3WVYQORBS5CYGCAMGQEYVX5LNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C540737209D
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 21:38:52 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id w10-20020a056830144ab02902a5baf885d0sf4700928otp.15
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 12:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620070731; cv=pass;
        d=google.com; s=arc-20160816;
        b=uaeKj42VpVeiq+K0D7XdO571bUsD+qcSpFhTpYPwBC4S4wGuW65wuNThNPUhTLboM5
         +AYGUKKeuqvXNzyKmQsvJde+jFH55YCMvwzn7mlpzHnL5hoazzWuPLkPcIhYO62qrRib
         PxayvuS/DlCVAxpSZ2Bfeq6o39vRfnaGhpv7FMhEgp+VJb8YapvwR1jHszGXWpRN6B7S
         QSbeZ4B4XeqOHbKqxrVoReKGBSB4I7HJuDIsT0BwUhipTArTmblaqejKCuaRgh/QGBb4
         nOtjf2Wvw4B4a0oTv1sANNHFDKBUkdZBnsUdERNSJ5rjg1aIy+gYiURbsTGWvhWpKw0b
         j5SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=W5Nh0nzQM5qBKYZG5j+qoqqQT4CD6edtUi9OQXF/gxQ=;
        b=aStPkrL9jfXt2Xoim+co9tDGRdep0GWheDovYYT1Z9Eq8f+o7gHjIkZkCR1wdzniA3
         IMQAp+sjqnSgOlVNtMMhsJIT0anmPP1bcgRV6/o0GkE+E4TK6rHySnndeOQ+FTo4p1o4
         cide69SYK9A5Is76k+CRFUoEabFh0epdbePRPMpYSeoBgPZ7S6kbhuRD1Pt/SrFKU3ny
         K9TLc2VoLrx+h3BGGbLHqR9sI8NymPw/1zXYa3BzCuSycZbn2tASLzsvbly7WfpchrVC
         Zn8fDRKURXdZ1bZD4cWWMT2duG6T9XZ1iHkN7OvJ7NweSJhcwdtOYQu1gRLB8LIJZzEI
         wsLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W5Nh0nzQM5qBKYZG5j+qoqqQT4CD6edtUi9OQXF/gxQ=;
        b=eVFI6zQVrbU+Bk9kKdHlOlsK4E5iAnekKyUJM1lhzoQNA1e8eqlt/aBCm8o6ru370l
         I3WiRlmqomgsEcjTnSbvW20DF+xpUMvTWzkm+ST30VySFSddo4fc+3yQ+RDBIbjj58dM
         9KImzgjuh6MOo8AYHfBK2QeBHgnYVAAWrgkRluUgbv7cpmDTsiDr/ZpoUw9SKwRIZ0lL
         X016BSLxAFy/3p71EUReLfNTprPR4iU48lUs1enVJyNXM/hNCRyHIrifN3WT80EjmkV5
         hdfcHri0WZ4GSz9XGGI5noGLVtujpXcFh5QUjDZx0R11wHgZ9TzUf+WfrdJ0aWzdTQ+v
         GTcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W5Nh0nzQM5qBKYZG5j+qoqqQT4CD6edtUi9OQXF/gxQ=;
        b=BQaeliIjud/q4r//sapJyVVJVQcZ9EYk2D4Y3nU5NgTZzqbJwUQrt8+NhrQ3VHsmgD
         zraeNJxw4JmQJcKr2e3E1cjfqpQRTRzIGzijvtCUbsOAvfletZEgiQbc3iJdtT06YLmg
         7rWbSjbmpFUnW2uUpAL2Mqm6UeZXSApDT2kvc5FZ12JzOVj4VCEPCgx+C3ePIvA8n2GM
         H8Kl4+4TGII21DGvoKotk//QGAh/dxU83MIoNF3RSwUUqhLS7SvXYUe5pcinYUF3w7Rh
         SghGRt8I4KXCg6dUhcloTstKE2gXMd4gj5dw7BgBJjdtLBN2di2IVIiawlIiu0coJ6kC
         92Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zPRTBGXZHFuYS/5G+ChKKLX5tGaXiaHZVDzzRTgDFDMYkymTg
	TjjCP3CWLUvj66Kycw4+iBA=
X-Google-Smtp-Source: ABdhPJwKAtlz9BypAfhevov+w4OAqHoVmnFspMP9s9LfWI4Cpn/NtGSsxwv51ZY2lBVm+3kkU5BfPg==
X-Received: by 2002:a9d:5f0c:: with SMTP id f12mr15878222oti.258.1620070731765;
        Mon, 03 May 2021 12:38:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1e0a:: with SMTP id m10ls4106527oic.7.gmail; Mon, 03 May
 2021 12:38:51 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr14693378oia.172.1620070731405;
        Mon, 03 May 2021 12:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620070731; cv=none;
        d=google.com; s=arc-20160816;
        b=aldg5uciRZH75NE9u9r7X2/iT7rMGZVljumu7NZUh8T55qARvIs/J2PbPr9z6jIS3N
         pZUiQybyXLKUnKTEbIoOJxA8dAGYwAn3O7u6TghmUlG4//WHk/7LXxqG+0DBxY03ya00
         I+UTEkX5NKKDp88mV/yYiO1lzym+5hY08xblESB6pVmPNss0YzY4LUDJXQxS97KqAShs
         WWl2RdxJlHAWdt9XC9lH+ii3W+waTA2FZovDEVZwJqgyS3ujG+BCWBQ97FreTanC3xiE
         uPA3QoAmHPFDSyCbJAeePX2LlRGSWwR3J9oSqxnrxBvHQTiL7kotQKhwfkHOrHR0+zry
         bVtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=K0os4gEvk+P0VHIpAO4J4iIRxe2N3GnHBBVat1Be//g=;
        b=YNULX+nDAaNQxLS9jnDcYx95DZUuZ+p5w4bUSEEAxjh3EPEGgMr+CTmmobcOeeRFcO
         FOlTlZVI2ads67DeQ8eP0unbtiaP0WFaRLsdETbLIkgJrYvwclS5T1DrGjqH+3fsyjsC
         cGAA2uVHNtIRpLamsVBlkikgd3UirnUW2AOqtRC5BMc1W03/FYRwhLUzW5cwnoIt8O/M
         GEXYOYTSZo59r2gKEVOuCGJhHP8810bTAkVWONmQLpqd8y6Q71OOarVdsuHfOnIpkPpH
         hfLmAmGonPThPGapEZxUjyksJs+NuvuyCjcOzZJ03W0ZKbvTI78ZF7U7xRDnNKEw9Qrs
         XCww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id f4si59692otc.2.2021.05.03.12.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 12:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldeP2-00HDI3-Qv; Mon, 03 May 2021 13:38:48 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldeOx-00DxKW-Li; Mon, 03 May 2021 13:38:48 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>,  Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m11rarqqx2.fsf_-_@fess.ebiederm.org>
	<CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
	<m1wnshm14b.fsf@fess.ebiederm.org>
	<YI/wJSwQitisM8Xf@hirez.programming.kicks-ass.net>
Date: Mon, 03 May 2021 14:38:39 -0500
In-Reply-To: <YI/wJSwQitisM8Xf@hirez.programming.kicks-ass.net> (Peter
	Zijlstra's message of "Mon, 3 May 2021 14:44:21 +0200")
Message-ID: <m1sg33ip4w.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldeOx-00DxKW-Li;;;mid=<m1sg33ip4w.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX193P6Zs47y9HH8Pk31Hd8htHGyDNhcJWFA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.2 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_XMDrugObfuBody_08,XMNoVowels,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.1431]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Peter Zijlstra <peterz@infradead.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 4529 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 12 (0.3%), b_tie_ro: 10 (0.2%), parse: 1.07
	(0.0%), extract_message_metadata: 23 (0.5%), get_uri_detail_list: 1.11
	(0.0%), tests_pri_-1000: 9 (0.2%), tests_pri_-950: 1.95 (0.0%),
	tests_pri_-900: 1.46 (0.0%), tests_pri_-90: 78 (1.7%), check_bayes: 76
	(1.7%), b_tokenize: 9 (0.2%), b_tok_get_all: 8 (0.2%), b_comp_prob:
	2.9 (0.1%), b_tok_touch_all: 52 (1.1%), b_finish: 1.48 (0.0%),
	tests_pri_0: 319 (7.1%), check_dkim_signature: 0.92 (0.0%),
	check_dkim_adsp: 2.4 (0.1%), poll_dns_idle: 4052 (89.5%),
	tests_pri_10: 3.0 (0.1%), tests_pri_500: 4074 (90.0%), rewrite_mail:
	0.00 (0.0%)
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
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

Peter Zijlstra <peterz@infradead.org> writes:

> On Sun, May 02, 2021 at 01:39:16PM -0500, Eric W. Biederman wrote:
>
>> The one thing that this doesn't do is give you a 64bit field
>> on 32bit architectures.
>> 
>> On 32bit builds the layout is:
>> 
>> 	int si_signo;
>> 	int si_errno;
>> 	int si_code;
>> 	void __user *_addr;
>>         
>> So I believe if the first 3 fields were moved into the _sifields union
>> si_perf could define a 64bit field as it's first member and it would not
>> break anything else.
>> 
>> Given that the data field is 64bit that seems desirable.
>
> The data field is fundamentally an address, it is internally a u64
> because the perf ring buffer has u64 alignment and it saves on compat
> crap etc.
>
> So for the 32bit/compat case the high bits will always be 0 and
> truncating into an unsigned long is fine.

I see why it is fine to truncate the data field into an unsigned long.

Other than technical difficulties in extending siginfo_t is there any
reason not to define data as a __u64?

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1sg33ip4w.fsf%40fess.ebiederm.org.
