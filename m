Return-Path: <kasan-dev+bncBCALX3WVYQORBWEP2CCAMGQEJ533TAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id C160F375655
	for <lists+kasan-dev@lfdr.de>; Thu,  6 May 2021 17:14:33 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id v12-20020a25848c0000b02904f30b36aebfsf6399435ybk.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 May 2021 08:14:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620314072; cv=pass;
        d=google.com; s=arc-20160816;
        b=wILCN7HYK/a2pfcw28FxsCZkYgge0kiag7injsruIy5faMzTTDpJ9Ic834/HQ59rw4
         173tak+i1/TTuSiyofwXtEfaoi4X/l422RiabYcMXE4KLp4QzgPHGAi8GbjF2WyIeXZh
         iKWCjZMHIsKMSKV9ZcB+tgoFnkrypiMYeBHB3X9oe7rnPlyNMEFFkX5Nbrc33Vgolewp
         5pP1PB7wuGPpd42kxhU+0aExJ71k1OHkN1EvJVAufs5vqbk+jNuz/ysVOClJbv0MhE3s
         LixTTZEn113JH+zla5SEp1g6p8SaK6WvV0aanQ+tdQp3wLgu0gtvN/bKuzhPMxASKWaa
         yTZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=UZoH9QWjxlJlX3iuxo+4y/CZ5zclwJKxfvQ55tKIg9Y=;
        b=hKRLcZW0aGLrWLhM+ym4wLgzLIze9b3caQ+8obcUMkOtMc5ARHG308esGgBIJB4Xgk
         oUV7fUlMdzp5eA9436yNgG1pwwbt674q9u0xE+ILf62/IwF+SGK0qjoORKuSQMENprE3
         DtVamn4GrYxn6TpVTrYWx5BM5aIeBLZ7S5PdDq18PAUUmvuvDV9Ajd1jisbxeUPtsgEs
         hFnYEZ71C0m8txcYYnVQJ2MqLTPfiesqNLC6ezwL7GiNi8Uc4K6EzBQ/pK4hwRiTmfei
         7NtHfTLQYxi3t6Yq0AYXfUbNRaFil0Nn9eEA6h5L6u10EtJ6hLP1L2yMYOgLJgzx2tSh
         nzFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UZoH9QWjxlJlX3iuxo+4y/CZ5zclwJKxfvQ55tKIg9Y=;
        b=PCZgRu3xoiQbFv1gMLcSk8U8QL4lcXAjoCKFeI8TRWn0lfANcVUkytEV2egZH3OkkV
         WDA5C4d0RfT/zZe7H5cuB/uYtT5/040bl4X2Q4AdD2dHkq/6lWvxDu2dSRI5jHQgCN8B
         k5ageZG/GgNvCplHRVLKiGUmm7fYZCEeWZKgduDZVZu07G6IgoZFhL5LCYzoQ65zuFdz
         5QK4y4P9wjHLw3cglEIRHPMNany+MJQ3vA/ljmCaQlS7j2C/VydjjOngzsRZZvDkDq5J
         I/GSL4WaloEC8Kyn9smq2mxMhl9Kw0/SfBzKJfSroJACIkelNaslKctN1/MmDyyaXUXM
         cl+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UZoH9QWjxlJlX3iuxo+4y/CZ5zclwJKxfvQ55tKIg9Y=;
        b=g0PquvH1tJsNZQiAh8rDj+HG3B29/q13P9jVSSnOKclessDDXZZJ2KzPwQeiHYrag7
         uBkmcNo3rnAEWCLxc5nf/45i/V5cPvHA7klmRHsxT0iWF7o69MLa3jf8vzVHu2W+Ij50
         c0pfXnxndAoNLFGm7y35nUC9VE5qDbFJZIfgkqPfB+hsfDULY5gMVHxtEWiudC9nlHf5
         LFqiStykdF0S3BBElLvmBoTuKvJj8APIAyG6+SOxmNowcTci3ybg64HH/uGZQ4WWxrDH
         sVWOjqPq2eZqm8d2/3duke9bKJ6mXpk+S/U+nmK4MzteSv0p85WkoBNTC4T3RGS+U/l6
         WLRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533g+V4mDpYlXo0qH7bMZ7Cc00QvOdM8HazZHRGmioh8z9OHX/uF
	0atfU2J8JxnuRd0W69//cVo=
X-Google-Smtp-Source: ABdhPJyCwgQJeZuG5KhDOTRqr+IuwFGHakj0EAYLnDNXHVXs3o1Jw/fxRI16/F+UCyPhT3kBFBCKgg==
X-Received: by 2002:a25:ab0f:: with SMTP id u15mr6243730ybi.502.1620314072578;
        Thu, 06 May 2021 08:14:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls1606167ybc.2.gmail; Thu, 06
 May 2021 08:14:32 -0700 (PDT)
X-Received: by 2002:a25:7109:: with SMTP id m9mr6832321ybc.274.1620314072194;
        Thu, 06 May 2021 08:14:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620314072; cv=none;
        d=google.com; s=arc-20160816;
        b=czS/OqVTLmMKjr9LmmrQcloUZjEN5mLuW7B4xkFhP7Kdo7IzXEhHOODaqmE0ZA8W5a
         QwKdygk200ZreL0KPR3AMacoPrilWDVLriLFd2QHO9r5MSuXw7nGip4V/gjpgWmhzKcg
         WbMJqjQR416sIgrIyfnN0CMFYaxR1z5AwMxQRFs/v7DatxIrRGZW05RSXNYR2Ml29CcH
         KiKRB0kRHbBFMPztbZYxkY+K4BU21tRQtW3QdVj6KtQCtNjNxWKs/PToi5vkxJ2Wgvkb
         EFTeG1gyOlkwqg8llhc3UYO2qLljKQHb3YNfdJbv87XL8iFWRm1ijjY8UFqgSlPvRh/8
         ZZEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=BTNXyN4dfSarE5eCvY/K6m9Q71mz9PaEDwoUtQgM1eI=;
        b=Yy6CWuZvjWnf8QZEl/7qHEio27iiUkVcbFejOXIuM3Aud7VnRyAtK2BBQvZ8QwYZZB
         Ygt6KJWQ3ZZxRh8k7cl/LOUfmuKo/KK3IusC1yZ4YqysE9kWcztWPl5Xc3JrD8CpeiLs
         IRr/wjb7eA+tDeso5hQme+MssS3HEEQ96lYLOIES/SC/0BAnvlPNfAcegrQSCK8nqkZk
         f75Vd9GPcgN5hHgPo5a0VcE7eqjy2KyDN9eUR+G0KpU6rVqHuf19pLhkwbbYJZKC3gS6
         /cAZkZSuAvcnW1V+QmQTXDENwdZ9ey/HhHyJpRokSIVHYK3ZosksiyjTFRd8GsYQTIuT
         7oGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id h188si128743ybh.5.2021.05.06.08.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 May 2021 08:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lefhp-005MIv-LY; Thu, 06 May 2021 09:14:25 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lefhl-0000RC-E9; Thu, 06 May 2021 09:14:22 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Marco Elver <elver@google.com>,  Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
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
	<CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
Date: Thu, 06 May 2021 10:14:17 -0500
In-Reply-To: <CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
	(Geert Uytterhoeven's message of "Thu, 6 May 2021 09:00:59 +0200")
Message-ID: <m1pmy36gja.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lefhl-0000RC-E9;;;mid=<m1pmy36gja.fsf@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19LyVyCtQprDRirlYQLwegi4JFnnMVJ0N8=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa02.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01
	autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4275]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa02 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa02 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Geert Uytterhoeven <geert@linux-m68k.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 635 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 3.7 (0.6%), b_tie_ro: 2.6 (0.4%), parse: 0.69
	(0.1%), extract_message_metadata: 13 (2.1%), get_uri_detail_list: 1.75
	(0.3%), tests_pri_-1000: 18 (2.8%), tests_pri_-950: 1.07 (0.2%),
	tests_pri_-900: 0.79 (0.1%), tests_pri_-90: 202 (31.8%), check_bayes:
	200 (31.6%), b_tokenize: 8 (1.2%), b_tok_get_all: 9 (1.4%),
	b_comp_prob: 1.72 (0.3%), b_tok_touch_all: 179 (28.2%), b_finish: 0.76
	(0.1%), tests_pri_0: 385 (60.7%), check_dkim_signature: 0.41 (0.1%),
	check_dkim_adsp: 2.3 (0.4%), poll_dns_idle: 0.81 (0.1%), tests_pri_10:
	1.71 (0.3%), tests_pri_500: 7 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
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

Geert Uytterhoeven <geert@linux-m68k.org> writes:

> Hi Eric,
>
> On Tue, May 4, 2021 at 11:14 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
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
>
> Thanks for your series, which is now in next-20210506.
>
>>  arch/alpha/include/uapi/asm/siginfo.h              |   2 -
>>  arch/alpha/kernel/osf_sys.c                        |   2 +-
>>  arch/alpha/kernel/signal.c                         |   4 +-
>>  arch/alpha/kernel/traps.c                          |  24 ++---
>>  arch/alpha/mm/fault.c                              |   4 +-
>>  arch/arm/kernel/signal.c                           |  39 +++++++
>>  arch/arm64/kernel/signal.c                         |  39 +++++++
>>  arch/arm64/kernel/signal32.c                       |  39 +++++++
>>  arch/mips/include/uapi/asm/siginfo.h               |   2 -
>>  arch/sparc/include/uapi/asm/siginfo.h              |   3 -
>>  arch/sparc/kernel/process_64.c                     |   2 +-
>>  arch/sparc/kernel/signal32.c                       |  37 +++++++
>>  arch/sparc/kernel/signal_64.c                      |  36 +++++++
>>  arch/sparc/kernel/sys_sparc_32.c                   |   2 +-
>>  arch/sparc/kernel/sys_sparc_64.c                   |   2 +-
>>  arch/sparc/kernel/traps_32.c                       |  22 ++--
>>  arch/sparc/kernel/traps_64.c                       |  44 ++++----
>>  arch/sparc/kernel/unaligned_32.c                   |   2 +-
>>  arch/sparc/mm/fault_32.c                           |   2 +-
>>  arch/sparc/mm/fault_64.c                           |   2 +-
>>  arch/x86/kernel/signal_compat.c                    |  15 ++-
>
> No changes needed for other architectures?
> All m68k configs are broken with

Thanks.  I hadn't realized that si_perf asserts existed on m68k.
Thankfully linux-next caught this these.

Looking a little more deeply, it is strange that this is tested on m68k.
The architecture does not implement HAVE_PERF_EVENTS so it is impossible
for this signal to be generated.

On the off chance this these new signals will appear on m68k someday I
will update the assertion.

> arch/m68k/kernel/signal.c:626:35: error: 'siginfo_t' {aka 'struct
> siginfo'} has no member named 'si_perf'; did you mean 'si_errno'?
>
> See e.g. http://kisskb.ellerman.id.au/kisskb/buildresult/14537820/
>
> There are still a few more references left to si_perf:
>
> $ git grep -n -w si_perf
> Next/merge.log:2902:Merging userns/for-next (4cf4e48fff05 signal: sort
> out si_trapno and si_perf)
> arch/m68k/kernel/signal.c:626:  BUILD_BUG_ON(offsetof(siginfo_t,
> si_perf) != 0x10);
> include/uapi/linux/perf_event.h:467:     * siginfo_t::si_perf, e.g. to
> permit user to identify the event.
> tools/testing/selftests/perf_events/sigtrap_threads.c:46:/* Unique
> value to check si_perf is correctly set from
> perf_event_attr::sig_data. */

I will sweep them up as well.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1pmy36gja.fsf%40fess.ebiederm.org.
