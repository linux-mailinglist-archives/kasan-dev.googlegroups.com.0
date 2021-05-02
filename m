Return-Path: <kasan-dev+bncBCALX3WVYQORB5W4XOCAMGQEJZ4465Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FFE7370E6C
	for <lists+kasan-dev@lfdr.de>; Sun,  2 May 2021 20:24:56 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id d17-20020a634f110000b029020ff9c39809sf686243pgb.16
        for <lists+kasan-dev@lfdr.de>; Sun, 02 May 2021 11:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619979895; cv=pass;
        d=google.com; s=arc-20160816;
        b=UKO4uff9mvdBu+Fx6HSH4hwlptG8xPAjQ1zHmd4llmlKNUFlruBXl4L0njSNC3Zyug
         /8FDUGDKPMix7ja/zXhRKgBhpbWCH+xAOSqplKJJDNLNT2IwZsH9laPztHdgXgZUVMlY
         0o1KvLpkcqOZHmHCDwyBNu/1DqNSl+wdghO4XLhyYHOwsTkbBIYLzGyhHxZsvH4l86dp
         Zyks2qZTtw/zX3bcG3knghuxMejNIWkDIax1rVrDX3OXVhriWDKVzSMzMWZWvRMkvlLQ
         29NIQH2PWRTZNoE5YQSgb8HjtUnZqIMmml1njUp60UJOwmu5jkdWEqAGncEI5hYUhB6t
         nNaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=spUFENSM9GHyXtmwtL7HTOSP1G8TVWduQaeCPd7BwKk=;
        b=e4tnm7JnoUf2oRY6g4fQkS0Oev3NlfOZancRrpJh0e/w53lPzqSa99T/tuJmAwf90O
         GESaDWq+FgPMmZg9NssBAxbdfJwJCXTiyDhw//ap+8Z43IbwdMp8zFx3HH+VKJTxdFOk
         nTpnDP34dGaDIuykFdyPj3BprKAM2Npj0ynXsi9ZrBeB8srt6WjZBPvdZZIfNvFL4sgO
         09UvWMpzelnmribnwBjQpZiBWahbmlZZnj8FOftn7zXhRYaCe31imnHNNjmlCZ242hmA
         TR+QQVYpEdXiM5WsLHT6/mqL6nHPUCPVmybYlwzYejGQkTTZV0c3NLbnS2w8zpSph3Br
         KZnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=spUFENSM9GHyXtmwtL7HTOSP1G8TVWduQaeCPd7BwKk=;
        b=XN13CnPgcQjqkMMeexAgF8njiiKaOVuRLCac1l2wY2PQ2+C6Am5iHpGRNPIqPeqCBk
         8/nA/gCqu7WyKQkdV+rJC6Ow4ReRaVmHxruYdszjHXic4F6B+B4iai9nzr5u1Gyig2n6
         CgylBOzzNrmmFYdiFghPLHsH4I2UVeEeyVYJzqKaJPqX+HJe6mr85kyXoNWgdGqAeii6
         AE20H/lYYlx3g9KznjPXJ3mmKiJmfQT8yFlpc3FU8ujWOdkjsCzb2gPxE4qv/ceY3DoE
         KmqB1fnnUHq3x4j3CV6MGswdY6gR9fGI/253IntbinPVD2g5JIKdXMxub8EQHDF5FpTK
         igzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=spUFENSM9GHyXtmwtL7HTOSP1G8TVWduQaeCPd7BwKk=;
        b=MBwUYw4rm22/fprjcWyKLeaPsgpYugtAkAF9QVAetE4VjBmNrbmdoG0fFgo4QMKaxr
         Px+MlK3uQnM4w3YICQJsMbPi7dDCq9durJpbYeBw6KxrQmTEqGrbBVHmhjnr7/3QCYqM
         14T1bfFu95/3memII5CvSljZAagnfdqgnWEkZ2HTgteQ8cevKWqys6X6cFL50RWx2wp8
         TQhDZYT7J28qG5WhIHVbjaJ0vtjvrASVP+TuWR4DjqnUHgfwnKGjNpUyz+qNXz/O1NXZ
         79yfBr8rhU1Fm6uFCCwJtojeYH/GMf8qKNwSmL0IkFssPW2z9F1mLyKFp/ycdqiYu8R9
         YTfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qeFbVVQL+tnev0BLyGhPimYCcJQ+r2SzlUoGlJJaQRSl6QKT6
	NqL/2QxukspaW0nteaHR2Eg=
X-Google-Smtp-Source: ABdhPJwboQ56cLeBdAoLaFtUKPxSbsP7s+RAIkpfIG4EVDizv77zGm58/IKHt9JT5JmmfVdcOL4aaQ==
X-Received: by 2002:a17:902:d2c3:b029:ed:764e:d1f4 with SMTP id n3-20020a170902d2c3b02900ed764ed1f4mr16414538plc.84.1619979894987;
        Sun, 02 May 2021 11:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8d85:: with SMTP id i5ls4761198pfr.0.gmail; Sun, 02 May
 2021 11:24:54 -0700 (PDT)
X-Received: by 2002:a63:ad05:: with SMTP id g5mr14565887pgf.239.1619979894310;
        Sun, 02 May 2021 11:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619979894; cv=none;
        d=google.com; s=arc-20160816;
        b=iarLojvNrkKmVOA8ZdFRoqY27+pQmiPvXCmmLBuuAu8N1KhaI/+EYo0YFpfoH07fHG
         5QKPSAETC88lfjUFyk3wEt7Zq8e+QLxryt69pmBEubCAVrXQvgl+dOFjzi+5lkuUgGCd
         klGLQgpMk2x1qGH4jPL7RD+hFIoJXV7iIdSJLR2TeAUOWE6JmvpcX2+VsLJ7tag4rJS5
         yP6dAhsrTrSjELAAkur7A2QeEdrBgfVcnA0HK5pJRNPUs+PSFR3wIq6llgHLnFNsHfr1
         p9vAU2m9LAqzBf1qKO3h/3p3K2muUNpajX9WYjCxureeXHGjpU6yutHzqY0BhC1h275n
         yJXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=PTlnVwVDjpNfBcq/ljw3WmT6RM0Uz8NpSJqPIoGJS8E=;
        b=CVFHo+C9AZ0mlVUcLEW8/YqJjXY/b50jIkkGNvtuYuQ9qxEseVriKvDmb9Yxn4uOj5
         7j3GQXG7NH+WrSEHU5/BSbENzDUePlhBweZapv5ayktQd2Zt7LpWcTqiQWvGbFo9yTSU
         IhLMPBSGlCv95OT+2xfDStZPUgt9d/c9R1QaWJa42MqRVIxpFENmpf9JD1NPwWbVX9yz
         ysCqUdPAxkU8ETIfxr6b3e//IQkpi3Cr1Kn6/WZuCJeGwtiOQFnhaKJTIqkSq/9kP1TM
         kWYHE5H05wUTC2Fx5rER5Sx3ahe+tJR7MrMJbAJA6Yavn3Bq6i9LyP9lqEfFc+cUV3xz
         niIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id n35si147793pfv.6.2021.05.02.11.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 May 2021 11:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGlv-006v2s-Aq; Sun, 02 May 2021 12:24:51 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGlu-00BNqY-8D; Sun, 02 May 2021 12:24:50 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1o8dvs7s7.fsf_-_@fess.ebiederm.org>
	<CANpmjNNhd+qAy7tPSu=08_y-BZiowKigVkOh6HnXsxhWYuFpJA@mail.gmail.com>
Date: Sun, 02 May 2021 13:24:46 -0500
In-Reply-To: <CANpmjNNhd+qAy7tPSu=08_y-BZiowKigVkOh6HnXsxhWYuFpJA@mail.gmail.com>
	(Marco Elver's message of "Sat, 1 May 2021 12:33:27 +0200")
Message-ID: <m1sg35ngcx.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldGlu-00BNqY-8D;;;mid=<m1sg35ngcx.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/0HsNqVjpzSZgBfn2EWtFrYSso3wfS118=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMNoVowels autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4942]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 509 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 3.6 (0.7%), b_tie_ro: 2.4 (0.5%), parse: 0.84
	(0.2%), extract_message_metadata: 9 (1.8%), get_uri_detail_list: 2.3
	(0.5%), tests_pri_-1000: 11 (2.1%), tests_pri_-950: 1.03 (0.2%),
	tests_pri_-900: 0.83 (0.2%), tests_pri_-90: 79 (15.4%), check_bayes:
	78 (15.2%), b_tokenize: 10 (1.9%), b_tok_get_all: 9 (1.8%),
	b_comp_prob: 1.59 (0.3%), b_tok_touch_all: 54 (10.6%), b_finish: 0.64
	(0.1%), tests_pri_0: 395 (77.6%), check_dkim_signature: 0.44 (0.1%),
	check_dkim_adsp: 2.2 (0.4%), poll_dns_idle: 0.88 (0.2%), tests_pri_10:
	1.55 (0.3%), tests_pri_500: 5 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 2/3] signal: Implement SIL_FAULT_TRAPNO
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

> On Sat, 1 May 2021 at 00:54, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> Now that si_trapno is part of the union in _si_fault and available on
>> all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
>> return SIL_FAULT_TRAPNO when si_trapno is actually used.
>>
>> Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
>> and have the same code ignore si_trapno in in all other cases.
>>
>> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
>> ---
>>  fs/signalfd.c          |  7 ++-----
>>  include/linux/signal.h |  1 +
>>  kernel/signal.c        | 36 ++++++++++++++----------------------
>>  3 files changed, 17 insertions(+), 27 deletions(-)
>>
>> diff --git a/fs/signalfd.c b/fs/signalfd.c
>> index 040a1142915f..126c681a30e7 100644
>> --- a/fs/signalfd.c
>> +++ b/fs/signalfd.c
>> @@ -123,15 +123,12 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>>                  */
>>         case SIL_FAULT:
>>                 new.ssi_addr = (long) kinfo->si_addr;
>> -#ifdef __ARCH_SI_TRAPNO
>> +       case SIL_FAULT_TRAPNO:
>> +               new.ssi_addr = (long) kinfo->si_addr;
>>                 new.ssi_trapno = kinfo->si_trapno;
>> -#endif
>>                 break;
>>         case SIL_FAULT_MCEERR:
>>                 new.ssi_addr = (long) kinfo->si_addr;
>> -#ifdef __ARCH_SI_TRAPNO
>> -               new.ssi_trapno = kinfo->si_trapno;
>> -#endif
>>                 new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>>                 break;
>>         case SIL_PERF_EVENT:
>> diff --git a/include/linux/signal.h b/include/linux/signal.h
>> index 1e98548d7cf6..5160fd45e5ca 100644
>> --- a/include/linux/signal.h
>> +++ b/include/linux/signal.h
>> @@ -40,6 +40,7 @@ enum siginfo_layout {
>>         SIL_TIMER,
>>         SIL_POLL,
>>         SIL_FAULT,
>> +       SIL_FAULT_TRAPNO,
>>         SIL_FAULT_MCEERR,
>>         SIL_FAULT_BNDERR,
>>         SIL_FAULT_PKUERR,
>> diff --git a/kernel/signal.c b/kernel/signal.c
>> index c3017aa8024a..7b2d61cb7411 100644
>> --- a/kernel/signal.c
>> +++ b/kernel/signal.c
>> @@ -1194,6 +1194,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
>>         case SIL_TIMER:
>>         case SIL_POLL:
>>         case SIL_FAULT:
>> +       case SIL_FAULT_TRAPNO:
>>         case SIL_FAULT_MCEERR:
>>         case SIL_FAULT_BNDERR:
>>         case SIL_FAULT_PKUERR:
>> @@ -2527,6 +2528,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
>>  {
>>         switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
>>         case SIL_FAULT:
>> +       case SIL_FAULT_TRAPNO:
>>         case SIL_FAULT_MCEERR:
>>         case SIL_FAULT_BNDERR:
>>         case SIL_FAULT_PKUERR:
>> @@ -3206,6 +3208,12 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>>                         if ((sig == SIGBUS) &&
>>                             (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
>>                                 layout = SIL_FAULT_MCEERR;
>> +                       else if (IS_ENABLED(ALPHA) &&
>> +                                ((sig == SIGFPE) ||
>> +                                 ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
>> +                               layout = SIL_FAULT_TRAPNO;
>> +                       else if (IS_ENABLED(SPARC) && (sig == SIGILL) && (si_code == ILL_ILLTRP))
>> +                               layout = SIL_FAULT_TRAPNO;
>
> The breakage isn't apparent here, but in later patches. These need to
> become CONFIG_SPARC and CONFIG_ALPHA.

Good catch.  For some reason I thought IS_ENABLED added the CONFIG_
prefix but I looked and it doesn't.


>>                         else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
>>                                 layout = SIL_FAULT_BNDERR;
>>  #ifdef SEGV_PKUERR
>> @@ -3317,30 +3325,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>>                 break;
>>         case SIL_FAULT:
>>                 to->si_addr = ptr_to_compat(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> +               break;
>> +       case SIL_FAULT_TRAPNO:
>> +               to->si_addr = ptr_to_compat(from->si_addr);
>>                 to->si_trapno = from->si_trapno;
>> -#endif
>>                 break;
>>         case SIL_FAULT_MCEERR:
>>                 to->si_addr = ptr_to_compat(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_addr_lsb = from->si_addr_lsb;
>>                 break;
>>         case SIL_FAULT_BNDERR:
>>                 to->si_addr = ptr_to_compat(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_lower = ptr_to_compat(from->si_lower);
>>                 to->si_upper = ptr_to_compat(from->si_upper);
>>                 break;
>>         case SIL_FAULT_PKUERR:
>>                 to->si_addr = ptr_to_compat(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_pkey = from->si_pkey;
>>                 break;
>>         case SIL_PERF_EVENT:
>> @@ -3401,30 +3401,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>>                 break;
>>         case SIL_FAULT:
>>                 to->si_addr = compat_ptr(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> +               break;
>> +       case SIL_FAULT_TRAPNO:
>> +               to->si_addr = compat_ptr(from->si_addr);
>>                 to->si_trapno = from->si_trapno;
>> -#endif
>>                 break;
>>         case SIL_FAULT_MCEERR:
>>                 to->si_addr = compat_ptr(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_addr_lsb = from->si_addr_lsb;
>>                 break;
>>         case SIL_FAULT_BNDERR:
>>                 to->si_addr = compat_ptr(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_lower = compat_ptr(from->si_lower);
>>                 to->si_upper = compat_ptr(from->si_upper);
>>                 break;
>>         case SIL_FAULT_PKUERR:
>>                 to->si_addr = compat_ptr(from->si_addr);
>> -#ifdef __ARCH_SI_TRAPNO
>> -               to->si_trapno = from->si_trapno;
>> -#endif
>>                 to->si_pkey = from->si_pkey;
>>                 break;
>>         case SIL_PERF_EVENT:
>> --
>> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1sg35ngcx.fsf%40fess.ebiederm.org.
