Return-Path: <kasan-dev+bncBCALX3WVYQORBXXDXOCAMGQEO4KYEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86680370E8E
	for <lists+kasan-dev@lfdr.de>; Sun,  2 May 2021 20:39:27 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id d5-20020a67c1050000b02902228a77a0e6sf1783132vsj.7
        for <lists+kasan-dev@lfdr.de>; Sun, 02 May 2021 11:39:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619980766; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEGz53d4gwBE8SrWc0lB9Jyo3tCKqxTLzRdlnAQILZUEDcJYtulSLrBvKniszXKZt3
         kXi4CIcW7kNoP0K7/fPw5Dm+80dU3V1st0N+nmFE8t8WCWPNNGS3Q5gHsRtHY1tRKzyM
         kDVpi6Voj4NT4SnJCxKJCKE0JGKzXj4gQHzlDhnxGTeIazzFyXFECWxNhf3RPHx3Zsv/
         73VpJqgw7tRKkWW5wKRtqzUvBaVHvuDDPHjgyY1+5KLpJSmwlQkq51ccSUcUq2ERwL5M
         JIv/exLgSYONsw4ABcFVWcQbpuZHlrGks/BAjYfY3nv4ClbhF7Wq/lJiuBEzfmX67QpL
         xEcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=vAJiafxwgaCPmQBWxJb4qE00BXSG38865KYFH22i/vI=;
        b=Mi+Io2uHQpSOyt3tgCgZuUh6Tw5H4F466R0XPo+M7MaU9ugup7QQYRyQ5aEbIBFIKf
         5dAA6ex97K4RhK8al/0D7RpZdfiG3LXWepHPaKBcnyEIc/Ahe+S8UuzaOPd8/qwbFKds
         ItHLITfGk6rDato5i26SBscjTjf91uc6kSb9qKgY2AI7yT/IVCw0JkVxYA0JIs2CaMl/
         qgJOjgJ5S/WuEEcKWgE0JMErq90JGmu9S54285W5yutYaGRwI/a3H0zS6jDrrQrq4mM1
         aqFUDLXahfKgLwLQ+c5I8/0o2fGujWivYH6rFS1MR/CXGCa+BVwi/+Y2Sq8nmlKbzzgJ
         Z9+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vAJiafxwgaCPmQBWxJb4qE00BXSG38865KYFH22i/vI=;
        b=QP5UbuLdiE5Ur3WB3idTtwsF42NJqj01WKgLBT/RNzYNoN3w0smbDmHSj0iOgXq22C
         0wVphrtyySaJkiavlykZzOuqKjSSvlfNydpThpocQYZohSC3ttasVIE3d24rJkNsLXp1
         v4hmvgOqsqZQV+yDb9DkBRYPJMQWgsVhoiYogMUd7TmZZpZ7lgPCpW5tnOaPji+yyskL
         Izmj40MF9VooSOiRY7zA+oe2QOkiRuTUf1MgGrlNlS+UCnDicRgTXf/1xAZcFwTiQhnw
         ivAAZCE40RxM1WS92wjmGm6PHS/Zs1n90ytHf5+le/MTn8G4Y2C0WO9SYPDOfRs2NsOr
         3SYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vAJiafxwgaCPmQBWxJb4qE00BXSG38865KYFH22i/vI=;
        b=Gyh7kLoDK4N/BHVArKMQX+twvIKnlcyg4lqv8Zn/vRyhqjCh6vxncL2efon9Tk9VPO
         RCtWNARVGy7vze89GOwu9PrC55nHuYJ3zDCnarXOrw3cQDnFdQI7o/BWnB011TxCO2Rt
         Tv5ftGCd6Dh8suByH1l+k+kD5R0UJwNzoK+uluRcCNS/eSQAhj6tLoCeO9XM4RNKgNEE
         07qvgYDtEAUFesRgg61uNlh9NhwWaK8TrY99rJe3PvbiIV5bAQa49BVBMwt+CpJEpU7K
         E70cn+9hKCXxcwxWAHtioh06piRDJ7n+dSxxCHXvl9GWnO8BPboW0Tgi6DVDFlkmC8pk
         Zlmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ToAOlp9aq2NuOxD1dVj+EIemFy9uoYpllsFtuOQFde5Z7NhqC
	1ZCcCFXRkMsSUXzehJ21oJM=
X-Google-Smtp-Source: ABdhPJw5W3P4vHyu85E9GZfdjIFzrsgd98lUSHv2FzXAfC9jt38kDtkArNHbs1H3kdKraisSxqfeRw==
X-Received: by 2002:a05:6102:22ef:: with SMTP id b15mr1347979vsh.35.1619980766478;
        Sun, 02 May 2021 11:39:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a74f:: with SMTP id q76ls908733vke.11.gmail; Sun, 02 May
 2021 11:39:26 -0700 (PDT)
X-Received: by 2002:a1f:ae94:: with SMTP id x142mr11727584vke.12.1619980766021;
        Sun, 02 May 2021 11:39:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619980766; cv=none;
        d=google.com; s=arc-20160816;
        b=i3fjinRAhEvoPLGs/f98++wMaKxSusXNxztOF55hfnbOW0r5SioMLe2NARpNpvvbc2
         N3MEIk6N0DeGbJ8JFaK/1MOYipDZHKtJs6TgGO4uDlkaAe2jaLfb1EHtE2KPNDcpo3je
         JN07Dew6B+FMvW/Vvu4vsKhcV5W4y0sKVHqfVp0Vk7uL0tNnT15AR5T0iS+qgr77Ja8K
         pYtlQU+zFZdct+rO0JXhxma+GOcAoSkIm/hPvXy6+cG8GyxpTBPiXEzsmGEghe+XRbsU
         UoTgSU3NQB0rCHrkarxMKc1HIGeK9kcqq/hCtVGu0sJnE/hjFKAo3J3A/pctYFcxDJ6c
         mMMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=PNFr8J1Y/723qBsFKm96Vn1BPUO0pk3/LctUj+Mi0to=;
        b=Gu27H6SkoiJn6xpZr2iJln/ogPbz/Osc42EDSQ+SxY0AxZlRGEXiU6ns7fU4qSGKFr
         NSNhurRAk9HNvuK3qjxzPEYoir5BdsX4gHa761eFbDT7xV5Flf3sI4qyLSczNyN/kJQE
         H/siD/s0T0zoCmm5FkTHJrVZKOvlT4sE8m2xmxnXDO3FaCG4w4PNeevzN0pHJceSWg2n
         EurjJv6+KndyTTcg/+7M83woY0MUmN4Jvl56ee909grOCAeeQA26ZuFA2I+UxI1c9Lhc
         Tj2dHGLniiMpj50CGTNnJo1h0Dy5jFa4jW1X/CVu44epUsw1Irt9uUQrlHQ7oAAjaxFb
         hscA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id m184si1182807vkg.5.2021.05.02.11.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 May 2021 11:39:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGzy-00FCZQ-V6; Sun, 02 May 2021 12:39:23 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldGzx-0006hK-2a; Sun, 02 May 2021 12:39:22 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m11rarqqx2.fsf_-_@fess.ebiederm.org>
	<CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
Date: Sun, 02 May 2021 13:39:16 -0500
In-Reply-To: <CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
	(Marco Elver's message of "Sat, 1 May 2021 12:47:21 +0200")
Message-ID: <m1wnshm14b.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldGzx-0006hK-2a;;;mid=<m1wnshm14b.fsf@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/61Mdwb7TuChJAy6IEn9kCmxkmOP4SzJw=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: ****
X-Spam-Status: No, score=4.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	T_XMDrugObfuBody_08,XMNoVowels,XMSubLong autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4960]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ****;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 591 ms - load_scoreonly_sql: 0.09 (0.0%),
	signal_user_changed: 13 (2.1%), b_tie_ro: 11 (1.8%), parse: 1.61
	(0.3%), extract_message_metadata: 16 (2.7%), get_uri_detail_list: 3.7
	(0.6%), tests_pri_-1000: 14 (2.3%), tests_pri_-950: 1.44 (0.2%),
	tests_pri_-900: 1.21 (0.2%), tests_pri_-90: 69 (11.7%), check_bayes:
	68 (11.5%), b_tokenize: 13 (2.2%), b_tok_get_all: 11 (1.8%),
	b_comp_prob: 2.8 (0.5%), b_tok_touch_all: 38 (6.4%), b_finish: 0.89
	(0.1%), tests_pri_0: 448 (75.7%), check_dkim_signature: 0.71 (0.1%),
	check_dkim_adsp: 2.5 (0.4%), poll_dns_idle: 0.70 (0.1%), tests_pri_10:
	3.4 (0.6%), tests_pri_500: 20 (3.4%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
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

Marco Elver <elver@google.com> writes:

> On Sat, 1 May 2021 at 01:44, Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> Don't abuse si_errno and deliver all of the perf data in si_perf.
>>
>> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
>> ---
>
> Thank you for the fix, this looks cleaner.
>
> Just note that this patch needs to include updates to
> tools/testing/selftests/perf_events. This should do it:
>>  sed -i 's/si_perf/si_perf.data/g; s/si_errno/si_perf.type/g' tools/testing/selftests/perf_events/*.c
>
> Subject: s/perf_data/perf data/ ?
>
> For uapi, need to switch to __u32, see below.

Good point.

The one thing that this doesn't do is give you a 64bit field
on 32bit architectures.

On 32bit builds the layout is:

	int si_signo;
	int si_errno;
	int si_code;
	void __user *_addr;
        
So I believe if the first 3 fields were moved into the _sifields union
si_perf could define a 64bit field as it's first member and it would not
break anything else.

Given that the data field is 64bit that seems desirable.

Eric


>>  fs/signalfd.c                      |  3 ++-
>>  include/linux/compat.h             |  5 ++++-
>>  include/uapi/asm-generic/siginfo.h |  5 ++++-
>>  include/uapi/linux/signalfd.h      |  4 ++--
>>  kernel/signal.c                    | 18 +++++++++++-------
>>  5 files changed, 23 insertions(+), 12 deletions(-)
>>
>> diff --git a/fs/signalfd.c b/fs/signalfd.c
>> index 83130244f653..9686af56f073 100644
>> --- a/fs/signalfd.c
>> +++ b/fs/signalfd.c
>> @@ -134,7 +134,8 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>>                 break;
>>         case SIL_FAULT_PERF_EVENT:
>>                 new.ssi_addr = (long) kinfo->si_addr;
>> -               new.ssi_perf = kinfo->si_perf;
>> +               new.ssi_perf_type = kinfo->si_perf.type;
>> +               new.ssi_perf_data = kinfo->si_perf.data;
>>                 break;
>>         case SIL_CHLD:
>>                 new.ssi_pid    = kinfo->si_pid;
>> diff --git a/include/linux/compat.h b/include/linux/compat.h
>> index 24462ed63af4..0726f9b3a57c 100644
>> --- a/include/linux/compat.h
>> +++ b/include/linux/compat.h
>> @@ -235,7 +235,10 @@ typedef struct compat_siginfo {
>>                                         u32 _pkey;
>>                                 } _addr_pkey;
>>                                 /* used when si_code=TRAP_PERF */
>> -                               compat_ulong_t _perf;
>> +                               struct {
>> +                                       compat_ulong_t data;
>> +                                       u32 type;
>> +                               } _perf;
>>                         };
>>                 } _sigfault;
>>
>> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
>> index 2abdf1d19aad..19b6310021a3 100644
>> --- a/include/uapi/asm-generic/siginfo.h
>> +++ b/include/uapi/asm-generic/siginfo.h
>> @@ -90,7 +90,10 @@ union __sifields {
>>                                 __u32 _pkey;
>>                         } _addr_pkey;
>>                         /* used when si_code=TRAP_PERF */
>> -                       unsigned long _perf;
>> +                       struct {
>> +                               unsigned long data;
>> +                               u32 type;
>
> This needs to be __u32.
>
>
>> +                       } _perf;
>>                 };
>>         } _sigfault;
>>
>> diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
>> index 7e333042c7e3..e78dddf433fc 100644
>> --- a/include/uapi/linux/signalfd.h
>> +++ b/include/uapi/linux/signalfd.h
>> @@ -39,8 +39,8 @@ struct signalfd_siginfo {
>>         __s32 ssi_syscall;
>>         __u64 ssi_call_addr;
>>         __u32 ssi_arch;
>> -       __u32 __pad3;
>> -       __u64 ssi_perf;
>> +       __u32 ssi_perf_type;
>> +       __u64 ssi_perf_data;
>>
>>         /*
>>          * Pad strcture to 128 bytes. Remember to update the
>> diff --git a/kernel/signal.c b/kernel/signal.c
>> index 5b1ad7f080ab..cb3574b7319c 100644
>> --- a/kernel/signal.c
>> +++ b/kernel/signal.c
>> @@ -1758,11 +1758,13 @@ int force_sig_perf(void __user *pending_addr, u32 type, u64 sig_data)
>>         struct kernel_siginfo info;
>>
>>         clear_siginfo(&info);
>> -       info.si_signo = SIGTRAP;
>> -       info.si_errno = type;
>> -       info.si_code  = TRAP_PERF;
>> -       info.si_addr  = pending_addr;
>> -       info.si_perf  = sig_data;
>> +       info.si_signo     = SIGTRAP;
>> +       info.si_errno     = 0;
>> +       info.si_code      = TRAP_PERF;
>> +       info.si_addr      = pending_addr;
>> +       info.si_perf.data = sig_data;
>> +       info.si_perf.type = type;
>> +
>>         return force_sig_info(&info);
>>  }
>>
>> @@ -3379,7 +3381,8 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>>                 break;
>>         case SIL_FAULT_PERF_EVENT:
>>                 to->si_addr = ptr_to_compat(from->si_addr);
>> -               to->si_perf = from->si_perf;
>> +               to->si_perf.data = from->si_perf.data;
>> +               to->si_perf.type = from->si_perf.type;
>>                 break;
>>         case SIL_CHLD:
>>                 to->si_pid = from->si_pid;
>> @@ -3455,7 +3458,8 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>>                 break;
>>         case SIL_FAULT_PERF_EVENT:
>>                 to->si_addr = compat_ptr(from->si_addr);
>> -               to->si_perf = from->si_perf;
>> +               to->si_perf.data = from->si_perf.data;
>> +               to->si_perf.type = from->si_perf.type;
>>                 break;
>>         case SIL_CHLD:
>>                 to->si_pid    = from->si_pid;
>> --
>> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1wnshm14b.fsf%40fess.ebiederm.org.
