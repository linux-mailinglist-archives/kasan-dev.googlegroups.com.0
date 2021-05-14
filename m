Return-Path: <kasan-dev+bncBCALX3WVYQORB3PX7OCAMGQEL3QVMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0056D3813D0
	for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 00:38:38 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id m18-20020a056e020df2b02901a467726f49sf981207ilj.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 15:38:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621031918; cv=pass;
        d=google.com; s=arc-20160816;
        b=N8hZprS9nfA78gwdb94Lj9CjZQrxkarGR3ZTB2VZE6sMIeMVTM/6gmNW3oru6lT1W1
         ALxVebTMcA7XKzSZ1ElyVkyh8XJLqSQSBqAol0tV3o9ykS0UGLf1q2FwdfsQaH54m/eW
         DueVaLW+JrR8kcAtUVUhPD0aRkxLI4pDdeBaySLpK1xhF8xEYZ5mBetiWnLW0ASfInLT
         xuHnBhiwQAvUKjs8Sy2COilbxllIBRwKFJO9en1RiqYD0LMj0TG6tHj+VCLx9lqD7KCn
         hS4qmgw2TVowYDDY7oWgQEmhzUrDAFhmFdOZ+fHFPyAQcstc/OpmWwRFv5cUD/DkoERb
         xtYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=EHgWOYc59UjwjW8evCoJosSP4SuwgW8WeFYXKZC1THc=;
        b=CHcyOBIjGZgAO2bX0SI6QrfRAp9sMRjvZt7LmCCBJLx9cU9mSryNU/+cq3iNrawBfg
         DNt7OUG6d6AFDmYkqCEm33NrKk52nhuPN+lVDZsgDrUHIl1ko9d2+k78+IMMNdirc80J
         uRHiPwaLtwtZ6a9Ovz8FJAEUXn2oJl/9fDeu/jGVLdgLz82nCgaLU9kvOvnBIuAFokDn
         lKiZ3Zd6NYpnVWogXR83RGH4zJdx4Ad1oOhtLnzJM+o7CdNf1VnTHOrBnp+x4iZ6sSDv
         T/C+9vVxmzgLo2GjrhQka6P0+K3tSi6IeX2Dlv0bFtBZhCYKJujX22qQMXFn6KaqbWGF
         FZqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EHgWOYc59UjwjW8evCoJosSP4SuwgW8WeFYXKZC1THc=;
        b=m5wvtdv4BMND9py3BcEBDQjKaxbxCilgYuBu21twO7nVQi3hopRNF4V+PVAXsFEbZ/
         /jAPgZEu/rVgvXNbGCSyYPpNfqTd7daW901ijEe2plV6pSSKVgYzUdStJIh0Gc8/XpsU
         xTuuEcwJ7+slxW9kHrMLL2oMn2CqrJcJ5xaNrot9L5Kzrg6R8uRCMs/QG1hXxc2Bz92z
         tSWE6Wx+7YIFlVzE1HFlnFPY3G5SJI1OPH3MSQaJZ1Ot6EIgatW7/E6Jzky2Oh8fiKsd
         eMGhBGxiECiT8UNnV02LilFRrt8lHUHxFVSAfiVlelju5flP2vBJMInEL0t3ixibqDWC
         0N3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHgWOYc59UjwjW8evCoJosSP4SuwgW8WeFYXKZC1THc=;
        b=DxxExiDhTztqAYXE5h5g1UhY1kU8Xl1dtb3kh51X4ktFSZDQU38xmyf4EiC4K0qrwt
         ae55wYoWlXk2ReyZvPqvFxnn0YfBLzVutRIo3cKP1i45YgT/+EBlogQJyiOjZtkcRSo1
         2RbKkpB2AVaIr9d7eXNiLi/wj9pZBoP6/zs5ny/HPcUjymwQglWjPRoLlp2SfOzhkYqe
         26OMuNmSa+4BQJxf+zqPxWIMCb0aUek679jvtOB7z8DmoXRTMc0SEzfHL2HPzmCCqClz
         Q1P59rdUPR7jptD/L6ZxodgwbaSnuOQLifhzQweoDVvnOg4iA4CiiD835D6xarl9I87R
         ouZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530W1WEY7XsxrRvvnD4D6wp2xHJHP37+a/x3UwWW7EztNHgpXVMV
	L8o5SkTpoD1RRiKOAkRuC8o=
X-Google-Smtp-Source: ABdhPJyHC62quM4FKRxWnW3lAIcozXI0khN7p0Ks9Rmhl5ScZrP6D2+2jUyhx9uwOuP9P+jgrkLvaw==
X-Received: by 2002:a05:6e02:10c6:: with SMTP id s6mr45097700ilj.15.1621031917995;
        Fri, 14 May 2021 15:38:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:114f:: with SMTP id o15ls2610933ill.1.gmail; Fri,
 14 May 2021 15:38:37 -0700 (PDT)
X-Received: by 2002:a05:6e02:84:: with SMTP id l4mr32983680ilm.278.1621031917735;
        Fri, 14 May 2021 15:38:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621031917; cv=none;
        d=google.com; s=arc-20160816;
        b=O2EFLC9HzPyJjHLR++zo1580TpAQic6MV/w5Vuy0F/H8wdrSmIqPMzcWP80UZOIF+x
         hGp2sXhnAz5aYBugpl3Y612Q5isvsVCK3nHuOTf4EyAaYi+20OYO+Va65Ozo6SdcMBZ8
         8kLFesavl2oQtAgnwUxI8B4wGVokCb07RN+e6hk2lFUprkYMUvMnYtX34ox/OkfI4zBz
         VpEF9pAyG/RzV27coxct242qTMrMfaWN0HTsiN6kxAPknCTELFR8PPRzGr0gLHxIyMAp
         juwPH/lHFSV/gxRt8rbg3cQ0jcB6gsKtbx5k3HuAQ/7IR4Vbvu9vI2ptfT4Ilk3+qZTD
         U2TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=AkwSbhlfUVXgBkwGP3PDhtZ4NKHDyAHd9z8OTnydtGM=;
        b=v/OpQdWhhWMmNw7GQIxE47DlPRxMskMXmPRqz6mbinO1TIgeDtbIk6pE9xGVftLV0w
         7UQB+thS6Joir7GWprWa87pEmYodMHIJ7egHpBouf6WZRNi04+Z57u3zfqCjeF48x+9E
         D4291fPVO3sp6/pmRttRvsmcxpj/KNM3f+A94b5BOS9BgUrk+RxjuIgsmlhxqTFvjy+h
         h+5c4jALU4tWBK6oAKqtUAz9BI4OWHAZ/MZGao9sG+mVWW1xFLPq9SfQItC1uBoerlSn
         abLLGfwslG/LZXX4lLe5JELfSpRLQPLTVa4r8inPzuXoLAF/CBaZzdt7z4isiY3yXEeI
         LNZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id h2si385988ila.4.2021.05.14.15.38.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 May 2021 15:38:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhgS0-004tzQ-9N; Fri, 14 May 2021 16:38:32 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhgRz-004D3L-AH; Fri, 14 May 2021 16:38:31 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>,  Marco Elver <elver@google.com>
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
	<m1a6oxewym.fsf_-_@fess.ebiederm.org>
	<CAHk-=wikDD+gCUECg9NZAVSV6W_FUdyZFHzK4isfrwES_+sH-w@mail.gmail.com>
	<m14kf5aufb.fsf@fess.ebiederm.org>
Date: Fri, 14 May 2021 17:38:25 -0500
In-Reply-To: <m14kf5aufb.fsf@fess.ebiederm.org> (Eric W. Biederman's message
	of "Fri, 14 May 2021 16:15:36 -0500")
Message-ID: <m1tun57xge.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lhgRz-004D3L-AH;;;mid=<m1tun57xge.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19odSp5HEfI42QhPUSRdilH+u4toHAL8FY=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.3 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMSubMetaSxObfu_03,XMSubMetaSx_00 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.1368]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 XMSubMetaSx_00 1+ Sexy Words
	*  1.2 XMSubMetaSxObfu_03 Obfuscated Sexy Noun-People
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Linus Torvalds <torvalds@linux-foundation.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 412 ms - load_scoreonly_sql: 0.08 (0.0%),
	signal_user_changed: 11 (2.7%), b_tie_ro: 10 (2.4%), parse: 1.06
	(0.3%), extract_message_metadata: 15 (3.7%), get_uri_detail_list: 1.72
	(0.4%), tests_pri_-1000: 22 (5.4%), tests_pri_-950: 1.19 (0.3%),
	tests_pri_-900: 1.02 (0.2%), tests_pri_-90: 63 (15.3%), check_bayes:
	61 (14.9%), b_tokenize: 11 (2.7%), b_tok_get_all: 9 (2.3%),
	b_comp_prob: 2.4 (0.6%), b_tok_touch_all: 34 (8.3%), b_finish: 0.99
	(0.2%), tests_pri_0: 285 (69.1%), check_dkim_signature: 0.51 (0.1%),
	check_dkim_adsp: 2.6 (0.6%), poll_dns_idle: 1.02 (0.2%), tests_pri_10:
	2.1 (0.5%), tests_pri_500: 7 (1.8%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [GIT PULL] siginfo: ABI fixes for v5.13-rc2
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

ebiederm@xmission.com (Eric W. Biederman) writes:

> Linus Torvalds <torvalds@linux-foundation.org> writes:
>
>> On Thu, May 13, 2021 at 9:55 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>>>
>>> Please pull the for-v5.13-rc2 branch from the git tree:
>>
>> I really don't like this tree.
>>
>> The immediate cause for "no" is the silly
>>
>>  #if IS_ENABLED(CONFIG_SPARC)
>>
>> and
>>
>>  #if IS_ENABLED(CONFIG_ALPHA)
>>
>> code in kernel/signal.c. It has absolutely zero business being there,
>> when those architectures have a perfectly fine arch/*/kernel/signal.c
>> file where that code would make much more sense *WITHOUT* any odd
>> preprocessor games.
>
> The code is generic it just happens those functions are only used on
> sparc and alpha.  Further I really want to make filling out siginfo_t
> happen in dedicated functions as much as possible in kernel/signal.c.
> The probably of getting it wrong without a helper functions is very
> strong.  As the code I am fixing demonstrates.
>
> The IS_ENABLED(arch) is mostly there so we can delete the code if/when
> the architectures are retired in another decade or so.

There is also the question of why alpha allows userspace to block
SIGFPE.

If it turns out that alpha is just silly by allowing synchronous
exceptions to be blocked, then the code really becomes generic and
shared shared between sparc and alpha.

Which is really why the code does not make sense in some architecture
specific version of signal.c.  That and the fact the two functions
are almost identical.

If you want I can remove the #ifdefs and we can take up slightly more
space until someone implements -ffunction-sections.

Do you know if alpha will be stuck triggering the same floating point
error if the SIGFPE is blocked or can alpha somehow continue past it?

If alpha using send_sig instead of force_sig is historical and does not
reflect the reality of the hardware alpha can be converted and several
of the send_sig variants can be removed.  Otherwise alpha remains the
odd man out, and the code can remain until all of the alpha hardware
dies.  (I don't think anyone is manufacturing alpha hardware anymore).

I would look it up but I have lost access to whatever alpha
documentation I had.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1tun57xge.fsf%40fess.ebiederm.org.
