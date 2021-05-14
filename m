Return-Path: <kasan-dev+bncBCALX3WVYQORBA6R7OCAMGQE3MCXUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CE013812B5
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 23:15:49 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 59-20020a9d0dc10000b02902a57e382ca1sf226564ots.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 14:15:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621026948; cv=pass;
        d=google.com; s=arc-20160816;
        b=JFNkdKfAwB+Ng3IPHK8UOr/Z9qV5gAZno9cvij5uz0BO0bQRlUOerXwhBPXJG/S3IN
         f1I7Bl+Y7R3adiybrd60bhE+ikoG+tvvPuVkiXeB+ShCcteHgLYvnATJLP8rTcM92M4e
         CUsoWRSB+KqzllN6SAc8FzIpjX3u3zd5g15FcjXn5lmHsLe4m2M67uPvv8GrJuieOvcg
         3PNo0+p51wyEvygHZuV7vydlX0e6x9gP/MpVZQlNZMpnXxefNfH1R6+1hDcR42iiGCRm
         5bMdOflW83zQ0TtqHDduH2PmW/aDxnsCzZlGFzepetpp9zROg+ukecJAHloWPb3cPU+w
         Ffwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=0iBCGRbdikQIPOpPADBgvSnHeGwj3pPX43tPoEZIR4k=;
        b=wJQ8w/7VjKJFpq1T7qGWTZJTvPKHfsHy+Tncp4uG0kLu5RtLsTm1RNygIj/5Il9w/a
         gRp2be1gYdyFFn1ZVONz53uqlUTZZeQE/uqr2XSsbuo2/nynL6buZq5B0Pt4WTomKct3
         rWMnBF4QDGLt3ZT99f1JC137upMD9PTdymvh3IT+u88KHteB7KBLV08ZleS4vR9BzBes
         r79RG4EyQ/7ITLFHnClpFzvPPWo933af5rd4YsbPY3yU7yVc/aijzUyoHjUjuLHaTO0o
         ex9Fw1IKiwXGPTms4Byy34Vu0Qx0bgMAidv45DhEMO6q7BYiCKJxEf8uRiOcc4TpLxdy
         ErAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0iBCGRbdikQIPOpPADBgvSnHeGwj3pPX43tPoEZIR4k=;
        b=Dnauxo0NVwayr05Xu8O+w5vuBi8zpOeLQFndfq5GuoEBAVoSHBVVtxe/AC4+sAmdf5
         1eMDUTq7SxVCHjORAGVv2SrXyyxmVYhFQBLxqlzQKkhN1sZ4HHVWCalsq0xnRBsiUXFs
         n+2zxS99fIrdqZ9oNlaEhqLl3SfV/IeW1qlREQVKiGQ0zyNs/2V7AhfVmif0k8eGWMpW
         3hYDI/IvATLc3jrDEP0UhoEEDpfzeGCjHUE6tDhigXFUBYsqtVAyAhOnm6RyxKX4KZWA
         2j0ywb9tcLaiCANnFMHXb7C3CkIjTV+RhcZQwxb5t9CCCY49YDhCaaSdq/WgeXSNIq8e
         GmNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0iBCGRbdikQIPOpPADBgvSnHeGwj3pPX43tPoEZIR4k=;
        b=sT2SmVlIDktrFOYY7GBqncBSNiJv7WdNDcyqRlUmMdzArr5WayO2Be0UPhedVGvYy2
         SBxitH7UXVZ1Rmu9PDgtfjX3rFqq9k812xCwehPZzik0+2vwJXIiAyDoGaj4gAgkNTlZ
         rpEedW1AHJTN7k3CD2+9sz1YF1Hfr7e27Lm2Q8EiO3ykpl8T2XTK5nBGTdKKq/8M0p3P
         /4kvx20eu7O5n/NsnTwRvuiYSg+qu7Oi0vTqhrkbJ3L817BG7fTQ6rhGF6jCJxO8yMaS
         Tmpa8LxDt/OHmOvLQdXIZgxamy8COnZ9654klMEO8PlQJ767KqNTEUcg23ThNecSCZDN
         dsHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323DzFm9KZfK81q4dYRF3n8TU/vtgKiivHz5AjDZYRuEL1m4BE6
	0/1hKRM4ot7SM15zd7/R7Do=
X-Google-Smtp-Source: ABdhPJzg0EOfexMBaGANiHMzPXwFQMAiqG4ZP8fbzRz7ZM6U3CSvF2ZKpbJ8dHwEkBPvdJCD15pXHQ==
X-Received: by 2002:aca:47ca:: with SMTP id u193mr8152166oia.69.1621026948057;
        Fri, 14 May 2021 14:15:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls2713047oif.6.gmail; Fri, 14 May
 2021 14:15:47 -0700 (PDT)
X-Received: by 2002:aca:c206:: with SMTP id s6mr34033461oif.177.1621026947624;
        Fri, 14 May 2021 14:15:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621026947; cv=none;
        d=google.com; s=arc-20160816;
        b=ydu9YHQZSu6JQdylwyrrTRzRB34QuhK5/7q/Oml4um2bapW8Hzt+cQ50NV5HZYAwQh
         SodVW0qwml4D+/DyW2B+46oNVkdUyQYu6wBEr35zlYPSauwCPcbX9epecrAfscQi5rDQ
         FsMDTyqfsdTKEt2o88Cvjk5w6mLXDIYycmre3oOPr6DqE3n/YVYUABd9YzXlaqxD8SvX
         aIaGe8bw3n8ghXtP7RSubBvh2Tvgzf9UsRliUBoqCN3kTOZGDUmxiiP7wVVpTwu+F6GE
         qexNOej2tVlITwxwjArvjZ8b2abuk7unIh1mG3EwO9TXAAQTlO/+n/G1EyDF5RJ08Qu5
         se4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=9k8HYEuiNhkLVgc5hLRKuBSBLqtQTBlWfXFqlYoczNQ=;
        b=0bA/rghL+Ty3Bbn6Y/4AjSwuWfhvDJwxygaGQV2RXov/qvnCj/mdEiZ1BF/ULi3P5F
         QFx82WtzTHQx/aDInCZbzwrAmkg7vLwBV5JU/8M+C/5QVRyongnXJSnmPowpQSLYYKX+
         /2Cd+bXaqEfpnXEWV2V7SV7LVdF+qS9V1FQdRH4QAjiMi4YfXRJpqoHGj0hsb+Qny0YH
         70y4k32V5OiW1+iZvOtiLJ8Sy5p+wAPRi3yHUXIkFS6MBbC3K38IcOLFgSWtdDu06yf4
         KYCg7jy0E8TDgHo3i3F246XbIYsM1tRzWbBzN7BcaMFdXZbPByl8aa+onKLKR5Hy2CA+
         OZAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id k4si692935oot.1.2021.05.14.14.15.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 May 2021 14:15:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhf9s-004lat-Tn; Fri, 14 May 2021 15:15:44 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lhf9p-0041DZ-M9; Fri, 14 May 2021 15:15:44 -0600
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
Date: Fri, 14 May 2021 16:15:36 -0500
In-Reply-To: <CAHk-=wikDD+gCUECg9NZAVSV6W_FUdyZFHzK4isfrwES_+sH-w@mail.gmail.com>
	(Linus Torvalds's message of "Fri, 14 May 2021 12:14:02 -0700")
Message-ID: <m14kf5aufb.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lhf9p-0041DZ-M9;;;mid=<m14kf5aufb.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+VgmiCnNh7t6EwWQgeO8qAQbN162o8ghc=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.3 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMSubMetaSxObfu_03,XMSubMetaSx_00 autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.1421]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 XMSubMetaSx_00 1+ Sexy Words
	*  1.2 XMSubMetaSxObfu_03 Obfuscated Sexy Noun-People
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Linus Torvalds <torvalds@linux-foundation.org>
X-Spam-Relay-Country: 
X-Spam-Timing: total 563 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 11 (2.0%), b_tie_ro: 9 (1.7%), parse: 1.15 (0.2%),
	 extract_message_metadata: 16 (2.9%), get_uri_detail_list: 2.2 (0.4%),
	tests_pri_-1000: 23 (4.0%), tests_pri_-950: 1.33 (0.2%),
	tests_pri_-900: 1.14 (0.2%), tests_pri_-90: 67 (11.9%), check_bayes:
	66 (11.6%), b_tokenize: 10 (1.7%), b_tok_get_all: 11 (1.9%),
	b_comp_prob: 3.1 (0.5%), b_tok_touch_all: 38 (6.8%), b_finish: 0.90
	(0.2%), tests_pri_0: 425 (75.6%), check_dkim_signature: 0.93 (0.2%),
	check_dkim_adsp: 2.1 (0.4%), poll_dns_idle: 0.54 (0.1%), tests_pri_10:
	2.1 (0.4%), tests_pri_500: 11 (2.0%), rewrite_mail: 0.00 (0.0%)
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

Linus Torvalds <torvalds@linux-foundation.org> writes:

> On Thu, May 13, 2021 at 9:55 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>>
>> Please pull the for-v5.13-rc2 branch from the git tree:
>
> I really don't like this tree.
>
> The immediate cause for "no" is the silly
>
>  #if IS_ENABLED(CONFIG_SPARC)
>
> and
>
>  #if IS_ENABLED(CONFIG_ALPHA)
>
> code in kernel/signal.c. It has absolutely zero business being there,
> when those architectures have a perfectly fine arch/*/kernel/signal.c
> file where that code would make much more sense *WITHOUT* any odd
> preprocessor games.

The code is generic it just happens those functions are only used on
sparc and alpha.  Further I really want to make filling out siginfo_t
happen in dedicated functions as much as possible in kernel/signal.c.
The probably of getting it wrong without a helper functions is very
strong.  As the code I am fixing demonstrates.

The IS_ENABLED(arch) is mostly there so we can delete the code if/when
the architectures are retired in another decade or so.

> But there are other oddities too, like the new
>
>     send_sig_fault_trapno(SIGFPE, si_code, (void __user *) regs->pc,
> 0, current);
>
> in the alpha code, which fundamentally seems bogus: using
> send_sig_fault_trapno() with a '0' for trapno seems entirely
> incorrect, since the *ONLY* point of that function is to set si_trapno
> to something non-zero.
>
> So it would seem that a plain send_sig_fault() without that 0 would be
> the right thing to do.

As it happens the floating point emulation code on alpha is inconsistent
with the non floating point emulation code.  When using real floating
point hardware SIGFPE on alpha always set si_trapno.  The floating point
emulation code does not look like it has ever set si_trapno.

I continued to used send_sig_fault_trapno to point out that
inconsistency.

If alpha floating point emulation was in active use I expect we would
care enough to put something other than 0 in there.

> This also mixes in a lot of other stuff than just the fixes. Which
> would have been ok during the merge window, but I'm definitely not
> happy about it now.

If the breakage that came with SIGTRAP TRAP_PERF had not been discovered
during the merge window I would not be sending this now.  It took a
little time to dig to the bottom, then the code needed just a little
extra time to sit, so there were not surprises.

As for mixing things, I am not quite certain what you are referring to.
All of the changes relate to keeping people from shooting themselves
in the foot with when using siginfo.

The most noise comes from send_sig_fault vs send_sig_fault_trapno, and
force_sig_fault vs force_sig_fault_trapno.  That is fundamental to the
siginfo fix as it is there to ensure that is safe to treat si_trapno
as an ordinary _sigfault union member.  Which in turns makes alpha
and sparc no longer special with respect to _sigfault, just a little
eccentric.

I will concede that renaming SIL_PERF_EVENT to SIL_FAULT_PERF_EVENT is
unnecessary, but it certainly makes it clear that we are dealing
with _sigfault and not some other part of siginfo_t.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m14kf5aufb.fsf%40fess.ebiederm.org.
