Return-Path: <kasan-dev+bncBCALX3WVYQORBKVBWKCAMGQEJTGASVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F7913703F7
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:20:11 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id w4-20020a0568081404b0290102a1fd05b2sf29405251oiv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:20:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619824810; cv=pass;
        d=google.com; s=arc-20160816;
        b=LuloxfF5rSdqnehrQYktw//ENejNQr6oHdUiWSMX9Lf2Srk3sH8xArfRKt1dKbA8GR
         9BRzJ0uZD/h83T6z251rYsMS11Gi4mVy76ekxCS2eXNtfDUJ/IxDxhbrBY2Xk7IGQKRZ
         MhKAHf4EJ+NYmZBdXyZe/SDwWqpD7jOji5usFJw2613webi3wUZQVx9rcEuqqgfTuMeI
         SU5EuDUZ4YvDndfMKbM22CAaOvWA6pyaF8qBT0DADCjGoFldMU/Nehh99wryrr2bH8WD
         kINV41XK56DCaJSHEv26J3dwc6aZjqfgCbl6yIpin2DQrDm95MI8S55Rr2GwgQhynlS4
         RYQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=sBwmr7PETyp0tpvmH6QyPvGRp2QvyKhN39GT3mZPLoA=;
        b=IKVcC1mb/+UQa+gQmVXcG5+rGek+xzBeubUaM4ePYrWa/1XOGpkyH6Vc234tNLGrEs
         SRl3ScDqgcQqnVwt5EEiz9aB9YsQGbK/QWX0YLamyyugCo2Q3EO4ClF1w9CDBwCkL4oZ
         JuNsCzIAmwC88I7I8MuA0q/W8Y1c4/RHI0h3wMFFH0p9guQ+UTLUwyP863JP7chOePui
         eAY+KeRAqP0E0pLm++lXXVops0tf7Pdv6POJDFRkpzDk7fWlMUE98c8R/wTgixiZk5F/
         kUGawuNGnYbNBMBAi1P+uWXULJ1iFXnRp4/klQPf4m+fiyN5HBq6nj0SQzZs1yJgwjqj
         JuPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sBwmr7PETyp0tpvmH6QyPvGRp2QvyKhN39GT3mZPLoA=;
        b=OepcA1H+pT3nHENxd7sDwpxbtLHvaBP75+7XccXbMty31SnLFGO5QcWmEhKjBYVxx3
         LQbyyeGVhdG1erpPBiKeRBTy2NNsxHbC9qwpO1Kb8JYxnUX1EixiPyBDRVXpk6kdy4in
         reFDI3U8cmrC2qfPivlB6Wu+spomPWWwLBBhczaIJ4TDgVwEqGM2dHXIUsPOgqDDbci3
         IPtgzX3LUg19Gy0bDAnOXsJIJfjeHvORhrCsFiAVOjC1LGKOUjs105a376dtkOUTkU3M
         eVC1a4RFfVwbQyqPM2BipMopJPa2JTQACoQkbCNGylp+xbVKSqC2ujjLSum2xFxrfraD
         cr5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sBwmr7PETyp0tpvmH6QyPvGRp2QvyKhN39GT3mZPLoA=;
        b=J++MbhYb0vM/NKX0GoOMXZinm0sGKUuAXLG8g9KCSF+t3VTLPH1m3FUTgDWjJn0Kby
         6M20WYUpUlab4NO5R+Unvr6uvoA3IL2WeNHgcNdq/BIs/16TkrFXyhB2o3Djaoib364u
         SeZrFO+eRIyrWSwvJYOK7ewDWXc+Uo1rnzPN1e5fEz2wDayZjs8LesL2R7Fd8Aguaio6
         L4HtowJr8XFqX/c//mJyaqQLS+gpgQnPqdVuSok3LvUJssmVBjBqV7hKjEtQbq9zsqXM
         xj5vveHtQcmemyoQHv6RjEaasr9xrcWi308X1fXX5XEkr9uvRmvtGh4I0fOYm2bgBnSW
         RzxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331TOSUi5otV94P/4gQXN5Ttt1T87baaMN2BY3VoZFOWLtEZCvK
	of2GcUfIIeMhyk4oe7gkG8o=
X-Google-Smtp-Source: ABdhPJwRQGKJ4oYv1gQlxAWP0g2H3qxaj00P3Q9YLp6PFWwJ3Muta+zHi6k/k53MopyWAXnIVfBpjA==
X-Received: by 2002:aca:f008:: with SMTP id o8mr5903815oih.106.1619824810603;
        Fri, 30 Apr 2021 16:20:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:926:: with SMTP id v38ls2163665ott.5.gmail; Fri, 30
 Apr 2021 16:20:10 -0700 (PDT)
X-Received: by 2002:a05:6830:1418:: with SMTP id v24mr5597399otp.66.1619824810153;
        Fri, 30 Apr 2021 16:20:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619824810; cv=none;
        d=google.com; s=arc-20160816;
        b=H1bbZQqPyb1ruePDEZxzoYIjuuP2iAFajQ96CdwZiMX/8QRDjf33wZg6f2hrPMkRn5
         7UJoVoMiedTaikjf/+JxuFePP3YJRx1jY1OmPA6hc9YuOAylvYwST/xptfrjCuBW5F4w
         uoSUGRyxrtfHWJsD9Ggn4UVpC13SMmvFLhQ983N3Sz40LqD8+9bsF1qauDpXTfRV4GLf
         cFllfxI4nZao8jE6gMK4bDhCBAEHzQ6WSUdh+hphZfM7PBiV6p4glHxoHR0T6GmNcw1M
         Vk6AqR8aRFPWZPstnYws3F/T9Fu/BwWgAGfKM7F1BwQgtPxnTsyRQt+MXJijrSUCzfCg
         Ad/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=Fst6K1+PQlohz52AeEbT1LKYLhwkY/jupI0cn1Z/fj0=;
        b=i1gPHG42S7aZPf9eNtgHTMtRnAGGXmq4KvgDX9u6JwttyVeKqYiXjzt5Ogn+cRc1D5
         SEsdU/k/L7x48k9uYW6gT9QgUeTQu9pUE0MAOt3+jdcEm4R/EzpkY8d7caFb8LFhLRVT
         DDfB2sAjthFycI8bjaRFpkCwMqy1/Zu0XNqTrST8TnDhRo7+CWEwmUz8/yG9+uOAU2EC
         xxQf9Ahn8Wttf+z6c+Ruh4sCNEAVnk+XFC4ed20UifTEfY/bs3Y4qae1i+TWC9x3Ubl0
         xnEDYIXMvOnoFBHrStEmvySHBMKEviZVkbhevs06qV+GWYY39PWX6lYY7zpxUj+pE+Iq
         Nikw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id c26si470576otf.4.2021.04.30.16.20.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:20:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccQV-004DLh-Rr; Fri, 30 Apr 2021 17:20:04 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccQU-007HCH-J2; Fri, 30 Apr 2021 17:20:03 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
	<m1o8dvs7s7.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:19:58 -0500
In-Reply-To: <m1o8dvs7s7.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:54:16 -0500")
Message-ID: <m1y2czqs0x.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccQU-007HCH-J2;;;mid=<m1y2czqs0x.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18OuzsZtpaVFuh5x4vTdt9uc78OYUZkyKE=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: ****
X-Spam-Status: No, score=4.5 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,LotsOfNums_01,TR_XM_PhishingBody,
	T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMNoVowels,XM_B_Phish66
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4989]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	*  1.2 LotsOfNums_01 BODY: Lots of long strings of numbers
	*  2.0 XM_B_Phish66 BODY: Obfuscated XMission
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.0 TR_XM_PhishingBody Phishing flag in body of message
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ****;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 518 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 10 (2.0%), b_tie_ro: 9 (1.7%), parse: 1.05 (0.2%),
	 extract_message_metadata: 12 (2.2%), get_uri_detail_list: 2.5 (0.5%),
	tests_pri_-1000: 13 (2.5%), tests_pri_-950: 1.30 (0.3%),
	tests_pri_-900: 1.45 (0.3%), tests_pri_-90: 106 (20.4%), check_bayes:
	104 (20.0%), b_tokenize: 12 (2.2%), b_tok_get_all: 8 (1.5%),
	b_comp_prob: 2.0 (0.4%), b_tok_touch_all: 79 (15.2%), b_finish: 1.01
	(0.2%), tests_pri_0: 361 (69.7%), check_dkim_signature: 0.75 (0.1%),
	check_dkim_adsp: 2.5 (0.5%), poll_dns_idle: 0.80 (0.2%), tests_pri_10:
	2.1 (0.4%), tests_pri_500: 7 (1.4%), rewrite_mail: 0.00 (0.0%)
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

ebiederm@xmission.com (Eric W. Biederman) writes:

> Now that si_trapno is part of the union in _si_fault and available on
> all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
> return SIL_FAULT_TRAPNO when si_trapno is actually used.
>
> Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
> and have the same code ignore si_trapno in in all other cases.

This change is missing a break in signalfd.

Eric

> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---
>  fs/signalfd.c          |  7 ++-----
>  include/linux/signal.h |  1 +
>  kernel/signal.c        | 36 ++++++++++++++----------------------
>  3 files changed, 17 insertions(+), 27 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 040a1142915f..126c681a30e7 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -123,15 +123,12 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>  		 */
>  	case SIL_FAULT:
>  		new.ssi_addr = (long) kinfo->si_addr;
+ 		break;
> -#ifdef __ARCH_SI_TRAPNO
> +	case SIL_FAULT_TRAPNO:
> +		new.ssi_addr = (long) kinfo->si_addr;
>  		new.ssi_trapno = kinfo->si_trapno;
> -#endif
>  		break;
>  	case SIL_FAULT_MCEERR:
>  		new.ssi_addr = (long) kinfo->si_addr;
> -#ifdef __ARCH_SI_TRAPNO
> -		new.ssi_trapno = kinfo->si_trapno;
> -#endif
>  		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>  		break;
>  	case SIL_PERF_EVENT:
> diff --git a/include/linux/signal.h b/include/linux/signal.h
> index 1e98548d7cf6..5160fd45e5ca 100644
> --- a/include/linux/signal.h
> +++ b/include/linux/signal.h
> @@ -40,6 +40,7 @@ enum siginfo_layout {
>  	SIL_TIMER,
>  	SIL_POLL,
>  	SIL_FAULT,
> +	SIL_FAULT_TRAPNO,
>  	SIL_FAULT_MCEERR,
>  	SIL_FAULT_BNDERR,
>  	SIL_FAULT_PKUERR,
> diff --git a/kernel/signal.c b/kernel/signal.c
> index c3017aa8024a..7b2d61cb7411 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1194,6 +1194,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
>  	case SIL_TIMER:
>  	case SIL_POLL:
>  	case SIL_FAULT:
> +	case SIL_FAULT_TRAPNO:
>  	case SIL_FAULT_MCEERR:
>  	case SIL_FAULT_BNDERR:
>  	case SIL_FAULT_PKUERR:
> @@ -2527,6 +2528,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
>  {
>  	switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
>  	case SIL_FAULT:
> +	case SIL_FAULT_TRAPNO:
>  	case SIL_FAULT_MCEERR:
>  	case SIL_FAULT_BNDERR:
>  	case SIL_FAULT_PKUERR:
> @@ -3206,6 +3208,12 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>  			if ((sig == SIGBUS) &&
>  			    (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
>  				layout = SIL_FAULT_MCEERR;
> +			else if (IS_ENABLED(ALPHA) &&
> +				 ((sig == SIGFPE) ||
> +				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
> +				layout = SIL_FAULT_TRAPNO;
> +			else if (IS_ENABLED(SPARC) && (sig == SIGILL) && (si_code == ILL_ILLTRP))
> +				layout = SIL_FAULT_TRAPNO;
>  			else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
>  				layout = SIL_FAULT_BNDERR;
>  #ifdef SEGV_PKUERR
> @@ -3317,30 +3325,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>  		break;
>  	case SIL_FAULT:
>  		to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> +		break;
> +	case SIL_FAULT_TRAPNO:
> +		to->si_addr = ptr_to_compat(from->si_addr);
>  		to->si_trapno = from->si_trapno;
> -#endif
>  		break;
>  	case SIL_FAULT_MCEERR:
>  		to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_addr_lsb = from->si_addr_lsb;
>  		break;
>  	case SIL_FAULT_BNDERR:
>  		to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_lower = ptr_to_compat(from->si_lower);
>  		to->si_upper = ptr_to_compat(from->si_upper);
>  		break;
>  	case SIL_FAULT_PKUERR:
>  		to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_pkey = from->si_pkey;
>  		break;
>  	case SIL_PERF_EVENT:
> @@ -3401,30 +3401,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>  		break;
>  	case SIL_FAULT:
>  		to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> +		break;
> +	case SIL_FAULT_TRAPNO:
> +		to->si_addr = compat_ptr(from->si_addr);
>  		to->si_trapno = from->si_trapno;
> -#endif
>  		break;
>  	case SIL_FAULT_MCEERR:
>  		to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_addr_lsb = from->si_addr_lsb;
>  		break;
>  	case SIL_FAULT_BNDERR:
>  		to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_lower = compat_ptr(from->si_lower);
>  		to->si_upper = compat_ptr(from->si_upper);
>  		break;
>  	case SIL_FAULT_PKUERR:
>  		to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -		to->si_trapno = from->si_trapno;
> -#endif
>  		to->si_pkey = from->si_pkey;
>  		break;
>  	case SIL_PERF_EVENT:

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1y2czqs0x.fsf%40fess.ebiederm.org.
