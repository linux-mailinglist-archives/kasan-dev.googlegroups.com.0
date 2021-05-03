Return-Path: <kasan-dev+bncBCALX3WVYQORBTWKYGCAMGQEP6CTKTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 873CC372232
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 23:04:16 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id n5-20020a67d6050000b02902276b7d7c95sf2473551vsj.18
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 14:04:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620075855; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYjoogmJeXm5xG6LmmJs8lRoBVz3sK2NYPslgCSz8rHIfjCmrblfu1m7nVuEdp9PrB
         TUhw/0LhfoFhm2MRu8QHh7Pu+c4kCVHMbNmwBagFYcN7Zln2PSZfvveWE4sVnTRU1h0H
         M1iuG1a4ROF8FkABldkXcUmw2Aw37ywyJSVAg/LUpSbih45t+s2FMpkmkhiFK3Prtd3t
         CCjF6q5Bbk6WnG2B4L3ME+6NwmbrnZEL5sC/bH9TWQcGXcDxFr8LXFLVdNESbQFno9KI
         Y7MGjUG5WrJUl2Wk0uqCiRjkEIWix/3PDQEH8w70TiNB1pwy55j4O8OXDjRluFlDtIb5
         fHnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=GEBXqIGFTqOvNorpXCpbWEc9cxHGfsgjtmFVqpjIaOY=;
        b=hZiJ03ntbWDRrmGcARxzXofhQl4tRTdYGS1A55KV4Hb+1iv9RZwdjaxRcQDRlKnlfL
         mc14/AfDEmw3QZ7tZ0fOmaUnxIAUx+1GIfJ3Kj8Lyv5JK/OF1K44NH1TdQOx4sNZXsn6
         tA29oiqJgQpRg37dXLKQDXB+S4uOMTpVpL/6/iJaROh/Bh8SOGrxz8Y1VNSGHheirz/0
         /fHqndfPXg1++TVCie/nBUBe5ddqCM+YK5x1L1McpG/bc+Tw5xt8AFGt3/P0GQ7VMc/V
         ysuFNJVSXYBIDwgQT8dC5l4fTBdl8HmZvzGeUJax5B3YvgzbvPGJ664NuLK1T1ua5of3
         IYOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GEBXqIGFTqOvNorpXCpbWEc9cxHGfsgjtmFVqpjIaOY=;
        b=iuuOzTxPXUhy7HdHRDP1p7qGTaAXdoFaFWmWJCr8IuzmxsE+BVLYFANjsa/e9Zrcww
         g0z2+V4LLyNO9mMVfgTJdGRkHksBUJKs0MKcBE2VCvHZs+ZDLv0a4bhOvNTwwQ9FKS0J
         DEOeBLX+P5ES9pR6t5V7eBglOHToqtmWCgOdOIbTN7KeFili8xDa2egonMO+sKXjMoJM
         Ojtpf9CdIa5sn6RLgETCO5Dz7lZIYPvko/b71f8ONtbLUrIZdJ1e51NUpjvWuc0wUjkV
         5v7FJ4n/NUbNVlHvRfTvCWVO40FbQuKuAEBACAmBsaWhdj5QS+GZXugfNktRh00Js/mt
         RqYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEBXqIGFTqOvNorpXCpbWEc9cxHGfsgjtmFVqpjIaOY=;
        b=gYaga1VPYLTnZMKP54XhR5yD0F+Kjs1JDaxLmLT6JVuEKKfchHMBpsv96FvU0/M4Nb
         HmzBVW9zccEvpVF5KbsmZKZZF/f7t1zP8PRU2O/IYUtYdN7IA7fimS2nb4b8qbL5aK3X
         bDCO7/iduAQHG1wqwuhcvR7XxxoPqLAaZO40CJuKAV7YAL09TSexjVayxVHcCugY4LJM
         xhpLCH7xtTxrsUISaONpZNaSRncGwKlvj4/ug4UJ4Z+XF95dJWc/I1Fi9f/L9nyT0bQ9
         LQfQ5+UDDyO1F3NYOJgl22TFCaWA85eFF2DZV/zj0YcewCOVys6G8ztmVxADLEgoS8l3
         nfxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310wVxlfStEyT1MSntjSbRTz4tSEq9qWHga+WmV8rMQVPHJb5r/
	GqunWijAnk2POR0Qb8QzAdU=
X-Google-Smtp-Source: ABdhPJyT4WBVlZhAewv1Kel98uONX8PIPNgi7SnIIIUut53ZPRPMmrpMVVSII7SDN5C+SVG23TUQYQ==
X-Received: by 2002:a67:2c57:: with SMTP id s84mr18602454vss.32.1620075854860;
        Mon, 03 May 2021 14:04:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7d96:: with SMTP id y144ls2433227vsc.9.gmail; Mon, 03
 May 2021 14:04:14 -0700 (PDT)
X-Received: by 2002:a67:f353:: with SMTP id p19mr6845123vsm.56.1620075854335;
        Mon, 03 May 2021 14:04:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620075854; cv=none;
        d=google.com; s=arc-20160816;
        b=RMs/Ey35X8OLB+tnQZzpGqHnNFlSz3Dp19B70T/ytq5/RNMcvyPq9kzYwXIN5Z3PJ/
         2XHlabFzlGkUEYcxSzukSHztn0AS9f0azrC5KH6idX3/jaCxUzOl0k2gRoiEzMKRamJv
         WArPn/PlnciuP5fVM1PlxLfWoSeb0RNyc6bffDiwIB+lXRb8+LWri12nKUJftlanxvOh
         Kj/3Ml0S1JysoZrHVnQxzu+e2O/gvMDKBZNdMPRWKB8BVlHfDMwujXf3SsrvSFedpWj7
         nPNEwPNi+KksaBi4PE5JduK5ZRhE3LybgRnfusY+yH0lNJObX4xSlDHehFw3/JzOUhr0
         WrYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=g5Pfur77R9miaXB8c5jxP6zPbE3vrckZ9DhhG6ZpIyY=;
        b=vXCZFkW5ZMHHS9OVxXo24KcXoGSOldfAZJ047G83/sq05GlqVukDyC3yDdPV3v+XSn
         E7NM5nQSgQLv15Ch9WGUgjgPk7Jl/lT09M7FfoLZna/6589+YPpBC8fZrme6ddZdtSpI
         xW70/b1erZ2FWL5syfurGo8VfbM/UJkvSsZQkjxBbxEcHm+/f0RQbUzkdyiymadg+xwE
         zs4nn9T3gqrR5c5kJtWsN2FSr0Gttax0jQYzIsDlJtH6k1R2VRCW+y+3ahJWtqGWo4x8
         yJOXMklKO5A7piC6k+sU+8v9iYYN4v2NO0QhE0MZ9BtL1lvwPfogwJQWarysro+GRbS8
         WeVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id x190si41590vkf.1.2021.05.03.14.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 14:04:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfje-00HL49-6R; Mon, 03 May 2021 15:04:10 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfjc-00EBAp-Se; Mon, 03 May 2021 15:04:09 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<20210503203814.25487-1-ebiederm@xmission.com>
	<20210503203814.25487-10-ebiederm@xmission.com>
Date: Mon, 03 May 2021 16:04:05 -0500
In-Reply-To: <20210503203814.25487-10-ebiederm@xmission.com> (Eric
	W. Beiderman's message of "Mon, 3 May 2021 15:38:12 -0500")
Message-ID: <m1o8drfs1m.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldfjc-00EBAp-Se;;;mid=<m1o8drfs1m.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19jU54L2zjLU9Ecan0nFKK7UMRXbGeKQos=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_XMDrugObfuBody_08,
	XMNoVowels,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4935]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 731 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 10 (1.4%), b_tie_ro: 9 (1.3%), parse: 1.17 (0.2%),
	 extract_message_metadata: 13 (1.8%), get_uri_detail_list: 3.6 (0.5%),
	tests_pri_-1000: 13 (1.8%), tests_pri_-950: 1.17 (0.2%),
	tests_pri_-900: 0.94 (0.1%), tests_pri_-90: 102 (13.9%), check_bayes:
	100 (13.7%), b_tokenize: 17 (2.4%), b_tok_get_all: 12 (1.6%),
	b_comp_prob: 3.3 (0.5%), b_tok_touch_all: 64 (8.8%), b_finish: 0.70
	(0.1%), tests_pri_0: 576 (78.8%), check_dkim_signature: 0.67 (0.1%),
	check_dkim_adsp: 3.2 (0.4%), poll_dns_idle: 1.23 (0.2%), tests_pri_10:
	2.9 (0.4%), tests_pri_500: 8 (1.1%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are possible
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

"Eric W. Beiderman" <ebiederm@xmission.com> writes:

> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> The si_perf code really wants to add a u64 field.  This change enables
> that by reorganizing the definition of siginfo_t, so that a 64bit
> field can be added without increasing the alignment of other fields.

I decided to include this change because it is not that complicated,
and it allows si_perf_data to have the definition that was originally
desired.

If this looks difficult to make in the userspace definitions,
or is otherwise a problem I don't mind dropping this change.  I just
figured since it was not too difficult and we are changing things
anyway I should try for everything.

Eric


> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---
>  arch/x86/kernel/signal_compat.c    |  9 +++----
>  include/linux/compat.h             | 28 +++++++++++++-------
>  include/uapi/asm-generic/siginfo.h | 42 ++++++++++++++++++++----------
>  3 files changed, 49 insertions(+), 30 deletions(-)
>
> diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
> index a9fcabd8a5e5..a5cd01c52dfb 100644
> --- a/arch/x86/kernel/signal_compat.c
> +++ b/arch/x86/kernel/signal_compat.c
> @@ -17,8 +17,6 @@
>   */
>  static inline void signal_compat_build_tests(void)
>  {
> -	int _sifields_offset = offsetof(compat_siginfo_t, _sifields);
> -
>  	/*
>  	 * If adding a new si_code, there is probably new data in
>  	 * the siginfo.  Make sure folks bumping the si_code
> @@ -40,8 +38,7 @@ static inline void signal_compat_build_tests(void)
>  	 * in the ABI, of course.  Make sure none of them ever
>  	 * move and are always at the beginning:
>  	 */
> -	BUILD_BUG_ON(offsetof(compat_siginfo_t, _sifields) != 3 * sizeof(int));
> -#define CHECK_CSI_OFFSET(name)	  BUILD_BUG_ON(_sifields_offset != offsetof(compat_siginfo_t, _sifields.name))
> +#define CHECK_CSI_OFFSET(name)	  BUILD_BUG_ON(0 != offsetof(compat_siginfo_t, _sifields.name))
>  
>  	BUILD_BUG_ON(offsetof(siginfo_t, si_signo) != 0);
>  	BUILD_BUG_ON(offsetof(siginfo_t, si_errno) != 4);
> @@ -63,8 +60,8 @@ static inline void signal_compat_build_tests(void)
>  	 * structure stays within the padding size (checked
>  	 * above).
>  	 */
> -#define CHECK_CSI_SIZE(name, size) BUILD_BUG_ON(size != sizeof(((compat_siginfo_t *)0)->_sifields.name))
> -#define CHECK_SI_SIZE(name, size) BUILD_BUG_ON(size != sizeof(((siginfo_t *)0)->_sifields.name))
> +#define CHECK_CSI_SIZE(name, size) BUILD_BUG_ON(((3*sizeof(int))+(size)) != sizeof(((compat_siginfo_t *)0)->_sifields.name))
> +#define CHECK_SI_SIZE(name, size) BUILD_BUG_ON(((4*sizeof(int))+(size)) != sizeof(((siginfo_t *)0)->_sifields.name))
>  
>  	CHECK_CSI_OFFSET(_kill);
>  	CHECK_CSI_SIZE  (_kill, 2*sizeof(int));
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index 6af7bef15e94..d81493248bf3 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -158,27 +158,28 @@ typedef union compat_sigval {
>  	compat_uptr_t	sival_ptr;
>  } compat_sigval_t;
>  
> -typedef struct compat_siginfo {
> -	int si_signo;
> -#ifndef __ARCH_HAS_SWAPPED_SIGINFO
> -	int si_errno;
> -	int si_code;
> -#else
> -	int si_code;
> -	int si_errno;
> -#endif
> +#define __COMPAT_SIGINFO_COMMON	\
> +	___SIGINFO_COMMON;	\
> +	int	_common_pad[__alignof__(compat_uptr_t) != __alignof__(int)]
>  
> +typedef struct compat_siginfo {
> +	union {
> +		struct {
> +			__COMPAT_SIGINFO_COMMON;
> +		};
>  	union {
> -		int _pad[128/sizeof(int) - 3];
> +		int _pad[128/sizeof(int)];
>  
>  		/* kill() */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_pid_t _pid;	/* sender's pid */
>  			__compat_uid32_t _uid;	/* sender's uid */
>  		} _kill;
>  
>  		/* POSIX.1b timers */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_timer_t _tid;	/* timer id */
>  			int _overrun;		/* overrun count */
>  			compat_sigval_t _sigval;	/* same as below */
> @@ -186,6 +187,7 @@ typedef struct compat_siginfo {
>  
>  		/* POSIX.1b signals */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_pid_t _pid;	/* sender's pid */
>  			__compat_uid32_t _uid;	/* sender's uid */
>  			compat_sigval_t _sigval;
> @@ -193,6 +195,7 @@ typedef struct compat_siginfo {
>  
>  		/* SIGCHLD */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_pid_t _pid;	/* which child */
>  			__compat_uid32_t _uid;	/* sender's uid */
>  			int _status;		/* exit code */
> @@ -203,6 +206,7 @@ typedef struct compat_siginfo {
>  #ifdef CONFIG_X86_X32_ABI
>  		/* SIGCHLD (x32 version) */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_pid_t _pid;	/* which child */
>  			__compat_uid32_t _uid;	/* sender's uid */
>  			int _status;		/* exit code */
> @@ -213,6 +217,7 @@ typedef struct compat_siginfo {
>  
>  		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_uptr_t _addr;	/* faulting insn/memory ref. */
>  #define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
>  				     sizeof(short) : __alignof__(compat_uptr_t))
> @@ -242,16 +247,19 @@ typedef struct compat_siginfo {
>  
>  		/* SIGPOLL */
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_long_t _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
>  			int _fd;
>  		} _sigpoll;
>  
>  		struct {
> +			__COMPAT_SIGINFO_COMMON;
>  			compat_uptr_t _call_addr; /* calling user insn */
>  			int _syscall;	/* triggering system call number */
>  			unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
>  		} _sigsys;
>  	} _sifields;
> +	};
>  } compat_siginfo_t;
>  
>  struct compat_rlimit {
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index e663bf117b46..1fcede623a73 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -29,15 +29,33 @@ typedef union sigval {
>  #define __ARCH_SI_ATTRIBUTES
>  #endif
>  
> +#ifndef __ARCH_HAS_SWAPPED_SIGINFO
> +#define ___SIGINFO_COMMON	\
> +	int	si_signo;	\
> +	int	si_errno;	\
> +	int	si_code
> +#else
> +#define ___SIGINFO_COMMON	\
> +	int	si_signo;	\
> +	int	si_code;	\
> +	int	si_errno
> +#endif /* __ARCH_HAS_SWAPPED_SIGINFO */
> +
> +#define __SIGINFO_COMMON	\
> +	___SIGINFO_COMMON;	\
> +	int	_common_pad[__alignof__(void *) != __alignof(int)]
> +
>  union __sifields {
>  	/* kill() */
>  	struct {
> +		__SIGINFO_COMMON;
>  		__kernel_pid_t _pid;	/* sender's pid */
>  		__kernel_uid32_t _uid;	/* sender's uid */
>  	} _kill;
>  
>  	/* POSIX.1b timers */
>  	struct {
> +		__SIGINFO_COMMON;
>  		__kernel_timer_t _tid;	/* timer id */
>  		int _overrun;		/* overrun count */
>  		sigval_t _sigval;	/* same as below */
> @@ -46,6 +64,7 @@ union __sifields {
>  
>  	/* POSIX.1b signals */
>  	struct {
> +		__SIGINFO_COMMON;
>  		__kernel_pid_t _pid;	/* sender's pid */
>  		__kernel_uid32_t _uid;	/* sender's uid */
>  		sigval_t _sigval;
> @@ -53,6 +72,7 @@ union __sifields {
>  
>  	/* SIGCHLD */
>  	struct {
> +		__SIGINFO_COMMON;
>  		__kernel_pid_t _pid;	/* which child */
>  		__kernel_uid32_t _uid;	/* sender's uid */
>  		int _status;		/* exit code */
> @@ -62,6 +82,7 @@ union __sifields {
>  
>  	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
>  	struct {
> +		__SIGINFO_COMMON;
>  		void __user *_addr; /* faulting insn/memory ref. */
>  #ifdef __ia64__
>  		int _imm;		/* immediate value for "break" */
> @@ -97,35 +118,28 @@ union __sifields {
>  
>  	/* SIGPOLL */
>  	struct {
> +		__SIGINFO_COMMON;
>  		__ARCH_SI_BAND_T _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
>  		int _fd;
>  	} _sigpoll;
>  
>  	/* SIGSYS */
>  	struct {
> +		__SIGINFO_COMMON;
>  		void __user *_call_addr; /* calling user insn */
>  		int _syscall;	/* triggering system call number */
>  		unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
>  	} _sigsys;
>  };
>  
> -#ifndef __ARCH_HAS_SWAPPED_SIGINFO
> -#define __SIGINFO 			\
> -struct {				\
> -	int si_signo;			\
> -	int si_errno;			\
> -	int si_code;			\
> -	union __sifields _sifields;	\
> -}
> -#else
> +
>  #define __SIGINFO 			\
> -struct {				\
> -	int si_signo;			\
> -	int si_code;			\
> -	int si_errno;			\
> +union {					\
> +	struct {			\
> +		__SIGINFO_COMMON;	\
> +	};				\
>  	union __sifields _sifields;	\
>  }
> -#endif /* __ARCH_HAS_SWAPPED_SIGINFO */
>  
>  typedef struct siginfo {
>  	union {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1o8drfs1m.fsf%40fess.ebiederm.org.
