Return-Path: <kasan-dev+bncBD3JNNMDTMEBB5WJ33FQMGQEUWXI77I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uMnYMfmkd2k9jwEAu9opvQ
	(envelope-from <kasan-dev+bncBD3JNNMDTMEBB5WJ33FQMGQEUWXI77I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 18:31:37 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id EBA858B7CB
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 18:31:36 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-89462dd72a6sf149960026d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 09:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769448695; cv=pass;
        d=google.com; s=arc-20240605;
        b=C5kZXJaQJtpybjYLOsPCHUqyhDw1CFmCI6nflUVgnexcnmPmLdYdfErlCCZTVn8T+f
         DxpousJw3hd01dj6y6zl4aEO0bD7uo4K4AXR+Vtj0NiyNArOk/uz3Ab8i2hbu1GE2wZM
         Ii/MdDZztws57btXkfOTLJXs9bd3T6thfzSYAdTpqAdXhdqJdA90kWVQiWi4DB+YBFPt
         Pn7GlI97WrHM+2dP6qztOxCnEp+huMcpn9RG+nKf4DtygRUKrAtsWtQUqeO0k5+Nb9qw
         buxykhTclN1tz/Sb7PnPuTX1cE/UroZGBMiktoVE4iCh2OS0FHipIDvyzzC73m5gawVn
         CZew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=hKaDcvTVUmlepA18rEXuYfQVBToXV0rdXXNW8l9mC14=;
        fh=nVrCCAb6sv9xoWdwYRjA13vVuc2rtBZ0x7+bgYXFU3c=;
        b=GQOf/fbq7uBDTiKrFhssvtprcLC6bFaUnC+XXi1dg8kPSq2yR8UN+mWo4A0HcA6HUU
         1EykTnKhekO+S97rCMOCev1W4xm1ZTgJ9BRK9SfOA9IaWPfljknucMCrh+ecl1K3wqtb
         VJ6o1Xmcp0cNEvcRV3T8KF7nHsCB8RD5FaR0/uu8ddamZy7pTYXJLGZU7T4FbRSsATaj
         p6Ys8RAgJzCDkNT67wep6UDAdhy8JMU3tBoeZnK9CEZsMBPueM2hkO81A3RrTGEAx+TN
         n24mLLs107lzYZQ+qHLqMI9OlQp9ZIybNOaPyDDPWx+AQWnMrDmikxoHgcg2B32/Xf0c
         e5ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=Jfjqa2A5;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769448695; x=1770053495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hKaDcvTVUmlepA18rEXuYfQVBToXV0rdXXNW8l9mC14=;
        b=Fz3xPda6MjvSAnwWltzY8DD9wFeysSU+RWq6c7KZ3CUgdVEqH0rP2w0zUEwuklGckN
         5Vk1GH2s51i8pDzsBflC3mvWvqyjCu8h9ZAp0CFWxqaWI/DLRoQLT7FN4Zxhnovk8I3o
         x0dx0yQloo34pMUP9w9kYseSRO3B8UoumeV7yGYm7AxOA+bdon9CKDQ0MFluK+bFRCHm
         nKlanrpES/IQQoUfWn3R7ZKGGzKQC1lqssYRoq97AqeVO4cLeGF/K1plrCgXDTui/I8v
         ja40V0dFXieRjZ9atAonSZBsAIE+L9+c4ZjrIHHqEFX7cvExe7Q1MUjuqklKRsnoBXLt
         qB+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769448695; x=1770053495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hKaDcvTVUmlepA18rEXuYfQVBToXV0rdXXNW8l9mC14=;
        b=KXSpyrhgfwgRFeVLPOCS+9PfkBhU2nnHjTcW89P3MFdaZC1hURbJW663bJX7k9u9z2
         fKqthAIWD32XKz5t+fvkr0LwPriYohZPxhCfR0+9Y8J8fYcTepq0p4hHbMwpogIM0jB1
         GOGMZZjXTjdpFRgfM7aP7XzgxWQXa+GXqVSkFbnHl5IsXsHrJY2NKkM4Wk0Y9VxlmaIr
         HLiN1TDnttcIi1cmnLC6YPl0xos9czegOITVOEtj9GI2Z5ZZ0xQs1Q+7R62HkZ7prFsE
         SDj+7q4LUgDwMgl8PVRjfwvnCJGRoptOCEUa872Col9vYa94ZONi3AhCZRYwj/e3xWJ0
         Rgow==
X-Forwarded-Encrypted: i=2; AJvYcCU2JOnOlm9GfR18JbERn1ArUW/Se3l3T6Jor4aqfYdvsGOXeCjSIRK44Lfwb+hlGbMddK+qJA==@lfdr.de
X-Gm-Message-State: AOJu0Yz3/BlNkdtcA5oePlhnjDEEBsjfQLknV4Vw0HoSdnNFEQJvJ6lk
	1eg7l+oaeuKBSDrgStJMZqnBMUWsFCKtJz9f2Smxwh+a6HZflOPZw215
X-Received: by 2002:a05:6214:c23:b0:890:586e:4c93 with SMTP id 6a1803df08f44-894b06c67c1mr71671836d6.15.1769448694971;
        Mon, 26 Jan 2026 09:31:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hj89mZ1iEHmbECwGE5ZTRjIOSEeuu8chscvXI+wdDU2A=="
Received: by 2002:a05:6214:c43:b0:882:63fc:f004 with SMTP id
 6a1803df08f44-8947deb64cdls96424346d6.2.-pod-prod-03-us; Mon, 26 Jan 2026
 09:31:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoQx99ntkQmsvw8MIt7sEwvfemAcNWIjfKg9Pnsv7j1tA63SGVWjT+2FTWJ+PjaTKcP8A1OZgCwrE=@googlegroups.com
X-Received: by 2002:a05:6214:e47:b0:894:6e23:3c3f with SMTP id 6a1803df08f44-894b06e382amr71433836d6.20.1769448692915;
        Mon, 26 Jan 2026 09:31:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769448692; cv=none;
        d=google.com; s=arc-20240605;
        b=OQL7YFCo3GzkINRP6XRfEKO2C7GQunLc7zVDxGWglf0LGk3hddiYM1p1Q1/kCJXZeY
         uyssITrLlL1GTsnVXK9BIml+eFb+UJ7UIqptUJwI0ededkaNXAYEGAqjS8mljQEa+/O7
         h0yDTG3S6qLj2wbTijHIIaRTvFbHS9/rwoI8Kg1BfqpIWeVyTyu8OJavEf3o77tNTVjA
         DQ0IQxL9FLcKL/pIaqKhUIsk43sX2+i+ot+USIL0Pi8zRac1xGAICYui1Q8f3bnS9e1c
         vo7mvUu5FJFk67PKKEmyABYRPMvNi1asS6ECL5ZS3X2Ddi5MYUYbMLgSuVTcak3cTYIU
         +Z0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=cqyCB6D2UZUFPhod4jHX3yXa2CT5+Aq6RptHuHLLwP4=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=DDOHuTWw2w4VSMBrlBpRomiZkGDh9AaJosPuNlzE5TEITaC8+STH4/jeTss+Mgko51
         /RHpT4iSxubIo9IxDfx6J6nP71Oa2H1LFzm5GmsnXuee4W5168y6eS6nniAVTKyxCs0E
         5StykxPNnlsav7OT4tIGAiYKCt8BtOp1JtEft0QojwcSdigEvfDvQlYU1av5wF5H6py2
         +uZZkR5JqX7uF7oCecX/ZIc+/2XTRPiKfCFzz9hx07iprczyyswJ5b5mU95wfIaSVzi8
         dJzVCBQIUf+mobKfZtv9bECGswTXiOu2xjphA3PzC3PXaNEU9XVJpL2ak63onvRSExiB
         3tbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=Jfjqa2A5;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8949188e9f3si3663336d6.9.2026.01.26.09.31.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 09:31:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4f0FvS0HvMz1XM5kt;
	Mon, 26 Jan 2026 17:31:32 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id XReqotH7_hjc; Mon, 26 Jan 2026 17:31:22 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4f0Fv22xNsz1XLyhK;
	Mon, 26 Jan 2026 17:31:10 +0000 (UTC)
Message-ID: <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org>
Date: Mon, 26 Jan 2026 09:31:09 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 15/36] srcu: Support Clang's context analysis
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-16-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-16-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=Jfjqa2A5;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBD3JNNMDTMEBB5WJ33FQMGQEUWXI77I];
	RCVD_TLS_LAST(0.00)[];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	FREEMAIL_TO(0.00)[google.com,infradead.org,gmail.com,kernel.org];
	FREEMAIL_CC(0.00)[davemloft.net,gmail.com,chrisli.org,kernel.org,google.com,arndb.de,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,I-love.SAKURA.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[bvanassche@acm.org];
	RCPT_COUNT_GT_50(0.00)[50];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,acm.org:mid,acm.org:replyto,mail-qv1-xf39.google.com:helo,mail-qv1-xf39.google.com:rdns]
X-Rspamd-Queue-Id: EBA858B7CB
X-Rspamd-Action: no action

On 12/19/25 7:40 AM, Marco Elver wrote:
> +/*
> + * No-op helper to denote that ssp must be held. Because SRCU-protected pointers
> + * should still be marked with __rcu_guarded, and we do not want to mark them
> + * with __guarded_by(ssp) as it would complicate annotations for writers, we
> + * choose the following strategy: srcu_dereference_check() calls this helper
> + * that checks that the passed ssp is held, and then fake-acquires 'RCU'.
> + */
> +static inline void __srcu_read_lock_must_hold(const struct srcu_struct *ssp) __must_hold_shared(ssp) { }
>   
>   /**
>    * srcu_dereference_check - fetch SRCU-protected pointer for later dereferencing
> @@ -223,9 +233,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
>    * to 1.  The @c argument will normally be a logical expression containing
>    * lockdep_is_held() calls.
>    */
> -#define srcu_dereference_check(p, ssp, c) \
> -	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
> -				(c) || srcu_read_lock_held(ssp), __rcu)
> +#define srcu_dereference_check(p, ssp, c)					\
> +({										\
> +	__srcu_read_lock_must_hold(ssp);					\
> +	__acquire_shared_ctx_lock(RCU);					\
> +	__auto_type __v = __rcu_dereference_check((p), __UNIQUE_ID(rcu),	\
> +				(c) || srcu_read_lock_held(ssp), __rcu);	\
> +	__release_shared_ctx_lock(RCU);					\
> +	__v;									\
> +})

Hi Marco,

The above change is something I'm not happy about. The original
implementation of the srcu_dereference_check() macro shows that it is
sufficient to either hold an SRCU reader lock or the updater lock ('c').
The addition of "__srcu_read_lock_must_hold()" will cause compilation to
fail if the caller doesn't hold an SRCU reader lock. I'm concerned that
this will either lead to adding __no_context_analysis to SRCU updater
code that uses srcu_dereference_check() or to adding misleading
__assume_ctx_lock(ssp) annotations in SRCU updater code.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dd65bb7b-0dac-437a-a370-38efeb4737ba%40acm.org.
