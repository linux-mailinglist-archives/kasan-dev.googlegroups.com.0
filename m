Return-Path: <kasan-dev+bncBD22BAF5REGBBAGS22ZQMGQED4OC4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 49206912B47
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 18:23:30 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-627f43bec13sf40166967b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 09:23:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718987009; cv=pass;
        d=google.com; s=arc-20160816;
        b=hDtsdlRIFvTaj6HY60kLEShKt0FanHRHD6yVTjckrprinUCuKGXhEE1nXJijrNcBj2
         nublPLPagimwebHudUkpQEqBYHXdKfM8Booxus1WckZVm/us+kDScounwB0/rlRX9m8z
         Rs7cg68S57eaXOz1Lr+RAZ8HVtJvsFMdceFo+DfREZQprUs82Kq+CsKLyItKhDE8kCrM
         Mfa85Rucoynv7KH1MzOoOqdBY65zR5huPe0TcBLBCQy1r4mECzEHT10+oWbLjnptT06G
         eWdIf+5JwWeDCxfxLooxpEkEXpoy8S1Zc9ZB4hhSW80DMupHpa/oGXAc9mFoFGpW4HgO
         Br7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=bBIlP/hK+jE2z5qLGj9IGaGyltAhn9QMBMgdWSCOAJk=;
        fh=P/8xGCBjXNLzTJolT/AvEdT6RCLQkega4j37mSxoC0A=;
        b=Fdb/vvg6e8u6vN7m9OsPefE4dvwLNMnsR5ljPnG5HuXTsP1sCrhpHB1KgE5Qopi8ju
         xSTpWd2QaMASKpoebV8nkHLqt58nfa3ULLXWrU2gpXWo78JPCpkQQnDE5vHFndMXpSBf
         sDw982hVLpQU0GLnaF4R5gOpQ57yNcxSY7ewTEy8GQOHTIGBxG8jY2RrUftb0vsMsv1n
         61t/xN5N17HmyciySVeNeHuPmRWRi/ZNLJW6QVS9NllUH8GhUNZFe//z1eY97J9DFRR1
         V0zB1RTdqjwhm7YWOFkBD+hF7+asUNxin0Dh3WGeWqGAl5nWNA5LMPVrsW45o7pe4kNl
         JWxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CGIjZKPI;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718987009; x=1719591809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bBIlP/hK+jE2z5qLGj9IGaGyltAhn9QMBMgdWSCOAJk=;
        b=rxm1pVbgAnKjgTlLNR53ZjEBazZYOkufUTmgz56GvWmqH/5U3rzQg69O7gcYfiMGPw
         5/VB0pkgRiqrM9aPJFi6Zj7Wn/trrb3tgo+MupS3EKN6/rlYGHiLO0qKcwg2iW4RSVMh
         319D2kUxPxBqauS+ja7VqaR6ewj7MKcOjL7MW/Seek8Vwtnccek9/3rXlMFDysJg0ZBF
         h1hF0q7iSDZIVvoeEaJ9u3M6MVulmlGam9zxyUpOPziGoCKAhUjyrjlQxXZr08M5HG89
         edXS9qb6z173ZLdBr9vt4A7AX4WvVKNodEFfY8tdiXjxGwsj9KTu8EIMcDZlVkfE3BYk
         LFSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718987009; x=1719591809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bBIlP/hK+jE2z5qLGj9IGaGyltAhn9QMBMgdWSCOAJk=;
        b=ZRUbk98twRuYCYbbsCAvlbkFB9UBgC0kI5GZZo4Ty6HXP1VtivMpjXKGEYz6Kf8gJi
         61mczAaMpWnH2qLFcHFG92L8xUbqPYjuG6nl36vFMcdQp3rVsDKbBUaEWv2eXgBNYOL2
         HgSwHBEYVcohM+rAB9tbPcnT8ScOIFOm0MuZXh+OkzfIfR2dfbS/zCGSgQFgEYfNEs2q
         vgq4uIXy1O5Up8LcFwXq0HfB7CFW7Xfsy3lEeCKsQ7Yp1zSWkf+Zh/0MI1nxkA0DP1w4
         sdDV0LUziKbWWQJ0xCqWy2WDBBlft0ACClKl4foftW26XAHqZ7AGN7496GOwzSb3frQJ
         T9Dg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUosDFHmzFGCB2t4P4MKSjq5uvzMIpyWQd7Y+4U0WgjKzpH7pUd1DlywN5Rb/z59DrdDu0Gpe4knYy/xW+ceI00e7+JwoUpGA==
X-Gm-Message-State: AOJu0YzOZHvQKSrAQNeBqEpVBxmdybEovewLp6LpbwW4o6eGoZAv7Bei
	HFAZz+UoezXQqMsXY++UHlEtM/cLNKaE1Kf9tdaK7aBxBXoPY9C5
X-Google-Smtp-Source: AGHT+IHU/KMC+ZerJTnZvZirzEiNQ+9U1XsE+Zs46WnoF+SNpM2UUh6FsK8QqANXdzFZJeaSNNi1Pg==
X-Received: by 2002:a25:6ac5:0:b0:dfe:148f:114f with SMTP id 3f1490d57ef6-e02be16c2acmr8316838276.27.1718987008570;
        Fri, 21 Jun 2024 09:23:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:722:b0:dff:36ec:fdc4 with SMTP id
 3f1490d57ef6-e02d0dbf4dals3221172276.1.-pod-prod-09-us; Fri, 21 Jun 2024
 09:23:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVl7e8IhsWTQkK9ywokxxgosSxMFFwbBwFMluyLGtQPskUyDJhkSHDuiuh2JckrTND5tVQchA93JYYp5QR9TVvBYPRoVYbPOo6RMw==
X-Received: by 2002:a81:918a:0:b0:62f:e5a7:5f05 with SMTP id 00721157ae682-63bc00b1312mr67770127b3.17.1718987007878;
        Fri, 21 Jun 2024 09:23:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718987007; cv=none;
        d=google.com; s=arc-20160816;
        b=E6O5NCfj6WqSgN9xzoIyv8XDMy9DcfqmgfWVBwwxDYImvtJXgDYCyqot4z4t+RxPBo
         3PW5CZE0AjQJbrzfej5UFG7TLqxeJf/UlIj3HABj/fEVTWssewXZHDI2BgaiTr5IwK5r
         MHYFKUjB7QhPBKAFuiyZga/T3D8ikk0Nn5TKXzFAtaCvH3oac4+jdKHMy8NmKUl6xmSM
         50sNEmHt6VqVKIwAxvvkCFUlT7Vj1Vp/Co0C0ShflY4xZxJn/hfy32oxa826Ngnlowlm
         yfqUq/TD1N3vwzPv3Ynqqc69Piz7xsLEDqD6VUMW08Z/qp2nUF8J/Kuldrx7G6xV8g70
         FGgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=g41fCr/vtBCeTN/Ly6SfE09zUQ6RXih71IpZHI2jeKw=;
        fh=p9ol9HbQzwu3EmcfdSTdvAcv6Qm2DBd7HEPa3sXYumU=;
        b=vKts4LG/Q+Sm1NwnGb05vN8/RdczoGk38zXWflPiGrtuyIOFjwsbda2swwne1dOFh8
         RnjoWiLQA5EwK/AH4NuSwtZuxsGBsi1PHTG2Py5PDZzIkepkHaYSUuDr/IcFlWPDDs1G
         smSkNYcKxcHHHI1h26MnFj8yClVqzUiPDB5mjkiiqbvK2otTBuXhFTDp1IZcHLu0EXXD
         o0TnzxG+JT88Ss+U+36+SoadCTz1M8JqG0SNsyplPsPYBad5bVh9ZmxSH/mM8OhSxvOu
         jqZzsQO4LZr/Bb8jxiVMBRKXkm2K11iBtr6uSUUU/299LyimS/9wuMHfDW873J3CKlPZ
         hDzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CGIjZKPI;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f0bde297esi1256867b3.0.2024.06.21.09.23.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 09:23:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: QGXIigZHTAOmwasfFbQapQ==
X-CSE-MsgGUID: rfQoBFT1TT6CtkpAUYq/cQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="19803313"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="19803313"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:23:26 -0700
X-CSE-ConnectionGUID: z3kgZMNbSAmL6j3YJABloQ==
X-CSE-MsgGUID: lnEidqcaSWCsjXCcWhadDA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="42718445"
Received: from bmurrell-mobl.amr.corp.intel.com (HELO [10.124.221.70]) ([10.124.221.70])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 09:23:24 -0700
Message-ID: <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com>
Date: Fri, 21 Jun 2024 09:23:25 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com,
 peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
 Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>,
 Boqun Feng <boqun.feng@gmail.com>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20240621094901.1360454-2-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CGIjZKPI;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.15 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 6/21/24 02:49, Alexander Potapenko wrote:
>  config LOCK_DEBUGGING_SUPPORT
>  	bool
> -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
>  	default y

This kinda stinks.  Practically, it'll mean that anyone turning on KMSAN
will accidentally turn off lockdep.  That's really nasty, especially for
folks who are turning on debug options left and right to track down
nasty bugs.

I'd *MUCH* rather hide KMSAN:

config KMSAN
        bool "KMSAN: detector of uninitialized values use"
        depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
        depends on DEBUG_KERNEL && !KASAN && !KCSAN
        depends on !PREEMPT_RT
+	depends on !LOCKDEP

Because, frankly, lockdep is way more important than KMSAN.

But ideally, we'd allow them to coexist somehow.  Have we even discussed
the problem with the lockdep folks?  For instance, I'd much rather have
a relaxed lockdep with no checking in pfn_valid() than no lockdep at all.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a38bded-9723-4811-83b5-14e2312ee75d%40intel.com.
