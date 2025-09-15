Return-Path: <kasan-dev+bncBD53XBUFWQDBBZHHTXDAMGQEE4FDP5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BCBDB56E18
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 04:03:18 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-77ccfa8079csf17698016d6.1
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 19:03:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757901797; cv=pass;
        d=google.com; s=arc-20240605;
        b=SExRm+Q8MGpDE9Ju/rPiEmxyfGC9Hnc6wEuiXOc2a5JY4HoLdVwDpBET2h1/naYy+7
         3KckM7D5rdAlg9r9wX/lqV5uvMwz4lsRdswq3XqprwqhM1w7U+DbwJ0yRkkFfv6EMAIq
         4swSxYnK3mntH8td9Zi7050lBi+tTqRHYCgWVYHbBzrMWwQiPQa2/f311U7YjNUUxZsz
         irpm+jP+jI/GNg7odT8bNimh19b4VbvJTc2Gz9n60893/oY4+eu6MerkQu1jgre1Ckxp
         Hz0a/77yCBUfzkQiJHsz2j2LZiyPvy/jSG2aidgiwysnV1Nl4qdhq+6TKaM1Wch7tV0c
         2BAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=874ZEHMEO378xB+d/Se27/aSNy4RpP14TUPwDo+strg=;
        fh=Zf8KPMLNSni2pAbRbNzKe0koCnT8PLjCgd6WexdNaQE=;
        b=a23mdMCUA4KwW2a8oTLldlVApetfwa7N5dB4rcKO2LLdWeLURhBw6nMo/gpGFCklB+
         eQ22ZIXJxJ3IOVlclsdhx9dm1rGmTS32rETpYxqiNMDgu1IukNNmjVjn4qUubq0lwIHX
         UITzEqdIqyRWusC9UD56RQvPdPKxRkO2oWRWfPGkhRMeB90q4QkyRTabFj0kD/JXP4YX
         UqN8bVD7lteWyJqfEuGP2sL/Ip1I4Kl6SvnqRfqXMUIxsclNNpTCIPeeJ4qxmRxHz5I4
         bQz3+3wuocSJrPQsY+trhvhH7RKyZlGCk3t5BDYK538gcw1kuPlpNqK4iTVFu+2D9CHn
         cRGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=akpTvZOt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757901797; x=1758506597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=874ZEHMEO378xB+d/Se27/aSNy4RpP14TUPwDo+strg=;
        b=I1lSj78XW9ZOno0qQpFMx4WxTXJ/4t/MAXYNoypI0S5UXH7NuYwq80Q+jFNhZUhoDV
         uYyXXLgrQWCpjdDOkYAK4LEnKuvvq3G+/3poIDUL2+zK7R8wqBcj28AVfCYaeIl9OAFP
         3Y9CZ70U+TIR0MY/9vl5RCZWzSDTGaAu3CIyaJrx4cR5uuzvPcGEpdY6GD3BskZifK9V
         rlXLJjedFuMb2kSYc9ovO5oYCu+zK8XxWjsGVQhzEOimhVXNybhyisZcFMtK2QCwyZTb
         KHkbqel5QvVgCPITx/qVBPJOrSWyyWyGqPSfoVTgmyDNhHgDCwAgQaap1tsLD9066AU6
         FkjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757901797; x=1758506597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=874ZEHMEO378xB+d/Se27/aSNy4RpP14TUPwDo+strg=;
        b=jOAZXHnl28JXsAl6KOH4YYqTLk4WMva48ocvlPSH8hncL1yMsD2fTRSnG3oRe8hHNt
         I/9GpzPM9AGqYnHyH1O/NjrhjpZLsWL52rDjlNXzlAFyxJqb4MVb/xDzkJ+M24VYIN+7
         zpWtBInQSmbm0qg8MYUvT4nDpc4vemE/ygj5n1CmRSqvwmPZGH/jo+Sjmsk0N4+HBgns
         +TNUb5A0gZ/L+6w2IrdR9NxSNaEbkRE68kTFri45x74cT9t2CDlcu9EYRfe/R5rudZbc
         h5PfeYFtLh46uwzYdpwQlnhHCogW8E7aAtSsOWaNywMQ5IyUB8KQV+SCJZrMQf2mMacr
         EG1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757901797; x=1758506597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=874ZEHMEO378xB+d/Se27/aSNy4RpP14TUPwDo+strg=;
        b=AtZg4/3pnGb4FW1eVcT9iZuOviQuSTbl+Kb+nm3F9supKTZE9974RO5H4x002n4FWM
         Z3umyIlSkRQyLMEUc/Reg7kkjzByGhDc1uuDewJxFjHzyUsUlvbSvDtuuuvY4smZ8GHc
         2sxNthQVWD4t+Wq2Q+3Qk6TPR5j/jkU6EbYsZBkn5PR5XDyfsgfn6VBNNOA9AEMuy7CJ
         jZihqydmJNfgQqTsndgePcG2IpGYj/UWqzDX+bz+mZqtppRjt5aZHoG5uAGfwLVVrcrV
         6hqSCilSjSNBsQGTy4eX7r+9ukdTbzcYI9LHmOmYxKSue738rbWCUFkORA71brt6J0Yc
         Yuzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAJIZ9X95LVdhC7H+rdx6v+/cIUnTX7LLhGPyZdcGPnCsqPgLrQC2EtZ6rqupyJQsVu2fkoA==@lfdr.de
X-Gm-Message-State: AOJu0YyrmRCmVLSR/fjmlKwu1EzUZlMpsZdHHFj6S8MFmbmmItXrDcDk
	cvLaMq+ZDp8UeCVXOpsCgY2RqMr065fKKUUXJIp405rI99mElIaeQ6YV
X-Google-Smtp-Source: AGHT+IGG50b6VnyygBQv8F5f7v+C63P1o3IGrabA5Iw/zysDm+c6NsRdhe/Dfr48rJ3Zn0uToEmAhg==
X-Received: by 2002:a05:6214:5194:b0:720:4a66:d3ca with SMTP id 6a1803df08f44-767bcfa8907mr126919186d6.24.1757901796625;
        Sun, 14 Sep 2025 19:03:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5/WpGUqbucBui4mFT36FnBhFjnVteJnXoZVkRPMc5RHg==
Received: by 2002:a05:6214:c63:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-779d37886ecls18768586d6.1.-pod-prod-09-us; Sun, 14 Sep 2025
 19:03:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxFxqniT5YoXYwl5uv1o0nbBcNrsIDKLE3d25yLAE92TLK9l+va53mMILm8yfgBpcndq8/E3uzxUI=@googlegroups.com
X-Received: by 2002:a05:6102:32c5:b0:519:f3b6:a1ae with SMTP id ada2fe7eead31-5560e7e0069mr3651884137.22.1757901795411;
        Sun, 14 Sep 2025 19:03:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757901795; cv=none;
        d=google.com; s=arc-20240605;
        b=dvg/b/iGspeohqenFPWBjER39Mv33wnLQ1nC7ZM44o+yoHXGmjbRHpnrODpd4es30r
         wF4n6RW6VJ8WDAqYdMIhZeGud21noDzHkfYddWjwLQnGGC1nhP8MGIc1qbY2GuvSvwKK
         IYmUm/eYfeun6K65hb78JIBQSPDxkWOV4s5+wR76/q3ZhZOwCIyraGZ7pyQdwFCL5cBo
         Xzpq+II/6205k/CHJsSBwOj+fgbqdo28YMlj0fjx4Uuxn9LhhoRsL+HAPT66q/2qLCa3
         sUkLc3MlbIDqY+KRrbbaGnIsCB4jSgIeGGL/EDv9PnuxfOEqO7md2EnQmOr0uDojvrpI
         UX3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JOygL22yeiI/c6chOsAL099+jLfX4ygYuBDAjkKbT5k=;
        fh=jWmq/+OLXXFLgJey7Xj8t6us1RbqiNVk4AdRxR7jnHE=;
        b=hTHgMqMCEaYBAPj+8o7vTKZ21KS189S+QjZRKfhU0MReTFAJvzBrCDByXNM/Igxa5D
         GrJs2xUlR2xK9GRtNlNkIPJFYE7Ntdg13YDEd2nkwLcLgf/19QDbKQDgoHhhLfe07dlo
         5ednMWGPlwfOI/UdCmDccSSLT5oESKgIHOLsex1BW40AtSL8y2WJk4srL8JqzW4++l5s
         /US6mBr8Tp32xtUWuAPaKEVSfBSGDV0eLiHhN7N8C8B29oZGzxfCBMH8X7JllS8DoeQt
         STeMR/3MrOceNgszf1YLg3oML+qRTSjvoBPg7WxnfR9QoYlgLm/2cVYz2Wx49pdA9PNO
         BSyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=akpTvZOt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8db2d6b7e99si106044241.1.2025.09.14.19.03.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 14 Sep 2025 19:03:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b47475cf8ecso2459006a12.0
        for <kasan-dev@googlegroups.com>; Sun, 14 Sep 2025 19:03:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrdozE81dy86XMBdlH0x2Gk7oYHi8FrSgu7EvO8lGpEoJMvBujENmxmterx/vVWBN+oCbiwftO4/Q=@googlegroups.com
X-Gm-Gg: ASbGncvHrDmaLs2S4v3oZ9u9wHo6VIdZQQLO7nkeVShf2E0C+G5dDg5a/yfi7teQm6l
	FBRva5SSzH7H1YbDn+bycHXlJ0b6u7RKcIkAJNKU+gh9QGB20x5YIg2tL3LneX5S9B+vvNpsNu9
	vEsGi3mCmsojpDMH4Y1ZG3NzWobbN8lkpf35qrdYLP4va/j9sAipd8BNLRCSipQAH+grRRCkav1
	N/ZRdaPHB0IQNMznqRdLWBXGNmBbXr+lDClAmvk27aRILhbG1c5uu1GkTgfavnkxOspPk74PJ8R
	UcOwVShq4ei2SmSBFMDEMEntnU9wKC5uRSs2S4xm36SsgJeLr4T+XQph75M5pK+JeyEjd9fLuHC
	ZF5oi0PrOLUQjfWiplYwqUOl93qF9+trb4roMKCU=
X-Received: by 2002:a17:903:f85:b0:260:5bab:8cad with SMTP id d9443c01a7336-2605babb245mr90876965ad.29.1757901794287;
        Sun, 14 Sep 2025 19:03:14 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-261333a972dsm51596705ad.75.2025.09.14.19.03.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 19:03:13 -0700 (PDT)
Date: Mon, 15 Sep 2025 10:03:06 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org, llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v4 15/21] mm/ksw: add test module
Message-ID: <aMdz2gMb5YC3G3md@mdev>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
 <20250912101145.465708-16-wangjinchao600@gmail.com>
 <69198449-411b-4374-900a-16dc6cb91178@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <69198449-411b-4374-900a-16dc6cb91178@infradead.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=akpTvZOt;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 12, 2025 at 09:07:11PM -0700, Randy Dunlap wrote:
> 
> 
> On 9/12/25 3:11 AM, Jinchao Wang wrote:
> > diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> > index fdfc6e6d0dec..46c280280980 100644
> > --- a/mm/Kconfig.debug
> > +++ b/mm/Kconfig.debug
> > @@ -320,3 +320,13 @@ config KSTACK_WATCH
> >  	  the recursive depth of the monitored function.
> >  
> >  	  If unsure, say N.
> > +
> > +config KSTACK_WATCH_TEST
> > +	tristate "KStackWatch Test Module"
> > +	depends on KSTACK_WATCH
> > +	help
> > +	  This module provides controlled stack exhaustion and overflow scenarios
> > +	  to verify the functionality of KStackWatch. It is particularly useful
> > +	  for development and validation of the KStachWatch mechanism.
> 
> typo:	                                        ^^^^^^^^^^^
Thanks, will be fix in next version.
> 
> > +
> > +	  If unsure, say N.
> 
> -- 
> ~Randy
> 

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMdz2gMb5YC3G3md%40mdev.
