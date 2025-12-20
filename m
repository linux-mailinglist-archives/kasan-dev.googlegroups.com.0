Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FXTLFAMGQEQWQ6O6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C0B2BCD2EE8
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 13:52:10 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7c705ffd76fsf2485707a34.3
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 04:52:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766235129; cv=pass;
        d=google.com; s=arc-20240605;
        b=lc0F8E5W0eBgC7wobamCooR1etU5B33W15hDMckncAcscMRT7XDfSnAVI4S8tzPgaq
         KPeSn5gjcTIAX+ztMK8CjrZDNDfRVz6o+8eF5G7BWIj59Jjw0qHX1ggokMTVupV1JjSo
         XDhEm/6InPHt1avwjUpaYkwilEO3xaA7MGEUlpei2TowqrVMrC3yGbHtoygciGq5oCuU
         MSElqkZIT7eCySWsJ3xGB5bJ1yt1PSP/Ygy7tr5SAZrWgsaXBnqdYpIGkstJI4MZpU07
         m1TD3YZ6uokUmRfGnHUhjVePykVaJ1OFL3hTXbetv7cVf4aacaPPWHW5WALt+kGy6pWj
         op6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n83fTRTBqzkcGAE0yKEuHmZwRhEWOXwOOAydaf2iIuQ=;
        fh=1HCL3Yf7viSQiaINpo1qr3kfW4n6KW3NWVlWKwipo6s=;
        b=eQGQn5gJIHh8hgDsxEj6yESf6Olik1XyVt2ZogSAsp3yBSSw/GHWOSN0sn+Va9Hqmm
         Xl7sIIcbE43rv4kk8AsYKY4bpHaik/9QxNZ64NhrvO//WZUVxUhHR7IiVOT2ZbE3edmt
         Jhwg+M+9Z4jd5a5kWGlqH2nHh/4JkAfThGpdWJzrlRjunRnwVr8n6CiQGsgyhchCS+Qb
         4v95wba23dtUkko2gpM6girHloG4GREydL6KFoadkpRAQAqeIHnFTPXPJrcTTO+ysMBg
         6jjBeCaHxMyXLD1XpzQkAnioa6d38TnK2H9UqwORS02VUhKC0+us/pVbAqPGGLRH6FF0
         /tGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sctat5kY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766235129; x=1766839929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=n83fTRTBqzkcGAE0yKEuHmZwRhEWOXwOOAydaf2iIuQ=;
        b=UrqCX50th40oWTG04arNvCtquYcGnRj5ev+JoY+Evg6sPPtAOw+dNs3Esr+DLKZZLL
         wNBujJctmG1MA4lbLIr6a8FaoLx9D53HN4z6582PBFqDQYJyXUrkU7YlAe/4lWGz5iPZ
         J2ZeyfoEbHvNSOveHyO7XcgFd2PbtowiTx3G20o6/nnkeU3P8LbGNPZ/oWGo5BNKcNcb
         uv2RDhGCEa0rzAMRrs7ZGt9yvepccyH57L7UIsgRAeZHghwNrMf+FfGfa8hi+yBt15p5
         cYxF0Msh1o1crSBfzZIDfUsckcKi8RmDQ+THqrTwRHKorfLX2WFON4t4mqDxZQfiNIk/
         xRTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766235129; x=1766839929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n83fTRTBqzkcGAE0yKEuHmZwRhEWOXwOOAydaf2iIuQ=;
        b=p1j7wx/KrC+UR2Mz/LONdXQzcXGrN8q5/ot3Sq06Q5c2mVRNFBw8JwBYiUe8ahcEc/
         doDCXBrSLD8vDeIf0x9XzhG0NYtaNwel/o4yRJ7y4vtKitEfxurPRxF//1x1mPXOOZ28
         /iDHz6+0t8G8dnqm2OvgFzb8Fll/QDCOaNEi4wAdQS87nG9F/RGjjDelzQfPo6K8DMnS
         6+ZwhMwzcX0m8JgQ+1IsMaXCuB0AwqnqT0sFo25LJTQlVSPi2YUcXPOr1iHtpyAaXvST
         H/3quBdf2/pJM6WHjY5EYQ+wTXq+zsw4wicb8zqBsr/K+H/OVm6mbIL0l/2nfRcWJu03
         lbwQ==
X-Forwarded-Encrypted: i=2; AJvYcCXoPBItwsJXqwquqylcELDnCyS9wniLwJdbSUPQXbmYXBZJfiM7vIZQQ1cNiWZyCDKCbBHh/A==@lfdr.de
X-Gm-Message-State: AOJu0Ywynwsc4ZiUiI+WIbaAxrm7TIGmJrLWp19TMmXdBPbkVeqQFybW
	Vl275pwK1d2PmxIsf2ksHF0g6LJh9YBLNDCaH8XIwzrKPvF+7JhbF2k2
X-Google-Smtp-Source: AGHT+IFH82SdUg4QoLop6WW6Ci9S3ZztL6gS8SE6bB0mSmL0TBU57CVa7X0ivt64WUvBiYxK/igUVQ==
X-Received: by 2002:a05:6820:f006:b0:65c:f583:d3d6 with SMTP id 006d021491bc7-65d0ebce72emr3131643eaf.70.1766235128952;
        Sat, 20 Dec 2025 04:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWadaG1JTELSnbTuWSOyTIDLesdKlLQxM3iH3i0pFa7YeQ=="
Received: by 2002:a4a:d818:0:b0:65d:3b9:f0d1 with SMTP id 006d021491bc7-65d03b9fbfbls1031103eaf.2.-pod-prod-06-us;
 Sat, 20 Dec 2025 04:52:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXqF0WgBUJRuDFsxW+ex2K9Pl99wwaRbjTdBSjd0eZPSh1tZkROAMFUkf9t05LMimviCHH+Fw6biy4=@googlegroups.com
X-Received: by 2002:a05:6830:2541:b0:7c7:53bc:54ac with SMTP id 46e09a7af769-7cc668b04a6mr3670439a34.13.1766235127842;
        Sat, 20 Dec 2025 04:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766235127; cv=none;
        d=google.com; s=arc-20240605;
        b=hSCUqUOWzgkPQ8d3yS0S7ulhjuOQCVoul1c+n33L17Yp8AGUVdD7XJMqPgrkMD+X3c
         kh9+xTY3weRaGGk9HHoTrss8pO+zTRpbx+8DuAMDFG3/F9rU3+ORL65dwyUsPl+zVtt2
         UXK5cR5uu4NxitRHV9dSIiDOfVhaiLbPh1qTfaqMO/wMHzHcPXXdPaKwBU61iYCWrlFb
         PF8ZNikuqgU/gOf0p3k5sZam6lelYd7CMh+Z4J2PQ/6MqI64Mfe147Rx+x/KdTI4ffeX
         8pWwCxQC+Tc8l1PB7ecy0kXbe7thcRBmbxAIkvTCCj8XMcoAjSACCpvlJr6qp3sLTRzt
         guBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+dbDPICBAvFxThOmxuLLN+XESg+4otRZJCktLSd/IHI=;
        fh=BFHD1ThCX1sIFslHIlKn8MMmu/MTdvbQf+wPed0pdIc=;
        b=S/RYjaAZHRXOFCYKO8tcve7abJXT08oKzBjn5nJzzY2j5Zkt7e3dgzhk78dAWId6W1
         2Rz7EL4o/0KNfi2ddL3tbPlvNWffRth7YG4Jtrpr+rXIstJueqG/m3rPKzPy3EKTP7zF
         lCkeQAkjhnbKJ6lCdXt8fc/ftvaTSi1QAQQpXO22dbtsC3B1lcnR/KRZyU6C/Dp0kcwe
         inMxyUqYFLn39x/VXPFwswA4dymTMshzsa0/6twr5//J+Lg5RaK/S/MLJfHrklE47EQN
         OZf1JRbywLqJ3U/DggYSlkAzkOG0MdV3yHY0sFNUqvwBdxXi9HYtrzBcbhrTobTufB0n
         pTcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sctat5kY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667b59b2si505013a34.4.2025.12.20.04.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Dec 2025 04:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-bd1b0e2c1eeso1944728a12.0
        for <kasan-dev@googlegroups.com>; Sat, 20 Dec 2025 04:52:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXgIDUiKHM+aDegt0znbucUomipB0gEelUseq0CIIo5DyXqpU+f8V6Qxq+ahcqJk/zsDhgK2uMGF4A=@googlegroups.com
X-Gm-Gg: AY/fxX6SUUy70xIFOSTvEpGfxU41DlM6WbqVyF2iTv0MxboP8jkQI8dkIp2A/ziRW6K
	0jTmNUyO5xlFCgVoM5b8xrCIkkzxzOHZChvRlIwYENeWFPX+fL8/y7lIG/1K+jjmwgrQl9HDo/7
	FbLyXr1cJxVmdBCoUI/OoO8NmlHG/PLQOCpRWTAchqXWgGg3sO30IAdB9hSKg9i+I2Cbu/D/PTE
	Sk2NtOUTE4y0EOZg5IcpbN0U1WSOnB7TVdpIcbgNk7Q6mIjJDV4i2LkzoPZ7l5ZyENAHLfe8fL/
	tutc8C2VFFnu5a2UFCJN1a3XD/Y=
X-Received: by 2002:a05:7022:6291:b0:119:e569:f61e with SMTP id
 a92af1059eb24-121722e12e7mr5961881c88.23.1766235126461; Sat, 20 Dec 2025
 04:52:06 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-25-elver@google.com>
 <9af0d949-45f5-45cd-b49d-d45d53f5d8f6@gmail.com>
In-Reply-To: <9af0d949-45f5-45cd-b49d-d45d53f5d8f6@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 20 Dec 2025 13:51:30 +0100
X-Gm-Features: AQt7F2ppWjAa_1uLXQb3ar2W4qqqhjA5uP_vsvi-YrCuihuPYztcukGp4Yjpido
Message-ID: <CANpmjNOUr8rHmui_nPpGBzmXe4VRn=70dT7n6sWpJc6FD2qLbA@mail.gmail.com>
Subject: Re: [PATCH v5 24/36] compiler-context-analysis: Remove __cond_lock()
 function-like helper
To: Bart Van Assche <bart.vanassche@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sctat5kY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 19 Dec 2025 at 22:42, Bart Van Assche <bart.vanassche@gmail.com> wrote:
> On 12/19/25 8:40 AM, Marco Elver wrote:
> >   Documentation/dev-tools/context-analysis.rst  |  2 -
> >   Documentation/mm/process_addrs.rst            |  6 +-
> >   .../net/wireless/intel/iwlwifi/iwl-trans.c    |  4 +-
> >   .../net/wireless/intel/iwlwifi/iwl-trans.h    |  6 +-
> >   .../intel/iwlwifi/pcie/gen1_2/internal.h      |  5 +-
> >   .../intel/iwlwifi/pcie/gen1_2/trans.c         |  4 +-
> >   include/linux/compiler-context-analysis.h     | 31 ----------
> >   include/linux/lockref.h                       |  4 +-
> >   include/linux/mm.h                            | 33 ++--------
> >   include/linux/rwlock.h                        | 11 +---
> >   include/linux/rwlock_api_smp.h                | 14 ++++-
> >   include/linux/rwlock_rt.h                     | 21 ++++---
> >   include/linux/sched/signal.h                  | 14 +----
> >   include/linux/spinlock.h                      | 45 +++++---------
> >   include/linux/spinlock_api_smp.h              | 20 ++++++
> >   include/linux/spinlock_api_up.h               | 61 ++++++++++++++++---
> >   include/linux/spinlock_rt.h                   | 26 ++++----
> >   kernel/signal.c                               |  4 +-
> >   kernel/time/posix-timers.c                    | 13 +---
> >   lib/dec_and_lock.c                            |  8 +--
> >   lib/lockref.c                                 |  1 -
> >   mm/memory.c                                   |  4 +-
> >   mm/pgtable-generic.c                          | 19 +++---
> >   tools/include/linux/compiler_types.h          |  2 -
>
> This patch should be split into one patch per subsystem or driver.
> E.g. one patch for the iwlwifi driver, another patch for the mm
> subsystem, one patch for the rwlock primitive, one patch for the
> spinlock primitive, etc.
>
> The tools/include/linux/compiler_types.h change probably should be
> left out because it is user space code instead of kernel code and
> the rest of the series applies to kernel code only.

AFAIK, the user space version is just a copy of the kernel version to
support headers that are used by both. See
4bba4c4bb09ad4a2b70836725e08439c86d8f9e4. The sparse annotations were
copied in ab3c0ddb0d71dc214b61d11deb8770196ef46c05.

And there's no point in keeping it around given it's all gone:

% git grep __cond_lock
<nothing>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOUr8rHmui_nPpGBzmXe4VRn%3D70dT7n6sWpJc6FD2qLbA%40mail.gmail.com.
