Return-Path: <kasan-dev+bncBDT4VB4UQYHBBUUNS7FAMGQE2P3FWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 08CB3CD205D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:42:45 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-34c704d5d15sf4307816a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:42:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766180563; cv=pass;
        d=google.com; s=arc-20240605;
        b=FBcD7p94YU9FbPzSGss5lJSIyf18QesRLdU7hAY7FoMDJVLEfMkYto4Q51X3HLD2YH
         /nLX255Nsd2ftEf4Q8ajUe+QHK3u6KpYK5uWQNNzXhbD990K+Jts65zau+1xd62qWQDg
         DgnLTFIBznDb6fB2LG0T2HFE7ScYzMmB1WBxO6ygy6Qwf43N+88Q2jBXIeoLMN8tlVQS
         W6C5No0J/BEW/gefE0YCCOlJaKT6BLW/kwiI8hOcYHoVsLI40PL6hnrXgMfZYlbsruzE
         +7dCc4h4gl0s6PkRGjNL7WQe1PoLfdyu8gtDYUm4NdUIuvn9eHVRzGKWls05Z2PUyHKd
         tLMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=57N2c3OIpusCdHEjBa0PruRN/FwUwky0iilGCjpPyLE=;
        fh=CS8Je+1uItx8DLJ5jFeebdNDoj40xxYDDGrs6av9zy8=;
        b=Qf/eSUroTudIUdn8YxltxB7d9ucOkExQZ7yjxcVnxUe4AKR3oXnf28URWeZUYJp4rp
         CTts/cHg6Fa+xXyeccdbp+gXnln1HIQTw4K39V7AnOFt2ObB/ImGQI6YhPmWlJ73xLip
         cqGKQ8lSI9D47kMaHNYFHG3zT3AL7kuY1VS6HBTPeAn8s0R2lXOf2zYA5sX5UUupChP4
         m31to6AO9OB7JUhZcVqvH6iBlwQmxo7w+H5CnfHukwQPN28U2rawwfgorLMHK+soLD/E
         Qj2v95TZavyl7+GS17nvvxO2mqND4iTutsAE3EhRpOAHaxzZGDR6h4frz698sTgUjLro
         526g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gMu7boIN;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766180563; x=1766785363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=57N2c3OIpusCdHEjBa0PruRN/FwUwky0iilGCjpPyLE=;
        b=SUC2hPef74Rx7QL4HA0R8plq3QlBLH177gCS7prOEznZ4PecFTz7GqF/SUkF0RBpDv
         068V2ekgQdZxmWDo0EFLjZcXErYLdryS5Sopffk5NgWSYDICbsf9/8RjaezICK+FZ5VI
         TxW/caJZUCRw/1qVA4AKm1nH1uNSt9A/IIaMpXJ2qychPJQD9rBs8UlGZSXHWVh5WBIq
         7Y14zDaBtJ4cKVRagGuwlMg33jLsOC8Xnkc1XD8k6dKX9P7+JloXvbnw+TaaRZfIvXcf
         3aJEP0JzRL8DX7lt6vwwvGHCV5/P8cyWMdzB8z63XPGhxOVjBadzhkLZPBdSaXMyb231
         YYPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766180563; x=1766785363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=57N2c3OIpusCdHEjBa0PruRN/FwUwky0iilGCjpPyLE=;
        b=FXwQyjPKNXv/yjspDJxhvWooZYMvrXNFLDgAE4GI2EM6hxvDoP/xsVo+bcbSjhc74T
         ACCdfBJ3HAr6TRXJPJoC2ZrbntWN47Pi7uQE4KOXLI1ZGAoxBd0ZKfWICva3JhRe5pwk
         02+5/ljx6dkC4hEIvuQKt//Qy7BfvzOsM7KuL3HWg0gtkxedgubxSn3Rx+yytJoe9hvq
         1DBQvotPROvvNTQFvnM8ZglQaD8GGviC+KV8qasgJVrlEUgtMd7ZNgiu8qqlxPSt8GIu
         mbkFN85+5hpaTtkJuKMEypZVpH1+j0aE0rp4eICru6cSItp01IscGECqXVukVUE0rFch
         SYAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766180563; x=1766785363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=57N2c3OIpusCdHEjBa0PruRN/FwUwky0iilGCjpPyLE=;
        b=pU/uxR3SdUo4k0hyLI6y9siRTqGUcQuBJLYeYeXuDwyMN0MkzoAVsdaoT2V02gs0FD
         aYhyKPAZyPBEI1xtDoEeEEtDvEdVftMzT552ZwAMuu1I2hd/Mx43YH30OM/TMYobhmhW
         UUPoR5uF9HuwF2qLoIPgjaI+wEFuvvPhgJsgyZQsCQdlf6F/J9r/m4Lvx/VYEGB1pxY6
         SH+jLAz8nlNv9C1RpqjHw9FvRbrB9kvY80+LNBLuFm3Tur6WtPnBXsiDTeTtpqtOI/gQ
         h98KmyyxvsY5NH8+mVH4p7TSfgDCpm91NZkyvXwcGejzx4Y5+6d1BHraAY5TY2MM4kaA
         ZkLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXL2y47M5cgFZyt26iwK7w9ec+dOr3yvZYTpJFSYbL/sjJczsiabtr+ne5Nh+ppnV70Bk2IEA==@lfdr.de
X-Gm-Message-State: AOJu0Ywj2Zqgk9texDRN9BnmOGe3wHY5FWhvzJVbCBvmSiEe29Ir0rLx
	PowJHW8Y+whn7lJ5KLBZwDhm3Mxl67adGSDcOqMrH9gjiTsj2ZRziEaF
X-Google-Smtp-Source: AGHT+IHcrJ9s2hFrXC+MBhu6yp0+1vKVZuaL78iCkf1evuRq/IMjWTVrEnsrronHWOlfhWSDsDyMYw==
X-Received: by 2002:a17:90b:3d90:b0:349:3fe8:e7df with SMTP id 98e67ed59e1d1-34e921be5demr2656828a91.22.1766180563333;
        Fri, 19 Dec 2025 13:42:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaKojmSE9fa1QZlORqPXhaHlP35TRZyAb+YnDRuUagdKg=="
Received: by 2002:a17:90a:db81:b0:34a:48fe:dff7 with SMTP id
 98e67ed59e1d1-34abccf6207ls8270684a91.2.-pod-prod-03-us; Fri, 19 Dec 2025
 13:42:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV5Hw+dvOMSazRIej+nTHbY3IcZTa3DZ5Ye4UR+yxrwzFAUjad44sZT7k10oc6maq4QqtoJkcimCuo=@googlegroups.com
X-Received: by 2002:a05:6a20:939f:b0:359:57d3:91e1 with SMTP id adf61e73a8af0-376a7fe5176mr4005190637.32.1766180561834;
        Fri, 19 Dec 2025 13:42:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766180561; cv=none;
        d=google.com; s=arc-20240605;
        b=Mi0G7yc30MaXpj0w6R6N02Ys5dDHKnZtZDON/sECqGBR0cq3krgrG2HVbX3LaT52bR
         4uLFSLEnER+VWsTJ39YycXM6G2NDBi+Nl+WgXeBIurIThDlaBAx6i30H0LUAH7wPLUx8
         /+PpsxoUhsTV8VlPl8J1W8WMxr34ohvNJ3lWPCfFfdIP5Gzf0GnzPbgJR64Pr0lG+ptC
         yN41p7FKKinSjYds+d+h7zV8h4N5UJP0kedBxUJuk8ZmjNbMnm7ORpDeWpJu78XTZdn+
         IRdhj+Xnf0XGOIuxsuihG76RjSTaOAInwgJfPzJqgjnUr8ScpYo7r0o2UxLb8IW80M7C
         ukag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=xhB1Fco/aAscGV7BUmHv+KRyMsa6iylEkhRycjuIJTw=;
        fh=q/5z5AHQL61fmuC1qWxqCJseT6PO/jhgI8vjh7vaYFM=;
        b=Lbt6GMQLTl1A69ApFTLZcxiXYUz/YSODBoIPhnsNhg8nSSzi1Ggh8j+3ac0FLRPSyl
         EDGnFn45jF4wrYydwa2du5kk58rIN5lkRTkYwCNKX32GCzMBH55QYAPP3LQpEIjHSVt9
         v4y3hfT8w69amdYDj4xADTpOm7tpSNslyYhZGIhLNisu7cLKYY+/s5t8eYECZvdFnMKJ
         Z/SFw27gRGr982lnmTSqvuCx+Sy1q/094GCkShJhEttts6nT1baREr0+7JRlJtrpBbBO
         xder+T1udtDeNciMzjMmpWnnPGvfZeVew9S+TMd3f7pjKGv1Bm/xxYK89XqCMoorJa2w
         ufhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gMu7boIN;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1e799193e1si83476a12.2.2025.12.19.13.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:42:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id d9443c01a7336-2a1388cdac3so20720735ad.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:42:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU85z62b5IPjLC0mO1lpFH85rMn4DxcEFffxtHqT+bv00Dnqei3pj7v6jtXcpDbL+DMNSu1L8JOcjA=@googlegroups.com
X-Gm-Gg: AY/fxX6ut8MINdl5pUmulGYt1jGJ2Du/DvIx15qDyq2s649w/lvPUFQ7stGmlzoYQz+
	NEVAgWe7D94ZmFI9QQb91BKVP+wK0O2ZrjGNnm24EZwCh7dDtigXscNYVBjhuTSSZg9Zdo9pA4i
	ob5z9IndcoOY7A8iRT9KziU7AvFvCbHiYi96qlGEbnb22PjeQCN3lHPVcDo1DLr1WRiQYZekvWb
	9Qf22bFqcwBNbblGzcoqpVe4LnAwBzhirWsBAPk6eTP30As/e7qLhpM5f2CGQKojMGR75wj9WGs
	fqTg8ur1gkLPxr7fmzP7HCJy2Nd+cTfBKQK4gYFNe0pZYro67WUdFyL5uYuHlM5Jl+BWlGT1/Fw
	uRIZabTKkvLjnNerOnHRh8+YMswZxz1MbYVz9Mjo0cnuEetmDgYWJnhAFf9lCrRZG413rcRNdWo
	ZXfZD3NqrsLCTwvRUXebStiEKbTHsrtocGlt0CWFu84VnOgutw/97MJynp9sMPXLMQWYAG+2wTH
	lwXVouXXUrtYoJ04WMZbp/B8FJJin0TOH+v0B6P8IrGaPVanVw3VSbM5oUJ9K3CH3qgmik3UZGb
	LzE=
X-Received: by 2002:a05:7022:62a9:b0:11b:78e6:8323 with SMTP id a92af1059eb24-121722fd212mr4438541c88.37.1766180561251;
        Fri, 19 Dec 2025 13:42:41 -0800 (PST)
Received: from ?IPV6:2a00:79e0:2e7c:8:5874:79f3:80da:a7a3? ([2a00:79e0:2e7c:8:5874:79f3:80da:a7a3])
        by smtp.gmail.com with ESMTPSA id a92af1059eb24-1217254c734sm11636083c88.13.2025.12.19.13.42.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:42:40 -0800 (PST)
Message-ID: <9af0d949-45f5-45cd-b49d-d45d53f5d8f6@gmail.com>
Date: Fri, 19 Dec 2025 14:42:38 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 24/36] compiler-context-analysis: Remove __cond_lock()
 function-like helper
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
 <20251219154418.3592607-25-elver@google.com>
Content-Language: en-US
From: Bart Van Assche <bart.vanassche@gmail.com>
In-Reply-To: <20251219154418.3592607-25-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bart.vanassche@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gMu7boIN;       spf=pass
 (google.com: domain of bart.vanassche@gmail.com designates
 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
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

On 12/19/25 8:40 AM, Marco Elver wrote:
>   Documentation/dev-tools/context-analysis.rst  |  2 -
>   Documentation/mm/process_addrs.rst            |  6 +-
>   .../net/wireless/intel/iwlwifi/iwl-trans.c    |  4 +-
>   .../net/wireless/intel/iwlwifi/iwl-trans.h    |  6 +-
>   .../intel/iwlwifi/pcie/gen1_2/internal.h      |  5 +-
>   .../intel/iwlwifi/pcie/gen1_2/trans.c         |  4 +-
>   include/linux/compiler-context-analysis.h     | 31 ----------
>   include/linux/lockref.h                       |  4 +-
>   include/linux/mm.h                            | 33 ++--------
>   include/linux/rwlock.h                        | 11 +---
>   include/linux/rwlock_api_smp.h                | 14 ++++-
>   include/linux/rwlock_rt.h                     | 21 ++++---
>   include/linux/sched/signal.h                  | 14 +----
>   include/linux/spinlock.h                      | 45 +++++---------
>   include/linux/spinlock_api_smp.h              | 20 ++++++
>   include/linux/spinlock_api_up.h               | 61 ++++++++++++++++---
>   include/linux/spinlock_rt.h                   | 26 ++++----
>   kernel/signal.c                               |  4 +-
>   kernel/time/posix-timers.c                    | 13 +---
>   lib/dec_and_lock.c                            |  8 +--
>   lib/lockref.c                                 |  1 -
>   mm/memory.c                                   |  4 +-
>   mm/pgtable-generic.c                          | 19 +++---
>   tools/include/linux/compiler_types.h          |  2 -

This patch should be split into one patch per subsystem or driver.
E.g. one patch for the iwlwifi driver, another patch for the mm
subsystem, one patch for the rwlock primitive, one patch for the
spinlock primitive, etc.

The tools/include/linux/compiler_types.h change probably should be
left out because it is user space code instead of kernel code and
the rest of the series applies to kernel code only.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9af0d949-45f5-45cd-b49d-d45d53f5d8f6%40gmail.com.
