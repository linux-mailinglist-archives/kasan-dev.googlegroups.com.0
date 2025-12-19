Return-Path: <kasan-dev+bncBDT4VB4UQYHBBYEJS7FAMGQEBFRESQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 93612CD1FD6
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:34:26 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-7b8a12f0cb4sf2564187b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:34:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766180065; cv=pass;
        d=google.com; s=arc-20240605;
        b=DpEVFKwsuAubG+iCM2kTaXxGNNvJK3W/oNESlaa9/Y+Dj2L/33D7AOMO6gocFJG9I3
         xPlnxe0+9C0T1UvG/Cwd4spEwalqpOqtbmsScCbgQGsy+p6wBDN6BwFPN3jSqayZhVQ/
         J6QKnXkcd4ac+0yslqt9eLmFNBV8dCxVj+NxqWm1Tw3QhGoTqUMhppG6/qJOvNrfOXAJ
         kG7nXxVr0mzYlj1ITXscWnAD04k10ui4fBw4eq5qXwqDZFJLgTvOb3MDS6mxrXSdzc81
         tSTc6UB1L9Xd8dnYw8lnL8RPj3lb7y+dt0dYLrteyZhInqVix5rMXC4M/bdNAsG4gwlF
         pVfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=X2Ll2FIfF3ToWJ0XCysased83qA/k2rtH0hwEWPIK/w=;
        fh=8NpuNE1b8YzzZoGwhjG4NfX5zqmWbkMvmPtnJsReenw=;
        b=JW44SZt3UgDMwf00p15JkGEGB3oHLd5dTuj95Ji0a40qzjtPYwHeSdIP26riF6QQaE
         8JBcSNbQkdtEISxVmOl4lwI0voBoQcfvwzyhgIF1z2aUKF8bAa1FoKa875zhF5rzBvcD
         MTm7NBioERC+nfsgn/Im6pzDZiTRKH5v2784wpztqV293rpsjPiG6jqmNaX4kpZFpVF2
         tXFVoYoZaCfLbxrBWzKDqx1YsljwGHqhil7W1gST+VUlDuXxmso3BhTDtX8K5PoTcSWM
         Ee3Vx9PFndUBRhj21pMu+vyUbL3EO/79GGp0ypD2eQtJXqdD0Y/KFTF7n9pbhKqCckcX
         LoCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eNwrnAUt;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766180065; x=1766784865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=X2Ll2FIfF3ToWJ0XCysased83qA/k2rtH0hwEWPIK/w=;
        b=WR3Ao8dw22sy/pJOrqN/hax3jeBq3clPIRQsiUSWotGR55Pwrnlq4CIudzxpiGyYiv
         cYxRboudAxDJDHau9a+8J0sivt7c28DMYAbBCfsdpfy6nnf3YE/Ksseo1ndaIhkwJVLo
         hTYARSR+d8rHBVLryCOhBXQfrtySCxTBnc8tsHYcbWKtQaN1XAchX7KOazXbXD66hzR2
         PvOqKUgVUyTLMCWxgrgveAqBRiP9u6aEvliOUS8VTHOekQzvEsU4JxcF657JvuY6pKpr
         GDHWXIHVP9Hev2nc2ye3vbREfv+sSGHC1+o3dlj2iRLcRyFaRmyD5F+Dd83HvowYDtIv
         BfGw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766180065; x=1766784865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=X2Ll2FIfF3ToWJ0XCysased83qA/k2rtH0hwEWPIK/w=;
        b=cA1r1oWNclOmatDrH2stpRlx93wMi8ggfkBUDFOuuxfERoF4ukp0JPvY+JxmO4jtE/
         MwQvAG/9Ncv0fft6R6AidKU1wzUfMEghBLZrVJD75QtAHD5T+1qf1JeLXOdrkqlEe1Zk
         pz0I5xlSU6EzZ7kG0RyVqQtyFxQU+iSqcyEi+PB8el7hVBEXb97fJTPX/2cXTB/WRqMc
         UZr5bsvdyNBD/jzviDqr4unl9Q3pC3qt/ShzD4dbwoGab0vPxf8+ShXJVME2IZZUpO3X
         F/Tr5sUOrOXw04Z4jFIq8/FOXvnyJ5hD4smO/9I857qDfvtdDcQ714P49XkPiJhhpOP4
         +rsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766180065; x=1766784865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X2Ll2FIfF3ToWJ0XCysased83qA/k2rtH0hwEWPIK/w=;
        b=l4FgofS9bsCRkpXyYzdNZM0mF82Dw/4Fo29Qif8li0MDoM3sjUbiUuvOO4FwP+a5Qb
         8Ruu6tRRZsw2UDEJvuakGImrtbEvTOD/d4ky/m7ZCC2cd9GbgJtLTMKgsxLEr9Ye8OiB
         lhsUDuMy56z1U8qIfes7Dr0fc0I+AE2QODUOAZilf/5dHHUlhumr1qDogJRMNVU6g1LJ
         qfAip/8WA5Hb5dgJfdzSo0liyc9GRIzwMuhjcRttlAoObekNUP9fnrmI37ekGNl9uq7W
         SvPV66TrfQ6TPY71EYP1AoryNVUGSR5lxNG4FvVfHZMNN3adlUsIVo7JZxZnHYx+ao+B
         wwnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeOH/OBNUyNzMxwWpo04YNLzcZfX26Y1/HqHblzQRes/Rf3bylhbeOIcXb6HBCK9ofMDoqbw==@lfdr.de
X-Gm-Message-State: AOJu0YwVIIHJp4wtfKYqx5eQ4mHEmsWZGjNfGNFKbyF0GXNPplX9z61+
	WkF6m9GtNbpmLpQrUBwPWDyY5pIVB9pryy5bm8nzgO1+/xjCso6PYMSI
X-Google-Smtp-Source: AGHT+IE5X3b1lFfv4qvd2B2aHqPm0BjHEoiFTWqEnNK9lpbYpCfnpT6BRggjoIrQjBgqxZN9h+cRZQ==
X-Received: by 2002:a05:6a00:4396:b0:7e8:43f5:bd4f with SMTP id d2e1a72fcca58-7ff676624b7mr3908258b3a.59.1766180064795;
        Fri, 19 Dec 2025 13:34:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWazBseGk9ZgZLVAR8C7D5lHYk7VMW7w5ObHwRuOZP2e5w=="
Received: by 2002:a05:6a00:9141:b0:7ab:f0f5:3013 with SMTP id
 d2e1a72fcca58-7f648499899ls7739363b3a.1.-pod-prod-09-us; Fri, 19 Dec 2025
 13:34:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUaIu6qUn/LSLAVlgfE8gCtzBvBJzIqbBrSy10Dnsej3d7kbW746Dzi0LG4IdvS9RYIgZCwr8sa7Fw=@googlegroups.com
X-Received: by 2002:a05:6a20:1591:b0:360:b941:9907 with SMTP id adf61e73a8af0-376a7aed4f6mr4453918637.24.1766180063109;
        Fri, 19 Dec 2025 13:34:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766180063; cv=none;
        d=google.com; s=arc-20240605;
        b=B7TCaRP6zzj3kpqSdv6ReLU+IA6ZW0IqGJzlmi0+VpeKEAsc2V2Z42jRYWM6Q7Hbj3
         cOXny/kU78kuVcXcRIOEgL4/RMPZCA8tuBHIp/J2r/aDjpzcJvRIcFfG4j+ZIxAduZmA
         RUiDVlKUtVqeUyjTvNbx4wxroF38t0eQbVVKcPHkKU47XS7L+U9YhTOmaeFtpWwdPZ30
         /bzuNrNSa63anmq8zzWVm35nPQxHVRLC51SlCInZbw1rQZe6BEgJl7WeeYlpzOamr2a2
         /k5OVw0fmUXBWPFRJkOt6LYnTbCJfa18cjgSUitJIBipqeU5WlUCLL0UUuSLKLfoLItQ
         G8+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=t32XLNtILrSHOTsv1yzEwE7SsXS6lnNnHJdt9fn7tL4=;
        fh=OpUZ1cR2Jj5h1RcfRgit+jhPRetlR7sgtfud0vTDH+M=;
        b=GP2LL4J18utY7rlGs5G4rD/85niYcYDJW6blER5MzlcXHf+CipjZfKTn3IMxxf+glv
         1E3a72HLlRB1I+lKKm9YwJaCJv4J76/g0nOFSMxeyxHrpIf6zMESkvi6knQTdYZRY079
         vpO75Y0UttfzT95XQXJS7NwoHhHAEOGxiz+ktUU/kf+OfuXzDe7MsGMF3BLfSb4er5D0
         U/sbmlDeebESZu1m+Vob/RxEw8A2pT24jg48AOlMEWDqtrqBY/BFBE3TkK4jNRazyqaC
         aJUoSyUH0Zcx3G84npbwicRllLPgHbHJ4bZDewhDiyT4izD2ZHpTXnUtjhISEKiAIT1e
         NR/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eNwrnAUt;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1e7bb66b95si80523a12.3.2025.12.19.13.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:34:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id 41be03b00d2f7-c03ec27c42eso1251989a12.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:34:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXD68Lrt/GqpSMMpbQFgWZaTmuwFWpH2eR2wXHAX1pvcN95+xugbqnyw02VnrL3d6i/XjGJ9Gbn1QI=@googlegroups.com
X-Gm-Gg: AY/fxX4sIsqVFuy9PhMf2BpfX2m7DTgWRX/jKo6nuvOSSJAU0rbRvjLlnGyXtFleLgj
	kIA5hZ5/tzn1l3qiBWA06C3hUs37vracwfU64AuISNWLcp9AtTjw0KaIXyhTWtSVutUeZG6q8fp
	CQSkkt0yRNtuIt57z7sGmEg3KuPRmzfvzUnZ5L9h9ohorGzxGx+ToDf3Cwv4DUFmUc9SZW9UDar
	+RlwPv0rTWPlz8D0wRpZL6B8U1Um4tHiCKANO2iNanzgL5NUMWyD9xigQFBAIRDjqf7sypoUvsi
	/XKVR0ZQxt8K+WkzCh/PlhplFoj7ie9nogShgtvmm0rpIx9x8IRdKUXUMmd67+F6d95590mazJf
	AR3Lgh3dx60oyt+JNWgu8LFAsSRbZ0ukZHC3dmrbb72kYBCBvJqEVROsTcNP5xR9GVmKqRZXpLX
	UqhSA/jm4n3qAJ59+WoIEBdLRXZeXPrCs+1B2zMq59rYQfhk2OVRAP6aHshNBQqgSBif8l99Xpl
	1qc6jGkgq2K1aacDxjCap+W3b3fIUOpKE+FsdPMv2Dxv+zHMBpayBVkzGRqLA+eZ64ii2X6HLbf
	pYM=
X-Received: by 2002:a05:7300:b54b:b0:2b0:57ec:d1a1 with SMTP id 5a478bee46e88-2b05ec745e9mr4652797eec.25.1766180062475;
        Fri, 19 Dec 2025 13:34:22 -0800 (PST)
Received: from ?IPV6:2a00:79e0:2e7c:8:5874:79f3:80da:a7a3? ([2a00:79e0:2e7c:8:5874:79f3:80da:a7a3])
        by smtp.gmail.com with ESMTPSA id 5a478bee46e88-2b05fe99410sm10155463eec.2.2025.12.19.13.34.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:34:21 -0800 (PST)
Message-ID: <0088cc8c-b395-4659-854f-a6cc5df626ed@gmail.com>
Date: Fri, 19 Dec 2025 14:34:19 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 08/36] locking/rwlock, spinlock: Support Clang's
 context analysis
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>,
 Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
 "David S. Miller" <davem@davemloft.net>,
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
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-9-elver@google.com>
 <17723ae6-9611-4731-905c-60dab9fb7102@acm.org>
 <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
Content-Language: en-US
From: Bart Van Assche <bart.vanassche@gmail.com>
In-Reply-To: <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bart.vanassche@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eNwrnAUt;       spf=pass
 (google.com: domain of bart.vanassche@gmail.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
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

On 12/19/25 2:02 PM, Marco Elver wrote:
> On Fri, 19 Dec 2025 at 21:26, Bart Van Assche <bvanassche@acm.org> wrote:
>> On 12/19/25 7:39 AM, Marco Elver wrote:
>>> - extern void do_raw_read_lock(rwlock_t *lock) __acquires(lock);
>>> + extern void do_raw_read_lock(rwlock_t *lock) __acquires_shared(lock);
>>
>> Given the "one change per patch" rule, shouldn't the annotation fixes
>> for rwlock operations be moved into a separate patch?
>>
>>> -typedef struct {
>>> +context_lock_struct(rwlock) {
>>>        arch_rwlock_t raw_lock;
>>>    #ifdef CONFIG_DEBUG_SPINLOCK
>>>        unsigned int magic, owner_cpu;
>>> @@ -31,7 +31,8 @@ typedef struct {
>>>    #ifdef CONFIG_DEBUG_LOCK_ALLOC
>>>        struct lockdep_map dep_map;
>>>    #endif
>>> -} rwlock_t;
>>> +};
>>> +typedef struct rwlock rwlock_t;
>>
>> This change introduces a new globally visible "struct rwlock". Although
>> I haven't found any existing "struct rwlock" definitions, maybe it's a
>> good idea to use a more unique name instead.
> 
> This doesn't actually introduce a new globally visible "struct
> rwlock", it's already the case before.
> An inlined struct definition in a typedef is available by its struct
> name, so this is not introducing a new name
> (https://godbolt.org/z/Y1jf66e1M).

Please take another look. The godbolt example follows the pattern
"typedef struct name { ... } name_t;". The "name" part is missing from
the rwlock_t definition. This is why I wrote that the above code
introduces a new global struct name.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0088cc8c-b395-4659-854f-a6cc5df626ed%40gmail.com.
