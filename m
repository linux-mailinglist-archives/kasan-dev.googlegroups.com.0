Return-Path: <kasan-dev+bncBDT4VB4UQYHBBFEHS7FAMGQED7H4NVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F4DFCD1F5E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:28:54 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-8b2e41884a0sf538759185a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:28:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766179733; cv=pass;
        d=google.com; s=arc-20240605;
        b=cEymjKxRcG66tYqr2D8oJeLUaPSSogVx8uCPb71Os6+EyuxHcMGwfsxFHoYEuWJnVu
         8vGONI+bhtgUHt92C6xtEp+TFa0k0bngbEpd8iqYoEQ+Y6tTJALnbEUIT1rKp9uNxCdX
         rbnsNiAgkNALjVjp9syJeWY1UC8f4QzMlPDUC+1rCHHRppcz1wnOnZpDeSrppyWPI6Cc
         vRQ02M3IdRsXwEzwpMeEtexLdc7sz+174HRRwW70XkMihQrhh9xxib/GGO0sSS32Mgq3
         q5WsYrOOVtAHE7C5wxDqXtERRgsq60aDmwUeeortoBVmLsuUBBiHCVR95Dhs2aEaagcg
         S+4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=m7kJprSBSkn3NL+nsdTVHMBvXGhwklel6q1U/cA6MGU=;
        fh=Ab4Iy1TGkLBudTieP/WrEEToonaNTHOjedWKnOpoVuw=;
        b=lJP7zCwfBTVRrdeVLuElkgtEMgDnrwAfo+60VJ8V5JSOUGI6tLbxYpOOOBKFm2hnl/
         Pg/PTsrPqnC4T95Wzh8Gyxjydl4OZqfjLY1HMetQ7EtjzVZphgeuPfOqwaVxeNBDOzM9
         q2WzqbuzurrgDV5jMA0piBRNqGntgLlqWbblJrOt9aDLgEvkMUDe1ptZS+snEE/Y5APr
         JexudjhN+ZhWYKa2IpRkm+ICAZoeCkLQGEO+l3xgMvUs+1V/BtY2lPK9ZN5eXTuiaVYD
         IzxyZX+UHuy7Eb9SN86OIFKzJzD7V3DaHRSP7TzCl4TrfM/o3S5y0C4xp8DD0pe8ZuLo
         821g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sh44tnMh;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766179733; x=1766784533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=m7kJprSBSkn3NL+nsdTVHMBvXGhwklel6q1U/cA6MGU=;
        b=H4iB80YoaPsyPoVJWsn5AfzRmTBCd21eVjLMi2DYNO/GoWfu/0q8GgZXKfFONzqT5+
         YSP8joViLev2tEk3vmjxm7lSXbuIONrtBL1LPB8E2bxs7N4Q+dk9qpHV3W+0yZH03UhL
         la7STCW/SfNDsWEGs5RWzvn3iUOdlh/+d1F8Yy+Fv+6HUNwATwgdqaWtXUM4WuTe6qk/
         HKs/SqdlqiFdA6qnRmcc60ZTs1XDWqBkStFo6QWmeS/HOw4jmyoRRBtyyjZw4AJDlFSE
         +P3JdGFLJH0V360K1t9n/JjNDORwFAyBN5FMPSEmWxqQtyx6A1DQ0exzJG/5sm5wcZgC
         MUCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766179733; x=1766784533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m7kJprSBSkn3NL+nsdTVHMBvXGhwklel6q1U/cA6MGU=;
        b=kfzPWEmJ4wghgXbWSEucRDqz4KGut2EXkS5lhA8iGu9fCf0IHIBt4W68q8px+V2yYS
         SxxyqnFFw+Op7imIm2ZJBfKeIHsIhknmm1zT34NIJQP/UXXzQSpRKZGitzzgToQmRNDC
         LhULOKIzWCHYLYFUQ23BHcsZjW0N5rwKhe0rbROqh+TwyoddJb/6AfgBnXq8+AoPz8Js
         5Y9DOKzWPef/PS4DG2d1L7ChHImjrcKfwJS2X9ys3pfS6WazxzaXERkoi8jXBuL/Teky
         FVK+Uq5uOY74ldeP+oBQygN97f482a9XY4L+BxqoBHG6qy4zZNMhT3pIiTB5nBfKzkBN
         eYyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766179733; x=1766784533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=m7kJprSBSkn3NL+nsdTVHMBvXGhwklel6q1U/cA6MGU=;
        b=Gbz3Q2dU+h+hL4kipPgbuOtjHvpq8nTb5F4Rqu3W5uvJk63faMJadOOGx73efsviIj
         c9gWVMl2d7Q4HRV+Nf8uy6Tq21ldCOAXTjZ7Z4NKenoUx55AiWNpTO8brDXMDJJMbwt8
         skh/HIqa09EMq873nNs24tWkpODetsGqsxK5B1GPhSauW+m0Xcp+DLg7lGfOBb262Xa5
         807nKu1zBjWk2mH3V6pnCPfKe1x6ZUHqMEL3FxJf/Sy2m6CAGYpmI7guyMZgHsfYzG+R
         r5vMUyMNhiiGbaCJnn8B2cNrmyZ4WuraqB2bjriBc0l+EnqQddrVbFPiptvJh2elGSxF
         qq4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8vAe4ahDk8H89krvQ3nmJTgsklcpS4V6DirJKYtxyU04fQDL0KHWdZdOvWb6h+NxM/k0NXw==@lfdr.de
X-Gm-Message-State: AOJu0YyDTTiwgCm//YJrajuop/wbAiJIbfyC6XKX5siZFBnnf2MRrgCI
	SAM9bu7eDVa4yvP6w5E38Ll57UyTgDotn4HFi6gdF/G4eOBlhWS8TA2U
X-Google-Smtp-Source: AGHT+IESsocCMcvtHfTYx+L2PzAmzC2aw2DfIJO/Sq1xq0r5Bm0DcZees0WV2hy+YGZ674cRh5xDzg==
X-Received: by 2002:a05:620a:414b:b0:8b2:e598:e311 with SMTP id af79cd13be357-8c08fc0147amr748861985a.50.1766179732995;
        Fri, 19 Dec 2025 13:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZmvt0YQvYka6E/crvoBwKdCiD2pNF7T5EaxZucMwI2WQ=="
Received: by 2002:a05:6214:4006:b0:888:57c0:3d18 with SMTP id
 6a1803df08f44-8887cd70dc4ls141681056d6.1.-pod-prod-04-us; Fri, 19 Dec 2025
 13:28:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWRWp8vUP8+gwxX86LIZKS9Xz8rxRPs/zZ64s5Jnjzfai0A4+0ngowAdbh3el8TRZAQJCAfSDFgFqQ=@googlegroups.com
X-Received: by 2002:a05:6122:8c26:b0:559:60b8:fa81 with SMTP id 71dfb90a1353d-5615bcf18f4mr1672056e0c.4.1766179732200;
        Fri, 19 Dec 2025 13:28:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766179732; cv=none;
        d=google.com; s=arc-20240605;
        b=AMZCx2FHFRAQIOfXP9N8zVdD2itVz61j3jiL55xesXJ6+pPpFDmxr3gZJV71sa7/Oe
         WSRMXWhtvtRkFcG0CIN6xcOSG2wsFn4qF4MUQPA+R4XfLEfkR1z2pTRfLtFwxqx4gRvu
         o9nMDV5pCjVkb3S/5boUtEua5Q1e1y46Qxn/U0/+XF5G2ul+aQumWK+k/E3yj3Ek7aYt
         9OyIDmDN7XBm5sbvACneBqlq90UeD1eiDL2YMeUf5+JjHfEYw+10YTWvsng+Fs6jMdKK
         OrxN0/ohb10HhiI7mosSbskc6FGscSEadpBtqqntmMIKt/YphlkY4MMTqzhmKcJJgnhg
         ewng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9qdyLYhk6D9KpgNEc9lTRHJNMgr66Y5zIziSEMCrXTM=;
        fh=V9Q0x0SrzFAwMslAWwRmtSiH4P1nX2E5ASdZhX+Ic4c=;
        b=Oo7F7i2WodfD66QwSBNl4FSS5GvQzkL1i8IQHrHdH6+wHDyTgQ42QZpYb9BcNOwRSE
         oLl5vs22MiG1Z9UiCcrActWVZ+HW9bMl4kjfA5D2kK/SbdLbLnpjuMdnv+b0jdrneOy2
         nZQP+Hx7Hgu/c3PtoR4LETcPYfZDHaR5NtHYR5HNcYQYbwXo/JEJjHzcVeaXl99VGpiQ
         XrRRnMFRs8sjZIGWsm7/rMMDwoc3PIXIOFrg4Gt+Z3Puvm4UU2mjy1dUDoXLGiTsDTQl
         /EUc99xUuh/PCvtLCTdM8kLIA2eGJ4iFQdNgZyIcLgTkQikauBNHibnDFntAm6gOR8oQ
         Zp1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Sh44tnMh;
       spf=pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d0f9c4esi117695e0c.2.2025.12.19.13.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:28:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bart.vanassche@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id d2e1a72fcca58-7fbbb84f034so1783299b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:28:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVflVW3KWgeCPCRe4l4IgB9FEx2vqtoyZWis52Xk6j1USPYEXTntxb6LkXwr+SsR8p1GHnI+LmLdnM=@googlegroups.com
X-Gm-Gg: AY/fxX4obOY3ypfYvLAclQktbqLu0tw5t4tatZDy9yeYK+YGC0BltzDrfhYBHhB16c8
	IvD8E6ixWD1ffucMELHR2WJG8lFx0yaeQbsG5yeUKeih05ToGb9NesqGZkKVla+o9lLx0C++u9y
	lGXk6U8WtFYUSwv3023/pH4IPpzK9IgSOATHIND+hBbPtInQZiRKZKIGG3AaG3xoe/i8o1cNEdf
	4DDYAo5qZyAi85v1Ll0Yc/ufJFRhxI5ZtJ9Vsgf9Y2l+pTtLvZPWA2439EYwrPAgMh5LSCpz20/
	qmwSaYx3L4EOqWj8POKKpOxYclyYZHgc5xQ9MB359uqla0HqBlUjeMn7df+7hgnv9Sx66B0miZe
	s3Bu3P92EPz6Tt065xIrtHhn+iw8H+fl5MRHFjJYwu+KNybh9hB9bYVi8gyhjQUPZ67COxkXAZ/
	eGX72XC0tWVH2e1BIcvDFVc3//l6tf5EGSEYzJhD28SOZC07ixomDsfiSIO98gElD2KAX1dpzgo
	jUDSimz3edMEStrdxYY1u0My2z0VV5FIs+HuKVpCBitYo3xJApPj+FPQ9WAtx79m/8iHHHZhs/8
	8Ek=
X-Received: by 2002:a05:7022:6988:b0:119:e56b:91ed with SMTP id a92af1059eb24-121722e01c2mr4354548c88.30.1766179731046;
        Fri, 19 Dec 2025 13:28:51 -0800 (PST)
Received: from ?IPV6:2a00:79e0:2e7c:8:5874:79f3:80da:a7a3? ([2a00:79e0:2e7c:8:5874:79f3:80da:a7a3])
        by smtp.gmail.com with ESMTPSA id a92af1059eb24-1217254cd77sm12305503c88.14.2025.12.19.13.28.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:28:50 -0800 (PST)
Message-ID: <ecb35204-ea13-488b-8d60-e21d4812902a@gmail.com>
Date: Fri, 19 Dec 2025 14:28:48 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 07/36] lockdep: Annotate lockdep assertions for context
 analysis
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
 <20251219154418.3592607-8-elver@google.com>
 <cdde6c60-7f6f-4715-a249-5aab39438b57@acm.org>
 <CANpmjNPJXVtZgT96PP--eNAkHNOvw1MrYzWt5f2aA0LUeK8iGA@mail.gmail.com>
Content-Language: en-US
From: Bart Van Assche <bart.vanassche@gmail.com>
In-Reply-To: <CANpmjNPJXVtZgT96PP--eNAkHNOvw1MrYzWt5f2aA0LUeK8iGA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bart.vanassche@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Sh44tnMh;       spf=pass
 (google.com: domain of bart.vanassche@gmail.com designates
 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=bart.vanassche@gmail.com;
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

On 12/19/25 2:16 PM, Marco Elver wrote:
> It's basically an escape hatch to defer to dynamic analysis where the
> limits of the static analysis are reached.

That's not how lockdep_assert_held() is used in the kernel. This macro
is more often than not used to document assumptions that can be verified
at compile time.

This patch seems like a step in the wrong direction to me because it
*suppresses* compile time analysis compile-time analysis is useful. I
think that this patch either should be dropped or that the __assume()
annotations should be changed into __must_hold() annotations.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ecb35204-ea13-488b-8d60-e21d4812902a%40gmail.com.
