Return-Path: <kasan-dev+bncBD3JNNMDTMEBBBHUS3FAMGQE2QAM37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0705ECD1D35
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:48:06 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-787cb36b60dsf28982817b3.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:48:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766177284; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mqsi8FijIZNGHtphFnR05M7ZOj/VWphbU/9U4GYdpD2JMmdaX7r76Zl018dPN4SzWC
         EulxrkRQuugkoLc5ifOGTurdc5F3plmJmQy/E0kIWOFn5nZxoXTJWXhzztNBUHddf6N/
         4SSh6CpAgfbOuEpKNgIDJysUvnjgAeJGyJuWEVanTIXK7yiZ+psaikyv44Ohnyc92A+2
         1Jua88P781ZuCXWg2dg36cR7V+JUsGbtxxCdbTlWAuMmSlHvTUbuMu9Z4Qi8jjHtfEvb
         JLZD8T+lMULX/9dkjikxZpz6hIGE16SPCMAwAtClahBYTCN9j2LXilsAIFAQNsTHr8kB
         JxqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=yRubp3CgD8F/kuxUYSOkPDImev3HgLVmvwEbMFD/x/8=;
        fh=eIOch9AG5LFsrma20HU7LoL6l8Hh6t4z33dDMMURHBg=;
        b=CTXrJ8Y1taYLLfi/n1d63TiQG80WuZYjLFVclAnPXpE3py69FiffUKW4XYxZoPR7fe
         eFxgVt7e9rU6gFXd9FbhibTtw5oRDNP8k6TUPgGiYQ6pNCxjT+5Ffnp4AZirGFwlqmiZ
         qNRX3v2Tjg3+LxorpAeD6OzJ116m6Z1uNer4E59BnjisHXhRLIiRIyb2Z2gUsXD1ViHZ
         UjudH8wg+doYSGwaBLV5N7AbAc3bMd0w84g/1seWogMT8bKK5IG+tzKlmyaO1Zt3J/1j
         P0H5Kv33BmqvuJWjIx3CfFWEfwm562J+f1ySTalivaR+ZQAUudzvedz8W/fta2Es7rGj
         C3nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=yvRF6QOZ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766177284; x=1766782084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yRubp3CgD8F/kuxUYSOkPDImev3HgLVmvwEbMFD/x/8=;
        b=l3466FqqAPlKKRO1kRHHr1fYtPWGpuylFV8pb4iyZBGpDDnWuVyU+xbawVG8BYtxlk
         r4FcWO92Skj0jYv3jR+RtYMzAKw6aly/N/UjcwxeG8MUO+zUl0skiZiuEytJaooGVJR3
         nvk5upuLywg28ziCIBXY6U8faxpptuxBSxNi0gN9dlheeIbdbjgZFhLDHellKoXrw3R4
         JDTepI4rSuOqkre7cCyTyldeWF71qELGzekYHePpyfgCEUGWcXDzgF9uX6jMPmfLWa2g
         aVEgH9kXewtk72GdmhX29bGSYh4UZRLym/mFCQ+wTlGCKsxSTB3QiqmZ7aFst3jNBRrC
         1DFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766177284; x=1766782084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yRubp3CgD8F/kuxUYSOkPDImev3HgLVmvwEbMFD/x/8=;
        b=FmpeHM0ABTN5he495AwweCMqfOtN6q8e4Wq1MVVWn4o0G3KU5xeUZkAiMuGIlEIWv/
         B7Jm3TPlngx/zCMbXMochacwvMsSKCMb4yDgxowXpJMCtA9Ix7v2PrQYAQ/cvJRNBVV6
         NAP2q7j0rZQZo2WM13mJsZRo9k6s+P8FuGa1QcM5HpkQ/lFmGEM8760aDfVntbFmkuSU
         VKT+e/NG99q1SohI3XKydiK/QUNpWKLKvkb3wEpHlzJ5hm1KsYmTcTuDr5wZWGRQf0m7
         7XGS0HLjYJVkeFxYU+Zj7RVuKush/6p8NdSEZPQr+yvjRiKQBCdrYaI9BrQ+9V4TEUZz
         PXoA==
X-Forwarded-Encrypted: i=2; AJvYcCUucgA6yNmnJErmpRJN6XAXsPmmgQ5CBbux6HqeqqHzrDKTNdK3XEcSWAE6AkIjwee53ttfew==@lfdr.de
X-Gm-Message-State: AOJu0YxuMYsAjD8aKzi3agJpPJ9j91RIEFpTXkVY2RHFwb+1aTMGAnbV
	W+3RAeWrb/2z9SIk87GDOT/zLGpyoQdY8BCXCNZVWIIcvLvDN/vW4UXV
X-Google-Smtp-Source: AGHT+IGIr/PLI6K6Rb96SWQddMPw4R4oHU0mEx69eu0rXAEvt+bxApdJqM7DiGM3T8lnnrsxdlV77Q==
X-Received: by 2002:a05:690c:6010:b0:78d:6f35:bda3 with SMTP id 00721157ae682-78fb40922camr72441727b3.53.1766177284313;
        Fri, 19 Dec 2025 12:48:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZczGxjEJ06beN/IWODXgZkc576FCkm0LetTpVkxj4zfQ=="
Received: by 2002:a53:b00b:0:b0:63f:ad1e:f1ae with SMTP id 956f58d0204a3-64554b3919fls5786528d50.2.-pod-prod-08-us;
 Fri, 19 Dec 2025 12:48:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVfHfkLl3+XqohpgWZhtbCqtO/weNQYkCIbPnzLWYHvlXp8XwCXK1gh3slwTgupfNrWqQMMGNSUSnk=@googlegroups.com
X-Received: by 2002:a05:690c:7208:b0:78a:722f:a7c9 with SMTP id 00721157ae682-78fb407b297mr72105977b3.47.1766177283333;
        Fri, 19 Dec 2025 12:48:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766177283; cv=none;
        d=google.com; s=arc-20240605;
        b=j/rI6REsA0UBrd5DPxm/38D0Dae0hCXtAOGqltmkuKTnfIiaLFkYJcRMYll6T+dl+2
         LtmKhY24ql2hjyZ86hR/XrgjU3Zy54+HeA/tUCbkGw//Zb8RRIMysr6shtFt0K65kYGN
         yAHEiCsT1fHmWj0iGEBYGpUGHdusDN9jVPFyiGPnoTCYB15PVSxt6uKXmNJGg5j2ojkO
         nFRlZbyoRx+dv27X1+XOdVVGz5T4Cu5nELsTdITmmDGauBzfSEdyRcOhunV3J7l85Ybx
         DkbUzPmf4SGCfgwweT/ngWMg7eD6bbw1tXHgUgteJZXjokHCoZUtzuLftArRTF1GxGLF
         NhvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=RpTDLGmqmvX91HRlulscWF8eEEmxcYbVfxnBODEf7Fc=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=VU4J6PBl3xe2O6u4c/El0dSad8aO2NzX9BZWSAxm3YUpfdW4xj0oxwZ2dBTU+pu/iv
         LjhROUjr07EvSGVC72yJNiE/jgfEXMk2Kq6IxAnRgJ/bfgDpxMtxSlYZq+qLCGN7HbNW
         yKAia2r66hFsEFK8Gl8YAX1inNlcdYAl3AfxE3+fzPCUp4qtoiRpdKID6kZ0FinVFELs
         KttPJuIo0nS/UrEHRGOsCwJ2057Ukgqqzk4mTlaFbJvqOlEH/BAco1Tpuq70T6C6c+5J
         WcBkr6URuWKpKA9R6HaFiMVjYlMciBOtXROHqEPSLbgQNDPXmgxZnV3UEcYyLXXi0Wnk
         8fvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=yvRF6QOZ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78fb452c466si499647b3.4.2025.12.19.12.48.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:48:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY03k3PBFzlqfwx;
	Fri, 19 Dec 2025 20:48:02 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id RwSAk9NGYx7Z; Fri, 19 Dec 2025 20:47:55 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY03N45hpzlvrT5;
	Fri, 19 Dec 2025 20:47:44 +0000 (UTC)
Message-ID: <3b070057-5fda-410e-a047-d9061d56a82f@acm.org>
Date: Fri, 19 Dec 2025 12:47:43 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 13/36] bit_spinlock: Support Clang's context analysis
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
 <20251219154418.3592607-14-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-14-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=yvRF6QOZ;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
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

On 12/19/25 7:40 AM, Marco Elver wrote:
> +/*
> + * For static context analysis, we need a unique token for each possible bit
> + * that can be used as a bit_spinlock. The easiest way to do that is to create a
> + * fake context that we can cast to with the __bitlock(bitnum, addr) macro
> + * below, which will give us unique instances for each (bit, addr) pair that the
> + * static analysis can use.
> + */
> +context_lock_struct(__context_bitlock) { };
> +#define __bitlock(bitnum, addr) (struct __context_bitlock *)(bitnum + (addr))

Will this cause static analyzers to complain about out-of-bounds
accesses for (bitnum + (addr)), which is equivalent to &(addr)[bitnum]?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3b070057-5fda-410e-a047-d9061d56a82f%40acm.org.
