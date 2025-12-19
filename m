Return-Path: <kasan-dev+bncBD3JNNMDTMEBBQ55S3FAMGQE5WA2OIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 23C92CD175B
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 19:51:49 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-45074787a6dsf2497328b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 10:51:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766170308; cv=pass;
        d=google.com; s=arc-20240605;
        b=TM5i2/qvxEZgbKvmJ/aLZIo88kAbuQtxS5Qe/j/2XjgPyyl7YHmVE/MDWqTwCxiNLd
         qh+fVFTgPpbWoIi0loe2nNF7+GiZ/u8JWlOwnOmfwP1s/SaaiQkl8vx58GPHxAC1BApY
         rsFjlhaZIsOQF+RDi8eNRkzQXP2uFZiYX6uw1IBjkRAUjL2BFq+qu/8aiX1XW0r7yNmq
         rf8LHgnzLBKWEsg3FuSTgcziTwMeynE1F5zxqsKImpQvAft8vk7MxrgcpQcA2HoEgP2e
         HIiGHjFh1hdZK7bWH5THaWG5IdZ+PzrrEH/q+yKxwXujijVgcCUhQB6+Fvu/THYx7TkQ
         X2QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=0fYGiyRlr5EB3aoqVkednJ0AQCACUtTAWS7nZPM5RsA=;
        fh=BnIQJWTF7kGJhFo6K/fm/yhIP9hRqGrOkts3jpGQNBw=;
        b=QUCcSylxTx69MSrHbLvcQLeLYT8+DWK1dYEpiuSQs7BU7Hi+2j7Y7dIbia1NW1qf+c
         p3glph9GUETn2Chzd0ULzekiKw/WUIcmU8DH99UWfSLg5mrUjRNwvfnByg4bcKOew6vg
         7vivEy2Rq0XUogGWt6ey4Rh9mm81VPfD1Wj4Y2oc90pd8T9oAfSNIIR02kVIl90VAxuq
         Nt3O2EZ6qao0tay9MJTTiTTmGqY4sgfDsM4TTPY8HOPV6CafCyShiMoc8d0GIPu+8w1L
         QGYhk2PTLK+yg1jJn35Jlq2/hPRyvOmKLGYiMMC4dpBkSXQZ3bX93iFgdqlECAobYTwa
         5g0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=DGiVeMQc;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766170308; x=1766775108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0fYGiyRlr5EB3aoqVkednJ0AQCACUtTAWS7nZPM5RsA=;
        b=lvKPJwMehM00plvUbTFAFy7xt1SE4uWbIoBoUv+RT/9A7iIBtRKTgdHyTXKIJPLKxv
         zIl2ioOLy+a4c/uGFKoY2maJdoMBzjcIvXw9K8Lc5Zy3omSmIGDXB6q1+JPpCBpAwDxO
         1R1FclYvWcSpzSp34+46A/2oAs2MzNcbd9TLxw8wZNHXJ/SaBrbcjR8IEbKz4IV5vUFc
         90G0+JyI8MvDg351GKcjwSpK7yTOnz4eLhxqRGEe5EN9IDzGmQ89gHd3chZkQdC09xH9
         yl+Qs4ISb3Qbc5rC+vH1sXESyp3jgSKyd0ArPWCR7XvSs/KKfUt2yhMREpgcyXwebrZr
         we1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766170308; x=1766775108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0fYGiyRlr5EB3aoqVkednJ0AQCACUtTAWS7nZPM5RsA=;
        b=OBcFrQPjuUk9lruVP8Tn/+3lZBrB4kE4clKHSyPj8cZUajL4ivvX6+dzvvN3gFNtWb
         +XtJvN1b5bw4g9i8P4dEwQdQe/Vu3PHodyiqdI0Kj6Nsj1B/kFljGTLuz/ettp/ZZl4W
         f4VNhhZKeOlOUm8KSlNj/PMqaViltvGPsigkRzqx1EaAvZyZPf5ax/dUtBG73kPHpZrO
         ONiWabfMpal8KC8rx7cVSdZHsd2VcUZf8lcG1fBRwvm/K4EW5Nw4TIQO7c413Qy37Eea
         mlomxY71P1o/ylf2oVkJGiE5OnBHU8o+ufHK6XFytk+vvAzPMjAs/oEZAlxI0OLsC4eT
         yivQ==
X-Forwarded-Encrypted: i=2; AJvYcCXixVajeCVxcQ8Y55h4vdzxoQ9O6i0xiDsS2TkyRiAbbh6iCKATalDSykWTb8OYsnmyfx5nnQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+w/8TMTQdpppelQlf6Hr8FvVSI35RdG7HzV7EADyqu4zxvMxN
	TZeCf26YbMriHZAokmke/q1lrq30LAXxmrEwy6QgovWTD0QqOn608oZX
X-Google-Smtp-Source: AGHT+IGC/VK2QuEcs5zc0SkAzJqFZNT8CGB14duefAQ06G5GkTZ+ZrYAt9ni5TBQ+j0frYbSKbnxKw==
X-Received: by 2002:a05:6820:f029:b0:65c:f4f0:7f56 with SMTP id 006d021491bc7-65d0e9f39c3mr1797661eaf.6.1766170307595;
        Fri, 19 Dec 2025 10:51:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaQ/Oyibz+qRUebjv7DfjA2JT6Efb+uE15FrSMnPE8nkA=="
Received: by 2002:a4a:dc91:0:b0:659:96f3:5ea5 with SMTP id 006d021491bc7-65b439500a3ls4123732eaf.1.-pod-prod-08-us;
 Fri, 19 Dec 2025 10:51:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXHYXNaroi/bVYySQpvCpAeVZj/zi0WawQZAQdBma91QLJi9TJHHqKj+vQ4netXSWOMWn4WqH1soO0=@googlegroups.com
X-Received: by 2002:a05:6830:43aa:b0:7c5:3afb:79db with SMTP id 46e09a7af769-7cc66a5aa53mr1459917a34.35.1766170306521;
        Fri, 19 Dec 2025 10:51:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766170306; cv=none;
        d=google.com; s=arc-20240605;
        b=FmuP3Iie3ffLQTOgAHvTRgbyuOvfWCgewlBzqqa/M/puPJkCevWt3M5vSJEATfBweW
         UQDyLOc4JWEO0y67Vov5AH1mVEBbCdrhJS3WR5RzeNuiKQjbdeEAdMdTQX3PS4r8QNPi
         6BnJOXRIJXvZlFrJI4jJI5O9T1qPbbS3e+uw3C7t7ls0BLuoO4qOqD6mCHabrhIK+Lm3
         +Hi2LmZfzQMGqHqJteBGvVOX0cCvluPOZMpMrpwcWf2zCRV/2QbOdwiD+PVbuRe7wo7V
         aZKmjGbJD2ESLI+QWYWwq28cqPVNgU5U45ktsziJrN2/ETHA7uxiVjU7cyluesSovFIi
         OzSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=PA/EzXjpJ9iY5HMhsPBqLPtFiBx7PkN32m/6FP5Ts4o=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=i1X3vNocaQ7WfQ8U23k2MBYx0F3FWm+fsBfNbQyfYtM4DX18edlVcE1mT/cHACyNHB
         85bE23jNnGYF+y6Uylgi5FvAdb3PictJoIeorOxUcPmj6MBdQGvqYoRP82u0rJVHg+lJ
         kYvFp2SoezpBbRJzei/IhGTmrUZM69D3ltMpCbFRi50fIzcd4Sw6njMbxopgsUMPbh7j
         He1epLkDz1+Xh8jRG3JzVf6ztTtcDfo2RJNaWbX3O+yvCUQIcPX4I7iDQQX3n9lfp7uX
         hImUhYS/ffhvzpQDFeQOBXo9zWZHupgNJX1RTpgKPf3lxHyIHve4cLXwsRSzy/zhSt30
         rcOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=DGiVeMQc;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667ca0a2si309754a34.6.2025.12.19.10.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 10:51:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dXxTY58fYzlvwp3;
	Fri, 19 Dec 2025 18:51:45 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id VtZoOLR-Tx06; Fri, 19 Dec 2025 18:51:37 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dXxTB01wHzlqg85;
	Fri, 19 Dec 2025 18:51:25 +0000 (UTC)
Message-ID: <3abc886c-aa3b-4816-9ea9-b1b2e7888225@acm.org>
Date: Fri, 19 Dec 2025 10:51:23 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 04/36] Documentation: Add documentation for
 Compiler-Based Context Analysis
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
 <20251219154418.3592607-5-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-5-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=DGiVeMQc;       spf=pass
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

On 12/19/25 7:39 AM, Marco Elver wrote:
> +Context Analysis is a language extension, which enables statically checking
                                            ^
My grammar checker tells me that there shouldn't be a comma here.
However, I'm not sure whether the software that I'm using got this
right.

> +that required contexts are active (or inactive) by acquiring and releasing
> +user-definable "context locks". An obvious application is lock-safety checking

Please improve clarity of this text by adding a definition for "context
lock", e.g. the following: "Each context lock has a name. A state is 
associated with each context lock. Supported states are locked, 
unlocked, shared locked and exclusive locked. Functions can be annotated 
to declare what lock state is expected upon entry and what the lock 
state will be upon return. Members of data structures can be annotated
to indicate what context locks should be held upon access."

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3abc886c-aa3b-4816-9ea9-b1b2e7888225%40acm.org.
