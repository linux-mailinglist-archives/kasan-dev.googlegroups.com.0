Return-Path: <kasan-dev+bncBD3JNNMDTMEBBF6JS3FAMGQEOKCVV7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 38043CD190F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:16:41 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-656b2edce07sf3161608eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 11:16:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766171800; cv=pass;
        d=google.com; s=arc-20240605;
        b=bpAoFvFb7iRVsNdNZ/0FehVtnN9uhooIkO8O1Ivu3a7FXnJ9et8WBaE9qvnieZduBK
         6XMvuIXr/cJUbEw8mFx6TUmbaS7v41YUSh+x6eAzCIavOPj2cb81458qU91lBe+7lMnG
         KctYWCkW9CWdDqkSEqc8VAonWBuJ8LOXFBZubAaO1IeG2pg3JOTVTNMAfvFk7AZ/+ry0
         2L6K4gpI1bp6guwFMOblM2DMPvpPaE/Bzy888XuY5JvzxpjPX9QoTt0saJdaQUnaUbIg
         czRzrZfQVstKT5L4CVPHvjv1aZXPkUR2YYc2WosxjC53XhVXSZCCp0p5ZiE8j6NEwSC5
         EmVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=WXdLHy0gGXn2U4MaKJlsjrjoC1CEBeqbPhiemGKxPYg=;
        fh=r/9Q30hbYWk4ldZlw/QB27I0ZaGvAjgGX/5oVmkp2eU=;
        b=ViW9JieK/b5Gkj4ZZxkTtg4bF7SkFRfuiyJLI34pmIzgShgMrNVa1o6rHWq1dTdEZj
         TuxFCbsAhsABJ+/iZs5rv5yZ2qw5UgjCF1ltmTCAaGgIgzycVHn2i9G/KWQCH9gh8FGC
         TJwsua4xWVqV59cVOaOe5Vsq+O6dtthiblqhyacLnkxOXhMtL19ikFvVyzd4fmufRrTU
         eDEpQo6PUc6Y5FnzmAvOIS1OJEMMrlM0BsJbOlvg5LzfIndOqCyIHIkhuYtLDwKNNCcS
         voaJ3x8nFH2ApWxsJDVA551zj/JcIKMWfNV1RlTjgll6pIh/WAefMRUA+YSZtw3NESxb
         Xukw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=xlPNwaOS;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766171800; x=1766776600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WXdLHy0gGXn2U4MaKJlsjrjoC1CEBeqbPhiemGKxPYg=;
        b=o2CI7mfNvtGdtOF83Zi0a2isQOhMSKlFVd+5jH96ArXo5jfmuOnBvQ77zm0JilPh95
         439ndRVua66Yq1tmmvSLrUxZT17KyoqP5CdGXCelLm5DDKoS/jlxKnApi43Me7Lq+qfN
         V9ITE25Ol2MMp05UL+qlwII8HPi4ZvfFAAAQStPbghITvKCeM6qTtCeNN9zWZ9KQLXdk
         GP9bzlbp0Hg1ylILMp5jJVXhNnhKuQUB+rGRaX8taa6RKVY4nH+4NoasEhc19DkHY3UY
         TcTHAapW+LumziUXWIT8+e9n2KjKR9eQDAjs5/uBaCE9oR40nhhUSmdU9Y9d8rpPHHkp
         FCtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766171800; x=1766776600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WXdLHy0gGXn2U4MaKJlsjrjoC1CEBeqbPhiemGKxPYg=;
        b=OwJZLTZpbKCGVXYcRcfai1R0/X3owZrSAjMaDgJqZdCrSdV6fPk/bPoNQz09NJaZi0
         Mf2VdzNbVcN3XkRQFFd22XRqV1DpHlOg1YX/58s2oIsXCct5o+qfxUW/e2d6YqiTLa+u
         y+NXoAbs/a5yrCRrsFAT17OUB3RkyDfAPiUlrqgkNkdLxJHG1Tam4nTPIkS24iJSaoCx
         5ifmiEokGoQvWWwZMU2PsfQ+k0yzJZ0F0t3hYaskkR0rrHtREIkpRVJ+F1FKo63DBVve
         rD8udV5svznPe9CAnIka/Qg37L1T23WJifMXYw8xUcInJPU9HqPVj+E8cbQj4tvo0FLR
         thFw==
X-Forwarded-Encrypted: i=2; AJvYcCVfTKcqMRQ5RiWCuPNNJxMSVF/Q1BZwgNFwmzUExgT5rSoccjhd/Lz3cA2WgKSd6KVn3Ch9rg==@lfdr.de
X-Gm-Message-State: AOJu0YxzKLpA7TJS+EoEnIrTw562b7x+uDHEriMrldzofOu9dsTns/k5
	Uy0Hp9hWChDexUJ+8TUDNEbsSyWhGGaXjIPml4K6lFEElN8G92Ss+UUO
X-Google-Smtp-Source: AGHT+IGKRHfGZkioApZxOYlI2EvXJkMmwj+tQE4TXecKOmMcHyToRfUHLfysKNvlL92wNaoD83vAlw==
X-Received: by 2002:a05:6820:1691:b0:659:9a49:8efe with SMTP id 006d021491bc7-65d0e94d517mr1723831eaf.15.1766171799948;
        Fri, 19 Dec 2025 11:16:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZd1C8k48jonW1xEnSjnBazXj2ARs11McX52igOWFh5Vg=="
Received: by 2002:a05:6871:81f:b0:3e8:4fc8:2284 with SMTP id
 586e51a60fabf-3f5f83bf1bbls4828215fac.0.-pod-prod-07-us; Fri, 19 Dec 2025
 11:16:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXlDrwixEBdrweMwFmWbaFSB2qftXpeiTG0j0wHoR/ULbXugl6rKGWKYZ1LQIUCcRu2jTQONeRjtu4=@googlegroups.com
X-Received: by 2002:a05:6870:ec8d:b0:3ec:4c71:5817 with SMTP id 586e51a60fabf-3fda585bed3mr1995372fac.30.1766171799041;
        Fri, 19 Dec 2025 11:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766171799; cv=none;
        d=google.com; s=arc-20240605;
        b=VTJj3YcfVC4XN2qWTbsky9PLBUc/EP+vO7IP1rRf0gWZu4Z8J/r2KCUkf4UzJpZ0b+
         xOVX3AAdCE0ArEujdR270gp++taOnrj+qH4Re+6fsuvcyeaIudBUoid1bjaKum8hA/TC
         h3b/rL1/Lj1rK5pKPhoXWEgpu6luZIv0E5w3zA5wWsR3aYHEqqWzcwk3sun+NZzkVII9
         hYKwZzS8olHOHh2E3Gighf9BU6DaMH3Qe7myL//Aao4yNwBSMNECMCIgqp5QZOaW2FHA
         fjtpHNp7uAPIpqja1npFVbVnIVYPud0dC+yGWWgbm8T7vdzd5aT5v2KmChUxB2eG8yZt
         QjFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1d1QBQb0DaVer6VJvBPQjMiptd3tuqlZ2ZCZ+5iT1Wk=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=dd66+Ea53GliYVQEL2LYIfJkI94mxwI7MpqDuRMBd8EhPmonbmrfEY50MKn+LlNgRU
         EDCMVYAK0JXua08IbQhQ3kEzmdyyKXsajadbS8q673V6I2q4hMBcTJrk6wjkrtNMFG8c
         fcEmhqVagVEw/OjTd0o/5RunT6HWaMuOqiVy4OTlIHjE6p02pIuvPjAL7cAvMkzMifef
         lvBxL1gnI6f7m1tKCvHnekbyzGM43ZqkPt2bddcNQjXUnSmkeUI2dGRur5Kb9J3H67HX
         /hHKxuI9POvgzFc3skDA7wXY1VR9MGYJ9LKGwhaHxSkRKaPMRp26ThawEyhL9XLJoG78
         mliA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=xlPNwaOS;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3fdaab591basi161437fac.5.2025.12.19.11.16.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 11:16:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dXy2G3SrRzlwmGs;
	Fri, 19 Dec 2025 19:16:38 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id tXR7wglYQRQC; Fri, 19 Dec 2025 19:16:30 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dXy1p2cmLzlvwXP;
	Fri, 19 Dec 2025 19:16:13 +0000 (UTC)
Message-ID: <9d548e47-82c0-4f81-8a53-faee09d22b15@acm.org>
Date: Fri, 19 Dec 2025 11:16:13 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 06/36] cleanup: Basic compatibility with context
 analysis
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
 <20251219154418.3592607-7-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-7-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=xlPNwaOS;       spf=pass
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
> +#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
> +static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
> +static __always_inline void __class_##_name##_cleanup_ctx(class_##_name##_t **_T) \
> +	__no_context_analysis _unlock { }
Elsewhere in the cleanup.h header arguments with the names "_lock" and
"_unlock" hold executable code that perform "lock" and "unlock"
operations respectively, e.g. mutex_lock() and mutex_unlock(). The
DECLARE_LOCK_GUARD_1_ATTRS() "_lock" and "_unlock" arguments however are
function annotations. Please prevent confusion and use other names for
the _lock and _unlock arguments, e.g. _acquire_attr and _release_attr.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9d548e47-82c0-4f81-8a53-faee09d22b15%40acm.org.
