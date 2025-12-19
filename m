Return-Path: <kasan-dev+bncBD3JNNMDTMEBB2PWS3FAMGQEEIORVFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54201CD1DAD
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:54:03 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2a0a4b748a0sf47772545ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:54:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766177641; cv=pass;
        d=google.com; s=arc-20240605;
        b=OZSNV3iX1DhPe4vjxevYuRP1iBkuoJZe4FQqkAcIOM5jvFYt004NAEfDRX15t8JgOh
         DSeg1oeM/pkxXeSt/ngg27dtRM6djoqD1ZrMhai5R01+aR1iSZD7olXDtAGM4MgqzJC6
         qJ4HcRKEt0SVnuAw7Km/+ITkJuTnebRspetLxFe3AsgSG9Ig/mrKFG9bstUJlcAUSjJe
         7LwcJsTSk1I7Is799o6hOVCykuzTOGy0h43vXZb8ajV0zEeve7VeMU6Z3jAaXitU/tGC
         DVjMuZcZ1i7qYWx7r/SI3d9hddm6+PV8N+3bf1GJbyCpZj7UhzZvj0S/VHn/9QLwxyOY
         A7MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=GTnAGomeLJK/6urQ2GF85Ww9f3xRCF6KQd0RBxbIDoA=;
        fh=oL7OK2QzE1lfuA9iXguLC9jRQ1f0sw3thiqY3/kin/k=;
        b=BS8ArT+bNQe/1oqoUChuoKHrEqv3lTzgGkL5wFCTShyfdEgpMd9M+QCMeKgWJDWL5E
         CVg/zY4Oq7PhBhxmR5P6MA4KJbC1jFOYMf/BFGf96oNHKcC2teQSb4Ob+yqeGDdN0BVX
         5Wl7zjXUTd+8wEoGB5p+qAHVTOJb6qRpFj6jFMBFdUhA8AtNU2w+7XhTQdHCUkIg/lqO
         Op9uSdlL12zPD0M/o/F99pTrh2aR5CnjYE3MC7/ymQxFOMNeMCHuabfLyKWS/g25TjWf
         F20Fo1mfiPsxYrXVBgkMsn6zcuBSQfawQ+JV4UIcS/SXsYw2/8OnbcHRzaqUi3GokiGa
         o4Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=UfehkjIJ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766177641; x=1766782441; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GTnAGomeLJK/6urQ2GF85Ww9f3xRCF6KQd0RBxbIDoA=;
        b=pisa9FVcPyMWaHEh3kcT3u/Srt0R3t9kiEOdP+tib+vd0Y9t1fVpw1CRFUVg0S8pLL
         XeoDBBdqMGXOD4DLuqfNloTmYRMDIez3S8TYgG21fsgwK4lMr2d9Oug9GQ+ctUtymypP
         +BxY8jhYj/yakAQWKBGX56nCyI2VgMRQSTgueQrwnmsi9qHGnqKQ5VmDmo0BbCKJsjt5
         TvMymJFsfRMTHIXsUwWaSrkH1/2OLGS+nfWFuCUdrflF1lY54fvqSsqbRL3Tt4RhoHPD
         2hzN1fpjl0mExtJ2HWuMyOqKf/WzOiJELEJZKGwGCZbfgfCOGVt1Y5R3y0I0y0K7gn+K
         iIGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766177641; x=1766782441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GTnAGomeLJK/6urQ2GF85Ww9f3xRCF6KQd0RBxbIDoA=;
        b=A4ZEmI2LGJq+h0S6VfqJPTWQwhN7dY8P6+1+3nGR9eLMqlqzz2Sf6OGypNxgeqPRc5
         +qWettgkyUvCyuMufYkMQ6ogIkzKLB/02xlLTwMLDBbwR4PeJ1qIf5h9f4BE+W5zN0/D
         SP3pucyNrRUw+neVXC5wrGWUmmOLhrj1/OkSXwdaoQzS9dz/dagQE3UHJy5o99sb1f6b
         CrWNQW2YjgkxnmHH5loDtnQI/gqcMIc7iSYYnh797ZQGE23xFAf+ymcIPHkGpqng83EV
         MKrZpzZ85F+FVlsvXGZNnUirKMGTJ+R5zhwIauJ4gvOi49je5uhFtvBz4ug+oKp3aMv+
         /qFA==
X-Forwarded-Encrypted: i=2; AJvYcCUzN4RUk9YahB+SwugdcCvi0VGUWRCZRgtSUa6u3dWOnijvd6ZLCPBKAzNNZlOxqUFyMQe6zw==@lfdr.de
X-Gm-Message-State: AOJu0YyCzlzUjfkS/L8bllg119lXTjJudkpBRFVxa2bUOYkQWvQqrxUw
	nswdSuNrS/rUXs9h1ioaMA4BJ8NnCpr1LPIGIhbOycrTpC9DJ6kPuEaK
X-Google-Smtp-Source: AGHT+IFZZ4/GOho75y34wCvp8OdPxf89ucT+v15gD4dN7B+oa5GvvGhPwd3Ih8XSrxhkgtNEdn9Haw==
X-Received: by 2002:a17:903:1249:b0:2a1:3cd9:a734 with SMTP id d9443c01a7336-2a2f2a4f99emr37661245ad.43.1766177641442;
        Fri, 19 Dec 2025 12:54:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZKIMbQ8H/0Q2m3Ckk3gdPPBvv/HbKrrcqcim4B1po3OQ=="
Received: by 2002:a17:90a:db81:b0:34a:48fe:dff7 with SMTP id
 98e67ed59e1d1-34abccf6207ls8246907a91.2.-pod-prod-03-us; Fri, 19 Dec 2025
 12:54:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1/AVR5TrAx+zaqmcOxcZYdDbebzF+KY6nkYIEWG84flYornOTTcQhFlMisZWk3ixBOrASulzPoSA=@googlegroups.com
X-Received: by 2002:a05:6a20:3943:b0:366:14ac:e1ec with SMTP id adf61e73a8af0-376aa0e07demr4131203637.62.1766177639772;
        Fri, 19 Dec 2025 12:53:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766177639; cv=none;
        d=google.com; s=arc-20240605;
        b=OtewcGYdsrSjmyCcRM5ShTy93nSo3/XOFA49TYffkkH6G6ZHMbcPIl62wgyUjn9ZXF
         XiY7An2+4SCx0mMGDaa9uOYQNRSg54xMGOvABGJcg0aDjv7WUBc2YCU4tlg5XJFHt3Fn
         kaZfDI1QYoRd7UCdLlvS/v3NGQMF8/3euJ43BcyHsC56A4AjZrRZ8DiWq2H46k+sXEWr
         71K1kz1RP4wD7UF6oKOBHU2ZeRcXOyrZty/R40V+9NB8gbzKE6DsgAwiVnvwIuZK0//k
         GejrBZQp1GQX+p/wLEXPuTun2dQSBufwSSJZDkI3GmlNH2AATqHNTaKd871UysVASZG4
         gYpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=n0Uo17R9WMorX1SnpOAKwu8b4IBQKRGE96JfpenCXBM=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=VDpwaDDCLHgEB+qvDD3owUK59LmwMcONvGCf2DSK+ACxGhQKRgYjKHqpuQx/UgeVv+
         EN0Hsg+ftZMJhAjOR8VXn+gNYTSXTgs/rMK+E336JxvzXhy2i95mjS0YKThnbLtZp5/a
         UTXYmFcDWWKZQr/HqGz8KGkwVsy/vviCvAZI6YfEzMiMePWI4KlFk4J5OsPKXPAAjbab
         +kFtdvgG7jvSEjZRqHRnM0MAaVrgww2fPhiynZrtTrwKMP+Y5zFdwePXo3yFsurU3p6r
         DNDSWJScpFMZUNjYCVwpWdBhuJR7Dp1YQ2xkml0rZOHEmnaugz9byOVudJGJvSQpztPm
         bfsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=UfehkjIJ;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1e7c33ddfesi62836a12.5.2025.12.19.12.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:53:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY0Bb26BgzlgyG0;
	Fri, 19 Dec 2025 20:53:59 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id vHlYWjU2OGjG; Fri, 19 Dec 2025 20:53:51 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY0BC4DBmzlwqQL;
	Fri, 19 Dec 2025 20:53:39 +0000 (UTC)
Message-ID: <cdde6c60-7f6f-4715-a249-5aab39438b57@acm.org>
Date: Fri, 19 Dec 2025 12:53:38 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 07/36] lockdep: Annotate lockdep assertions for context
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
 <20251219154418.3592607-8-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-8-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=UfehkjIJ;       spf=pass
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
> diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> index dd634103b014..621566345406 100644
> --- a/include/linux/lockdep.h
> +++ b/include/linux/lockdep.h
> @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
>   	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
>   
>   #define lockdep_assert_held(l)		\
> -	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> +	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_ctx_lock(l); } while (0)
>   
>   #define lockdep_assert_not_held(l)	\
>   	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
>   
>   #define lockdep_assert_held_write(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 0))
> +	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_ctx_lock(l); } while (0)
>   
>   #define lockdep_assert_held_read(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 1))
> +	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_ctx_lock(l); } while (0)
>   
>   #define lockdep_assert_held_once(l)		\
>   	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> @@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
>   #define lockdep_assert(c)			do { } while (0)
>   #define lockdep_assert_once(c)			do { } while (0)
>   
> -#define lockdep_assert_held(l)			do { (void)(l); } while (0)
> +#define lockdep_assert_held(l)			__assume_ctx_lock(l)
>   #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
> -#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
> -#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
> +#define lockdep_assert_held_write(l)		__assume_ctx_lock(l)
> +#define lockdep_assert_held_read(l)		__assume_shared_ctx_lock(l)
>   #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
>   #define lockdep_assert_none_held_once()	do { } while (0)

I think these macros should use __must_hold() instead of __assume...().
lockdep_assert_held() emits a runtime warning if 'l' is not held. Hence,
I think that code where lockdep_assert_held() is used should not compile
if it cannot be verified at compile time that 'l' is held.

Thanks,

Bart.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cdde6c60-7f6f-4715-a249-5aab39438b57%40acm.org.
