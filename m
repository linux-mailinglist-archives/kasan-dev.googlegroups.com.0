Return-Path: <kasan-dev+bncBDHMVDGV54LBBJVMUC7AMGQEJKMRVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E7BBBA4F9AD
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 10:15:20 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-22366bcf24bsf95067555ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 01:15:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741166119; cv=pass;
        d=google.com; s=arc-20240605;
        b=Myk3HU6E9gn3nF1FdoZ5JzZcb3DJcFB2BvELM6D2kUCMoaLq259bjTBT5lQ3PbW8Mm
         j6tIjb9yMWaKEhZLeRywklvkPhkfd8FiuhmWlbfQizc2OtQeNSla7D1Azern12r/Bnys
         6PpdRDbnC8zHbRVebX6gM4eOiExRMxszedfPzKzRIIZWtQ8Qxqri+++w36j1ZNkLsr5s
         LfdRhTcohgS4ZD1zHKIQTA67GPBECuNXMHlk7gcizjpiIa1jwvzn+H21F4IW+FzYctJZ
         2LV6ckjP2dV+dGCWt7UOoFRbk+BCfxlReMGdvQl+tt5eIasueKgabiSTqlkkjODmJI3o
         oflw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=QgmKVESgfMGYZlYIev33bM6Xa2XfiS0xA129Ds6VVcQ=;
        fh=Q2zeQc50Ug5lKofz4Z2BYFnulUqsSdZ15skKFLY7yLQ=;
        b=JWwEi1K03MJvpuPVLeZ+AtyNqAIUVSFGdI/Ed7m0bkwNq2Q+NP6C/0MnxY4w7qtHwZ
         WU1xv+RHoJe4h8OR4RvJoNvwPFFLwJgQMcyZa+lsGhhWtBqZc+8UFa2/K+5/VJvDE23N
         IdXa3bVuQvE0NX72KQAKBcU20YGPwj7ntbuzp80cXEgub2BM/29c+Wi0EKohz5mqKIhX
         dQ2cepuc3fA8Xkhxkg3KrP7zCT3QgoDuV1yz5Pbm+iM9kIi/O9uaxnS0pnX3qJL2xLgm
         V8HFNiwIQ/TZi7J/27jTXKVcVT7Duuu91RizUgQNTDtPNCtuDUzntthK5PhTTqqZRjt7
         uNLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O9QNY17g;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741166119; x=1741770919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QgmKVESgfMGYZlYIev33bM6Xa2XfiS0xA129Ds6VVcQ=;
        b=hmI5ZFiGCLbGAQ2kxkh7zUfA415wn/DfbqZamliDWRBaeTAdb/c0ECaTEUiVd624oX
         j/t1qARbj5N/eYAmjZ9mPYODgXKnsb+fiS+qk58iBKxNs2JkG8XNMB6wREbZva8YKkOW
         HezRgmClV41RVMv4L8LFrPsvrlOCn4gOntlJ0CjkPCh+Tk9F2ni7kz89qQ/NjD+oEkzE
         2pvIjH+FaXQG8L6EA626mWOApvz7Ny347P2NIcuhvUznKuELkJk2rhrCvR5vcvuKkEcD
         CcqDzBKpm4hwertReMNoDwA4PGRNJojC9cw/Y9PNGWTSzsmXxMwowy1GiBqeIv7yATYu
         yJcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741166119; x=1741770919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QgmKVESgfMGYZlYIev33bM6Xa2XfiS0xA129Ds6VVcQ=;
        b=gcxhJKjTl0IAJGK0yKanfOYF9ydade62T1dfPbmhfXXJKtrYVbWKtQQPwhzM4aivuP
         NxB+maB/GYc9Ou0njbwRgcUqsvaD4vCiST5v0MiTJrBjV4j8qKowwW6JTIdHik09vE2u
         Ry2MHm6h4I1BtSqmHT6LzrTF7m0EcHzIfXPkyythD7eMv9PAFk+GenqEPscMP2ygASRW
         LmgBfwmW+/5XGlYPClSLlDoJuSMCEYPwS7Z4wtDUz5Jxyvw6qKLZ66NLxQTzY3XpJeJd
         1sfFsrnWJ6sTfQraLwB3Lm9/c7swnaRYuOmkselEbpcupFNPiO3pR+ZQ33b8VzIWmSdS
         zSvg==
X-Forwarded-Encrypted: i=2; AJvYcCXLSSAiRPxTgHl0DaB01Wg2DpYx4wDu55iVJ+A/JvxFLvBH3iUL/yh2InV2g3HZ1i+33Fg1SQ==@lfdr.de
X-Gm-Message-State: AOJu0YzB3Cnl63jQLzIPhrtdN9rZ++G56/gXw4WZdJ1LZbKg+8w7YWvG
	hCGt5ZRg2iYE2/5Mhus5QnP7ED4RITrQpNR2PVcv/qD08YwoxJxL
X-Google-Smtp-Source: AGHT+IFvWgRgesQpdIXyIg9xhZ3QSoS4lkNnUXrXjx3hWVzlcGU5HsxkJzgksYGNFV+mwEEDJTuQvw==
X-Received: by 2002:a17:903:1987:b0:21f:85d0:828 with SMTP id d9443c01a7336-223f1d6cd19mr37592065ad.41.1741166118841;
        Wed, 05 Mar 2025 01:15:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEtb3QT8+WTA4VdJYQh102MaJbl0H1ZhmKaIf6QhWo8vg==
Received: by 2002:a17:90a:c57:b0:2ff:53d6:8af9 with SMTP id
 98e67ed59e1d1-2ff53d68b49ls165036a91.2.-pod-prod-04-us; Wed, 05 Mar 2025
 01:15:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXmFxq6QdchdGYXg7tTwfIa/7aNY+j5O7w4cYe1GqIbmz8DOpcWBQ5svWhIJ4SeGjpkK4hRJWWpqUI=@googlegroups.com
X-Received: by 2002:a17:90b:5249:b0:2fa:1a23:c01d with SMTP id 98e67ed59e1d1-2ff49753b0fmr3720094a91.21.1741166117618;
        Wed, 05 Mar 2025 01:15:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741166117; cv=none;
        d=google.com; s=arc-20240605;
        b=g954uxLCZV4DDUUyNt3O8jcqo996wlPuzd34axh8Hc0STtZmfh1+HM8oBrTgY+LHwI
         qUb4O2YU/F7nZ7RCXtFgzdnEZd+Q8F4Zwz01l54S2W7LU+Io4Wwfngb3Hdp2dkn+aT/X
         0QjFxcexx7PjlIHPVA9CJDu92BjCnUCr9k2yOEdjQ6DrLzv2KnzJ9La7M624HL3apD5z
         w9+DAx36XAuSlwOffooQ9Ynsv3YckMhJsGNsfCyNbEXpcFSTrd0O/4as2RLSV+scMw6M
         z29Isy03Pw10WP9RtWEhejZWKYSbbElsIKmMKj6BYGa5AOXG7tecndyjdoRLAZtfGarT
         U+PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=qX/Ji/bUzIlh6TPryzyySz+qqHsGsFMehlRcIayr5bI=;
        fh=wEAB6W7cwC/HeBjsnY6848YZNiyJjtxLXkBH8RI3a7I=;
        b=EP/bcHpvSbIMjZzIYiBLeEBjmvJ6mKVFvtIyglfGfxgjhuBm5+C5BwI8txJlCF/l2c
         V/5uq6NQG5c/jXq0QwBCs+v23SobRA1osv8nshnTg9M/hRqkiz58c8KFn6eSy7FRD2KX
         mHOgTa0IZXp/BMuMon8uLalSJDCvLQutzfEI1f69ojmO/t/hQLQONBbiS+5SO4GvZuCz
         eS/sfKSAlZc3LeobAEFvDRAuYdTXz1MUaXd8fhcrDKKhAVSE6Ccp1GMrKMnrD9s2LRJC
         HCSg1EI7IAGN/Y5+L6T0qQarA1x/RyN2cQ6lym4a5WudUhRcF0Zyio+0McKoUKkDHCRk
         9TnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O9QNY17g;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ff35960cf7si458576a91.0.2025.03.05.01.15.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Mar 2025 01:15:17 -0800 (PST)
Received-SPF: pass (google.com: domain of jirislaby@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id CF321A44FD1;
	Wed,  5 Mar 2025 09:09:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 830DDC4CEE2;
	Wed,  5 Mar 2025 09:15:08 +0000 (UTC)
Message-ID: <569186c5-8663-43df-a01c-d543f57ce5ca@kernel.org>
Date: Wed, 5 Mar 2025 10:15:05 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 31/34] drivers/tty: Enable capability analysis for core
 files
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>,
 Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>,
 Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>,
 Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>,
 Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org,
 linux-serial@vger.kernel.org
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-32-elver@google.com>
Content-Language: en-US
From: "'Jiri Slaby' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=jirislaby@kernel.org; keydata=
 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
In-Reply-To: <20250304092417.2873893-32-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: jirislaby@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O9QNY17g;       spf=pass
 (google.com: domain of jirislaby@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=jirislaby@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Jiri Slaby <jirislaby@kernel.org>
Reply-To: Jiri Slaby <jirislaby@kernel.org>
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

On 04. 03. 25, 10:21, Marco Elver wrote:
> Enable capability analysis for drivers/tty/*.
> 
> This demonstrates a larger conversion to use Clang's capability
> analysis. The benefit is additional static checking of locking rules,
> along with better documentation.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> Cc: Jiri Slaby <jirislaby@kernel.org>
...
> --- a/drivers/tty/tty_buffer.c
> +++ b/drivers/tty/tty_buffer.c
> @@ -52,10 +52,8 @@
>    */
>   void tty_buffer_lock_exclusive(struct tty_port *port)
>   {
> -	struct tty_bufhead *buf = &port->buf;
> -
> -	atomic_inc(&buf->priority);
> -	mutex_lock(&buf->lock);
> +	atomic_inc(&port->buf.priority);
> +	mutex_lock(&port->buf.lock);

Here and:

> @@ -73,7 +71,7 @@ void tty_buffer_unlock_exclusive(struct tty_port *port)
>   	bool restart = buf->head->commit != buf->head->read;
>   
>   	atomic_dec(&buf->priority);
> -	mutex_unlock(&buf->lock);
> +	mutex_unlock(&port->buf.lock);

here, this appears excessive. You are changing code to adapt to one kind 
of static analysis. Adding function annotations is mostly fine, but 
changing code is too much. We don't do that. Fix the analyzer instead.

> --- a/drivers/tty/tty_io.c
> +++ b/drivers/tty/tty_io.c
> @@ -167,6 +167,7 @@ static void release_tty(struct tty_struct *tty, int idx);
>    * Locking: none. Must be called after tty is definitely unused
>    */
>   static void free_tty_struct(struct tty_struct *tty)
> +	__capability_unsafe(/* destructor */)
>   {
>   	tty_ldisc_deinit(tty);
>   	put_device(tty->dev);
> @@ -965,7 +966,7 @@ static ssize_t iterate_tty_write(struct tty_ldisc *ld, struct tty_struct *tty,
>   	ssize_t ret, written = 0;
>   
>   	ret = tty_write_lock(tty, file->f_flags & O_NDELAY);
> -	if (ret < 0)
> +	if (ret)

This change is not documented.

> @@ -1154,7 +1155,7 @@ int tty_send_xchar(struct tty_struct *tty, u8 ch)
>   		return 0;
>   	}
>   
> -	if (tty_write_lock(tty, false) < 0)
> +	if (tty_write_lock(tty, false))

And this one. And more times later.

> --- a/drivers/tty/tty_ldisc.c
> +++ b/drivers/tty/tty_ldisc.c
...
> +/*
> + * Note: Capability analysis does not like asymmetric interfaces (above types
> + * for ref and deref are tty_struct and tty_ldisc respectively -- which are
> + * dependent, but the compiler cannot figure that out); in this case, work
> + * around that with this helper which takes an unused @tty argument but tells
> + * the analysis which lock is released.
> + */
> +static inline void __tty_ldisc_deref(struct tty_struct *tty, struct tty_ldisc *ld)
> +	__releases_shared(&tty->ldisc_sem)
> +	__capability_unsafe(/* matches released with tty_ldisc_ref() */)
> +{
> +	tty_ldisc_deref(ld);
> +}

You want to invert the __ prefix for these two. tty_ldisc_deref() should 
be kept as the one to be called by everybody.

thanks,
-- 
js
suse labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/569186c5-8663-43df-a01c-d543f57ce5ca%40kernel.org.
