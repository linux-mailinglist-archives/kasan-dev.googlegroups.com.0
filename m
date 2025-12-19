Return-Path: <kasan-dev+bncBD3JNNMDTMEBBPHXS3FAMGQEE2X4C7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id A220CCD1DD4
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:55:49 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4ed6ceab125sf52120481cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:55:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766177725; cv=pass;
        d=google.com; s=arc-20240605;
        b=lO6pSjZoJJD0P1CIjMfbXM1fqrcnSdcG7dVJFlYqWXmiux2BpAbPxMJj/spLFhDiaO
         L94f/SarSB8O7ryyjwPaXYbYMMgRfODjjCxbQPMzeFxrnuZ0aBCykQQtwhnFv7o7wQz1
         FEQ/0NhjzwVseU3COpS8ZTxmDx1Vc+CbAt/wIWwYyLIhjFym2ugFHUbVO6SC3DWkmj/F
         cWSco/LKfgfBGL9pjTo7ei/T7x766imvWBHapUOMjFTi5ivUS0R41bvY4NLodhiY66Tj
         PLT8xBaowl0uCgIk12cDIdi23Ebn4v6QNp2l6KUhKDZJj5gIZJvKikatRNq/lBUpwf7R
         UxBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=wI4eATgkEzl7s3FFPeaJ/xB7hP4DGn2wy3XlZOUrCfI=;
        fh=ssELgIbyCy2IaMKof13GHFrcfbG0idcmAJM8+cSW3yc=;
        b=QYrq2zXcfmppVSVp5NTTBlDgj35FHis4fLyWsA7tsKH3PnIMcpR6yYmd1XersCxJQt
         UbysbgPIUx5wuPcSowDvgNTnlFL3elH/r8M+iiLo+Zw4OYzi6RAEyxOJd9iE7HidFquP
         m6xkFM6ViLhbJBzwrbOaztYchxvhRtq5J4jKcG1gwmWQmdNw1P5HI7+R5NLO9OENsxpS
         B9DBG15rkIh5P5uR2yhHTWbce4p5uXqdh8p+AJAkXHWdSePoFst6mFUKKKltEetmHutb
         Vhf1aXrEZouOW8ca/r+QV0DtutWFD5Wz4Z8CqIqgLP473X869Bp6V5Z6fL99ZAZvs1Xu
         X0CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="iY/ltKNs";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766177725; x=1766782525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wI4eATgkEzl7s3FFPeaJ/xB7hP4DGn2wy3XlZOUrCfI=;
        b=pwQeX5Zx0kKsEHDSFmjWoN03GjFM9XzuyylLG80Tf5ACv4nAk9mxNfpk4D6qWRlLXZ
         A6iwhRg2W0zA1l5ym5lTxxwZVtOdF6DTCglehvc1TB2HbRiZ6OIVAdfK4SZl3z8z/HP2
         v5zHwFAiD4gUtpCvsJ/JliX/Q1nATEbGXWvR++UbLfDwnicCTlsRArOaNZRFTb6nI+bB
         7OT5WZo64eJIrpXUYoka7HMok8IAPtkvt9QfGWLrmUIAauZXYNz4Zml9glJidkPVc6re
         SGKfIt7J8TuOR5kzExcu1oQqYG7VlWjnOGVRV62Un7sfP5bSjQwblLmKG3tNi95qhyKg
         Gv5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766177725; x=1766782525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wI4eATgkEzl7s3FFPeaJ/xB7hP4DGn2wy3XlZOUrCfI=;
        b=jCcfdbtT3fM6GjTOxXm4vxcDJI64xvFu+svyLwZnMkN6DmEUNMZOVARlTv/OjXTrCM
         18ic8LVgtp51uf2/9BkXbprTzKRdNsaEWyWZSE0sxwH/nyA5i92ib97D8jJ7EfPzd+H2
         DatoBHChxofjh4ArgVHb4IxvbONZ12hbp2ypXWl2la4nxl/7/nW8uqr07TksaujLdA7X
         97Mge7TobCmrOt+cgbo3U6PoTzAWA1cbSwvx6rHAiki10VKxncRcLc/+ArvAyMPqxE5H
         YRw599Rjf34CYp7ik3UiwsUHYQPsBwGytQxwxTM0hinQ75Jd4J0jNvXTDMCiUklnvetn
         wbBg==
X-Forwarded-Encrypted: i=2; AJvYcCW1s4HLzYto0hv4u8zE5Gm/autxAT1H5WmlNc0RElG35NPPOous1DidOT6rO1DatE1og9IqoQ==@lfdr.de
X-Gm-Message-State: AOJu0YwoCSbFFwANLrMBHT5CNC+LhsJIU+8/v5AbUeXmX5QtTo0ld3+h
	gGnuNBxHO/TyJd1XzUeNkxo6b2VAq+w9lM08IZ5RBLDluOjcNV94pe+a
X-Google-Smtp-Source: AGHT+IG5e4GQQwarejhAQ97tGCg1Z8zVJ1M+pAD/4+ghECH3VNEU0+OmIIsYrtRBymR0Kj4ORkGKZg==
X-Received: by 2002:a05:622a:1f13:b0:4ee:418a:73cd with SMTP id d75a77b69052e-4f4abd118damr61486151cf.36.1766177724903;
        Fri, 19 Dec 2025 12:55:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYFnghgf0Le7ZQ1DVk1nKYkpfbRYiQCiaEIYQGPcgdwbg=="
Received: by 2002:a05:622a:1654:b0:4ee:4220:d0b4 with SMTP id
 d75a77b69052e-4f1ced3ccbbls34119571cf.1.-pod-prod-02-us; Fri, 19 Dec 2025
 12:55:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxFXQnDeqUEjj7FSobfoY+VmLiWXnBcKVHN5BuCGHJvSfTCTJYCqoMybXygibTN3f10ePG2CArcHE=@googlegroups.com
X-Received: by 2002:a05:620a:3196:b0:8b5:9fc7:812b with SMTP id af79cd13be357-8c08f654cbamr684439785a.6.1766177723957;
        Fri, 19 Dec 2025 12:55:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766177723; cv=none;
        d=google.com; s=arc-20240605;
        b=fDox0ftBzFmHbMqMISFZgK5rb6knXqurxO8ggseDjF3DStygmw4bwWVSsqmgUNd18z
         dEGU+wYj2ChvA7bIJgd3viF0qtrLeYEi/f5oFAVkCCPShHFsGUssmx2akXKAgd3nYpO9
         HBWWTdw/fVSNwnbtVwNy/9MeaG4aG86w4KEWCLqNG/VV78VgGtUuyL0UowcxkVmH2amt
         EOGu97Hn744DDlRSxiDFFBxxnpKBN3OrD4D4fi6phKUyxF+MHI7Gkrd3UBNnsKM048fq
         7/LEYTM0BcvKROu1FFR8qWjk+niOnPdYzmJTM4ZZFlePG4Rf3SX7brWE7mfW5kGSxt+x
         5Iuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=XdZxKJLVv/us0MhlURSAieVC/jzQimy4qD0cHcgmVzU=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=TQmqt9hWFbEEUjBvLEFcudlNKw6RAoFvmiG/pCpEYtw4CWXf8voPIlEHgO54DlIgzq
         F536ExuGD1FlTdp8zGUL1428pAhqtRN2pAo3FH4I3xbmwBkiPTu0txfjSDJ4xpIKd3Bf
         OouRlEfJ+qQeJ7BcLWT12VQReCF4+1k0jpHbUy1bDj/kU5mUjQKtEL0f23lFzDc8CQAP
         +AUfnEkn4sY1P1i0NWVrpFm96GWob0+TvkqEwO65A22kfZmehP5BYCdBhIilDtUng+2l
         tdEEEa5bixtsYy0rjobLy7biUcJuRO4TbM2yF3HE8o/jIKjcB+Vo99Iy58Hg6StKwKY0
         nRNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b="iY/ltKNs";
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c096683499si15945985a.2.2025.12.19.12.55.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:55:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY0DC1g6NzlxTSc;
	Fri, 19 Dec 2025 20:55:23 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id qbQZoCDMrrgt; Fri, 19 Dec 2025 20:55:15 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY0Cp5nntzlwmHT;
	Fri, 19 Dec 2025 20:55:02 +0000 (UTC)
Message-ID: <81d2defc-8980-4022-a464-3d285aff199c@acm.org>
Date: Fri, 19 Dec 2025 12:55:01 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 17/36] locking/rwsem: Support Clang's context analysis
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
 <20251219154418.3592607-18-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-18-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b="iY/ltKNs";       spf=pass
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
>   static inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
> +	__assumes_ctx_lock(sem)
>   {
>   	WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
>   }
>   
>   static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
> +	__assumes_ctx_lock(sem)
>   {
>   	WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
>   }
> @@ -119,6 +121,7 @@ do {								\
>   	static struct lock_class_key __key;			\
>   								\
>   	__init_rwsem((sem), #sem, &__key);			\
> +	__assume_ctx_lock(sem);					\
>   } while (0)

Just like as for lockdep.h, I think that the above annotations should be 
changed into __must_hold().

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/81d2defc-8980-4022-a464-3d285aff199c%40acm.org.
