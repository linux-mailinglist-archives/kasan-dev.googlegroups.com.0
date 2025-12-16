Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6PXQTFAMGQEJYHWK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F1D9CC20C3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 12:01:15 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-477bf8c1413sf29396485e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 03:01:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765882875; cv=pass;
        d=google.com; s=arc-20240605;
        b=fXb9tzZ4f+jco6TsEVEkAMVTYHbvPm++gOkrww3U9QO7tduvnKS7mNWj0UN1WBdnIm
         VECtB7CQJyYnN7eIk7S7qwC6mG2BFi4By27fii3LGbdfPkgzVz77br0fwNQgAVM8QiXV
         1y/PRnorHWaJ2CcsVFTuMKsYvISZWCn7/rZxiWnwlwYcUo0RTv7ECM+0M2IBgvyHX+Pe
         3ahhxda5aDk3NQ4Fsz+tpIdgcZ6X96aKjvdW8ZNnK0ybG/+r6QAX5LxKy/Mu35N8PeVL
         fDGN+yLzZ3CdIE4dpB61cj2MGeE6lnnhCvx5a6rmJEmC/ddSsSidK27lEw103GGx0536
         RkyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dg8o+aKy7lWhcIOUL5D0UpnoZTZgNNkiXObypz/bAFM=;
        fh=YWr6NIqU315Msc+hPuzaoM5w7Ec6bU4qx5qmpHsuXag=;
        b=c9hb+9JnBeo90zeKWqTfsXTfKAtdYv36zNDQSGqjlB663heIY/px+3xsp1l1xcYvXY
         X+HKGBbsgpd+QEyBpOwP53q3lqxUsMDz/eCOshxse4cBJswXmi9eoLaMlelreXyNghcE
         F7fSn9lrku6gXamjwOBbx7tEdye8dipFHI0ZSNKLKhifoIGpf2eHrgGftVjBPmNli5Uv
         Q+VN/Ro2WzlPW1yKOf6MXqR2wycBlvUJLOfjcEvy+LQ9lVGSxMd0ck9pAw4goH18056v
         5sDBIZFzHzSpOBj7iuO/abKgcR03oa0/7R27uccvCGdvj9Jq+ynTpnGIB8hAKJnUgazd
         gyjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OB64fBh8;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765882875; x=1766487675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dg8o+aKy7lWhcIOUL5D0UpnoZTZgNNkiXObypz/bAFM=;
        b=BLknkpN5w+iUt1M4xag9jIHTdZHu8Vp30VjxVpbfasw4aMwxWBrhpZuXb86mqITD/c
         F66C6rsQNx73EzH6433dd5mu+c3NTqKysclLwWKfhCOswaEL0Gcwon4X+0DL4ouXDrvG
         JhCydmZdbpn02cu8B2GzSQnmSvlNWhsUrdUx6e1AMYiV28u5ZDyVpMWkHChhz4q0onBK
         NbVzXhj45MoVMSqVc6reOWd3M1jrCmabKj0skOozYK27CBe3tzWX+uDmJsXpFdmTgp4d
         lbqEHqQ9IhSn3PAuqBYpmUIH5cjgRQdGv/TYy5L6jSCPWmRBIPO/RE9wWJ4ZDZ+yngm3
         JSzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765882875; x=1766487675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dg8o+aKy7lWhcIOUL5D0UpnoZTZgNNkiXObypz/bAFM=;
        b=nZ7dnEbIaYeC8JiIIZFPgm5fhHUCozIUkThw9iy+o+GGBdrWwzOCjzzFijiLnbdMrj
         fEePb68IybxwyO4ZiXVKdI8EdGuUajZzRb0JxVhSS5FxJ0u9fpvoXwCyEt7jCg2TcK4N
         sunXSpHX5xH8dt/+iNuiQ6/BNdWrINYg5JHSiOKDdn+lHzQxtmO9xh5UZj8g9eArQZe9
         o+Lg4Une6VZKpk0xj4xl/8Wer1QB5K95t8EqOyIzySrbzmmBMIpIyEB1x2ZC/3ToeuXF
         fQoKzzh9f77YuXw48INaQ0W/NReYtbnl4Hhg/f1SlHVw+67sE6LqtA0lMhrT/bV6Gyor
         FKuA==
X-Forwarded-Encrypted: i=2; AJvYcCWgWk+vw1VxXR4qBt+WisxR7v5FmXcAxaeyWyhweKYyb1yyz/AIzk+PDoai9obwC69HO/hjzA==@lfdr.de
X-Gm-Message-State: AOJu0YyfQDf041B41w9BZ0DGZsZcVYIflCDP/mvSuSUHUufq73i5q2mM
	BpXPSiKZaeajzQYGBH0dGNwIyHl6fjv/t8/i+fIa5fud9Q/KtE+r0X2f
X-Google-Smtp-Source: AGHT+IF7POjKQUspyVLyj/THV5AziWVxfvFGZNWWgtcpljSTRYLMpF/js9mzPn1J5NAt5WDvoIb8/w==
X-Received: by 2002:a05:600c:4f90:b0:477:9dc1:b706 with SMTP id 5b1f17b1804b1-47a8f9055bfmr129371935e9.19.1765882874457;
        Tue, 16 Dec 2025 03:01:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ67MXS69aT8pus58y8l5+I/gxTtrnCfLfj+qk6U5cIyA=="
Received: by 2002:a05:600c:4ec6:b0:477:5582:def6 with SMTP id
 5b1f17b1804b1-47a8ec639ecls25715995e9.1.-pod-prod-03-eu; Tue, 16 Dec 2025
 03:01:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhcPjL7CITBmGpEGBIL6KwW2DwARyx0fIXWZ61TQPef3lhdXOmqMN/9gf1qBf1aqgehIeMZ0HRqH8=@googlegroups.com
X-Received: by 2002:a05:600c:a46:b0:477:63b5:6f76 with SMTP id 5b1f17b1804b1-47a8f90cefamr143651525e9.25.1765882871546;
        Tue, 16 Dec 2025 03:01:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765882871; cv=none;
        d=google.com; s=arc-20240605;
        b=B3yU+Sx5DrbzUbb4K+I0VmDGaKxRtZN9v0MKskTg3xtPkkqvremZj2T1WcHNN3ng91
         Dw6s657RpTP+6FZSXEJKNVCocsRpoRqEuPmIwXrl9mFIelovXlpCZyFE0iTr6qP4v5vS
         AMNOe25lGwiJPzhHNlEonVI3kRH4ZE/hpsC1Pb97R9UUR1MG4zQIULyFdhud0ks5kg+R
         anUFMjMREcLEov3+qQhLfDSzZ+8uzawnH13mixqwriWcbA9zovS/KJ2L8kt4L2Rq96o3
         FKmYjB4GdyMH8LL2zd+gGMRSVVgsU3xAq/Egpx/qzunrggSxrBegSy36sQXIm4wbweec
         JaNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3fwbXvgWn6Nd0xRDLnbqnTLufRK/0AjdBlMA+CLIc/0=;
        fh=LmAsu3DlmC5W8FLSEjck9wkzOcQ3PoP9sOCQD55pexY=;
        b=M5yI2+8c7phHfCyR/qK54lc76gdJ7bwPKcguxqtECSuZDGEyRoGXLjqglDIZeOe9sa
         VUYfzJD3hBbCvmQ/ArO7B1nxa+ocVw9ebRA6JbkDxbfe9yMl03IhFmap4FQ9vqQuIfnZ
         H/BEXesxRPdC8iCVM0DdeRHT6cOPvyrXmpTMOkoRMN3FgGGrfpAjgSP69Bm6joH0G/ev
         CFOjoxPtHPw3f1Fm1hMjwKpxmmJWfpPsDQW3nMTPdiD2l9pJaE65tfV5MjrFIMGbht7T
         mHiaZe0FsXGUjJUE/GRChWgonC6wSLu+8L4RKcE7L467KZArGnY21Uu1OcpscUmz9ybA
         BaOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OB64fBh8;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42fbb844cc4si164589f8f.5.2025.12.16.03.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 03:01:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4775e891b5eso19595035e9.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 03:01:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXp4ujpjUH4q13+JTwM7oz4bV0pOlcIDutsbTbX2zFaKnbTQCcKF3F2WsZOQit8t9wsfgbVzDDkrzc=@googlegroups.com
X-Gm-Gg: AY/fxX4Ghqurybj9Vc/MyvO8r8YalvoNupzw5nNL0+zaFTPYdLy6diRuPawkIp/1HYJ
	nr+oZEmewSD+i7kSI1iz4tkJYAeIAVdNALfuRrGP3ohChHjBS/9/Eg347/IirDXyJ9Aits5tIiR
	QTfDlAfoC2QyoinYQW5V8de9CWKreiRGZ0r+7J7NmvOeTsolxMXZHHaFqOE1uAfoK8ixgiqqId9
	8e740BdHLs+8NWwESym3aK8pUhuio7j6Qk+aXxMBb9/qQgQyTi9NkqxQ4FZm/q0HbeHZcdc6M0F
	RN5Ed8bdrKeIx+aCxrGR4QZ6s2asakAWjjACxRg2+ycY7RCWMuRKCi0xBxpCdPBin0EFLe+hE2Y
	PwrxWd8E2yhoqd1YvKJd3KUumr9Y6kihhYSUboboT5LMWnPupdSyFmg6/HvjscqEtiJGvL0KUUe
	FpO4uZOvbng/zfBhoS4xNVCPf8G1jOpWfB6FyPsLklvPrbNNuHR+KauisxJLU=
X-Received: by 2002:a05:600c:3ba7:b0:477:7af8:c88b with SMTP id 5b1f17b1804b1-47bd3d41de0mr37923685e9.11.1765882870450;
        Tue, 16 Dec 2025 03:01:10 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:ea4c:b2a8:24a4:9ce9])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-430f5f6ede8sm17789236f8f.4.2025.12.16.03.01.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 03:01:09 -0800 (PST)
Date: Tue, 16 Dec 2025 12:01:02 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
Message-ID: <aUE77hgJa58waFOy@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OB64fBh8;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Mon, Dec 15, 2025 at 04:53PM +0100, Marco Elver wrote:
[..]
> > > So I think as is, we can start. But I really do want the cleanup thing
> > > sorted, even if just with that __release_on_cleanup mashup or so.
> >
> > Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
> > abstraction. For that one I was able to make it work like I thought we
> > could (below). Some awkwardness is required to make it work in
> > for-loops, which only let you define variables with the same type.
> >
> > For <linux/cleanup.h> it needs some more thought due to extra levels of
> > indirection.
> 
> For cleanup.h, the problem is that to instantiate we use
> "guard(class)(args..)". If it had been designed as "guard(class,
> args...)", i.e. just use __VA_ARGS__ explicitly instead of the
> implicit 'args...', it might have been possible to add a second
> cleanup variable to do the same (with some additional magic to extract
> the first arg if one exists). Unfortunately, the use of the current
> guard()() idiom has become so pervasive that this is a bigger
> refactor. I'm going to leave cleanup.h as-is for now, if we think we
> want to give this a go in the current state.

Alright, this can work, but it's not that ergonomic as I'd hoped (see
below): we can redefine class_<name>_constructor to append another
cleanup variable. With enough documentation, this might be workable.

WDYT?

------ >8 ------


diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 2f998bb42c4c..b47a1ba57e8e 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -518,7 +518,10 @@ static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
 
 #define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
 static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
-static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
+static __always_inline void __class_##_name##_cleanup_ctx(class_##_name##_t **_T) \
+	__no_context_analysis _unlock {}
+#define WITH_LOCK_GUARD_1_ATTRS(_name, _T) class_##_name##_constructor(_T), \
+	*__UNIQUE_ID(cleanup_ctx) __cleanup(__class_##_name##_cleanup_ctx) = (void *)(_T)
 
 #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
 __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 8ed48d40007b..06c3f947ea49 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -255,9 +255,12 @@ DEFINE_LOCK_GUARD_1(mutex, struct mutex, mutex_lock(_T->lock), mutex_unlock(_T->
 DEFINE_LOCK_GUARD_1_COND(mutex, _try, mutex_trylock(_T->lock))
 DEFINE_LOCK_GUARD_1_COND(mutex, _intr, mutex_lock_interruptible(_T->lock), _RET == 0)
 
-DECLARE_LOCK_GUARD_1_ATTRS(mutex, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(mutex_try, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex,	__acquires(_T), __releases(*(struct mutex **)_T))
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_try,	__acquires(_T), __releases(*(struct mutex **)_T))
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr,	__acquires(_T), __releases(*(struct mutex **)_T))
+#define class_mutex_constructor(_T)	WITH_LOCK_GUARD_1_ATTRS(mutex, _T)
+#define class_mutex_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_try, _T)
+#define class_mutex_intr_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_intr, _T)
 
 extern unsigned long mutex_get_owner(struct mutex *lock);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUE77hgJa58waFOy%40elver.google.com.
