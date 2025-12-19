Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAEQS7FAMGQEYPIZBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C126CD209F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:47:46 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4ed6ff3de05sf58992691cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:47:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766180865; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q0ubLEzzdWaQjlR6Ax3Q2HgMXKO7RAujBMtfmoGWJxlWrKiZQMQSqSGuc02Z2ecyh9
         4mjWlJYXfbeS/VcExeS5kTAyEmQ3RLOcEhc3AqNwMj66Nf8xtaYDrQs1dNdXCGemmTxk
         j1bLze6IWbWh1QO/BQtkLi2IjjrgLSKl9usCsxGoMwtEGMPjsv+ur9r42HUXSbo3WEsY
         rbCUu+GxIyQPOfKU/Zfwdl/VlUXcEBgDkdGl2gABMYhimqYEZdXfpnhFDYcvb5tfnk42
         ppj7MHdG8ivowpPgRsckUDR11dKhKrFGKhgcbz5MTNwlDnP+sv1jF5n1XOs7h+lgoDE2
         299w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=grotOITF/6N9j2O4AxfNAeTPNrrRnbLP+vy7aTazTsY=;
        fh=DI0+ZMwlWw3pAuzD3XpE/OzFGfB9QdQvmQSaaLYfgh8=;
        b=F2BLVYoQKXK5vudV4k3a1yxl1isal9iL4MhA0D7dCjM89me3014ERCAeHe3PV5+u9j
         TcJ/zuy5lG07MU0JLZoLulWizgL4HUk4cH+93oBQBDJWnWdBbQTiV8yiPr78IcpJwdE+
         +nV4Gbdbl175KT8NLMARsViHUe1MZzXhAa3VXWVPz1HOjxeOYTquJK5QzG4m2n6kDE13
         t19Pu0Bg+HW/AGqmxcEjlomKxPDKm0qeRFTjc0kmFN7V1Wy4kq2pn2KBBj4h2TZmLzLJ
         fupkZa3y9ND942Lfwcs6FJ1KJu8EVCeZW//wjfPz+z0raXhWUPVDxL7s+Fec/iDyQcKh
         /h8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1G72GmXk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766180865; x=1766785665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=grotOITF/6N9j2O4AxfNAeTPNrrRnbLP+vy7aTazTsY=;
        b=QNSG7ZeXKggd1YN8Inr400UKn7O6cyg9pmB5pYQBEFtqn43LTSz2WSskY5VrGyedgs
         TMrOUZ3thbj4HWfH0X8XQqDDMDjifdwJ6WG2w45rv1rpJnC63q+HYSWFGmzrjJIUo+Lz
         5kZrx6lk9gZnjwKmH+LKkt7qJqj6EAGEXN8Ae/CRQQrmEYyi23E+Lcaw4Jbusct4vfxW
         oRDAPUQtbUobaIppOQYoKcdFs2ThDkQa7FXM1m0RvXQ+PFLOZ/S2xAfidLRKFb0zqGPC
         q7B+jh+I3AFEAjzihia/yOkmBTSH49vhGGue0JWnSu0HKMTdVw8DUSrMfaRfI8MXKbdz
         7egw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766180865; x=1766785665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=grotOITF/6N9j2O4AxfNAeTPNrrRnbLP+vy7aTazTsY=;
        b=qO+kfUCwrlvWHNyBf/D2pMrwxHQs/ITbpyv5FXNqEA+19Dl3y9jB+jL0xKCpO1GtYz
         uwNk2T5HlLqm3p0Gmm1bZguJFYpP+Vlk/LXc6FvTUNlzXUGOIFV6D5lyLP+pMoW9iQs7
         +05CaY5cr6ieiLFomiz4lJ2fqQEWrFS19f8EjzycUMke4PhZpvuwUXx3rkOv7eNvecjd
         OPaOS6dtuvs+oPCfhYEOmAZrY+agRUBqqD8Qj3THinbaFouzcxETx/AA0eMOlTE/6S/+
         qynzOnKlrZuAa3BjhK2cWk1c1edg9BDVj0KLG3G5/N9AaOO7PjExGEOCaPlbN8wRWDLt
         daPw==
X-Forwarded-Encrypted: i=2; AJvYcCXUeMoGVJIxRC+K/9oyKZi5Pncdn4Eev27hAZP2bJp6mIBkRXUlVX5FZB5E1gKF4bMNZHG3fg==@lfdr.de
X-Gm-Message-State: AOJu0YwbtzQinsHFTx2xm8wkAsFwVjaGAM/0EP49XvCkrEgH66XiF4KQ
	2Iyz0tX90XHekpVn8Ynq5eb/csTRB9TY6sxXxO9ZKpXLPvbAr4eYoYgV
X-Google-Smtp-Source: AGHT+IF+XZZQR7iemK+vntC2Oe3k8AVjsqPsoR7bz86z1vL9nhetx52nEfy0RN5en7h6srGmkd58xQ==
X-Received: by 2002:ac8:5751:0:b0:4ee:155d:b560 with SMTP id d75a77b69052e-4f4abccf941mr61388151cf.8.1766180865126;
        Fri, 19 Dec 2025 13:47:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZnQOnA2VuIDyVpYmea1LqaQ0JLhFdPFQAuYcs2Cqa1GQ=="
Received: by 2002:a05:622a:4d3:b0:4ec:f039:2eda with SMTP id
 d75a77b69052e-4f1ced614a3ls140261301cf.2.-pod-prod-09-us; Fri, 19 Dec 2025
 13:47:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/qF+N81kNNrgG13Sw5ha9yBGcjjWU7wcOgCx//sZdgb4D0BYcwaKa+eg1V4KwkR7RGnNNOSBmqU0=@googlegroups.com
X-Received: by 2002:a05:620a:460a:b0:8b2:e3d1:f7e0 with SMTP id af79cd13be357-8c08f65e369mr655197785a.0.1766180864363;
        Fri, 19 Dec 2025 13:47:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766180864; cv=none;
        d=google.com; s=arc-20240605;
        b=VaIKvMfZqd2XIxUOTZ3C1wohK2WYcMdggQ7+wfQ5msmzTdX9ndITvdks1vnBx//XD6
         eXY8CEJ+EffkSv6IjWXVdgopmnzdviv8sxprR6XilzAUQEX7SyapXuctAqpUuaLuwiJf
         SHNGCspTbH4VbOJOoSOpBqQFgimyc9GUNmjQh2jf4m6Ee3xstm25B91/rlcPs7/4kZOH
         OpRK6RryvM3EjuSqMVjsvolDdUrKRXoHLP0N28dDRLGIf53C6D6DZWTlbeuNWb1delpN
         IuffBsEgkdUuuCd+/d057erVVV0XRR4yqigao+qkkbSF951UMgxJPVsmlEc5b4FrVjaa
         PWaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ms51wSRYcNMLU08U6XlitTxavoeEVdn7PylZ66BFoeI=;
        fh=jPnyTd6Qp07IjKHgL6z3AhUXhG2AITWOrZq308ZT8fw=;
        b=D4KZY81vJy+zb/5UM7oT8WQ6zStOXcJQXYIS40m/z/gwbn4Y6BwF5IgDp/i9u2NKTz
         juNoY9PnqjXQ90FK9sPrHlPNci+HGU96AxVKrrG9U4v0z7N73u878VNx1/wFDPuAwF/F
         Bfmx51jEBgGgUzohH3+po1TEWRfntpQYeujtAMo36FXxwIJZj3i5krTeSjH0Gyb4n9F6
         T1c01yMAgRpsbpMTRAJU8NstdcW8wEU9K0s9PWURPmdOVuKPe+SdP7NVKc38FzTNkYaH
         7uEI91DSGMzqrrSwHFNs7vX2lrwluOAMOFCK94YTY9enTbeV92+/OM4ymSUST68m/UjE
         KcHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1G72GmXk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c096ef019fsi19484485a.6.2025.12.19.13.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:47:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-bc09b3d3b06so1389877a12.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:47:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXJLwFtUabr1bN22d29v+B9zzq0UxLHW8rsmdUXLhySqX6ulYlxjHyZjrEaQNJww07zziJtzVOPYcA=@googlegroups.com
X-Gm-Gg: AY/fxX4oSrSFlZ7MwOL6f4RZNUtnMcRfF7s55GcVKkhtKWCsTxG4IdHQih7q41WRnza
	SYgYAVEfnR5earEKxHG64FdG9Kn/zObCjDfkAR4Yn98ILc9/wWMkad6dEgkMDptrEbJXEVatYB3
	/N/iCIcLg7dxrrZPFQq5GyKiIwmNIH4cAUXHpRZBdDZ2+fCPObNdZx+mA9ujMVBOuIloEn9DnhJ
	jTkF3sGAwKbCYTQOUDHC8HhqWhT4BlYVDnpY0GUUv5m4Zizj1HHMmogwAIpsUvjagJFnjWG2kzC
	1e2Lv1+6oPdh2oarJn8NrTrmT8I=
X-Received: by 2002:a05:7022:5f0b:b0:11b:9d52:9102 with SMTP id
 a92af1059eb24-121721aaff1mr2914480c88.6.1766180863274; Fri, 19 Dec 2025
 13:47:43 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-8-elver@google.com>
 <cdde6c60-7f6f-4715-a249-5aab39438b57@acm.org> <CANpmjNPJXVtZgT96PP--eNAkHNOvw1MrYzWt5f2aA0LUeK8iGA@mail.gmail.com>
 <ecb35204-ea13-488b-8d60-e21d4812902a@gmail.com>
In-Reply-To: <ecb35204-ea13-488b-8d60-e21d4812902a@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 22:47:06 +0100
X-Gm-Features: AQt7F2oOvMMB1QIst16kG-Ehhh_fmZRMYn3rIRXwuCNiu1TQ-QKGkuW-c2bqFwM
Message-ID: <CANpmjNPp6Gkz3rdaD0V7EkPrm60sA5tPpw+m8Xg3u8MTXuc2mg@mail.gmail.com>
Subject: Re: [PATCH v5 07/36] lockdep: Annotate lockdep assertions for context analysis
To: Bart Van Assche <bart.vanassche@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1G72GmXk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::531 as
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

On Fri, 19 Dec 2025 at 22:28, Bart Van Assche <bart.vanassche@gmail.com> wrote:
>
> On 12/19/25 2:16 PM, Marco Elver wrote:
> > It's basically an escape hatch to defer to dynamic analysis where the
> > limits of the static analysis are reached.
>
> That's not how lockdep_assert_held() is used in the kernel.

Because there had not been any static analysis like this, and dynamic
analysis is the only reasonable option.

> This macro
> is more often than not used to document assumptions that can be verified
> at compile time.

In that case the lockdep_assert can be dropped.

> This patch seems like a step in the wrong direction to me because it
> *suppresses* compile time analysis compile-time analysis is useful. I
> think that this patch either should be dropped or that the __assume()
> annotations should be changed into __must_hold() annotations.

If we drop this patch, e.g. the "sched: Enable context analysis for
core.c and fair.c" will no longer compile.

It's a trade-off: more false positives vs. more complete analysis. For
an analysis to be useful, these trade-offs make or break the analysis
depending on the system they are applied to.

In the kernel, our experience with developer tooling has been that any
efforts to reduce false positives will help a tool succeed at scale.
Later you can claw back some completeness, but focusing on
completeness first will kill the tool if false positives cannot
reasonably be dealt with.

From the user space world we know that "assert lock held" [1] as this
kind of escape hatch is valuable to deal with cases the static
analysis just can't deal with. Sure, here we can make our own rules,
but I'd argue we're in a worse position than most user space code, in
that kernel code is significantly more complex (which is the reason I
spent over half a year banging my head to make Clang's analysis
significantly more capable).

[1] https://github.com/abseil/abseil-cpp/blob/a8960c053bf4adadac097c1101d0028742d8042f/absl/synchronization/mutex.h#L210
(ASSERT_EXCLUSIVE_LOCK() == __assume_ctx_lock())

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPp6Gkz3rdaD0V7EkPrm60sA5tPpw%2Bm8Xg3u8MTXuc2mg%40mail.gmail.com.
