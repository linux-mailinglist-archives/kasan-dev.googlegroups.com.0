Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVF2QXFAMGQER7ARHHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 772A5CC3288
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 14:23:34 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37fd5c84925sf19863461fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 05:23:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765891414; cv=pass;
        d=google.com; s=arc-20240605;
        b=DK8xO5RCUKlwhFv98wZ2X8ZFeNOYGhjarDsBZp6B+Wu/Bzj15NOwdnRESzql9wGZK8
         ZEBqa7hT/ZunBonkx/vnPM6FH6uWSNb3UezwbVvMqd9Ka32TMPGVyPEkO7TaZ5Wmtwyh
         uNsCTy5SPCY+UCoGGiy+wqDfhgB6FvVpg6bNaQUTC0b97zGegNQEmYLTpo65i7W05PyO
         K2RksPDfZnv/IPRmxFR2LKGVA9IJBo3SEvkCwj1QYE0FacRf9BDjyFR85r2ZonRcHj5l
         dByGzmRU7ZZ/obhrKuv4KrhQVioYAHtUVZ2fPSV5WMSBUEmwo8TYy5K0z8MmvyVtwwqR
         2EVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HL21uY/MG8ESa679lZDaFPDJYk8dXq3sdl4khuyFBVY=;
        fh=rBsRplSKbBCOCot1wWNBtgj+V+ZOhwpGRQwnfn3ozEg=;
        b=BWW9Yk9FIdtwu1MRgTuib4MnLwwRQb/IdCct32ducnZT393subv5bAov/882Z/I7y7
         rzdPwa+SNd4QQlWqvU9FAOtf5qzgzT+J1G+bIUgoxfs9h42+g4/rTgy4jQRVQbBTm+3P
         eQtezcICVcCMErlqB/xg8G/TGVi+ptS2xdLaDhg1iQkVsBGXiYw+4U+vCS1L/htP0XYb
         dTAxpIxinFPdSNqMrInVrJ5gq/9HmWJlGr7vLK0H4tT+tfVTNwhDF8CuzIH/7vqOmuG9
         zlZiuvH0laDNPLxIIwmSjg4yPJW4HMxaViAZ0mYMWHZ6SvFRx+pcyDpTP8IW1YtLYc/J
         tYEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qBjv4D9O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765891413; x=1766496213; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HL21uY/MG8ESa679lZDaFPDJYk8dXq3sdl4khuyFBVY=;
        b=bWISYX6RuuCLbcJgvbe4k5abB+tA2RpZUnR6+M1uNSpuCGdieTZnQYPfOVFvwePukr
         5+gyI7AqJTGhpprEaE9ytOPSnV71FWwjMJ6/LID6yUkITwLOCyzwoWZvv5SahlAAZFzJ
         zf1e5/G/VTwIV4f6v40+IKHtSoXEFXdPcu/joqYfl2PnawZJPE4Jwsa3fc0GPG5mLDg2
         psrREIoZyrxquxKPfrgXpom3PC2KCvH4/wlUYL/BiJtCPZGS0hZr1V9afJlEYvhSmoaT
         cpLy1h0FEp0FNOncyIXT7MIhIrA9zhoKAuR4zRkrJYWVYMD7WybwAUQpvYMmvnhjMUe7
         /Sgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765891413; x=1766496213;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=HL21uY/MG8ESa679lZDaFPDJYk8dXq3sdl4khuyFBVY=;
        b=J4lC2fN+LVOfUdRlZPBbcEqAe31lmxYEdiBhIYx/97KWKeF5FvTy0F54fDlZrgCzI1
         lzucT3yR83h6Adu8jNo0RCb7ZuJKX3e1NB8gUVaX+9a04o06naOETUbIDfGGv/YveRKL
         JJY1NsqT+ujz5Qy99tgUS9qL6Olso4nvM1o/DKoHowPYRDNwoRXhhtZFTQyYRYzbM23R
         6bHiMcbmdveX76kRg7HuqMLXwxYl2nbpntqtnq4zgO5kCLGFuyRLyYAjIT/6J4l7VoHM
         g+V+J0lW7Bons9iTeBfXid08rhbdABMuMBYcGW607esMN0EoEevA9kUdw6jZZI8kWDcc
         1aeA==
X-Forwarded-Encrypted: i=2; AJvYcCVAq2PLo8EZMEqbuKl7Fbc1AbcGYu1d08IBMC7SvKXs8fMfeO6jXFEkAOam7UOHKzZ5juBG6w==@lfdr.de
X-Gm-Message-State: AOJu0YxeKAA0e1ksUtxilRffXo10TLFurCwvOmPlTlqs2UleO+0N4oWR
	vWg1ASWxM+ERZVVHzjclDwwWBlZdsdQ1fkWRXL8eZrU3u6QiecIk9aye
X-Google-Smtp-Source: AGHT+IGldE272OgEpMno5yvLExnD9T8JZNSQ0alCuqsPjz4+YuLfzh1fEgfIxE2KQdGlMa7ZpuPBag==
X-Received: by 2002:a05:651c:2101:b0:37b:a4e2:4407 with SMTP id 38308e7fff4ca-37fd08da78emr38856781fa.43.1765891413177;
        Tue, 16 Dec 2025 05:23:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbi34d3Q5TVQoJir6HnU5JrsZIQBTGD1Fy+e/VcDAdeDA=="
Received: by 2002:a2e:7c0b:0:b0:37a:3088:a94f with SMTP id 38308e7fff4ca-37fceee4903ls5632091fa.0.-pod-prod-07-eu;
 Tue, 16 Dec 2025 05:23:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvqcDhg2s1MlNuu2vegyYqFvyaD05Dlu+u5X16Ru2IzBlGTP5cLcmli0+S2EHe5QWQlLr2jZSEglY=@googlegroups.com
X-Received: by 2002:a2e:bc0b:0:b0:37b:8ae8:f690 with SMTP id 38308e7fff4ca-37fd089a11bmr35340931fa.31.1765891409836;
        Tue, 16 Dec 2025 05:23:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765891409; cv=none;
        d=google.com; s=arc-20240605;
        b=jDC+C9uLUSQL3wkParI/J26PJ55LxdeooURX0F6Ha+FHOeU5GCahls4gV6UriLujQZ
         R6iSTj9nytUMP+PjkR27O2SuK0h2lZuUulahBLzRJkVM4WFuGYYrc6fnvW0qF5OJcrmd
         mGGK4iSegHVNLVPhCfRW3Tw2Ufh5Zd8rKH63vDNIimH86Z/9kskcFmyo1gpvdk8vaqMo
         pWo/payT4SWd7bPnfWYJYtQzcrjNblCV7CblWTmd467eC28cnSWP3x7C6H+mFzKGDrkz
         rf+/2HZfadpq0wgtTCvo51GGuxJdhLMIT5jZyabxUQ5axQAJJb3eEc/D+Sno9bmsNgzh
         jC/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uDxfhRBysj2yPZBzYVVRhpxcjKV0qpQrPWWhDK3SHYM=;
        fh=S1DJ4bQAWn+oVgi9s2jaJQJ1Y5ZJ6T4mimCE1OO1hNk=;
        b=GL3QXbuO1nimVe5dd7mkocheWM7RcF4KTbMHtTSXbKam5TCdpO7NmJRnQeNqerVq32
         KRJFMi5heaoQJ8oU62u87YmDv4OcdH8BFwo94xvOe2Jvud6E1pbYuMsfHvImFxl3l0jY
         gAHF2XrF1kZmOsUClSeSTQUgOinW4kqzNxo0fm82n1Pz32BUKn0xwj52y2fXlr1RRgzb
         l7teBiugnqYMrq/pIdU1by65QBLR4FgmkKx7VqPyrtIttse0W3vg2gPa0JAIXWcApKIG
         9W8NNTwGRGL6ddGqyEjUPLdvx1G1eaBgrs8zftF9FPK1t2ZbAHNS4AnXj3KZA8jxNkPs
         ezdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qBjv4D9O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fdea7c5f3si1827531fa.0.2025.12.16.05.23.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 05:23:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-477bf34f5f5so34810265e9.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 05:23:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV+Pdbdk8pNsw9vjqYCxg1Z8FmsmhxB55JPM1tdtHMio7BwNtthBFyFtIUtMsu5KkeZ/qmnO4CKQtM=@googlegroups.com
X-Gm-Gg: AY/fxX7qjF81Or4M+RNv0dQ+jypJ/kHQlwQDC9VP+GlZROhPl9MRR/ksOq2n4DYMsHx
	ufHjvvjFcTqviBMg/QUodF2cCjK4LSFVyO5eiQKvCar+Hvq8tDG3UYXUL5UzMa6QuZLKMEgdLXN
	nnL535wFTDTwscSzuqG1ETMMezVdk/RwZFjQwc3ZxxW3fnYGqPJq+3G887stAjHZjUocTnFFRKg
	ok5cD6zw92NSTxugFS2AJBv2M/RkprVK4UmV8EQ9P+eYaOm6US+JMhWVSrXC/I86ILh5kEkFo/i
	0B78e3VvrNI/w/8qdALy2hg89JnNChDX/3xqWBxw8RAUpi5E1TgQMASFFRj4e7nbVfrssLkK4nx
	UghqyyqF4HThtso6R/P2C3A5nbcM+E/C+4zArxvnqck+sBaAYJ8R9wGujQ0MpXeVlw2e8idFY8V
	sz9OZEiBTTsX2TCf5Vz4TAwDGSWC+gY7RzWYthIiOJiziWtNnh
X-Received: by 2002:a05:600c:4f90:b0:477:6d96:b3e5 with SMTP id 5b1f17b1804b1-47a8f8ab02bmr133331835e9.7.1765891408469;
        Tue, 16 Dec 2025 05:23:28 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:ea4c:b2a8:24a4:9ce9])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47bd8f86b83sm10764215e9.2.2025.12.16.05.23.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 05:23:27 -0800 (PST)
Date: Tue, 16 Dec 2025 14:23:19 +0100
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
Message-ID: <aUFdRzx1dxRx1Uqa@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <20251216123211.GT3707837@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251216123211.GT3707837@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qBjv4D9O;       spf=pass
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

On Tue, Dec 16, 2025 at 01:32PM +0100, Peter Zijlstra wrote:
> On Mon, Dec 15, 2025 at 02:38:52PM +0100, Marco Elver wrote:
> 
> > Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
> > abstraction. For that one I was able to make it work like I thought we
> > could (below). Some awkwardness is required to make it work in
> > for-loops, which only let you define variables with the same type.
> 
> > 
> > diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> > index b5563dc83aba..5162962b4b26 100644
> > --- a/include/linux/seqlock.h
> > +++ b/include/linux/seqlock.h
> > @@ -1249,6 +1249,7 @@ struct ss_tmp {
> >  };
> >  
> >  static __always_inline void __scoped_seqlock_cleanup(struct ss_tmp *sst)
> > +	__no_context_analysis
> >  {
> >  	if (sst->lock)
> >  		spin_unlock(sst->lock);
> > @@ -1278,6 +1279,7 @@ extern void __scoped_seqlock_bug(void);
> >  
> >  static __always_inline void
> >  __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
> > +	__no_context_analysis
> >  {
> >  	switch (sst->state) {
> >  	case ss_done:
> > @@ -1320,9 +1322,18 @@ __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
> >  	}
> >  }
> >  
> > +/*
> > + * Context analysis helper to release seqlock at the end of the for-scope; the
> > + * alias analysis of the compiler will recognize that the pointer @s is is an
> > + * alias to @_seqlock passed to read_seqbegin(_seqlock) below.
> > + */
> > +static __always_inline void __scoped_seqlock_cleanup_ctx(struct ss_tmp **s)
> > +	__releases_shared(*((seqlock_t **)s)) __no_context_analysis {}
> > +
> >  #define __scoped_seqlock_read(_seqlock, _target, _s)			\
> >  	for (struct ss_tmp _s __cleanup(__scoped_seqlock_cleanup) =	\
> > -	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) };	\
> > +	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) }, \
> > +	     *__UNIQUE_ID(ctx) __cleanup(__scoped_seqlock_cleanup_ctx) = (struct ss_tmp *)_seqlock; \
> >  	     _s.state != ss_done;					\
> >  	     __scoped_seqlock_next(&_s, _seqlock, _target))
> >  
> 
> I am ever so confused.. where is the __acquire_shared(), in read_seqbegin() ?

Ah this is just a diff on top of this v4 series. The read_seqbegin()
already had it:

	static inline unsigned read_seqbegin(const seqlock_t *sl)
		__acquires_shared(sl) __no_context_analysis
	{

> Also, why do we need this second variable with cleanup; can't the
> existing __scoped_seqlock_cleanup() get the __releases_shared()
> attribute?

The existing __scoped_seqlock_cleanup() receives &_s (struct ss_tmp *),
and we can't refer to the _seqlock from __scoped_seqlock_cleanup(). Even
if I create a member seqlock_t* ss_tmp::seqlock and initialize it with
_seqlock, the compiler can't track that the member would be an alias of
_seqlock. The function __scoped_seqlock_next() does receive _seqlock to
effectively release it executes for every loop, so there'd be a "lock
imbalance" in the compiler's eyes.

So having the direct alias (even if we cast it to make it work in the
single-statement multi-definition, the compiler doesn't care) is
required for it to work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUFdRzx1dxRx1Uqa%40elver.google.com.
