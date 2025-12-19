Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCWHS3FAMGQE4UF272Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D17BCD18EB
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:12:11 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-43102ac1da8sf1567913f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 11:12:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766171531; cv=pass;
        d=google.com; s=arc-20240605;
        b=itTkuv4svgjM8ZB1mlxY+zmJboKE4pq6zmvXwvcwPIUkZE9uqGD+FignKr0F1mju1n
         layz7Ee+uV/S+fO57BLkvBmq6l17heiek/U5dBYdQPLQ1K5QOUa6CFtijIaCC05mVIRf
         AI31Kcjzmuf/0z8+Pzgke1phQso3mESHE1VDPNxE9d7eYqSxFzkXg5WDSqB8aZW+X9X9
         +YFZ+8pmg07HR5FZxs2iOdLmhGsRXCtBCelVodmkfyiHUBceerY51oUs6a9l+IGDsr3j
         87UBL73eY+Cb9tv+R7dTkkRFcuaYZx6o2sOxQB4sphXaEFzeil6tOQ0fkljAiq98TQQi
         Jmyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Hd0hL0pU+8KqzuA0n6OlUa2SxfNOBUQwEvbTOIEqIOg=;
        fh=2qH7UdvtpZOXVCb5M/Ahf5fxZ3jFzt6M/doh4EVoEmI=;
        b=NzUwt+x1ej2j/PRllbHg25qsg5MKB9F+JbpPmMZw1NHrPMFpaAQOMgCowNT86dSmsi
         tv7PTgMRo7071kK5UiDg19Pd5p51Iwz2F6ozIXb0W6vbXNGPwqnFAGrW1ccvJGJJAacV
         87evqjpC5cxnmlvdkDFwNSFCoArWIM91m4vKflbiHknAIIl0RUa/3B7N+WjPV+cwKem2
         MgyeelO5auN6XVNnQAvbGZ+cPc8z+A2EZqASqb2pa/mAr5IXpUf7awbN0QfFODy45oyA
         VpBVuwMczKImWqQAX4ZclnxjSCP0/eofglO3w5c1pRt8U3uJ9s4vcum96G0Jd7ScXPvc
         jbmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U13Vn9sh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766171531; x=1766776331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Hd0hL0pU+8KqzuA0n6OlUa2SxfNOBUQwEvbTOIEqIOg=;
        b=j/iuV4ibz9x3jbDdZKKBFeyMaAdaQjaCk3NROUn/aMYWdViuanx88CoVO/SuTBMjzB
         o0U4nSBDPCfr712UNnQc59/iH1OcucmvH64QaiabyYPK27mm+EbCL/YzKIvGzZRVcEYP
         D5pKoaO/43Oeis9CfKYUzDaRU7dEHpqRYbAS4G1+DN2Dr3JUNImu7HQzlrcZf0vpx9Jj
         hb6VHwa1BpFGpV7imwVnhEiiObvXDNK0muzzu1FNQBp74/Lf8hQWVbWW94CfiKGfvRNv
         xpS2cKR98qO0CG6svsSx/IpWHykkn5iE02Ky5PyfwE72pvNJLM2yNaxyKFcnwwVeQaJE
         4jUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766171531; x=1766776331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Hd0hL0pU+8KqzuA0n6OlUa2SxfNOBUQwEvbTOIEqIOg=;
        b=V/dg8/ZsW6exjKpcx9gFFKa8QYBPYtx2n0WdbwVgFjGlJ7mXd/FxVHYRz5U9y1e0bW
         horzzO/FC2LQnewope0W/EmLLCJ7vWGPO/b5KpDZDvM3Z1KN/e51XsTijNRf6D3OrEOf
         y/NWyInpaSIIX0OTdwJFWSGFNRWpcdF+fhvxon92XFvekttwMejKEoiN8/ihc1gq7beF
         SF2id+AdKCGbwzqhWQn5ZxoG8JHfWGKgpoDPso1DSpeidDj1lRyg3/ohnbQNdlrbd2OV
         crwyuhSnbi9/rUQmUjEXgY0QpNvUSAZtTqcp+dG7r8fJrZYuV+98GS/PZKTfX4WRjcsA
         oxJA==
X-Forwarded-Encrypted: i=2; AJvYcCXsABnE4WmFpbFvAUfnu/haYoT2FcTPRs2ee2CldypN93ON4XU9eJj+Uh5E4SO0VafPF3cNJg==@lfdr.de
X-Gm-Message-State: AOJu0YzSvg2f2v7mONCk+KNkmaWDiAzUK3nPPiKN70SzB0W3qJQMzEc5
	o/pI3/zpyb/4ypzqOWedIgLi4a86Zl5+0NzRNhvJQFMiFEYU2GtfmrH/
X-Google-Smtp-Source: AGHT+IFdMH41IsvWzrEYDBUL1pmJQVK29X887L8oPK1Q2a4VQmbEUDijJalXvqV6sQURZbn6ZBCHMg==
X-Received: by 2002:a05:6000:1a8c:b0:431:1d4:3a71 with SMTP id ffacd0b85a97d-4324e4d35d4mr4576700f8f.27.1766171530968;
        Fri, 19 Dec 2025 11:12:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbYUivq+jEmgyTDRFtxZgMt4rTeX1CUUO3aUdIYS0QIiQ=="
Received: by 2002:a05:6000:144d:b0:425:686d:544f with SMTP id
 ffacd0b85a97d-42fb2c83d26ls4227751f8f.1.-pod-prod-09-eu; Fri, 19 Dec 2025
 11:12:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVxxwlG5ePaGfFQIPsUhNEF3L0i7iJUeH8cw2dDZLl76kB39AFqvUagpwUtyVbpVDqlcJAXH1JKSu0=@googlegroups.com
X-Received: by 2002:a05:6000:1842:b0:430:f1d3:fa2 with SMTP id ffacd0b85a97d-4324e4c713dmr4382180f8f.7.1766171528133;
        Fri, 19 Dec 2025 11:12:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766171528; cv=none;
        d=google.com; s=arc-20240605;
        b=G7IfsCcqc/RJ6cZOsj4dYFB48BohXFYo86utvkTUgaKv9G4UXSbGbF6wKvYKXluxsG
         MQiHUXP3+VBIjbO/sKn1VCmnnFcuTYbe/feJnXdguMZL/ITXwlfw/vQ7+6iKXw+FM+Q8
         t+kISfWoSy58uygGr1/iVWoC5tpeV2LxxO3vaAYCJUme500lFFledx3k0caENdyOO5KN
         NM45oNHUUAsJuPv0eED0Mh2+9VFQfw/6rrolndEsBmGpdQTP+mrUXWLW4X5tv72kcS1A
         psDT3TFmxAaDtG0fNrjgJCDchHGN9VcBhHcRUUwV+EP7hMKxS8VyTW2oCjf4RRNd6q8Q
         GG3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xBMt69sCffmrONEUk9HcTp6E3Zeeun0qAoojziALA+o=;
        fh=3sOpV8e4AxV94xVVhy/VLqmNWiwxsXT0RIqCh55dqDg=;
        b=i5ThIFkGXW6If5oRMoaFN/VRBfGLr9aiOlLytmAzNJSsRddkQGkCm5hh8esMpqKjca
         9WyNrlbLDKF1sgFroKdD8Ywg2HrUMaXLouE825aoUPGXFq1MkDUv+aQZfZI/5F5fI3/5
         OI+AOq0etfPIsWsX7K4lOgumShBQbGkoQLFUQBxQRvpgekyeZ8OLwsWD7VU3zSThs33/
         Vwn3eaCufXVeWs9UJ9hHrETlDh1cB0x0gcDKTvwxRJkttVzJcIrQ9tNgI4F99gDEqmdF
         q55j2A03ML1OEd5Oa/TJPlKn2qAbbRt1zZqQ2SAxZlCad+gJnMYeoZFigt5Kh5OzqOSR
         syRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U13Vn9sh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324ea208c0si52399f8f.3.2025.12.19.11.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 11:12:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id 5b1f17b1804b1-47755de027eso12493405e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 11:12:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXA97coA0Xez6ETlQRgqzANebsjLJ++E5eefGVc1GTd7tf2bv+IzsoxtriGY28wQptriuZLt8uFxTQ=@googlegroups.com
X-Gm-Gg: AY/fxX4f7rxW7YZDE8gQEt49m2p6pEjvQOqez5IJkb1PTiJ4kZZ5Kuh902nF5ll2xGH
	aK2Wh8R1jdPDzYCGLTiun3dLc5QpGbKbjmnnqiEsmuhsmJ5M57dPXM0EGzAn3WgVcrNQaWxesKR
	5+E2lxAfZDTViRruJ+p4l08XQAsv8283U7kgPzFt4W2JDsRZca8nFrvJRXH5jNb2V8XvOn6XlHA
	ID7fUZRJOqs4s5IMJcdRSuycPDUyHWzJU4wfbRx97k4V8Y70boXH0PaWL4lAle7eTHVuMonKRwq
	RIcqw2u9ut+5XeosWD1QgXa4EUuSpETzZgBxjraq3IXNfuD9c2WTfict3JHbcdVnT4Mq+TbVafd
	hnoLQcGAigVEnrGcm8BSz/TcbY9sqgLYItVX0UXIOyHyGiSonALqisrBNse3arM/4PmsWeumQnS
	2jZTA3iqB7IOcN484bReJyVNqS3flSNf3FtiNlEUlww8lm5JmzeZ6mokhgEgY=
X-Received: by 2002:a05:600c:3506:b0:477:a246:8398 with SMTP id 5b1f17b1804b1-47d1953b774mr34567195e9.2.1766171527309;
        Fri, 19 Dec 2025 11:12:07 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:f7c5:1bb4:fb06:fd5e])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-4324eaa2bdfsm6628486f8f.32.2025.12.19.11.12.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 11:12:06 -0800 (PST)
Date: Fri, 19 Dec 2025 20:11:59 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Subject: Re: [PATCH v5 02/36] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
Message-ID: <aUWjfxQ1fIZdxd-C@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-3-elver@google.com>
 <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
 <CANpmjNM=4baTiSWGOiSWLfQV2YqMt6qkdV__uj+QtD4zAY8Weg@mail.gmail.com>
 <2f0c27eb-eca5-4a7f-8035-71c6b0c84e30@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2f0c27eb-eca5-4a7f-8035-71c6b0c84e30@acm.org>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=U13Vn9sh;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
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

On Fri, Dec 19, 2025 at 11:04AM -0800, 'Bart Van Assche' via kasan-dev wrote:
> On 12/19/25 10:59 AM, Marco Elver wrote:
> > On Fri, 19 Dec 2025 at 19:39, 'Bart Van Assche' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > > I'm concerned that the context_lock_struct() macro will make code harder
> > > to read. Anyone who encounters the context_lock_struct() macro will have
> > > to look up its definition to learn what it does. I propose to split this
> > > macro into two macros:
> > > * One macro that expands into "__ctx_lock_type(name)".
> > > * A second macro that expands into the rest of the above macro.
> > > 
> > > In other words, instead of having to write
> > > context_lock_struct(struct_name, { ... }); developers will have to write
> > > 
> > > struct context_lock_type struct_name {
> > >       ...;
> > > };
> > > context_struct_helper_functions(struct_name);
> > 
> > This doesn't necessarily help with not having to look up its
> > definition to learn what it does.
> > 
> > If this is the common pattern, it will blindly be repeated, and this
> > adds 1 more line and makes this a bit more verbose. Maybe the helper
> > functions aren't always needed, but I also think that context lock
> > types should remain relatively few.  For all synchronization
> > primitives that were enabled in this series, the helpers are required.
> > 
> > The current usage is simply:
> > 
> > context_lock_struct(name) {
> >     ... struct goes here ...
> > };  // note no awkward ) brace
> > 
> > I don't know which way the current kernel style is leaning towards,
> > but if we take <linux/cleanup.h> as an example, a simple programming
> > model / API is actually preferred.
> Many kernel developers are used to look up the definition of a data
> structure either by using ctags, etags or a similar tool or by using
> grep and a pattern like "${struct_name} {\$". Breaking the tools kernel
> developer use today to look up data structure definitions might cause
> considerable frustration and hence shouldn't be done lightly.

Fair point. In fact, it's as simple as e.g. (just tested with mutex) as
this:

diff --git a/include/linux/mutex_types.h b/include/linux/mutex_types.h
index 80975935ec48..63ab9e65bb48 100644
--- a/include/linux/mutex_types.h
+++ b/include/linux/mutex_types.h
@@ -38,7 +38,8 @@
  * - detects multi-task circular deadlocks and prints out all affected
  *   locks and tasks (and only those tasks)
  */
-context_lock_struct(mutex) {
+context_lock_struct(mutex);
+struct mutex {
 	atomic_long_t		owner;
 	raw_spinlock_t		wait_lock;
 #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
@@ -59,7 +60,8 @@ context_lock_struct(mutex) {
  */
 #include <linux/rtmutex.h>
 
-context_lock_struct(mutex) {
+context_lock_struct(mutex);
+struct mutex {
 	struct rt_mutex_base	rtmutex;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;

So the existing macro does support both use-cases as-is. I suppose we
could force the above use pattern.

The reason it works, is because it forward-declares the struct anyway to
define the helper functions.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUWjfxQ1fIZdxd-C%40elver.google.com.
