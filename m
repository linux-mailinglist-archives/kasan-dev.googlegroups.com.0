Return-Path: <kasan-dev+bncBDBK55H2UQKRB2MKS66QMGQEJY25O4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 824D6A2BE18
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 09:33:47 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4361ac8b25fsf10202585e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 00:33:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738917227; cv=pass;
        d=google.com; s=arc-20240605;
        b=fXvCwFJ0qOpizwBV2ZyAqL5krjuxD8ETR7csHRApmFISEB88g7Qpsu3ra7h2Sced2M
         QiMWXnJsvdROCWqmjb8rFwa/VNcILCsIRdsuIGYf503yPeEvp9JOIKJSnJ3SeRs37kM/
         QMFSLW5t+m344RzjX+WoZIV+jnYs00UVFBvkuxinVEpuvBlUMg1Rd0nvtAzqS9WQu78H
         O/T9Eslq7GBkXEyyrRkcbtyO4MTm+9QU0GKYVeIRiROs2GjB27Bq9XvdGkpgMyLbWDXw
         EnK0psDpBCGHTf7j0eu38xzJB/8mYlGHRfkKRDVU34LYenr7qhxv3PVKOgaSC+y6AU5g
         upzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qx9fSD3/Q9cURPAK567oJqrH0xJS9a3WGap6FmuOqFQ=;
        fh=C8HljuXhBFCROfW9PlRZoUbWlKnrs4RsUZY7UYMhyzU=;
        b=DUW0ClDYEl4Ib0YgOBGckj0IEzgY4lUj73FOsWzpyclAfb6YmiIOH8/JieiLh6gUQ+
         0i63wvPab1g5Dk2E9WncekkdoqK3AWdQ0zSRRzsS7MeQ2M8UHZDxSNSm3CgrRrydyfVX
         y0m9Obl+oZ+p9UmTzmgPv9xYVNirk+E2D4UqJ5IpjZIjsK38sGLo3FqIl3vE4uwCrzKk
         1am97pCXxXIXq2YBc3djP1nIQYSWSjHTCefl5gvPeD4rx8jh3aYC+V+4X1jBM+fKHmwd
         K9YlyAKWDfyINAX/J+lKDsxWhroOPsRwDZHQDVXfAgNPlv7Y0toJE/O5m8EsARgQnOLu
         HUbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=SHcdBsCn;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738917227; x=1739522027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qx9fSD3/Q9cURPAK567oJqrH0xJS9a3WGap6FmuOqFQ=;
        b=kvGcjJSlpaf/XjRtcWTSwF+aNfJWExk5dMrn91R5kusS8NSC9XxLi9bZe409QAGYEf
         1Oz1JUw+5YEfvM+HFSxinwyyPT3XoB+XjeqpLIFV6D75rKV+3I1PG8NKiYVlFua80O/s
         VXske3DEWVZPIYkuALzJ3H5oaBqvdlxWAFpDOD5rofNBHYV2hGwQRf60UggdUqKEkCwn
         oGSILBNFyFz1uMItK7vEMNaXFAPjZcplVC171XlagFceIznx65zGvaI9c/BuZt9hYmEK
         wDVqLCrRwAaJrj7IU3YHUymPsGAKXFOaKyZzioHwDw6dDHUp43yZh8vnx3SKkshW1TV/
         g3Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738917227; x=1739522027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qx9fSD3/Q9cURPAK567oJqrH0xJS9a3WGap6FmuOqFQ=;
        b=plVNXf5HOzHurvqO8hm87LTaIdf+8Nr02ueaYCB4HVbPm8CjeSvmfo/OrdgixhFfgY
         6lm5ayXGPhAtqElf8I8GM+zTJ9JL5lYGYih24MY7/N69GReU8yoS9lWd2TaxC/Ri/VDg
         ImHTfsYmC2gDjjFYzLPIKMrIvp2q8+cOpFeiNJPme2L6ShuYsK8cDqU5X83pKAQBZco2
         1QPwFNptK4TJCiOUpb/KpuWYUskUi8KFGSvrbcECdSlxjOf0zDswlgf+E4/3c2V+0UuL
         pyRYQrNKMMCTf8G6GHddwGDQuF7TYyOsC+I8WYPMmaRCSL8C4VaPwsjXKepEMmFVLpxt
         1ZXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJRLSq6NH6719QCfbCg873yQm5XVdEgCnfOJWCeHnIOUvIJF+VB0EFpKUwRbLjEaRt13zLzw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4kUzZQhqES/iWl9JKAZF9O2Q+dTN8V68wcXWL8GFo+UUPnxxq
	Iamxm4+vjONj21yt3C+OLQQ/VR32EjN1Ea0S0uUATU6aSiRdB06Y
X-Google-Smtp-Source: AGHT+IFDuBrrQmmF5aRm949tGxbPBTUXmpxjMvD2A8pk9VkGwL7qxFAsrdEV0gawa70bIkeX/RHokA==
X-Received: by 2002:a05:600c:4703:b0:431:547e:81d0 with SMTP id 5b1f17b1804b1-43924988c5amr23371615e9.11.1738917225522;
        Fri, 07 Feb 2025 00:33:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3acb:b0:436:5d0c:e9a4 with SMTP id
 5b1f17b1804b1-43924529fc3ls3361625e9.0.-pod-prod-08-eu; Fri, 07 Feb 2025
 00:33:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCHQqMRfphPlHPDTwcQrn9y1eyhVYuEc2BGn+APhMsxpZzTROaArA+mRBRfE8v0eInqUHKmqdBQe4=@googlegroups.com
X-Received: by 2002:a05:600c:524c:b0:434:a59c:43c6 with SMTP id 5b1f17b1804b1-439249c03d0mr15469185e9.26.1738917223099;
        Fri, 07 Feb 2025 00:33:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738917223; cv=none;
        d=google.com; s=arc-20240605;
        b=Y8js60Dr8pcUkDcjSZQeTnb12CbzQpsBWLH5Dfg3j2vd8N0dneCE8g7YLPdirPVbbz
         AMDPgoZeZyqo2yhf0lE15Nv+DJisQJOmGwqXFcLYNPMMxJgexv25/8K1C4tMXxMciIng
         n13JOgADZCMyXo8pFc/lB7NS+J0IBqpUmrHJ6/fQ+MDnG3s81q5fXyspL4ToTpMQ+vry
         WLv4Y266ZriV1m/4v0Mcc1hvBfUiDx7fRyU+5paS0Jum+NCNwIjPsZRCj7afoC2+9q1N
         a2C7v4TDJhTdsA1R7rli+RJeCrvZ75gOJU4eq4vPL1EwnyfrqbPx1CtrwfplMF5V3/Cd
         IGRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BS6iDdO4KJAv6Qvg1+T7FVPsD1MTg6ZHoV7nJRWxmPs=;
        fh=ulhlXQwfNiVlgrmODD3KaXc3WQOhDndHdMyFzwV3nvo=;
        b=ZC8OSgp3PZljfo87LX/1IpxKBfNH1ZClpFibZQpnswW2BwYzzPyRGJcFBhipHJqnzD
         9nScTFqTu2wf22wZv9UV1aVBB5SxxxM+xYmVb3SWUUnlOMDHwQKFn8Q/hcLvdODU2PN2
         1KpE4qbAVSR7p36ESOnEZi3f3+Bgm1UXgrrW+BDQPGDCXjUFI1hjXzeGIE3Aj0OUlZ55
         loi8ya7TmCyCS6X6Sn0k9qkdVXGH8ERR6T7B7PUvX7OghLxyqBeEUBVFpTSzAN8+Q7PY
         zoDeJTJL8t/b1Rj/C+n3Fat9OrSMIunYRmxX1fwOve9WSytjOyuehjmMbn1EerXOeYxk
         lYVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=SHcdBsCn;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4390692b4fcsi3294435e9.0.2025.02.07.00.33.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 00:33:43 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tgJnr-0000000H901-2oF4;
	Fri, 07 Feb 2025 08:33:40 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3A7A2300310; Fri,  7 Feb 2025 09:33:35 +0100 (CET)
Date: Fri, 7 Feb 2025 09:33:35 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 01/24] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
Message-ID: <20250207083335.GW7145@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-2-elver@google.com>
 <552e940f-df40-4776-916e-78decdaafb49@acm.org>
 <CANpmjNP6by9Kp0rf=ihwj_3j6AW+5aSm6L3LZ4NEW7uvBAV02Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP6by9Kp0rf=ihwj_3j6AW+5aSm6L3LZ4NEW7uvBAV02Q@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=SHcdBsCn;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Feb 06, 2025 at 07:48:38PM +0100, Marco Elver wrote:
> On Thu, 6 Feb 2025 at 19:40, Bart Van Assche <bvanassche@acm.org> wrote:
> >
> > On 2/6/25 10:09 AM, Marco Elver wrote:
> > > +/* Sparse context/lock checking support. */
> > > +# define __must_hold(x)              __attribute__((context(x,1,1)))
> > > +# define __acquires(x)               __attribute__((context(x,0,1)))
> > > +# define __cond_acquires(x)  __attribute__((context(x,0,-1)))
> > > +# define __releases(x)               __attribute__((context(x,1,0)))
> > > +# define __acquire(x)                __context__(x,1)
> > > +# define __release(x)                __context__(x,-1)
> > > +# define __cond_lock(x, c)   ((c) ? ({ __acquire(x); 1; }) : 0)
> >
> > If support for Clang thread-safety attributes is added, an important
> > question is what to do with the sparse context attribute. I think that
> > more developers are working on improving and maintaining Clang than
> > sparse. How about reducing the workload of kernel maintainers by
> > only supporting the Clang thread-safety approach and by dropping support
> > for the sparse context attribute?
> 
> My 2c: I think Sparse's context tracking is a subset, and generally
> less complete, favoring false negatives over false positives (also
> does not support guarded_by).
> So in theory they can co-exist.
> In practice, I agree, there will be issues with maintaining both,
> because there will always be some odd corner-case which doesn't quite
> work with one or the other (specifically Sparse is happy to auto-infer
> acquired and released capabilities/contexts of functions and doesn't
> warn you if you still hold a lock when returning from a function).
> 
> I'd be in favor of deprecating Sparse's context tracking support,
> should there be consensus on that.

I don't think I've ever seen a useful sparse locking report, so yeah, no
tears shed on removing it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250207083335.GW7145%40noisy.programming.kicks-ass.net.
