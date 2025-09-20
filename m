Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2WDXLDAMGQEQT4ZLKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B4C6B8C865
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 14:45:32 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b60dd9634dsf60851311cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 05:45:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758372331; cv=pass;
        d=google.com; s=arc-20240605;
        b=fDqSnXHIJrhP0L2zPncFqUwK6m3zw0PY9enai0ahZtJvHB9fVUUaF2pGtgGSIODXXc
         xTKQGdYZl/8ZJi3nkurmzw396fwzJgcki+MMh6vwM3XH6t4G/Lx5GSgRJUHOwGKMAYBf
         +Q2x0L3npdmMD59jEkuglWbYwkREBZitn4YVP2Sh1OxjFxWEXIrUarWr6iAKBhRY7ae4
         ok2whDm1S2P+JBS0wumnLIl5fsGGIqDhU0vBLAbIlRi6ypYQv+2fKXAVK3URlmjFmsub
         KPIrqIjYVGwN9ygEMBO7FiHzoXlCFnIDblzMQa8Dgr0ayLy+USNYlCRUtee40tebj72K
         +pag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+s74SQuN8w3RMJTVqpdgZhdxUEijO0si29zpL5DXGK4=;
        fh=qgjKkP2l0vX823xhegRZpqc6wQs5lSuMA6w+uRB98A4=;
        b=hNfslECVnigAfh6VxtGK9ZRgrElO8d3x7JAy31jZFUf2nh4At8xLAaltvTnZ0njduO
         r24UGzGqFFA+mSdBVQQE7mmiW/7tXeCqQRtUNmsrfxiNSHFzW2joEHRu1QMHTtp3exDH
         aYmnkV9F7vhiUnPRxxbJjUTH9KBff5jFA9fS+7WBlsToMx5FBN7Za1X4XCgVnIyfIYCL
         oycLnTwlAIjGGVaFlwIesvv/bk5A5T6nUWZKFJ1Yl2tDCJfjINIS8GYiO7wvqaLdVgMa
         NkHj9xqLgTe6oCgYPb0ieOyp4pbq9m7E29zWTEt3UbAHxTqm9Qr/sE6E1xzXdXSg6+Z+
         sC+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iSIA8ouC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758372331; x=1758977131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+s74SQuN8w3RMJTVqpdgZhdxUEijO0si29zpL5DXGK4=;
        b=X7yvqETkJrZudE7bPiNYOVOD5On/IwvKG7gyeNaJJlZtQWI75ts5kUIaAZltvPvn6B
         c7RAxyitF0gv4AJkOKovHrq9NWbeTK89Xtq8Wva76aUMwqdAMXGRLTtx1ikzuWSgJQh5
         jcMmqWMFX5QorhOzPaeBly/NXStJcY7J4ZIOS6RjW14sGEXGG8KYHFF+fjuS6fcx4ZOP
         /KoioFg5DArUVdYPzKjgvl4rGuxNWP062J9XtArY8+75xYHfo2Ja8CwxAleGCAwdnmDl
         +7NXmZhSgTZpIXbVjZvSgcp6n52jdSz3dqb2mxIHUH2vQeTZvuFgDkMmBZm9u9Dw/0Vl
         t3Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758372331; x=1758977131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+s74SQuN8w3RMJTVqpdgZhdxUEijO0si29zpL5DXGK4=;
        b=h3hEpuZ/kERS3g/B9fSKJs0BcJSgHL0/B8ihltFQTWESGLt1/WkaKZFh0t3OTNEQFk
         bo9tJw5NFAKQVjkVseR7pbLBrNeacIM5Awejl26xUpd+5+dD9qRdyphGZ6bqNdijn+C0
         wdDs052veXo1+WgB4lA9GXhsZptoREX4SnEQnuflMSXC2T+bl0ATtEWq+ffsceBy1eMT
         9n29kZnca2kcb70+gx7DJ+yIa0GsGjUjvWVTkw1L3dyqtuXNMx4GNSkUluglik9dK8Bg
         UB4174a4HJ9aPBnMyUMI/8L0NXrijtRP6643TQt55KIoQ59KM524SjVngYUo8IPATbGl
         pBAg==
X-Forwarded-Encrypted: i=2; AJvYcCV5H6ZzSRhsYH5xudPIE08AhB9Yjr+SLrd/r9ftcbdP/gkb4jvXYF/iEIQy21QtaAu+/uHCmw==@lfdr.de
X-Gm-Message-State: AOJu0YypogH9osH3Gve1pFd2hAxkhZcEtDLWh85Rdxk/NG13PTuTaFve
	m4JKkBev42DAGbIJ7Gvv6Lh3cIpZ//k21LxZ+FKWY1BVRdYg9YLFbH61
X-Google-Smtp-Source: AGHT+IESE1SvSFG5f7Nt6VG7dnGiTU229kCStSz3uxYCekHnp1I8bv5EwJHNKKn+k4nYjshEwW4fAA==
X-Received: by 2002:a05:622a:4089:b0:4b6:35e7:1746 with SMTP id d75a77b69052e-4c0737cccbemr84938811cf.71.1758372331064;
        Sat, 20 Sep 2025 05:45:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4Wr2smRjRB1AP5XvDWRLEVblbV015vUb7xjc0JNrLnng==
Received: by 2002:a05:622a:1116:b0:4b7:ad20:9381 with SMTP id
 d75a77b69052e-4bdfe510bd7ls46583911cf.0.-pod-prod-01-us; Sat, 20 Sep 2025
 05:45:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXigNa8CXnhwP4//TK8yZdJGJnrI/i4f4aE/AEl6SWkXexrsnQ5kjqO8TeYtQbPIjhTRXw3L5PFZ1Y=@googlegroups.com
X-Received: by 2002:a05:622a:1a27:b0:4b5:8c3:cf6a with SMTP id d75a77b69052e-4c0720acb70mr76386781cf.39.1758372330008;
        Sat, 20 Sep 2025 05:45:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758372329; cv=none;
        d=google.com; s=arc-20240605;
        b=hEWhVwGK5mwD9mIeQbhLHbVaVhgetXvoYKYUa7vAqxgCAg4jtKxJ0+neh5VJs3IUX5
         ZiKZqp4Q8vJ6q+itrG+uPaJsKGlhvcZRqqoqrIJBLfHSkR4s1/fMm5jb5GhGPREaUy6X
         FLI6WMdBcGkp8froGHopfbZeqT+64VUBYEAEabfYwsWuOQwN1xfoPv5vHgtcKhN9XDZu
         AXhApVmo//W5xNeD8uVckV8cNlAddIplIvjdxZRQl0+ZrRiAar1sL+S84qOGgdlY+Y4a
         akpqUy/PQAcqLmPoORl/Y+qrzE2GdLbKuR/6aBoVoE77TmW3scCaYSI2rHDoQERt7wfQ
         Yt9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P2Xt5dxImFQDNB+zIOSzEq8xo9rsZmb+jmetH2dJjzs=;
        fh=V5/HnQzBR6PS+Et7WobzBKQdNqaKZsMaZ/u7qIhmaFo=;
        b=RfCm9B9SytaqKeKxgfapT0ul4av8XqzoAEbcJFfgRmdrFKLOlRzRLvBS2JEa6O6vMJ
         aXD4AFWUpL3nrTvWcO/YO3Nnw+hgkaF0piZPuF8MwCbKx6jdLj0QSAvE/7Gxsb64XSl3
         toNZbXtq1o+qEBnoMcXKEZkz0mIXllZ1wlWvNBp37z/w60MfVAC2331ZfYORi3Js8BqT
         gMreXQwhirD1mIdkzQvEMB+BNCaYqt/ifPE1dp6GwHD9b2tIzbBLs+TR1jad1CDbD24V
         h8Kf8lDjuV0IE7A1zClhDCSa7aWR+soX6MNNIPejYISHXlxkVTrCCVXlgQxpTdBwoKWf
         oTUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iSIA8ouC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bda380d3a8si3111781cf.3.2025.09.20.05.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Sep 2025 05:45:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-2681660d604so27805775ad.0
        for <kasan-dev@googlegroups.com>; Sat, 20 Sep 2025 05:45:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWG3PuKXlam5KJt1U4xx3BjxsQFP3BJwVVlTHzx2OIRYd7KpJnysqVFRkQLixGqC0AVSQ4nK05NUHg=@googlegroups.com
X-Gm-Gg: ASbGncu34JmT9mPdmz20mLUkD7rp/n/c2uyZJ8dUB34QW3hrxoB+8XKHLarxsmaKt4c
	nuv3wIKLiXnOwPboh1trw5NqFuT+u7U2wSePusQwdy5GfwVPKyE1miuSAU/VlCRB6Fdj8yQZ22Y
	qBNtdndV0jzRs14HmDyNAEPTwS60GuCf1Dhf2eZMm8x9CmJNCGqu7NCRHfw67ZCsKCgd0IFLTpF
	TSz82aCGsrdxL8Kzlalvx0QBEziR5DpEvVnblOnVTxPlgyM
X-Received: by 2002:a17:902:ccc9:b0:267:b2fc:8a2 with SMTP id
 d9443c01a7336-269ba46f141mr83309515ad.23.1758372328847; Sat, 20 Sep 2025
 05:45:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de>
 <20250918174555.GA3366400@ax162> <20250919140803.GA23745@lst.de> <CANpmjNO2b_3Q56kFLN3fAwxj0=pQo0K4CjwMJ9_gHj4c3bVVsg@mail.gmail.com>
In-Reply-To: <CANpmjNO2b_3Q56kFLN3fAwxj0=pQo0K4CjwMJ9_gHj4c3bVVsg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 20 Sep 2025 14:44:52 +0200
X-Gm-Features: AS18NWBli1y9TeOySCtz0PRORw8H0Rr8apw4LW7wblD60qoNXqS9BvtJEM0Stlo
Message-ID: <CANpmjNNkRQmt1Ea-EsSOVcA94kPqH_WntdT-NGnTjRocT25tFA@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Christoph Hellwig <hch@lst.de>
Cc: Nathan Chancellor <nathan@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iSIA8ouC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as
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

On Sat, 20 Sept 2025 at 12:23, Marco Elver <elver@google.com> wrote:
>
> On Fri, 19 Sept 2025 at 16:08, Christoph Hellwig <hch@lst.de> wrote:
> >
> > On Thu, Sep 18, 2025 at 10:45:55AM -0700, Nathan Chancellor wrote:
> > > On Thu, Sep 18, 2025 at 04:15:11PM +0200, Christoph Hellwig wrote:
> > > > On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > > > > A Clang version that supports `-Wthread-safety-pointer` and the new
> > > > > alias-analysis of capability pointers is required (from this version
> > > > > onwards):
> > > > >
> > > > >   https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
> > > >
> > > > There's no chance to make say x86 pre-built binaries for that available?
> > >
> > > I can use my existing kernel.org LLVM [1] build infrastructure to
> > > generate prebuilt x86 binaries. Just give me a bit to build and upload
> > > them. You may not be the only developer or maintainer who may want to
> > > play with this.
> >
> > That did work, thanks.
> >
> > I started to play around with that.  For the nvme code adding the
> > annotations was very simply, and I also started adding trivial
> > __guarded_by which instantly found issues.
> >
> > For XFS it was a lot more work and I still see tons of compiler
> > warnings, which I'm not entirely sure how to address.  Right now I
> > see three major classes:
> >
> > 1) locks held over loop iterations like:
> >
> > fs/xfs/xfs_extent_busy.c:573:26: warning: expecting spinlock 'xfs_group_hold(busyp->group)..xg_busy_extents->eb_lock' to be held at start of each loop [-Wthread-safety-analysis]
> >   573 |                 struct xfs_group        *xg = xfs_group_hold(busyp->group);
> >       |                                               ^
> > fs/xfs/xfs_extent_busy.c:577:3: note: spinlock acquired here
> >   577 |                 spin_lock(&eb->eb_lock);
> >       |                 ^
> >
> > This is perfectly find code and needs some annotations, but I can't find
> > any good example.
>
> This is an interesting one, and might be a bug in the alias analysis I
> recently implemented in Clang. I'll try to figure out a fix.

This fixes the problem: https://github.com/llvm/llvm-project/pull/159921

I guess I have to update the base Clang commit hash for v4 again. :-)

And thanks for testing!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNkRQmt1Ea-EsSOVcA94kPqH_WntdT-NGnTjRocT25tFA%40mail.gmail.com.
