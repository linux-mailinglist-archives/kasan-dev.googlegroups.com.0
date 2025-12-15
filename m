Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFO6QDFAMGQE6XZH3RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb138.google.com (mail-yx1-xb138.google.com [IPv6:2607:f8b0:4864:20::b138])
	by mail.lfdr.de (Postfix) with ESMTPS id 04C68CBEC46
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 16:54:19 +0100 (CET)
Received: by mail-yx1-xb138.google.com with SMTP id 956f58d0204a3-64471fcf4efsf5078299d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 07:54:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765814037; cv=pass;
        d=google.com; s=arc-20240605;
        b=YDYW+mhDlloEPbwYKIW+Puaa65aGDaa5nVJC6mNrkAqRuEQpAgAtB/og5pKlu3hExO
         bVNdR8UsjNXMNsYC5jJJGmjzKbBp72uBLeKxLpgm6QmeRN6Yj1BAN6G7ZhtyfswS10Hv
         j1+Wplgq361s1w+h1m6sQRoEkOuDeAUPL5I9HLZMDXFDcfITLorKvQEkeVmWD7z9mDzn
         UU9NS1zmcyrwh9sGof4/HjQxnZNSXdU8n8wqNRFUNh7iWYbaSFok2Rhj2My4hM82BMyH
         UFVQrZYAYurXUhR2XUYmGsZvJHs/tnGOzgvQStxD8NNg1LE1GK0VwrjnKSwv8br9Xrhl
         YIXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+sdaG9GRb2W5WPF2/Ineoz3UE/lWe+DJyeVRDxZb5E0=;
        fh=m86RXuo3AkyY5UA5IGl+8YMaeSTj8X9Azo/WzPRxQVU=;
        b=dSvk8v4FeuKlrTy/anh6lUBdNnavvjU+GZIbkABSdAX39KzGNjVjh8DUFtDj1Sy5v5
         ODnmoUaxf2i3xUbATkQ6d3HySoKdvGI9ZuXjTccIEgelYsA2am1KLVZRsGu2bh9OPGWC
         /7mvv6+MdGhymqFycht+Fd4OVbc+lgkWSmMcKcVmOhSgnNDvXIX6egrdauUQpkS4hdPJ
         SrAtkemxK0RuAwROjrSANfS4vI0H/FY+DB2R7PwaS6diH5o3WMW4rd190jJE2QXJl54W
         vCOxXRvJh9+foGd/ylTYSipohWj477/kMESaUyy3XQm7GeXQcf/5OvQhgEFfHISmCFOW
         gZgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NbVakZiC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765814037; x=1766418837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+sdaG9GRb2W5WPF2/Ineoz3UE/lWe+DJyeVRDxZb5E0=;
        b=r6jc43xHunYlOcYGL2gt/IK2QGFXKfvJzSAf1lIbxg2PZ4hUk3jOEB1HYs/oSgDIHN
         9QDyP60txsiLvhh8wib1c0H2h6/5SJV5BMN+giwBZAeta1vlWSoOuIoTjNy+RZazTOLT
         RgQojDJo0aYpoKWmc86ZY2B4DSRmND+8DBkOE3lZ9cbOw3QcWdfopVIucZDomeWDB+NX
         8KYkncAaN/VKXz1McUY/3EdoSzTYcv6GZn0BtXXBwlxk8ChGz95hjOD0hKJ7zv9HH1NS
         eNKZxGeJU8EAq1AHaL7OZ37Tu866mUoB2tSxckVnfnu3jMhzQE1NiszGbu/DEclnfATD
         DCfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765814037; x=1766418837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+sdaG9GRb2W5WPF2/Ineoz3UE/lWe+DJyeVRDxZb5E0=;
        b=X3s5DuUZim2KALBEpz1Dt9Sj6t349KGMBLlAPaGhnVvm7OjsW74Zp1bUkg1AvaPGDE
         6VHEw9/M8l4C3bHX4gsoNiytMQPRrM+gNSLBB61Y7XVtb84AVyU9Luhlf3MwAuWbKJAF
         IytBRPT0ZNOQ7dAE7iziruoF7o8OyzkWoR+TqR83Dgzl98CVozzbV0m53j998im3ltcR
         ni6c3i4ylmUxpODVsOC2qEzI+94HjeLAG6Sq8EeqJniM1K5q6v6T+4xh/TbPzh3fyKV6
         FmObFMfbYlf5J2yid6B0aPZ/nvH4SSN35kd6fhHJ37g6exz6/Ys6CR73j+ycweFl1sUe
         tvag==
X-Forwarded-Encrypted: i=2; AJvYcCUfL+pTFZK+hSlh4drxgsXLViL0gx5ZEO3S8QRQxFOoiAxQyehaVPWpOAM7j95a5Tx3icD60A==@lfdr.de
X-Gm-Message-State: AOJu0YxTbDyGS3oIMW3qf3xB1X/R1GxXSZt++waCx3flKV+5ofZ9hQ3O
	II7zJfJ0RjElgOXRefmcdLsFG2dSdNUEHWvcMlMdMVfU/9U184cT2CAC
X-Google-Smtp-Source: AGHT+IGAFd8z2DijZviGhpOKWh5je08e7/PPjzVrp3kLXwh+jcQtvAqioY4yB1WTcToozf6ux14ibA==
X-Received: by 2002:a53:cbc4:0:b0:642:836:1048 with SMTP id 956f58d0204a3-645555d27c7mr6744905d50.2.1765814037435;
        Mon, 15 Dec 2025 07:53:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZvx30QzxejoBQ7SGqmUpHF1tsko4WLXDlAVm2543gm/g=="
Received: by 2002:a05:690e:1aa3:b0:607:623b:bb59 with SMTP id
 956f58d0204a3-64554b4b965ls2780893d50.2.-pod-prod-02-us; Mon, 15 Dec 2025
 07:53:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU5ZlZjZ9qtzBz63MFuQoDGo5VjFdH3Rq8Wq4bFxObyfcf0Reizy/qO2cUoQCmRbmn41sf1riF1dJw=@googlegroups.com
X-Received: by 2002:a53:b205:0:b0:644:6520:eadc with SMTP id 956f58d0204a3-6455564e8a4mr5839964d50.50.1765814036487;
        Mon, 15 Dec 2025 07:53:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765814036; cv=none;
        d=google.com; s=arc-20240605;
        b=SY366DOWIcX+k8DSS/8alt7veB2GPFqAto+p3Tt37lc09XILR1roOHp5Tm5zUw1sbi
         5igJdaF0Skcx84KN1tcqBJEDB6QLGbXkZavt3Y1h4RnwINp4ZSYt9Ksw6XnKQ04x3S6G
         3dqwSDN6IS4GDL83aW1kMxaibJBLM/UiX3PQctqJlXEf8lTao7icDDvhvD1ATxIGQwWN
         2NgAoswrzAK/iOeivoUabAQGjAv/ybanq7Ey4jerLoqBhqOHLiaRm9lnJpmAOH1BB6Jr
         iPG7TDm/RtyLXCIn5lVfcxNn0vsMzpVCK1B+iTPOypH0YBHLnKfJNK+wf7J3+F0wDdW4
         MOvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ROScw7LkVEobmMJDTvBXmeogZcMVtVRNIb25XYU/aOk=;
        fh=wsWetg0FsvnoRNbxSTi698RmSFreGOTK4TVfxqRIal4=;
        b=QS7zIoTmR0T68YW0CYkJKD4C5gNxuE1GAa5SUWGXcdPlV1dhicANE094HcE2ywviLc
         TUV9eaisPnp3mCkLUvEWs6Vko8WjacLK1rdi72MbI60fcsBxBzqfwMiFP/VqEa1YAWT/
         VTWQOxyOsWIDQ+Sh+8zJFRuxYMdXTzjEHb2GdOM5zGL/O25baXOioNNQbzqTbneSFHi4
         RZBcQMVCtpJOXSrhgcuUTKREzvyFYNNRCi0X6H3PanqC4wbrZwaWRu26CKUGrl1zPFFD
         rZnPzsfpJQ3hgbaR2EiLQ/Xip7VAj03r8jvdhGegi7GzJIftCA0NG9bcyYDAGebEd7xE
         O7aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NbVakZiC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78e748fd553si2237187b3.2.2025.12.15.07.53.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 07:53:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-2a087b2a9c0so26289525ad.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 07:53:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5No9xxBKIbcsuRIf9xkxdGAFNcLCEJ66yuLTr9vjvuAI1VogwUh8xsR3khxoMw/FnuCoyhogDxo4=@googlegroups.com
X-Gm-Gg: AY/fxX5j6JCf9VA4H1xYpKBAb58nfVUVvVMpsNWpQwZukNZplcbXwv6V4Fl6VWcUvyN
	KCOzXxtGXec/m8tvNoBOK5Xiipq9mxeQxTAiUjSBnHwPVH/jCEYTTKmR7lLpzd75uzbKLP+eLwS
	CXfrGc0Iqk3+qWFk0wNyF/9I1ozuahbtElD0oKTRlik/BHTDuzG+2hXcHvYu7D60Qre8oFVjhB2
	QyYDMWLiSI27kdSgRLTfUE9RmQzKAhCEGyERf+KJbNXv213CRNXV+aJ0L5X4wpc2P2Z5Mj9bnZz
	0KVmT5Dd8UcEQhL9jepDgZvXKQ==
X-Received: by 2002:a05:7022:1b0c:b0:11a:3483:4a87 with SMTP id
 a92af1059eb24-11f34be9ca7mr8171406c88.13.1765814035105; Mon, 15 Dec 2025
 07:53:55 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net> <aUAPbFJSv0alh_ix@elver.google.com>
In-Reply-To: <aUAPbFJSv0alh_ix@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Dec 2025 16:53:18 +0100
X-Gm-Features: AQt7F2oxzebZt0rcTkreaKMT4PDBgj_kZoo-YwczNEo1aa0S6zPi6Xbs61JFiQg
Message-ID: <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, 
	Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
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
 header.i=@google.com header.s=20230601 header.b=NbVakZiC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as
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

On Mon, 15 Dec 2025 at 14:38, Marco Elver <elver@google.com> wrote:
>
> On Fri, Dec 12, 2025 at 12:09PM +0100, Peter Zijlstra wrote:
> > On Fri, Dec 12, 2025 at 11:15:29AM +0100, Marco Elver wrote:
> > > On Fri, 12 Dec 2025 at 10:43, Peter Zijlstra <peterz@infradead.org> wrote:
> > > [..]
> > > > > Correct. We're trading false negatives over false positives at this
> > > > > point, just to get things to compile cleanly.
> > > >
> > > > Right, and this all 'works' right up to the point someone sticks a
> > > > must_not_hold somewhere.
> > > >
> > > > > > > Better support for Linux's scoped guard design could be added in
> > > > > > > future if deemed critical.
> > > > > >
> > > > > > I would think so, per the above I don't think this is 'right'.
> > > > >
> > > > > It's not sound, but we'll avoid false positives for the time being.
> > > > > Maybe we can wrangle the jigsaw of macros to let it correctly acquire
> > > > > and then release (via a 2nd cleanup function), it might be as simple
> > > > > as marking the 'constructor' with the right __acquires(..), and then
> > > > > have a 2nd __attribute__((cleanup)) variable that just does a no-op
> > > > > release via __release(..) so we get the already supported pattern
> > > > > above.
> > > >
> > > > Right, like I mentioned in my previous email; it would be lovely if at
> > > > the very least __always_inline would get a *very* early pass such that
> > > > the above could be resolved without inter-procedural bits. I really
> > > > don't consider an __always_inline as another procedure.
> > > >
> > > > Because as I already noted yesterday, cleanup is now all
> > > > __always_inline, and as such *should* all end up in the one function.
> > > >
> > > > But yes, if we can get a magical mash-up of __cleanup and __release (let
> > > > it be knows as __release_on_cleanup ?) that might also work I suppose.
> > > > But I vastly prefer __always_inline actually 'working' ;-)
> > >
> > > The truth is that __always_inline working in this way is currently
> > > infeasible. Clang and LLVM's architecture simply disallow this today:
> > > the semantic analysis that -Wthread-safety does happens over the AST,
> > > whereas always_inline is processed by early passes in the middle-end
> > > already within LLVM's pipeline, well after semantic analysis. There's
> > > a complexity budget limit for semantic analysis (type checking,
> > > warnings, assorted other errors), and path-sensitive &
> > > intra-procedural analysis over the plain AST is outside that budget.
> > > Which is why tools like clang-analyzer exist (symbolic execution),
> > > where it's possible to afford that complexity since that's not
> > > something that runs for a normal compile.
> > >
> > > I think I've pushed the current version of Clang's -Wthread-safety
> > > already far beyond what folks were thinking is possible (a variant of
> > > alias analysis), but even my healthy disregard for the impossible
> > > tells me that making path-sensitive intra-procedural analysis even if
> > > just for __always_inline functions is quite possibly a fool's errand.
> >
> > Well, I had to propose it. Gotta push the envelope :-)
> >
> > > So either we get it to work with what we have, or give up.
> >
> > So I think as is, we can start. But I really do want the cleanup thing
> > sorted, even if just with that __release_on_cleanup mashup or so.
>
> Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
> abstraction. For that one I was able to make it work like I thought we
> could (below). Some awkwardness is required to make it work in
> for-loops, which only let you define variables with the same type.
>
> For <linux/cleanup.h> it needs some more thought due to extra levels of
> indirection.

For cleanup.h, the problem is that to instantiate we use
"guard(class)(args..)". If it had been designed as "guard(class,
args...)", i.e. just use __VA_ARGS__ explicitly instead of the
implicit 'args...', it might have been possible to add a second
cleanup variable to do the same (with some additional magic to extract
the first arg if one exists). Unfortunately, the use of the current
guard()() idiom has become so pervasive that this is a bigger
refactor. I'm going to leave cleanup.h as-is for now, if we think we
want to give this a go in the current state.

One observation from the rebase: Generally synchronization primitives
do not change much and the annotations are relatively stable, but e.g.
RCU & sched (latter is optional and depends on the sched-enablement
patch) receive disproportionally more changes, and while new
annotations required for v6.19-rc1 were trivial, it does require
compiling with a Clang version that does produce the warnings to
notice.
While Clang 22-dev is being tested on CI, I doubt maintainers already
use it, so it's possible we'll see some late warnings due to missing
annotations when things hit -next. This might be an acceptable churn
cost, if we think the outcome is worthwhile. Things should get better
when Clang 22 is released properly, but until then things might be a
little bumpy if there are large changes across the core
synchronization primitives.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw%40mail.gmail.com.
