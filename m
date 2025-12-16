Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCEDQ3FAMGQEJNKHHKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 88AD2CC415B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 16:58:02 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59580c95819sf3058829e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 07:58:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765900682; cv=pass;
        d=google.com; s=arc-20240605;
        b=fLYfIZ9hDth24vXSR73gI5HOTEmybiEDaZw1XVV03OBaqOZmhGc/fIgHoQHMLKlBFE
         pUCHfYJOYiNivnaVpWBu0AEGGd824KFMQFvjQ+QVrOOMZ4bS6Nmv0cz24uR63MlidZR9
         ADZF6nezUCGoGr083cTuNdkcCpSLAiHf0CDecdyvDNl5srVFudFXRSGcla2LA6LKVzwl
         WL7pUOr63gaWc9dGaFCi1Yjhyo/qHFXIl5R8hj8d6eGXFDj3PgGMCQRBGudMRwaObTuG
         QPgEE09/J8s2Q/vj6y525z861/qw/+5kPVd6oJlN3E2N8xTj9vu41vVkkD3eSMrCknzo
         Vsbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=P1LJhKlnZTS5ivfAX2AIF3BDnQMTUE4DjY47kXjUpPg=;
        fh=TodXyBN9N8lbfwQ7ERk3LH1YExHeZq7j2na529UHioY=;
        b=BrWumFG7gDLZLep9tgB2fNSId7OvwD36fFyH+qphyH7MFgNOPl06J82qnsT00qDrpa
         3b7bAdL+0HAJh4uAZxwSXQ8lG103yXDAz71Ys+vUAMrylwMTsoJkSjJP3pGZODuu4Z1R
         QN6TR4g8Xu8d1l6gKP6xudq+cTocQpKkVHterMdW6ZmGkLtguXZryHjHkpBRjRNOlErI
         iIqapHzHJv/JT8mhiT1OlTuVCvPk9TQLZSa1oCRg2u0nRWxMrgSxrqY4+ARBFNv+5EU8
         k608FoEGNtfcYqesFyBmKd6tX4XxHvkIyJ4N83e1voeHSysmvsoBiZge/XzCUUMoU5FR
         pdgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JhfGLnQK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765900682; x=1766505482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=P1LJhKlnZTS5ivfAX2AIF3BDnQMTUE4DjY47kXjUpPg=;
        b=f8IJ9/6x4QUiIFwgFmrAGVBNPlHsHETacTifsELW9P3VetfLRXBH1LOwG+GEP1D036
         KT787LKfiObbfPr00A1t7w0EFseQr8T+dpccdhvsPZu3niU4am16O9NWPoHwz+XyjBF1
         2vmo2nJFSOQbWGbl+HyCYIJbIVGwi+k0cdWzKj2hGuiR+2xOvIc83riykW2lIhDBKqbj
         0MmsQPpwRXumnFDQ8+TjCkczmfht4UZqDJOST8aunYk/9hPuRWmJ1YXDrUW0r0eZQnYY
         OOn/HGlPGcV212KK56LtC1Pxgi80a9kkDfycKwWrBU78Smoxv2wmeJmknRe71/39g+yW
         9g4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765900682; x=1766505482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=P1LJhKlnZTS5ivfAX2AIF3BDnQMTUE4DjY47kXjUpPg=;
        b=jKdMNpMHjIDiC9xf61E37hLyZC0AuIgeiWvlepVgBmK2wMDGtwxFcQh/CVW3o6cDrL
         7krgK4n+SFEgRmSioXGDFy7B0cyNzygRtnbcFyXxLNGhoCYLd8NVEdF5m5WKlxrSioKQ
         uJtBl78NiHJi9l3QgG4K+0IUBPQXZLeVH7xd+oqrmSZwzjnvTdgg09+mHRD3QMW30r/m
         yyKtdjnWHym373CZzkI80amijO2/0FLXjgPnQ+13mInW60Ex1gTaKA2uNRyegE4q1a17
         tqUZ0zr8VWzK5+ptj3b/CLN4mm9wZLd6W+cTAvbg5XUfpJZE3Pdxd5xFk/cDuMyBBsmk
         24xA==
X-Forwarded-Encrypted: i=2; AJvYcCXeJMnHPnKbJDandgjO4o8F3bxPPpU7ktL12K6giYgI9acRugsD16O/VaWhakQC9LmEGJkzeQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywm8W/k8JJJ5iXy7fmmkc7iWnJ3u44/00kxzmNZ9wNQSiFeAPCl
	0WFIbFThIw/bSJVT6NFY/FcySw1ubdtQhoK6aZGWmXTVRTOHmnNf3R9r
X-Google-Smtp-Source: AGHT+IGgEFhWsyy+K0SJV90BEFIH1KVWmmUiT1wi7V9AW2JWbNyjGpn17LmpMfUwhKd/3aIrtivHTw==
X-Received: by 2002:a05:6512:3b11:b0:598:eacd:ceb5 with SMTP id 2adb3069b0e04-598faa147b7mr4881616e87.17.1765900681432;
        Tue, 16 Dec 2025 07:58:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb0r5L3qMy+ZZukmODER2Uswtnhz4oYrp2Vhv9HBuj1vQ=="
Received: by 2002:a05:6512:3d22:b0:598:ec8d:f528 with SMTP id
 2adb3069b0e04-598fa4095dcls1812012e87.2.-pod-prod-03-eu; Tue, 16 Dec 2025
 07:57:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVv8ZJp2vGwyhaxpPqiBXThCK4JrVRjRE8/YHRWh+XyYLIz5scE57SArtQDP/CsOHPOVmeb38tFz1c=@googlegroups.com
X-Received: by 2002:a05:6512:1324:b0:598:ef9b:b25d with SMTP id 2adb3069b0e04-598faa73b7cmr4673942e87.42.1765900677964;
        Tue, 16 Dec 2025 07:57:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765900677; cv=none;
        d=google.com; s=arc-20240605;
        b=fZppREhGB+dFkpIl5A5EKbxRoS47k72bvjRUt2X2UAQt6f43ZJ4Y6kL9//Dl+/YVK0
         3VSV5dMNYSN5hGXxUQRGcuiLN8ueOsi54lAaB2tenS1u9xQw5/4NRPM5kIdu33PV2i0S
         n9lqq2iPbqsU22MV4RsR27GdV3ZVbBKSPFAS3QNui7I7Fwr2L0zAGUOGNMBr/Oj8VEwg
         DsknRKydF+EgYP/pUgwDqkzPqTq8gq9H+qGURXh5JH7QVI84wDSQKpzzLsmh++RNCrgx
         HtzQv2pA86nUxwGwTRnfnfClmXK1e6jHCI8qYLHx5wazQZbs/ZY1CMhPcJJTfg/iQLHx
         usfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4T6EEvpkYB8O/dSoH4wvSyTHiJOCpYvJH+j1ElyVX1A=;
        fh=m+UjkfjtHpcA7DFXEWw6hTJkgjFHw2bICO6pq5UqTh8=;
        b=bTQAuVijGYAH4sFRXUjQmi/yVyPy44viKkFOMFIBf9JZvLv5V8vKNl4zRVyqnzzwYb
         pEUc98F5/mpUWDBtnRnhoPQXBqCHfP+n1tclSNBK6QtuCAjkVSpN7WQeQh0D70KmfjFb
         9h3gDbLLSDdTCLFQVFocQSnUwPbB0yU3pVsS06pv+U0nw6kI40VQx3iVoVFjKP09RwUS
         BinRj3DhnEACn9t+6o395BjN60B0gR9fc/1igyZdNkByV8H2vof8kovVr6bT1O0+6Dq1
         6SyZaJK7DPp5F7hnqUUq8jrZw9kARJF3qlB3CVJc+ty9LpVTITfSTrI4thtT3zRD8Xnr
         ucfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JhfGLnQK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5990de2e5fbsi44801e87.6.2025.12.16.07.57.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 07:57:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-477b198f4bcso38684435e9.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 07:57:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX8fBvgFHJeuRURIaGGPE5BJD+I5u5j7VzlRSXS+nVoY8kxzSU5hXkXXC6UF9g2GDovtcwBToFCssA=@googlegroups.com
X-Gm-Gg: AY/fxX6ZGpVFUfJO1ho3Zza9REo0YcVkAwLA7p4i+uIRJb0lYRJA6yEn/QC0qvek8FL
	aIp55KYBwknyPBJMBbQVJlHefh1gP72DzbDmZOTjKY9lnK6lAm2xjv97oXGYiOg7x33lrS75+Da
	A8QPjqv1yDRC/B2FbwkKDoV2I+A8dA24TGhUFMcojea9Gw0GZEcx2TvgwvpmLZsUO4NLqXKKNVh
	p1kjMqUrkvrumnfQQTJDd2b5ZulIzv2vCRXk3FISDCAD2wOUNFZeGLzU0g+luzpkgTKEvQjEBPG
	FHDyQMHW9WekFqvmULnpb0Q2n+w8YkZFvkmNZkGKd8qFZ9w3svH5W/drNKVFBTfwck0fk9bABdC
	dX1f6IqU5q0YS3PQpWqpjICNwdYbTZ+4Bq4tX92lo5Bnk5UQo38IPo2bNr69xv1EKXZO9t2aRts
	88lbV2pIQEqiLhUUbFicmAdVYW/e/x+WoZjqEn606CiRsgezi8
X-Received: by 2002:a05:600c:1c1a:b0:475:de12:d3b5 with SMTP id 5b1f17b1804b1-47a8f91601bmr141242195e9.34.1765900676692;
        Tue, 16 Dec 2025 07:57:56 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:ea4c:b2a8:24a4:9ce9])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-430f7994b58sm18141460f8f.22.2025.12.16.07.57.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 07:57:55 -0800 (PST)
Date: Tue, 16 Dec 2025 16:57:49 +0100
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
Message-ID: <aUGBff8Oko5O8EsP@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
 <aUE77hgJa58waFOy@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUE77hgJa58waFOy@elver.google.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JhfGLnQK;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Tue, Dec 16, 2025 at 12:01PM +0100, Marco Elver wrote:
> On Mon, Dec 15, 2025 at 04:53PM +0100, Marco Elver wrote:
> [..]
> > > > So I think as is, we can start. But I really do want the cleanup thing
> > > > sorted, even if just with that __release_on_cleanup mashup or so.
> > >
> > > Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
> > > abstraction. For that one I was able to make it work like I thought we
> > > could (below). Some awkwardness is required to make it work in
> > > for-loops, which only let you define variables with the same type.
> > >
> > > For <linux/cleanup.h> it needs some more thought due to extra levels of
> > > indirection.
> > 
> > For cleanup.h, the problem is that to instantiate we use
> > "guard(class)(args..)". If it had been designed as "guard(class,
> > args...)", i.e. just use __VA_ARGS__ explicitly instead of the
> > implicit 'args...', it might have been possible to add a second
> > cleanup variable to do the same (with some additional magic to extract
> > the first arg if one exists). Unfortunately, the use of the current
> > guard()() idiom has become so pervasive that this is a bigger
> > refactor. I'm going to leave cleanup.h as-is for now, if we think we
> > want to give this a go in the current state.
> 
> Alright, this can work, but it's not that ergonomic as I'd hoped (see
> below): we can redefine class_<name>_constructor to append another
> cleanup variable. With enough documentation, this might be workable.

Below is the preview of the complete changes to make the lock guards
work properly.

Thanks,
-- Marco

------ >8 ------

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index 2f998bb42c4c..9fe3b0f816c6 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -516,9 +516,42 @@ static __always_inline class_##_name##_t class_##_name##_constructor(void) \
 static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
 static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
 
+/*
+ * To support Context Analysis, we need to allow the compiler to see the
+ * acquisition and release of the context lock. However, the "cleanup" helpers
+ * wrap the lock in a struct passed through seperate helper functions, which
+ * hides the lock alias from the compiler (no inter-procedural analysis).
+ *
+ * To make it work, we introduce an explicit alias to the context lock instance
+ * that is "cleaned" up with a separate cleanup helper. This helper is a dummy
+ * function that does nothing at runtime, but has the "_unlock" attribute to
+ * tell the compiler what happens at the end of the scope.
+ *
+ * To generalize the pattern, the WITH_LOCK_GUARD_1_ATTRS() macro should be used
+ * to redefine the constructor, which then also creates the alias variable with
+ * the right "cleanup" attribute, *after* DECLARE_LOCK_GUARD_1_ATTRS() has been
+ * used.
+ *
+ * Example usage:
+ *
+ *   DECLARE_LOCK_GUARD_1_ATTRS(mutex, __acquires(_T), __releases(*(struct mutex **)_T))
+ *   #define class_mutex_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex, _T)
+ *
+ * Note: To support the for-loop based scoped helpers, the auxiliary variable
+ * must be a pointer to the "class" type because it is defined in the same
+ * statement as the guard variable. However, we initialize it with the lock
+ * pointer (despite the type mismatch, the compiler's alias analysis still works
+ * as expected). The "_unlock" attribute receives a pointer to the auxiliary
+ * variable (a double pointer to the class type), and must be cast and
+ * dereferenced appropriately.
+ */
 #define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
 static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
-static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
+static __always_inline void __class_##_name##_cleanup_ctx(class_##_name##_t **_T) \
+	__no_context_analysis _unlock { }
+#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)				\
+	class_##_name##_constructor(_T),				\
+	*__UNIQUE_ID(unlock) __cleanup(__class_##_name##_cleanup_ctx) = (void *)(_T)
 
 #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
 __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
diff --git a/include/linux/local_lock.h b/include/linux/local_lock.h
index bedcbb33b928..99c06e499375 100644
--- a/include/linux/local_lock.h
+++ b/include/linux/local_lock.h
@@ -104,9 +104,13 @@ DEFINE_LOCK_GUARD_1(local_lock_nested_bh, local_lock_t __percpu,
 		    local_lock_nested_bh(_T->lock),
 		    local_unlock_nested_bh(_T->lock))
 
-DECLARE_LOCK_GUARD_1_ATTRS(local_lock, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irq, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irqsave, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irq, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_irq, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_irqsave, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_irqsave, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, __acquires(_T), __releases(*(local_lock_t __percpu **)_T))
+#define class_local_lock_nested_bh_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(local_lock_nested_bh, _T)
 
 #endif
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
 
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index 0e75e26e8813..8da14a08a4e1 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -262,17 +262,23 @@ DEFINE_LOCK_GUARD_1(rwsem_read, struct rw_semaphore, down_read(_T->lock), up_rea
 DEFINE_LOCK_GUARD_1_COND(rwsem_read, _try, down_read_trylock(_T->lock))
 DEFINE_LOCK_GUARD_1_COND(rwsem_read, _intr, down_read_interruptible(_T->lock), _RET == 0)
 
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_try, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_intr, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_try, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read_try, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_intr, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_intr_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read_intr, _T)
 
 DEFINE_LOCK_GUARD_1(rwsem_write, struct rw_semaphore, down_write(_T->lock), up_write(_T->lock))
 DEFINE_LOCK_GUARD_1_COND(rwsem_write, _try, down_write_trylock(_T->lock))
 DEFINE_LOCK_GUARD_1_COND(rwsem_write, _kill, down_write_killable(_T->lock), _RET == 0)
 
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_try, __assumes_ctx_lock(_T), /* */)
-DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_kill, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_try, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write_try, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_kill, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_kill_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write_kill, _T)
 
 /*
  * downgrade write lock to read lock
diff --git a/include/linux/sched/task.h b/include/linux/sched/task.h
index 397f4753d10a..41ed884cffc9 100644
--- a/include/linux/sched/task.h
+++ b/include/linux/sched/task.h
@@ -226,6 +226,7 @@ static inline void task_unlock(struct task_struct *p)
 }
 
 DEFINE_LOCK_GUARD_1(task_lock, struct task_struct, task_lock(_T->lock), task_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(task_lock, __assumes_ctx_lock(_T->alloc_lock), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(task_lock, __acquires(&_T->alloc_lock), __releases(&(*(struct task_struct **)_T)->alloc_lock))
+#define class_task_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(task_lock, _T)
 
 #endif /* _LINUX_SCHED_TASK_H */
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 3a45b08ced43..396b8c5d6c1b 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -537,109 +537,132 @@ void free_bucket_spinlocks(spinlock_t *locks);
 DEFINE_LOCK_GUARD_1(raw_spinlock, raw_spinlock_t,
 		    raw_spin_lock(_T->lock),
 		    raw_spin_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock, _T)
 
 DEFINE_LOCK_GUARD_1_COND(raw_spinlock, _try, raw_spin_trylock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_try, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_try, _T)
 
 DEFINE_LOCK_GUARD_1(raw_spinlock_nested, raw_spinlock_t,
 		    raw_spin_lock_nested(_T->lock, SINGLE_DEPTH_NESTING),
 		    raw_spin_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_nested, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_nested, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_nested_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_nested, _T)
 
 DEFINE_LOCK_GUARD_1(raw_spinlock_irq, raw_spinlock_t,
 		    raw_spin_lock_irq(_T->lock),
 		    raw_spin_unlock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irq, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irq, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_irq, _T)
 
 DEFINE_LOCK_GUARD_1_COND(raw_spinlock_irq, _try, raw_spin_trylock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irq_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irq_try, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_irq_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_irq_try, _T)
 
 DEFINE_LOCK_GUARD_1(raw_spinlock_bh, raw_spinlock_t,
 		    raw_spin_lock_bh(_T->lock),
 		    raw_spin_unlock_bh(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_bh, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_bh, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_bh_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_bh, _T)
 
 DEFINE_LOCK_GUARD_1_COND(raw_spinlock_bh, _try, raw_spin_trylock_bh(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_bh_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_bh_try, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_bh_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_bh_try, _T)
 
 DEFINE_LOCK_GUARD_1(raw_spinlock_irqsave, raw_spinlock_t,
 		    raw_spin_lock_irqsave(_T->lock, _T->flags),
 		    raw_spin_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave, _T)
 
 DEFINE_LOCK_GUARD_1_COND(raw_spinlock_irqsave, _try,
 			 raw_spin_trylock_irqsave(_T->lock, _T->flags))
-DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave_try, __acquires(_T), __releases(*(raw_spinlock_t **)_T))
+#define class_raw_spinlock_irqsave_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(raw_spinlock_irqsave_try, _T)
 
 DEFINE_LOCK_GUARD_1(spinlock, spinlock_t,
 		    spin_lock(_T->lock),
 		    spin_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock, _T)
 
 DEFINE_LOCK_GUARD_1_COND(spinlock, _try, spin_trylock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_try, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_try, _T)
 
 DEFINE_LOCK_GUARD_1(spinlock_irq, spinlock_t,
 		    spin_lock_irq(_T->lock),
 		    spin_unlock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irq, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irq, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_irq, _T)
 
 DEFINE_LOCK_GUARD_1_COND(spinlock_irq, _try,
 			 spin_trylock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irq_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irq_try, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_irq_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_irq_try, _T)
 
 DEFINE_LOCK_GUARD_1(spinlock_bh, spinlock_t,
 		    spin_lock_bh(_T->lock),
 		    spin_unlock_bh(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_bh, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_bh, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_bh_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_bh, _T)
 
 DEFINE_LOCK_GUARD_1_COND(spinlock_bh, _try,
 			 spin_trylock_bh(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_bh_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_bh_try, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_bh_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_bh_try, _T)
 
 DEFINE_LOCK_GUARD_1(spinlock_irqsave, spinlock_t,
 		    spin_lock_irqsave(_T->lock, _T->flags),
 		    spin_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irqsave, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irqsave, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_irqsave, _T)
 
 DEFINE_LOCK_GUARD_1_COND(spinlock_irqsave, _try,
 			 spin_trylock_irqsave(_T->lock, _T->flags))
-DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irqsave_try, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(spinlock_irqsave_try, __acquires(_T), __releases(*(spinlock_t **)_T))
+#define class_spinlock_irqsave_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(spinlock_irqsave_try, _T)
 
 DEFINE_LOCK_GUARD_1(read_lock, rwlock_t,
 		    read_lock(_T->lock),
 		    read_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(read_lock, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(read_lock, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_read_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(read_lock, _T)
 
 DEFINE_LOCK_GUARD_1(read_lock_irq, rwlock_t,
 		    read_lock_irq(_T->lock),
 		    read_unlock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(read_lock_irq, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(read_lock_irq, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_read_lock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(read_lock_irq, _T)
 
 DEFINE_LOCK_GUARD_1(read_lock_irqsave, rwlock_t,
 		    read_lock_irqsave(_T->lock, _T->flags),
 		    read_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
-DECLARE_LOCK_GUARD_1_ATTRS(read_lock_irqsave, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(read_lock_irqsave, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_read_lock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(read_lock_irqsave, _T)
 
 DEFINE_LOCK_GUARD_1(write_lock, rwlock_t,
 		    write_lock(_T->lock),
 		    write_unlock(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(write_lock, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(write_lock, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_write_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(write_lock, _T)
 
 DEFINE_LOCK_GUARD_1(write_lock_irq, rwlock_t,
 		    write_lock_irq(_T->lock),
 		    write_unlock_irq(_T->lock))
-DECLARE_LOCK_GUARD_1_ATTRS(write_lock_irq, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(write_lock_irq, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_write_lock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(write_lock_irq, _T)
 
 DEFINE_LOCK_GUARD_1(write_lock_irqsave, rwlock_t,
 		    write_lock_irqsave(_T->lock, _T->flags),
 		    write_unlock_irqrestore(_T->lock, _T->flags),
 		    unsigned long flags)
-DECLARE_LOCK_GUARD_1_ATTRS(write_lock_irqsave, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(write_lock_irqsave, __acquires(_T), __releases(*(rwlock_t **)_T))
+#define class_write_lock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(write_lock_irqsave, _T)
 
 #undef __LINUX_INSIDE_SPINLOCK_H
 #endif /* __LINUX_SPINLOCK_H */
diff --git a/include/linux/srcu.h b/include/linux/srcu.h
index 88f01d6fded8..bb44a0bd7696 100644
--- a/include/linux/srcu.h
+++ b/include/linux/srcu.h
@@ -621,16 +621,21 @@ DEFINE_LOCK_GUARD_1(srcu, struct srcu_struct,
 		    _T->idx = srcu_read_lock(_T->lock),
 		    srcu_read_unlock(_T->lock, _T->idx),
 		    int idx)
-DECLARE_LOCK_GUARD_1_ATTRS(srcu, __assumes_ctx_lock(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu, _T)
 
 DEFINE_LOCK_GUARD_1(srcu_fast, struct srcu_struct,
 		    _T->scp = srcu_read_lock_fast(_T->lock),
 		    srcu_read_unlock_fast(_T->lock, _T->scp),
 		    struct srcu_ctr __percpu *scp)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu_fast, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_fast_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu_fast, _T)
 
 DEFINE_LOCK_GUARD_1(srcu_fast_notrace, struct srcu_struct,
 		    _T->scp = srcu_read_lock_fast_notrace(_T->lock),
 		    srcu_read_unlock_fast_notrace(_T->lock, _T->scp),
 		    struct srcu_ctr __percpu *scp)
+DECLARE_LOCK_GUARD_1_ATTRS(srcu_fast_notrace, __acquires_shared(_T), __releases_shared(*(struct srcu_struct **)_T))
+#define class_srcu_fast_notrace_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(srcu_fast_notrace, _T)
 
 #endif
diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
index fab6a19dda02..7c57a6d2f847 100644
--- a/kernel/sched/sched.h
+++ b/kernel/sched/sched.h
@@ -1874,7 +1874,8 @@ DEFINE_LOCK_GUARD_1(task_rq_lock, struct task_struct,
 		    _T->rq = task_rq_lock(_T->lock, &_T->rf),
 		    task_rq_unlock(_T->rq, _T->lock, &_T->rf),
 		    struct rq *rq; struct rq_flags rf)
-DECLARE_LOCK_GUARD_1_ATTRS(task_rq_lock, __assumes_ctx_lock(_T->pi_lock), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(task_rq_lock, __acquires(_T->pi_lock), __releases((*(struct task_struct **)_T)->pi_lock))
+#define class_task_rq_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(task_rq_lock, _T)
 
 DEFINE_LOCK_GUARD_1(__task_rq_lock, struct task_struct,
 		    _T->rq = __task_rq_lock(_T->lock, &_T->rf),
@@ -1928,21 +1929,24 @@ DEFINE_LOCK_GUARD_1(rq_lock, struct rq,
 		    rq_unlock(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
-DECLARE_LOCK_GUARD_1_ATTRS(rq_lock, __assumes_ctx_lock(__rq_lockp(_T)), /* */);
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock, __acquires(__rq_lockp(_T)), __releases(__rq_lockp(*(struct rq **)_T)));
+#define class_rq_lock_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rq_lock, _T)
 
 DEFINE_LOCK_GUARD_1(rq_lock_irq, struct rq,
 		    rq_lock_irq(_T->lock, &_T->rf),
 		    rq_unlock_irq(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
-DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irq, __assumes_ctx_lock(__rq_lockp(_T)), /* */);
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irq, __acquires(__rq_lockp(_T)), __releases(__rq_lockp(*(struct rq **)_T)));
+#define class_rq_lock_irq_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rq_lock_irq, _T)
 
 DEFINE_LOCK_GUARD_1(rq_lock_irqsave, struct rq,
 		    rq_lock_irqsave(_T->lock, &_T->rf),
 		    rq_unlock_irqrestore(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
-DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irqsave, __assumes_ctx_lock(__rq_lockp(_T)), /* */);
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irqsave, __acquires(__rq_lockp(_T)), __releases(__rq_lockp(*(struct rq **)_T)));
+#define class_rq_lock_irqsave_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rq_lock_irqsave, _T)
 
 #define this_rq_lock_irq(...) __acquire_ret(_this_rq_lock_irq(__VA_ARGS__), __rq_lockp(__ret))
 static inline struct rq *_this_rq_lock_irq(struct rq_flags *rf) __acquires_ret
@@ -3075,10 +3079,17 @@ static inline class_##name##_t class_##name##_constructor(type *lock, type *lock
 	__no_context_analysis								\
 { class_##name##_t _t = { .lock = lock, .lock2 = lock2 }, *_T = &_t;			\
   _lock; return _t; }
-#define DECLARE_LOCK_GUARD_2_ATTRS(_name, _lock, _unlock)				\
+#define DECLARE_LOCK_GUARD_2_ATTRS(_name, _lock, _unlock1, _unlock2)			\
 static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T1,	\
 							    lock_##_name##_t *_T2) _lock; \
-static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock
+static __always_inline void __class_##_name##_cleanup_ctx1(class_##_name##_t **_T1)	\
+	__no_context_analysis _unlock1 { }						\
+static __always_inline void __class_##_name##_cleanup_ctx2(class_##_name##_t **_T2)	\
+	__no_context_analysis _unlock2 { }
+#define WITH_LOCK_GUARD_2_ATTRS(_name, _T1, _T2)					\
+	class_##_name##_constructor(_T),						\
+	*__UNIQUE_ID(unlock1) __cleanup(__class_##_name##_cleanup_ctx1) = (void *)(_T1),\
+	*__UNIQUE_ID(unlock2) __cleanup(__class_##_name##_cleanup_ctx2) = (void *)(_T2)
 
 static inline bool rq_order_less(struct rq *rq1, struct rq *rq2)
 {
@@ -3229,7 +3240,12 @@ DEFINE_LOCK_GUARD_2(double_raw_spinlock, raw_spinlock_t,
 		    double_raw_lock(_T->lock, _T->lock2),
 		    double_raw_unlock(_T->lock, _T->lock2))
 
-DECLARE_LOCK_GUARD_2_ATTRS(double_raw_spinlock, __assumes_ctx_lock(_T1) __assumes_ctx_lock(_T2), /* */);
+DECLARE_LOCK_GUARD_2_ATTRS(double_raw_spinlock,
+			   __acquires(_T1, _T2),
+			   __releases(*(raw_spinlock_t **)_T1),
+			   __releases(*(raw_spinlock_t **)_T2));
+#define class_double_raw_spinlock_constructor(_T1, _T2) \
+	WITH_LOCK_GUARD_2_ATTRS(double_raw_spinlock, _T1, _T2)
 
 /*
  * double_rq_unlock - safely unlock two runqueues
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 3f72b1ab2300..1c5a381461fc 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -459,8 +459,9 @@ static void __used test_srcu(struct test_srcu_data *d)
 
 static void __used test_srcu_guard(struct test_srcu_data *d)
 {
-	guard(srcu)(&d->srcu);
-	(void)srcu_dereference(d->data, &d->srcu);
+	{ guard(srcu)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
+	{ guard(srcu_fast)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
+	{ guard(srcu_fast_notrace)(&d->srcu); (void)srcu_dereference(d->data, &d->srcu); }
 }
 
 struct test_local_lock_data {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUGBff8Oko5O8EsP%40elver.google.com.
