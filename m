Return-Path: <kasan-dev+bncBDBK55H2UQKRBGWP57EQMGQEXEN3QIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 81398CB88CF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 10:59:56 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-37f98ab7cb3sf4336821fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 01:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765533596; cv=pass;
        d=google.com; s=arc-20240605;
        b=QncsW4Bs+K5/kY6MEAV/xHqV4npzC93+ei9G51GGVKJKReZGMI9cANOOnJEKbJGCS8
         IgZqCy8DREy+A6iD3R+fA33RUnKMbEi7kNXHyCV42kjbKirRy3NmaZvcfNx++iCTUE05
         gjsCaLX704bByB9yyMoEMmWQlahn9CKoEGz5xtTKEogNfoUoUTrWlPtCI9W2Bd6J+gXc
         o3Ec5lMjXlbtsnlQRquDVXa8HmCoFYqky4XOn5TSmXdL2xkZvO4Nibm104kfl2A7pm2K
         924PLu2zUiprXaGfFlcZUIX1e1iOk5FBXyBKFENgXrGZOsdJTJPuWhs8qkHWm2bYlg7G
         mFVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FxE7gKH3eVx0keJBmFwY7X10Xk4qlXsYQOvzmdx0wxw=;
        fh=X8cPw4hfLQ7w9UHCv+pB+5DsR9RnlKGYw/aS9PxktQY=;
        b=igxKYpNy5Ir6uFUvbLUPQkySJmuBmu9KPMiSpdZKMx4vHyzDlVG4o1Nv/hK1udYFl/
         xiIEiTsKvY5IxiDHItggQgND3C04Z7NP5Fp2mlbxYuHGe+VuHvwbBRBUly/fdYWvv+P4
         4pHx2NPt7Hm2eiAz7ZL9LfIuBUOMtju8C9/W3x0rWAdbF3NbrObk1LDVVk+w8iNDNZz3
         SgNMCoAVBkR+pRZkQcycsMYd5OwABXaigtsCBhpfeId+lVm6UMHRaEvm7zZ6rNutr5vT
         y9wgY9Jc7CGN6Iv8ij3wr0OYR4WYODlAQIFnzdesIw0v8QfQfW4zzqIxX7PkVcKxdUSs
         icIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=q4PvE8q1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765533596; x=1766138396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FxE7gKH3eVx0keJBmFwY7X10Xk4qlXsYQOvzmdx0wxw=;
        b=Ra2TekFe8x2vmYlqrmiDL91XNFS7awUsYl8K0he52DERlcoHgeOOJ5peJ6EGY+cWI5
         /rg6G9kx7xBrBa60ntOA51mrpbPj2mcYf4o/ldHxlLpjlVZZ47bAbsdZPVwqecrv3bBE
         GYIQak2atiDt2OrbDhfMOmmZfZ4hbmjPW6U4r8WOY25Xc+9xNq5XysEgy1IVezq1M7H2
         TcUOKMjGN2829edRM4Jn9vuMwDKiG9l+Ph3cgbqlGVL6wavyyHOV+nfbsmyGYnDlBAL0
         9ARo9i0mhhg9tN7m0nGOotuE0kvVnUkMs5FiwtmlNSqSV56x5T8G0SAdrlFlhEVN/Fe8
         e52A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765533596; x=1766138396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FxE7gKH3eVx0keJBmFwY7X10Xk4qlXsYQOvzmdx0wxw=;
        b=V7YrRKWlZDhAcV3XioaMK36+QVA1WyfeRAnsfsRhdSySfgXdj5jQyp56pBCVBu30oS
         UxCA1bGf45KeK/+VjGvFdTz9JpC+xGhedNJx3/QA+sCCf3o3Hq/+XdjJKdFNtXfL0wJC
         zCugWBZNdhm9SBxF7O0XOR05/qn26u2AsQM2Ee6IIpZkuQBKg3xzIzgZzsU90oWYw8iH
         lAFOLd9TaScQkOsKOTH4Syo5JMyoaaqyZ8XUqeiqJteE3BdJgzAlXzix5XtEVMB79I4Z
         ZUZEwMrgJmJXG3YL04vltMg2IucoDqsJCAeEkzrPBQr6UqMENcNVX5PcNDs3Mm5qfFS8
         +jJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWveTkp9vrvybe/3YfPxpr826JqWuler/Kq4lqlug96LDfTWoWPsveOZE6D2f/1NtGZB2r/VQ==@lfdr.de
X-Gm-Message-State: AOJu0YxHeHPvJeXZnISKbatooGbZt9JE5TejunpkaOgJPW2gNwZJcnlf
	cLMplPaXVJMASuzL/vtd1X7lPGumhTZyEoGiDvJ2avymy+y+uFEniEzw
X-Google-Smtp-Source: AGHT+IHIykT5Wiri+3sLuBkCbWDuuv/aeUDGPr5+8DZ+o8r9Fd3sLF5TZX+IkEKfciejAMK5Wsimlg==
X-Received: by 2002:a05:651c:19a6:b0:37f:b2d7:8a0e with SMTP id 38308e7fff4ca-37fd070b348mr4386191fa.5.1765533595214;
        Fri, 12 Dec 2025 01:59:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWavc2SStVdNnWV20V2ireRbIebUUHAknJ82aujg/FN84w=="
Received: by 2002:a2e:9c94:0:b0:37b:9709:9756 with SMTP id 38308e7fff4ca-37fcf0defcdls492491fa.2.-pod-prod-09-eu;
 Fri, 12 Dec 2025 01:59:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMn9xv9Wtm9vTxDimNN7iFYO5J2F0vsmV35C1DCnUz0m8pV29CG/t8rxY0Rb1BaKNxElGdzQbZPzE=@googlegroups.com
X-Received: by 2002:a05:651c:1548:b0:37b:967e:d73 with SMTP id 38308e7fff4ca-37fd08a2359mr5155701fa.29.1765533591742;
        Fri, 12 Dec 2025 01:59:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765533591; cv=none;
        d=google.com; s=arc-20240605;
        b=aX7R9HIAzdTg29eGZYHEPGGsaxqRGrJ9Ox1TnIy7srkLx9q7+VFebdXjr0IGFMwDMZ
         33UGG1PZs4tNZKtPZ/3xz9qXntvJDcjwbFoEbaQIRZxIGITHUoug+BY56q2T3mlqM9yb
         tAFHQsmKtRhhs27u2jGvBh9HCxBDxDUzDB0OdC2eakYscYyYszQITeJ33HgtoIoRIywK
         AIt3u3jrMp+tVjTKpXhTIClkqgRy2PWAqVQdXfDLniZQTUmkyk6MANrw38E1To6Y9P6j
         5pmDdGRACjqHeyaWD+2MjN8ejlVQcTAHydumrwbEeBo7B7nVIrL8WBdnMSKV/kGau8au
         JdSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KSM4F9EPA4VrHSATWZaVBC81vHU19MDt0Mi2nP4hTcc=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=fH8U7F33HTGqNsSNeFPYXzrbJjvoCFD+D7M6+HarcLvCF7qaKQRfPPDG6h/nCSfxnX
         1Op2Wdm9a1cEW7zaxIOmGH/0OEW6nWTHMVD/Guurl6lxO398MuJOPCvJQmUGGpMZ0+uf
         ZfEF854RQAfRQEvq3pOSTaYdkM4MyYjAbB7cL7fGbyZuYvE6Jv7nTexhd9AZbE2K3mhe
         jvViNgR/PC5d1O/g3tcfT3mgP5TE5qOdaxp5hajcC2xdayXB6hdKkRLo9w7VsmQK5GVA
         u6SrhJmqMfI1BpsezksewGK5tGe5wNe9l2KzrAoaW4S7i6ny6/ffLylBlHBEAmE891eM
         eYsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=q4PvE8q1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fd29cb6aesi143761fa.1.2025.12.12.01.59.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 01:59:51 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTz4d-0000000GRLd-1uSY;
	Fri, 12 Dec 2025 09:04:27 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C2F3930041D; Fri, 12 Dec 2025 10:59:43 +0100 (CET)
Date: Fri, 12 Dec 2025 10:59:43 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
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
Subject: Re: [PATCH v4 07/35] lockdep: Annotate lockdep assertions for
 context analysis
Message-ID: <20251212095943.GM3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-8-elver@google.com>
 <20251211114302.GC3911114@noisy.programming.kicks-ass.net>
 <CANpmjNObaGarY1_niCkgEXMNm2bLAVwKwQsLVYekE=Ce6y3ehQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNObaGarY1_niCkgEXMNm2bLAVwKwQsLVYekE=Ce6y3ehQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=q4PvE8q1;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Thu, Dec 11, 2025 at 02:24:57PM +0100, Marco Elver wrote:

> > It is *NOT* (as the clang naming suggests) an assertion of holding the
> > lock (which is requires_ctx), but rather an annotation that forces the
> > ctx to be considered held.
> 
> Noted. I'll add some appropriate wording above the
> __assumes_ctx_guard() attribute, so this is not lost in the commit
> logs.

On IRC you stated:

<melver> peterz: 'assume' just forces the compiler to think something is
  held, whether or not it is then becomes the programmer's problem. we
  need it in 2 places at least: for the runtime assertions (to help
  patterns beyond the compiler's static reasoning abilities), and for
  initialization (so we can access guarded variables right after
  initialization; nobody should hold the lock yet)

I'm really not much a fan of that init hack either ;-)

Once we get the scope crap working sanely, I would much rather we move
to something like:

	scoped_guard (spinlock_init, &foo->lock) {
		// init foo fields
	}

or perhaps:

	guard(mutex_init)(&bar->lock);
	// init until end of current scope

Where this latter form is very similar to the current semantics where
mutex_init() will implicitly 'leak' the holding of the lock. But the
former gives more control where we need it.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251212095943.GM3911114%40noisy.programming.kicks-ass.net.
