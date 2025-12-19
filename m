Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMQS7FAMGQEV7W4TNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id B43E3CD20B4
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:49:15 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-8b2dbd36752sf496216385a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:49:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766180954; cv=pass;
        d=google.com; s=arc-20240605;
        b=E02JY8J6noKx1hXLIVN2tzIxoobI3gXKz/Q4/MCneQnkvgCVDzUn8Fw+IcoqrWL8Jn
         lNXh9tmlGhc1I6wJy7HkT6KmQY9FAK5whRT00rRN5RyHI9wFb3IKWMMz1UTNJSVADI5/
         4kBd8g8GVcf9HZakUVDui7aNj62qMPnh4F+AcPBv8Mbm54o336eeMVPnavg+JWw5d4y5
         Qd2CPR2qp9X9EzBVDKxeOqaXr7I2UXyNAOrXxMMJsDJeYf3aBSJWzIi+AljpjbMReBnW
         lcd39VnOitrHhJhdD5oBG8DJstQVUd4yVbzqNeu8SpD9MRWfU/mSS9VpQc7eiCAcCOX9
         sqTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R6+wRRmIt5CRZn7l529hjI8keGkEXTL2N+TWG2WPU/o=;
        fh=psB5RARt+U7Cw9opvVx4M8RUTVIZD2D27kWDSlg4DXQ=;
        b=ZMgMfF592kpyKWtyBSnfxPNl8P6OkQzAbPHI4DdDGr/Xo6Oxw8Egd0RVvn3QzIsdnX
         59TmdfvrLIOaN/yL5wWsMV97MBOtsd7oQxfDQFXpl0UaNofIq/2p+h9/ZWuYSHtiMZlM
         7eSN8umDuhakn7h0ZWtmF5KVebTaUvlYvHToaRYgLWIcc0d2M3zFFLTiJQwQ0GSTUvaV
         SA4hbZDEIbJUSpCQMMpkSXqry4FsUnK5g9xysVAkbb23fqJAvMOksqOItB35MhV3GMWU
         2iJsutPqdzDPSPzsyS3eCrpcM07ivI10GirDzEFjrf9mdug8/ZQLLBn3JgydCYEKBBrQ
         O/kw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QFnJseMy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766180954; x=1766785754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R6+wRRmIt5CRZn7l529hjI8keGkEXTL2N+TWG2WPU/o=;
        b=eECsPFIFqwlT6v3vgcUnd3any/rZ0KWMcqiw3yfiPuPxTj2waLP6dABfVJcVj69McX
         RgXgKd+kRUSAEGv2XU6u26gEhU4WfxOKYE36rbulyOW9BIVx3+xAbR8GFQi54HKHovz1
         B22S0v4gOqDkpxwSWBGBDLqH8k+8Dpjy5sk55t5yEIFnyMXSCrxyIskxMIIe1cWkq6VI
         ohirsh3HKmlvyVliM8zfZrBn628rQg1rngG+LXWTgJIkxw1Y52E0801lnfud0RGMWaaj
         T+bGn4JMCXFD+cas4YO345Frg0OUJwiJ1GKE45SaUO+asrLhu8oN/8o+az6+ckHqaUQG
         lCmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766180954; x=1766785754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R6+wRRmIt5CRZn7l529hjI8keGkEXTL2N+TWG2WPU/o=;
        b=NJGMws1Ku0ajL6HX0Qg8INQ4uauOlf69TzhOGju7MllwqmUBECKwobuXRYMYnIcoig
         F92m4+lCkFQWxPNBOUmj8uMZQ+mCYnLz9+8NoPYN0rbvjXRjzcWLmeP9oEhvNrtmGGd1
         dS/kWTntP/PuhPzPkjnqll6gW3mGLhqWzf+naIy36C5EmGUVPJC6jsshiBy93gIN7V8i
         HBaGo5itT0igh9s1dALU0IGumJcgWl4VpXeghaXX8m5BGDIXHA5i//pIgiAqVNAp38VA
         1LZ4/n9MbIxg3ELxLI2yJEoLVCWKVL2N4J0yzvtJsBNOkHUg8+p1giAff628l4/7HXh/
         qZXw==
X-Forwarded-Encrypted: i=2; AJvYcCWFmzdHnKb1xa9IZtN9bGhwdIxh5UNxJqyl3oxCNKzyTTOknENnGkO1iAqexsz9y+tTIbMPSQ==@lfdr.de
X-Gm-Message-State: AOJu0YzMFc8HoCRJcd4eza7kA4N/ZbXpdaXIDZH/3Wrds6jC7+TragLL
	uS2rqlwjlRPEdfP4AxzdD6gB9un/fsSzxyekwLwBVRHTa7skgZ5g9MvA
X-Google-Smtp-Source: AGHT+IEy3ovbclxUEGoN4tpBkV6F/0+OdIfIsuU1tzgcPjV4H5gcU+IUD62QYOE1m5DMzPn5tKk0Tg==
X-Received: by 2002:a05:622a:4807:b0:4ed:7312:1120 with SMTP id d75a77b69052e-4f4abd75b34mr70232971cf.53.1766180954086;
        Fri, 19 Dec 2025 13:49:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYwrhO0E1PI8wAsLbGvzC0wAkDd7rjv3xYTFXE7Y7jHdw=="
Received: by 2002:a05:6214:230b:b0:880:803b:bd47 with SMTP id
 6a1803df08f44-88a525bca84ls67192676d6.1.-pod-prod-05-us; Fri, 19 Dec 2025
 13:49:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU83bwtSO1DCaPLtxkUMnwuNbTq870OnHqvBeozmFbXHQn69/MT2FrHI4g/FXqsc3zjDkO38WAlMDw=@googlegroups.com
X-Received: by 2002:a05:6102:2b84:b0:5db:fe0d:7fd5 with SMTP id ada2fe7eead31-5eb1a6798f8mr1468771137.10.1766180953342;
        Fri, 19 Dec 2025 13:49:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766180953; cv=none;
        d=google.com; s=arc-20240605;
        b=iQQ+CKLHCTsSHsSlsXAwPkvhMkNcrfOllG4fsvtG5xRjhiVNK4oIzF7swtemMc43sc
         kjJnxQUgcpwIejBIi09r/z4p+72WJHy4l4oz4f2kUeufxDzX0yUjHULH/49t4XsRPlzF
         9djb2FlglMLPzAUztmDkZE3J63pTxzovtHsIfJ8eXoNsr5XXu/J8t1XXQlnv9xPHI+Wo
         PMz871o0T3IsR8K0Ed47LLpy1yRs0yVX9yGEVEiLvVglBwlRbrm6YuZXIYyJhwolEr2N
         8ldgLptLWlXNlwDzvXKJ0iqfDwdguOXU6lR5Dq5WnlkgFBDOzXTrJgda2M4nheBfPYNh
         gWdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NzDuEDjTM8ZWLDMfL/9YFXqkNSYfSWOUAvfjFgQokA0=;
        fh=UeglvrfiERLGz0oK3TyBhSZ5WFm/oLAvBgaiL7HhdTE=;
        b=lggQkwxcxJTlSNr3vvBkwG83qTFj9SVUDTJRpOZmIDjmEvrsZbKbfYYpDf3xQizN5M
         QJQktEhzkN2qppZcmzfEuebPXTx1Z/vVQFBP4SsQfpYpc6XN9gV74xltOwK0iEVodwlJ
         xftFmKM7RRdl7Bqrxw+SDX4q6ytCCsXksVJbv9Hz7MdiW2/ivc/64ZwM/+/2nBXn/ByE
         8sHa0zrUhFQZ0kNEgunKHDk+P6i2iF9sQaXndcFD2j0wklnqYmDh0W+rB9JXNhx8yLVN
         yHAIcaRKJl/Owel6MV5MtQfjCTec5dNMlxslnCv7gbywUq+snYxBZ51H8r11QJ/eBRHH
         rE6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QFnJseMy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94341515cfesi187284241.0.2025.12.19.13.49.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:49:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7b22ffa2a88so2184381b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:49:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWzrbVVHPaTlS+mzMIbXZBm51akVAlhOE4Iu0gMHBycHCcXQHQ7hb9cpJ36ScZbPXqv7Hab/XQpOU0=@googlegroups.com
X-Gm-Gg: AY/fxX7fwYJVwL2bK7bclSA841qHTdUST8bxbmonlfsce0W+m8jqwYOYtov0oNav88z
	gIjpEQyqAktwXH/kLHr0hbexrjqKJQW8Gifj0bt0+7a78HfMUQFDTMrrqBg5Ep3SrWYdl1eOoEO
	YBacnL3dszqWe1JwvVHEAf9GAM7T92xfQ4GZprfRVYRlBgDGcA9lUEPSnihyFouHMlrnPvOUc+b
	GDmMzWLmkavje/Q27nX9/930kG8OGXsdofijsJ1mP17hMhMmtF0nYPmA2pApXULRVBJx4+VXn0S
	LBB1bFr6Em2eDfmtsJ8qz6MJb/I=
X-Received: by 2002:a05:7022:213:b0:11a:4016:44a5 with SMTP id
 a92af1059eb24-121722de1e1mr5781198c88.24.1766180951816; Fri, 19 Dec 2025
 13:49:11 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-9-elver@google.com>
 <17723ae6-9611-4731-905c-60dab9fb7102@acm.org> <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
 <0088cc8c-b395-4659-854f-a6cc5df626ed@gmail.com>
In-Reply-To: <0088cc8c-b395-4659-854f-a6cc5df626ed@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 22:48:35 +0100
X-Gm-Features: AQt7F2rGv_yg31bAGJRVSa1c9k6UbjL-L12dGmORxx_mEF1TxDypAURYmp5bQlk
Message-ID: <CANpmjNN4JNG1OSWfGd2fAqTyYQ+Re7Czn796WD-47TwmuECxaQ@mail.gmail.com>
Subject: Re: [PATCH v5 08/36] locking/rwlock, spinlock: Support Clang's
 context analysis
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
 header.i=@google.com header.s=20230601 header.b=QFnJseMy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as
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

On Fri, 19 Dec 2025 at 22:34, Bart Van Assche <bart.vanassche@gmail.com> wrote:
>
> On 12/19/25 2:02 PM, Marco Elver wrote:
> > On Fri, 19 Dec 2025 at 21:26, Bart Van Assche <bvanassche@acm.org> wrote:
> >> On 12/19/25 7:39 AM, Marco Elver wrote:
> >>> - extern void do_raw_read_lock(rwlock_t *lock) __acquires(lock);
> >>> + extern void do_raw_read_lock(rwlock_t *lock) __acquires_shared(lock);
> >>
> >> Given the "one change per patch" rule, shouldn't the annotation fixes
> >> for rwlock operations be moved into a separate patch?
> >>
> >>> -typedef struct {
> >>> +context_lock_struct(rwlock) {
> >>>        arch_rwlock_t raw_lock;
> >>>    #ifdef CONFIG_DEBUG_SPINLOCK
> >>>        unsigned int magic, owner_cpu;
> >>> @@ -31,7 +31,8 @@ typedef struct {
> >>>    #ifdef CONFIG_DEBUG_LOCK_ALLOC
> >>>        struct lockdep_map dep_map;
> >>>    #endif
> >>> -} rwlock_t;
> >>> +};
> >>> +typedef struct rwlock rwlock_t;
> >>
> >> This change introduces a new globally visible "struct rwlock". Although
> >> I haven't found any existing "struct rwlock" definitions, maybe it's a
> >> good idea to use a more unique name instead.
> >
> > This doesn't actually introduce a new globally visible "struct
> > rwlock", it's already the case before.
> > An inlined struct definition in a typedef is available by its struct
> > name, so this is not introducing a new name
> > (https://godbolt.org/z/Y1jf66e1M).
>
> Please take another look. The godbolt example follows the pattern
> "typedef struct name { ... } name_t;". The "name" part is missing from
> the rwlock_t definition. This is why I wrote that the above code
> introduces a new global struct name.

You're right. My point only applies to "typedef struct spinlock ..."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4JNG1OSWfGd2fAqTyYQ%2BRe7Czn796WD-47TwmuECxaQ%40mail.gmail.com.
