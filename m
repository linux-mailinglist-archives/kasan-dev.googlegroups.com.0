Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKP6S3FAMGQECJ6OQJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A1B4CD1EC8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:10:03 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4ed74e6c468sf30022921cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:10:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766178602; cv=pass;
        d=google.com; s=arc-20240605;
        b=QFSqRSRu7fg4k1GQs+txvMpGVal/o9AkqLm+00XMnBw2k4CWfDcV9MMTWGpVzhxaf6
         CKTAufCIGs1vycnRk81UkmhHCeDB2bKsWHlYWW8RKMV9xL0rpbC9qHfq7vSEk2QC3142
         NOaKDyQBAUFzSfFP3E7OGbjIp3M3CT1XylOU8ikymktJjKN4zZohDkKqRMHCP1m6ZtRF
         Mp4IT0qIeGWeBSVKqdk+NcKc8KKxwVPfvDMSeKIf1Y6aDajPkK3vhczyk49cRLUcRsEe
         zw/ZQgWyci3tTKpzPMKXWh+gjI61aNsWqM1uV6bNHXRY3rR81Mdmq0xRsZj2Cd9IiAwX
         kHDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C9m31yFGOl1vU945iZ/kxqfH4WCzbdwrj4+AnchJkQ0=;
        fh=xLPgvO67AbOpubB25KXBnYgXxSIxClGntIVfJoXYXTA=;
        b=gT5PAqzo8DrQ0EawV7XdNbPDqOi1UuUU3beepBRdhHnpBRrVVSw1ZX0mmdffWnQrQC
         g/aLOMX6R46Kj0CZqw2U2QVqCHhHx6upvYTz6HgVFq0ocwMPCR1iNbSE0YQTtcKhVshh
         DK3YLhwCny0NJyo9D4PD9dLGhD6nSQGqnA/iKMHv1aAwgFWe6pTltpBFczeQGzaKyLei
         bgoqlKq1ojr7dXVmd2RyA+Ex6aEhWhkB67sDhuAXXIUTdH3CaYXdWAB/V/XhVapnQArW
         fASbhGY6IBXjx1Qh4mVaN2iapRrrb+2hDMI68jtR/fPJqkNpw81xJII0pJvQ3JnW7Da7
         W8nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2ydPqv4K;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766178602; x=1766783402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C9m31yFGOl1vU945iZ/kxqfH4WCzbdwrj4+AnchJkQ0=;
        b=EVYV/snMcKtZHgfVnRHT01B1ODLlZTbnn0AH50yCgKcbQyW9KwPjrdjRfXlKSLKppS
         N3+CJjwY3agcldcS+2m87biYF3P8Tc+p0Mt+1etQb8q6KKU1zRFzKoswMrumzu1Bh42j
         VrydJKyhKExuJH38OE18a4uJtllCJ6GGlyhcZ/Ls9oUiHhbgFoeze8A97KQGfIDooEJJ
         8NMJ9bp5PX6KhOaLRP6pywxO5t/bCd0/xm8Yihy/i8LmTQ65Vx5WVaf2Sh7E1KADXWmm
         wtsW9dQhortaxKcgHUIotKSGhaCC0T1dNUdWiALOtCPRflN/UkW3ob8OPnMmKwKmr/n7
         CIwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766178602; x=1766783402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C9m31yFGOl1vU945iZ/kxqfH4WCzbdwrj4+AnchJkQ0=;
        b=wZj9cw83ySrZcOD3gZjyTcHTNmOMNqIrMssuK1uq9EtZySJhVCFo7a32+Q3SDKzcRX
         0PdaSeFTkl3UG/hApuK1Zc459tslMB0FbPFBkAJ3r0szjr845OCMuFbGydUeG9jzmRFV
         YmVB3fxHpuaMfr4mX9soK7diSn1EjGDpP6L/X3FqOfQOUTyUFYJNdgjdOwaooXsGxAsg
         jnx4H/BjkwRYXm9OPbUxt+rLQ6/GNKnjPmE2ypWcBGx6Z6X9SB3yNv3nRorkplucmKq3
         lsns5kUiVWa9OM2E4VhdBQ+Vjrfn1pPmSl3mreTr+pYGHTi2IH77uoRrNvsSWL95g4y2
         2hxA==
X-Forwarded-Encrypted: i=2; AJvYcCVPY6mFpnoeJf//UsEwja/cF/811Q8NMJ1OBZeB5Cvj4FEbiG1i9ximhRdlW1YOxbvUqEjePA==@lfdr.de
X-Gm-Message-State: AOJu0YwuS0idCY4mC0ul92CgIyx1VeLhWXvy9rDtWMUsDiBJmdKbYxnv
	4DzY/YmYACH5OWNnH3RizlVxPVt4RR8RYkHsMO6EhJUq59s4Xc/pGbYi
X-Google-Smtp-Source: AGHT+IGCar3UNdYkj8oNEwIc5hkYVjOatlWouAlXvCvIBT8VgAGFaN0nzZ2LIXGtIp2Mx67UQsm69A==
X-Received: by 2002:a05:622a:3cc:b0:4ee:11bc:bc9c with SMTP id d75a77b69052e-4f4abdc5595mr63690731cf.74.1766178601595;
        Fri, 19 Dec 2025 13:10:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZzxnXn+Y8vL88biwFtjChcrrCISwxmvghrbed1+JDhmQ=="
Received: by 2002:a05:622a:1391:b0:4ee:1b36:aec4 with SMTP id
 d75a77b69052e-4f1ce9673ddls168542011cf.0.-pod-prod-08-us; Fri, 19 Dec 2025
 13:10:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUCi25DcwwbnPfbtU7a8EUegyDR6ig04HOC8IkqlS+xrDBHJydnOTHZp6QKdS7oRGypuUAT9BVFpyo=@googlegroups.com
X-Received: by 2002:a05:620a:4488:b0:8a2:e1db:f442 with SMTP id af79cd13be357-8c08fbef6fbmr704487785a.30.1766178600660;
        Fri, 19 Dec 2025 13:10:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766178600; cv=none;
        d=google.com; s=arc-20240605;
        b=KPI+4fNQkh6baxA3Uq9V4vUAf2o7mc4E+AG7o41XWQ2VqJofbVSuUn5Q8WtJ7YHX/C
         eYlAHbitOAHp11uV/ouVEoVdN4t/IOA/gPZ7CiuC48JoC7i2b4FEPb9PDKwkGDBXVGHE
         qFTbco1fT0pfRb7FQGU2UPM67vceOmrf9Olg780xbswntv+9zsZE+7aQLovtwyeESRfd
         yfLSGva0fyNa6OocosQ33G6+74TfVFJXfOoMBLbo4rafJmFWxjdYPBcMTS/43GuNLUrk
         MAnnKvS5QA7hIiHhYNpo/KLDCYWHdJSp9vcxOD9l56z4i2upytc42aOgJwDokseWNadv
         DAZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iqhEYrpWgm5Yfz8pxMwX3Z8XLhEcxpfARdS1KcSLhis=;
        fh=j145VQ0u6hoNxheLFv6YFVMVnKYUKyqfvrDT1bROVJ4=;
        b=h4CnLTSqEIMPGPpLp5v6PzYuLJBH++DlJgX9cDba/6/9VvaVY3cc3cdP/qlf56f6ZY
         VTRIc45k20L90EAYyq5xZDA+SOH6ZQCOqvrYU6jraIh1bT3r1heTFLhmwEPqcrb50jVE
         MM1Qho/RI/2PEr7YQ2DMXHfVBBQw9VGe7OFPcwBbdBOWqh11UE/+ovV9Qyh7Lrk39xej
         I2OvURQ79V9jwVWe60P8IcFZqCshv0RcJvghKo6kxC0YsUJUx/m8kaP7KAUHR4pI55dE
         nOjdmzCC8itdrkjw2Jxfe6hAszpOy6EegG7Exj/zb/dneQ3cgVINKpADjJA49EWYQfPg
         jQSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2ydPqv4K;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c09658e696si21377585a.1.2025.12.19.13.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:10:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-34e730f5fefso2178377a91.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:10:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGd59gw2gFQk3nBGDzN4W5E6plapD9qB5f9zYE9D5EhB8Gb7BsAGnZPZ/E3RW8wruobk+O7BL41Uc=@googlegroups.com
X-Gm-Gg: AY/fxX5QDaBBMweyFXWBsyrQVSKuDJvGN7SxAfgg0Mro+NIq470JxtmxbGG3HFcC/tz
	uBk4Om0k0ZvAPbQvHQC9hSNFb/ilNxA2fvp5zeiEB/Gmv7b63phnqw8cGBmeZuwdA6/pRu5djGK
	sMWJQUmFpJaDxInGZAL/a0tq7pCjpLWCtEAMvEc8qkTaVKz/ynaqrp+Eup0LF0HsIPLzfDIE6dy
	lEnozZQAM2mpazdSC5J/qUCnuMAvApLrhOvkKdJiOI+lcW8Cn1IqhYboFjdcoShKVW6OpSwKkZx
	BngN4I/apfgOqGfni1xhvHoQHvg=
X-Received: by 2002:a05:7022:ef0b:b0:11b:9386:7ece with SMTP id
 a92af1059eb24-12172309509mr4284248c88.43.1766178599422; Fri, 19 Dec 2025
 13:09:59 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-14-elver@google.com>
 <3b070057-5fda-410e-a047-d9061d56a82f@acm.org>
In-Reply-To: <3b070057-5fda-410e-a047-d9061d56a82f@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 22:09:23 +0100
X-Gm-Features: AQt7F2racRCVQBtX1XHCEqHFLvRozCqLgqx9fCp_0Wp28A2qceHYZ0Bj23R_eEk
Message-ID: <CANpmjNN6QrxwUUkpAopTfxLwUqGfB53J96dwOWHNcoYrOrEocQ@mail.gmail.com>
Subject: Re: [PATCH v5 13/36] bit_spinlock: Support Clang's context analysis
To: Bart Van Assche <bvanassche@acm.org>
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
 header.i=@google.com header.s=20230601 header.b=2ydPqv4K;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as
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

On Fri, 19 Dec 2025 at 21:48, 'Bart Van Assche' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On 12/19/25 7:40 AM, Marco Elver wrote:
> > +/*
> > + * For static context analysis, we need a unique token for each possible bit
> > + * that can be used as a bit_spinlock. The easiest way to do that is to create a
> > + * fake context that we can cast to with the __bitlock(bitnum, addr) macro
> > + * below, which will give us unique instances for each (bit, addr) pair that the
> > + * static analysis can use.
> > + */
> > +context_lock_struct(__context_bitlock) { };
> > +#define __bitlock(bitnum, addr) (struct __context_bitlock *)(bitnum + (addr))
>
> Will this cause static analyzers to complain about out-of-bounds
> accesses for (bitnum + (addr)), which is equivalent to &(addr)[bitnum]?

Only if they decide to interpret never-executed code (i think the
kernel has various dead code that's optimized out that might trigger
static analyzers if they analyzed it).
But this could probably be improved by using a different idiom, and
using an empty inline function that takes bitnum, addr as args, and
Clang simply takes the call to that function as the context lock
identity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6QrxwUUkpAopTfxLwUqGfB53J96dwOWHNcoYrOrEocQ%40mail.gmail.com.
