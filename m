Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJU25PEQMGQE6SKP2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E77B9CB61AC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 14:54:48 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-297f8a2ba9esf1531765ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 05:54:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765461287; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZGGqFuh1DFfxQMTXOu8/chn2lPLp16X86NsIavnoD+LfS+vWE0521upGQVwZpNlX/m
         q9lNWkcPMupVk2v5p8FGD8JCFQ0qTX44kBHHqpVtc/r4+yGad87WSrkm+VyAXWe2FWQt
         cZVgIcSaZmSgfg97dMjCWNq4k1vItrS9vRyEwUgC+hLX5GrVxfHsrK1So2DejGDbjun7
         NmtY7DUfbBpG3P46YJX3d5a+m14jB8YDkUKZStN9juk6MrGk2ZWtIxr8hywK6namYpfw
         qFxYhumGbHqFA7lJc6MdVOfQlSBpuU3dICjYE2OV+tKzBdJIWaX9I1spLpN5iR6n9RWS
         NUeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Wtdo4iWS5W902+0VaCf4+cn6M3rfBBXuW8I2zqCtT/A=;
        fh=uVloqVeUqhG2RnCLgqp7g5t8Srz8YIPZGqKxbwpNbhA=;
        b=IfzMu6elxj0ZKtij9bCWzNlEy6tFAmm8OROzzvsX2IL/5ZDS5jR+cJED3hVdBalohu
         Eu2DB0LBBxAv6WtwfgNCgB5IvopOqAtx/9ZAYZlNQBh6vnXZ4Cllms3Qg1kRuiWWX9VU
         r+iRfZjcx1yVj//hJzTR5VnwdNc+/FrHw959jVzxuinUfEinPDHW8+aJIVqiKXsrvZeq
         9qBS5HfnVObH2Y5KtBwwlMWNATH4tQPDR0XWhKQQcEl3jdI1N+MDEHbEfvozue6/chbq
         UPFZ5/3D7RAF0AvnvMITSyVNnbRwTFVxmpNyGnQ+ca6NXiLE+PZDaq7s2CP8TcPYqcsG
         byyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xKGBTy3B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765461287; x=1766066087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Wtdo4iWS5W902+0VaCf4+cn6M3rfBBXuW8I2zqCtT/A=;
        b=L7KZSGE8mIwgc0F9/ginruPmRIjPxlr+lxyvsjm9lHNCk2kZiGoyyUBuZSwiSKmE4+
         5vw3cwfHgy3xtBh22LoW0JujJKf2Jl0TRVAWq28PiP83RzDXS+4EseEu9OYx8RUW09ow
         rppn0ao/Fs9pMLKgtMPga641tEo5TuznWyC0AIJiTmMSiW51mUmKRlrLvcGV8dI+fR0u
         8pmfMF+g2BKq//pasWKRDfjpKKayTUZdOqBaP9jVz0Ip/ZQ4wxGSSS08iq/1bm21LgU5
         DrKeLWoExicI4dg+tQLwxOgL/5t039G9Jc3qAzt5k3TnU4prtGkHcxEP4fwGPW6+hR2s
         lvYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765461287; x=1766066087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wtdo4iWS5W902+0VaCf4+cn6M3rfBBXuW8I2zqCtT/A=;
        b=jisMOdLCLfv83pMaCANjmM1tdYb/kAnNXxkRTmQ8EjpYzo/5BJXtLg9gyNIoP6V/Wy
         36YSaVBEnK1/c4j2pW4Lm3jSmxSfOvIlUyS4B9o0ltQ9bjsfk0dqCAjrPVDOSjDPzDL8
         q7bL+fqodBcLr2JskMazKtav0j0zDFhF62NkLJYRsbOEG1ikTNq3t7NWzQnixFWd5mmg
         3qajewu3l0uCXS744bpG+Q58RmzTxdmMB8OIvS75tpcrGcDQp4ycVohUXKo4Eu15RkNs
         LoH3hXuN6fvqFPCDYp7hieXEauyeQJQIDjcz0WKAnutjrQHfM6yiot1zLARsrg5P8pd+
         AYQw==
X-Forwarded-Encrypted: i=2; AJvYcCVkhme1ONfiP4LI8jfsnKn+HEziJ3n5DACiaUhpWa66OESGwY4Avu1FOhrhsz4fP7G9e+Id+g==@lfdr.de
X-Gm-Message-State: AOJu0Yx8haescGKuPFGhyiyFDhNKCgKDOqBJSqFix6gVG9sPokXsojA/
	h4kmtOoEuM5VyGHziWT86TtAjIdODr+NnJtOwdzy4U+0A8kJt4/iy8sE
X-Google-Smtp-Source: AGHT+IFnlm+vDwZ61/BUTsDd0aoBHRMEdL0iFbbqgT+DR6AFQ+emdsQHPKGbHuOajs2fop/dMbKu1Q==
X-Received: by 2002:a17:902:d581:b0:297:fbff:fab8 with SMTP id d9443c01a7336-29ec26b99b8mr60548335ad.21.1765461287224;
        Thu, 11 Dec 2025 05:54:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZsSDCjxeAbdpAyc8RDnfDxaOUTzWaTBi/Ox9mmzWoj7Q=="
Received: by 2002:a17:902:d504:b0:295:68e4:74d5 with SMTP id
 d9443c01a7336-29f0feea216ls63105ad.1.-pod-prod-01-us; Thu, 11 Dec 2025
 05:54:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXroM2j2lqzjVu1azglJlwTyQRhdZMpvtQTJccgQIN4PKTdoXmwz6p3vtSm9gKAoroMKd7mjiEreWs=@googlegroups.com
X-Received: by 2002:a17:902:f708:b0:297:d4a5:6500 with SMTP id d9443c01a7336-29ec27c5bf9mr69356135ad.26.1765461285403;
        Thu, 11 Dec 2025 05:54:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765461285; cv=none;
        d=google.com; s=arc-20240605;
        b=Fs3cMyb2n5LFRKFNj+eBvxWfKQEWp5JAXy0p4xNrKm8eBG2Cq4G7vAqhIgq16LPj2y
         d00AVUVhs25inxsYJ7CWqsXJeIYgmFVuD8by+EHDdQp2jyKX3aNmWrCGlqQmvL/0tvd4
         SJPrZ6aqm2aMI9VjYTH5wYfpM636sk50a6h62WlIHLUVt5oDHWmGC+DjdZI1izosinOC
         UAyo/m5GDUdng6O3SfYrGaEgzswmyWTP2i9qv5HhoaOiYgxEpODjDlZeI4SpdkoytuFF
         NjH2qRZQcuzFGX/GpBa4iKxwgFQuAoQmP0c7iLbr7kuOcGUjALXIKyecCvPRMx6LTzzW
         eU5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aWRPRAJ89lgq7qGLYK1gyasHO8BcBnTXm3hkZRbZKOw=;
        fh=fmqz2zaKDzGnc9ugu0+5dz606oFKX+PVaJW1S4fSJ8w=;
        b=MOblfqmDivVSIHkBDw1voixRc1TxZUOLcg8YUKHKWghvlJN59nvw75cv4VsdMD/Iom
         HXfOU8D1mI+knCQVFCBY9mxuStLO4ulK5mjuaCntaxN5w3ZNcw1mM3B0PvH32xav1Ymu
         Jyd6u/v8mFUdmhjkzdzau60Vbo6XbS3DqiqlDzuknkIkD5zTMOmKLPdbWPMz49X7eS1s
         j2QtIJFEwcWqSrrXJLzKh1r05J3y4kwRmZ65e5xeyuLPxsR6krmz3GXPRRNs/aQxGjsc
         dBODkO9uywsyvuXFmsnNJQZ4omMDdfOwBfMRvux1yIwFxrGRdew02EnH5yu2EEs9bAcb
         91Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xKGBTy3B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29ee9dc9716si1112745ad.6.2025.12.11.05.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Dec 2025 05:54:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-295548467c7so1154935ad.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Dec 2025 05:54:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWnsA/zc8xS781lWCwQ1ZbhdjYIHptyT7N0D4yNm9Tx6Z8LT1ETwBr2VCEMoY57WrZbnGV1LZ79lsc=@googlegroups.com
X-Gm-Gg: AY/fxX5nH6QdYZ60dEAwTmBmRFtK3/6H3FYCnd/FwfF4E4DIkEsZry9ZxyWGD57v/gp
	nPbO/56p9b+iegZBIOVtRrmyJfbq0gjd2KIOaKTSRtDTFwsY6iyCP9O+Z02BNGtnhFzImBqfH2l
	AbGOddcLc0eVy0LyJ5kuRuhNXloSk2Kq74zfA8Bc+aQG62XGRez0hsCtc2A4VEkl9i6xNUgorJ0
	A80YU3uXS15hpgit8gO17O2Lx6yO5kPhwii2jZZNV1wFHQyfEgZQXK2DEs1UzEMz1eK5/Fpajvo
	HHf7vLfmgBbCJBBtwDUJiwSu
X-Received: by 2002:a05:7022:2219:b0:11b:bf3f:5208 with SMTP id
 a92af1059eb24-11f296558d9mr5045780c88.1.1765461284380; Thu, 11 Dec 2025
 05:54:44 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-17-elver@google.com> <20251211122636.GI3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251211122636.GI3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Dec 2025 14:54:06 +0100
X-Gm-Features: AQt7F2oz75av79IX-Fsq5GL2dibuf0pX45-76DYGUr2aahssaITkwrN9Ju3gYq8
Message-ID: <CANpmjNN+zafzhvUBBmjyy+TL1ecqJUHQNRX3bo9fBJi2nFUt=A@mail.gmail.com>
Subject: Re: [PATCH v4 16/35] kref: Add context-analysis annotations
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
 header.i=@google.com header.s=20230601 header.b=xKGBTy3B;       spf=pass
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

On Thu, 11 Dec 2025 at 13:26, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Nov 20, 2025 at 04:09:41PM +0100, Marco Elver wrote:
> > Mark functions that conditionally acquire the passed lock.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/kref.h | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/include/linux/kref.h b/include/linux/kref.h
> > index 88e82ab1367c..9bc6abe57572 100644
> > --- a/include/linux/kref.h
> > +++ b/include/linux/kref.h
> > @@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
> >  static inline int kref_put_mutex(struct kref *kref,
> >                                void (*release)(struct kref *kref),
> >                                struct mutex *mutex)
> > +     __cond_acquires(true, mutex)
> >  {
> >       if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
> >               release(kref);
> > @@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
> >  static inline int kref_put_lock(struct kref *kref,
> >                               void (*release)(struct kref *kref),
> >                               spinlock_t *lock)
> > +     __cond_acquires(true, lock)
> >  {
> >       if (refcount_dec_and_lock(&kref->refcount, lock)) {
> >               release(kref);
> > --
> > 2.52.0.rc1.455.g30608eb744-goog
> >
>
> Note that both use the underlying refcount_dec_and_*lock() functions.
> Its a bit sad that annotation those isn't sufficient. These are inline
> functions after all, the compiler should be able to see through all that.

Wrappers will need their own annotations; for this kind of static
analysis (built-in warning diagnostic), inferring things like
__cond_acquires(true, lock) is far too complex (requires
intra-procedural control-flow analysis), and would likely be
incomplete too.

It might also be reasonable to argue that the explicit annotation is
good for documentation.

Aside: There's other static analysis tooling, like clang-analyzer that
can afford to do more complex flow-sensitive intra-procedural
analysis. But that has its own limitations, requires separate
invocation, and is pretty slow in comparison.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%2BzafzhvUBBmjyy%2BTL1ecqJUHQNRX3bo9fBJi2nFUt%3DA%40mail.gmail.com.
