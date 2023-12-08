Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH7LZSVQMGQEXBB5GUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id AD86180A74B
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 16:26:24 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-77f46b7ef40sf156099585a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 07:26:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702049183; cv=pass;
        d=google.com; s=arc-20160816;
        b=SOUJ4MseJqfbNmXGMj7QNqkwHenuDf9Q+PlwWTwY0eQU/RGXfhKttLpZp3vIyeW8/W
         gG/vYxIj2s2zc1zYJNVMEaiE1MZMAG0WasSm8eJXMrZ6/pq+viUwR95eojXFrYxpK8GK
         RHr4I9gDxFDUN5WBCZr2tSEI01qTMGr1Sq0Me8dITABqAtWI0ynNgSErh5q2WE1gTwAE
         vX+sIgqmBkZm5O440MxoM+LPp7BvKqhtwpRfoKHPU18OOSxLvX90hA0xbN6CxjpgmkSY
         kl0Rwpe7VQe0iitdqIppzYApHga9/EfgOVZhmnFakIxU/qn/kFXfXdyalWKEuerT233W
         XzdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dzDTh/TgH3pd4Q7PYI26FQKrEcdYRVoj5lbm5BqWO9U=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=MSSSSPgmnFPF2pByRHnUXsIxQ2n6AQ1m3T1p8c95c7rIzzXNwbncfHePFCVubtArI2
         /CR8I4Cl9XNf7WTATjgKExIgt1Pjinu84AphHE77pXWZxv9lQIMRNn0BidUFa9HIQjqN
         zhBw2gXWV+PR/AQ0iJ6gbOR6ajZMxjH4EHvkQXpRjhR7lIc1v18N3hcE+fNxHvtym3ZE
         eJr7tLa9oobC+SG+/e2DwPaTaY3LNGFVdRCYm8aHQ99c4FLxSqd6++rc77/hH8/I7isg
         tzJdsG5exo+pvDs4SGZRy38XLDwVPoPV+3OiZ4zIjzKpAolhPlwVPufC+bLMc1O81XOI
         qx2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bBnNAVJ4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702049183; x=1702653983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dzDTh/TgH3pd4Q7PYI26FQKrEcdYRVoj5lbm5BqWO9U=;
        b=MVtdprM+yF+/lVa51XLgRkqtkcsqcKAcAdN4bXo+nXHcHd2pHIeM6lYP8C9/pcAE6J
         7bMZjWQZxhNq6EETqfbckl0Z3W486Ok23SFn/41s9NQlkTVFiCgV+fUhcudBRzwtSa0z
         jUyOq91FG/pCfAtnGi+9tkZvhSTM84q5bq3pDYYtEpO4WXeoC/9+DFiyNc0fEuEkj28X
         4H5jKvis+FAlIvKYBUMcW2wfBAl7sDQS8ASUj8k4Fks2lMbeBcCunvtPKpnVdqUnG/ol
         iHODukDZaKoSShJo9EkzisJOPmxt3RHs9hQ2Dl/BrpXpgN86utPgcNzkYc+W7LbmTtOG
         P2xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702049183; x=1702653983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dzDTh/TgH3pd4Q7PYI26FQKrEcdYRVoj5lbm5BqWO9U=;
        b=ezU54CLsPvh4IKLzDi+hvOVqSFTWLi8jYWYGWMiqQUkMapI9xAskzugWYMCPenz0PJ
         oSeyom8hehaJCNY41FX662NJRSRU1OpDlEtIu+YLhJsqgqEimgjdQimEY6SC9iRDsdUG
         DzF0YPHOy58lqDMDlUcXC7v7pZBeBoZrOZw7j2ISzYS0Gfc9eQhc2syoOWQOjjNY151g
         bKOp437Q3CW4FvWR75UC9dwTBdYrZmPjaoEjBJ1RXmlcZzvkymX5zIhGKM3Lp+QEMIax
         LZoyTXG3AOCYd2PCv/Ka9BN6dj6JbaUaGJVy/LYNkEl6kchmzHdH4PhG32+JWvf7uehl
         0sew==
X-Gm-Message-State: AOJu0YzxoLtRWwXqEo+Mk+pWYQjKHmRzvzxBK0qnVCMulDdaR4wneM5g
	N7OTN64NnUefHNI4MasZS+w=
X-Google-Smtp-Source: AGHT+IHUiU4vyWUWHoS7S3wekNlcm14ONiQNhFrayXTx47+bPBQtSyy8YpiDFCfBsJky7q99+sXQ4Q==
X-Received: by 2002:ac8:5bce:0:b0:425:4043:1d8b with SMTP id b14-20020ac85bce000000b0042540431d8bmr274872qtb.94.1702049183327;
        Fri, 08 Dec 2023 07:26:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1aa4:b0:41b:5e46:aa61 with SMTP id
 s36-20020a05622a1aa400b0041b5e46aa61ls1601713qtc.1.-pod-prod-02-us; Fri, 08
 Dec 2023 07:26:22 -0800 (PST)
X-Received: by 2002:a05:620a:a1c:b0:77e:fba3:58e0 with SMTP id i28-20020a05620a0a1c00b0077efba358e0mr215006qka.113.1702049182584;
        Fri, 08 Dec 2023 07:26:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702049182; cv=none;
        d=google.com; s=arc-20160816;
        b=NjP4FBewKNhm2uxBpGMXxiViXSfe6GIwrQ2Rsoo3KsdFAPUp9fnoLL/kt1IcTUvLV7
         xhKFyPovLvP0aY1eD1ILHFqVJYYZhwSQPt4GGLKn/xkx33swEeGPmV89gFvdUCQSnevL
         imaB0PRUQGM63izsj8zg0FHJgzLRFImmNdH87oq58m4zXCGvie9AJ5yaH085BT9z8zy8
         HapzhfSdRj7Pa+kSpmCXiI++PBs9j7pQHhRp2uU1RadOzLR3SyoJWcJSsMEai8UYNSIr
         dJLRdYGc8uiLKLFCIom2IH9mftrMw2rlKK33Jd7qovT5lXRJGLLCSUNi+mPz2RXI3b/E
         Gevw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fmveRht4WTP9VCfRGY2TlBDNiNt4nqiRyGovDc1Drhw=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=zCCo45KnUYWHr0kyx5G5L3334KnVtN8ThoSJsKsUaS+fvFx7QRBf2s5UghikpgmZts
         xe+XU6Xtw0K1o4+QQqO8rdE+BN1Wb8m/JPhkBGIugDGaC5LuP7MOriQfpSyom8uyE5XD
         hebym2ywWKNik0qn+lFPZC7YOpjR0eeCSg3+lme5b6sZvryiGUwsrKIij8fuvj059BJY
         SxpbJjs0rI7hSEQSNEmYlgrwelRiAeHe4mLuNNKgCU4klmHc+ohnkUmsPYKaWwhhG4J4
         5lRFSAHAvoBAzVNSQdxqKIB8AlX9bS0tEDlEeICQ/eockkiBFgasg3a8twji/IgXdPq0
         bW/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bBnNAVJ4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id ea24-20020a05620a489800b0077f09d5186bsi203588qkb.4.2023.12.08.07.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 07:26:22 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-67a91a373edso12402336d6.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 07:26:22 -0800 (PST)
X-Received: by 2002:ad4:52eb:0:b0:67a:a721:82f8 with SMTP id
 p11-20020ad452eb000000b0067aa72182f8mr105489qvu.82.1702049182002; Fri, 08 Dec
 2023 07:26:22 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-14-iii@linux.ibm.com>
 <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com> <69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel@linux.ibm.com>
In-Reply-To: <69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 16:25:41 +0100
Message-ID: <CAG_fn=UbJ+z8Gmfjodu-jBQz75HApXADw8Abj38BCLHmY_ZW9w@mail.gmail.com>
Subject: Re: [PATCH v2 13/33] kmsan: Introduce memset_no_sanitize_memory()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bBnNAVJ4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> A problem with __memset() is that, at least for me, it always ends
> up being a call. There is a use case where we need to write only 1
> byte, so I thought that introducing a call there (when compiling
> without KMSAN) would be unacceptable.

Wonder what happens with that use case if we e.g. build with fortify-source.
Calling memset() for a single byte might be indicating the code is not hot.

> > ...
> >
> > > +__no_sanitize_memory
> > > +static inline void *memset_no_sanitize_memory(void *s, int c,
> > > size_t n)
> > > +{
> > > +       return memset(s, c, n);
> > > +}
> >
> > I think depending on the compiler optimizations this might end up
> > being a call to normal memset, that would still change the shadow
> > bytes.
>
> Interesting, do you have some specific scenario in mind? I vaguely
> remember that in the past there were cases when sanitizer annotations
> were lost after inlining, but I thought they were sorted out?

Sanitizer annotations are indeed lost after inlining, and we cannot do
much about that.
They are implemented using function attributes, and if a function
dissolves after inlining, we cannot possibly know which instructions
belonged to it.

Consider the following example (also available at
https://godbolt.org/z/5r7817G8e):

==================================
void *kmalloc(int size);

__attribute__((no_sanitize("kernel-memory")))
__attribute__((always_inline))
static void *memset_nosanitize(void *s, int c, int n) {
  return __builtin_memset(s, c, n);
}

void *do_something_nosanitize(int size) {
  void *ptr = kmalloc(size);
  memset_nosanitize(ptr, 0, size);
  return ptr;
}

void *do_something_sanitize(int size) {
  void *ptr = kmalloc(size);
  __builtin_memset(ptr, 0, size);
  return ptr;
}
==================================

If memset_nosanitize() has __attribute__((always_inline)), the
compiler generates the same LLVM IR calling __msan_memset() for both
do_something_nosanitize() and do_something_sanitize().
If we comment out this attribute, do_something_nosanitize() calls
memset_nosanitize(), which doesn't have the sanitize_memory attribute.

But even now __builtin_memset() is still calling __msan_memset(),
because __attribute__((no_sanitize("kernel-memory"))) somewhat
counterintuitively still preserves some instrumentation (see
include/linux/compiler-clang.h for details).
Replacing __attribute__((no_sanitize("kernel-memory"))) with
__attribute__((disable_sanitizer_instrumentation)) fixes this
situation:

define internal fastcc noundef ptr @memset_nosanitize(void*, int,
int)(ptr noundef returned writeonly %s, i32 noundef %n) unnamed_addr
#2 {
entry:
%conv = sext i32 %n to i64
tail call void @llvm.memset.p0.i64(ptr align 1 %s, i8 0, i64 %conv, i1 false)
ret ptr %s
}

>
> And, in any case, if this were to happen, would not it be considered a
> compiler bug that needs fixing there, and not in the kernel?

As stated above, I don't think this is more or less working as intended.
If we really want the ability to inline __memset(), we could transform
it into memset() in non-sanitizer builds, but perhaps having a call is
also acceptable?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUbJ%2Bz8Gmfjodu-jBQz75HApXADw8Abj38BCLHmY_ZW9w%40mail.gmail.com.
