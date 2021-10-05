Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHPY6CFAMGQEW4XLFNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E829D4225B7
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:50:54 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id w9-20020a05660201c900b005d68070ebc1sf18856642iot.19
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:50:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633434653; cv=pass;
        d=google.com; s=arc-20160816;
        b=YN+ftyxkpSFBhGrLoeISnsbEGGGhpPQj02vYEVzoYdC7ZYehqsnrjBDKq5Ub0WCK8J
         zWTKdNas/KVLsJvF1Y2sEBapUyihxHnrU4bsJSzw86lnXPAqSiQFn9f+yzXQ7aqtDquY
         ptkIuH3BgonrylFpjV++FpwbBf4LDCB2PKQPVEyR5PBmBivJK4ukY/qqsNmk29QkCfaI
         fTRFUzpjSYJ2aCpQHlRAbfui4tGoWL8ACkC1wrfByOXSiWBf8iH0mljDQkikj9nI6Wfu
         QCC7fk5B+XeemHMqbUy3+00BiqtSEQVbkVJJeAeHaVwp/A+b1bH5UbtuJ93EY9Er32Au
         E41w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XBEM8DiSfVILFOuJARSQeZR5m/znz4XmYfxTP0g1ARk=;
        b=DT9ciGNo3W8hjWcpqPUUYv1WRsWYJAoqQRXPe6qP3yNEu/DWe5BEYHOYdn3fa+p+Ek
         rCc0U+IeYoyCfrIaV3XDv8XTLCSaXe5WaP3IwUrcGVRBaLounSkyqK3FBqfDJox2XFaQ
         VP4jAbxIl8ufnkbm647rHQBVnXwwt48E/nUCT3rCTqEKVyLThqLbeXYE7WyCf8E02Z9C
         itPmT7cPQvy4QvDULIJmO6LssBfRe3LXjzCMgC0i2Fwh4/6ws357/zyU5fj9kQgIK2dX
         qx4gSFW7W6h5aoH4Br7JBs18WvV1JeB8El968YOCqC33EVi8cwvKymh4vl/n+0BdBF8k
         tWbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AdpPxdZ9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XBEM8DiSfVILFOuJARSQeZR5m/znz4XmYfxTP0g1ARk=;
        b=UFDMh+NjnUsMGq1WIfK+yyXdz+dw0K4HZMXDtP8X7slt82taliJ/7iK7dDwUvL6hkY
         O7fiNUXyJQqDpFPjFCap7u1ZPxr7ZjN48A3EDj6RZ+k6rYjLeNiEY95Rh1eK/f7/33sn
         0CsFyaN2w0rbOsKg9xe11oD4oSsV2xP+FaAITKhIdsutzSa0dcJ36PD30z+ykR+07vty
         Sb865xaEORsz6QbqTtw8ooMb0GgD1ABvI4nDv0Sk9YPJRIZpj1N9mirBTsGe4WXdezDX
         QmAyVlbBxg7lavJNBs5erFs4C85oaNyKRU2v84cGw/yfp5QQxyl3ygyg1PPwdQh1MKGt
         dlCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XBEM8DiSfVILFOuJARSQeZR5m/znz4XmYfxTP0g1ARk=;
        b=dJcHebajjdn89q0BYSUJbu8XIrkiluCFVmAP0CePCasEcLry4TjxKaCL91qVvuHRY1
         CIZ95JBHhuu/QqQRKStHj8GNVcAtHQppBUZHX6clvuiSC/IFC3YL38DyScMzJGspAN9M
         9obc7HdfBIraGFMJ17FbDCX1hv4H6Mcl2jlHcMMTQqUUjOB/cK+SQ5GRQgH7kaRBn4+K
         8HcL/7tgSqTPuI4xoDzi8htL6WWdFLdgJe+r8I1RS/pIE245Gs3pmFup2qpD7YHRhked
         IxMu4RF40i6WHyKAt9BGCiDZEn3ZnzEuue3oVZKEQO3KtL4jbiIeVSAu61sZPrM6CO2z
         SYJw==
X-Gm-Message-State: AOAM531mL1BlrvaVQbYWC3FDky8nDeym3AMQENWumtHjb3qZsTG5g7X8
	kvKF7cpZwsU7bj6lLERN430=
X-Google-Smtp-Source: ABdhPJwAtjsFNC3VQQmMANhbXUepoeO0qt+lUHdkCZP58J4+l8T3phjWUIw0x08BZSmVXUjByxkA4A==
X-Received: by 2002:a6b:cd8b:: with SMTP id d133mr2052246iog.88.1633434653741;
        Tue, 05 Oct 2021 04:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6a0f:: with SMTP id l15ls3016733jac.8.gmail; Tue, 05 Oct
 2021 04:50:53 -0700 (PDT)
X-Received: by 2002:a05:6638:538:: with SMTP id j24mr2285048jar.39.1633434653387;
        Tue, 05 Oct 2021 04:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633434653; cv=none;
        d=google.com; s=arc-20160816;
        b=EAi8emkem9sAjOgBJOjIgufuzKN59zNetuc5H2+CKDI7t9eRa6DrfiDauL4A3cDLLf
         IKUVc0NwkEBzZ72+ffKVD8Z5Y//XTUEDS5+UPsRQtDizVXBfDBfFceiTOrpfNtmq2TFx
         p/4Thk2PxlhLhE3KkoSfGrv30cIu/sFAEeIEY7QOHQT9qiykO4DyoPctbKTE++Znmt3/
         z/4z4M0hXJsgvXrMoIeX8pfdi2FSj6swuTl+milfTpBi/J5Jsrp5o0+ckCWWu853h366
         VUoBJMu9Jklw12xBPs9QAYW/hndQnL9sBaaor+772Gn+0R8Ih3SaL3brLmF8HX790Wvo
         6H2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZXyHYhWprLF6VOTKKbJ9elBPTHHvHE5sqZFrMqC4ukc=;
        b=lMDM0vkU4mipVcaQMzxGRtZODw+z1b3CgQSJkJ2IsilvFgiXHeQ4x1ZJ2ZPWg0j2Ho
         iZXY2bne5Ql5KBkkOSfBf15GmBNgVu0zlzPkVGDCLty5Nj4r0b8Whmt4PUMqBCPnlYpL
         f7XINl0GVmdD60XscRYZdz7Mw/F9ShMgDMgwhwo4yQfNLoQNOMnyjcNBWu6CrRNX80Cy
         oq0vdwexoKIpHYUHUv0G0sKiQKdHctpW0D+M4d2Nv+u8yjwqvLaPU13z1Lg9wYH937hj
         W14b+0OSzA4KopP61ZAmUx2+b8CIhmXvFIWMFoXzpW5xPGI2uara4g5aDSjJUgqMSnj+
         wmNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AdpPxdZ9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id p184si818059iod.4.2021.10.05.04.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:50:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id n64so25866865oih.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:50:53 -0700 (PDT)
X-Received: by 2002:a54:4618:: with SMTP id p24mr2068916oip.134.1633434652953;
 Tue, 05 Oct 2021 04:50:52 -0700 (PDT)
MIME-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com> <20211005105905.1994700-6-elver@google.com>
 <YVw53mP3VkWyCzxn@hirez.programming.kicks-ass.net> <YVw63tqctCMm+d7M@hirez.programming.kicks-ass.net>
In-Reply-To: <YVw63tqctCMm+d7M@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Oct 2021 13:50:41 +0200
Message-ID: <CANpmjNOXWtUg9qsLJ6m9n3GYZf-AHE_21=zLnFnUMDBHMP2umg@mail.gmail.com>
Subject: Re: [PATCH -rcu/kcsan 05/23] kcsan: Add core memory barrier
 instrumentation functions
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E . McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@kernel.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AdpPxdZ9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 5 Oct 2021 at 13:45, Peter Zijlstra <peterz@infradead.org> wrote:
> On Tue, Oct 05, 2021 at 01:41:18PM +0200, Peter Zijlstra wrote:
> > On Tue, Oct 05, 2021 at 12:58:47PM +0200, Marco Elver wrote:
> > > +static __always_inline void kcsan_atomic_release(int memorder)
> > > +{
> > > +   if (memorder == __ATOMIC_RELEASE ||
> > > +       memorder == __ATOMIC_SEQ_CST ||
> > > +       memorder == __ATOMIC_ACQ_REL)
> > > +           __kcsan_release();
> > > +}
> > > +
[...]
> > > +   kcsan_atomic_release(memorder);
> > >     __atomic_thread_fence(memorder);
> > >  }
> > >  EXPORT_SYMBOL(__tsan_atomic_thread_fence);
> >
> > I find that very hard to read.. kcsan_atomic_release() it not in fact a
> > release. It might be a release if @memorder implies one.

You're right, this name can be improved.
`kcsan_atomic_builtin_memorder(..)` is probably better

> Also, what's the atomic part signify? Is that because you're modeling
> the difference in acquire/release semantics between
> smp_load_{acquire,release}() and atomic*_{acquire,release}() ?

Sorry, just a bad name. It's about the builtins. The above suggested
name should hopefully be clearer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOXWtUg9qsLJ6m9n3GYZf-AHE_21%3DzLnFnUMDBHMP2umg%40mail.gmail.com.
