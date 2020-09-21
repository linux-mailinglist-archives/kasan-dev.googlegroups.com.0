Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVOJUP5QKGQEM5ZJFNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E7442730EC
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 19:37:27 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id c197sf9137411pfb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 10:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600709846; cv=pass;
        d=google.com; s=arc-20160816;
        b=qNF/kB6Lc4tRA+fPyOvny69lIUC7IuH5yrGSDpUfPiBOCz7JM4C3iOnbiU/03Htg3W
         T6CA6Xo+wiumHYBtpY4aurpABb83HlWlmcaQDks7L0asmQa1P00qehl5TshhDpSjBUzG
         aZRVryy/UVWtmDX7NoiT5uIkLFKOzAkHbmXv2jh/D1GOTWGipx/gwHTnvxhItljrSjxu
         5Ps5OmKTJuON1UFnTDwg/Cr7+F0TlaJF+pSiZQxquxMbRAd/3U8EYyH2+5IQtfOmBJAT
         iyW56Lifz2F1+HNm3xUPKJ4b/ZT6qbIWBoMOixFv33b9Eb56SQC14G/iqmMHB4ZWfijp
         EMoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rwg6IOPLWYyGeKnPoAUwX4xrHuH/lYw4Q+N5KtfSTZ0=;
        b=Xl8CP1rhuuiKmHUBbw/meEb7bBnQPRGQ+CXg6fdHSUXB6RPHfzn1AfVM9jUxB2chVz
         6dmJl34GkVehvH5EnvHMtfIVGW14Q4Ag+2oHzZkc4TQg3lVO2of2pcWYYE/arkmvhhdl
         OFpEq7MejooggFitSfc+g16TvLoZr9u78+7yrTfYl2VwlRE1rn/NSUz2Ko2oOtGLX5wc
         hrYFQrszMcm9Un6mN8jXC2pmAQldvxTAcIHvzp6b6t5fgVsGL3NvwGQbDG5LWuMxdfef
         K6tDZhpVGRBRT2J10KbMAmcw2AeFWHgt9SoGZOnivuSINeCRHlCo4HQTtiUUChyc5KBO
         u7Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pamzCqMF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rwg6IOPLWYyGeKnPoAUwX4xrHuH/lYw4Q+N5KtfSTZ0=;
        b=ECsCJdUYsthhGVrdwKoLmniv0ux/wWeID23wqLCi+OWlSXzSLzoHqNmbnNmWVpjmDo
         z/Pe6oUTblbcH10vQC6Dvu1NFlaLIYiNbkRwVt5Rv5TRxwsUs0ShUQDKgch6+rGUrPB+
         +8UYrnD/lGErWMPW+E31of2WliFM9NG+GBJax8y/+lnz24mUZsJN9Bum+W9UeWz2xy8k
         nbHfN1RgHY08MhrNGh1X3UHIxaK7cxfpwZTo1SvrkYbHmvFm4CepnPdOxFAoICeV7xnq
         +7gb4NMkGeTVU6C2K/tz9xNKAC0oR5fGEVVGaCR79hsALI4SwjFIl/ZrOiJsrnEiOZ76
         giDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rwg6IOPLWYyGeKnPoAUwX4xrHuH/lYw4Q+N5KtfSTZ0=;
        b=suJ2VDzKUFarKJ36/f5bOhYzu4AFsTAOke2uIYSvlcu25gP/bssv/ztay8iNf/Gyxf
         Jcuj7wdRm1rRQisvWMBvAFcPAfYiasGuN+tyPicwwlUzPr+fKfqCvoAOPg9Yfjk6KzCr
         NSBH1WAJYKJ7MbCib0aHUUG7Ay2+nIiwuix5W2fzRQaJa7TZPJFrSLmLzN1wz+etD6Wn
         NHIWpBfRflz2WU8pYkNmrP9LbQn+bUhN5VvhlrALm9DaRp2GheMf+yni0uWxxCxlhpMS
         ev019Redl1VQWzoqRFYjllPghjN9AFC++NejNe4eKeiN1wYsWdcSr7TGf2us5j+8PDYr
         9psQ==
X-Gm-Message-State: AOAM531w0d1SiCRBQPRT/Vim5jxDgMPOiX3Q6FNyCb3U03BoZ+N70WHP
	PISZtEKUkurwYTudsoHi+CU=
X-Google-Smtp-Source: ABdhPJzWWBS3GxNwOCdar7rzcsre8WfO30q2WXm3SL+mqU7cqyu22dL8mz3N2ftloZxot/EFuHEfQw==
X-Received: by 2002:a63:d242:: with SMTP id t2mr573575pgi.47.1600709846134;
        Mon, 21 Sep 2020 10:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2a2:: with SMTP id q2ls4862563pfs.5.gmail; Mon, 21
 Sep 2020 10:37:25 -0700 (PDT)
X-Received: by 2002:a65:68c8:: with SMTP id k8mr612770pgt.0.1600709845441;
        Mon, 21 Sep 2020 10:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600709845; cv=none;
        d=google.com; s=arc-20160816;
        b=H3GbfSJv6wOY26CV3I6c6AyyIhYmok6p/VhvC8NJnl3w252tIK/S4KSjqz8+T6UaHi
         iWdMkvl32Uyi/qewRSucFfaLTh5OuteirMA0EqRsq+UiAQku3F84Q+2ilkUOcpdPgjmr
         1WfITVcWpIeP/9xiudUi7TjtPNtGss65rB5DfltbRuV46wbuMDlW9IVroxh2xpHOs7fj
         iGLQE4Z7sejrrIJ6lGKQZ0Cjj+TL0/iyAsMCw6WufjzAl3/94gPkCRqgRgeu3lQvKudh
         muc6TOk/ltMlgOkXtFN/GU54Zna3cnlmtQbrevyeIqWLPtijIWr2OTEnv282H+i9vVMw
         XNMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SSZ5KD0dn5jNkyMg9eCMzr2gsc7k3aZ4lV6MBn/HzxM=;
        b=MdbXNyuB7PE/bWzbscsrRL9V6ewqerJYpbKK4Wp2rWSVZ5k1RDdIJY7fK4Q7M2uGGt
         TnYADcLPNYHnJsrhFVFTIS6fiIB3V2evEG33YUQOk/LApGMZ7MyXC+yxkvWepUh8ZT8Y
         AlTapE7UGCXiGQg/Hyf1ToJREKkiXxwypJSKQFYSY1NiEiHoFMs/IdLHvF+jlHVjMHPe
         fVjH9jCzqBQ5LmMCa3NTJRm2qa0efi/xgg3VYCZC1u0Wvm/CM/szsw47UGbQlsIFwfUY
         4jIUjZy29YYTHGduA8+1whzglRJpiMY59hWgaXp4I63AfglkuHIPDAMtMYuo2bxY50MN
         NVjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pamzCqMF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id bk9si15839pjb.1.2020.09.21.10.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 10:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id 185so17846879oie.11
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 10:37:25 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr303275oib.121.1600709844512;
 Mon, 21 Sep 2020 10:37:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-11-elver@google.com>
 <20200921171325.GE29330@paulmck-ThinkPad-P72>
In-Reply-To: <20200921171325.GE29330@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Sep 2020 19:37:13 +0200
Message-ID: <CANpmjNPiAvyn+oARU39yOx7zxMxV8JHiSS_41H+65D_-MKmk7A@mail.gmail.com>
Subject: Re: [PATCH v3 10/10] kfence: add test suite
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pamzCqMF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 21 Sep 2020 at 19:13, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Sep 21, 2020 at 03:26:11PM +0200, Marco Elver wrote:
> > Add KFENCE test suite, testing various error detection scenarios. Makes
> > use of KUnit for test organization. Since KFENCE's interface to obtain
> > error reports is via the console, the test verifies that KFENCE outputs
> > expected reports to the console.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> [ . . . ]
>
> > +/* Test SLAB_TYPESAFE_BY_RCU works. */
> > +static void test_memcache_typesafe_by_rcu(struct kunit *test)
> > +{
> > +     const size_t size = 32;
> > +     struct expect_report expect = {
> > +             .type = KFENCE_ERROR_UAF,
> > +             .fn = test_memcache_typesafe_by_rcu,
> > +     };
> > +
> > +     setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
> > +     KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
> > +
> > +     expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> > +     *expect.addr = 42;
> > +
> > +     rcu_read_lock();
> > +     test_free(expect.addr);
> > +     KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
> > +     rcu_read_unlock();
>
> It won't happen very often, but memory really could be freed at this point,
> especially in CONFIG_RCU_STRICT_GRACE_PERIOD=y kernels ...

Ah, thanks for pointing it out.

> > +     /* No reports yet, memory should not have been freed on access. */
> > +     KUNIT_EXPECT_FALSE(test, report_available());
>
> ... so the above statement needs to go before the rcu_read_unlock().

You mean the comment (and not the KUNIT_EXPECT_FALSE that no reports
were generated), correct?

Admittedly, the whole comment is a bit imprecise, so I'll reword.

> > +     rcu_barrier(); /* Wait for free to happen. */
>
> But you are quite right that the memory is not -guaranteed- to be freed
> until we get here.

Right, I'll update the comment.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPiAvyn%2BoARU39yOx7zxMxV8JHiSS_41H%2B65D_-MKmk7A%40mail.gmail.com.
