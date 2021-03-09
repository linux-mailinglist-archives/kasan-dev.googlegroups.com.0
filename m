Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDPHTWBAMGQEP64CBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 619B133262B
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:09:34 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id iy2sf10079685qvb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:09:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615295373; cv=pass;
        d=google.com; s=arc-20160816;
        b=08Edr6Wug9nr5z4ukAY5KN5dU/3Vhe7sOOmTP23Bzb361xvDunzrmcAGcAcw44PxHm
         HTTWx5n9H7Ov5SOFLH+dw07eSBQJMquTgZKkI6Qp2xlJl3Tqq0CNkIJYdKbRZnWuZpyF
         jk1/HBMQ3cpsBodMFdjmw3Ni4YztDxflcHCq9fBhLldFBSw03l/ndEPLVl1Gr8yakH5r
         Hp07/fWE94NCNo49ipBytWmOckmB+4IKnE7ZchAlxfUxNybRmTc3HXrwLWlUh03UI+Ou
         9MRV+uAZg8cZMudHkDE9un5RCb9snXQtIFJrGGtwyQg5U7BG4Lxow2pUxVo6/ZnyKPOi
         fvcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0MgCORlekO6i++iwzpoYePaAI0GhlxfrT+g8tgiPagQ=;
        b=M8CF21m2y7LENrF6fEESMkrlcOrQk3DoKsUkHxzTRg9NamD/Ed+WbW1G+uNh4aJJvt
         AnpRaQu1JEGmbubtCpw8mEDBiwXMI4XnnL23sdSkPoiBj8t0nbo1ul/sw4s4W4D5F+9s
         ae5m5XlIcTbrZ4XGCDEH/XC6FLi7Rc97iJkFJaucPWL1mtDIXEDDuxyyq57xQFt4BVjk
         9QaytXa/7/pa2umud8g6AGCRkMUTTars/0og04EF1AhgmjARW6DUV6CV3JQmqCdmtbe0
         bEpCymHfNxJj2QHT+D3EyYgwG4QhsWWt301/vGNmhH50EP9JMU9XHXLUwC+UFyIqlBVA
         Ypog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l11KSv0z;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0MgCORlekO6i++iwzpoYePaAI0GhlxfrT+g8tgiPagQ=;
        b=UQ8ubnjufzwlBBOe4zmhS9psSkTIc5NQEE5Fh8Rw15nVnsTu6/iAu6JkXITFSjmYUr
         dqEEOCqF4hj8r10kIkI8gGUmHmUAePMLju4tlmWcZYx5E7ABEqy4SueyTAqymsKWnwYs
         CVgMEVsyevltLf2H0CSVZbkZgeyCKv2BiaD4qn7+bZJBvLfFA896gzylf4qUwnUOXv+z
         AT3TZK+GLPRABcITfWlNseazp5Yvasg4Yy3McdXP6R1ZUnJR5PVV3XeBJKKOlObiikny
         wshGi3l4rM7Aki3aWbZjB/wdRXqEmUX+pbibgOJC6CBixVIuFIaTeIRQDy5pcnwnh1dN
         bOBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0MgCORlekO6i++iwzpoYePaAI0GhlxfrT+g8tgiPagQ=;
        b=OP324GX63ybUg8W6/TcEuUnjvOSoarS+sCnfuDp/czIkd/XWzWFY1JKSAOzEchTclT
         C142GQ4SipMqkhZIWejTldKJC6SN+O5F0ZNB9z/LRegyQkyZbhwxwxrUS7IUIAakWnA4
         kPufc83C89vIeTe1cv5R0deDODljkgCMUzGMM6sNMg6Huw6plPJBaDKgvgzWjszIxf3M
         kd8kXvCuBBlGSCRCU4+4fqrE+rhBBAv30wE6kHhY782eu9FldaGWeiE9wUwgc0monNgm
         xTQ0tJqZJjRUpKSnsfvShHk1FXlsvz7EvZt8IfgzAxbkrrLu6Ap5cILfTVyuGlxPgHkM
         8OgA==
X-Gm-Message-State: AOAM530FsPwU72ZqLJgLtP83s/m9ju5yN3L82BwlEU1QZb/Ak6aCPoJn
	dzGT1tzTCgCz3zYPdI0qF98=
X-Google-Smtp-Source: ABdhPJwmN4hpoVLr9uLeH4lg4kIZDtdi2nDwWOkrXoPOjC7lidkZZPcDQWvVaXQ2XzgAPL3aDCzigw==
X-Received: by 2002:a37:a913:: with SMTP id s19mr25701328qke.158.1615295373219;
        Tue, 09 Mar 2021 05:09:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2583:: with SMTP id fq3ls5253479qvb.2.gmail; Tue,
 09 Mar 2021 05:09:32 -0800 (PST)
X-Received: by 2002:a0c:e84d:: with SMTP id l13mr25457642qvo.28.1615295372807;
        Tue, 09 Mar 2021 05:09:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615295372; cv=none;
        d=google.com; s=arc-20160816;
        b=iluKBIfNOhvJqm4mlH+rMycW2SBzINndpCDbE9mLdo7jxiYrwwzP420kvbYqL/UtAI
         9bCO7tH50VTTtFEQCs2y5UZiw5JHomfIsbHdLJcpogZgBonAwIH2BTBHPDkMFL/RBROJ
         hMLzjjmuiVqWbcphWCed1ZYXWzTmQbAPxY7TQzw1r3RGC4hnXbE3wYUMlqrU/EKc+1Nv
         uFY5wsZsnYD7wYNllD3PJkf8vwJ4EeoZ8xjdCYbMGSyH4nBPy+yMDJzJXeYXsE4IkYgd
         kmqt6ajAvjGEHJSq+VcB1K2iRAlnUAEFZ0SJwORDE6lDXTV5SFBG29tRdwvK7cmbxr3/
         a58Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sbY3FA8sDFV7e3j6jkZbThLGcOzdkl8VfF99h6lt0u4=;
        b=fR6gj0On/bPhxMLrcNdumDDMqCK/8mF9KXnl35LhxBTWhaH1OCssdDH5k1gPWLytC1
         o9AzpY1q+Bhd02IfItHSbn9OOI9Rpq8i2F/e9pXMIXU5H2EL85DFykv7oUXzOoLJFP0c
         yihNsVdwB1byUaR+V5jDjYPhXMQTQpAR7UoM8FETFr99hghul9+8G1KKRHIHgPUgZJXP
         LFO3kEB36f1w7QvM3iDRAH21Pp84GfaBbYDPnTlggMkStnY+145oF23YeCtmhmZB0R7s
         TAuytXwFGU2KUqiCHb0Yu/II8DC6T0x6NEMnyhPLJzXnOwNJ9qB3ZanjmN0nuFKbbJAn
         3FdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l11KSv0z;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id u17si903426qtb.0.2021.03.09.05.09.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:09:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id l2so8729433pgb.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:09:32 -0800 (PST)
X-Received: by 2002:a63:455d:: with SMTP id u29mr24462220pgk.286.1615295372295;
 Tue, 09 Mar 2021 05:09:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1615218180.git.andreyknvl@google.com> <755161094eac5b0fc15273d609c78a459d4d07b9.1615218180.git.andreyknvl@google.com>
 <20210308165847.GF15644@arm.com>
In-Reply-To: <20210308165847.GF15644@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Mar 2021 14:09:21 +0100
Message-ID: <CAAeHK+yaHufdycvawHAQ-Lt9GHKrGkzKkdJnTA3qN1MTtwiS5g@mail.gmail.com>
Subject: Re: [PATCH v2 1/5] arm64: kasan: allow to init memory when setting tags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l11KSv0z;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Mar 8, 2021 at 5:58 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Mar 08, 2021 at 04:55:14PM +0100, Andrey Konovalov wrote:
> > @@ -68,10 +69,16 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >                * 'asm volatile' is required to prevent the compiler to move
> >                * the statement outside of the loop.
> >                */
> > -             asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> > -                          :
> > -                          : "r" (curr)
> > -                          : "memory");
> > +             if (init)
> > +                     asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
> > +                                  :
> > +                                  : "r" (curr)
> > +                                  : "memory");
> > +             else
> > +                     asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> > +                                  :
> > +                                  : "r" (curr)
> > +                                  : "memory");
> >
> >               curr += MTE_GRANULE_SIZE;
> >       } while (curr != end);
>
> Is 'init' always a built-in constant here? If not, checking it once
> outside the loop may be better (or check the code generation, maybe the
> compiler is smart enough).

I think it's worth moving the init check outside the loop anyway. Will do in v3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByaHufdycvawHAQ-Lt9GHKrGkzKkdJnTA3qN1MTtwiS5g%40mail.gmail.com.
