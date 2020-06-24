Return-Path: <kasan-dev+bncBCV5TUXXRUIBBXUMZT3QKGQE2KWPCEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B14A206E41
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 09:53:03 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id y133sf814632lff.20
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 00:53:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592985182; cv=pass;
        d=google.com; s=arc-20160816;
        b=m7QzYF/SN+m5IVT9/yK4/iijuGtp70zfElDbGs6NVx2By79OptmvbLkLOmQbxHGfN9
         dDXTgTAWlYyfX2Tt2/w1BF7qlqfQT86xj3ohpi0X4056hA0XkPeR1puCY/RvgE1Z3rKn
         6uj5LeI0BYaJ/4chvamjn2FqDKCuFEQPIQ2yWQTMs5d1NPvpevvlKACQ3l/5hRh9Dy3d
         SCUPI2ZDEWS4QLwlxjRnzvM7ZtFWLqX3EH710SMh9zbjCr/ZHYHFOItPogrpIcqy/Wae
         f8zTQrDcygjKAF6EbVKk/JBNThZhcOD5ID7aFLhLbeiGgAtedldtNFCR05F8rRC9CnIT
         MBVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=acVS/HLHrPGoTNPl5sdkiz30hvpEQ+/i6NL1X9F8y4k=;
        b=l/8GsTMPN50msCuhkaFYDbD35vCnzAt2TwCIZxGN/mJWP/iY6+J/ANwJb8hHqlMtD8
         VCoZ5wSRu7QVtaGJA4toKq2D4ur6ILGURJo0pyhk25LSlgRZTS6BDTOgAYmn/jvrZ/9I
         9wLR/cx2bPq5RSpOvOvMHHHR3+bLUtQLYOPtGRW7oOpYE5PvmPgD8kIbx3kEIL7EIppX
         yZwTEc+TPWpG6xZ1FPS5F2ptQ8Zh9JhOKBOm2hKXh9+IUtN/gTKT777jmEIQNBoRV2lZ
         /lW66wvfdVRw6Zx6mA0eABM3PLNa9kTclBx+JtmgCNIRHiwmBvID1fdYGOYO9mUCFFtO
         UqZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uN0lL8PQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=acVS/HLHrPGoTNPl5sdkiz30hvpEQ+/i6NL1X9F8y4k=;
        b=S2rTAVsy3SNbWD7/QKhnLYEP9H0wEOmXMndUMa+oddfkY97afruJHY59bLnoUQW7By
         gfmgrYYATTxiXLHonVvFMWUH9WuIdTTYelW3wEZ/i2ko737iNVsVKF22GFJZmcvZ9wFk
         Oio9tYYVIBfP5442F5XKIJ6zx8dKQ5gzy8l2C4LhoqepXnkhgXlMO/gZ+Y+7FmHFdzgS
         sOfRp5MeSW2yLIozKGHX3L5fgAiMRAJkrA90sndMKEe4JVxh3/eLOWsfbVowPwWe9XaD
         Dv7kdxzo/I6l63DLPDn4SBNCBgsvHQqdkNguIYbzB+tXvW99DSJ88H+0JABV5xXmxx9l
         owAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=acVS/HLHrPGoTNPl5sdkiz30hvpEQ+/i6NL1X9F8y4k=;
        b=PhBXh1801t+EjKb9/6b4vKdND+hHIs3QxhMwEDUPH0PrtbgRfFP8Dfra0bQgF+Hlhd
         N/9P3zqs7c/d7KuLtAlqnUWZ90wkUU8XOh5E/WpYvQwnOuwKlLLou9bn20it76+7HrDz
         cC64uwN9J2PoDwhLTyfk/08v3fPWKasUN237yBizNy96BF8KZUgkFwrF/vSyP7n2EZZX
         t3umOOkQTGNyDSW2vdfYQLzQmMnQm83hHxzCNoHu41MBEPae/gXnePlv27SXDgRQOX5W
         vcJf+Ao8wnNzm7gxcc7m9brm0kn3D/oraYKieufcV4RVKDqhKRpj0cs1tovunQU5jWfC
         fxHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533N3Cao5QNLVb2QjPri9Vq36cQSGO4BqRXctP0MIxuB2JdOVgrL
	O8lc4ZsHWp2MCvK1AIqFktk=
X-Google-Smtp-Source: ABdhPJx1Ewuf9e4U0ZMzqj8GpV+DPHVr/EcPC6jx5axQLbUFDlUYeAcRo4cI8rmI45cxG58O9OG2Qg==
X-Received: by 2002:ac2:5df7:: with SMTP id z23mr3346385lfq.18.1592985182557;
        Wed, 24 Jun 2020 00:53:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3047:: with SMTP id b7ls358650lfb.1.gmail; Wed, 24
 Jun 2020 00:53:01 -0700 (PDT)
X-Received: by 2002:a19:8a07:: with SMTP id m7mr14767827lfd.31.1592985181784;
        Wed, 24 Jun 2020 00:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592985181; cv=none;
        d=google.com; s=arc-20160816;
        b=Rqwr0Bi9aop3Dj27pYa/XGV8tmXaykj39Mp4Hs86RFpC+0j5aIdZq7uRf9M/NKQJUx
         ZiXUn43AAgMLewU82wvrb5OU9dbYu8cfmfz7u3Fo0Xl/NvDM5c/T3ttNwRwVa85fkmfZ
         LAOXT5OVRRj3w1uOD2yQCt5+6pYfc57mQX7U5lIy9IpNZiiaZIgYKooIPKwdwJ7QYH8P
         D60tP4EXYhK6DpzCGYcVpcolPDgLDwM/z6m6FMrW6oI/R38ktz8L2CbD+qHH1HnFBZXc
         78NcAfPUZKF3ucwrMc3VSb0hOg1Eztfgxr6MVKHmOzf1dnrkwUMqwnOfM4HPf3osnxbd
         YmbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5T5TvBb+88tPNfoiiFDEVsZ66I1kFN8shpVe/RD6M+M=;
        b=FER4AgiKSzIsL2dHLNXlS4q0QLXNydS0I4yGlnHElGVPIvOin2Q1reI9LdSjf3FRTR
         lKnCpxsow+LUSkt7V6wKtOXGXAqTieoeWHPIWJLyu/7P2CeTj8Wu1VSOlgGnkXhYPZZa
         i0gbTdLgAhN32iXPTb3vhGvXD8LGxug+d6NCwiGCtfI30SGu7gSAyijGrE74SqiVT77N
         +iGQqKXV28bmVO5jdkSyQg4aUVi0DEXrEP/MH7Nv2nz14G8DjbxgUmsWi7T0K1fTXAy/
         JGJLkcfR7q3VgrlX473uZCaMUCLH4t8PjSyJLLt8ASlcRUt8OyYH89hjamooGG1s5vaa
         afCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uN0lL8PQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org ([2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id x19si87788ljj.4.2020.06.24.00.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jun 2020 00:52:59 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jo0DE-0006vW-Cv; Wed, 24 Jun 2020 07:52:52 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CFA25300261;
	Wed, 24 Jun 2020 09:52:49 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id BDCD129E7F8A0; Wed, 24 Jun 2020 09:52:49 +0200 (CEST)
Date: Wed, 24 Jun 2020 09:52:49 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200624075249.GC4800@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
 <20200619221555.GA12280@paulmck-ThinkPad-P72>
 <20200623204646.GF2483@worktop.programming.kicks-ass.net>
 <20200623214433.GX9247@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200623214433.GX9247@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=uN0lL8PQ;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jun 23, 2020 at 02:44:33PM -0700, Paul E. McKenney wrote:
> On Tue, Jun 23, 2020 at 10:46:46PM +0200, Peter Zijlstra wrote:
> > On Fri, Jun 19, 2020 at 03:15:55PM -0700, Paul E. McKenney wrote:
> > 
> > > Just following up because I don't see this anywhere.  If I am supposed
> > > to take this (which is more plausible now that v5.8-rc1 is out), please
> > > let me know.
> > 
> > Sorry, I got distracted by that NULL ptr thing, but that seems sorted
> > now. If you don't mind taking it through your rcu/urgent tree for -rc3
> > or so that would be awesome.
> 
> Will do!
> 
> Just to double-check, this is the patch from you with Message-ID
> 20200603114051.896465666@infradead.org, correct?
> 
> Or, if you prefer, this commit now on -rcu?
> 
> 	5fe289eccfe5 ("rcu: Fixup noinstr warnings")
> 
> If this is the correct commit, I will rebase it on top of v5.8-rc2,
> and if it passes tests, send it along via rcu/urgent.

Ah, I was thinking about:

  https://lore.kernel.org/lkml/20200615162427.GI2554@hirez.programming.kicks-ass.net/

seeing how I added that instrumentation you wanted :-), but either
version should work for now. KCSAN is sad without this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624075249.GC4800%40hirez.programming.kicks-ass.net.
