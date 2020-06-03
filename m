Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPUV373AKGQE2ZGLFPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F1AB1ED3EE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 18:07:28 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id x4sf2276278pll.19
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 09:07:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591200447; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYH/GxJ5j4jO3aqs7YxbqKSVovqVKZLPy26iS7BbiuUNQ+p5ASQfDw5r74BNXU778o
         mSVCIwPihZBnMqBaR/Dn83ofoVcCEOLK5Jk/d9mPfpm0aIeafrrk9hNORHW0mwZ7cbeF
         65nY1S+RtC/Y5crzytzJDNsJV4xtShxr2yaCxcoM/nTlPMwvBo287J715N/WZUzlEwVc
         sWAE4AIgBkHrrQ6F5nGV8Vv9iuj1t2rLbhcKZykxpdF9W/juZ4xYz6LMCbjFkipH3vWd
         qZopyVnY03+kmOBsrpDiZK++7qyR1TbAlyb+DkkPat7onJ/xnENmPpadGf8rA+Wz4rnl
         2rNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fug5ttuOmiOYJfQ6LluJT9KuJ+VNRzR7p5Ve1PCJCxM=;
        b=I6fmJJd7FEPM8Qu1iO40cg6YehbdX4dia/qyJzlc7zbfhSrdwrSK5kj5aVxC9f257w
         JtquFaULPpPdrcd8vncvvj8jlN2Od29LKlidjafvssA8lOpqM55e8wENuNHEdt2Q/D5P
         TR+XiWE3Km1ybciy4uiBqKL8ggtgVnpAmYn4JL7f/i1rt27Hk4+Nc7VbKEB62xmUXE50
         BQssWNJwkfR65WDW6C3Fij8F5IzH11mtwHVg2fH02T6OAHNRfPQLdZZKjMm2f6Ff0ork
         AbmwMfu3UkXT27PPAAU4+EzgGZjcnZqYyedYjphqJsqI71q+HK04CnqiOVQ9/Nkcv1EP
         skQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=qUTdWW7g;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fug5ttuOmiOYJfQ6LluJT9KuJ+VNRzR7p5Ve1PCJCxM=;
        b=JAXgFFxpaheVbSbwgxohBFfoOL326j6l9AWXUGrOPlBtyTvL/5BUtYxA1jfqiKlSxY
         58r4UAh83zZUGYZG2folGw4686qTxNed6X8+Y4v2flY1gwSQ0IAQEg10EPQVIsdqL1IE
         AVhXQaeU8x4ezX3qmeOAwNDOLHNOayx3Rd7Vi8eyfxClZ29eNIwJKBgbDBcrx/DuYz8I
         1AcpuadynabRcYHb/A6GCPMW6j+xR49+RuvKi8zC8CQlPhU/scwGEkSGaZ8pnTs549PQ
         0VQOuVH3p6RGQTq17alFD6AeExllMwxH/GC1rqthRrYwF2Zr2yx1+HNzkyX+REbEyqn0
         03nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fug5ttuOmiOYJfQ6LluJT9KuJ+VNRzR7p5Ve1PCJCxM=;
        b=BRPQCisPBWqR8r3hqajuebK1TjRgm+Zou98IUGO5hTHPCaRvg+KeFInYtT9/qTVjc7
         xyR1Gu5hoZHY8h9uCrY8Fk/4W13qf2RXnn1XSVCIsU2lfZ7PMgsdfwVq+f8xRsSzTQ92
         krARC+Py8ocUGdvL1SfaJY9nzGg7fxNqff0zvt7f+Hezkbz9UBZVjN+WYgTV1k+teRBj
         bGsFUDdLGU4nlO93uyiLRD8vqedkzIeU/nwEfzJ+zFmNvjvYpNn82+JMLDEhwwLSf7rJ
         cogJv0sW3W51hl+0zQZcGsh4T6r88x0ao9ls1LVLwbm4Ac6pgHYxlGMjzvYEmNLsfEtS
         Ms0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OZEvEl+kWBEYt8zK5TWB0KlMmAz4Exwaa/luk0cD8T1rrs6Tc
	V7Tb/2KPDJ5Z1ap7btNHXvQ=
X-Google-Smtp-Source: ABdhPJxLu9NzAixxSOZ2H0yxvd0EDgEfLiUsCumtziQHerSaRQKW21nbW36PONVMF8FhjN4FcL0D2Q==
X-Received: by 2002:a17:90a:22cc:: with SMTP id s70mr568756pjc.2.1591200447062;
        Wed, 03 Jun 2020 09:07:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:94b5:: with SMTP id a21ls886948pfl.5.gmail; Wed, 03 Jun
 2020 09:07:26 -0700 (PDT)
X-Received: by 2002:a63:1e4c:: with SMTP id p12mr91443pgm.355.1591200446453;
        Wed, 03 Jun 2020 09:07:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591200446; cv=none;
        d=google.com; s=arc-20160816;
        b=Oh9NTEIM3X4DUZSxH47/M4MkhHqlgtVG5D3VbuaK7N3n2BLmObg91OYhqt4oYKqlrF
         2eR0L9AUnSPSIP1vV1jNc815LprupjBLVP9Q4RU39/tAlHwt3NWc/LY9vtKdaJtSn5n6
         TJkR6rdd8KQPO8yDbOVd7cOENPeI8i3bXMldMJ+axnydnOIfvZ4abP/+0SoPe4b3OwrJ
         AtEmPpORnZP/D/Osu6WXJJPB6nlcIXA7FIQl+W/4QA/AwUaJ/ANNe9SBU/fAmtnZy5jA
         H4lQHuQeD2MjAmN7uXsM5TiFZQu3Pevfu+RDHNoW8B4+fa2dkrLE6V5KI7GkOxIikego
         OyMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=I0LdSJBp4zoME7tY6bpA1Q8Wf4c6QK8RY6BCgD6eGqY=;
        b=J/RqhQI+bSkECRTmCkIA6IwSVpGd1ZiK7YHtkfZeXWo6JdmFPxzS4oREou/kxUbiar
         +cWVbr662OMQ1pTKrmfQEO//YzncT0Ue+HFeR004StGiNbD4wTJHHqW6+IG8vMInAm9L
         89+btjH8KIipnxLDqtfsIdnd5/VhdC/lC24QcfTxQM60kQxQhp7Sp8dxMDxSg/EKbW0y
         ftE3FOe6XRXjKTJ1LuS0Q19+Iu3g4N6teiL+Q28Ut4TJU1rMwyTEza/sZaFsyyYaFVeO
         65ZrJbRI3dt6ieAvi9Om7H3wXSugCX3pI+GiTvuzdclVzvt+sE+yxaXpsYSt9sbovORj
         YYLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=qUTdWW7g;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id l9si252170pjw.2.2020.06.03.09.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 09:07:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgVvI-0003p3-Up; Wed, 03 Jun 2020 16:07:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5B0E930008D;
	Wed,  3 Jun 2020 18:07:22 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4657320707D4F; Wed,  3 Jun 2020 18:07:22 +0200 (CEST)
Date: Wed, 3 Jun 2020 18:07:22 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
Message-ID: <20200603160722.GD2570@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net>
 <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net>
 <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=qUTdWW7g;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:

> This is fun: __always_inline functions inlined into
> __no_sanitize_undefined *do* get instrumented because apparently UBSan
> passes must run before the optimizer (before inlining), contrary to
> what [ATM]SAN instrumentation does. Both GCC and Clang do this.

That's just broken :-( You can keep it marked and then strip it out at
the end if it turns out it wasn't needed after all (of course I do
realize this might not be entirely as trivial as it sounds).

> Some options to fix:
> 
> 1. Add __no_sanitize_undefined to the problematic __always_inline
> functions. I don't know if a macro like '#define
> __always_inline_noinstr __always_inline __no_sanitize_undefined' is
> useful, but it's not an automatic fix either. This option isn't great,
> because it doesn't really scale.

Agreed, that's quite horrible and fragile.

> 2. If you look at the generated code for functions with
> __ubsan_handle_*, all the calls are actually guarded by a branch. So
> if we know that there is no UBSan violation in the function, AFAIK
> we're fine. 

> What are the exact requirements for 'noinstr'?

> Is it only "do not call anything I didn't tell you to call?" If that's
> the case, and there is no bug in the function ;-), then for UBSan
> we're fine.

This; any excursion out of noinstr for an unknown reason can have
unknown side effects which we might not be able to deal with at that
point.

For instance, if we cause a #PF before the current #PF has read CR2,
we're hosed. If we hit a hardware breakpoint before we're ready for it,
we're hosed (and we explicitly disallow setting breakpoints on noinstr,
but not stuff outside it).

So IFF UBSAN only calls out when things have gone wrong, as opposed to
checking if things go wrong (say, an out-of-line bounds check), then,
indeed, assuming no bug, no harm in having them.

And in that regard they're no different from all the WARN_ON() crud we
have all over the place, those are deemed safe under the assumption they
don't happen either.

> With that in mind, you could whitelist "__ubsan_handle"-prefixed
> functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> case is quite rare, it might be reasonable.

Yes, I think so. Let me go have dinner and then I'll try and do a patch
to that effect.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603160722.GD2570%40hirez.programming.kicks-ass.net.
