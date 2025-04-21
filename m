Return-Path: <kasan-dev+bncBDCPL7WX3MKBBH7LTHAAMGQEA5CHINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 231AFA954B1
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 18:43:13 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e6df6f86c89sf6029663276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 09:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745253792; cv=pass;
        d=google.com; s=arc-20240605;
        b=J74a6t70ok11qE0T3LiErFz/+ADV7gd7RqiqEu3mCh5rjWrCw9Ei5fmbDH7rH3SViM
         h/D9gHOAvq6cZekMmQPclVBg1EZEMXO4ep3dmeErPfQ//16CpOeg+ZBTeegIQOuqADjF
         8XDyDI5PbQ5lkZwju9yG6kxHawFIu7dbPtAWCcX/4ddyTaJvizIm/5lvikQnKe650BM0
         Z515Q3k2cjo06uDyWwD7e4CZKWcRPLhm2K4/BoqnWa6ivcyqXgVmCpclW6tL8dlxAl3P
         cF4ILmjJ9NRsAu9ZhQOsRRB9+2mBGA1rOweFbvAsEooirwrx/Qc6LLLi9AtyQ/e2C3Ci
         weug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NDh/SsSYqYSguXhskGAWuK13yb8oMydfDrp6XxTvC/0=;
        fh=3V9sF5ehLNibZAVhcujNL+TrWCWU/0DmGwHdzo0Y4X0=;
        b=FYf+QPR66dgqDpQz/r6zNZDhF+/P99qMINrh2gG78rXsBAau4xJGknyOKUXHVjHqvW
         g1knJT+17NmjejQc2+lL7SZKQlhYvx+/fK0ZF/6G1OeKihNbk2fL0JFU6ESNhr+ZirG/
         Y+Yhg20hm8fUZIE5trR83KVFNWDHkV6l5fjPJI9h9qLpU/a+LMTEtbbjnzTG9D0mhYVr
         0cz51k59M+mP8evXJOJIFFrfRB2Nl26Bsgtjkq56kcBbwULZqXdECFnUULzyAohOajke
         gIsSJc2JSXRd+ImCpLbmQzo0eSle6v3KodfCzZXkhxiG1Znqk3ErnYOkhIEw72ObapIn
         wQ2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ecXGgq2l;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745253792; x=1745858592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NDh/SsSYqYSguXhskGAWuK13yb8oMydfDrp6XxTvC/0=;
        b=Sjy9reOt1WeBnuuJaGwCnrdcJ/qDbaXnFF39W5sGwoVfhO/sY78S6AMKd6Ny2lqFVA
         E1zMmPuWB9QZ3/6ABdtQ1ajTWKOkkI/OuSvPDziBZVliJlfFIR1dfH52TzPJ/BhcFs3e
         9D0wOLxiL7ty2ARG+RbYq7KCOk6U4k4nzD3rN593A0CdaH6CBU9yNmelk/UzAoLDZ05C
         dxjR6p4Y+j7PBF46+ao/EuvYuGLMFhRgOX+1JJbEJSPqxjVvZ/UNvruQtJL0UckLDAR+
         1fwqX8I74og3Mm6guVfXpWwHZJX2PHgQwRGwHlPy+11D6DUZuosSF3sQprc0eSCjbpWX
         xoYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745253792; x=1745858592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NDh/SsSYqYSguXhskGAWuK13yb8oMydfDrp6XxTvC/0=;
        b=DpXKN8pVqb5Cv7QWHK0z5xvFbSlRc5k7cHCdSZxZvX2oDM/HILFyI660MoelqnrOsd
         /ab4uwzYvvhnIbbeWwsqrsBiNYXxktAyblJbAqB2A4y+E+jWf3xt0q9QWUmJvmFfHXFA
         Zs/yuKwu2WrUvGibTAzgjDjNXpQeoMtzdjiaChVqlDxjrCqgOy5ZGUFHMETsBzj8yE0w
         v5SlKmr1dNXL/4CvrBziU6DcIdDhoU0qFW1BPC1nDP1s48Rck8uH0jFVtlhyVlfGQdQO
         5Z4/yO4jolzELhskXtdkpyS8X/xJf4EeSvtnKvAIHIOrvxmSFQGB6gfFpaAjOq6UrgFZ
         LeTA==
X-Forwarded-Encrypted: i=2; AJvYcCWJEG3PXCbqoSkW/5IP0ePq/EMEzsukggVYyNN51c6wff5UaYEjdzaH4UqJ3AUdKq6gzF//Xw==@lfdr.de
X-Gm-Message-State: AOJu0YywKtv7H7EvSECPRUsr0GwIPI3FOybUMLAj2oyrI4Hudzca/lxM
	rtiMAhP/cM0MmyAeGA2W3PKafuhsGOHkMirfa8DBHgBbG3usUUxj
X-Google-Smtp-Source: AGHT+IH18m0sN/yNh++E9O6sPn81v11pQ9lzHP53J1dDYwcb/HNS7yd4c+A531bRSSvTIhXfA27pmg==
X-Received: by 2002:a05:6902:70f:b0:e61:1954:567a with SMTP id 3f1490d57ef6-e7294bb5213mr19320919276.20.1745253791619;
        Mon, 21 Apr 2025 09:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIijikd4IKJqsef17vCZNVOJchWPZ8Net7JV8FL/QiBsw==
Received: by 2002:a25:5382:0:b0:e72:70cd:502e with SMTP id 3f1490d57ef6-e72804b3654ls443678276.1.-pod-prod-00-us;
 Mon, 21 Apr 2025 09:43:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcd+CRmNmsuN7fTH78qw3gDVjmy7BsSXArZffj3lglVNcK2TFRczsyN5oyRTG01g9Krk3g7lNfQHA=@googlegroups.com
X-Received: by 2002:a05:6902:144f:b0:e6d:ec89:be4d with SMTP id 3f1490d57ef6-e729481b70fmr20225537276.7.1745253790804;
        Mon, 21 Apr 2025 09:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745253790; cv=none;
        d=google.com; s=arc-20240605;
        b=WfiYwk5omdNJiJGFtqFX7hfWFY5h3zhWtebikUM4uTTtN7KE1oO3nW/MJVKu1MpAEd
         edWA4WlATAOFsCBjLmG7OvKO5ZhYY2a/tHeCQ+d4aOi2CJM+nNa9zj7aBWzhtqWifQ6h
         pQ9nLrjmoOdTlwRhGVfZXGErhbMOHqDI1UEh9L6ZfZy8PEVaF2/bMM+cKKqxSt/M1Tp9
         z3h4dbPVpldWF8ZOuHZ9gyiG7CaWtkIVR5r+nHu8SUtQG24LDI9yz7kkvqvau1DAb1CR
         yDD1B8BCcWSGlyxqNSvqzxgqAQ+H1BRZd9wPa5M2VibfLtdAOusX7dS9wdt+808+d2Wb
         JyCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0vLT8UVtMdP+2KZnL+KAguQMIE+qlInB/+bpVxdj6JI=;
        fh=7lSzNedt5d/WFE9rHCaKvBoCgxG10c1Z8K48DH57/Vo=;
        b=JH+o6r+M69OY2rCbcBzEJ03O/TMFnmu2WarmsJg7Cc+9tnAOH3VRJVi3GwpL6nAXbu
         u82LrEkZ62t0MhtER2kKVk3bG/4JQM4SLB9IpH3n8QWtmyz1wQximMh0S9KGAAqNz21r
         +2o92i599W0cXGUx8u0a0kNpntmLaHnp93olMBvQbRXGJWKp3+kYMGfs7D4JZbWfLfol
         CoMUldt3xOiZLQuTVZqblNpxrQyLsSyxR6OuTaCmYYmIyy5KZaszI4G2SQx2kpDz4Vg9
         /P1FLq6NwVD/F0+ZHqg917s1/ZK0ktBsIHJx8fa/nVFalzgcoMGwV0Bh8Bo4ATYniZan
         spZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ecXGgq2l;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e7295987654si418474276.4.2025.04.21.09.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 09:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7871E43D70;
	Mon, 21 Apr 2025 16:43:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA3E2C4CEE4;
	Mon, 21 Apr 2025 16:43:09 +0000 (UTC)
Date: Mon, 21 Apr 2025 09:43:06 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-sparse@vger.kernel.org,
	luc.vanoostenryck@gmail.com
Subject: Re: [PATCH] kbuild: Switch from -Wvla to -Wvla-larger-than=0
Message-ID: <202504210940.8B3E06C4F7@keescook>
References: <20250418213235.work.532-kees@kernel.org>
 <20250421091233.GA21118@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250421091233.GA21118@lst.de>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ecXGgq2l;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, Apr 21, 2025 at 11:12:33AM +0200, Christoph Hellwig wrote:
> Looks good:
> 
> Reviewed-by: Christoph Hellwig <hch@lst.de>
> 
> Note that sparse currently also can't cope with VLAs including the
> prototype syntax, which also needs addressing.

Hm, it looks like it's been over a year since a commit to the sparse
git.

Luc, are function prototypes with VLAs likely to be supported by sparse
soon?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504210940.8B3E06C4F7%40keescook.
