Return-Path: <kasan-dev+bncBCV5TUXXRUIBB5VE4T3AKGQEQ27A6ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 98B8E1EE7AE
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 17:25:43 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id l25sf5291810pgn.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 08:25:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591284342; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gq7O1rFjP6hcsBF/gNheP2GAt6LVfFcQyNlrnRjTOmAqU/CXt7I6yEek3sQe5lwVwA
         2QJa4SJQDXVsY7VuhkygtnSF8V7WiTFLa4HqNv9m86YMwdseFlXmh+J89A4JFhvG8vkU
         +LUdIWm702zG5LxnMei8aDdIetmVOhlrFqE8g9Q5YgLzVryJmuQUOweKDb1IlRYgNLZJ
         UDyP0uqzKXMh4JU++gqX6gxV5y+C2Z6pEk3+Haozukn2SHl5CkuS9GD9wcWUTFy0uMGx
         1lvl1222k15P4tmaZ2DGLyLcl8VJPaqBW7jPSYl/FFVEG5lZFkfRbA219DWZYAVPRMon
         Uxag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SjHbAPhYustSUXE9B1LS7tKJwOQnjxIxM8X9/iKSzqM=;
        b=gQBzNyMly0n9Jk2ek9UhXrv34NKPRUk80myxMEvJlxmmByaqfV+fKHUJK/g5ptYylO
         1Afy8AP5CeW2pqU5RxVti6k64um0QpIpkozW8kQKjpJHyG3QKL3tJhTBxPOY2ksu2JQO
         oFskIi5DxHKHwlnzUfAf7m4wRSNtQrPy7TODBnYwIAGssZNPKcHKVhWXAvU3B9vW+RU3
         174JApsH2Z9eyb4cpJ2a2rZuLRkkVobQ1PYwxPOLbzgIFHBDqSKL5WUtaoc86M/7P+t1
         ZZfEVloQhRIOtfhd8Kf/wSpOT+AxyxET1d3q7WwS36LuOybxTD6JFc5JuoKw4hNzCW/F
         mf6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=jB26+r1F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SjHbAPhYustSUXE9B1LS7tKJwOQnjxIxM8X9/iKSzqM=;
        b=FOibB5TWcktwJwNycmXp14SswK81uZGZu5WGSak9jMJYzD/9Z3Qx4u5XHUhB4WQHid
         p4Ny1Vzle24zMl1y39gNApDAO8L5JjVQh7H+v82MwejySm4lT+n0Ja9yLhAKe69Vv3sM
         6tNY2A+TMsvDotQaZsZxVO6fN8jSnJJCKW3ziAJc8izVh5N7kX3BHdFZdOj9RpToX+Lc
         znUAbXXcSyUZMTFTPZIyHnLROzeoKAHXmLeHsIvt2Qp40jfntvXTocgBIOxUYT5a5D7C
         bkNDMyt3eVnCJsw73I4q/Z1IMhIwNKzcCZ18govrJ1G9YeRTPDYbk+dOl39fufaZ0EdQ
         ykaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SjHbAPhYustSUXE9B1LS7tKJwOQnjxIxM8X9/iKSzqM=;
        b=HqJIpGNQPbYA3ZXSPIiwSKJSIvEb4fP9+AdhMucl/f8PUUULuqsfLmCpmPHVV2KXdi
         VFfqX/wJEZg/4RT8sa9WaqpPeQbec8tt/bXH3mH1iwTXqS/gKOZyTDrs8DV2+hDQqHQ2
         VvIN8kQixSPVEUNkFCHEDr/1Ioi91vII1fJE7KG3v18edCtzUET2fdyqNl5ZRDNLVm5w
         O1hu5Lu98wx6xZ2D+7sBjB3drTeeLLdfnVLfYhrxlvI+kPIN5W0lhj4HSgn9Kqtpj4jp
         /eJyceuAeA23R348wCx4Dgfd0fUUS8MAlR9F15F49iTzGA48DWsp8eVXFbNvb2vX9tdl
         cFzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pgNtJ94BFPkIwzO4i++PQ474TiCOaDIEHe2FpffEf79X3lwRy
	Ma4Luvk8t23+c3wX9B/9Ik0=
X-Google-Smtp-Source: ABdhPJx4COISxCrrAwUnmGUWzk6l7S5tA/+DMf4pS3j/7/QgaNAr6haBpTyiK2UwdMMjYCXTpt15CA==
X-Received: by 2002:a17:902:9b8f:: with SMTP id y15mr5186989plp.76.1591284342230;
        Thu, 04 Jun 2020 08:25:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f3a:: with SMTP id y26ls1955066pfr.3.gmail; Thu, 04 Jun
 2020 08:25:41 -0700 (PDT)
X-Received: by 2002:a65:6703:: with SMTP id u3mr4859011pgf.179.1591284341757;
        Thu, 04 Jun 2020 08:25:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591284341; cv=none;
        d=google.com; s=arc-20160816;
        b=WRm3iytFZ+uJrNFCdfzDwLgqe9l3x3kf84eFm6BHHOlnqVx5ozAzxEUv0MUR1oHH+N
         ACiRF3niNQ483iSEPsAVT9rtZFONPh40o56+XvHyAh+oAitUDih7MEe8LwUK+adRqsSu
         r34oSATiKDtOkbq4o1AHakLdhzZyJn/RNU9HfE4EodcRk/7B/0T3lM0wH5J2IISYY0Gc
         CxnbK4SceHMtFdQ9Ojc1wFsfGCv7qVDgg+bLpSm7uUgqUeZgtNPDWkl23Jy0W+cHQ121
         cvpYZ0vHs4UJ8VeLPQZlaAM3H1iy7lbRprhSqSn7dLcGQnqjJtGtgTPrYAAQ/fDHMyWW
         gMAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7nUdXGk9WUnPOP8CYGbU/r6c+Zp3RIzDzbNwRPB+ALQ=;
        b=S8ICK43b928eH5pGPeVvJWKqjYqlwTUU3lDjVHrka0bzFiWVivK4fCpXSOznxHIe9U
         QkANEq7Em4Rt53ch3wflRexIm0O7nnPESJjAgXE+ehNE0JYt0bj2XKchyXW57/y6wsOk
         hUMaZ6DMCh0BLZI8NZgYGneQ+HuA+IkWR2ID8rcxlWL2sNadGS3L7k4Kdpq82raqjuyi
         QuvavVkl6UTf/otv8tThczhsSPJpa8Clpf6Jo0R1r9A72DELZiYj/jgmY25/d0UhmhLd
         2ga+fMmUX1S3a+HJHlAaBXG5Sx8uLObnTLWNwIDgzCGmo1H/4pz1MB6MfSGQaeHkji1V
         fSVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=jB26+r1F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id m8si239461pgd.2.2020.06.04.08.25.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 08:25:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgrkR-0004vl-76; Thu, 04 Jun 2020 15:25:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 549D4301DFD;
	Thu,  4 Jun 2020 17:25:37 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4045A20E061B2; Thu,  4 Jun 2020 17:25:37 +0200 (CEST)
Date: Thu, 4 Jun 2020 17:25:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: bp@alien8.de, tglx@linutronix.de, mingo@kernel.org,
	clang-built-linux@googlegroups.com, paulmck@kernel.org,
	dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	x86@kernel.org
Subject: Re: [PATCH v2 1/2] kcov, objtool: Make runtime functions
 noinstr-compatible
Message-ID: <20200604152537.GD3976@hirez.programming.kicks-ass.net>
References: <20200604145635.21565-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200604145635.21565-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=jB26+r1F;
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

On Thu, Jun 04, 2020 at 04:56:34PM +0200, Marco Elver wrote:
> While we lack a compiler attribute to add to noinstr that would disable
> KCOV, make the KCOV runtime functions return if the caller is in a
> noinstr section. We then whitelist __sanitizer_cov_*() functions in
> objtool.

> __sanitizer_cov_*() cannot safely become safe noinstr functions
> as-is, as they may fault due to accesses to vmalloc's memory.

I would feel very much better with those actually in noinstr, because
without it, there is nothing stopping us from adding a kprobe/hw-
breakpoint or other funny to the function.

Even if they almost instra-return, having a kprobe on the function entry
or condition check is enough to utterly wreck things.

So something like:

void noinstr __sanitizer_cov_trace_*(...)
{
	if (within_noinstr_section(ip))
		return;

	instrumentation_begin();
	write_comp_data(...);
	instrumentation_end();
}

Would make me feel a whole lot better.

> +static __always_inline bool in_noinstr_section(unsigned long ip)
> +{
> +	return (unsigned long)__noinstr_text_start <= ip &&
> +	       ip < (unsigned long)__noinstr_text_end;
> +}

.entry.text is also considered noinstr, although I suppose that all
being in .S files avoids it having annotations inserted, but perhaps a
comment?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604152537.GD3976%40hirez.programming.kicks-ass.net.
