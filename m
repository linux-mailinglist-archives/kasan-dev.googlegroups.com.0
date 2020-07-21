Return-Path: <kasan-dev+bncBCV5TUXXRUIBBBXM3P4AKGQEDPYBBAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id A8BF422819B
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:04:55 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id a6sf2242576pjd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:04:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595340294; cv=pass;
        d=google.com; s=arc-20160816;
        b=a419E+8EbAS2BAymt3dzT8K1IGtN/ujsWTNMmFwuwWcD7ilHjdpRvxcWp7PsrJv2ST
         G12W65teimw6qdxo/l0WcLqgpOJQrKszMgYONHYAsZvz+2mQoaTAVG+OA5g0Ixq6w6FG
         W+Z168WtPzmYoUXMXb9L6h15ZxlojQLM+S9zvZNP+DlL3/bxevYxuUx3XK4buF+GyPC9
         mNoGf0aENT4U1AXRXuiaOOGyvJQOcg5Lr3URhr4BOUx3rmeCfkUlaDnadpTKxl+mIvKa
         zIB7zLCJCf9/+XjBwSAk+qWMdnyMjtYrRFaz5QMybT51jozDiCXSa+03HRU96QfSekTd
         M7JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RI6W34FmKDuKqH6lyNYwH05kePQDWZfEY0mkYts6IIA=;
        b=ujV2foJ3sJdUfo9VsoZVUSIqHVHV1boeKUZSydXiNwdi9KewkLGphklLlK6meCoaOe
         QqfNIFX9rk9Jx/f+sXgZvm1bpaYTQjfMRM6NV+RZunfgkcKDtye4ydC7Gx+hJWJem+Mt
         BAMJlYwu5jErw+vP+Mk8TLJ4Mad3N5c8HLsRBJ6M7euN8dL6quMdWcTaP1oaESLTpfm7
         vMd9yM5TKfEakcfAqa3CVFUQRZhua8bQpF/kqCQgC1joLvzrH8ZO+FBspe+DEVGxGnUm
         wv2eN/n3QU2O/7W0zS1Bbw7I1/dOP/8VRnNuKQ7Tb6wganVWvljwP5HWMuTeSfd8ZEXE
         /Egw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=0vFJ01JM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RI6W34FmKDuKqH6lyNYwH05kePQDWZfEY0mkYts6IIA=;
        b=HiRNs/Bjk60yFRvTUu5aCOxyWjWcDNPRROsodQz+1e/+BhZQ/rpkQdF5zWxyURWDDH
         lmIb9a+lrdo04nqGtaV5PxJSY8qUej9SNlEOjrcEiDn7t6hyGm37Yik7m5Glrf/hF4WA
         gKWjfpSXz8CRnqpfEPGAB3QCr7W0ZvGgJhssLeBVcljXwC123sw/9v/3gtffNEXcML07
         8FnaReA95fukQ6qKnrOPHtzItELPlSVZhYWk7QD/lhUdYv+XsUOSDtcFwd7ybXam/a9s
         omGHXTNwEgWEGSWjoC9ezaqphGdkYEck9HvWm6fvhewAGHifC8YFUNGIiGovhE+d3fNn
         qeZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RI6W34FmKDuKqH6lyNYwH05kePQDWZfEY0mkYts6IIA=;
        b=CFNMUL6XzBBVLY6O2t2ZdLtCj210croxsRXSjY+Ae9GL5bGDYgtm99TI46dSqTOLyV
         yLO+5u8sleriNd9LPyc1qozEDNnR3VvcpBFvJ7unUw8VahI2zaiJ6yo8uGNPqRUr9o9A
         9zv2u8nvBe/Ae43niz5CRQMPHe50ObGdT8QcF6nXkR1EC1KgaLzPjLOdhBeFAf3lIxRl
         yDEk4pjl5CQtYvYIXYOnHKEwyGoEy3zlx/m1BR/NzYXmokgyyDbfkLDGRn4RJKryzgN3
         yUYoFW/7E1eyXs09dUyo2q0xVQXCoyZzWZGeq9OsD01jyhRUk/CDYY0yULqsfN/qtgVd
         E0Bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ujNTdkQTb1qhKE5xjZ/LjHaTemyd196jNgdQIVHe22XPfcY6s
	VM6FPMoOFyaXq99HVhUS3GE=
X-Google-Smtp-Source: ABdhPJyGf0ghg6Wge36qH+6OEo3Kv/XOMIvHbGVBFdf4oEKa3KuDKc+EvQavW7uQC+ohBwBnPYgI9w==
X-Received: by 2002:a63:7f5d:: with SMTP id p29mr22619786pgn.259.1595340294416;
        Tue, 21 Jul 2020 07:04:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8421:: with SMTP id q1ls5845752pfn.8.gmail; Tue, 21 Jul
 2020 07:04:53 -0700 (PDT)
X-Received: by 2002:a63:441c:: with SMTP id r28mr23098251pga.372.1595340293865;
        Tue, 21 Jul 2020 07:04:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595340293; cv=none;
        d=google.com; s=arc-20160816;
        b=hafuKkBxqyDxTUu+QyOaTGqeA8RwI+hdrFfr9jlvxTfgnrt18D833lgdtwztP5fBhs
         EaLp51mT8SeouSuqB0bP6s+VtV97YxW/EldQOuPf7gqjNoFg5QpidGgpxw/G6P1mNFfY
         /FxmteYNpd4Nk0umdid4dxakc4thxe9CDWP9bVQ6zCD+awcJq/hhhS5ZcyNyy2GcQIpB
         Cswf8z3bf6aKh3e3Fz+zQf3ElOJ3ajrApzimIy2eomsj3tFw/lNtdyTX9vVzXzwNdYfe
         9Tnmdd7vAzAUvnRvN9u1uZsoKcawWdg4q5aMzNxZ8Dcme4R5F9Pa6+opkuISh8Mbx0yb
         eP1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=35SbtfWGz45hL6nU4tFXWLRurwYHBqmeuQ1Pfog9lBE=;
        b=d/SgS+cPFO5DdD7upWkSkCsZN+MPQ63TOipex9F/kuYIB+2/70n5eRj2lvKk9Ek22g
         IuUkNF1b+js3NxcmZVVpmP1IgAH268/kih1uUoOYW2b8X38BwTVZOe5LZzMPVdu7PPmO
         jaa7OU6fPPhY2M4ERH3+J+39P2guO2eluSYD65L//z9Xq6LIkFrghhWa6LSbKake70Zf
         q+NKjq6uDHA51tiY/MA8cAUf5mAuuf7ULHhSviMzxr/zWuCV906mjFm9SqKu95zDTnPh
         OqWyEVH9Xr2QOsbBYSUsF/NT5h+oHeUNQhWlqoypzKmQrTh/vVrWmrnIt6YycuLywIqI
         t5KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=0vFJ01JM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id q13si1140721pfc.6.2020.07.21.07.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:04:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jxssz-0007zy-LP; Tue, 21 Jul 2020 14:04:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3E0A6304D28;
	Tue, 21 Jul 2020 16:04:48 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1603B20DCCA0B; Tue, 21 Jul 2020 16:04:48 +0200 (CEST)
Date: Tue, 21 Jul 2020 16:04:48 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 2/8] objtool, kcsan: Add __tsan_read_write to uaccess
 whitelist
Message-ID: <20200721140448.GZ10769@hirez.programming.kicks-ass.net>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721103016.3287832-3-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=0vFJ01JM;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jul 21, 2020 at 12:30:10PM +0200, Marco Elver wrote:
> Adds the new __tsan_read_write compound instrumentation to objtool's
> uaccess whitelist.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
>  tools/objtool/check.c | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 63d8b630c67a..38d82e705c93 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -528,6 +528,11 @@ static const char *uaccess_safe_builtin[] = {
>  	"__tsan_write4",
>  	"__tsan_write8",
>  	"__tsan_write16",
> +	"__tsan_read_write1",
> +	"__tsan_read_write2",
> +	"__tsan_read_write4",
> +	"__tsan_read_write8",
> +	"__tsan_read_write16",
>  	"__tsan_atomic8_load",
>  	"__tsan_atomic16_load",
>  	"__tsan_atomic32_load",
> -- 
> 2.28.0.rc0.105.gf9edc3c819-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721140448.GZ10769%40hirez.programming.kicks-ass.net.
