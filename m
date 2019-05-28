Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPG3WXTQKGQE35IICAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9032CD7D
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 19:19:57 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id j127sf18594684ywd.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 10:19:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559063996; cv=pass;
        d=google.com; s=arc-20160816;
        b=urJntisW/keTl3ouJyBAjBvJA/VGUCPNKxwGe/pB8r9sQtl2kvoOJORp8gJlG3Jr7T
         PXXdqwUKhNVuV4Ad5+hPLXclgF/XddoDeYP/Y0u3HYcQipqbp8U0tRaqW4W4OsGqASrz
         tPCIdRWJPEhgxwM9CPanidg84wHZ6CyFygPsxCnfesY8ye1SktfMGSgaobXXYQzwNRsG
         SJ6Ksi2bhrPpDfTJO+E1owCiUaYAy9cUAkeYVOQuwxztX+q1Ol5j9zGI7I50yqXXsBIb
         VS703KsiPcAVc2546rrH8LvK05MbaFn3PSPbHSN6PvhnbguaWdmSrwF25OebGW+rX9PV
         Ny0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=jK7IOxz5wwDp/Ea0H/X9OHLkyhIta2B4skX3Jt9puNw=;
        b=F9ksqlEJZ1tg0NGUlyGNRXUBGDdHFe01C/9hU3ZMk7+eeb2evc1bRlCPPrkHMI/M9/
         +dpyxS7KUzlcQKHL/7FAdfeFrzasJwCFeCkB6PimIjD1SOuvCiVpAI/J+veuF3kEe3oT
         YZVeMQk+bn/eXjafwn2lUkDN+FvdQ3EqL44I/SqKyuxk/IwikcOIGsAwF1l9xc+s9aqU
         oDD0iUDbX5tTxD8wPzpaO2Y+VuVur16PI4a8/sap17n4HvKatHEQypCPGeJiyuBm+RY3
         5KyFE5ModGf23dKjWT3jn0SvWxPIeileHlLLaoplLWlG9t67bqeZ92CPeTACzFuWhtwl
         uovw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=1Supj4ah;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jK7IOxz5wwDp/Ea0H/X9OHLkyhIta2B4skX3Jt9puNw=;
        b=EvBx9QHDUVGTfq42q2vnRGviJeDFleKnxUkZ0V94V2cipgz1PWmTPUBdhtvRps6cXZ
         t/fJLNtyBJsCU+/ZrwEY0aVHlz4wuYbBGRIp58wHp5oRfHq5CdvJniGlMBry5Wpg7bxX
         llCNb2b2k/arcSqxwAr7CkcI3OYsNrKtF/+k5O9ZerhJqVqLZDWH9bNAJpJ3YQ+hp/Qz
         v4MmA2ZGXlKu4f71hs+NR9Al4ea9QO//ZmHZmC75sUXlTZNcQuo2xIXtkiIWDAz8w/I3
         j5VcsqFFi3Ee0JOsBM6FiHayksHjxWqqGxr6bPk0EepoYa9+veL/rs5bDSSjQtZuQgYM
         j1UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jK7IOxz5wwDp/Ea0H/X9OHLkyhIta2B4skX3Jt9puNw=;
        b=FaTEy1BIwxV9vghh21crWMFj9LLn61Zz/ckpoEnGztjnWaPjJu4anBFVN/TNwIbvI0
         zdHduxb3I+SzqkPDJjyniKVYrAGiiH27ewD/azRsulsx7h7svExshtzRb3RJWipeTS26
         QBKOMm1f9uU86F5iRj2g65b3nI6ULm9nBTAbFf9x/xfgabDy5C28poCboiWufIXLjI6M
         XZG87SeloSAv2WbcZjctRleaGb8IaDrIo6Zf8m7ORIkPvq1KOueohskyg2qY99ieS+/0
         m+pM8GkravzKe7Hy3yulHzlM6g70STUXMiebalVhEX4zxWpA8nx0xmqnA+JB9w1Zvv3B
         O4yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX+4n4lMJlRw3hj+jBPpSb6oVjwEsZb+Tl6lCpfT01/BOe96cW8
	dLWgeNq+lIQbmvoE2fUO/oY=
X-Google-Smtp-Source: APXvYqxDqfv3uxtDz1w5DhlVJBkIZ7BEF/IDMuu1eM1Wp9rQR/2tpylLhgvRk3/H3I4nzTiA1mcDhg==
X-Received: by 2002:a25:2:: with SMTP id 2mr36159838yba.516.1559063996308;
        Tue, 28 May 2019 10:19:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5ec2:: with SMTP id s185ls710796ybb.14.gmail; Tue, 28
 May 2019 10:19:55 -0700 (PDT)
X-Received: by 2002:a25:7642:: with SMTP id r63mr28408967ybc.253.1559063995968;
        Tue, 28 May 2019 10:19:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559063995; cv=none;
        d=google.com; s=arc-20160816;
        b=qvgkR6irpZBwjVeKxSMH55rdSBf4sXNAjKQ8LElsO1Wohmchhz8TSO4dIOUD5rulFm
         8CdRkzjnAn/l0R8I69U8zwltHHYjr/Vll9jE5H0YLGekR3YC3nGhFmFCdLYdj234YB1t
         WRF1LAofNwIg9bTSzhOxTYMaBYQj5r2pz1NdP/d5CJ5TfhT1t1Ks04hcNtNgBOFA/Cgq
         6ggcp5dCR/8ozGk6e+USzJ7g/SJfkcN6sDn7AjTgRF0LQM5YT885DHFc1wgYBeaZqSK3
         okJX78H0EnA+U8QfsOJqaGZsEAQmvV2VUwvwZYQu/zDq6OAw9YjOt7/3C6VXuVCXSZFs
         LNww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qsxG6nrZHIG6W3Utol1ADoMvGd1Fu++xoBrnNWF+g6w=;
        b=MmP4mYjOWayABiOSoELtreSW4EwLuzD/XwELnOvFBmeBSByujnxUnpAExDj751+0kK
         t7mIMcAFjFwuJ0WcV3iC8Zd0N5lDHGo7XEyxSYPcz9DCkXkP1uXDSyrkOr/pqdAV/9C/
         DVm6jsu3E9Tdr2MMLXIoQJ6FfWtwXytu1BS/3ZfPFUNYsvdOxGj5ISisx2ISl3/VjS7d
         93toFjiv/pbgGsN8vjCWtNQESc+7ltc4dAyBJtqpgqttsuV77kQxsLFAiL/ORsmxlOQn
         lQ2AVkXTb9LcovJqRBWn21LIQ0NTq8Qyt/rb7kR4OxDj5EJlZ5yVlrniBFnm4rNmVFJ/
         1jMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=1Supj4ah;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id n193si725532yba.3.2019.05.28.10.19.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 28 May 2019 10:19:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVflI-0005pf-Tr; Tue, 28 May 2019 17:19:45 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4AAD52007CDEA; Tue, 28 May 2019 19:19:42 +0200 (CEST)
Date: Tue, 28 May 2019 19:19:42 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, corbet@lwn.net, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, hpa@zytor.com, x86@kernel.org,
	arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/3] tools/objtool: add kasan_check_* to uaccess whitelist
Message-ID: <20190528171942.GV2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190528163258.260144-2-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=1Supj4ah;
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

On Tue, May 28, 2019 at 06:32:57PM +0200, Marco Elver wrote:
> This is a pre-requisite for enabling bitops instrumentation. Some bitops
> may safely be used with instrumentation in uaccess regions.
> 
> For example, on x86, `test_bit` is used to test a CPU-feature in a
> uaccess region:   arch/x86/ia32/ia32_signal.c:361

That one can easily be moved out of the uaccess region. Any else?

> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  tools/objtool/check.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 172f99195726..eff0e5209402 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -443,6 +443,8 @@ static void add_ignores(struct objtool_file *file)
>  static const char *uaccess_safe_builtin[] = {
>  	/* KASAN */
>  	"kasan_report",
> +	"kasan_check_read",
> +	"kasan_check_write",
>  	"check_memory_region",
>  	/* KASAN out-of-line */
>  	"__asan_loadN_noabort",
> -- 
> 2.22.0.rc1.257.g3120a18244-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528171942.GV2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
