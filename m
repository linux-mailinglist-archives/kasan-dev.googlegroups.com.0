Return-Path: <kasan-dev+bncBCT4XGV33UIBBKFIR2MQMGQEYJ4ZYEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A9BD5BA22E
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 23:07:54 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id k19-20020a056a00135300b0054096343fc6sf11822416pfu.10
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 14:07:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663276072; cv=pass;
        d=google.com; s=arc-20160816;
        b=GmzwAsmxWJ8cd8ZKiE0lqfQv77Or+z++w7UUuASfYva2XnUjDdUnuehjXJdlWYJzV8
         dnrZsTwr8RlelZezWxm1QF54FSRAlLcojOKmz5mMU9AA90ZtLwvt3kDFUw31N1/mcI30
         mTFKy+twxd1ytNuc4YWn+RHqDT1oNl0PF/X8IlfCNHmD24hR+M/IX5baNcwMFFakWf4i
         o/5NczvZeDjljIvnDH0MSvvwonA082GEiKm2Arjy71AfDAoFMvSZPHlAzTg9k56fR7q2
         KLjK4jSe3AzAwJl7xIWuZy+9t10dHRrG5/4uHc0TVfYpd0z21rnC1C0vl0UgN5P8AFsH
         r+vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=mwOJJWtAK/ajJmrDpvqjoE69JgncphX6LPTJ0yqUa2w=;
        b=FSlNDFx+4fDL+HwWek+z5KRqg/QWQhQSv08Z+t9n8D+JtsydP/bg6VEIipEBtdGHH4
         78bTKLghYh4a88Gt/MgeqqByh5xwu5oPAzWTOclsHe+8xhfd38v1ha8e2Ei/GWuv2c3W
         coAvLHo8mJb2VS6gwuSJa3rktaqQqsjhPy4nz4Co9StCgq6iSQnbgEquzUPNgShT6ALK
         MalOWAeYwMVmpmgi3mZTcurhI8oGhL+sRendQArZF9py+ee6Ag/VVDLAuvw6iStTSMNo
         IDrh8p6LLzwitSuMzjZO40z3mhqQZKY5kvRcb31yI5KSyD3+7yD23Rxewm+NNniquuJ2
         MsRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NULC6DLc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:to:from:date:sender:from:to:cc:subject:date;
        bh=mwOJJWtAK/ajJmrDpvqjoE69JgncphX6LPTJ0yqUa2w=;
        b=e/sfeB4qlZ0RCnjNG07DT2zdFmf3Y/yPRrvFrcreaZ8eYCJFNXZrd051zOUmuItpH7
         xnUEV2yJCglFtDgrt0brVQDJoSCmIJk1L2poWfQS0Fu3oTfewQi4zx86wJAIkeCsCeK2
         PTaFmAS0GJCYk+48JCmlxBzzWYGuwFzOWpYT4AXOGVUGZL5A6vc/4ulcBic0Ksl322VK
         Wu4/LMhqEeoF3m+HkjIimTB8eb3IFZrFjW16S7rYN/uUnURyDfdQVseXehO4IWtpWquq
         uh8sxUVu8MNOjNlaMoxWLbnrdtyd7Hk3qEo/mphiUoSUrDjYWHJeq2BSKx//WgVE+/QC
         AjIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=mwOJJWtAK/ajJmrDpvqjoE69JgncphX6LPTJ0yqUa2w=;
        b=oVouyt38IhKvXVmOg24n3qDfi2RTr5Ou4oLagg+WfHwQzYKDkE8XAFxVEeO45jXPIZ
         uGm3nz+wdOP3cDTqG+s+KQAvmYP6QAaig6CtXNHDLrwByadJKgfZ3TlEkoPv9ncYkFPF
         AZSwQ8Y+zIx7rhFZTvpVpJz5pExqYPxrg9QA6SN48nh0J+SOTKWSqhYHtuVmColPBN/k
         iJkxIHqLUbQ/UIhTNEJCB2vWzVTOXknsSpe8/3QjOL3nL2go7w/kv5+zYMfAu8g1+vzO
         QFO6fNX/2Bgfw9ChKqHTQroHa/31jgcH/+d3rGVdolF6au9bv3Usn1mWjE4WDt8Yaqld
         a0qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3kqZOFfpDnOK5Y/P3dnkPoDL3D5tW9V4tvRtCtocGJfGkaPu34
	6gy189i/xtCFLsovC5EH1OY=
X-Google-Smtp-Source: AMsMyM42eLZdMoqB5i6nWaoE9cWVELaWNH1xpKsO/YdHBX7Pf8NSHJ8GPfxyxaQ9lq+UipKdwUtbvA==
X-Received: by 2002:a17:902:d70d:b0:177:fc1d:6af6 with SMTP id w13-20020a170902d70d00b00177fc1d6af6mr1508999ply.148.1663276072401;
        Thu, 15 Sep 2022 14:07:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:234d:b0:1fe:692:faa0 with SMTP id
 ms13-20020a17090b234d00b001fe0692faa0ls14092265pjb.0.-pod-prod-gmail; Thu, 15
 Sep 2022 14:07:51 -0700 (PDT)
X-Received: by 2002:a17:90a:d3c2:b0:202:acc2:1686 with SMTP id d2-20020a17090ad3c200b00202acc21686mr1851646pjw.126.1663276071519;
        Thu, 15 Sep 2022 14:07:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663276071; cv=none;
        d=google.com; s=arc-20160816;
        b=1HDOZXt0Crh/79/L68Y9fwsJvjOEmxep+EWHQV2Rz2TQPO61Z+ixdYV6YMBR0BN5Oj
         efhKoVKPJCEzg0JcKb5acZPHihL0/77peSEthqWeisSfBDTizfBNtpOwpjYNP8qxQ71/
         vNHQy0sZBZEciY9e+71B6fD+h8YvaZQlTOJRWCVq95oqM3AV4xQdLuCXQvP4lsgs+IPb
         Pypqc4IOXIiqzVZ+exWSkmCcImDsVHvuwN3AihH/Fe81YFC5nsm+fUVudJBO9ntCzv81
         OeRwLxoeEpyRXnHF4Idw9gXFTfZaKrWDdksTOowd4Y09nVgKkDMykBhwE6PkwswyQCxf
         9X8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:to:from:date:dkim-signature;
        bh=qEE1zojO2odxRBuHNu7vqOEYl8NElu7y58k2azJf/ZY=;
        b=Yx2qlHvaSdVD7vpPWqGgJeLwaFq0KyX3zDkyWzUJB/jPqaktehbA3k0enJXPNloyTQ
         i9zKZ5lbGV+GV/XTDtz00socUfLL1E1ZCrTVnPY295Gd5Wk9mwUDrnC5ESGN/3Z6dS49
         XwFRyghjXY+6PDm+Z4b0TEOcX4pplUiDMg0ozrAuwrvNL4LKNUf/oEeVhNkeSxhjB9sa
         yG/49RhMJGxceDikI5i80h5g7M8beAm6syTSL/R2CJ23g3BEfuzhq4LPIy2RZL/agHTT
         o6/jsdniFH9S0cQEgpPmP3+IsyqzTN8eNhg50BhOoh1B9s8lVCxbmBCBn0G9d3p1jrd4
         vNhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NULC6DLc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h12-20020a170902f54c00b00177fe01366asi485004plf.13.2022.09.15.14.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Sep 2022 14:07:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F144A625FD;
	Thu, 15 Sep 2022 21:07:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 45BE2C433D6;
	Thu, 15 Sep 2022 21:07:49 +0000 (UTC)
Date: Thu, 15 Sep 2022 14:07:48 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>, Alexander Viro
 <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, Andrey
 Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd
 Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Christoph Hellwig
 <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, Eric Biggers
 <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt
 <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 00/43] Add KernelMemorySanitizer infrastructure
Message-Id: <20220915140748.843a2ebc2efb35f509b56ef4@linux-foundation.org>
In-Reply-To: <20220915140551.2558e64c6a3d3a57d7588f5d@linux-foundation.org>
References: <20220915150417.722975-1-glider@google.com>
	<20220915140551.2558e64c6a3d3a57d7588f5d@linux-foundation.org>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=NULC6DLc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 15 Sep 2022 14:05:51 -0700 Andrew Morton <akpm@linux-foundation.org> wrote:

> 
> For "kmsan: add KMSAN runtime core":
> 
> ...
>
> @@ -219,23 +212,22 @@ depot_stack_handle_t kmsan_internal_chai
>  	 * Make sure we have enough spare bits in @id to hold the UAF bit and
>  	 * the chain depth.
>  	 */
> -	BUILD_BUG_ON((1 << STACK_DEPOT_EXTRA_BITS) <= (MAX_CHAIN_DEPTH << 1));
> +	BUILD_BUG_ON(
> +		(1 << STACK_DEPOT_EXTRA_BITS) <= (KMSAN_MAX_ORIGIN_DEPTH << 1));
>  
>  	extra_bits = stack_depot_get_extra_bits(id);
>  	depth = kmsan_depth_from_eb(extra_bits);
>  	uaf = kmsan_uaf_from_eb(extra_bits);
>  
> -	if (depth >= MAX_CHAIN_DEPTH) {
> -		static atomic_long_t kmsan_skipped_origins;
> -		long skipped = atomic_long_inc_return(&kmsan_skipped_origins);
> -
> -		if (skipped % NUM_SKIPPED_TO_WARN == 0) {
> -			pr_warn("not chained %ld origins\n", skipped);
> -			dump_stack();
> -			kmsan_print_origin(id);
> -		}

Wouldn't it be neat if printk_ratelimited() returned true if it printed
something.

But you deleted this user of that neatness anyway ;)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915140748.843a2ebc2efb35f509b56ef4%40linux-foundation.org.
