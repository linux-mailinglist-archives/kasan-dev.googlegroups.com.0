Return-Path: <kasan-dev+bncBD3JNNMDTMEBBOOEQXFQMGQEM67IKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE4DD0C288
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 21:17:02 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88a2f8e7d8dsf132748616d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 12:17:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767989818; cv=pass;
        d=google.com; s=arc-20240605;
        b=COvz+Z54EHRw8XsAb/AgOo2f4NiWbIlbDG+HFxNELKEEaIUekygroTZdMNRGekCjY/
         whP1xuQzTu2XMhD/77vy5gt8bcQ/Cajwhymy5QVG4tCx8TzVqXXz0kA/mItlwEkoujK0
         gB+o4kXC4zjHYyrYImHS2LOn+8fZ8+UTw3xLvnulW/WhOiTFDnrjnTQEkZEOfnLT7mhb
         +Q48GhYql+NchrtPoP3JTOh9zC53YNI36WhDGYip9oaA8+Xw3TK2PPo5R1DYBh2/crRg
         REw+NhlhlR8U+lY/QL/MPLa7a8xJry0TFEMxX5ZIn8S41CV8B4qJrTdrvtlaQIAlEpQB
         tgGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=pY322g8rRsOe2pFCyph91No0ZcmwB1MUrKjR1Jqc2Nw=;
        fh=YsHwOghj+mht0bEp+DCXNfX9vcu38UZth7nGB/o2zzA=;
        b=Tsdz645uBGzwR4iPlNekyOj1bVq062vXcgg830V9hl22n0aiXI+JS//ZGp71/yGgvk
         jpUlWgeaHC5qcQ+JOLwbWanbDqh1z/d6HLazuqB2bZ71D2TtVdk/LauqD3T4sILig1jB
         swJAS1N0De/KJPVAI24xdnsGuBEsanMYLcec3x5ura9VkQBG0kU4CoYeGXhCJg+JFHlI
         B8kIuky2gmfMoE+4ZGncoygXSPqVAhPLFTTymK77iIRd4RKH3rYn3smB5oaxRNrsenh7
         zFikQUGf6W2EpIQ6ukj3UtFfnjjoTKlwIYDG603G8lUkPugeK9W3zhnFlQtKtYuD1VLl
         f9nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=RjLtkJa1;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767989818; x=1768594618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pY322g8rRsOe2pFCyph91No0ZcmwB1MUrKjR1Jqc2Nw=;
        b=gCEMZ2VaS7koE6cj7ELmex4LudeueTXj8nBEE64kkE9mvTs9OIjXFDcDkBXC1+0IVa
         TMwNug6HIbxg9bVVj/D3UYyKregzbC2JoKLm0zx+2qNKLgSoVCplpQX76czPJj2ZsGsm
         RjXyRffU7rfnNbIwJfVTmbrl0FGaOEe2Rc5xiUfckaEjKshUWOwg7pJCcexT5gD6PRYe
         otEp/MRtnHhpn40idO9PXUC6ZjQZvBhDJnJob7z/sSCPuYekm/lci3lEM5GOKHj12ngN
         tHn/BOJQd8NgnYmxAiwSh8NPu/E4HKTucaa+dQHtgEJRqdWYx0DrCCDI/tJQiUmq0KhA
         RISQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767989818; x=1768594618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pY322g8rRsOe2pFCyph91No0ZcmwB1MUrKjR1Jqc2Nw=;
        b=Rty2fXETlg22QH9b2Ub0H77GHDQ4+Thq/sXm197yOO5So/NI0kWGU6ucFwjswbqvct
         I30w7NV5aJN1e/AiJAMzE2HQzPBC+XB8wTdu5XhZwgqOuhmj/VC5Z69Y2oi/kbHmmkCe
         efeYYghRmJ70IkkBvUkc/bGziUCeKcNRX4uToPkK+e9HLcw4boTYOXnkQVN5UphGCoAs
         baXXP9hGantJtMbLVQzwHF+R6VST0/nvOgmMw9xtuz+LXWk1w3wfEs35Rlof9Awc39HC
         k+XcM1z4KQuC+PLgUWdnxu5nVKQKE+euFzrGLFuxDkyFFpwSBHmhbI5gNwsnQLRyeMzL
         dp2g==
X-Forwarded-Encrypted: i=2; AJvYcCVSeLDUq9LSGIbywBVlIApo9CpF6Ol2Aer8s3q/MPNUN6ULh0cAb7Sclx5HeDzy7iBxk9/0GA==@lfdr.de
X-Gm-Message-State: AOJu0YxqVXd7EGrihy2IBfjR3ANdinIcs9EP+TdeE63lZ4V7JfWZVLlF
	Iv5DgcBBIqqIrZ9IJPFEYseH3Uuybnq2hllRJl6DBSCmU7hH4y+k5AXa
X-Google-Smtp-Source: AGHT+IFZmuJ/UpUGim45WBWjETJlzhicpHQFKHvwr8om0SgLPvhOAMEH3WWWBZraOilFG7cGZ3XqkQ==
X-Received: by 2002:a05:6214:4a8e:b0:890:7fc7:8839 with SMTP id 6a1803df08f44-890841cb8f9mr149539546d6.25.1767989817951;
        Fri, 09 Jan 2026 12:16:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HBjbs3+0tB+LUO8CHfaJqrc1iqXLGpHE7kcwMF0CEjAQ=="
Received: by 2002:a05:6214:d0a:b0:88a:577b:fa53 with SMTP id
 6a1803df08f44-890756cc896ls104364876d6.2.-pod-prod-02-us; Fri, 09 Jan 2026
 12:16:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXq8adinvNtl+Xzqsmrd+/BPzGcWKCZSelvvZtD8MZoE6u6b38FLFlQoFaKkVUVhigHWGPB3m0Pch4=@googlegroups.com
X-Received: by 2002:a05:6102:3913:b0:5ef:241c:e0e3 with SMTP id ada2fe7eead31-5ef241ce230mr1792873137.23.1767989816494;
        Fri, 09 Jan 2026 12:16:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767989816; cv=none;
        d=google.com; s=arc-20240605;
        b=jnuklEodH6kGfrC+CfCLG5bI3JBSPahHzv+nNFpawN8zWcNV8c9ZZBv7UntUAu3p5m
         dVXpwu7wXlvbjWUunFIuIQaqYLRGlUkW5xL7F4ykqXJvDDmihbeoA2C38R8gnekw+tF6
         BeWohRFYg2VN9EwfVMtK0l1Y8uMurtSD0NHvHFEDA4iZcI9eYLqE+2+pNjtWcqv0Bloh
         I8RE37/BjOvILKJp+UaiUjxsVWiLdsiA1WBlj296TcbXuxc9zN+zzGV7RLX6TX8NQlyR
         4BLXeg0lSbZV9qsjfp/JXDr0eAI73ZYCWmuzcMe4n1cDlgI56TUQTbaoBY3tIxMlMjse
         8mVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=MWWlok8ve6te0Z1LFT3tDlJ2/NkqaoxHzzfJCelUW48=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=hyycBjjn+ylujgjlrEMMp3W2GmC6TnvI6jXBJNjk1tIDqcd8w2LzWq2jpXAyGOIbh2
         r9xl8rIAFbNN2+v0IhBGEB7QmuAyxnj3vvnLo2zvlnSJegcwJC8RddRh069rqt7XDPt2
         qApkLntxm5S9LOtgxJ1fPZL4hwUvMSpGxIctCMLEbXaRnUtUN8TsbIgVD6DT6fWdcNRw
         sv9/0ftQALAhKBpE21cegqYvkoK9Nn4MJH5pv4skypMiHT9wR5aC1fcCkTzKeisUSJEi
         FpLcewCL3/olAgjLtgMJcwIcTKuyu8dtM2D1ce1oWwo20D97JFLqvsFJMOr27bTy+cIN
         ejSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=RjLtkJa1;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ef9a7a41b1si81570137.2.2026.01.09.12.16.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 12:16:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dntN66qC7z1XSVtL;
	Fri,  9 Jan 2026 20:16:54 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id JY_Dc9oQqhZL; Fri,  9 Jan 2026 20:16:47 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dntMk3WPZz1XT1Zk;
	Fri,  9 Jan 2026 20:16:33 +0000 (UTC)
Message-ID: <05c77ca1-7618-43c5-b259-d89741808479@acm.org>
Date: Fri, 9 Jan 2026 12:16:33 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 20/36] locking/ww_mutex: Support Clang's context
 analysis
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-21-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-21-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=RjLtkJa1;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 12/19/25 8:40 AM, Marco Elver wrote:
> Add support for Clang's context analysis for ww_mutex.
> 
> The programming model for ww_mutex is subtly more complex than other
> locking primitives when using ww_acquire_ctx. Encoding the respective
> pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
> using Clang's context analysis makes incorrect use of the API harder.

That's a very short description. It should have been explained in the
patch description how the ww_acquire_ctx changes affect callers of the
ww_acquire_{init,done,fini}() functions.

>   static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
>   				   struct ww_class *ww_class)
> +	__acquires(ctx) __no_context_analysis
> [ ... ]
>   static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
> +	__releases(ctx) __acquires_shared(ctx) __no_context_analysis
>   {
> [ ... ]
>   static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
> +	__releases_shared(ctx) __no_context_analysis

The above changes make it mandatory to call ww_acquire_done() before
calling ww_acquire_fini(). In Documentation/locking/ww-mutex-design.rst
there is an example where there is no ww_acquire_done() call between
ww_acquire_init() and ww_acquire_fini() (see also line 202). The
function dma_resv_lockdep() in drivers/dma-buf/dma-resv.c doesn't call
ww_acquire_done() at all. Does this mean that the above annotations are
wrong? Is there a better solution than removing the __acquire() and
__release() annotations from the above three functions?

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/05c77ca1-7618-43c5-b259-d89741808479%40acm.org.
