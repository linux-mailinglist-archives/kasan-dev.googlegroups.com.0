Return-Path: <kasan-dev+bncBDUNBGN3R4KRBFW3XTFQMGQEWRPY56Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C713D3C042
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:24:08 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-477c49f273fsf47337135e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 23:24:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768893847; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rtj2+35u2pe9S7Mv1yETRKqh0h5rICQaP3cd2x/2ewjKcs6G7Fo/PHiW3+8uGhYcCx
         LKx1V+cBK3R6PVspp0WLeVpdxP+hNY7c+03N34AiNiOM+7cyDNhMBmvPgZp6M7YcW9JY
         Lssccab0pz0RAiDsNAnX17UlkVw6R73OiD7XQyar+/bK3kv93w1OP3nkYt3r36CzjHlu
         W+1Tqf4GMAM7MZtaDB6LAxhySOEObPsaLiJrCBu8RdiSj709o5qNs+n3HTnUojSU41Ah
         LXwXyrLEB2OYbN4HIToK5m548xNlxiixSv9Gini6di29OEPJof4yHiihzhLvrK5q9nBk
         kIgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gyxKWQgR3Ecb+uz2xcttjx3MYOpsXXblDuJ0gxX0n4g=;
        fh=T/31LhG636KRhrRgNgZ9sGUzVmvQFlJGGoOi1YQXzG8=;
        b=GJb59SmJbuoVRrafTz0r+2ISvy94LDAQ1mCWMJLzm+kBx5sKNwygXSzMmgUO8Ffmcv
         S6ni8a6LWf9n17VQyhuCT7cY3IvSWHGbTlFh8zxtmYk7qDM8LOpKybKuamJB1HsJrs9I
         a2O5QYgowJfZ+XWZ1TH5Rg+Hs8B8vRsVB1id3WMrOO6MQ6ABEfu/hL6EH0p9yqfEPjh2
         AuSkfso5jTtvn9tdDxx9cxz2MBIuG0cdpmKGJrPb+Lmjh8JirK+wNExXyd3s5dPlEu0J
         hFzvDnFxq8/LcNxLQalYpEcdXU10Vo5+FNa6K+tWwQikEyuzmq0FYxjCXMSWuGCbRiIB
         gM9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768893847; x=1769498647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gyxKWQgR3Ecb+uz2xcttjx3MYOpsXXblDuJ0gxX0n4g=;
        b=FPTbu7rUV03CVfmsBpzsEuIONb9VzmaDhrmT2PAwH47ItaJ7MyY4m9thvEDOORZeY1
         yXYul9ftW5jUH3BnL+2YFkU5KND61htENqjyejAcBUtDpQdpYP3L5VkW8N4JM/JO9CY7
         ekKe32DZnaxoPQeysYX5dwIalKie+JXj0pYT+u/2vEnrmF3SuA0aYs5xTTDbnfb/sy7b
         cHnXIzTmP3auBES9wMyvIovi3vl6cep+B7YFfGcFlI334IPRrVOPT8PRPARrdCl09GxW
         fpe6SD6hPyq2+Xv5+kThEvRahDe6yaxMTBAABnW9YO/RYyLCyR/J4zNPB8o8rUAVYHg5
         bGww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768893847; x=1769498647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=gyxKWQgR3Ecb+uz2xcttjx3MYOpsXXblDuJ0gxX0n4g=;
        b=haep+GnOuoQo/w9X99Kz4cKkJ44GvsmW7C3YxEpX0tDfbtsteRFG9jznZs1M3cOmyc
         LSgxsrwYqGazwlv4Vqk3VYXzA5xQiAHlXwp+VV2L9zQAtSz5d1Yhssj0AsBODXkt1nXu
         hwwoseTFRBznrq+RQl2Qqp29NY6RBlEP89GLmatatnx0JuKLKQGb2FfASJ+qZkQjmald
         3hwbxz4VfC8eeGNNJcsCzlryYQ7vJhNRHddEfI2F4GmQMsXCN6KFrytHzwoy971m68Jl
         VrunK2r5ub60f3bIby6105vLunRMdnhGs3qyXIPlghh6sAw1ODfjNGthYqh0PtgMBpFG
         LUGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVL+VIGRkybY1dSeX50CBWE4vfrLlG87jMar3TQOU54TXFX1KY9Y1K00nD4CCla/4TG7rsHqA==@lfdr.de
X-Gm-Message-State: AOJu0Yw6jE2XhW2peDNwjWYGpIX3L/CYKmO2/cuM8uKgivpbW3KiORJV
	7Qb/8k0Bp/dxQdxRJbyzEg77yWssEfX0/pJyohjtdArDCmb7+C/IP9H9
X-Received: by 2002:a05:600c:6990:b0:47e:c562:a41f with SMTP id 5b1f17b1804b1-4801e334361mr170560255e9.18.1768893847281;
        Mon, 19 Jan 2026 23:24:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FVMH4ZzyCVmL7CudjrtRE9UYm67H9MVDqQkRge8uI7TQ=="
Received: by 2002:a05:6000:420b:b0:432:84f4:e9df with SMTP id
 ffacd0b85a97d-43563f82258ls1367874f8f.1.-pod-prod-02-eu; Mon, 19 Jan 2026
 23:24:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIHRnela9T4PJ+GDRxm1AzRcgovieZNwUddNX1CfCeRhkpPhmF7IU+HL2VWw8fj/mL/wyh5F3ZLxU=@googlegroups.com
X-Received: by 2002:a05:6000:1817:b0:435:9144:1417 with SMTP id ffacd0b85a97d-43591441649mr652865f8f.49.1768893844667;
        Mon, 19 Jan 2026 23:24:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768893844; cv=none;
        d=google.com; s=arc-20240605;
        b=A4P0uS9ZH65AE8s/OKU+WE+S2Ky5fWp0gqL/TpzkLFSAD1HaxtlmfTpOigfAwKwxu4
         GL6yOs96Jdy45ygyTgJjsuPGRbUdH2IzkBr1vLwjIGsU6sut6k5KL6TzR9l6KL9COmAQ
         RGRe8O7bga6qViAa9tcRz5kkXFCLATCE2k3vNfyn1SvzFm4A4E7VNKqNzVcG827SN+ln
         mfr65nqe9Mx2bz8Rx44uf5GTWKhTRq/UTPGdeOVfdbDdnCf/XbPNcAFtCqqyG1FQPQEE
         WoQhowvuVbefbNj7HTyjMGeQVL3x2vBkQPgpjxY5JESr7v7EkmsTmvn5HnOgKYLK6mvK
         yOOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=9nekwj4rymvcYQ/M20zZRMs/uuk39SmEg5+1tonqerY=;
        fh=pN/195l7EQrs8KF7+pVqoRFb9q5BcM8+IzCxYjn3TqA=;
        b=H1s5L/rCdCpTopavz07JOesmRaffm3IPVtzcq49QuHNeA8Qfad9oEX52b5+XqYd3BO
         EjARMxVXdPBDPL1oAVyG4zFjZ3sXGaodVOhKx0/s+NCplwEl/NPI/pSRFMJSVleVeh4I
         4uUo+rluzHG0jb9Wnf08dSJ4HSksfbFq+b62WeTrOVqFWwd0vxuMIinaoCYXRL7p7aWm
         vQd3Uec+JUZe31msv+l4CHo51B8llTZIrzZ2nfj4kKcfwcgb0pFxUCmkuI4UXtOm7ABr
         Uj/ZoTrRir1ETnT6OF/q/3cL1ZD1mYDa28WZ871b3zyWCZz4ZM2f8D/BGiYvBovx3M6n
         gp9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435903fe0acsi16079f8f.8.2026.01.19.23.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jan 2026 23:24:04 -0800 (PST)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 14809227AA8; Tue, 20 Jan 2026 08:24:02 +0100 (CET)
Date: Tue, 20 Jan 2026 08:24:01 +0100
From: Christoph Hellwig <hch@lst.de>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
	Christoph Hellwig <hch@lst.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Bart Van Assche <bvanassche@acm.org>, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
Message-ID: <20260120072401.GA5905@lst.de>
References: <20260119094029.1344361-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

On Mon, Jan 19, 2026 at 10:05:50AM +0100, Marco Elver wrote:
> Note: Scoped guarded initialization remains optional, and normal
> initialization can still be used if no guarded members are being
> initialized. Another alternative is to just disable context analysis to
> initialize guarded members with `context_unsafe(var = init)` or adding
> the `__context_unsafe(init)` function attribute (the latter not being
> recommended for non-trivial functions due to lack of any checking):

I still think this is doing the wrong for the regular non-scoped
cased, and I think I finally understand what is so wrong about it.

The fact that mutex_init (let's use mutexes for the example, applied
to other primitives as well) should not automatically imply guarding
the members for the rest of the function.  Because as soon as the
structure that contains the lock is published that is not actually
true, and we did have quite a lot of bugs because of that in the
past.

So I think the first step is to avoid implying the safety of guarded
member access by initialing the lock.  We then need to think how to
express they are save, which would probably require explicit annotation
unless we can come up with a scheme that makes these accesses fine
before the mutex_init in a magic way.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120072401.GA5905%40lst.de.
