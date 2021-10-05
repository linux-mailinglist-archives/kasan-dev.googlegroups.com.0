Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNXV6CFAMGQESVII6CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EFB5F422586
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:44:54 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id d12-20020a1c730c000000b0030b4e0ecf5dsf958041wmb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:44:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633434294; cv=pass;
        d=google.com; s=arc-20160816;
        b=mYefrVAjDBNcBEWjGsPgukWGqrGptuV5kXIDw2u3nhSRgCX/As9n22GTjsROh4iXR4
         LVfOlqaQDtmyFmIcJDJoqSvBI34xIrbut5yadBh4evup/alqeX8PmhaYl+iRvLFQyoTP
         Qdk3ydVzUQ4JIVmN5LaYsJ2z07HRqL/GXmZnKbjBOm5t+PedQFajmKCjk0WLydLMnagI
         x6NRi1h1stl2RfrxN1b0r39Me08vRyQaSrpMJK3/DxieLuV4uUrIQ+Pc6me+yGYOucu4
         6hM6/JagKJzuinXsGqDv9XghKmQ8z6J65EW9BdPsh2e+KZp6cNq04fNaXWNdFXgMSNwD
         G90w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C0q5rKABov7bI34+Ddz8ytopFZSOZqGFiPywd8fxC/M=;
        b=wmyb4wYu8vjeNYKQ7Cr3OIdGDrJt25qfR5vXildXRyYAdk1C3NDlqlDcO+jgsVTMvU
         SgqzA44YZRvz+NaBscWdlQPrr5DUVGHyRBxrUDXhbj9ORYb0Xn7NHZ9g1MkFYC/LAz9d
         TvCE80OH0MpCbpQ5MX/DrHrXRdSIoQGw1/46/P4Wgq6kc7YEqIvmRyJi6M5i0bnXpvxA
         GT4CKph8OwuKh/W2xhy+WjCiZ6EAQ0yYnYln1L2M5QEELdjzarFpUXH7lWwrX8pmA+nk
         yM/+WdZujKovCwdvaawmHT8lCQRQyIVcXqpPEdUNFWtORsCZdT8G7IMWvSutowjIaedC
         Y/0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QwhZudjT;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C0q5rKABov7bI34+Ddz8ytopFZSOZqGFiPywd8fxC/M=;
        b=KS7ALPnmgpEphOsKlm6STMZ1YBPUqgEw93zUWZqj73yPOAGJ/5fwymwah3u4/8lr0k
         CA8OcAMP5g0RfQkY/0R1q/muOzAiB1ClCWZEdxKFWjv5jNWpdcSYyCFyIDRRiailacHo
         1MUNTzYnzvLBd5rBcHgGCC/UcBQAZ6uC2UXtdF//OiomPyjyvd/tsc1gYPr4VsZ1iviA
         hRY8uwphTEEzcpzMGXAohP0+FpSlC8OlKHuNNRUOziRiwj+Kj2aSM3XLrZd4RH1EJh9/
         uV5D8yzkdFn/znWTUJZlmQszlnMMMUhaqUgu8sT7e4UMUFcu70+M+yY64ETNZyGJBejp
         9e9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C0q5rKABov7bI34+Ddz8ytopFZSOZqGFiPywd8fxC/M=;
        b=XrZS6VneLuaoJq7LcjyNS8KerdlLUfGlw6B0R41sjrWKzbe0u1bYMThTMP5H6kKPX6
         oWCapX+998H+2UCOs3n54sKajjfImq6GyCzYe/WyM9f7S+HANQ+neUifFsTympso4lat
         D4wVu6mm0jQ7t8hi8gapzZ8je4AcBeafyWC2rGwK9hX2GtI78LNM0AROAHQGWpm3e1yX
         rT+tExemhANvj7WpbFz3Th6rMRTmohOgnWEwHmNDawztCaWf9iu0BSHTmBM1ge8FDFr6
         TEkA6zwZp6UcER955ca3s0WRESohC4j/aPcuXkeLOxgBREu1uAI2MfkknWFt+IIH1FER
         MFqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Q1hASGnJ0Ol6mFRvyyeVDcNZX16p0b/ziqP5U72WFQAj0LDqA
	QB30zRQpLj2epSoOOADamhY=
X-Google-Smtp-Source: ABdhPJzy606mB9uH1K8ZophUbLaRhCxC6x5gRyc4MBxEql2L6+XST8EwHNUBc2COi9SsYQVOtn0kkA==
X-Received: by 2002:adf:8b47:: with SMTP id v7mr20658259wra.321.1633434294734;
        Tue, 05 Oct 2021 04:44:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls2029560wra.0.gmail; Tue, 05 Oct
 2021 04:44:53 -0700 (PDT)
X-Received: by 2002:adf:a350:: with SMTP id d16mr21391070wrb.136.1633434293909;
        Tue, 05 Oct 2021 04:44:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633434293; cv=none;
        d=google.com; s=arc-20160816;
        b=Y8qR/mO31IBH7Q45el/0pK6BRTiwsHW7bF5bLXSuv91hG9lwIZDiwaVDuqn1zm8s0a
         ej+Ygxto8F8Xec8AGeSWuQ0Fh+rFLnpjFe42t4oOOhDF8jcdCJmrO6475FdCJ44JO5Xl
         8ykbdJdd2Pue6hgd9v94qXYLbSqbRQwPJ69ezWk/NqWTGpzkYXVFraaOwyubZ0Kv9b7D
         FGBnYLazAjrL6RsacG4KRJwV+vYmjs/ruVuUtXiOeRZYBObS0Rc8Zf/Vom/erPXj8AlH
         OZi5LMzWX5wrksHzjnlf6VGLr7c69kj+p/DSe9zK2jPsjaOqwb6YkjMFJza9reR8j9Q7
         7Hng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ffKpkAKU6pM8rv8h0B9+33I0DIIEdsYkyFi/KKBw/n4=;
        b=gZtZUYuBzWO+KEjubuOmkcGfDfM7XRE9MdRtJ4yEzj8bvp/EWvrqWo3DHkx90p2TIb
         isu69YG/Fejz2OWnctjt9DrxRj/SjID3ik4FRnR5pNUiJ0MFgjWnl79bDhMmnKh5hf53
         a1rdjPrba4uMquh6gOwQREDuQjPkDKJEXNeabv97pRD9pBTgvXgZ5YxNLrMqg13+Dn/O
         IJT+1LExLnXdo3P250eVw+va9tZ0ChmqgcMKPW7F7lU/m2WVmzfiruQ5jU53BtKik1oB
         hmDx63xseGWQQYODGYxvpkie7kEdGy9F1t6ZepU6VQNni2dh2hPHVb9v1QWi7U9kxA+D
         v2ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QwhZudjT;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id l3si92858wml.2.2021.10.05.04.44.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 04:44:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXiox-000MNr-Vi; Tue, 05 Oct 2021 11:41:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 622C630026F;
	Tue,  5 Oct 2021 13:41:18 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 452272038E207; Tue,  5 Oct 2021 13:41:18 +0200 (CEST)
Date: Tue, 5 Oct 2021 13:41:18 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 05/23] kcsan: Add core memory barrier
 instrumentation functions
Message-ID: <YVw53mP3VkWyCzxn@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211005105905.1994700-6-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QwhZudjT;
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

On Tue, Oct 05, 2021 at 12:58:47PM +0200, Marco Elver wrote:
> +static __always_inline void kcsan_atomic_release(int memorder)
> +{
> +	if (memorder == __ATOMIC_RELEASE ||
> +	    memorder == __ATOMIC_SEQ_CST ||
> +	    memorder == __ATOMIC_ACQ_REL)
> +		__kcsan_release();
> +}
> +
>  #define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
>  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
>  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
>  	{                                                                                          \
> +		kcsan_atomic_release(memorder);                                                    \
>  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
>  			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
>  		}                                                                                  \
> @@ -1156,6 +1187,7 @@ EXPORT_SYMBOL(__tsan_init);
>  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
>  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
>  	{                                                                                          \
> +		kcsan_atomic_release(memorder);                                                    \
>  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
>  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
> @@ -1168,6 +1200,7 @@ EXPORT_SYMBOL(__tsan_init);
>  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
>  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
>  	{                                                                                          \
> +		kcsan_atomic_release(memorder);                                                    \
>  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
>  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
>  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> @@ -1200,6 +1233,7 @@ EXPORT_SYMBOL(__tsan_init);
>  	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
>  							      u##bits val, int mo, int fail_mo)    \
>  	{                                                                                          \
> +		kcsan_atomic_release(mo);                                                          \
>  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
>  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
>  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> @@ -1215,6 +1249,7 @@ EXPORT_SYMBOL(__tsan_init);
>  	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
>  							   int mo, int fail_mo)                    \
>  	{                                                                                          \
> +		kcsan_atomic_release(mo);                                                          \
>  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
>  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
>  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> @@ -1246,6 +1281,7 @@ DEFINE_TSAN_ATOMIC_OPS(64);
>  void __tsan_atomic_thread_fence(int memorder);
>  void __tsan_atomic_thread_fence(int memorder)
>  {
> +	kcsan_atomic_release(memorder);
>  	__atomic_thread_fence(memorder);
>  }
>  EXPORT_SYMBOL(__tsan_atomic_thread_fence);

I find that very hard to read.. kcsan_atomic_release() it not in fact a
release. It might be a release if @memorder implies one.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVw53mP3VkWyCzxn%40hirez.programming.kicks-ass.net.
