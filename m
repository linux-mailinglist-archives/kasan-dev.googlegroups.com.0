Return-Path: <kasan-dev+bncBDUNBGN3R4KRBVFSWDDAMGQEXNTYM2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDFF6B85493
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:38:13 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-45f2f1a650dsf7406695e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:38:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758206293; cv=pass;
        d=google.com; s=arc-20240605;
        b=eWTD54g0ouuScKbdVaJgG6FnvlyZnSWmCJQSpDk4lc8K8xr6RYUI70DKLtyONeWEH0
         A5ausdhfuAyGMmozd4DSIHKX/kpb+SP8TnoZlk9We+hTa8ogrQalheQAKVJJk24dKhQV
         xkpjPAKtgX5rj9WOyDZtBcHcGsHRJSXgRfU3NMYlpJoCsPZYLC9erlIC0tye04HVXELz
         SOJDQnmN5tulJae+PGPDV+bfkI/3qRYIgbGi1Pp98NOPswsCLSfzvlIk/mMdZSjJ/PP9
         z6th5sdgYtpzyiq7JkPWvr4Vsv9+OTH10oDPABjysJxZRaIZrzDrgylTsYGZRAkkwPrK
         WLAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=clpyeJjgxfiOZ+4kUtvuFnYGEUFYXk4n+5oPSbM7JRI=;
        fh=vcc0USwbHIZi+2ml/stIXtmQ+yGVTCHOeYWJ40985ZA=;
        b=b7ebOX7KZjweahRVhcaWKPqcqnwg6F/vXjUi/6yiH0tKr5m5FXKcsWH1SBwmGt3lK1
         sVAFXqq8Aujkq2qczk9GElVuGP09pY0tw20FwZj08nG//u3+wj3YJfBfRVoV6HfvDvrH
         VsU/bF5Y7yD40pdC7FDGsiMjGXaVQnyKOaI/gf2TebR6bphF/DzDnWy5xDHtasufsaWV
         bWRgiWiVTTOc7EmMnwSVef8OKiZg8qESRBPGG8oDIt76GxMFcC96PSjc6KUbHN3OJDdE
         I46eIjvZ5OxOsGDSN5nf9NLJpfiM7Qb8KenxG4eug43XKqccQ53afHYtXg4+9urCDxLn
         SU5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758206293; x=1758811093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=clpyeJjgxfiOZ+4kUtvuFnYGEUFYXk4n+5oPSbM7JRI=;
        b=VK1wdk69E2GpqtMGQoOvyzUI0sXH1HWPIZKzmMnyN7iJ48mR6B1uYoZR9B2yYien7n
         p00kDBJVfDVzB4DlmKe5JJ96DyDNSwltyiEX7cOcwUbdHL/LCc/tqkeyRA3fPeEKv813
         m98grwfOWLuWE9Oh7w+o2hhX1iLTaCYoeOCIuIMtevWYnb4iirgcvDsxX8y7SedrU3wC
         DM0dg8tF25RjfDZPzu334ZrISTgTvjvSdiMgVGwDL6HvkDjFSyZiXn8a96UcbZVBnNcZ
         ImpU+eJZqiJkeTbYl12k0cC2wV1c9shXRXIL+iZZbkZf+pAvztP2yS3Iz3k6a1TvZb/R
         R54w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758206293; x=1758811093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=clpyeJjgxfiOZ+4kUtvuFnYGEUFYXk4n+5oPSbM7JRI=;
        b=Ur6yoRWprLz1pl8RWieTcUiuQvAH3RaevXWGjQ4VZfQaIYeIdkqbtS+3H9/Hpd0JGP
         a0ACj+MKSIXkbRlgivYRUNjPfRAdd53UskWxNVk/uRmhO0ZGtmn0hp9mCFRlFiK7x5vs
         KwsnGigK2U73qhz91crs44zgiHWz/EqeAJ95qmbzMx3G2cj3ejIQtgxMU2O7WoBg4360
         cU4uphL3xMbWDLxzy187WL1rZrp28THCW6HVaQzZO5aBZyt3fD7DvI5/Q+8KwzDd1dWR
         cdn1wW3UzArfKGvj/Phquf0UmKKzi52aOfgZp04cdf67bk6/o22uepJK+Y9Go6bHnW/D
         FNeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKUkSKYnF6dYYsm5+SSaoxq8Kl15zdeQ+Cm7n0vZxXhESNrvt8dqP6cMam92BB6tSiV5Ue1Q==@lfdr.de
X-Gm-Message-State: AOJu0YyUZWIO8TAo2BrwoHsZZdRBzGJXdGeLB+IB62fp8XfPKoJBTfQc
	joC8GMulRGUIZw+mql/wHdw4Uc2b39u+7F4mNQ6qOWyjCPJDuxqPLvOV
X-Google-Smtp-Source: AGHT+IFNBxk6RNFuC1cUpzd7KyG7SaDDvvykcTUC98Bmc4465aHS4UKZT+FPRZrFOJa/CXjD/+9oew==
X-Received: by 2002:a05:600c:630d:b0:45f:2805:1d0 with SMTP id 5b1f17b1804b1-466643562b8mr20951415e9.34.1758206293259;
        Thu, 18 Sep 2025 07:38:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6iTZUqreARhZyf7pP4BRyXqS3Gv0/6sZqbf/wpgp+JZQ==
Received: by 2002:a05:600c:8b2e:b0:45d:d27e:8caf with SMTP id
 5b1f17b1804b1-465452e453dls4508545e9.2.-pod-prod-01-eu; Thu, 18 Sep 2025
 07:38:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoVLqqorvF5PIuVWzA947y8mQJ7c81Ly3htPMmwjeaqgZgIcRaptsbO/fnrcBXA7AX1eDBpozZGHI=@googlegroups.com
X-Received: by 2002:a05:6000:4021:b0:3eb:4e88:55e with SMTP id ffacd0b85a97d-3ecdfa0b182mr5229923f8f.41.1758206290209;
        Thu, 18 Sep 2025 07:38:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758206290; cv=none;
        d=google.com; s=arc-20240605;
        b=Q1s34jAUSJWckVbMitvD/FHj9V97E9+u4J0/BBWZW4GUaLqZ9d2vrPeKgY472cR67H
         pH9q3XbtheTPI4+wUSkdrx2YvjwQ8BFcZg5IaUeC5vH6bOB/QPEM3AZxpZmlBpGr/eig
         7CrSt5rIQsGr+QxnyzONC4AP1y9gBuat2BpVGr/7P1/2mRqDqmqsca4MsK/K5+3ba5rk
         kuf+Oxkva81s+JiOs8zBXGJGW7xfN2W2XOBIXS+foqeabiYfuDC0SrTPAfbhsCO7p8qV
         m9gb0CvenmxviT6hXVNDZ4deqSPukOKfWwv8QwLIUNQlFajI1KP/TyC/0+y2ioLr/IWn
         NcVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ErYq1TN2gNxHsdO/CoNyrv+xOAeKq1mQd5/OAeURC+w=;
        fh=kygEiGmfbB3OTVPh2GpS/Zz7j0Q0J3HcfJTPbQs/A/M=;
        b=UFKpqbO2Vpp2EtdhogB6OAePX+GwqyN+xYrqcJaIcWmQUcW9zOpuvgDaZd2v76gZu3
         fTL8uqhC55voOtRqGGLRzGRrOJIVIPScJE4fcHsBVf4mIcoOea82aOgwh9C02Vl25fQx
         w8OZM+tjX89jVG2l/fuKqD8tnskGcKIbNYtdHSoQ8dbbpRmuEOn+pvaQl+ngdUoU9BT2
         BJHy2GAGWW4EfCVujQFte3NBgsb6V0XZHqS/srqGuAXR0tIRldCaKZ7tH38a03pG/UDb
         aPwp2tpctXa51XFgG8oaE8d1S3XMJUkbl4xFELgtiISF/Fhr+SByeA79hTkhgfQeGNi9
         b8SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbb7c0esi43427f8f.6.2025.09.18.07.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:38:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 95E65227A88; Thu, 18 Sep 2025 16:38:05 +0200 (CEST)
Date: Thu, 18 Sep 2025 16:38:05 +0200
From: Christoph Hellwig <hch@lst.de>
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@lst.de>, Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and
 Locking-Analysis
Message-ID: <20250918143805.GA31797@lst.de>
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de> <CANpmjNN8Vx5p+0xZAjHA4s6HaGaEdMf_u1c1jiOf=ZKqYYz9Nw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN8Vx5p+0xZAjHA4s6HaGaEdMf_u1c1jiOf=ZKqYYz9Nw@mail.gmail.com>
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

On Thu, Sep 18, 2025 at 04:30:55PM +0200, Marco Elver wrote:
> Not officially, but I can try to build something to share if you prefer.
> Or a script that automatically pulls and builds clang for you - I have
> this old script I just updated to the above commit:
> https://gist.github.com/melver/fe8a5fd9e43e21fab569ee24fc9c6072
> Does that help?

Just kicked it off, I'll see how long this will take on my laptop.
At least the error checking that tells me about dependencies and work
that needs to be done before starting the build is nice so that I
hopefully don't have to restart the build too often.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918143805.GA31797%40lst.de.
