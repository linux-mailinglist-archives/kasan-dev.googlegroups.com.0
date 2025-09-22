Return-Path: <kasan-dev+bncBDUNBGN3R4KRBAEHY3DAMGQELLMFRNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CF78B925CD
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 19:12:34 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45de07b831dsf33046975e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Sep 2025 10:12:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758561153; cv=pass;
        d=google.com; s=arc-20240605;
        b=f3TnGiTJD5QNhLcNpy6MyiP2DsAVyM33oIjfJJCSP03dxshhxZuv1CX9ULF8JJHh3P
         WZASQ1kea+74Op6M7d8A/ZiDYaYf3PwfgUqOhukDbu9VBCatJpMXUIv7/JekXSjrlt64
         pPhC7YivXtQVX0M1LW9HxjlDlnyLZ4dHzwnmr+OB1c2LC+ve+3Cvza1kFNH4dkGM4ZhU
         jUwrHFnGeB9JlNsWXqu+ro3+NgfEsQuFs6XUwbEynqR4waB/bKGdl5dyEKcPQ9WNxOxq
         PaAy4L1EznLrImLQUu8B4NsoREgPNOs7rZHBCgRTr+cVQ1hmRjU2WFXum+TuNYo3ciAa
         P8AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=MIXg8TL70RxiCkU8lKwC2FbcRWS5/fFPtyaVk3yL7Lo=;
        fh=1hCZwCnn7pK5S15oG54bZEtTniEpAO6YRSN7T5L1k74=;
        b=dRHx8DTI/T7cAllxbwkMpC+MQruXCMyUF3sSpTkowPkITnL0Xm2IaEwAxWFRvPD2Xg
         T79SY9H9ixSweLBqu68GcNfYMiysr8vFNj2jZrXbQSI15IvbUqpe3jdWIOXXMmYyJzAk
         tSipPZcyEdnmBKONj7c7ORdzrTrVP1etpeMuqR5h0lXlgV15dyIuy3WlrsbqWP95uJ+D
         qa8/1wD/7n09u3TkGeWbIRH7zlgIvEZAF22EqWOGx4rQbJsVme/+LaT3l0SflRC/Ra7k
         DnjaHvoxzYyhnZjWo8nygwMFsHvvTxgKzaW030ubtJux1FlWbp5W4K1vfAUKuwDomSUK
         o2FQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758561153; x=1759165953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MIXg8TL70RxiCkU8lKwC2FbcRWS5/fFPtyaVk3yL7Lo=;
        b=mVrPJtY5hQiXNjjjnYEKS4QYGXUFDqUpE9iPiPXMKAsHO+YNZzzIryVINabx7Ujs7P
         fR9g1jFXCHFRU7mUjpH4UbcOLDdo4V4d/uOhQxlQi9lr2QVlHwJDX+0l46GPi0zN1Seo
         GsXYkKPTwRIuHgAYev9pURp28lm5UKEODpjBNoGCuLeyAI7PelEQ/qGem5mS4kP+yIRq
         NRO6NtsEYjJ+sJqryjkfBvxXIwwBPV9SR0si9IlUOAh/wIuP0BpqyGBkOnBQdNJupYni
         2FFvMW0XonHlzemKPmpUGXfZTp61W8puABdy9KHLgOkhjDiSISTTygLj/2XG9YGHF+lD
         l7DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758561153; x=1759165953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=MIXg8TL70RxiCkU8lKwC2FbcRWS5/fFPtyaVk3yL7Lo=;
        b=ZLS04Klrz5WjcMcE139rQC8QIPqMI1zdffYwxVYq2FxY9pmQh6oefs6kfHA8UNN+VF
         +aG8M0yQpxPYlwo6R/Ct6PYVtnYq6vZeeKQ9nKJFW6F5RuPRyjeK2WN/zs0pzbQ3WTFk
         /1UDmVkqzWv/ivKGMi3uJE5ac21ErT90/6tbztNMOsVWuX4F8qnK80nTMGxl42XbdkwX
         m7VnsaPC1FrHrDp5TmZ6DMnBt0dhUkm6GtfG+7YQhZMbMqwxmsZ6RswlwkDYXjtZGiIC
         dEFSjMniS/EZ4XpcpJaF0+37qNOJCx8tKdy2Npb/egDH7gmD4tLIv3xc9bkuUxilhOIm
         FrMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0xCvSbDDGNFtV66k2qi571OlgJZQnZG28hsnPmKHP9L/Wqtj3WmePxJghlM73gxaW2c1awQ==@lfdr.de
X-Gm-Message-State: AOJu0YysXv/OyiMKZLu557quLVMCVvEHwfYW1Yz/qeabgwOngZjeqNFs
	MUj8AIKSBqwkgDEqpuNJ6jLlTKEK1FjjZPZRFkJKjQRLTcQ8eqL+BjI5
X-Google-Smtp-Source: AGHT+IH3E9a2tEauz57aQUMYj6yu5rIfdiVByaaY12Ef9zMQlSpo+fvPPMrubSf64hrOYCCK/+/x2Q==
X-Received: by 2002:a05:600c:a48:b0:45c:b5eb:b0c6 with SMTP id 5b1f17b1804b1-467e75eacd0mr134683375e9.5.1758561153092;
        Mon, 22 Sep 2025 10:12:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6xWfL8zzavoYuSpyd0bbkt4XJeJ0Sk8+sfIBygkW5eHg==
Received: by 2002:a05:600d:1a:b0:468:7a59:f88b with SMTP id
 5b1f17b1804b1-4687a59fadals16979255e9.0.-pod-prod-01-eu; Mon, 22 Sep 2025
 10:12:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsdUlB6/GPh83sLAatfBvw9DJyysn98uKe15QUXkIIvm4qtWlmSpCVY+MPV+3G5fpq/WvlTmDZpjc=@googlegroups.com
X-Received: by 2002:a05:600c:5246:b0:468:9e79:bee0 with SMTP id 5b1f17b1804b1-4689e79bf3amr122523295e9.0.1758561150051;
        Mon, 22 Sep 2025 10:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758561150; cv=none;
        d=google.com; s=arc-20240605;
        b=X6bfQ9Kk0Tl02pzTFAYOj3MfkW1/d9IbvIWKWlBfnmpBx3YhY3vWbaAOmQLYw6jXlp
         hdA8hTrfPpqEHOb1qmNpdeYIiljn5AHCqSHFvcFgu7UB951P4rxy6+KNSNgRqhDHjEq7
         Lm8eqIA7wk8dGO7B5HddaK4B5jKGNUDcc0oWvG886S9MVAVF4NlfLh9Qb3Ds5v0coA3n
         NeyhuJW/OC1ODUjjcf/vLV0+tLjNHh9WNz5muhrlFFxfTsqm0fsy47ItkiiHkqiLnH2d
         s/ImmoZEIzOeju9yPlLpQjD/NkfsvZ40uwZa7/02YohicwauJS3U7Jx4d8aptYGWHvor
         JnGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=hVd5FYeaOOqCS05QvLLgASbT7Tr3N+hlXgG8BG8Sjtg=;
        fh=0W554JPPJw3oLqB7bwJ1EtKggrpHbLK5kc3l+XcjoAM=;
        b=N/7VnJd/6xMRFKSLARJCjq8tjFQanlr/F5ALPmdZhoW0K8tis5GJ79INLSsQIiWyvV
         9ntMBAYQCE4TyJTS0pHC4YR0Em91zClZZnibDjOSwJH0KEUXeq+KvPm3GxBpQzaahwt7
         xIdc381QsM4M8TVlXJCyP77t42RbwZSKa6cEZ4NCpp7pWibTFL+byHZG5ivzmrbZTEq4
         sreVaghUTd8vR5lTg/jEPbjx7/0QrJxSQmdzScWgmDpIm6sYmJ6QahyzgzPbRT8KVXO2
         fE0cdBNpPK7guQH3caCQyrCod4haOvO5u1z2RaSBfWXyT+ebhEQUBvrI2nCTVSWFURKR
         TLWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e1ce0d04dsi24675e9.0.2025.09.22.10.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Sep 2025 10:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 6B6BB227AAF; Mon, 22 Sep 2025 19:12:27 +0200 (CEST)
Date: Mon, 22 Sep 2025 19:12:27 +0200
From: Christoph Hellwig <hch@lst.de>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Christoph Hellwig <hch@lst.de>, Nathan Chancellor <nathan@kernel.org>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bill Wendling <morbo@google.com>,
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
Message-ID: <20250922171227.GB12668@lst.de>
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de> <20250918174555.GA3366400@ax162> <20250919140803.GA23745@lst.de> <a75f7b70-2b72-4bb0-a940-52835f290502@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a75f7b70-2b72-4bb0-a940-52835f290502@acm.org>
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

On Fri, Sep 19, 2025 at 10:20:37AM -0700, Bart Van Assche wrote:
> locking annotations to kernel code. I ended up annotating multiple XFS
> functions with NO_THREAD_SAFETY_ANALYSIS. Maybe the locking patterns in
> XFS are too complex for compile-time analysis?

If our locking patterns are too complex for analysis, either the code or
the analysis has problems that need addressing.  Potentially both.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250922171227.GB12668%40lst.de.
