Return-Path: <kasan-dev+bncBD3JNNMDTMEBBKMESS6QMGQECUH5X2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71903A2B165
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:40:43 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4679d6ef2f9sf32056031cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:40:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738867242; cv=pass;
        d=google.com; s=arc-20240605;
        b=HTZiAOMjrnERY8lXDbfG9BqxMmfEAqSx41ghBhm3ejNKjOriLmuKeCVwBOolfnxW/9
         rvJfnGP6xkFHqxWqkwq9tfwHFjgVEJL0Z/ND+0KeFXsToOA6mNrEjFDtTkKfp866+DC1
         qlfE90UL2jBGWWE4bBhLI9IkbX8XgxPQmmHAXTjYRlsRJyVz+KRWRfHAdJLPx3qz5Ynb
         ZVuKazzzad/9pbu9+HgL/sZBeBOcJdQ1VVHuZRDx3oyyE74gcaZY+3WCbzJBoCSrNnLA
         RqhcuWrb2vPQgKDBp3AlyZsVqpFU3cZA4EtVVJzRy0OdY4btoeTSGge1c2h8QJiUBAFf
         FX2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=438me4lXpg+NAcgvn0xGtk47TsGGs96AIPsDLjBpXaQ=;
        fh=WV3kOGNyqqXtcpXQwSdge3nePbYQKL0n0XNSxdmcyzw=;
        b=an4/EtvLeGF2SvcZrTxx9z4AU7mO4GsAP9aDrzFlB9ZTZ77X66N04q6ahQlc087qMJ
         ZxB/dxrxlCFDhp9YOhqSl1arX7925rz9iZ0dWc74JjG+6uh72mP0ju2JsiC78C/XP2d6
         +huTI/rnhINR7shqf8+0CUBSqpggXYW2UWFv/MZdSYF9mTTPnJavDbIf7uDZs6N5oOZR
         +kzQnsthk0qSzFmoGjDdMMmGalQdqzSxM3NBiTa1gnEtaPFziUVRuufbEnQiQVC8JDxr
         gzki3VS1lEHb9aUS85sJanG2aoxh1TPFoWUX47GdyaNgjDD12+sH4b4Qa6w9f65/RP6J
         b54g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=gQY7Abju;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738867242; x=1739472042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=438me4lXpg+NAcgvn0xGtk47TsGGs96AIPsDLjBpXaQ=;
        b=Y0rhAstHEptqFYR7AbcNMJBoe9uUJSCpSBR5gZWdf+xOC/kmtTaV//2Q2+ErwljJ19
         QYMcMapmD5xwvyrSSYQN6LEZtn6OvD32GcMu6qOOU688YZlCG0rnsHqJddNaGI3Xy/1G
         odqyV4+N6N00lwdi/yufT7Hw6+V4QjlJ95YrzcmkQ/HHCphnx2rt756jwjLu2hH5iieP
         s522srltzODWfUV1N59fzH2YurvzeXeDJxBkqIJvmj1tiJBHyrpRkxqg4GlEkc4fGlpt
         Z+0plk5mCpM0FNVxx7OCBn5bsqNm+bRovVMxktQ451yM/UdtP8FAGja76RxKYwMEgTEP
         DyYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738867242; x=1739472042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=438me4lXpg+NAcgvn0xGtk47TsGGs96AIPsDLjBpXaQ=;
        b=QOd9u2vJdvL8unSu8arJp8EXsskLqtPHcUyBh//OpRwMWwUCs8bXAp/LZvtVbyg9xR
         3dPzuejh86NXZhBnhGDjzQ2IhsqChvYgkP4TQoiglrPsYukDB/cSiCOAA3XcnVZw3eCh
         yt8MqeMzy92fkTp0Z1JefU3hxOx9V+UfNm8YWQtFXn2TvqVG0rUW6ZdR0QYBf/BpVKGK
         f4jCPLa2aiGe9WYQTBhEotO3Lp0ayYS1ajNbI5jniuAASvAyzA/7yhC3MREsJjrnSBWG
         z1zKqmkxvbb9qeAoIPJCk7VWJDxgQK57Q60odSwEeLYVGFM9WF+hmrfmACGoSZ6jVyOO
         KxmA==
X-Forwarded-Encrypted: i=2; AJvYcCWYWjA8wzdNyTPwYlkVcOmhyeSx0fMJ4sLOlvZugkmWG3qfKFwPh2nfJO6UMm9r8l1O/NDWew==@lfdr.de
X-Gm-Message-State: AOJu0Ywg+xB8edLNGIZrYHxhcFwZuSM8iA+lWHtGNwcdpfKur2GyiQM/
	gOekNth5q1RwRzlHSDczYUkY5UWbvK2aKQmwHYlpdxkTFhGOPaxd
X-Google-Smtp-Source: AGHT+IGJGSO+D4Je2tZXrsSYd2Oz/Mk5FCGchLw3DduRaA8WBu5CoMq3O8nOF7uLBhCUcAa2FCss/Q==
X-Received: by 2002:ac8:5809:0:b0:467:6742:5633 with SMTP id d75a77b69052e-47167a3763amr4742261cf.23.1738867241881;
        Thu, 06 Feb 2025 10:40:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=AT6nird0gKvJPiBZzHd07u1GwGp4vcClr69dQfJcN4OAeZfFCg==
Received: by 2002:ac8:698d:0:b0:467:4d40:31b9 with SMTP id d75a77b69052e-47167b776e0ls1449371cf.0.-pod-prod-06-us;
 Thu, 06 Feb 2025 10:40:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7SMPlNKBd21SmW0h4gLK70IRRtbUoabanDwl+0fr8mDCECo85LlI1ndT1FiOUYWBekUD8y6QGVy8=@googlegroups.com
X-Received: by 2002:a05:622a:1114:b0:467:6e25:3f30 with SMTP id d75a77b69052e-471679f5659mr4369431cf.12.1738867240386;
        Thu, 06 Feb 2025 10:40:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738867240; cv=none;
        d=google.com; s=arc-20240605;
        b=NIMjA14CvUkqNxLinvDSnhrXEWJoLTUNG6A6u5s906+nw+QfOkPU8pNPy3jutjCehl
         gNup7NGM3CvvbB08nJuBiu8hfqiPbG2jvrQfGhexsuUz8cRu49GwHxxzYgJhDUf53C59
         lL5bR4RMRDfJFgXHdIOczHy7GCemysi4ZMGpb4kkk8GmgzK4KbksDVqdzhD5qSEl/riy
         RowWtBA+a3eg5ng/4jn84WtRH+IAZvX6K3b3ERpuHeG/YfWN+seEW07GeqoXviQ54x6C
         Ff/sotQHNHnWYgQWBJDFbkp13+z+hZi40G+wesguVjTMSBodops2uksklRjCUdrbcjap
         cUlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Yyh2TZL3d6MbabLSKwMavcSPt1k8xkVlfy9IlZ2yLS0=;
        fh=0Ovo09T/l7iyAM2CZR26Zg4xB/uj/2vRoIXmdAf37Lk=;
        b=Nv1kOeWQWWEQNEb7Zkm+z4uVKABuHVQoXfBYl7kv/Ih81nNy2XZShTBrl9Vgq076Sn
         q5We73i1Nqdv0Bf5JeIrt7K8Iq2Rqg/LLPwnRZD9OC7asuZNOgebmyXlHIHu4H1gb+nf
         QK4NEYjgS4gnyaOQFYjXXKrYaQFom9iMdF1FFP3YUnZoSwcfOMQhQEkUAx9otdrBp2hs
         QV81kH8NcO30kKMg6CEBxt3Fat/andzJFD8ULZak5xdOI9QIPsAt96yTj0lWFXH8oRrO
         vlUbGjhknXWIfgePuHIEyUopBRtjV1nNjS1Yzjp5bzaCcW5EmyjnMzKQMSHmfyoQJhGL
         ADtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=gQY7Abju;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
Received: from 009.lax.mailroute.net (009.lax.mailroute.net. [199.89.1.12])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47149273fbfsi802011cf.1.2025.02.06.10.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Feb 2025 10:40:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted sender) client-ip=199.89.1.12;
Received: from localhost (localhost [127.0.0.1])
	by 009.lax.mailroute.net (Postfix) with ESMTP id 4YpmBb3nppzlgTwF;
	Thu,  6 Feb 2025 18:40:39 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 009.lax.mailroute.net ([127.0.0.1])
 by localhost (009.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id MKbvYFl6_0ku; Thu,  6 Feb 2025 18:40:27 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 009.lax.mailroute.net (Postfix) with ESMTPSA id 4YpmBC6m3KzlgTw4;
	Thu,  6 Feb 2025 18:40:19 +0000 (UTC)
Message-ID: <552e940f-df40-4776-916e-78decdaafb49@acm.org>
Date: Thu, 6 Feb 2025 10:40:16 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 01/24] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Bill Wendling <morbo@google.com>,
 Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
 Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>,
 Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>,
 Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-2-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250206181711.1902989-2-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=gQY7Abju;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.12 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=acm.org
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

On 2/6/25 10:09 AM, Marco Elver wrote:
> +/* Sparse context/lock checking support. */
> +# define __must_hold(x)		__attribute__((context(x,1,1)))
> +# define __acquires(x)		__attribute__((context(x,0,1)))
> +# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
> +# define __releases(x)		__attribute__((context(x,1,0)))
> +# define __acquire(x)		__context__(x,1)
> +# define __release(x)		__context__(x,-1)
> +# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)

If support for Clang thread-safety attributes is added, an important
question is what to do with the sparse context attribute. I think that
more developers are working on improving and maintaining Clang than
sparse. How about reducing the workload of kernel maintainers by
only supporting the Clang thread-safety approach and by dropping support
for the sparse context attribute?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/552e940f-df40-4776-916e-78decdaafb49%40acm.org.
