Return-Path: <kasan-dev+bncBD3JNNMDTMEBBPP2S3FAMGQEMM7GC4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B519CD1E5C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:01:51 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4f1d26abbd8sf53791681cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:01:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766178110; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lvf/Ui71DtZUAQSTsA4h0VBZzpjARf8bZOdAuUjTRI2KqjMHj7o9TREkmEynOX9Kde
         zz0laBvo6Le+9QsAIimM2A21On3H7Wh/x5KLx4F3RKISL4WEex7RhrFOxDEg62whSEar
         bKWhZb/Og6AypxZPQMEMJxmyzgQnYJYx04l2NGYub3QnkS6r2X1ArzJPgyyhI7CU1qgC
         dz5sq/1m3t018dCIPw72lKHwZiyLv5AYohFLiMPYA0TLufMYaitat/VMhLnxnD+n8L8D
         YVWQLuu99kkRCsmzGh5v2A6UH90mwYcPaD9W/20L0VKVzVfYegJ41aOMQWwjkjE8z74i
         hSPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=XRKKdg1agE9wNzxivQu/dRsQQBApqXNslOwxEC0wA3Y=;
        fh=iwMGrTYQyLdOUFpjICipzEXh+dsnr7bGxGhs3LF7vro=;
        b=YczpWQTe9l67rwWhfIDsBIeC6Upwa4fLlZlVW7nZSeeFxxfmtv+2GB6S+ipNvXOhjV
         0czGCT3sfqIoXKP5B5yDtxf+CjBE0MKRLuNDmmN64gEUf4hZlFxxSo0DxxvaNRmk7YQj
         P2KAbf6RgQo4/XSp6Z6k+q+fxuTx37+aLIW3mzOeclNcDfeovyLXooyY/MAIpgu7wCuF
         aJzyzGRMHburTBwBn+oIr0LVxsZde1CPF8zxogGf7waAAmbc8KIlsbNj2Jhc5pOrV0bO
         OWR2sF5anF0HtEjETjE8paBgRl0eFtI3NKs2U/Ic+LmprYeZgcbbqkBRG/sCgCtvDRnb
         B0yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=s9OJBwkd;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766178110; x=1766782910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XRKKdg1agE9wNzxivQu/dRsQQBApqXNslOwxEC0wA3Y=;
        b=eHm8ok8bTcscUnI86Ce27DvoN/H2PRQpzrt4DdtGIChUTA66WoVx2ba4Yu4jDyXvlY
         1OEntkONxtAJkHfCH35kJfzedKum57yeoiV5gnNqu32EILxNoJe43Vg6bH/oM4l3Z9Js
         KDbuCoj4GhX4txcvmO0QASbSfPqcRZaQgPBvBW4khx5vHYc/mQF+lr/IqXmvpG/BFeV5
         WLZYLL4zY5SBuw2bj+jpeUb9rizFL6Kxh+RR6U4oom3vs8iyhKxpJCH8P4bsWibieV0L
         1J3HI+GfvWo0Ti64yqUJ8dwprMVBPTF4JRaSR3awE7ZZLt90qvKDFt5VuD/SfjTjEGhn
         RsQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766178110; x=1766782910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XRKKdg1agE9wNzxivQu/dRsQQBApqXNslOwxEC0wA3Y=;
        b=IlNSCiMXklYZaW/tTBG8gL9+zzT2W8OVJi+svz6oRzbm1QxYw+FgdK+FlLKBf+JXSr
         Zy/0dY0clp/gFTi/3yW4JQ34aOBrKZVjoWWJHsKeGt3ZsFXz8wEhBo4o+uxPjbjm3P+f
         ViSKSD1fsTZI2MpkY0SIj1sg//T2WhQloiMEIU6H9Wae+DgwCACwRFQfcXS+aNFAHAuW
         HGg/PGsLEHbBtXBvJQV3+w0ViL8gYqIBh2cG9q1RjAOmtuVIdvC+84nwfhf3RYTtH9Cl
         7SY03iz9cvLjq8axcToYWZRmdFFuyOhQu1Sx4o/kCYHyuTf7gqBJDcs5vNxk2kpaUfnG
         OTOw==
X-Forwarded-Encrypted: i=2; AJvYcCWdA/zojenuui8T+t8eycAbBeZq0bQTg266fVr7z3UGW/kKF3EvG8pelXLRpyunA30CuuEEfQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywjx9pdMnLs+Y4aegbONNcDGWEUmMJEbki9JL80aFuX+z4GWDwa
	FpePRTIVGLJswYXoU3jxInGRi3cW/8yTtfd46Ubgwni1lKovAFqcTIrj
X-Google-Smtp-Source: AGHT+IEOXcn03Uq/6N8mB+G0jGT59TVsOhrz6O00oWGH5ucaPzkiu9f1HWn03rllRmk3UrXfArLgtA==
X-Received: by 2002:a05:622a:2515:b0:4ee:4a3a:bd05 with SMTP id d75a77b69052e-4f4abddb647mr60719761cf.74.1766178109871;
        Fri, 19 Dec 2025 13:01:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa/9/CgBisIi0AU9+FV33ZUEsDkrcg+5cC9QBSLJOiheQ=="
Received: by 2002:a05:622a:10e:b0:4ec:ff90:36a1 with SMTP id
 d75a77b69052e-4f1ced3fd14ls128374571cf.1.-pod-prod-09-us; Fri, 19 Dec 2025
 13:01:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWzMWD9Z2m2Nm46E9eX9C8aLdfgrvi8t+GczIgA75k/7lhkixTMxZvDfks5wA+UNB5viHJZbYw7YaU=@googlegroups.com
X-Received: by 2002:a05:620a:2699:b0:8b2:dd0a:8809 with SMTP id af79cd13be357-8c0901239c2mr662527285a.89.1766178108813;
        Fri, 19 Dec 2025 13:01:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766178108; cv=none;
        d=google.com; s=arc-20240605;
        b=Sis1pTHdEFugTWUlZpHydiFzRJHcZ8YLJvqGudyPLiEzKl7vYu+4P0nKnffRAnCtlh
         OTzQWe1ixJsJclTWS19H7mMaVYXpq96zROHRGx6ZSzEYrhkxUOevLzErfslrtf/Qtpkg
         ZlJBBu9h2yzo5+leMrdM+ADe+IJva4Sf4GBY7Ze8YtnOHTzty3B58QB2p0Q9frlD0XFw
         9W4nPwYv6tuiVlSkGlPShe+1uPG6+uYJexP4J+bA2glFD6p93w0unLTypGwHpqloJ/xK
         GbZ8QVdBcrYWJKbwGySCm3eOPSJPqQ85vt9D2jXCG23NoxR0MkB7JOQm4b1z09pxKJKv
         +LGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9KjTqulqtSqtlYJ8kiScMrzEzgfg45JI8uubNScSnWY=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=WJZTKdfpKc2BYVPaoMulnPFXgYTkfjNn7/t312UIRr2EeReSN0E9mWvr++i+4aeQMB
         nrkjNa8EIS9bXKr2CX8mXCPQZk/FIRWVDQ6IXsOTZLJokf8hNnz+vT8ifZgktkTCpR7V
         NjYx/D4NAlLIhjen+7CdK0Rt6J+iUcJD/gLZpDRz4Uy8Fhaezk081dobKqw/H9l8ez/C
         LW+uGzqndSGF99aJgCjPNIuCF/0g6Ro65nJ4Hkt4XmECKkLf+DpwoOtUf2MfEgxLC5bT
         ayGlI1Pd0FlK1V19ckMMVq30VomCqaY6Duw+DeUQC+IOQaK0NCA3m7OJwuMXUmN23Uhm
         4IpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=s9OJBwkd;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c09658e696si21196185a.1.2025.12.19.13.01.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 13:01:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY0Mb6PP5zlxr5f;
	Fri, 19 Dec 2025 21:01:47 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id IXqnKxjTN97r; Fri, 19 Dec 2025 21:01:40 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY0Ly622Wzlxr5b;
	Fri, 19 Dec 2025 21:01:13 +0000 (UTC)
Message-ID: <a62c731f-7ff5-48a0-8700-b62cd163f369@acm.org>
Date: Fri, 19 Dec 2025 13:01:13 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 21/36] debugfs: Make debugfs_cancellation a context
 lock struct
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
 <20251219154418.3592607-22-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-22-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=s9OJBwkd;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
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

On 12/19/25 7:40 AM, Marco Elver wrote:
> When compiling include/linux/debugfs.h with CONTEXT_ANALYSIS enabled, we
> can see this error:
> 
> ./include/linux/debugfs.h:239:17: error: use of undeclared identifier 'cancellation'
>    239 | void __acquires(cancellation)
> 
> Move the __acquires(..) attribute after the declaration, so that the
> compiler can see the cancellation function argument, as well as making
> struct debugfs_cancellation a real context lock to benefit from Clang's
> context analysis.
> 
> This change is a preparatory change to allow enabling context analysis
> in subsystems that include the above header.
Reviewed-by: Bart Van Assche <bvanassche@acm.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a62c731f-7ff5-48a0-8700-b62cd163f369%40acm.org.
