Return-Path: <kasan-dev+bncBD3JNNMDTMEBBZ6WQDFQMGQECEZTQHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB64D0666C
	for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 23:10:49 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3ec76da7aaesf4212080fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 14:10:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767910247; cv=pass;
        d=google.com; s=arc-20240605;
        b=ArFIyJni2WNZxD6WmbYQ5XfpcZlGFW9N0f9D5XXcR+GSV631inhpfd9IQ41cPIlufq
         f+ZToXunVA+HvE5xqUcDPLu63qLwnE4KYlQs5BOY8THaHa4TJOyIlpONAuGECZBo/Vo6
         fSMj9ylNLYiUkjFRtBrhc9CpGPkF9wbFaGe59mgbGnerjF4C63XSe2wBPD6BfP9WHm+q
         f8A2k+M8WRlDoA/TRivPRDzG9OdtxiRU5p2qKrLcdU1PLfiXS8obPWvlKL6R3iE1YLXp
         1lKUfh5B0ytzfg3jDss46kfTyu1kJXmrrj8ApA6Tq3u+4O6wIJdDR3m7GRvnCcSYZICZ
         AnNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=/PQfFSO+DsK/9NvMdWcmrJ/F1GrCk9Nj546QkCR+Yuo=;
        fh=qrPhO09HUhvb4weobqWDcgQ5ljBfjcff7uT7k4DRtuc=;
        b=PtlIidqVobNKIF3toPkpmF4v3aXTNUZax0QOrlRTPZXZ5uJRz4zZwtG2j3UZw13d05
         ps8Q3eYFmgRYJgldyBUhrORMUpaN17ht8+lrS+WfD0nv/fmnTk0y71mB+tLeYk7NRod/
         L59L7uoklQf4EdMJ3u9rhqvrdiDbe/zIGicQImEatBvGCWuL6dcqpnb7UPWAZNjKzoRN
         N/DsmmjcEo27Dg+3VxzniySdbvQhs3slz422T3v31bVC6FgewpBC+8eJaFINL0Dm/Ajr
         E4mkOsbS2pP2mKc3QHLZ302X63nu7dPAvseQBwMbV5viKqGd/YHhSfUShomuLVbFkzwT
         kq4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=y3DnIpMC;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767910247; x=1768515047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/PQfFSO+DsK/9NvMdWcmrJ/F1GrCk9Nj546QkCR+Yuo=;
        b=wZG1rdbig1pzLNwdVIN4VPYAEB25aooKYBJHDIv1cPkuXy3D9oiB/0IFUXZw1UWPJx
         Vs3533FBn8yLbfAIOWXKIW009WitwYy5ff1I4XopYdSxY9sgAy6dglRpYPNDymD4hWly
         1GiO7TUqhw3WJwKbU1SvIYadwyRwLnB5YjoWuGJkm4NRf3lnY8iGBxlQgdb7zVhto25P
         HFrTN1x4Zh2IXl1dXhcIIJ1v8XWnNm3Vq51BIFa+TdzOkK40uJmMFwx6+HH0vE/ERGUi
         yd37W5mwzyp3VZJa2u5b3rQYU9VNs/aXMDsHKp/ojT6cWo4mFk19mtVUrj/qv8x/fyzi
         SGOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767910247; x=1768515047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/PQfFSO+DsK/9NvMdWcmrJ/F1GrCk9Nj546QkCR+Yuo=;
        b=xLAqBKc3vIpm8JpCvg835tKb3ccGpsiziFCj9BuC4fx+cjojTHLsN/LwJZu+DLlhWt
         SyQthY16EDgf19weEmFsRPcDjdjkLMgZuKFmmgaxIDlem2dfqQ35tuZIhxSwkehECnso
         PSv06c4h14gCihPMmo7/kzJYECyl+YAdQJYLDDNd2valqlnLGMrhO06WPa9WuIstI3C3
         3RK5+TdPWdxQG084ORdoL6epWJhrd9LLFUaN1Yj67CgJXDDznx5pR645x5lGo4y9mPqe
         X+6EKnJEmqNyAeHbsNQLWZMghT0SoTknbVQ9IjKYuRT2sY1UbIoQS3LOlAr689QrKACj
         zrfA==
X-Forwarded-Encrypted: i=2; AJvYcCXti7G5COc+IoqgI/IPLuFEw1ZgQM3i5Em6jD/gTcGXnd8zebzcpxRw+PEH9Zkm0HI7dvX7ig==@lfdr.de
X-Gm-Message-State: AOJu0Ywf1/ef970rGd9rUZfWMa/B/WbZNVvs5Qor9+iRw5i0x00ziVWA
	DaCHhRCx+SOJnCAMeG8fEbRtynsagi1TnBOWQ2QamW0biFwmOLu9cdmg
X-Google-Smtp-Source: AGHT+IHk85nXw8kB7oMcI0D7MqBfTRKck6T/RWcTfjqBOV+Zbk4ADlc67JO7D1a2Wf8Ib/RYPQSOJA==
X-Received: by 2002:a05:6870:f14d:b0:3c9:ad69:4416 with SMTP id 586e51a60fabf-3ffa2249158mr6534501fac.5.1767910247474;
        Thu, 08 Jan 2026 14:10:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWarqmixj60jL9+gpYTZO01WfCfPlHdbe3nZmYACRCHdGQ=="
Received: by 2002:a05:6870:934b:b0:3ff:a5fa:7cf2 with SMTP id
 586e51a60fabf-3ffc01d0a8cls1040065fac.2.-pod-prod-00-us; Thu, 08 Jan 2026
 14:10:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVhW0CndVW8cNC46NVFshvAOvBd67iKA/qnD4+W/0aT7zh/SjEErt7dTKBODvzTj7a2f4aXt83ipBI=@googlegroups.com
X-Received: by 2002:a05:6830:918:b0:7c6:d01f:591b with SMTP id 46e09a7af769-7ce46cf4075mr7409893a34.13.1767910246546;
        Thu, 08 Jan 2026 14:10:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767910246; cv=none;
        d=google.com; s=arc-20240605;
        b=UId6tZeRGm6u9TVqlknyl1Xwe7xjBB0seBsanNgBMqiN5oSPnnbXhUnIg/qLinDp/l
         GSZa9eTgL6d14XBdyqDbOdWIrsPFK/yO0UaWy2VB9MMNm0q3gZP85RqS8FpD8EsUA6FJ
         6TgI0PlvyS8f5T6iumJ5wqtVg+0ZosBibX8v+LAdalfyUHcexDf+wwDNI2siX4LHVfa6
         BrjfyqE+5kFPRDB4kkI7nPnaqWbQK5wPa0k1plLPzK61rHs1s0+DnSCyw8Y7MiB/76sO
         eChyV0vaM0A6CO9Ldi+q6PvzuqQxWu5Uv+FeY7UbIA5JFqB4kMkSVXcxXo5/KBUgQx4I
         vovw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9wcZSTi8w0Set4rh18vUE4zPr/D6QOeIA+Se4D2Yz7E=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=F56K4qg+4IUGfbWxYevQ9IWoW7japBhPYYkjQuU4B6/+Qg89keJ/xY3PldDCI816Vg
         lV/kaOZve9gULArJ0UWGhgNT+0CsCBHPNggxd2TY1UtrpJQcYH62xiZrRogVQ7EAIDqS
         /7szCuYTmatpad7xThcvc0YA2CprYv6XAMw9Gh+gRWNdthKMxGeqHADF7TTOouXN/Oid
         la64wvi7McHzyViAZFrPdzqZt3M9V5Ba5ZRhqMm/KG+ShYNt0h3NlZ1DyounZGphxZHH
         s8R+lLNKWRvqKRxjyssZokZhQv6pn4zfC4U/9d2twU4Tx6mzBIASsEuE9wK5YXno0mlM
         eDNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=y3DnIpMC;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7ce481ea90esi465427a34.5.2026.01.08.14.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Jan 2026 14:10:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dnJxx5cFFz1XT1Z9;
	Thu,  8 Jan 2026 22:10:45 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id 2VIQQt_5Aq81; Thu,  8 Jan 2026 22:10:37 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dnJxZ1xlYz1XZYyy;
	Thu,  8 Jan 2026 22:10:26 +0000 (UTC)
Message-ID: <57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org>
Date: Thu, 8 Jan 2026 14:10:25 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 10/36] locking/mutex: Support Clang's context analysis
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
 <20251219154418.3592607-11-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-11-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=y3DnIpMC;       spf=pass
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

On 12/19/25 8:39 AM, Marco Elver wrote:
> diff --git a/include/linux/mutex.h b/include/linux/mutex.h
> index bf535f0118bb..89977c215cbd 100644
> --- a/include/linux/mutex.h
> +++ b/include/linux/mutex.h
> @@ -62,6 +62,7 @@ do {									\
>   	static struct lock_class_key __key;				\
>   									\
>   	__mutex_init((mutex), #mutex, &__key);				\
> +	__assume_ctx_lock(mutex);					\
>   } while (0)

The above type of change probably will have to be reverted. If I enable
context analysis for the entire kernel tree, drivers/base/devcoredump.c
doesn't build. The following error is reported:

drivers/base/devcoredump.c:406:2: error: acquiring mutex '_res->mutex' 
that is already held [-Werror,-Wthread-safety-analysis]
   406 |         mutex_lock(&devcd->mutex);
       |         ^

dev_coredumpm_timeout() calls mutex_init() and mutex_lock() from the 
same function. The above type of change breaks compilation of all code
that initializes and locks a synchronization object from the same
function. My understanding of dev_coredumpm_timeout() is that there is a
good reason for calling both mutex_init() and mutex_lock() from that
function. Possible solutions are disabling context analysis for that
function or removing __assume_ctx_lock() again from mutex_init(). Does
anyone want to share their opinion about this?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/57062131-e79e-42c2-aa0b-8f931cb8cac2%40acm.org.
