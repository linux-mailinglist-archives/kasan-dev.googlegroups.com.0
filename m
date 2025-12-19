Return-Path: <kasan-dev+bncBD3JNNMDTMEBB2WDS3FAMGQEFWJEESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 15B58CD1873
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:05:16 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-65747f4376bsf3109585eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 11:05:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766171114; cv=pass;
        d=google.com; s=arc-20240605;
        b=O2OeO0ehDxmeY0O5NXyYI05FUi5Cx7Oesgeu7SvOQhJ0ySfQejVbAdk1RTLXcqNKPP
         uXVHxoPsIRXM1c8on+0U02p+NcZoaYY8KrpFjp6nTARq9W2PIYf6Mp6TcB5XYAZbz9w+
         9Z1K+IK2yGcCb9zV8/3DwnpVGzLoXqRml9Y2xd8Xnh8qyg0XOCYsu5wq3fRICwk3bbFp
         e71iG+rPPtEiJzZbyh/SSCKvAZjrLm2lelQCabFVIQ9gQ8483Io8lGiqgNiIGi4E/WPE
         Dq0X6vbq2iTo2XG0ZkkJPIt9fO1w0JYOhUhMiNu9nGh2VEI9P43hXmHIqRiA1kG9iJGl
         Lfxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=bB3YJ+f2TOJ66iCXuuGBlN7x2TMnZTJH5IgD/uLjB2Q=;
        fh=Fj0+yKADRLOckYw+63innbfmVtgH3q/MEyIQTr0tLao=;
        b=c08/kZuTlV7KpBRUUkrUbUQ3AnwKQl97quojOHh06GqSWxA1ROaGwRbynB/k3whXcX
         lLxqSvCHRWUs6qNcvDuCdeZ1khINnNe8WSv+bE4x7RGVYU6PRdUkER5GFgykSyQecHb8
         T8CoPLtliQL8qzHGw1CIQnxJquPUoo7rV9ho0suVDfwCLkb7otIBn0hCCm3imCJ/ZTLm
         NBkzGZo8kaeZ3NQQHtg76FIKKuK+XYPx+zU14ayrzhf0Z5j4hwR705ac+C3VDY7wxhw6
         KD+UD3AnQzAaL0aoX16ShW+GRwtA625kWXKCxjd5iPu3kCR042V18Gq2cx70XOAY5dTA
         NScg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=boeNGRJs;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766171114; x=1766775914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bB3YJ+f2TOJ66iCXuuGBlN7x2TMnZTJH5IgD/uLjB2Q=;
        b=bm7/tJDJBAWouHr2MhiWRG0pRl6kByz3DdUGMZW+UYK/iPKH6M2vtr/jecRozG4Aa/
         qNWToXQZdN2Rs52qW/WfD+QbCjr3OpEB63CB7xn4D83bEUZIL0rkbXT0gd2AUnDQoNSv
         +lkq5gRgV/U1JIa+Gqwe3EVCQc9+aSwmoV6VvvDjmLaOChWDrxgIfq5bNsXL10caVTQo
         JwhxIeb7bGx1i7+AvQmcn+crT0L8ICaTZ6cDZxNot2rpQx9u+0lY7vZpj86CAhZhRYJJ
         IcCKJN5XWSe5YEcLkXcZPpCI0yhRkSgkAdyIMFcmLN7d0Q2qkpU/XQwFxadSEzks2SMJ
         7Kug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766171114; x=1766775914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bB3YJ+f2TOJ66iCXuuGBlN7x2TMnZTJH5IgD/uLjB2Q=;
        b=cRIHGwI7AoiV2tL78HEJ31y+cJu29UCM68I94jL+vAGn0GniDrFyHO1OT1/rJ8/irP
         yDqgDf5DM3yYU0t1TqZA9+9W6+U3Kiqi5nul+rYffEu9wAVuZeehn5cxIU94HrCUPY+k
         kLYfYog8Iu88lAhkExuRub34H/MwBHmoCPv3s6r4npne4hNo66CSriW3GBc0nYCzECw1
         p7EdwsLjZtJrMvhXTKx9ahtBsu/GrCW3nu6F8xXAYBOM4ESLkR6FgQdEXPzSEVIBwJKR
         1tSYv80QXBypZWXHiow68qxu5ZdWH5nCjt2kOQOhYENjVie/OYYBXSLVLeWVfO5dWvW1
         PqvA==
X-Forwarded-Encrypted: i=2; AJvYcCXbxWh+1cc7w3fduYW7xB/xVa9xY99+WvYtcyYzmnShnohOj3PeHlJ3xQYb/q9+3DRsOgLeDg==@lfdr.de
X-Gm-Message-State: AOJu0Yxf/iB15SGnlx10jHWyODtHZ+cTniPfd0i44uyIbCCBqpMx1tXB
	8n+Z3BfMvCA2D5SJ4D/Io618o550o1qWLVpYm+S2CXjKvNy3Cfbsg/ji
X-Google-Smtp-Source: AGHT+IHT5XCpd5v/hF05mwjDBOOHa8dHdmuGsFkn26vy57kievNYrqPOJCEcBj3hinbcJ2mBfSgnTw==
X-Received: by 2002:a05:6820:f029:b0:654:faee:1065 with SMTP id 006d021491bc7-65d0e9f30a2mr2188215eaf.5.1766171114637;
        Fri, 19 Dec 2025 11:05:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ7yfFLtm9xvAMi1HenM6IZYbWmuqDYJEQDGNpmu7Vv0w=="
Received: by 2002:a05:6870:1704:b0:35a:ce0a:d0a3 with SMTP id
 586e51a60fabf-3f5f83b784fls5322196fac.0.-pod-prod-08-us; Fri, 19 Dec 2025
 11:05:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUsSo+X0VNuv2sH9GWqiPa9LkgLG4xY7naK/NM0DfWGW1fQ8PUaZyBSdfyf7Vn9yJOs1P3wFpLO3cw=@googlegroups.com
X-Received: by 2002:a05:6870:832a:b0:3e8:8e57:a7a4 with SMTP id 586e51a60fabf-3fda5481aa9mr2042125fac.55.1766171113554;
        Fri, 19 Dec 2025 11:05:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766171113; cv=none;
        d=google.com; s=arc-20240605;
        b=DqYC5pqqDiK8KS7MTU2EIyos0OSxIbK+b49xuecJUtqgg1WvAh5TDjKFenss+t6M5c
         gnzExT7X/RksYCh8uvX7zRkml654Yd1EI70iHFOdQ1quNBDCJjQ7SrCx2uNQJl+cXtO6
         SOYP3V0Xte6Jj3iaO7TDUqgkXJ0JQK4HW2S+1r94sLMAnVbj0wCkNQAS3ZBwBxFXBv4P
         pG78+13H7BgqvOdSTHYlNxVp6jJeXWyLHMMLJDOT1iX12yjRUqRtTQQpBJvqLFj0hwPj
         4hDfVf00zq1RWsAYQ0yyp5qJqP4bX8s05NOeDczrUey1GCCrMYhXx+EfOT9CXooItOil
         XxXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=eV7MMJjNh+GgBWpC1KWI4e80gQbcoqCCVdMqswFoyR0=;
        fh=gxy4knLMkqk26VcUfaeRtWia6+1L36ooxTX+CrbnkHg=;
        b=a20UVQ1lLbVNt54NNKJcYGD/zuNJXF6JDxM3K+cDdJsJLTkS0pvVnTdWGxmsJw7cQs
         vJauN8xITUit0t9VMuMcRZ0CCqKYBKcqAtAfmbvlqLGzBVtoZLqnswDuHNkLdAT4RSz6
         MYP+4GS92B4AxkNSVWRA41YQt33DE3v96ornuLdaf/TcvNc8tNH6qq6JuOT3+IKzmqFp
         dvpIrSrbDfuKf1wGr3c/4Q0ZOe4WQFdksJxwdwv+0+UFpx3cZQK8i5IXsxtOjTRp21tn
         2842H709j1b+0u3ngXY0voENq5d5K4cIE3W6gDB0BN3CIJm9YqeIZuZ+DxGVq+2Ztp9z
         W5LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=boeNGRJs;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3fdaabc2e7csi164371fac.7.2025.12.19.11.05.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 11:05:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dXxn46t8hzlwmGt;
	Fri, 19 Dec 2025 19:05:12 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id Pu13yLEvt3U6; Fri, 19 Dec 2025 19:05:05 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dXxmf0ZcWzlvwXX;
	Fri, 19 Dec 2025 19:04:49 +0000 (UTC)
Message-ID: <2f0c27eb-eca5-4a7f-8035-71c6b0c84e30@acm.org>
Date: Fri, 19 Dec 2025 11:04:49 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 02/36] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>,
 Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
 "David S. Miller" <davem@davemloft.net>,
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
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-3-elver@google.com>
 <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
 <CANpmjNM=4baTiSWGOiSWLfQV2YqMt6qkdV__uj+QtD4zAY8Weg@mail.gmail.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNM=4baTiSWGOiSWLfQV2YqMt6qkdV__uj+QtD4zAY8Weg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=boeNGRJs;       spf=pass
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

On 12/19/25 10:59 AM, Marco Elver wrote:
> On Fri, 19 Dec 2025 at 19:39, 'Bart Van Assche' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>> I'm concerned that the context_lock_struct() macro will make code harder
>> to read. Anyone who encounters the context_lock_struct() macro will have
>> to look up its definition to learn what it does. I propose to split this
>> macro into two macros:
>> * One macro that expands into "__ctx_lock_type(name)".
>> * A second macro that expands into the rest of the above macro.
>>
>> In other words, instead of having to write
>> context_lock_struct(struct_name, { ... }); developers will have to write
>>
>> struct context_lock_type struct_name {
>>       ...;
>> };
>> context_struct_helper_functions(struct_name);
> 
> This doesn't necessarily help with not having to look up its
> definition to learn what it does.
> 
> If this is the common pattern, it will blindly be repeated, and this
> adds 1 more line and makes this a bit more verbose. Maybe the helper
> functions aren't always needed, but I also think that context lock
> types should remain relatively few.  For all synchronization
> primitives that were enabled in this series, the helpers are required.
> 
> The current usage is simply:
> 
> context_lock_struct(name) {
>     ... struct goes here ...
> };  // note no awkward ) brace
> 
> I don't know which way the current kernel style is leaning towards,
> but if we take <linux/cleanup.h> as an example, a simple programming
> model / API is actually preferred.
Many kernel developers are used to look up the definition of a data
structure either by using ctags, etags or a similar tool or by using
grep and a pattern like "${struct_name} {\$". Breaking the tools kernel
developer use today to look up data structure definitions might cause
considerable frustration and hence shouldn't be done lightly.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2f0c27eb-eca5-4a7f-8035-71c6b0c84e30%40acm.org.
