Return-Path: <kasan-dev+bncBD3JNNMDTMEBB7PJS3FAMGQEEOWEKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 615D3CD1BE9
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:26:39 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88a39993e5fsf48295036d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:26:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766175998; cv=pass;
        d=google.com; s=arc-20240605;
        b=lgMdYlhWsIfvmKu/9Cgzm7GSPCjk/hEBAHZatqFJQNibjj9247fqtqT/S6sBOLwBZ9
         yFuzUtM5OCQtOQpRjM9dMIvKGe0pCpdNNCsb0NTkUzcKFHKDV/RKfVqYGKQTU774KILd
         6tKJnZgd0iYho+ODRa8kUd82rWjCjlDRjN7EYox6cbfQIk/jpTk4Gw7cFdc4bww7nV4n
         727OJ4igej0AMWtYLE9jNGVk/Zeil3mq3xtoYFkuPFl1ozUG6NOfpAD3+PuFJLpHENnR
         w+Z73QlJsXl21+c/9SyhMnGHjKgleylGmqmc5GbSQ/esGXTjMj/ltL57Q7NT2ahB8pjL
         KJyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=OaR3NwyErQAP1RaUz4k79FFRerB7TTkGHQQwnhPonag=;
        fh=qonNoflRETI9JlHzTFcJ0Zbt/O1OdSLG/RWID86yjDA=;
        b=FSBgRablUqN3kd426nDuXKykKVena7HCJm/VtrPEIKn8BPHReNk2UZsjoAvmdIUU/w
         RcahkpbztNLK75iBLRJpVjV0UGASu304Y49X4nC8hNKow1Z7zp3nEd29p7ZQd163FNMo
         umMbQ77YdbcreN4XYhGvir2fSYaTozftry43T640EghlgnMU7txyVWiSTRWvEWloeUQ9
         cWyxuJnJtJHiMSeBhGMe2VNvN05Ojoq8z2kpZZobOukVqXs3iX07JFkftZ9nemdBsr+h
         AK4g933qFNK9H0K4kXJkXEK7PFjm/VhaZwmZwZWgNsERPBSYDyt5tF1lBMFIIDYsy3Ex
         yCXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=3LHIpw+i;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766175998; x=1766780798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OaR3NwyErQAP1RaUz4k79FFRerB7TTkGHQQwnhPonag=;
        b=ICmUutP7VjKhmSA3EvJbkg59g/fFGC2/tHuAou4VxgJY+rxFO/PFnoBkx2FnPx6sPa
         kKDME3kUpm5bUrkEZxC3tDkJq3GoK8F3iHUmlqSfs74YxSdQ3VGUu3+B96ADWX7gFvPK
         Kwyc0YHHhTkJafNVdu1RCAjDNyFbWFwTV5n3wT4TW0jUCqylIZZ6X66GRFspeg/I5blB
         BlI8SH8460JdEWz61eDGyu6KnCyMTuEoYiq7XbJAEPD/u7zTFOed9wj1HmmPpM9W243Y
         cz3BA/fZ+TMtvXEZUVGC5uPDs5BpKf+dOWzPrZ0BYuNEGAbeO6WpYYJEX/uhQqRpFqQx
         6lEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766175998; x=1766780798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OaR3NwyErQAP1RaUz4k79FFRerB7TTkGHQQwnhPonag=;
        b=I7HOfwLdFVKuxR/bcdYNGlVOs9tJyiQcucc1XH0yM75BCU9ulfpQZGUyipVpAjTUOE
         zGeASkPxmB03bY0Q/SJo1BZhhsyDxxbaqS0Fv5viZMkt8bVxfDw+B2tVGNAhhV+B0zT/
         oc91AIivJth8E5h4aid7eKSMDMgvz5guTa8zeTWPWu2Q6Z40HpxZUZUWtoOrA2LeNjNl
         ivmKNTKZEx3zhm9iN1gFZLH6r9s+ScOK6S4qTlh81SX+EaDGJtRYCtMf6EAVHKlc2Y8R
         p1PAfx30VBKfd37PnfbEe7rBSZx92bGGWdv185PBHjGlae5mkzDfH6UmqOT4COF1LKJD
         G3JQ==
X-Forwarded-Encrypted: i=2; AJvYcCVuYlz9O/3giUMxveToisNjCQGnxINqVRg2S3qc1k4oLcSHeB3VC1Xv1b+WZaOMNrwdqaxDdw==@lfdr.de
X-Gm-Message-State: AOJu0Yw99JLXMN3rJ852JEaFPSTekfQ0Ah3GnHFzhIz3Rrv9CsbxuboJ
	Zi9KkNgHJyhFjiRuuJOIWNi8UUj8/JOF1/wMgJonE2fbMN8DtkOQO5D6
X-Google-Smtp-Source: AGHT+IFN3eOHsBCXApxHr1CY/AUk2rcGlgQOd1MO/PV+jqLo8JLIs9ygjQ1KjaItOeYChBLo+qZs+A==
X-Received: by 2002:a05:6214:4308:b0:88a:2f0f:c173 with SMTP id 6a1803df08f44-88d86e482c0mr65983606d6.68.1766175998065;
        Fri, 19 Dec 2025 12:26:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZU7oL9LsXmOVb03r9U91Iv5SocfWmjINmV18Hx2UCccA=="
Received: by 2002:a05:6214:f6d:b0:87b:d44b:314a with SMTP id
 6a1803df08f44-8887cdddd1fls154203526d6.2.-pod-prod-01-us; Fri, 19 Dec 2025
 12:26:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMaDJi5I21DHcp0JhpymHXW4BvKNVF4LComgUihU1q8n7PHbq2YoKFJNG87FSCU95+/n2TpIKlwVQ=@googlegroups.com
X-Received: by 2002:a05:620a:f01:b0:8b2:e9d2:9c69 with SMTP id af79cd13be357-8c08f664eedmr736378385a.22.1766175997118;
        Fri, 19 Dec 2025 12:26:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766175997; cv=none;
        d=google.com; s=arc-20240605;
        b=avkFoYQ7BXNTSPvCnH/TXRnQ0+1aqLL60RXAMAVGs1CFhRIDK69lopxZWsbLZ8StgK
         t6ZtYL/ORliQNR0L0xmxCeOnrY5lR1yqlINpCz1BAwSIyzpJ/bfKHtF/Q9GDcvQTSavx
         BsIGgjoCK05Fah2GpsTcBD0rEonfCJrNbcRO9EZF2an+K4sdDHGs/AwT8MDs15AlrbP+
         BYRNMTomvQvpSxTqn0OU8stdcxR6nuMeB0wTWmv5adw4B6b6Ic4BzvZPvAAhMtkmiB0n
         QcHPAcBT96MQxzhyGNgDq54NKOGHEPUDX36FKo7vMbSs2VsYy3p6rUIW7D42ijlldFAn
         S8iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=+XIWCwsoEOSiUB9cSDM01ohKHVap8EzItAr4kGei6l0=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=OirlM0dewj1/c3A1fiHUiMvuWrMipdpEwLLgv2FGTldCvAATELakhcjDcXprcgwC7N
         3dyXfqO1Atpy4kjFn4LIzwIUjEluc3vPYop6ZTQ6/DiFSi4jHFYZVCCeac9jZaBIaGS8
         xyHsOSQ/pcMZmNHpnUy3PlyNuvqz5wlL+Uw7G/nVEutSvozlzyqVkxPZ0NKqEhkRMZhh
         /Uw9T/rbS0YZLXF3JnwlsKQos8zQRmF+CJuxJCqIuGldS9Qosq/P6UBj0XyEwn52ifNv
         DjQhXiDJ2JiNyW6y00440WVezs6SI4Uyl1K8VsZkXlCkwCFzPBSmLGCVGsZLmJS1ZkAH
         oSAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=3LHIpw+i;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c096ef3215si15216985a.7.2025.12.19.12.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:26:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dXzb00Dlzz1XM0pZ;
	Fri, 19 Dec 2025 20:26:36 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id qiEhQEwhfLs6; Fri, 19 Dec 2025 20:26:28 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dXzZd0R6zz1XM6Jk;
	Fri, 19 Dec 2025 20:26:16 +0000 (UTC)
Message-ID: <17723ae6-9611-4731-905c-60dab9fb7102@acm.org>
Date: Fri, 19 Dec 2025 12:26:16 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 08/36] locking/rwlock, spinlock: Support Clang's
 context analysis
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
 <20251219154418.3592607-9-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-9-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=3LHIpw+i;       spf=pass
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

On 12/19/25 7:39 AM, Marco Elver wrote:
> - extern void do_raw_read_lock(rwlock_t *lock) __acquires(lock);
> + extern void do_raw_read_lock(rwlock_t *lock) __acquires_shared(lock);

Given the "one change per patch" rule, shouldn't the annotation fixes
for rwlock operations be moved into a separate patch?

> -typedef struct {
> +context_lock_struct(rwlock) {
>   	arch_rwlock_t raw_lock;
>   #ifdef CONFIG_DEBUG_SPINLOCK
>   	unsigned int magic, owner_cpu;
> @@ -31,7 +31,8 @@ typedef struct {
>   #ifdef CONFIG_DEBUG_LOCK_ALLOC
>   	struct lockdep_map dep_map;
>   #endif
> -} rwlock_t;
> +};
> +typedef struct rwlock rwlock_t;

This change introduces a new globally visible "struct rwlock". Although
I haven't found any existing "struct rwlock" definitions, maybe it's a
good idea to use a more unique name instead.

> diff --git a/include/linux/spinlock_api_up.h b/include/linux/spinlock_api_up.h
> index 819aeba1c87e..018f5aabc1be 100644
> --- a/include/linux/spinlock_api_up.h
> +++ b/include/linux/spinlock_api_up.h
> @@ -24,68 +24,77 @@
>    * flags straight, to suppress compiler warnings of unused lock
>    * variables, and to add the proper checker annotations:
>    */
> -#define ___LOCK(lock) \
> -  do { __acquire(lock); (void)(lock); } while (0)
> +#define ___LOCK_void(lock) \
> +  do { (void)(lock); } while (0)

Instead of introducing a new macro ___LOCK_void(), please expand this
macro where it is used ((void)(lock)). I think this will make the code
in this header file easier to read.
    > -#define __LOCK(lock) \
> -  do { preempt_disable(); ___LOCK(lock); } while (0)
> +#define ___LOCK_(lock) \
> +  do { __acquire(lock); ___LOCK_void(lock); } while (0)

Is the macro ___LOCK_() used anywhere? If not, can it be left out?

> -#define __LOCK_BH(lock) \
> -  do { __local_bh_disable_ip(_THIS_IP_, SOFTIRQ_LOCK_OFFSET); ___LOCK(lock); } while (0)
> +#define ___LOCK_shared(lock) \
> +  do { __acquire_shared(lock); ___LOCK_void(lock); } while (0)

The introduction of the new macros in this header file make the changes
hard to follow. Please consider splitting the changes for this header
file as follows:
* A first patch that splits ___LOCK() into ___LOCK_exclusive() and
   ___LOCK_shared().
* A second patch with the thread-safety annotation changes
   (__acquire() -> __acquire_shared()).

>   /* Non PREEMPT_RT kernels map spinlock to raw_spinlock */
> -typedef struct spinlock {
> +context_lock_struct(spinlock) {
>   	union {
>   		struct raw_spinlock rlock;
>   
> @@ -26,7 +26,8 @@ typedef struct spinlock {
>   		};
>   #endif
>   	};
> -} spinlock_t;
> +};
> +typedef struct spinlock spinlock_t;

Also here, a new global struct name is introduced (spinlock). Maybe the
name of this new struct should be made more unique?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/17723ae6-9611-4731-905c-60dab9fb7102%40acm.org.
