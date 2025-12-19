Return-Path: <kasan-dev+bncBD3JNNMDTMEBBXPPS3FAMGQEZRZYV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 40D37CD1C9C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:38:55 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-65b2d43a899sf3116626eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:38:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766176734; cv=pass;
        d=google.com; s=arc-20240605;
        b=OqxI85Y3HL6VhQtYBGREj3A52mjxQacNI2Umz23IcnGzkdENSecx/Z8eoC3U8+EvO3
         RtKZTn3/u6YBk4QNlcexgYPvvMD4PF5a6aRhJ9fL4c5aUDi/fWdeB/sQt1LTE/f9oPgf
         iTSZsKA1jtZTyNuNnWobgBS1sddNTOMkMZptCr3zlY/w5YsMmR9FgTtLPrbN0dk5D8xG
         sVqOANYhfeNzz/TvHssRxXJWSQjsx/QvFIB8p6JARCi1nh+AqUAN98ydZB/2h8rK6MBf
         1P+qtfvLCgM16Fa6NXNZF3IIr48SEQdbdibyeWG6D5eh6LbmB0awfQ9oGxAl0bNbu1zF
         udPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=WpG+diFdOUFSPM+CMIaVDxS815JW6rkEGkK9laDY7Qc=;
        fh=d3cG/kLEopSKpxJIUUQZgwPDu614Bdl7npeQp31h//A=;
        b=OlD6lh3VyytWXANIiuQcpP4fmpPuf2IQOd8icb0JkeDYMq/XQGNRbdoJV+UrpGLlry
         gPUHUMFpl+g2W7GtNHxEEGQV7ActEV3dnXjjlqmAxEc4Opmw5c9r4coHYcz8W+Pxi4a3
         kJNRniNLFskfLupHwSMu6tqcWAcZ+iMJJy3roreu4tsWHsD+tP62ViBvQsJAxx5TcOxW
         JjMAH8t+u0+6Ew0Y+fApRMWmdMuPsk3+HPHrnCPsVqP25h1N9fjiWPgHSD/fqqE5XRIE
         cI+a5EjY6kF2PGjeDY67Xu6snnp1iVsUxGV0ZHruiefBVXK86GrlcPVxuOzUvNc/dCqe
         XKKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=23ejbMoW;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766176734; x=1766781534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WpG+diFdOUFSPM+CMIaVDxS815JW6rkEGkK9laDY7Qc=;
        b=keD25LQqidktgE0vqopZigShVZIrimA/TotX75YpBtLzZIG/X5Qsj6zFJkzZyxu8ji
         Tnx1MjOqCofpj/F8aJGNuqsnfQSsJ8+GERysU3fsaSvgzZJGXV2Lxr5t1NbT8EabB3Oe
         9NGi3FGUjsW9AqCTgcplTspGxpGY/2PDPxBv/OabBdxQMV4iq62vtXPmIsLi5uld4jSe
         ma0KDT2LykVZYmwYhhXwPJ0QpPuU/h2bX8FSUOe6j9tDasXkYBlxqQo4Zd0O810rv3Ac
         Zy1xjYNaPOXvZmQmfjJPDdQeAYsT/v3ZASPnW0p8Ew/eYUQbCAfTpJM7mcWUKdF+cdgh
         s7qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766176734; x=1766781534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WpG+diFdOUFSPM+CMIaVDxS815JW6rkEGkK9laDY7Qc=;
        b=hJgtFUDQjFIUDnGH8zY9oj1WyQX9cJcw9pLzT6f16mT7E4u+X14yg41V2p7fEhZYZw
         0BVji38k2PSWi+OPjVCue8c4L0NC5gFpDrS9bwMfTdZdyvmIneRjSBf66c8W56QPTBww
         5sJvV4ZuqrpR8C3M4ejh326xD+SElZ3aSreEP8q8D0OkySgzg/mUFcJQNnf1Lon8KDQy
         V4TV4hHVPYu5hZ1wO9H9QzKkqUmo2ov8jM1WwCJJ7+MhIhmgRvl7GdkKgtPq8WmrnFZ8
         O/rQQUTBLBIOstbsLlUJ0Ex0MdAwkhYj80YuAYVb1rL5MwYBg6rTFg0wLHFR1w2z82Uy
         rdLw==
X-Forwarded-Encrypted: i=2; AJvYcCWkLBUYE/R/OFk+xYIM1UcQtlBKW3cnuI0rbvkqp8HOd8Ymxog04maT4P38ykvYDLboNWlS+A==@lfdr.de
X-Gm-Message-State: AOJu0YxXvO7snMYtIcXqyuJYsOrBAgy/c+Pr0NmWWouuzS5Z71Z3oNRY
	hs9wZ3AM45/2ok7jfq49a2AsksKEukelTpD+HG1vXaRFEaqxMQpEh5CS
X-Google-Smtp-Source: AGHT+IELernoT6qH3Knvc1Yyc+z0FAYstuC2v1K5VV1+KynDSCD9hOnZE4J1nyEHM6Mmq+q39NtkJQ==
X-Received: by 2002:a4a:bc84:0:b0:659:9a49:9072 with SMTP id 006d021491bc7-65d0ead135fmr1234173eaf.61.1766176733868;
        Fri, 19 Dec 2025 12:38:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaHVcyL6INxGdtql6lWjm03ECo/mQQeqpRiim117qXhfw=="
Received: by 2002:a05:6820:530a:b0:65c:f65a:64d9 with SMTP id
 006d021491bc7-65cf65a6716ls1322668eaf.0.-pod-prod-09-us; Fri, 19 Dec 2025
 12:38:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVePlAZtKZSFuXdlMQVXi3orEeOjWBqS9P1CaMmKJIt8r9s+l7p6X8IVTlQEoI8i5jUrostKB6tFM=@googlegroups.com
X-Received: by 2002:a05:6830:4426:b0:790:710f:60e3 with SMTP id 46e09a7af769-7cc66aada5emr2294940a34.23.1766176732970;
        Fri, 19 Dec 2025 12:38:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766176732; cv=none;
        d=google.com; s=arc-20240605;
        b=DBZ90EEVTncrVH6rACRiJzKYKzHTEzz9LGwcsUR1fgGcUT+XTV4M/lyjFefalJSAjg
         4BLgAck96cj+I6IFhcqQoPvGmjuMdNDVd9LwkiVj6uU0dYmx/6BSOhQDZm/UP8k5cLFc
         iGHiU7Xwx8ZWzsRmHaUSaP+hwf8103eX46tNSoOSIUIfYO9e86fel9nIV5Zyt8k7ZpjG
         lRVvDfPJyctw2DpOJJ9jzr4DYAkijzAykxdBM2zZ8M7RhzM93OJ0lb4xx6fc/OhhpPMp
         jZCjPKeEBl0CghKcLAoxa4nm7oyocjmxsNF/8KLZlT5wZCiUOb4ke/UwaHY99ZHdHMZ/
         Fqpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=M2FKNH25BsSSupvqYh8XNhufT7PJPLlufiLItK/K4/Q=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=YtC3I34/ayQIIDdS36LswIXlBGRUrGhkq/R/IycW0BXLkoaD8yr/D24Azwi3u+tWGO
         kSVCTRIrrpFOlSeyu7X6ij3g5L7gbOF8mZkRA/tLNaSWxwEzX1k6xKJLftl92FEceYuE
         zOXqdS3mJwKx5OIUoqE0jpRWxEMNPxKyVLh64zdg2//r+hmVZrk1+A8WbmLYTotyuCv6
         z3eS6WbHTdgiq3B0NdajERViC0Y47pckZk1jrWTk59Z86a/onYctNOKdPX8DbPLvp6Od
         fg763PzPvXirzGgTvUd1XZx+0QL3v7wiEkVlQKGb4/A03X9qa4vh/O7g3pvbuyxb26iL
         qaBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=23ejbMoW;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667c988esi339187a34.5.2025.12.19.12.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:38:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dXzs815rqzlwqPy;
	Fri, 19 Dec 2025 20:38:52 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id MkJHsfOVfhWT; Fri, 19 Dec 2025 20:38:44 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dXzrm6hBtzlwqPY;
	Fri, 19 Dec 2025 20:38:32 +0000 (UTC)
Message-ID: <61037092-ddfb-4504-9351-7f6a3e5e4616@acm.org>
Date: Fri, 19 Dec 2025 12:38:32 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 12/36] bit_spinlock: Include missing <asm/processor.h>
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
 <20251219154418.3592607-13-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-13-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=23ejbMoW;       spf=pass
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
> Including <linux/bit_spinlock.h> into an empty TU will result in the
> compiler complaining:
> 
> ./include/linux/bit_spinlock.h:34:4: error: call to undeclared function 'cpu_relax'; <...>
>     34 |                         cpu_relax();
>        |                         ^
> 1 error generated.
> 
> Include <asm/processor.h> to allow including bit_spinlock.h where
> <asm/processor.h> is not otherwise included.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>   include/linux/bit_spinlock.h | 2 ++
>   1 file changed, 2 insertions(+)
> 
> diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
> index c0989b5b0407..59e345f74b0e 100644
> --- a/include/linux/bit_spinlock.h
> +++ b/include/linux/bit_spinlock.h
> @@ -7,6 +7,8 @@
>   #include <linux/atomic.h>
>   #include <linux/bug.h>
>   
> +#include <asm/processor.h>  /* for cpu_relax() */
> +
>   /*
>    *  bit-based spin_lock()
>    *

The abbreviation "TU" is uncommon so it's probably a good idea to expand
it. Anyway:

Reviewed-by: Bart Van Assche <bvanassche@acm.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/61037092-ddfb-4504-9351-7f6a3e5e4616%40acm.org.
