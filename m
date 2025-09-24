Return-Path: <kasan-dev+bncBDV2D5O34IDRBGWK2DDAMGQEBCBYAVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 36D79B9AF95
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 19:06:36 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4d9a3ca3ec8sf1436841cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 10:06:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758733595; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uj4ZArgG2UZ2nVUQgdzVNvGzB55rwebP+tSMyftmUqzncWvS0CWXKw9P6LwWI96TXx
         GdZ6dUAGmM7s3xXnF6o34tghy7Se3LQytdhhboXXpPqL/MgYGK2zvBxhT5CYf9Jx/aAM
         7HYrNEuAN7auLe5FwMnlYDRMcgrqyNG5sbtkIsz6xPUSAf7gP1GEZ4CHcNMwd0gnOpVP
         FSRWkx19Vq+gCVOthYg916aZEda7n0WFNCMUHzgjPwBOta7/IM7e4GjPDJkCF/RxM/yR
         U1FgiJ00MmzciTrmk0rrDV+LB9uEeqISL/5ixQ2QY1PefyMHAEEhRn+H8rNXt8qGMBkC
         EBzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6idrHw5eF55h31Xl2vw37hd4Vb9S5hc0DSQg753b6KY=;
        fh=fGEVYLUlUzvcp32eS6fRq7yuw10h5oU4TBJTHJaHwzc=;
        b=h+wvqL/q4h4zixGWVn+Eg9lVc3UB1PrGrtvriPqV0TczDWXtLL33Gt0mPf2iVXph4V
         GHWFYLXxVpcqtixqC3GtGDnj3viToOPJhJckYwdI6GY6hBoNExa18NJnffJSXJsAsg/V
         c3Jm6XaLb4oI5AiP0H3J+h56NjG+QTrM4hP5MfgAztH9dPV28ryL3OuiMb5P+oUFgSn8
         SDBzwcmnhPnN/20mQL939VI3R7LDJfUGDJ6zEmJnidiNrejhUBvrcqcQ0DVhYQhSpERH
         sQ8Kk4wvbaMbzrAihPxjIupK4Zq97b74VJ1FoYOzERybE4mixx/5aVrdrBXAqbpxpWhi
         Qfmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=yMVBBGhb;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758733595; x=1759338395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6idrHw5eF55h31Xl2vw37hd4Vb9S5hc0DSQg753b6KY=;
        b=UcN/xo6ApTem86YxHeFF/OWLAHWNki0uvtAu6A0OcxOwgARMyTL2lNa2zDME9VkB6E
         qMHYznb5Hfj95XPliUPlvkP0u8ZKr8VYZdf0JktBK9nCzcTVFokO/Dr/HCA4Wq+iRYRQ
         QdK+0w8GXaNbHYzlAe8CvjGBGwWe4zstwmZfwVZn76sNEaPr+KP6+gXshTU+xBkXSdw2
         KvBtkQJ+1wbVss1TjfCj/5wDJjjWEFosNvLwKKsTPBeiCl3+s1oWcIgnuZoG0DVE9ouX
         Ie1EiWPbad+MKS2PqTBs1VQN+S83tf6B96zXrEaecr417FTbGaLcL9e2DbA0jZ53ONOh
         SxUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758733595; x=1759338395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6idrHw5eF55h31Xl2vw37hd4Vb9S5hc0DSQg753b6KY=;
        b=lnRzek1LjIKOQzhMp9IywX6pnoBy5DRIdI5wBBmyVWd7h8B9/qxZxwf+zIH6WNYJw4
         TciIKfca8ng92DlyzsBJTevayADJbYD2BqwqwWCXCqvHVencXSuf9rHBO1wLFYl0I2NR
         KLK89catISmmy7m+IvVdNFPTyK1lhtX1liy5EXkyEEBX9NfzepIkc6CucPdYrZeLewt7
         ia66oHFISQEbWuDUJ6avM//M6Y0N32Ch4JYOgXcO5nJUzFOPMprm1SP6yqsHRptWkKq6
         R2bZ7EBmEoX2xBy6gGZSdFcMXDo4hfWUpwympA7hnJpooDINWSZ1I4xUqM4Dvc9SrJ6V
         Y72Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVAEIt+ybQd4wUlXc5uWDkN3rNWEnTdpWOCZIk8kalbiLQ4oCpdpe6qwFRF3ex7aM4l76efbw==@lfdr.de
X-Gm-Message-State: AOJu0YwSFr6dnQtiwBUXDm22Ttn4XGeTYM2barSjKYeNXqgMEHsC6bEF
	VSi2d5+deP5oPLAZCYhYKqGb7Nut/YGoVRz0AI+/KsbEn8YqnJYKwQOT
X-Google-Smtp-Source: AGHT+IHaVwztOYGCHfJAN2ygyGo2dvVBJwg188/uIMaH/9iTUoPGs/iDnRIYVQ2aAkGgO++OO5yxUA==
X-Received: by 2002:ac8:5809:0:b0:4ca:a077:2929 with SMTP id d75a77b69052e-4da4d220829mr7223671cf.79.1758733594883;
        Wed, 24 Sep 2025 10:06:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7/TalD6oV4gp/B4xoHUB+By8KAxOOAQnzP13tqWuueCQ=="
Received: by 2002:a05:622a:768b:b0:4d7:a20a:baad with SMTP id
 d75a77b69052e-4da7ee4f07cls254721cf.1.-pod-prod-01-us; Wed, 24 Sep 2025
 10:06:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDfAm7+lekdunvl8jRU3BjjSL8g/bVKtA6dw7Q0k+pdZ8VY/p9rXyiIHBj57t44TXzK3M50JkzunM=@googlegroups.com
X-Received: by 2002:a05:622a:212:b0:4b7:a8ce:a419 with SMTP id d75a77b69052e-4da486b7062mr8697281cf.26.1758733594058;
        Wed, 24 Sep 2025 10:06:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758733594; cv=none;
        d=google.com; s=arc-20240605;
        b=WetxOFj2PPDPMym/UqLTwcytxQ87pUeJWWERj3vfRXoDMh+AxQ1DwU0Kj3fqLRCA0Q
         BAGGwSrPFgOI6u2S0oku6ynUs2XV9csetsMAJ8lQBWeEuscbBNQFfYeib8lorpUiCCSE
         TJMNrBihYx2+r/LiIUombxnQRO1IpA1zigVIDKGW8b8WVSw4w13mgnUN+yN1Vd5UI9Vz
         OtsqH8qt1RsqxwyEJKPM29E2fgwljl1d4khcv4g8yybFL8lXHgaMarOjOtY5xcZxWGJO
         Kdeo8Kiu9JLYz84lwjo8sGD4TOcBcxstQsLPSbwSoMq6TPLIXXyqQl+65WurDRwStVOM
         wlLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IYQIoIaOKCIxSPFzuBjsQ4uTXQsp3WYZ5kAt8a5vPEc=;
        fh=EStM6pqu3a7Q8MuRqDY8UFKW3fNq6kCdmrImRGWgliM=;
        b=XZaGambYnSchtFiZvN+E8UfBbfuOXyOl+aSqrw9Ez4d6PiohTxGsby6hWVL3Jc6ysa
         ig0SfhVqIZz6i7Udln0fdnZgsd7pqtnMXa69wMuKW0ifCOAmoXmcadZXS2PaJkqLeLiI
         YWKiixShJUcFeHs08O4yUadSRRjK75WWcUwkRY+5bXlV7fNRkv/8i5lPw8YQXNkQT37j
         BbXowAw8p+FlnYfHocFlurZ/nnN+BdlOtUz8t6x2wAmaQmvO8JQD92lwjnx9sh/htRZp
         jvWKnoEPlSgOV2cJxPSnYsAwPrC6upjgLqIj1Bqsk8nSIyZrdYWDbbDng3QrRbDZPpZN
         Yo8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=yMVBBGhb;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85a35b4e523si3172785a.3.2025.09.24.10.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 10:06:33 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.17])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1v1SwW-00000001yYJ-3ITs;
	Wed, 24 Sep 2025 17:06:12 +0000
Message-ID: <3504b378-4360-4e55-b28d-74aabd4308d7@infradead.org>
Date: Wed, 24 Sep 2025 10:06:10 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 04/23] mm/ksw: add build system support
To: Jinchao Wang <wangjinchao600@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 Alexander Potapenko <glider@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Juri Lelli <juri.lelli@redhat.com>,
 Vincent Guittot <vincent.guittot@linaro.org>,
 Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>,
 Mel Gorman <mgorman@suse.de>, Valentin Schneider <vschneid@redhat.com>,
 Arnaldo Carvalho de Melo <acme@kernel.org>,
 Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
 Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>,
 David Hildenbrand <david@redhat.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>,
 Michal Hocko <mhocko@suse.com>, Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 Kees Cook <kees@kernel.org>, Alice Ryhl <aliceryhl@google.com>,
 Sami Tolvanen <samitolvanen@google.com>, Miguel Ojeda <ojeda@kernel.org>,
 Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>,
 Naveen N Rao <naveen@kernel.org>, David Kaplan <david.kaplan@amd.com>,
 Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan <ruanjinjie@huawei.com>,
 Nam Cao <namcao@linutronix.de>, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "David S. Miller" <davem@davemloft.net>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 linux-trace-kernel@vger.kernel.org
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115124.194940-5-wangjinchao600@gmail.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20250924115124.194940-5-wangjinchao600@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=yMVBBGhb;
       spf=none (google.com: rdunlap@infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
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



On 9/24/25 4:50 AM, Jinchao Wang wrote:
> Add Kconfig and Makefile infrastructure.
> 
> The implementation is located under `mm/kstackwatch/`.
> 
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  mm/Kconfig.debug             |  8 ++++++++
>  mm/Makefile                  |  1 +
>  mm/kstackwatch/Makefile      |  2 ++
>  mm/kstackwatch/kernel.c      | 23 +++++++++++++++++++++++
>  mm/kstackwatch/kstackwatch.h |  5 +++++
>  mm/kstackwatch/stack.c       |  1 +
>  mm/kstackwatch/watch.c       |  1 +
>  7 files changed, 41 insertions(+)
>  create mode 100644 mm/kstackwatch/Makefile
>  create mode 100644 mm/kstackwatch/kernel.c
>  create mode 100644 mm/kstackwatch/kstackwatch.h
>  create mode 100644 mm/kstackwatch/stack.c
>  create mode 100644 mm/kstackwatch/watch.c
> 
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index 32b65073d0cc..89be351c0be5 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -309,3 +309,11 @@ config PER_VMA_LOCK_STATS
>  	  overhead in the page fault path.
>  
>  	  If in doubt, say N.
> +
> +config KSTACK_WATCH
> +	bool "Kernel Stack Watch"
> +	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE && STACKTRACE
> +	help
> +	  A lightweight real-time debugging tool to detect stack corrupting.

	                                                         corruption.

> +
> +	  If unsure, say N.


-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3504b378-4360-4e55-b28d-74aabd4308d7%40infradead.org.
