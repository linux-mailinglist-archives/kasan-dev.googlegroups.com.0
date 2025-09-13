Return-Path: <kasan-dev+bncBDV2D5O34IDRBGG4SPDAMGQEQ3QAOKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 288C3B55E32
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 06:07:54 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-71d60163d68sf37730817b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 21:07:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757736473; cv=pass;
        d=google.com; s=arc-20240605;
        b=RO31jaPcLae4Wg/QI5Z73vsV/LyFdVFvPervQm4IHbSzDcxIpAdyml/TGBJ1KEUgWa
         fqpsLQM5HoYsFJ5kEfGyHumJChpzD9wZFu20rDmD+H1sYjtDr3gXRL5EftQ+c3Lwteib
         n4Bu7E4aZUx7sTI/2FNcCWply//2mEZWqw2N90CFOQ2pWFCBF2y1JnfwNq/jIY8hR33z
         ERgAhDja3TZ/VSPMrB5cYFYjZtXNGTVA4Fi/3T+7ZzxqCmtacKBLj/KKPiGSAfQ6arj/
         UuPkh+/K7RAZumFXycAYv/JShBAPMqyfXchRvacfg+4kIY6aZPsV9P3ZYOzuRJllJoNK
         N37A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=bPLX4pZswIZqCKLS5PO8/FcLL/3GJ3dm9+4iOtp3wi8=;
        fh=mpFzA2I0vXNKglQKODchdw5E+tFYHvL7s8ZA21krWlc=;
        b=EUQLCYpVedGk3CzS6D5NkPiozi7WRC7wZrkJZ+cZeocvpwVxkowE5xwwf85kxznXzT
         7cEKTYJJBjCFytjHA4WHoYlthI+waebNvkxyAzcpwib2FZTrSpxfoejvclkT7/DEcNBe
         Er3j7HELdX9OBiLtHgPkKqedT5KGmQvqC9892UwPO58PqXTVainhR4dlIyfnZju0206d
         OR1emdaGVHKmSPhl3cJ/LbOaUukb9Wvz9AT913Mnitusvaun5XGRez/qAqKaAdEiw3AN
         zxNTbb1BIjSHnJagnPypAZDO5G0Mzfy3x+PA9UN6jt2bLilCM46ZO0ie60u9C9xhi8Rp
         +OaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Zvj7+2VJ;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757736473; x=1758341273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bPLX4pZswIZqCKLS5PO8/FcLL/3GJ3dm9+4iOtp3wi8=;
        b=sHOHamidWds6KV8HNqtHfpsmWOtsq27G43tmAYyNsJTCKnJUri9tupqQjC3aGYFtaD
         kZzyuppNFgloWOVFSBe3yexrc6jqUZzejh8SLWjgHmR1CvsRHViiIla5RBU93R0C8wgN
         AFiK4yNex3sRIFxIaaRHvWFiJMHb17OA9jE9HS9JXQXBKfYHvRsU4NfvvWDRkcY+jDDa
         yMNuPdHV0zJ9e9+UwtMhODzbteu9EHB8MX5+QOq5f5mGLl8lDYw8P/R5CzZvb3DkSrkE
         Yq5SBO0/uBJmahHTLlGFKWJsEyFgAgzhawsRxLp0ciQxIfp2/na/nV7iHcGDJ+UciPkf
         zw5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757736473; x=1758341273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bPLX4pZswIZqCKLS5PO8/FcLL/3GJ3dm9+4iOtp3wi8=;
        b=wlZmvqRzvM/N2OUCqePUG+WkNJpSPSZMyK0c18pB+7LXfht8iraHhfyw4tpbMkWif+
         JtywJGm6DCcklyPkDN8VMaQy57+1W7kCHrs50HRcFN/IWr5lbUiv3dtXCqkpC8GuVAiK
         wsT1BbaptY/OSeaBSfj0CvoQOWBHZAqUVSoUgsx6mXbvNmI/JUFGeH2ciMNgWptk87Uj
         uJ3LUVxtiwxwMU8vyMeQCTZKR7htU4anj/DhPCRpxJGc3wU4h2gKFHMZ1seo8f8Ru2G3
         yixrDGnhhplNBGZDxxenb6hCJjNJvUZeTPf4xa21R3UMKRmyFj39HEWEQHA0vcJfsdTd
         GZYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeOL66VADo5UDAFB7pdW0zoqpU689ox8I8xkjK5MCxKVeTGQkPvsVg3L8ElFgSGKNbWXbKeA==@lfdr.de
X-Gm-Message-State: AOJu0Yz7oK52iRxdojIKh1DHPTI24XbWQWer5ndynPUzza/vZltSqyMe
	xkhj+ZyABfbYEAPoKqJ0XlleoaZ8Zd86rk9CKityy0ryDCixBmOaIBkK
X-Google-Smtp-Source: AGHT+IHuAJ5PDv6EgeqikkD4SlvVFkxfvlkzQJ9WccoALT6kxZG3JT5b+52VrVtLFMYj/7ySfjMXjA==
X-Received: by 2002:a05:690c:a92:b0:72e:13d3:fdf5 with SMTP id 00721157ae682-7306481ca73mr53510527b3.26.1757736472770;
        Fri, 12 Sep 2025 21:07:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd53s+OqDnPF9OsJSvkE2PqDAoZKCBu1eR79sYGk/+MaUg==
Received: by 2002:a05:690e:2549:b0:5f3:b853:a8e3 with SMTP id
 956f58d0204a3-623f31883b3ls1123498d50.0.-pod-prod-04-us; Fri, 12 Sep 2025
 21:07:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJ77miZYKZUjr1kgELV2AyoSi7Ro8X4ZwGyZwx6ITjbaReVRv/akbv9Zs6543nnDU9/qcu4RrdgsA=@googlegroups.com
X-Received: by 2002:a53:d6d0:0:b0:62b:c5d2:bbed with SMTP id 956f58d0204a3-62bc5d2c3e3mr574917d50.33.1757736471579;
        Fri, 12 Sep 2025 21:07:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757736471; cv=none;
        d=google.com; s=arc-20240605;
        b=kWfk6+clCdTFy9dojTkatwtEeAc777VQM910Q/uiXwpVQ78RtUZManctC6DHeYB4JT
         6v/zd5tkfHLnc8p5ADUuD2EIY9LpDNyziQP2bZQjOF5mu+fvSix3MKvAn+h8x5eBogAF
         4GGzNkdbwx/ByxGp1J3LWGgiEyzUaEpveznVwnhfy+J/m/6kR7WAiPnREFzILJIO0ILB
         r4maSe8V2aJBD4hJCHNVLGXi+/K8ly1yvXNvee/94Lfcv0RQTQF/K9MHhhIpbM824bJg
         Jf18vG6ndt3GWTkVQitIy5sEFnQBXzdWxsvD+ptAFpgh96LTwAqDxeP5eCpxPGhF76j6
         pw+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ZkZpc5dBMnXI4POCZ2TCFFqEd7xijX/+QZHk6h+vWnA=;
        fh=EStM6pqu3a7Q8MuRqDY8UFKW3fNq6kCdmrImRGWgliM=;
        b=hzyA8Ahlv9/AY9/qIeKacl+URxL2UcZoJ/kZJJq7/LJbWFkdiQMtpy36PfewcFFaFw
         TXBeNQPFhXrNq3REAR/nAhDMvpE8BTqojcpXzz6rwcLdcuF9iEUuGXQmBL8fhSslbOwa
         4OQnpB3H+jpd4H6QhoDF4IsaLAWTvduGtCbypQM0gtdXtpH/6KUuu1uRkU+sS5G8Mb1b
         8YDf2HTKjJgKk1UIDFFp98uZE/W2BUblj5t88BauX0G6KYhn8SJ2jl5zy56sdSdiERsr
         tuoXIc1PL20qtsedFXk0EnIKq40+6h7JW5Ob4ZpWl8xfC0RSYujsP60ZVQhh89JnBLXU
         1l4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Zvj7+2VJ;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea3cf1ed1d0si233666276.3.2025.09.12.21.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 21:07:51 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.17])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uxHXd-0000000D5gz-1paw;
	Sat, 13 Sep 2025 04:07:13 +0000
Message-ID: <69198449-411b-4374-900a-16dc6cb91178@infradead.org>
Date: Fri, 12 Sep 2025 21:07:11 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 15/21] mm/ksw: add test module
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
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
 <20250912101145.465708-16-wangjinchao600@gmail.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20250912101145.465708-16-wangjinchao600@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=Zvj7+2VJ;
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



On 9/12/25 3:11 AM, Jinchao Wang wrote:
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index fdfc6e6d0dec..46c280280980 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -320,3 +320,13 @@ config KSTACK_WATCH
>  	  the recursive depth of the monitored function.
>  
>  	  If unsure, say N.
> +
> +config KSTACK_WATCH_TEST
> +	tristate "KStackWatch Test Module"
> +	depends on KSTACK_WATCH
> +	help
> +	  This module provides controlled stack exhaustion and overflow scenarios
> +	  to verify the functionality of KStackWatch. It is particularly useful
> +	  for development and validation of the KStachWatch mechanism.

typo:	                                        ^^^^^^^^^^^

> +
> +	  If unsure, say N.

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/69198449-411b-4374-900a-16dc6cb91178%40infradead.org.
