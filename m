Return-Path: <kasan-dev+bncBDV2D5O34IDRBVOMUXDQMGQE3WWOJUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (mail-yx1-xb13f.google.com [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 93B52BCE714
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 22:02:31 +0200 (CEST)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-63541ee6187sf6192745d50.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 13:02:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760126550; cv=pass;
        d=google.com; s=arc-20240605;
        b=VzunCD1IKfmIpIyE69AQ6tNKKNib+xS812hnFbWmOMnBbVfrvCAoFL37jO4vyK+Qf8
         kHYxQecb9dpLe+MEeSY2S5C0OLWt9LXCV0OqHblksFW6iiATMI5zUKlOWjTd4X+4J6e0
         ea7I2KowC+RBs/om+D0VTkF6cBUtVggT4VLUha1WJbqybUtOAhM399Vk+Ptme9t7tS8h
         Gj80rGyHrXA/xLVG9ER3XIWKPBnATdcLMZjTvM+ivW814fXHbAVmCqQqx34oi9o/hS/t
         X7jpD5jR+O4TMIEpay7Bbw9NFyiFEFtGIVICj2ZDKFVqS9w8831hGK0mqNoSVECEj+g/
         blJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=BwibYNvGUH+cJklrbEy+9wvcY4U8DiTa3qUT1xU8buk=;
        fh=GsvGfFniE90a0d96vyiO9UaTdYCxmkmKt0GnX+eWoZ4=;
        b=Cx6gIo2rMrVno7uNG37VgTCSwmnfloJ87gtYEyug3AgnZU+iUXFy+YYQn0PDhvjaaz
         bI8RwUMin+ZB9pJ4TrbwSnaRHV85jpRRX6WeS3LzSw1a7a9iGInhrnUH8m5CjxWVW5r2
         O6m3VK8RXKLST0ROG1nfNYvnTKgVY54Npwjn3Wh6kSkWnsNrYz7/U58mJsoTeKkemAlk
         sbrybM3hG1ZYY2Xltje5QWRGlwgrTKAgdUXaNf/RUYFqSxYER3jNgJrdqX/3BLlq2Dv6
         Ff29xKDK9DZ2DfIjkXLizSpgv5f4GRcHUZc7y9GIfz4x/MPetSye9jeyEIO35nLv51kq
         rADg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Avo+7IaE;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760126550; x=1760731350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BwibYNvGUH+cJklrbEy+9wvcY4U8DiTa3qUT1xU8buk=;
        b=KAX3hxwcqUhiFw9B3ww8VlsEiZpGVCaIpJIIO2OLZavsxEIK9tsIMpBBUmgMfxCrRK
         D4WTmXpS5cy7ZPMaAm6uTMKwffJ8P10iefKwFRj5QO6e0QDV2Jb3YJOfRITyNOiPoK+s
         OHV0VAGrnF0diavjZkVq2knVqhdTYN66Go9t0NxstTkO1grz9lSqahUcRc86ipbiF6aY
         OdCuwv8Npm3FJGNrUR5u9U+/HsRz7J7p3roRcG8GWlAXlxIiv4Y2qVZKn83YsXKE9ZlL
         H1KxEk7VkoKIMZngWRB3SW948vNAVg4sUFPieqgWMnJd3M4USVuEZ6srI4KvIOPFoO/s
         q4uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760126550; x=1760731350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BwibYNvGUH+cJklrbEy+9wvcY4U8DiTa3qUT1xU8buk=;
        b=FvwjdyqY9PmZTBaHtthSRwQmqZu9cqx4hWCt/mLa9OlHUDh2tuSc2DyyOxsFu0y4v2
         5swkEECueZGzXhf8naQ09ogL72rlm2w/do81rZMm4iPk88o4p4cIIZ3sti+qpMtOtdsN
         prqbd9te+4PkVCxcd3HBwkqhlHXZyb3UoCvJalpmcNn8je6bGKB1OwhwP0C92GJKTuDe
         kU5r5740Sxf25zNQVP8vYLkYcEd/dZZ5loRrHTIOB2+AyKar9ouSb6iM4wm4Z/ZP4n6D
         IHYW6DtoFIL4sgGgb64j2VYxzcyddzYKWSsIgtTRFsOFLHyKSEkZWJr/uVBwt3OON1Ef
         DPpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWy2JT1eGKKTUH/K/6bOMmv6ZXZPb20YkcJwQVIPzU8P0WGGbnVg6nyQnCUxF6IAqAONV9cHA==@lfdr.de
X-Gm-Message-State: AOJu0Yx+6TbV8LTPNoER1RK0X+IFFb06IYyfO2/pyQVxeokyyWCsDOVe
	ZOQSnVB+UZndrqanjWrU4Y9S4jD5m9EGKSQAfWDY1I81gbir9gerpYkD
X-Google-Smtp-Source: AGHT+IGjvKGzvIids745W0Hai5BnU+vfII0rRWp/fKjaOa+EaR1D3mUrvqycZBKMaGSOxF3CeU0Ljg==
X-Received: by 2002:a53:b4c4:0:b0:63c:f5a7:408 with SMTP id 956f58d0204a3-63cf5a709c9mr323541d50.60.1760126549940;
        Fri, 10 Oct 2025 13:02:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5WC20ya320/fQLuiW3gSVS4GUlWU9XyhWEVrBX4QA8xw=="
Received: by 2002:a05:690e:150f:b0:61e:b065:c897 with SMTP id
 956f58d0204a3-63cd98aeca9ls95407d50.2.-pod-prod-06-us; Fri, 10 Oct 2025
 13:02:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZN34rnc3AX+pjwwhVwoXyzXKT+QqYz9XJniyVXoxKhxM7NZaElXDgmDkbbUdA+lEgb2dA5hj7tcA=@googlegroups.com
X-Received: by 2002:a05:690c:4c0d:b0:75f:58d0:38cc with SMTP id 00721157ae682-780e1534b26mr144713837b3.27.1760126549076;
        Fri, 10 Oct 2025 13:02:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760126549; cv=none;
        d=google.com; s=arc-20240605;
        b=SVnuARU0F7d2nViamfk2RHXoZIp8HOF/EeRLc4N4TTccIEP1Cpib5lUbg3EmkIbIkF
         xwt7ZjAhEIOh/rZRJLgfR3uls1ehNqUuyl/VJ3XYycqFY987dU0Vk7xMuWKeJx6ZaC6q
         dHv2aJw5atCFjryYW+V/MuJdVm6ph1thFSm5jt6aZhqmji2KZHhTMbaZAB0slEB9CzRQ
         vz8/sS8VuUC4vQJ5/hKtIYOQKzZ5mzb+bhhJYWfITwIVPjXDQO6ebwiwATfg9aJfcS+V
         oUvyd2rzUgOkykq6QiNBeEhRzd5TOMIOUhoYoeUiz4c6i4YyBx4jHw35lS5BqqDLFBkN
         BUsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1uOItTL0KBTFqu9SxT/ohOMw6976arZ30lgBj7Y1/To=;
        fh=cHwqki7ZDIrT3RHhLW47jmiIK6nXXmPQd8r1WVcpAy0=;
        b=aZxMi+5UPxPVtJRzFte9jQ/AHuIBmyrZPwQ9k1OAafrtUjA94c4Lw0u8/Defhtzz9M
         WaETpbz2oQwQ5az+kl0W6Zf35fCuyuZ7t+w7z0JzpkA7jMLWsncigCOt8PlhS5slB7G8
         GSu98oTBdm+Ve7vX1fB/MkDQsm1fmqpl4v++9wVuycALzcUtFn7sQmU17s2KGX7iM2ut
         yEVrnbGwKmi07YLKZL1l9OlqxbtVZDo47E/Ube7N8ZB0330vWRjDx0vhj6YEHK8+k6YJ
         UCYsXWkPWYYTGsZTvK2ri4C6Z0El27BeqPDlSWmTi2Lkq7vmqVBkVhiOJcP+lNCdXTfx
         rQhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Avo+7IaE;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78106fd6027si1119557b3.3.2025.10.10.13.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Oct 2025 13:02:28 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.43.113] (helo=[192.168.254.34])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1v7JJb-00000009HMt-11L2;
	Fri, 10 Oct 2025 20:02:11 +0000
Message-ID: <c1b2ec8c-0c09-4356-819c-7d2ee28b47f2@infradead.org>
Date: Fri, 10 Oct 2025 13:02:09 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v7 22/23] docs: add KStackWatch document
To: Jinchao Wang <wangjinchao600@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>,
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
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
 <20251009105650.168917-23-wangjinchao600@gmail.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20251009105650.168917-23-wangjinchao600@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=Avo+7IaE;
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



On 10/9/25 3:55 AM, Jinchao Wang wrote:
> Add documentation for KStackWatch under Documentation/.
> 
> It provides an overview, main features, usage details, configuration
> parameters, and example scenarios with test cases. The document also
> explains how to locate function offsets and interpret logs.
> 
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  Documentation/dev-tools/index.rst       |   1 +
>  Documentation/dev-tools/kstackwatch.rst | 314 ++++++++++++++++++++++++
>  2 files changed, 315 insertions(+)
>  create mode 100644 Documentation/dev-tools/kstackwatch.rst
> 

Tested-by: Randy Dunlap <rdunlap@infradead.org>

Thanks.

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c1b2ec8c-0c09-4356-819c-7d2ee28b47f2%40infradead.org.
