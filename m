Return-Path: <kasan-dev+bncBDV2D5O34IDRBY66SPDAMGQEV6WF3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05682B55E37
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 06:13:25 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-776aee67d5bsf291846d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 21:13:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757736804; cv=pass;
        d=google.com; s=arc-20240605;
        b=kTbzeU2biEZPptX4wKRGYT7I2nr1AX5QhArGBOChRN129SrZIKN8j4im1k6W9bgxEw
         uGICA8AVMC7yYfL+EkaixaEPGWPOzB8tuZsGJvKmjzI2WhGNgW6m7ZfxiWE4erqlAPZU
         a8ZhbfKTeXjiWJk7rqeHSf1c+/0fze9ThKGMfuoazva6idzB5e8uraYszBWMbLzRFItn
         rSBDH9y26z1SebmDw6l5uWcsWkSn3aiK1xZ1flqvQ0Pnohbmzgekgp9+N7jxBj25VvOT
         U+ZT4pY9mviHwHtARCUQON5VDyJq5/Re7vUCL8aM1MMPZOQqLjdX6OtTuyjbDaBIyGbZ
         wJrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VljqMA7lHOk2FiPC2E+RWRZN8gxJimV3riwruzqYB9c=;
        fh=HP0O4z5981pTvCRlKn8ENt9v/Jd6EnxOTTEw6iE9VY8=;
        b=YfqbVn4V3HIj02OuSudg0XuDbdAlotrc4znwDz0go4uSKa6f1BrzBRVQAeCKrczfhX
         uKeXYsj+75ZHJSCldsC/aqmb6/8bk+vYqNMLD9rHTktTINie3Es/uwLhB6gxaAoD2vW1
         R78uDpIbbY+/1cqNPiCI+19JnG7sBr5wvL9EHxlEvipxiYg+4Pmj/dv453+YD2eRB0Db
         PL6OnFlgCUGw8K5m7hrEo291C0bZAqQQt7m7/u3twZV+VAKT7MecJeTqo/UZETny7sSu
         831+CDVRwvOKcjEqpJXEJtdToZXpuUrGO16CXWEAL2rnB9L8SIHhiVD4eWM1Noh9adqe
         2cbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=xPzy07H5;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757736804; x=1758341604; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VljqMA7lHOk2FiPC2E+RWRZN8gxJimV3riwruzqYB9c=;
        b=bIazr7lLeSbdXVHuXHrpB0URj1towTh5xji+6ShJ5UkrHds2jKvnUNMcHZZRNEOkf4
         RZG+hdo605K3LsNczKaCPS70ECCw8+Emk5NqNqDzs4X+IgjbuIRqm/PKLDI8eS68S/BF
         1N0+k2HNRCDkGLRRyVHsna7QbzBW+pEuzlOK/G33DFGsgdj9dPJefqmgKehGNg1hf3Ew
         HRgeGVhDNMIoRVo7m5GgaLicqD6HcPxM3RrhzM2TtoyO1t2vdC5/XS9TWOMCgrWMLWA4
         /ItIMauBYJLwSI7Mt3k8t0csedUSFYqFms1rgDZIpUtPq2RAcrlov0Q/GLsOMVc5BOkd
         BhBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757736804; x=1758341604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VljqMA7lHOk2FiPC2E+RWRZN8gxJimV3riwruzqYB9c=;
        b=uWXpc1QXm3Eu+aaLTZvB9XXaLw+qCESfa8yOz/Q6geJ4k7yfhtzbdRPOi4NTwBGGoL
         eQOaOnpewNcI9Onr/sew71ktFOidmy/gicl7ehQHIsch+JkLz8iCRUUMxIKHQdHj5Udo
         GtIa1Qfv1qz6wWWzEzgCbFVWIjAxB+AWyiYP+3oxa9hXRH1ZutHx5Z9h1/6kLMkqPEK7
         /8V1PBwm/DOICD4TpgO9R+je9VTFUGjMvtcpRpWJg4A/SdJMChQSFG6CW706HwJEHVrr
         Mt6J5LY4NudDZH22e+3yQDPuZYkv9C2pEhNZ/0CrTCN0dMmsM3qgmF4FSJzkz9AAWfV1
         KSYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCpeVWYk70Z8FEBgCt55NOSkKX2tfpaUV1uV11ZZ3kO+tojR+MOBBI77Vl6eGqIMrJTNI/bg==@lfdr.de
X-Gm-Message-State: AOJu0YxzsO9KAU7YDma/swJmkQUb6JbDwF6DJg3sbUu9guWIDaOpunab
	gmsHxwtTTqAx4t8WQ0+OM+t81uF9V1eUWHP3aDvoWdSKNRzY0iltM+ae
X-Google-Smtp-Source: AGHT+IGAzRNxa//IR5MkEMoNu/DDfBwLrm56daYMtK2pxiSx/0kFQ8a4b2zV0NNH88ooQ4C12aLxig==
X-Received: by 2002:ad4:5fc5:0:b0:764:c753:c57a with SMTP id 6a1803df08f44-767c215c27dmr70191246d6.34.1757736803626;
        Fri, 12 Sep 2025 21:13:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4hAIBSr4mCn3nReiQPGz2uzusuxjPGUsx7GWiUTY8X6Q==
Received: by 2002:a05:6214:5287:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-762e5bef220ls43832016d6.2.-pod-prod-01-us; Fri, 12 Sep 2025
 21:13:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVTOHX6lXNC49X9Uylf17Sizt0Ivwubuiv2MMkTCfORCSTaAash8COOKXLYO7C7s+GhkdOi+6Dk/Y=@googlegroups.com
X-Received: by 2002:a05:6214:246d:b0:725:c2b4:3335 with SMTP id 6a1803df08f44-767bac0e426mr66864666d6.4.1757736802618;
        Fri, 12 Sep 2025 21:13:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757736802; cv=none;
        d=google.com; s=arc-20240605;
        b=FT64KDThbkwQKW82/JXgv6xlE7Z0rLfUqzgVCLvJIso9M0s2+9waFqsYDzPY8jblKr
         I0Lnsh4crI1gQuksvJkWKsHmZW9lRZR46BFB41QMvnjHUFE4EZkOjw6UUun+U2R774pt
         lsSlOkqpNbskEeJGpQDFLNG7xNeArWqO+R7xxlC/mUAR39ObVjHdkEU1O5knUog1pDrC
         NoMlnlsCEXtQsdYuNOJY9jTr9iD1S9b5TpQ8evGrk+KfUSc/ai70sZPZORbsZ8G2GPqu
         ZPO9913llavZRmD1sFqxOxNhsdkc4LWH8LAPZ4thK5vYdZIPYVipNaRHuqetzd9ghOZd
         a7Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=u7ndZnQxyXKvcCzhFli8oZf0PjWLBirdplU5n0FJmLw=;
        fh=EStM6pqu3a7Q8MuRqDY8UFKW3fNq6kCdmrImRGWgliM=;
        b=idtz0z5U7RoUXncDQcQbyiyj6y/4Xd9wgDaNPNX3ZJgevMejLnz46liVtcj3uICPaO
         gJDs+zojKpF4O9aOsMEQwJYnDpouJBD82V2uZ1SlQOaSUFg/owt7P38mXLTK3WZhopWf
         uRTi6wBM7ErOnZI3aeycPzJoflZSUPM/m3IScIDOX/lhBQACfpAmf0lDM+13vycBKI3e
         MzCIEV+rSmlLMI9tyHz2Ze0KSr1VnI6QyPDTao24NBQqS61s+ATkszhwF49HOLENAuzp
         Amzgsodi4ZgylyXQXRCqrUrqS3uTTWSgvSZTtsjtr0xCANo63KinxUVuPvdht5Up6AZE
         umLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=xPzy07H5;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763b97136c0si2681756d6.3.2025.09.12.21.13.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 21:13:22 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.17])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uxHdN-0000000D6om-3RkA;
	Sat, 13 Sep 2025 04:13:09 +0000
Message-ID: <6b5e5d3e-5db8-44f2-8dca-42f317be8e0d@infradead.org>
Date: Fri, 12 Sep 2025 21:13:07 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 03/21] HWBP: Add modify_wide_hw_breakpoint_local() API
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
 <20250912101145.465708-4-wangjinchao600@gmail.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20250912101145.465708-4-wangjinchao600@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=xPzy07H5;
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
> +/**
> + * modify_wide_hw_breakpoint_local - update breakpoint config for local cpu
> + * @bp: the hwbp perf event for this cpu
> + * @attr: the new attribute for @bp
> + *
> + * This does not release and reserve the slot of HWBP, just reuse the current

                                                 of a HWBP; it just reuses

and preferable s/cpu/CPU/ in comments.

> + * slot on local CPU. So the users must update the other CPUs by themselves.
> + * Also, since this does not release/reserve the slot, this can not change the
> + * type to incompatible type of the HWBP.
> + * Return err if attr is invalid or the cpu fails to update debug register
> + * for new @attr.
> + */
> +#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
> +int modify_wide_hw_breakpoint_local(struct perf_event *bp,
> +				    struct perf_event_attr *attr)
> +{

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6b5e5d3e-5db8-44f2-8dca-42f317be8e0d%40infradead.org.
