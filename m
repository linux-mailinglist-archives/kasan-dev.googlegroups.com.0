Return-Path: <kasan-dev+bncBDV2D5O34IDRBPPOQDDQMGQEMAC6U2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id AB4FABB8253
	for <lists+kasan-dev@lfdr.de>; Fri, 03 Oct 2025 22:51:10 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4e0e7caf22esf73520301cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Oct 2025 13:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759524669; cv=pass;
        d=google.com; s=arc-20240605;
        b=DX7rM17sC5VLU+nB/e6p0PxXNuqLe9sy8aAIGwIozP3UK9N1i9hPkmJRGOaL7YgBPZ
         Ut7qg0hmcR/ZUt6obxRWdfKI0du34chNhp8mJEJCRClxRfZMKbr/tybdbEMSUgvJX2i1
         s9PI9lGjKuHUHIFCTB5kBgGEeYxyJMq9xRsA/mmR+ZpuahAEIt7TYM/1cUwasZ0nXFrr
         v46VV45WM0sKcb0rBudA1yTNcKyuDHKQ9jwRhYTmwDBYEfF6VfVcNIbCEdvlI7kbWua2
         4tlI897kC+r1hAzo81BBqjKjqwuSKPyOAtGLeRAVQXdLskVByJ4I0QANx9Lirnin2IYJ
         GwmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=gW6Zy3x1ZaKH6h4S/iRMYJu1k28r3TQ9hzDSI/ODY8Q=;
        fh=CCNDdLeCLUToY0EwCP7jbklv2uyLZ+FibVYEva4xh8k=;
        b=RxmJaNNsPYM430Fa0bySe4oxIK1B/5tMCzps78shawxkUhuVMBMzXO2Ggl7OmKG8X3
         S+7XTwhgUqXXqe3DT5gkiDpyYeYHSUA1bteEMqFTKlGXFDreLugEpBZjjrCHw6gUX1Ei
         Q5TVF/tmAdptpXdC03H/LiC6bZSl1v4pSZfxLeetukWa1O0Fo4Gn0+RYdzLcBo0MWcCj
         74fyRk1gUKlQF0O3Tfp2ENou9/8C58FZlv7Ocr4t43MoMkG25hdq9dikql3NLRIgXzER
         TVMrOVgSp1sHHIFLCHbKo7PWt9wOgwc8ptpChlwag4c2IqgocRQkSPl93ux6HuVcilUB
         KtnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Lrx+Opa8;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759524669; x=1760129469; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gW6Zy3x1ZaKH6h4S/iRMYJu1k28r3TQ9hzDSI/ODY8Q=;
        b=xWtAd44tY6fDhyxy9yl5JEdJ655HPFFdcnzXMbaTNWszugx6CIlZ+97YAW0KwQIjjz
         cBLURgJXbhjYnDoBp8Nu0Ra+kr3DGuJrDqo3X6PwagAAPYiu5/60xYvqpeR8VLQtbWzE
         J5A5GAOwJuKTGxjOiymOrFcCmbtOMOEHisowwyWYKwuZTSQzWmDpGwMQs5jz+jgrnDJV
         2AYs7drQlBBCm187wUldcp8oYG54ax7fp0rz/mLJS+y1F4bSlEaY5OZqw7HzhRoyE+aC
         045iLlcxHH8WL6UrCShjBNLIp7MDihqe0ENaezqhFjO7YqW9rEUICa4BGyljeT2emfjG
         +nsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759524669; x=1760129469;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gW6Zy3x1ZaKH6h4S/iRMYJu1k28r3TQ9hzDSI/ODY8Q=;
        b=buML38ePafEkIVqskJfjV1UuEQeSae8Ih1NMprAo8sbtpW3si5m0QT7BkI17z67jtr
         pBhawWEcRvFeUuJMMMhfGANeOmTXW7e/IVBNhkJrl9DgDto4WQWClg1uMSolsoGFlLAw
         OEIJQhpy3S1mFE060eKXnqNLftDSpZktEhkAhqFGLMG841jiSzsRhIFDkejtU9da51+8
         Uo0kSkM+GYGB8AvCeSZshrrBMdYTeN+la/HaMx0guOT6ubeKC8s60pJ9wcWZO8XYSXie
         IoLH3jA/eMgEM0ZDQ4PZqldZqxsRkZRyqpwxV+Yezvp+cbpV0d8cEMyj418J0AJIZbGo
         AABQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLZvu5TmSgxGH29gCOc0IMjUzE9YLG6y3XvqSHR2Hr1FgwpdfQQMyuVZ/czMJWSIhiAicyuA==@lfdr.de
X-Gm-Message-State: AOJu0YzNSYjNsgODBdXjj60Vk6ie7DV7mduKYY9S4CqaXHMpP4eaAwPl
	LcA2CuRf6mbhb/SRdfT8EfnmjGNNQy9CJkBwV31Beu4ipoRbBTBPfmU4
X-Google-Smtp-Source: AGHT+IHlg4KzMEFPekaV64e82BCVSga53a0Qik6vIOA11mU7ej3xkqTDvaR3cg54EOMdvrZ2cwPRcQ==
X-Received: by 2002:ac8:5fce:0:b0:4d2:322b:9b58 with SMTP id d75a77b69052e-4e576ae7575mr58926721cf.46.1759524669257;
        Fri, 03 Oct 2025 13:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd696SkFeqmLH+Qou7eUUNmkWvMpexoQEb3x+k3XAQXhtg=="
Received: by 2002:a05:622a:8352:b0:4d6:4b7c:c237 with SMTP id
 d75a77b69052e-4e55ae306c2ls39419381cf.1.-pod-prod-03-us; Fri, 03 Oct 2025
 13:51:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWagNjwV+9YrViHMN/19BLcUZpWrle9bwdaeFyjxxIaNGyH0Ee6opccxmrKu/mfwRrUexbkiZFBgU4=@googlegroups.com
X-Received: by 2002:a05:622a:4894:b0:4b7:9c8d:1bab with SMTP id d75a77b69052e-4e576a60b1dmr56327031cf.20.1759524668522;
        Fri, 03 Oct 2025 13:51:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759524668; cv=none;
        d=google.com; s=arc-20240605;
        b=O+dTFXesMxbkt1Hk3K8S+iaIIhCldQRIbj3ObfZxJqn+fJcozYU3dwcxrraI2BBGj/
         I5Cuteww0Rgt0AEDoJAe4RzRugl5FyrBnnaic8xNj4sk7fLXPZ4CXsmEqazQ26I8CFSS
         dnXP1WAiaBolj4bXyb/2DveImdhQEvA4wH+MhoVpMHvBG15H6VuPi03dQOMIhaEEWDgh
         bhjtnemWqgXXcFpO3OtDgy1z8Xu2UeKzyq4wlK8MylYWvlW4dWgMC+aLmsIS5+cGb/sy
         6uZHhPVwP2G6haOabMVqKzfT1myCFQ49Y2/Q738PLySdXhoBf+MlBNJxexPT5rbHD4mV
         3r8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=oIs3ppVLk6gw/qZXypZLZcOfa+yCn//X21VZFkDaLYU=;
        fh=cHwqki7ZDIrT3RHhLW47jmiIK6nXXmPQd8r1WVcpAy0=;
        b=kR7BEOSd/QGHt5MSXzvYg0oAxW+2BKmLa8RCeyx0wPuqhdSIp2QXEiz5c1Cvrx/xv6
         fnNZLtl2zRrT3gcCodxJIsKyHRLcyoGvtLflmMJ+ZtaOxA3RKFLHaSRIst3wVfrpjvyL
         3ieMvEoAhOun8SKSHcdUol+lBvEfc1GJSpXO7tPS1EMlv2JPDUsYOQb3m08HrvQuusb7
         lxXuqHv/7snT0hutJbCDIM04y6U3UpBRuriMx22yW9aaDLfyxZbr0OhOQz2WwK00cXX5
         uFhHAnYdKv8xllhIxXIuPWIR72QAfyCChCyu3bVQDZVKaWGA6Trs65nsArQR1iLC+Qmi
         aQHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=Lrx+Opa8;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4e55e277612si43571cf.4.2025.10.03.13.51.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Oct 2025 13:51:08 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.34])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1v4mjl-0000000D7bQ-0Z25;
	Fri, 03 Oct 2025 20:50:45 +0000
Message-ID: <3913273d-12e2-426f-aec7-263b7f49008a@infradead.org>
Date: Fri, 3 Oct 2025 13:50:43 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 23/23] MAINTAINERS: add entry for KStackWatch
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
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
 <20250930024402.1043776-24-wangjinchao600@gmail.com>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20250930024402.1043776-24-wangjinchao600@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=Lrx+Opa8;
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

Hi,

On 9/29/25 7:43 PM, Jinchao Wang wrote:
> Add a maintainer entry for Kernel Stack Watch.
> 
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  MAINTAINERS | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 520fb4e379a3..3d4811ff3631 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13362,6 +13362,14 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
>  F:	Documentation/dev-tools/kselftest*
>  F:	tools/testing/selftests/
>  
> +KERNEL STACK WATCH
> +M:	Jinchao Wang <wangjinchao600@gmail.com>
> +S:	Maintained
> +F:	Documentation/dev-tools/kstackwatch.rst
> +F:	include/linux/kstackwatch_types.h
> +F:	mm/kstackwatch/
> +F:	tools/kstackwatch/
> +

Add entries in alphabetical order, please.

>  KERNEL SMB3 SERVER (KSMBD)
>  M:	Namjae Jeon <linkinjeon@kernel.org>
>  M:	Namjae Jeon <linkinjeon@samba.org>

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3913273d-12e2-426f-aec7-263b7f49008a%40infradead.org.
