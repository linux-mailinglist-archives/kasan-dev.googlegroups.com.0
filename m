Return-Path: <kasan-dev+bncBD53XBUFWQDBB2FL53DAMGQEVNBLKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id C10D2BAC103
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 10:33:45 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4d6a82099cfsf142745421cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 01:33:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759221224; cv=pass;
        d=google.com; s=arc-20240605;
        b=Prx02OS0/MJoUTyLDPABn+CzTqbqO5ZJOON/wKLhMNNbxHlTNu4ySeFr0YAUDRwec4
         BrGyxqtVfcT/zteFOO//AKHrIPYjpNp+SCJhihN8LogkDgl3sYHbslx4iyBOoMD9L3op
         sfeW0hpKSuW/LGV0WHZLSh+Y00d40rO/QMAw+EbvSsRdqulRByqX6Yix+EYecCrjw6t9
         ssqzZRdstqWynzdrsKVdqle8L6iKbdo/Re3wsz1HGmcuyBGt7Ajv2DP1WnVmTLWGlyYE
         siyYwQ71BUvPQIuge62Vi97GXkKQH40ZeCEjhPrIVQ45lWa4UeXpsRq2A4EmHVmGMDS8
         Dj7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=vXn/VU4YAN6W1iwCLyBOKSLicazPAZUoPkXI+ov7O6U=;
        fh=2xCV2Xo5xoz0d1dHmish5XFMMvOA8uVW2wNdhtFsQdw=;
        b=QzyUiwED4EcIVNXqV+kgoaSXxkgocdiTJz4qu8AsNXx6dySypyzX5R0EKhGjUirpSA
         z2r59sEjH9SDkUKUSq3WY69FbdwhKUTkpiF9AF459B8OaEGyre3BRJA9Puum33lawxRR
         HAthGQhRWr221iEObo4mbsw0Wo52WItDWnw0TIsFWFbVlQo/EZkWHnl81ygkZIMOJpmP
         uD1OskbGtVrsdrP/D42W1fJPAyw5RSYqCikmQhHxwvXi9wTPK7e1fDhgP3aoDgPQVVNw
         +3kW+RhspotNpbHGD752GdSUIc1BbSRf9J+QSEHcV7jCWPhgKNd0HUHetdDyRw8A1aF6
         QWEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A/mfWfCS";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759221224; x=1759826024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vXn/VU4YAN6W1iwCLyBOKSLicazPAZUoPkXI+ov7O6U=;
        b=tyIdD4e0/w71+c23wIhiACT0k1DjtleUmRO5lnfjDxntR/+rf8Xd4fqp/SELGkIebY
         hVd8YwD1RPHQZw3CZDV5nPIb9rBELVE1O9mIXySjzLPXcxTn9Ni6G4AEOdbhsE7zpCEG
         ZHH/mqFK47x1mRSrfINqAwudHPLYKLhWSqJU7QhYChwWBh/wkestRsdvFXRSVR3Y2Od5
         WOGrWd2wWLVlD50LCMJr2nV+rwHYuYd60XwyG19Qhkz5v6jth5v+GRObKjUfUytLhzX/
         MrxizwjDkNqnC6k28pfMcioxXZoTSDaYs+40ZrfXWAwaMXYVp9Tb+5z8FQhSaas+EZAa
         Blyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759221224; x=1759826024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vXn/VU4YAN6W1iwCLyBOKSLicazPAZUoPkXI+ov7O6U=;
        b=UTFSD/w+WR99adfyyvl5GT30y5YvfYBfHbQk3cCSDsBxEepMqNYT95dwMtgclxNhDR
         s6PalqAbUCH5UYTlfYA7WiFAxKZaPtlzDBcvC50U5eqzx54+suDiZdaLE4wPBBbgM9ub
         4Ti9xOhiDpsiMZbt6Df4OOtPXhLVszDABdnzQwEFcOwmaqR9E+fnZKDsp5mPxjizYBqr
         qxtX/Xikhdo0oz3JRLDqrPc/acbie58uTwB4WsfOGHnWB/ytF1OEl7TPH2kJI0nXt05v
         ZTFmKTm/dlNSHFMHMxzo4dXT0wPPGM5ytC3TiuPgOvv3YWvSzx1HLIF7lvoAF5lUvjGA
         Bhrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759221224; x=1759826024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vXn/VU4YAN6W1iwCLyBOKSLicazPAZUoPkXI+ov7O6U=;
        b=rb/zPxgaDaAD/FCC3WmYUOtq12K0YaEzIpMYsvUscYliZ6rzx7AG1YFZhpdHSRjJd1
         8CoW38HS0xZW//iz4kQcQaY9HKRcfRtTz/M2vMm1dlb914iESYbAxp283ZhBzQkR4wxh
         ft+MjiAYdxCK4e5v6FtJSXcpbif2+qWJVmVpmp0RB+7GPXU/qi6yyNon+NERFlaMAzJi
         73qxenT3rrA06fTeiCVttShAUtMt5isCoWdj4+zZjoEgHuy8WuHxDbKRYrwnegem3tRN
         geRwTz79Ogp9QvYfg2i1943ezwjgRUJE5Rq29zB5v1/XOQ3ZAAi2N54nqUD2IjLFxSwu
         ViIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXaPgKvAZWXoQ3CNahgc2nCVAHr7N2txf7JovYVOZjucqoQsFheYNc5DNsra96/H0FnlL8ITw==@lfdr.de
X-Gm-Message-State: AOJu0YxApWdN1XVDsHbxqTcMkV3IBYMrKJmTI7KG6c2HFhvdiFJ5xZa9
	9LBC9l10ryRrG9Euo5NPQmLOg3vmHR9e3fncpupoo6RwEkfyJe+d5dmO
X-Google-Smtp-Source: AGHT+IHLyqhitRn/RrktioTjS8hkfuzv+6ypcrauwGGs3rE0s3AQog+o0SaD+9j94BXhf3g44+DKqA==
X-Received: by 2002:a05:622a:289:b0:4cf:bbf8:da68 with SMTP id d75a77b69052e-4da4c591c05mr262399211cf.52.1759221224301;
        Tue, 30 Sep 2025 01:33:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd72LsvfRvc27qi1XOy0PLI1hW+EWDaXL2/W/qnOm+v0Xw=="
Received: by 2002:a05:622a:578b:b0:4d6:c3a2:e1c6 with SMTP id
 d75a77b69052e-4da7ee4ee3els95990711cf.2.-pod-prod-02-us; Tue, 30 Sep 2025
 01:33:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHXricCPCHP33+QDqmvrXpzcT3p6a6JzkKaiLKFF/riSyJKjZ86z7meiALOhz+vzr+H9FDf/9pWkQ=@googlegroups.com
X-Received: by 2002:a05:620a:3182:b0:856:60d8:3688 with SMTP id af79cd13be357-85ae69af937mr2826367785a.47.1759221223438;
        Tue, 30 Sep 2025 01:33:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759221223; cv=none;
        d=google.com; s=arc-20240605;
        b=JDJQWWvwOZuqLgVenej5rQaLlde616VEnv6buSSqr5myxhZTAev0+SujMQwAK2PjhG
         Y1ugNdKKV0si+RlvEHgJCzHqLTfYvXcKvVToZI7nMjp/I6AY14QuOulddPN4D7XEwFxZ
         mDS9WA6k+HVTYU97nzXEtt8Lut3fSfc6EZ5VBS0gvORXXUs8iUM+qHFPjmUfUf0au1pk
         xUel5efmK+SK6x2ICugw1QaU/a6EJenfRrNLmy7yclHmOOYjdTFQ8gniduHEj2jkv1Ig
         ZBGym8eVq1t8ksmGmsNgOxj32CPoDADpKAbdK5R34H1dOExORyk6WlHOKTRJSPYN6UjB
         fzFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=bBOPU6N+QlAarzu9LlqnD6xE/6f1CWCmb96507SlQ5Q=;
        fh=qRgw4ecL5OVxBjd+fVOZdLs0ed0/QaUGoxcNEV0ngPw=;
        b=SenNk5/QcNqfc9vdgjZn2PQnrt+W2hHZ+SaEATHu27CBiVE0bTl3m9c2CkZ7srhAMx
         erWNjLUyZ8f/oVJdXW1gjReHbuu5Epp+JCY4gMtLph+xWgMssznfKDI8l79zkbBWCkK3
         +OZ9smxm8nGdXWQ/vJDz6E/ZaSr2wq0ZXqCVw5map9vSu/bVBvO26mg2/hNjIyMX6D2j
         MAeQuWz65nKpgjUXRtABgBt+GuxfmIPFUJyyuPPt+ZYYtPy61RL8ofEMqCXHVABWi28Y
         M4Rw2iiBGKRag65lI9CgMRNahkM8rK3eIGjtlydQTMQn+PVgvYngJtHQfvMKtF5MQCTZ
         a6iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A/mfWfCS";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85c2c903fffsi58346385a.3.2025.09.30.01.33.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Sep 2025 01:33:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-73b4e3d0756so70011957b3.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Sep 2025 01:33:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbIiIDDBaIXqEbmgIBbDAZDdTXL1m6BwA4bE07PYc5Zf31zDo/bCO1sWVdfnJ/ImcEE/+yijhYwdI=@googlegroups.com
X-Gm-Gg: ASbGncukWc8CnLzTWXrKgDIyDdKcDiRxuauKhzKXRGv1P+easq7v4ZECPzZNdOB1ai3
	y0BsdlXrw0/D9mhQjJL8EMdW53Y7ozSxrh0NXrO8/DTf4Gms4rlCl7wWK11hu+/aRwht/EPFBKp
	A5M2Hsm4xvvGiltze2YuKvrQLWC4ZPCocHt104XZ7ehYrKRMEq5H6/Rgq9a4QksAEHXU7wsqn5K
	u+0/DxZyBKG1rhDs93fotALNXFpJviUdxgMjTRqz25r6oe/dU6zS7lcfNZP43ExGV1tZoOukhhS
	chth3eredWb9/FS1cSDCeGTn15BmF17Tin1gxkLZpz9a0IDDYDfRJcvfwG9fby+EzMjh7Evtquh
	FmfRtYbkBoDo9gpF//iVHxV8iwyIyGpYUIM1CMKZWOpjrmJ/G4AesTJc4JhPObcmdB0Qy
X-Received: by 2002:a53:d015:0:b0:635:4ecf:bdd1 with SMTP id 956f58d0204a3-6361a8d4824mr21581008d50.51.1759221222864;
        Tue, 30 Sep 2025 01:33:42 -0700 (PDT)
Received: from [127.0.0.1] ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 956f58d0204a3-636d5b1d875sm3280311d50.10.2025.09.30.01.33.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Sep 2025 01:33:42 -0700 (PDT)
Message-ID: <7530d25c-f4ef-40bc-9ac8-40de4abe3960@gmail.com>
Date: Tue, 30 Sep 2025 16:33:14 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 21/23] tools/ksw: add test script
To: David Hildenbrand <david@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 Alexander Potapenko <glider@google.com>, Randy Dunlap
 <rdunlap@infradead.org>, Marco Elver <elver@google.com>,
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
 <20250930024402.1043776-22-wangjinchao600@gmail.com>
 <3ed8a6a5-9983-4b9e-bae1-4c433568de16@redhat.com>
Content-Language: en-CA
From: Jinchao Wang <wangjinchao600@gmail.com>
In-Reply-To: <3ed8a6a5-9983-4b9e-bae1-4c433568de16@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="A/mfWfCS";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On 9/30/25 14:49, David Hildenbrand wrote:
> On 30.09.25 04:43, Jinchao Wang wrote:
>> Provide a shell script to trigger test cases.
>>
>> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
>> ---
> 
> Do you think there could be a way to convert this into an automated 
> selftests, living in tool/testing/selftests/TBD ?
> 
kstackwatch_test includes 6 cases. Because KStackWatch is aimed at
debugging stack corruption, several of the cases intentionally trigger
kernel panic. kselftest is designed for tests that exit cleanly with a
status code, so these panic cases do not map well to it.

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7530d25c-f4ef-40bc-9ac8-40de4abe3960%40gmail.com.
