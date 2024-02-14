Return-Path: <kasan-dev+bncBCT4XGV33UIBBHHBWOXAMGQEL7IGE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id A09B9854F31
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 17:55:58 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d932efabe2sf5725725ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 08:55:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707929757; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZDrP+S4dG9JQnkYPNGqsdwvimDJ5QfbxLBrmVEJn1nYddVFjlt4jTrAPA6PJKtN4rl
         bRQ3Lk30m/NPSdmww0ozOtTSCk6LgEG8oTalW8Gfe0ItAaYAUs8Zv+sYZ8MVABJEufJL
         c9yzDTMjpadv/452EDA/MScZURYh8gkfwpINvPP6N44JyCQPaZyF5RpM8hwdCHaxvE9/
         HkdtqBL3u8FX7JywWApCLCSwFYy+WKAoODGhmUKxltG++YElT2EsIGty7+PjyNdMN0XH
         AuFZItKqKA323CsoG7JtoCGI5y177ykEac5Ai+rKdsnaAL2UcnK7OMVodshhXEZxKAJP
         UNHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wYIzwDbm2j8jjidjUM5oin2t/7wy+d4NZHmdLSPrEZE=;
        fh=fVJyWHYVzejPnG+vt3kano2TGS2WgBBjnxWYGwfjjRg=;
        b=QywGNb3Z7FslVA3sAFDqmCev3ZFLq1UBIrFY7eWHOWS2g4jDOJqgnFFcKSLwdEgx6B
         7Z5bqE6RApb27Lq7GsGqyNpENp+yKAk/qP+jv1q8Rct95ULw20cNteqJlDUjcprLOS6y
         95J4RnsJUDJV/N5WNdmC1VxQtn6cD+c7gM+HOcxz88XpcIbZl3w4IOxJPXAYH5vCw0le
         FRZqpuSEp+A37v6FlqC8bqzwx7hiQoekCxQJi+1jcEuMdwhx9J4Gm2fmEP/eLis6o+2D
         4RdFrCFVZ7YHnrf7Kk6i//sCSgUB5pe1Dl/tHC0gc7QFPmF89OzSOl+apsJ4XjL3oXQK
         FZ3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aP6eNqCb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707929757; x=1708534557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wYIzwDbm2j8jjidjUM5oin2t/7wy+d4NZHmdLSPrEZE=;
        b=qFO/VR9fbhlhjX93nEGhKqE7RSx6WieYvhENgY4Z+moBVXWXzpq1N1ggQNs+kAMOmh
         hti/MnmpjdMMRceMQUBdak/AXwB4xj65DibteH3xRwhMwMZLwBFLx3HeqsrvqUbSOFoX
         Qb0p1sWND4DW6aCKAKKHoNSYgS7TRWygnXjlFanSKU8UnQnDP6cPtOa0asjhN/JzbcYW
         IVN2USy1eZBPPTgLZQIYV5Q8zGo2o2eVsqidyER9xmYjOiwAGeUYarnMupueztiHiO0W
         gtisrKV2lGM9xSWFV2tT9JcwOIuwpNJS0egDXsW3aOq+T8sdZ2nRatk7FOynedXx/5ut
         SHVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707929757; x=1708534557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wYIzwDbm2j8jjidjUM5oin2t/7wy+d4NZHmdLSPrEZE=;
        b=aedCyEEaI/2MFUwLuci8B44AcE0Uucqd4LmR+T9PJkGPq/LtvwqVwQJOOz7+OKQriC
         5KgkA5GygfVCyDMkltJvw8EchNb4+VbSL0E1Y3sSJfSm44zUkFDBQzsyyWL/ywkrTAUA
         boNTudwFvwUdWvteKAhKUF9tkZfX8Pd56OcvmwZdzAnsT0rZZSP5Wu0/F6gutVRLZ0O5
         hwy1gdZoo/Xb/YTTUbPWF/eXUyNigR1poMom0B6aXEXyd6EsgTq2NxNMYP65sUneiDfB
         l7ZQO10woQv5/3i7hd/Gm1pKL3SasrzsFbWl2ne0CcHg0ch1j2fuK8k+b8aE3TPPJBhQ
         p7lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7JGSO/IR8yOJlc+haTm/Lq1+OndA0JY0InnEnigqH2py8OH/TPbQsPLPLjJ+hF3qNoHZc8FtFZ5JvePAaZU0n+PfNbFNh6Q==
X-Gm-Message-State: AOJu0Yzob3uxa6liS7cnuDzLNvTCGgdIaP3vmfZbODlim24HydXd0AyJ
	MlXzqK1TQQPgD6KcLS9O2e4+BM6URYkWrt7shvug5cRuwqndIu+y
X-Google-Smtp-Source: AGHT+IFoQ/XRqAGoa2uU8EVfFc9mIeBRGt4oas68t/gsPVk4zUEApgf0RU7l0qipCSFS39P4xnvvLw==
X-Received: by 2002:a17:902:fcc7:b0:1d9:5930:b066 with SMTP id mi7-20020a170902fcc700b001d95930b066mr300224plb.28.1707929756809;
        Wed, 14 Feb 2024 08:55:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:341:0:b0:59a:85c:a968 with SMTP id 62-20020a4a0341000000b0059a085ca968ls4912618ooi.2.-pod-prod-04-us;
 Wed, 14 Feb 2024 08:55:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCULiEnoSdJ5FiTVXBefnKXL9Qq7PXZxAxYFFm2cyWKy/I5ALl8ElFTyB2tqM3hYix8XThdd7fsKXSPSLf3lwfm7ABLGQi4b7WX+QQ==
X-Received: by 2002:a4a:351d:0:b0:59d:743e:5cf1 with SMTP id l29-20020a4a351d000000b0059d743e5cf1mr3433269ooa.1.1707929755371;
        Wed, 14 Feb 2024 08:55:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707929755; cv=none;
        d=google.com; s=arc-20160816;
        b=U6V7uUyHZWsb9I8P8nodBsmtHpeLobTrrGBYds3K+y5o+rVK7F3r09DJ934D9RQd7G
         rIHWg5cgixK+v9SRlcn1ffBBvxtNH/eRNKVlxNcU76JkLHsMVEvVOGgwY0LwVeFx0MuO
         8d92oZdZWZK9hAKEqaEWL0IAZZH2axu09LfuOSaFfzgOucGqbypwxKwg+IDZDLToRm7f
         Bdlr38w7GQz/Emg/HEYQLy6emmx4XEEuw/GIYtLaSAOnTINhZ7Jvk8tU+T918c9RBci+
         lFFwfYAiDhdA2VJyGh+wUihOSwhNRq0htEFWxqvp32yrWjEuMj4Cp1oNM8Gkk2ojX64Y
         PkTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tiTYbjQqGLnM5HLaU1m7I4ZW+k7FNgBvatNZAZim8+Q=;
        fh=PeYEELi0lrmZ8S6X7ooT7q+BZBDExcrEhJimnt0zf4E=;
        b=dJr939LI2fF5yAwTHX2UWfbQg2jlVz7sUPQjjiF7zJRh1umTTLzbXHZaDN45TM+T4Y
         dNTxBglXIcKDJS/L1eq2ATmUZJ/uwaDtdv3/1zTOtZweMZxXIF+tRupPjsiCP7OfhfEG
         6YgLAXxjGtNVEPKjg5kKo1blukoMix9CzzzxwoXfOjhCJ8cFm1ZK2EkIpm7QJt5lLmZ/
         TPwKis8gREwCiD6gVHd8kwROtcs+0L2kFg9RXcYTTtMu8upsxZ+BlXe/3jeRpU8NJBKy
         rMbiL/J34dLoMxXf3Zmjv+tMP6AZfqcXG6ff3ntrvV7kNlRanjJ41ZY+XmpBR6lFt+PQ
         kpqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aP6eNqCb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
X-Forwarded-Encrypted: i=1; AJvYcCV3sXCFKfFVF+zdfn4oy4kABU1kVjxhRjUqWQKtgKRWUzraL2dvCAiWwfIMQTLh/SfBZx1P5uKDkSx7pRwXwqfe3VP4HlUFcPCYNw==
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id eh23-20020a0568200c1700b0059cb5174063si461680oob.1.2024.02.14.08.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 08:55:55 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 5B907CE230D;
	Wed, 14 Feb 2024 16:55:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 57F71C433C7;
	Wed, 14 Feb 2024 16:55:49 +0000 (UTC)
Date: Wed, 14 Feb 2024 08:55:48 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, David Hildenbrand
 <david@redhat.com>, Michal Hocko <mhocko@suse.com>, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-Id: <20240214085548.d3608627739269459480d86e@linux-foundation.org>
In-Reply-To: <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
References: <20240212213922.783301-1-surenb@google.com>
	<Zctfa2DvmlTYSfe8@tiehlicka>
	<CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
	<9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
	<2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
	<6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
	<CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
	<adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
	<r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
	<CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=aP6eNqCb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 13 Feb 2024 14:59:11 -0800 Suren Baghdasaryan <surenb@google.com> wrote:

> > > If you think you can easily achieve what Michal requested without all that,
> > > good.
> >
> > He requested something?
> 
> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> possible until the compiler feature is developed and deployed. And it
> still would require changes to the headers, so don't think it's worth
> delaying the feature for years.

Can we please be told much more about this compiler feature? 
Description of what it is, what it does, how it will affect this kernel
feature, etc.

Who is developing it and when can we expect it to become available?

Will we be able to migrate to it without back-compatibility concerns? 
(I think "you need quite recent gcc for memory profiling" is
reasonable).



Because: if the maintainability issues which Michel describes will be
significantly addressed with the gcc support then we're kinda reviewing
the wrong patchset.  Yes, it may be a maintenance burden initially, but
at some (yet to be revealed) time in the future, this will be addressed
with the gcc support?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240214085548.d3608627739269459480d86e%40linux-foundation.org.
