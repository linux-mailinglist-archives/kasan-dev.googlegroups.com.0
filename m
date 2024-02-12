Return-Path: <kasan-dev+bncBCF5XGNWYQBRBYVQVKXAMGQEVK7CV3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 85AE185212B
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:14:59 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-219209cc714sf187305fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:14:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776098; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZmoIXnpKyqa0OLLYr6Nd3fgs3034GKx4hvZpLKs6L2I0zWUHIOZa/kywOthi18Ld1
         iLbXhyexxR8u/YmGCCH3Jwjay8Ee03Eqqm2w8ryGmy4FOytQI/LCxgKzGXHLtr3uZPnn
         LKMF7TZfMr1p6dTQujf9ch1Ocy/EuDmjlkkzqSNYunDtLJoq5xqKnLgRCcPq8f2vk0n2
         GAGmww9Gf1hBmBTrdbUKT/FTENxJ8PqYOsPVAKcnB41G0ufoxYhIv8mCPBDI0kM5iByt
         JsQXxMWMxJrjH3BBRHp08XbGUDV/Cn6dshvf/bP+Tipo6IIgj5N+cSBioDtbOtoMCzSB
         Pt7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Y0zZFdE2enzgqHbFlldsSaujCkYZmJgQ9/WYvnH1pS4=;
        fh=s9ZhWqwDPipjW+Qq7P4B9MMgfIY0Zz4GjDQSEwvD9TM=;
        b=tWV1kOhXlTbkfxE49vh6d3ZNGcRafyppacDLmMNgcEioRwMr4iRemBv2luVq0sl5U7
         AtmLWV6zD5UM12vE16ezAZ2E/eo3aDk5X4Nilj4DOawY8slHir39QTOC7ivbHAkexqj1
         oRS8z4DiNk0haCqfUw+4Zx91ulg49huqH4zUYgfi6BP/PnDkxayzUB0aI87rbW8AyPP/
         MfkVlP2O3uJA5kJA9VnMO0NkGYVYz7bO9FLXaEhBmNIPzOCac5Uw2SI9SqYGIG3hSU6m
         nc7iC3mpxRpJL8CIgk3GnoQDZX2A2tt+ZPb/ShL9TuHW1s8mzdYb+KSILYyRF2BW6LT6
         CXSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TDcLWkZc;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776098; x=1708380898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y0zZFdE2enzgqHbFlldsSaujCkYZmJgQ9/WYvnH1pS4=;
        b=ZhNMoLjqFejro/ZZMTMFe+GxnxH38xzdno0czQrT40qVCrls3FUd6kY1fmkMaXGe9z
         fkJtVWRQRRJKbQV8xSi9seDyVLyqu2KRPvLIDobpaYFrPLcx2Gc6z+tdsDJq9AJGH5Ed
         vMWmpXlK/lqrRWcr9PkKu9F4nnI7Fa7HZ+RkgWszs73xQC2zJRkUyd20Lp9Eb/FcfIMO
         VbxGcpeefr4qwfmN9W9uXgo7zO23etQt+ByAxwjypV0hByGiCTzgb2mC7EC6NWGZDAR+
         bnO0j26zBMDZORYKVaE0RDrO6DJa5G29LZjZWJUjdoO1xAALhcNFZK9ZFROChXJ9LxMt
         3Ofw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776098; x=1708380898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y0zZFdE2enzgqHbFlldsSaujCkYZmJgQ9/WYvnH1pS4=;
        b=JmQbF/5U/cbriwkZWT3hFHr5PYMJke8+7L28f00bmtURrKBu/AGWEv3PbP33h5i2wp
         BNduqXnlv1DJEfSkyu7Nl5WZBCaTD6IvljD3suT8kF3Y0OJiDD57PXvY3c1uXCGzNMxA
         oTtRe9FjxUQ/C1i1eGI8PjrdybXdrg2k0kOcvwy3xKCOcFE2WbnlhKgiyBvHVty4s9ZM
         qzSl0A2q/k2BC/3iBVtbol8dFVIM34g5AComqfF69aXIwnYEtwl48ls38agTtDdfcGvZ
         4Dl3uZ/cSvaF/d9zQPkuvPAXRnXPJBmnC1Kivx8axg5mrIMrfwMK/R/UKgOEUXqIRUG9
         SPmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6ioZd/VneHa03avaOmjCm+mTjSCRw1Qv/JDl588cExSRom0w50rpD8VeeGMwkAVh1MPuxUHMzLVkFiZC0ANeiP1NEO77LDg==
X-Gm-Message-State: AOJu0YxcgeY30Fn7UmrIHfSwaowpIvPR1UqKUj74g5UW704hjV9g8JET
	pHyCNjpcXaDTC71o+q9MuCmhN3lINSW2sII7mpct+Tk7RsBGefvB
X-Google-Smtp-Source: AGHT+IG0YyQpmeYwon1hfJhKhLZlB/NbuqXXSoc5113q/UT2PKj2/JYgFU9ii1k3Uy6GoS9JDgFhrw==
X-Received: by 2002:a05:6871:150:b0:21a:252c:1930 with SMTP id z16-20020a056871015000b0021a252c1930mr9610236oab.3.1707776098306;
        Mon, 12 Feb 2024 14:14:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6586:b0:219:d5ab:fb3d with SMTP id
 fp6-20020a056870658600b00219d5abfb3dls1051941oab.1.-pod-prod-02-us; Mon, 12
 Feb 2024 14:14:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU02I8GIKJlDVBRWfAApe1Pj6LO0hoBXE9axqrHtLYln7SzOzJxABfPBBh5vpTS49V9ehtyRApaTdMJdKIf3BkQNP3A59BToIA36Q==
X-Received: by 2002:a05:6870:15d5:b0:218:f761:91b7 with SMTP id k21-20020a05687015d500b00218f76191b7mr8930728oad.56.1707776097646;
        Mon, 12 Feb 2024 14:14:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776097; cv=none;
        d=google.com; s=arc-20160816;
        b=m+M4ZY6KcN3ZcohfSb4DTEB51+894xcjqyLIDZkgEGaMK0qzd+rxhvuqTL3diuB8sb
         4u/jRruKjf6id9STFD9WTY4djZynxVUJRC2NYqtNFYffaW+mVQrK1c/YUg5DJ13W+E50
         TnzFCeLcIWq0xc4X+mle24BXaeeb0tZ2Bb2u3Ms5WRoXwiGoNawbeeYtoqv+n7UPz/DB
         TTRrfZZjiVRtXR1LP7kxoyC2oP7t8xe3i2nVMGxj0GXgDVXnS4BCyao1hurBkQ/m8xbW
         Sm/5Bd6gHRGT0m/rdF+43exBQU7Fc3BBz8RgMhpkLK93OFRgIWLceKTwH0DtpMcttOq7
         pkrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=njQYW+8QUhLVezZTq33SQ25bt0JrLVgtIWx4ItZ5PfU=;
        fh=hn33wHJKe7OCpv51gSLPxZSom5K6RuGusMj+h222uZM=;
        b=R1xyENz0VxZ0slrTww+U7SLHluPVVnz/KZzBIVU/XJLRl3x9RtHqNjnXynKsWbgnvx
         VoJPpQrWIhuVe39ggR29Vp7iIbHeD3OYJKU5m3nu3JYT5BqHpU6kzwGFtOSATF1ATE/1
         3S8V/Qn2czYPB9GGsP1syxDZ8W8UeMygaXzIDRPE4jPyMgHvesipb8kUvhXQLXyGJ5MO
         rErW+Mm2Z0mNz/6UTCsE+C2Isw0rWyFcGS6PF6oQkZPCVztOXyKgVyYMTZhm9GInWd4u
         QlKyE03EnGFglq+PnMzCuHmap00nzDtRwiVekYfqA2NxeAZten5cjfdsVom8zD568PB7
         Hssw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TDcLWkZc;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXKfeCVPNYNgBxtk9/IbMCMnFkxaGpOaySmwf4dL556OIuVT3ustE7k9cQbpYw7AIEWFAYd42d0XrvD7b3Qql1yQctMbj93yiAf4Q==
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id wk6-20020a056871a7c600b00219763912bfsi639598oab.1.2024.02.12.14.14.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:14:57 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-6e0ee8e9921so267322b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:14:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWqxN4kiQXw/2eWcZKUfQCU2Tn91yIBvLqErfcti7tVRyDpZx9M3WQT4I7yxC3AR3nzoRBHqTSy4pnqtGMBqzAV1RDSF/Pe7QhGaA==
X-Received: by 2002:a05:6a21:8cc9:b0:19e:ca6a:118e with SMTP id ta9-20020a056a218cc900b0019eca6a118emr5263441pzb.36.1707776096922;
        Mon, 12 Feb 2024 14:14:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUY5Ox73rc0sdliH4AyPx+AO/QnJZhTbOXGRt+eh/8rkGNCB0uassog2C487+Q7i/M3CgYvHsrW20L6lv5QOYAcMeMVfQnMTPm2efNpFJKFjOjIWjnCadbQlQnI2R9pK58VbN/I9uD9TtNIkISFD1y4DW0YejMZAddnTn+kBQjrge8kvXTPnGFSQT9VJB1XH/rFe5i1KsRxlgKq0iZ45gPI6pYj/+mN/N+TF/Dm4qDqDaqZ235vLgKXtOVs8dUDVTtXN/hZJ8cGUJo16n9o+kimRR2PcPr3Ay2/D7WhQwSGkxlUjgh3I9rVqEIUXJ+qM+8HH7eUszQvxivAeBH6amV5PUn7i70F0vSGit3wCSge8Ihvco895EcbBDJuO6u/PozFBTImgriJgnSyp8isbUDEpPVNBqkKc5H/T9YEm2xw+QpqQRBLaPPH2yTx254qoJEXzVrfucKBam75GPgc4eWVZXRBm2h/wzRIpLy1DNzSj75xCfG7ISpUkSpaCt4IcR5g4hzCKqKKTtI48QllK7td8ypw8LNHwZzpoKVtrlFV8E9ktYL/ibmGy6iMIXh6vriRq84g8pUsIjxMOs0LmP1K6w8jxx4RHtsXwMee/JwRHHM3NUbK8dhmA4BA3psq69I846V5S5Q7EZSbYH/wd4etKZhIEKHXoNKlAiAP3ACDF21BJMHB0nhqi8p/DPPYHChLeEq6LEPgc8iTeARl/eP/cEfj6KCMyVyY9qlnBDgH4gntbB06fRkaEgTEMnkY5ns+7aNBtkorBTpWdoq683PLOe0QR5WZHPN5A+LMcAcU5oW+MfvCdDekkBRQELPEPbcLGMFsjMj+iPMkCdMFagcVo/R6omrxl/E96fgFsO6blpaouyp9aEeR/2vj5EHnMcKdfuly4pmSqMkQTuObAy0IJliOBpmI+jDk1sDmsmJKNBJ0mtZVoEgq7KcYNSSuJ7RN1b
 OT5IU7RslPr6TYpcDcE3j2S5/ZtqiRKJylyy8PaAA80KPwLWAWkRIDdvmNlRAdFCO5Rb56bkl3blqWAak2UXkpu2VIbSh10oylBPvwjgHaIC3t3bVRVinHRyf3X3KBqpnHDIMmhIz+nMKAPnMcOXV13KqYEgSJL3pq5mC9uVmeArKYsmAIl6JnwUlZ2a2AAaee/cfuoSagBNssFOP3cW6LgJUlta002J4I0KfvmWoLylFZ4ZwgiyZEHjQ8tYSeugs16pC0wK/vFcNSNdbYtTf1/jXOTNh1t8pwsD+JPXNOndg/PfBfBwxKjv5QH5l+AXY625jH51yjkORyRKFWQDexTT7InE3jb2IUsMI0Ho4IiSsUyb0ruGmDR5hH1qVvu201S3obIjwnW5/FEgra3D49M1CQ1qheKsVm0zu3fx8Bro2XVPRL8fdq6IL2Alg=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id lm17-20020a056a003c9100b006e080d792acsm5916707pfb.184.2024.02.12.14.14.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:14:56 -0800 (PST)
Date: Mon, 12 Feb 2024 14:14:55 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
Message-ID: <202402121414.57F185ACC3@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-8-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-8-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=TDcLWkZc;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:53PM -0800, Suren Baghdasaryan wrote:
> Slab extension objects can't be allocated before slab infrastructure is
> initialized. Some caches, like kmem_cache and kmem_cache_node, are created
> before slab infrastructure is initialized. Objects from these caches can't
> have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
> caches and avoid creating extensions for objects allocated from these
> slabs.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121414.57F185ACC3%40keescook.
