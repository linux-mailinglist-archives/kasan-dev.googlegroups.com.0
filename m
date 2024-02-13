Return-Path: <kasan-dev+bncBCF5XGNWYQBRB77PVKXAMGQEZ6AYENI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A05AD85239C
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:29:52 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6e2f56a15b0sf62130a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707784191; cv=pass;
        d=google.com; s=arc-20160816;
        b=uXUTTjh6f+sU1izC8S9zU5rmrIuMwas9LXvZ4pKJs1RpFd2pWJPYKXhiUjpAoiDhJa
         87jXPCTj/t4htyvCZdzLhAV/9kh6COnHg91vyQiBMienGy6+VuRbBbboYzWbTckivS1K
         nJShCd8Au3wC5M0dC3xh/BHCCxWBUJRGaY71YwvK95/ntduevw/ZkPGsGE9+7IxXB8JO
         v3TQ2c6u87Wlo4D6x7Imdqyd8vRMNJ4sAC08z3pYMSzJJ9QEPiG4Rzp1Cooi5yqd4emB
         SCwBopAtDDCtLMrvPxDzaQn2e01xK9KioJ0liaFuIhXLET2+B3A6Dbzy8W1g6QDVLQ03
         X2fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hkk/k+5VxAVqOmkvY27ZTCUa8li2oOQHqekWFMLBg+M=;
        fh=IOPYMQpr0i0pCBwUXiCEXKBCC+hsyRzvreBjMHFxt2M=;
        b=uk/CccFUVJsXOPal9BQQl8qq3OaiOTFyUeGJZeOV4pYRQcKxYCB+jHij/+3KRYzQSl
         Lbcxu2NXWvB/ck0alolKb71nlV5ocyMx0m63qW1Nj9z0s+sYeOFlCDquztRJzJwuGE8q
         oVTig46HnqLgSUdn0OhxmqlcdJbTX7AsK0vAZaCVUj5ZPnJjYh1uiCSqbf5QxVg9KCBu
         0tvFPtmP9BPMeYKRceIIuG8ITdMVhYiucJBOmJ6T8MLR3jJi7A6xN5AJ8SFnk9HRyBGJ
         7bWt7vaCuYh0qr3Qdkjuu3ePOIXlW1PaZ6fLcgSZITmYxruTa50DZEeirn1bHjRVPtRi
         usDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ihweytbS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707784191; x=1708388991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hkk/k+5VxAVqOmkvY27ZTCUa8li2oOQHqekWFMLBg+M=;
        b=clCZDUNtvnFUpNBCvbzTwBexgi2hUElXTWGFLplKwaEta5lYJ+Kmd/7h5ixE2ITcoS
         ztF5n+OU2S5KQMePk6LdRaLwVacFyWk816arovHrqZ66VUK9/im7DUvGRMQ/vDR7s+Gs
         lJBpfGAdoFoK8JpFdVlOlwpvphGLoRghbNg2KnQfi1kDc6rNYPLNQrKeSeFkYBtYZL3F
         RX/0JU6Hvnxj5P/Lq3uvDLbC5rgPT3huXwQB54jWEU191faiqNpUKca/0l7FA5Z1UZmS
         H4tkSMl/HV6pKJpptHgH4HUcGoD200AFmg/B2+hyGM1o+Dfjn6xxZscq+V6DdNe4B/dq
         DVbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707784191; x=1708388991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hkk/k+5VxAVqOmkvY27ZTCUa8li2oOQHqekWFMLBg+M=;
        b=JK6FgFH1sA6GF3AbjI3WhpwUCbf/s9rB6Tnpt1gvNgVTjbLVxylKSmtbbiqjSFCGAp
         2IGNySovzq/qVaLQOiMWE0qIFzJsPHwqbcSDjlcYqwOakFGyLu580gW5gI85B59sMHZz
         OPPMdGSxwYlmMEPkLdoV7Sg3mQifq6A38aIDisCFTssB8UudvVFBW9HBMzCdfzSqboUS
         XvqF/hpk3GQ8I3RBYBCrNIrAnqhmQEerBEUuCqVNmyeDhnZBbq4E52gCSkBQW51QtM62
         xx0tBzwob6yEWJ/eDrzhldaCI/zJoQyehVI6m3+10axPHrzyGB+0YlXjU4sY0x7/0C+Z
         jUpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy10cboHrJwQENa+h9skJlTUqmZGt3q+by03yQBbi9fcbJDjMme
	WqBxJcCpOxER30zI5PrVmcnRZPfKFEqWID1QmW76yBEZmUF7zhgO
X-Google-Smtp-Source: AGHT+IFHACggCXL5ze4BFLvfcA47kQClq1HWiLTpOBsnl9IdFV+7xa0iVy697K8F1IfGdmcYjPlWNA==
X-Received: by 2002:a05:6358:6f98:b0:178:ff94:f9a2 with SMTP id s24-20020a0563586f9800b00178ff94f9a2mr8634691rwn.27.1707784191343;
        Mon, 12 Feb 2024 16:29:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d91:b0:6e0:e588:64d6 with SMTP id
 z17-20020a056a001d9100b006e0e58864d6ls642037pfw.2.-pod-prod-08-us; Mon, 12
 Feb 2024 16:29:50 -0800 (PST)
X-Received: by 2002:aa7:9e07:0:b0:6e0:6c89:e308 with SMTP id y7-20020aa79e07000000b006e06c89e308mr9173471pfq.3.1707784190206;
        Mon, 12 Feb 2024 16:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707784190; cv=none;
        d=google.com; s=arc-20160816;
        b=wyoQUYjquqgjCDaa08d2JXiiSJ1d+sj5rMXEPkFAmOSXbt26sX2RS9deTphZuoVHGi
         R61ZcoB03kwokIwLfG3dnb3i7RmmZoGRrdyok9DzluoUNM+/B4Za1vtxVPgKOfLru11y
         XYKebNVWWrKwMwJhYSsrrJGYuuiPrYXydLvo582oF5+XzWabCacOL29BZRD7ngmgw1Pb
         3zqcKv1iLvR1APedsegfxB1+8PazSDmcnH+nXjlIvIcLMH6Acrldc1oBuppt/92/wTU4
         EBhxEjDSpA0WieHInZqfac/+TzgarxA8JWCX3OslD3vyIphc2lE0aatxoAROpbnZN6q2
         E0yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DKs+1yTn2Kh2ROZPp6elsN7agahGkRma180U23twrOk=;
        fh=IOPYMQpr0i0pCBwUXiCEXKBCC+hsyRzvreBjMHFxt2M=;
        b=AkRV2G4dKZmW5XZGc+53nb6SErqyrpGmH+4JkGdHFdGY7WOn9MDYlAajN+ElMyRbI/
         UmQXSyn04cR9xdhyQPdjxA1RobKSJ95RZXcdekpEYuGPvqlD6h00HJXhv2tA0jPW6pVP
         +j2CcBg16JiGCmvAC2jRdbxk/I9hd+NkcLBawWuXwbtRUX2s74PgqaxWwkygCT4x8Zwo
         8LzlJTLRne5oKNJ3e4D9Rq24C/1QWfFiKa8kpTzsetqfOVHa6oQ+5A/qv1gzKkZWAdCT
         2XUCX+hBf+dKWObpCzO9+4eni5nbDI8n0dn6jz9P6q/qBRocun8ElTXSWg2vz53K6WjV
         G2yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ihweytbS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCV7+cxYNJr+ZZNfLRY6Uw8Oyxms1fXRA5Vmtm1sQCsdK9qUzn4fe2enltmH44gbnBpK7SW/1Vng1TwywbffJYutBdvV4KpREpsFqA==
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id ey13-20020a056a0038cd00b006e03dda48f5si523010pfb.6.2024.02.12.16.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1d7354ba334so32407245ad.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:29:50 -0800 (PST)
X-Received: by 2002:a17:902:d4cd:b0:1da:237e:4754 with SMTP id o13-20020a170902d4cd00b001da237e4754mr7884371plg.8.1707784189920;
        Mon, 12 Feb 2024 16:29:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXTYspgr26zAmL6L4uhxbHpiIUY7JIcEJvHffQhjMFq0/wPHNorS8KP+UHq0XDynmIr8RjAnGUHn1U6RlalFAm27740uYO2418NakZ95TU2Ad9IeAA9Z+7Ba1Tli80eGOx858UddIns0PGZ43yfXktxWJr297mh+Okobwin+ag8nSnZnutvyvfdL/B5tTBsG1ohgqgXCohGGN6S3bgvq1P70kDLIXmQ5vZFmJZZ6RNcrA4og1o7znroFSZY7mjjjxPMwqWhiLReTzN7UE5yCC4yWT8mfsVFXhGOO56iNTa8LzPmSIoWzTvdqty9xePUIsSxOlHUXojCZeELTNRT3uUPoSNnGqSbq6EXPzeeZCPjEreXhnX45l+uWcXhObKNcrTlEEBRmb1MYAOaNYAs7UUJIdXLgEvI3wKqkVXk24hlohbYbQBq4Fd5+juhrldIIIz8dnX3Yr2/Q9iAjXAA76R+v4CMFRBP9+8EvyTyFH0btPkOBqxEKuSuh/t2GKCjue/fRUKrwsNPLOpORdnHb87v6ZhyI1FPZpXY+r4ERqmIJQiFqwDWplU6G/zg3kfpjFq9CAjue0MSARbmpbqsUUM/E83yct4tFysf7M19JMqXmHGgWoMbyiija1rVYP1LnkFZHTTwumdtki9OMm1aH4V2uvM9vyrKgU3tbYEUIL3ukFjvatUMbaRmtB8Kwqgu4z50i9sHnLDM30C9R1iEIyVOyckO08zwrfTTB3ZyGioW29fJQdXAfCciXb8E2sq5Cua/GQG/ZunQSHA03zIdX/FF3ri5fW4nuToOSyAoIdNx9FIKEfy8szQga/QRNEGsn3e0PvUX1e4EB7mlkJIStabla5slbRGZOH5hPtXXjThQLRh9+we8M+t1liHeL1Uq1t2ui0j9dNqwk2XuT8Ip4Qp9ZdJehrj76i79DFXE8OniGRymr5SCpntRoZr815nvYj8ePF
 LLb6pPNe8wJimg7yoQYKIqcQxdz/rtZcAqstb8yFq5+OArwu1xDGp8VqzpmjDZnL+qHUmHKUC0zHiZJ9KWQ/d4nE3hwGOtqetqPF20TXKeie7CuxBYkG7Zjbw9d6aCsgrhFTMkvxGy84Yr5OIKwjxLJx9x6phKgPUP8nTDbj+akjJ8q0X43g0oBg7p46O8sd7hkBQQuBQEJGW/Cg+ERGekM5sz4wg4I7IjpwWvMdim0bKrlW2EXIhpjXYiWhT4KaTokCEvc8l/D9WSDN+QTnWSkFAfYBnuJijZSMcCC0rrgQngu6HfJhxf22M1kYQ9n8bWGagoI+CKnFVfAZjfAgU+ODXrvBvjrctUH97FFCV7qo8WLyGJEiZuwwWzCoT1E0BlP1SqSNLrTy42ldDrEKg2xnIriPGegNtuKrOFAzuqMMipx5qbstJMm1jrBY0=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u11-20020a170903308b00b001d9a146907dsm919916plc.11.2024.02.12.16.29.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 16:29:49 -0800 (PST)
Date: Mon, 12 Feb 2024 16:29:48 -0800
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
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <202402121602.CC62228@keescook>
References: <20240212213922.783301-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ihweytbS;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633
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

On Mon, Feb 12, 2024 at 01:38:46PM -0800, Suren Baghdasaryan wrote:
> Low overhead [1] per-callsite memory allocation profiling. Not just for debug
> kernels, overhead low enough to be deployed in production.

What's the plan for things like devm_kmalloc() and similar relatively
simple wrappers? I was thinking it would be possible to reimplement at
least devm_kmalloc() with size and flags changing helper a while back:

https://lore.kernel.org/all/202309111428.6F36672F57@keescook/

I suspect it could be possible to adapt the alloc_hooks wrapper in this
series similarly:

#define alloc_hooks_prep(_do_alloc, _do_prepare, _do_finish,		\
			  ctx, size, flags)				\
({									\
	typeof(_do_alloc) _res;						\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
	ssize_t _size = (size);						\
	size_t _usable = _size;						\
	gfp_t _flags = (flags);						\
									\
	_res = _do_prepare(ctx, &_size, &_flags);			\
	if (!IS_ERR_OR_NULL(_res)					\
		_res = _do_alloc(_size, _flags);			\
	if (!IS_ERR_OR_NULL(_res)					\
		_res = _do_finish(ctx, _usable, _size, _flags, _res);	\
	_res;								\
})

#define devm_kmalloc(dev, size, flags)					\
	alloc_hooks_prep(kmalloc, devm_alloc_prep, devm_alloc_finish,	\
			 dev, size, flags)

And devm_alloc_prep() and devm_alloc_finish() adapted from the URL
above.

And _do_finish instances could be marked with __realloc_size(2)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121602.CC62228%40keescook.
