Return-Path: <kasan-dev+bncBCS5D2F7IUIP7PFUVYDBUBE3JMSD2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA168553BB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 21:11:44 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-558aafe9bf2sf102081a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 12:11:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707941504; cv=pass;
        d=google.com; s=arc-20160816;
        b=oi8iElsrGxrgAPsFUIMoG/P2JIm7EvHqe0q0KIO3nXPvA6PLuh3JRESOnymmINXrx2
         hZgxCgpL98W9neW6JqtBsrm3teAGTJbSqxF1ujO5I3QYGrSYFMnAGPUOG/NKvzuMDhrA
         6TseTvC13fCKyxQVjJ9BWmzqZ2J600ZLInk6AEntLnn6gW3+0TJTnHb6FHPd8S7RJDsj
         yqTkHMmIQYZn2cGuc9Ezh/bl/ijHHkXcwkZG2MsbbxIuyNhzkcrsnASx5bndOxt9hMOU
         MCm5VwPEvn7+5sibFE2wqTefRT7ljeEUS98lsSJT2b7mFWo2eMbJQvvfE0iLENjJCW7R
         YnXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xNLh7NdOPaNkuEyXJwJAd5MsVwpBBDfkfpXnQ/scs8Q=;
        fh=TueCXhpLvOtwl6lUr4mttyyJVmalZTwZus5Ldrygk/Y=;
        b=FpuZmYef1CWRSk0MwOFWEIEaHx5wQK+UADBW1scZ7flDujgDq2B/aJwxmq5oPR3ZXt
         dWPHlN/Pp52mv7ehGFp2n4bbJKc5tYFYOMyPEoYiaNkf0hObXrcV6nlAOIFht3BVaCRE
         LtbXHOCIj7F0h5dvgh76o+JeRGw/jtnFwgNzoj0aw6aUS7aCtHJnFiOTUP8S4WE7hX++
         gwKTu6wghBDtR/mqrqp4phB55z4CKyLwLo/g9wekqEN3SV10vdCFivM9xf5nOAWcjB6N
         rdAbLDcSV+3tu5W4Z24ZTLOJe2ql4UyqlOiqDimvpyzlyJwX4LG/6GYdQGYXj0ZOsATo
         YI5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RR1NvtO6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707941504; x=1708546304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xNLh7NdOPaNkuEyXJwJAd5MsVwpBBDfkfpXnQ/scs8Q=;
        b=YfYjBJQg9Y2jOYtz2QhOYfr4fCunMPOep567OsuqUkEo1TWq1LVF0UCFzYRV72+qAn
         j7nnS6mW9byUVypYK5FTKmYxaW4fqNmoxEo7V+/8VpFc6TP1VwGL/AsGQKPtpRG1gAd2
         wuHYebqFsE5SE7HYK4DO5FRBLGHFbdvn6uVLJxLd59cdNpBje2w6z+BrC8U4Xb+Ykden
         7zzkSsFkixlpOqPvVHrrsyB409jtPIALl2zsba7Nmt3TsmH5h3DXLGNhJZRVeV/ms8f7
         HA9rFbWWk8TlLhSIKbzt5iIxuoTcvKOQN9JwZfkMRbHGaZTbMUWp+COBuiXGtGjJuNe6
         kMgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707941504; x=1708546304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xNLh7NdOPaNkuEyXJwJAd5MsVwpBBDfkfpXnQ/scs8Q=;
        b=Rba/4BH/dzuCUpk3gcWiWJ5VCd1dluo3tYGk5NfK8+XO/hnsXn8+cMQI52Ex5peRfE
         p4MlszmBOUINIyXYyEaxw0hrhYUtN1xXERgz8z8B7OnWR4AFgDGh2NkuwKyrM4aSIb8L
         9kgT9xsgbG7IhM6h2qqxK0eTURLnoAGY3XNrWTIuG+vE35yzLn4L896T0D5fs2Pv2hV9
         bRpovvzbL5FqQ38Y4Bd979qjCMZfASMilni2/qsHV/1IMowv7YiCoVOxcWJz2cglptyM
         4or8NcZ+SmwcILnsTKacLh8TMSQoFCdSNmpeyUNpavEWwHs9VlN1KlSP5sw6EVwMk95J
         wALg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGVCRG6Ms5qwsUdPhjqgqeU00ZnGN6Hulc2/miaS4NdVAeTMl3DHdwpa7gXasoMWtnKYHD7gcA5NvAJuKiSjgWpJsW6q2MtA==
X-Gm-Message-State: AOJu0YzGn9ZWRQyQEByriUgK+TfXc9BqmJ8GNx8iFJtCNnrkfQHfzdYh
	hIhEytYtCPOuqg5Mg+l1YrBHup5s4iVjqHpbMTqFlS74AkeiITjx
X-Google-Smtp-Source: AGHT+IHZbMBkLZ5NX3YG73gXIjSFVrU43wJQJafGCWKe5AKwBSMMXQH7OC/KoGGhsWWV5hOdv7NkOg==
X-Received: by 2002:aa7:d8d7:0:b0:562:966:ba9f with SMTP id k23-20020aa7d8d7000000b005620966ba9fmr2767303eds.33.1707941503317;
        Wed, 14 Feb 2024 12:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40cf:b0:561:2701:7e00 with SMTP id
 z15-20020a05640240cf00b0056127017e00ls857336edb.0.-pod-prod-03-eu; Wed, 14
 Feb 2024 12:11:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXlU4f9gMDIfNA9S3iGFQnevTky8JzWTt9ShPwFyO9bXRf7E6bc/WQSz/7APZl4IuKVcxQPjWs3OwqAEo2nvNKE2CRqpW5VT0dfQQ==
X-Received: by 2002:a17:906:6997:b0:a3d:6f47:6bf7 with SMTP id i23-20020a170906699700b00a3d6f476bf7mr745096ejr.12.1707941501230;
        Wed, 14 Feb 2024 12:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707941501; cv=none;
        d=google.com; s=arc-20160816;
        b=VQiHho05wmjH17kZCkNCyprtiJGekcLzS2E7gv5TI0nGaKyEUAopOAeHCzaOw6so56
         Pu6nkSOA8/q++HsYEu80DxgnzSUtxUEmlzHwCW2IqHoPLpz2BbcPs6nu0xerum//mdtr
         +bbMOe3xH4Q8V6FPqCdY273GZLsmNs/DWmBrdyTPLA79s3lTIIIQXiCOGzVe/+kch5s+
         lwmSdzkRutYIHFJkzNKe/TCpNwZ9KyML8iZsCJlZBMdVIEYVloJdqSExaUeEAhDQQST+
         lP0tVBpb64hZ02WMAUHxwOCiLRBubailbWybfb1ctsFwXc2TN1uqZ7dbletmbFzqqzHE
         h2UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nzG+mcwtKVReimCU6zx6inAB8xN7+k5Rvm7slPc1wIQ=;
        fh=k6uBYMhtlQE+S8U0iNmF/Nqsv+wSeIsU/cv053GcjQA=;
        b=ZFijrKC3Imy0edWB4Fr3gqolpcwJBR991wtpfRH/opOPPEKMM8AlZewhZZQGEQBu7B
         sojCZCQKIq+cF7ucge3QFcv7oySoX+YcbwGO7Q++3TKvqQqSGus4QwmlnOLMK+xNqwsr
         +QzVdde8Ww8uN9gSbjy9kSFkGN+ZeXaD3//bV9ZP/IH8SAle9vYRvtlJHxOy33sbqvOp
         uhCv5AqDem0Esm4aaLIHoaYxsgInNto7z2Q/P/H5DYMkU5W4qoIgeAsJeIpV15ERmAWR
         FK/AqBMYev3ViJMVgceHtDt7e7UXgLV2jXWLVxxcT2c7MXnnLcuthFL/KFyQ0PNYWSaB
         ZA9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RR1NvtO6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
X-Forwarded-Encrypted: i=1; AJvYcCX+8rQ+UmF/mPBegsladbjsxa79Zk8HrOvydk1dt1+gnXG6/dF+eGEB3vljpL9P4SpkJ1eNWEDgSVOhPmU9pZV8lmLE8ypyCzABew==
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id lc25-20020a170906f91900b00a3d6acddb2bsi41470ejb.0.2024.02.14.12.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 12:11:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1raLb0-0000000HUak-0HCQ;
	Wed, 14 Feb 2024 20:11:06 +0000
Date: Wed, 14 Feb 2024 20:11:05 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?iso-8859-1?Q?Tr=F8nnes?= <noralf@tronnes.org>
Subject: Re: [PATCH v3 01/35] lib/string_helpers: Add flags param to
 string_get_size()
Message-ID: <Zc0eWURJL64C3vqn@casper.infradead.org>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-2-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=RR1NvtO6;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Mon, Feb 12, 2024 at 01:38:47PM -0800, Suren Baghdasaryan wrote:
> -	string_get_size(size, 1, STRING_UNITS_2, buf, sizeof(buf));
> +	string_get_size(size, 1, STRING_SIZE_BASE2, buf, sizeof(buf));

This patch could be a whole lot smaller if ...

> +++ b/include/linux/string_helpers.h
> @@ -17,14 +17,13 @@ static inline bool string_is_terminated(const char *s, int len)
>  	return memchr(s, '\0', len) ? true : false;
>  }
>  
> -/* Descriptions of the types of units to
> - * print in */
> -enum string_size_units {
> -	STRING_UNITS_10,	/* use powers of 10^3 (standard SI) */
> -	STRING_UNITS_2,		/* use binary powers of 2^10 */
> +enum string_size_flags {
> +	STRING_SIZE_BASE2	= (1 << 0),
> +	STRING_SIZE_NOSPACE	= (1 << 1),
> +	STRING_SIZE_NOBYTES	= (1 << 2),

you just added:

#define	STRING_UNITS_10		0
#define STRING_UNITS_2		STRING_SIZE_BASE2

and you wouldn't need to change any of the callers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zc0eWURJL64C3vqn%40casper.infradead.org.
