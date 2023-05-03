Return-Path: <kasan-dev+bncBCB5ZLWIQIBRB3W5ZKRAMGQEXZQKH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB0F6F5EB3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:58:56 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-63f17b06d3fsf3365803b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:58:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683140335; cv=pass;
        d=google.com; s=arc-20160816;
        b=qZizeM5KvYPkWQO6Zfmmjhn67LjnIkLNdE2uyyNdxXzzs6XJ5TyhNtBVhvrM59VT8H
         qRckbIUydqWy6DSPklOn8WhXXMuwf4xJVle7Bk3zhSpWPaEIFyrIRhZtJkXMOi6ayYc9
         vVCrx5srQVx2P8EBlinovqxMnieChM9XjBa9c4U6NSmFpkaf20AiPdNV0pDg9yqF5EY/
         mZ8cTOyHm7PvEIOm8NTh5qCaK7T+79zQz81ZS7bdq8JZ0806JddnAhgdFrSo/xTCvXlN
         2wmqQ7nTlIdTyw3EK3u7mRrLSCkhnNnQEwhilze6/1QQDjopH3yiRAGKJQLMb9cYUeHx
         DCqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lc60D23TruEqR7nfBURuvTcaNdryHnbEEhjDpedWXSs=;
        b=cQCEvZy7mZXK+3j8J5jH7bDf+bv6F+dxPelSqBFtboWLAjKZ69YSxZu1/Rqf5dP3eZ
         bSfD2teDJau/B6+1KWZ/LUI5OfLouimec7XBJvbtaykkOxLB+QHUeogfvqyKkvIfG883
         HDmgW0r2r4P13oRlfG9cX8Y4m47KOU4459CDjFWmfkeyh5JvGl/Fr6XdK71DNqsRbxuD
         djZEe0WIbaSCzs7ewothrOqKKIu74QehrMQauSvXwWH9/XO44zkgJ6hiSRu2GxfvSz+r
         0vSg2ccTH5GmXhEOiJW0Uo2FxuhtZ32FgUmZemOU85jKuAahZgHQmFUB5BvfK8mC1xfx
         jt2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=AAvxk54Y;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683140335; x=1685732335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lc60D23TruEqR7nfBURuvTcaNdryHnbEEhjDpedWXSs=;
        b=pPigxFiZJe4eq+WIYrvPkCmsAC6TxBFUBvbt/JJRrzCxvYHJvq1YkwTkB4uUHq0pcl
         1Q2g3Ni33qemQ9BQ429DlKElgAsBdhb8tzz6yzB59s5/0JF2vIHwgyyO1JQ+XK+71hlt
         zxrH/OaafH6v84CFcPVmKheu98/Z1+M+SvQ2fVjF/Y49jiorW5Zizw10ivgEs2Y13q9F
         2u9kO+zBgP3FzAxx8P2w8penmVGyedPcQXTOZB9A4tnYYB5QOK2MCiQYlJVoZgb7vS+f
         9SFlnh+0dKbCdvi9P84BJz6cwtVvVu0ZL2SnRKPReNQmuc72uJy0V/Ia3sVzqFSQc+kT
         rMoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683140335; x=1685732335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lc60D23TruEqR7nfBURuvTcaNdryHnbEEhjDpedWXSs=;
        b=Q2WAHKJSW0rsmWZdvxiY1dT137Ga71YV+DhDoWd283xQFbU6wFXC/FXP6wtgdxJDS6
         fAfgypGN/umyNfUYQrCg77FqL6RKXd8etGY13JsrX7KhQJ8Rhy4/AtonU2ZAQIgnHqUf
         ipT/5YQprQ7X5+PUOaBkLtcA2FO3rJKsf1ZuG3OyyD1FSn+EIVu6IidA6zubNkbUGf4T
         X97m0FZ8X50Hj11hOUrYDfqlOROMhaeb1DSLtsHJ3qFNbK5+ocdjVs7LACCAAuqm2iBf
         WGqU78HqkFkZN9ubty7lduWBSWRWHZCfq7zwlfiGMrjzJzChHTubrSVFsiqTR+D6tq7P
         bzPw==
X-Gm-Message-State: AC+VfDypsvIwfJbfjGimjC974pRniuKBMZ96Y8isESRjdMcQguHjb7JY
	OTYW9rurJlsyiROwYet/9GA=
X-Google-Smtp-Source: ACHHUZ76QdiqkCam+vGklXDvM2OlZlkYVaoSiwxPSfY4k7jq2cUMvJ6J8/APUrIds7ktNeMR9pqRxQ==
X-Received: by 2002:a05:6a00:3207:b0:643:599b:4db9 with SMTP id bm7-20020a056a00320700b00643599b4db9mr400840pfb.0.1683140335103;
        Wed, 03 May 2023 11:58:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:74e:b0:1ab:90:b443 with SMTP id kl14-20020a170903074e00b001ab0090b443ls428578plb.0.-pod-prod-00-us;
 Wed, 03 May 2023 11:58:54 -0700 (PDT)
X-Received: by 2002:a17:903:2289:b0:1a9:7dc2:9427 with SMTP id b9-20020a170903228900b001a97dc29427mr1203057plh.21.1683140334042;
        Wed, 03 May 2023 11:58:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683140334; cv=none;
        d=google.com; s=arc-20160816;
        b=ptlkpAylIzZTJ7fFN6smJjXX7wEqrhuKtF8jK8aQUC8gR7Hr/+3pn5bLOQDsSS6s0L
         T5MZOFO8q9XUT2sKR3oZmpB6ZD/IUYTdKjDtVNXSHs2LAXS5AkC3SCaazHH+1DLKjIur
         9pDNCxVrVDNtS72bwI6IcCr7vLomB7l58g8YruhUtcSyXZY5NglwufFMaZTNDjWAwORj
         BUBEhxJTsZNf+kL0DSWZAUUKZ33z76ZOsEMgbwHPN6vR9ruI6056Sr7lLyJ9cYQX8lTD
         SYV6Qb+l21S69fSOsyvlyPGBLz1+eIncnyZoq2uv3R91L7vvCO+f5JGqueHlzoHlYMTD
         TuGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=vMlAqtjRc2HuzX77sJKufpwTYm/Gq3h8+fD7OUvgqfE=;
        b=sZN8EdCelYIL8z0Go4KuNbysScPoK1wTshxQT+j/hG0JYqApsuzyk0etOtET1jLuKg
         4td7yENiV8hutHGVnUJB8evsYzfjy20Y2L91nOwMoFZM4ncmFfKu0X6WfLqF0BjAs4tM
         v1MxGW5QvM/2xsKBcSozwKY89xlQO4Y0HI+xzxH2d7DnOCt29tlUj4/8CmH85sFYcv3W
         uw3CxUq7vxPKOI/M9cXFZf4G6PenbpdZSeoZxYHkgnvh0iN0TwSDhoscW3Sucs3a658u
         lB+uJaHreBL1IJaoq8Z0Ndlb4PeLVo3TF1RbNXjpyNjqx5jcYiOEmwSFcMKTbvC1ZDG4
         KVIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=AAvxk54Y;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id l11-20020a170902f68b00b001ab132cdbbcsi221244plg.12.2023.05.03.11.58.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:58:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-64115eef620so7164047b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:58:54 -0700 (PDT)
X-Received: by 2002:a17:903:2345:b0:1a9:6a10:70e9 with SMTP id c5-20020a170903234500b001a96a1070e9mr878641plh.33.1683140333441;
        Wed, 03 May 2023 11:58:53 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id 11-20020a170902e9cb00b001aaf92130afsm5726253plk.116.2023.05.03.11.58.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:58:53 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 08:58:51 -1000
From: Tejun Heo <tj@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKu6zWA00AzArMF@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKubD/lq7oB4svV@moria.home.lan>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=AAvxk54Y;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::432 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 03, 2023 at 02:56:44PM -0400, Kent Overstreet wrote:
> On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > > Yeah, easy / default visibility argument does make sense to me.
> > 
> > So, a bit of addition here. If this is the thrust, the debugfs part seems
> > rather redundant, right? That's trivially obtainable with tracing / bpf and
> > in a more flexible and performant manner. Also, are we happy with recording
> > just single depth for persistent tracking?
> 
> Not sure what you're envisioning?
> 
> I'd consider the debugfs interface pretty integral; it's much more
> discoverable for users, and it's hardly any code out of the whole
> patchset.

You can do the same thing with a bpftrace one liner tho. That's rather
difficult to beat.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKu6zWA00AzArMF%40slm.duckdns.org.
