Return-Path: <kasan-dev+bncBCS2NBWRUIFBBCPAYWRAMGQE4SNYZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 498D66F4B2F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 22:18:18 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-2f446161e5asf2610161f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 13:18:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683058698; cv=pass;
        d=google.com; s=arc-20160816;
        b=nRZMRCKVR6R+CszGOQZnRW18B8+JaICIZFSwjqgN6cdFc4yPLprScQ/p0mjJRdcQbU
         NgMG1+aiTORM7KU8r4/91Z8CC8INCretB9z2Ho4t8QX5A0o/Vp8nAy5w5YxKqm3CDWEl
         EmXaUOf/Fl5s+IlFI4SHR/hNsMRj4F/7cnLWTdPw9doAp7F/aBdIqEf+BK24i0czmqlt
         CPb/5DWQ6P9WUlnJ/yIfkXb7P52xidNey4pZw5DNm8JD8CYLThlWHQyJcoZpRPtqisHn
         aoQfy3EB1s9outsBY3ywHPsiGBrEuz7+5H0FfbVBO7RITdPPQOwyoU0TlrGL4xIMqFhl
         KeHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=VjDEPee1w0BeBBQjJHgCtda5chJQ/OIQtNhnEjvoof0=;
        b=rNrLJOS+qfWfM7Y5O8YhnUGr8eiLx3SEgG2JXfCxGyiV1Fhw2AndFmzH44iidDvhi7
         QXa6jg4TiOeYV5x0C/cltma3XatXBXGoohGXtPxPwhFaEZXoNqIqVv3+JwBoZ1MKSANT
         mlqWEte/gUQ8+5MfesDxFIjOreaWBX7YJtkVJRBSvMnUfSWqRwScaIiiSbLkMphGampo
         H1knZukw8zy+5pJhbHBkW1EADbeH4kQkDxg1ZoTK6nqsHaIxBiiM6/86YQEvoE/2Sw93
         OSkNQ+V6os2UI8IpeEV4x+5cwjwG8z8g/ziiLZyKq+zPPJF73jVFPx+jotlMJ7GuNuWw
         AMHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hgtKk0Mn;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683058698; x=1685650698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VjDEPee1w0BeBBQjJHgCtda5chJQ/OIQtNhnEjvoof0=;
        b=YAVFhJGCmHzjm5TXdwuU66DWcJcZ4YFdj179CD2Yb1IqIxuerHKEf8ttDKh4WSDwAV
         OkNxlFNLNzEawExCX/pkUTrdmWg1nZ75ZnzMNpkL97lIxYLMtTCnJHVpYEfwLvD86LiR
         aWjDh311q700GO+2tr1GhPY9XAvLIxk05jsVqAOpnwpPjSP00RieY2YyO9looFUqSQ5M
         CK02+qqXCVMwIrbbIP9cphtZDvOcpyu+pU8EK1gvZLWqWx5Nx79JfWVUG83YYUI3kPPU
         j0bwWIt8/mR/qQ7+cbjKM7ZN/m9adfXfiL47x3wlmgS2JDruVBm73qAu6xUcjkAWW+p/
         H+CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683058698; x=1685650698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VjDEPee1w0BeBBQjJHgCtda5chJQ/OIQtNhnEjvoof0=;
        b=f9RJCTuXeO0NG5DGoX9d2DgzQPi/yM3IOMtxY5/+8bLK9tTrvaNCrOD3gS6nt/Lssz
         c8dON82EOlod79Pmq8MmbhTIMLvDx0Pw0ayHHmKhsR+fk32X7fS/yZRmxmmnc0dQCsJ4
         6dDfOVBxJMTNRmBytnf3oRE2ktUZrnT1edNN8cgeIYvm4nk0X0TVPd8Ls8QKNarT3qXa
         eDEGKEgYr/qwlnxRMhgBuiBnQItkgHIMVcK3SdKmNSK84hva2Z0SO8DAqCvL+CNav+uy
         5VKl8OyyPNBG4+gcUNHqOGvpLow6DVYcLiyp9IlPYe6+qgzqTZblC+qNeotHhVwoJoiO
         yYeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz5cBGVAfpLgjS7gpB4hVz7p8GZy5OQFXPshmq55V7pCPlnqpU5
	En05a7QX+MMEiS1qTOl3nmA=
X-Google-Smtp-Source: ACHHUZ6ho6w2XmCyy+jAl/KshIfLs9jPeBBt+XQ44/dcH24y/Dn0895muoAwcA2WzxQ9NRcVqLRRug==
X-Received: by 2002:a5d:6dc8:0:b0:304:7219:a5c9 with SMTP id d8-20020a5d6dc8000000b003047219a5c9mr2979393wrz.12.1683058697816;
        Tue, 02 May 2023 13:18:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f717:0:b0:3f1:7596:66be with SMTP id v23-20020a1cf717000000b003f1759666bels7240491wmh.3.-pod-control-gmail;
 Tue, 02 May 2023 13:18:16 -0700 (PDT)
X-Received: by 2002:a7b:c5d9:0:b0:3f1:7278:66e0 with SMTP id n25-20020a7bc5d9000000b003f1727866e0mr13436504wmk.30.1683058696597;
        Tue, 02 May 2023 13:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683058696; cv=none;
        d=google.com; s=arc-20160816;
        b=U60W66cfs4NyXERVQ6/F3RaALKHqIAu22B2RcwQ61foodV0z4t1K4kHmCDcz4vGSP8
         3PT9wRo/Xo5w5hjU6SPFQYF05HHQTYVNZxXNlGT94PlJEv6kkz9AcMPLsT/6v8aUDJI8
         Yx71enIqRfD/4YKbT4W3FAWWoOUdldEwQTaSZjyVXQYH1/pu0jSHzrNJy/C1Ie0g1il7
         VCLw2AYTZ4yrlePFulTqrXmlFhxLQXx5LVs0paw9yDW1qPq0QDaCshbPNpXtglqRPtKI
         FCNhgj/9JNyKVKJFcu28fzSI63ySKK0kMTsalBMuS/52JW3NvSb3EPOWL3NJvqzMR29K
         qAMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=WhFW8Rae+PmqA9NsRu2fCLYsKzvllBF+D9enxFH2HZY=;
        b=vscTxhZIolddceRAh3k2DPqj6hU4oRteK3aA6dG81sz55Qaghsibc9o1kqGUm8lKjx
         mVE9nwWg+3sAEQ1uXwSjfNkFTSofBy3DCyF7Td93uipJ/uA4653+eC8bwjeh7SlwZHKs
         Yxvdp02Z7LY62AiKfc6u4LJPBQQ8Yt86c/rcrBqoOfEiamdxCh/ktJMO/fFUGlpp4ePz
         i4EiLIX/Nd85B57OTswISQOuI9JMkSGMX5dd6//mxPbZmdSdFGPhoaN9F1YUjkzRdL26
         bpjGGzzfgOc1vxaeHlJP+uX0BxLyHKZap18qmtdHLUfWdfFflme1HQUu0LN2wX0BLbl+
         MeWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hgtKk0Mn;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-9.mta1.migadu.com (out-9.mta1.migadu.com. [95.215.58.9])
        by gmr-mx.google.com with ESMTPS id c17-20020a05600c0a5100b003f17618a207si855080wmq.0.2023.05.02.13.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 13:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.9 as permitted sender) client-ip=95.215.58.9;
Date: Tue, 2 May 2023 16:18:04 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
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
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
Message-ID: <ZFFv/IDprimshC8d@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-20-surenb@google.com>
 <20230502175052.43814202@meshulam.tesarici.cz>
 <CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF=usZKwFXgTBe8g@mail.gmail.com>
 <20230502220909.3f55ae41@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230502220909.3f55ae41@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hgtKk0Mn;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.9 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, May 02, 2023 at 10:09:09PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> Ah, right, I admit I did not quite understand why this change is
> needed. However, this is exactly what I don't like about preprocessor
> macros. Each macro effectively adds a new keyword to the language.
>=20
> I believe everything can be solved with inline functions. What exactly
> does not work if you rename alloc_pages() to e.g. alloc_pages_caller()
> and then add an alloc_pages() inline function which calls
> alloc_pages_caller() with _RET_IP_ as a parameter?

Perhaps you should spend a little more time reading the patchset and
learning how the code works before commenting.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFFv/IDprimshC8d%40moria.home.lan.
