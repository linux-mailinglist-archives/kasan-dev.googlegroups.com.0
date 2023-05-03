Return-Path: <kasan-dev+bncBC7OD3FKWUERBJ5ZZKRAMGQEFWWCJHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CB906F5D1E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 19:40:57 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-6434307a64bsf848272b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 10:40:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683135656; cv=pass;
        d=google.com; s=arc-20160816;
        b=TfQIrTimSMAjs3yOwOcreKvDPjrK8ISzm+IlcD/VCn0P7lN2g3WkKPytFyPfm+mEpm
         5pCUpJI4iQrmkWKP4Z8OeDKaoH47Zv/pQe4W3TeVwCGb+X0nKHE+W1sReSkEB+CFwtLD
         qbtrbHcoxbh9ngSTCKX7e+/ExRrYOu/jZyon8LShcK+x4l5CccJnCLQVaMVhZ5xC2W/n
         zntfo+W320y2LMexRE3rq9WlQveBFiCpsPfnZ/ZcjxqzryiKP6PervOCwg8gGPtHm3yA
         Ks3sBYixvSi3xH+VdR+jjUGT53oli81tWUtWEtHm0VSZIgP63A+RMpeCepIPtkXnRjD3
         mzpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GMV0kFJB8V74HLX01WAO1o12AStzN+vzHhdQa0A6DyM=;
        b=UheKgp9n8Ioe+zmFLX4yuJMD2RUoINNpWAJlAtnFY0Qvkz6UavTCyCq3SPqO3Zu+ri
         qY4a6EHsUH3YhyUSG7/WUcozaiwemUMANgt/8Vu0U+PURvxFOYCIcsUeIZqxVo4oe0E6
         waWl6XZGrH4RDToGL/1njzXRiIdX9s+oqWy6vZUMKJZGfvi2fbqBbff9FkKBtQHjlnHg
         oJU+WnmFlPCqmq+PTxOFLR3Wn8JAOgeFTs0El+oMmCwkj+/uhEeXhw8vhuJsv01sdpIM
         SNEK10uvCo3h4vfDMX3eACnWaD7xBqTtjZSZPldug8PlIKQQcyg8LwRL8BiFGzEtngFy
         M2Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eK3o90MK;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683135656; x=1685727656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GMV0kFJB8V74HLX01WAO1o12AStzN+vzHhdQa0A6DyM=;
        b=Va8oLywfxdKPpS3gJEA86QHxudwbbnUZ63tMVSPdfYMvMBDSGaEXqJU3+ky2fiZj6X
         vBDVdLbC22PfTCZSXSrEiapSinimVDEzx9Ffwz48YZ2xZPgGeDKgvO0YCVXIhsbKJPZy
         Nd/b4os1UQSIMBxnf2VwOsJhfEEEw6r4ouJFYsEPswnUhk+/w8vDw4sU6xVBlh99dbBG
         8BqecCTSEHVbHEaSsLG+LNREiiDNfyd/MH2xaBbuT8DSyeOtbKZ3WKt9caXMyHtUQYQ9
         A7npJHAgRRgxF94ief2N+u8VA2WUc/pW7e9up5VfHImh4hH1zC1QD6dLReSCbV6e+C/u
         +MXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683135656; x=1685727656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GMV0kFJB8V74HLX01WAO1o12AStzN+vzHhdQa0A6DyM=;
        b=btpbq8QdnpzghF3rmAyee3EDrrnXXsdltzOEZ9Xp4E/MTVLp2/N1sIXHQtALRtfa/X
         sx9gE3NPT72YJ4Sqv5TnD7TQW1ifBUWeAugkHlJPWO70cA14N5hX5bxZepSIkOFrN0Sr
         KaJcqVcma23Sdk3KX+45IdX+HIw+glrJ+6f7ORGMHoaH8giaN2I11manRzNM27vIAUrX
         BybhohCNiE8/bLuKFzYWcyfhcbATRbCz/Xc7G96LdMfCAn7d/RefSlLCKnV/REOFyKf2
         /uVcnvnQTYRaxZkPR2fmS3j/+fko3W5jMigq9+yLbQVc9p6XSIZlrTHODbwF+QuRuyYh
         34tA==
X-Gm-Message-State: AC+VfDwo4TSP4royuESlXujKALSF9/mOUKtiNmcragWLadR5nwGFQSTc
	qxdyJksZRIC5/AkL6HcTtzI=
X-Google-Smtp-Source: ACHHUZ4Oj5i9f0SR96PzvV+08c9aTSsGEi1YEEZLslj7k3dr5Gw8iVMqyQEDI6QJWa3OLA1HnJGpPQ==
X-Received: by 2002:a05:6a00:11d4:b0:643:7916:16df with SMTP id a20-20020a056a0011d400b00643791616dfmr23441pfu.3.1683135655981;
        Wed, 03 May 2023 10:40:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:238d:b0:634:c780:5a90 with SMTP id
 f13-20020a056a00238d00b00634c7805a90ls5838254pfc.5.-pod-prod-gmail; Wed, 03
 May 2023 10:40:55 -0700 (PDT)
X-Received: by 2002:a05:6a00:2392:b0:624:2e60:f21e with SMTP id f18-20020a056a00239200b006242e60f21emr29446671pfc.29.1683135655206;
        Wed, 03 May 2023 10:40:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683135655; cv=none;
        d=google.com; s=arc-20160816;
        b=0xKE6hqvuVL9+a8V1lkhM3slJ3pJCup4ROqA7R6IN1nY6PU03fNGZgIlmhsHuK7SQr
         1ewXiECa4z2N1rSDGGowr4BTmjBvu045gMy0FeHW0STmiHM6NhnVbWWACyUiU39+SwAJ
         uyHMVTBo3zowAJYwv09uVE7BOSFuOnUsqCmisvsh9vYdeOJSaXAsNZ9NcNN60Xzk+4/Y
         YfujVA5XL1gj7ZjWfBVpFkpW3EN+9HSHdmSAk6qgZyKRTxM1J7xM78JqzRbCl+JlRiBE
         XeD7+ZVcL7vRg8JNYFL84ggc28l1rybs7tbzQpnyYFmdotmwS0OaVQTidblbYk5+qJqF
         ULxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VnWJwoqbKS+XkHViPIVupavn1s9FL+9QLrnitzrqP5g=;
        b=sXxGHxnOeE332/XmdzfdPRPe9MiXktra2lrLrim2zWI8o+hF0/c9RovphnN24U+6qX
         1YhGQFtvY6k17ZqZrAzeepblJKU35Ue2fVyMrMU2z8PrijdH2Ajlhg0Ru5ooyRYCyQJd
         zy7XMgdfg2vPyWLKO3pp5XG4wHGIOQ2uBBVTKMe2KqfswyH1VbArkMFf64cjGQDlOj8E
         /oJ4xGWDTuRRfRSYodAzOVEuAVzI8kZEMRI9fFNJT7d/oua4Jo7WbSZUYQoj+uHsS52h
         5n+gvtXUiAzldUPrlYCfBoorSHakljdiShjM8Nx8JsStqMWNjD4YibXllnivebBX8HUw
         LFVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eK3o90MK;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id dw9-20020a056a00368900b0064364fb3b6esi40575pfb.0.2023.05.03.10.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 10:40:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-555e853d3c5so51879027b3.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 10:40:55 -0700 (PDT)
X-Received: by 2002:a25:1885:0:b0:b92:3f59:26e with SMTP id
 127-20020a251885000000b00b923f59026emr18942712yby.41.1683135654167; Wed, 03
 May 2023 10:40:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com> <20230503122839.0d9934c5@gandalf.local.home>
In-Reply-To: <20230503122839.0d9934c5@gandalf.local.home>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 10:40:42 -0700
Message-ID: <CAJuCfpFYq7CZS4y2ZiF+AJHRKwnyhmZCk_uuTwFse26DxGh-qQ@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=eK3o90MK;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, May 3, 2023 at 9:28=E2=80=AFAM Steven Rostedt <rostedt@goodmis.org>=
 wrote:
>
> On Wed, 3 May 2023 08:09:28 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > There is another issue, which I think can be solved in a smart way but
> > will either affect performance or would require more memory. With the
> > tracing approach we don't know beforehand how many individual
> > allocation sites exist, so we have to allocate code tags (or similar
> > structures for counting) at runtime vs compile time. We can be smart
> > about it and allocate in batches or even preallocate more than we need
> > beforehand but, as I said, it will require some kind of compromise.
>
> This approach is actually quite common, especially since tagging every
> instance is usually overkill, as if you trace function calls in a running
> kernel, you will find that only a small percentage of the kernel ever
> executes. It's possible that you will be allocating a lot of tags that wi=
ll
> never be used. If run time allocation is possible, that is usually the
> better approach.

True but the memory overhead should not be prohibitive here. As a
ballpark number, on my machine I see there are 4838 individual
allocation locations and each codetag structure is 32 bytes, so that's
152KB.

>
> -- Steve

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFYq7CZS4y2ZiF%2BAJHRKwnyhmZCk_uuTwFse26DxGh-qQ%40mail.gmai=
l.com.
