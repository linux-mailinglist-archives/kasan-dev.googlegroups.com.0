Return-Path: <kasan-dev+bncBCC2HSMW4ECBB5VRX2XAMGQE6KQCOXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6036D8583EE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 18:18:48 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-dc6ade10cb8sf4604802276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:18:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708103927; cv=pass;
        d=google.com; s=arc-20160816;
        b=LGvDdvQdTqOnWuMhgG1tkbalrxO8AatHX5hBn/CjR8wjfEkZA4LGbeJF6WEVlKmMIE
         nGjiu7smFPPZhvykClc/ZQYA1AZD7QcpVpENylE0nqAuJwtXLObW4iJsJvdEew2yaHRj
         Gmm8QNlFMg8GPDGSaN2Q+Etd8RhTnr35m/2OozxKP/6Bh471ybT7RbPLOFTcb9+d+dPm
         rjpjuO6KKLz50HREP5DJxF6Eza0lCy5JpCXoFWSJsgMAcopnI4VPHrirdeh15+rUI+Wx
         QMBfmiaiK30Ns/nc1mrVdEa1I1urTYaCUPoLW0Woi/WKZfev74S5Kfs3G32F63HSPF2w
         ZEvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=36espsW7+yz00kxR8x4L9mZkrc1pvaJp2tNfn6oQ6qY=;
        fh=WagQqm9DfVz65ZswR9vX5g3ouQa+zrFuYt24Tizf7U4=;
        b=QnlD8cYKsAcCUPSyxCayxVhMHE5B1PYVJL5zZnvWWx1uyxAB7vMtnloMqwmc4nTiDe
         m5RA98ViCLiOARRr56ZZ7GS75HcUaB0Kc5C9wUIw6ZehD7mc9VNoQtWbDoGjAIWzVJy5
         9t0U903q/xOyZoo2Qcq9jgRjtuylr6cZ3rXy/kmPRcqUsewuZvRBJArpv64RabwxsJ9S
         cxkRU6xggMoD5tGn/wisrl7C1qZys9VBhXSb+j/JBwzfkxkxqjYbL96VvqMFhH240S6w
         hQZ9IQH9755B6bMrKgdNuHqSeXB7TcIHfwWQjR0CZphtAwooIYpQU38Zg1arOrSZ4VJX
         SKWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=09j42fcg;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708103927; x=1708708727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=36espsW7+yz00kxR8x4L9mZkrc1pvaJp2tNfn6oQ6qY=;
        b=CC23AVWHsXa6xUjRsrsAS10NcSPQ7/ZW1+gD+AFpI6qJctz/hyNkRqkDBsGpNUuJiK
         dl+XKjYUsw1TKPSMF9mLgYARsydddDTnhOIhoybgqMkxqXeXnxpoZwfv7DvjoYZUrRJe
         4pvzJEQYfQoQdbNziIOcQZLvy/x0ANwRBYe+2BB6PCcq0giN4FXMOSa+ExzMtcfpA6Mu
         0sxbSNm9ZDoESYBwO11OHn7D8Jx6eVRu/HU03X7lZfGIxUC90tlVu98zd0YxlDfcd1qX
         yP8RUkj8ZPmpIbzgtiSYmMR7KWwvp99+xSq/uwr+hzoJnDbbAmigfQreYGF3MsjltnKr
         VE1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708103927; x=1708708727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=36espsW7+yz00kxR8x4L9mZkrc1pvaJp2tNfn6oQ6qY=;
        b=P3vKcbp/Ulfi+qnTh97bP6uGfldnHdTlZYhfqmbC7xlarSCWh+67BmHVmHmMO/PRUQ
         AxXfzVoqoV5+5ZTzRcQNESaFc8/XU45tC74/degUt8mn1UR3kxF6boYuwmIl7RDcPSfc
         uNuCqHTHZ/WJN+3NdH+fQmQZK0039v2OHvrjQWw/2d7mWQjKx+c+STcgy/4nHKe0TmSu
         4Wve9orMvIKWZlQWgL5mFFfIgDPATdE+ub98zF07O8uSs1KrbrLhA4gYme47DH5n5xcp
         au/NtGbqtw4hZBzJzrqnYuXFrRdp2syfjAMuLdkCAXd3FuxAvkx6sSpQSejNFuBFN9Hk
         UiiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdRNElcvVw8j03VYWu4DL152tjk6KEwDT09BiJDmx9LkuFldFGR0rzSIDEsNWcLnlBX2LQXMReJ554npKnLgmK4IBH8upCiA==
X-Gm-Message-State: AOJu0YzS68ZfQjAXwDmJ0Lq/zTUy4ROV3j15ecYRACY6vQwAlASf6rlm
	KTRjmiFlt59o2cZJhOc8PbdlqscabDRLJyyL44S2lghMminfObD/
X-Google-Smtp-Source: AGHT+IH0djiap8Qf8Ly9Y9SZjDVYhIxkV6AvoCg7AITwCLklmugIyl4qtUFBATRd838amldFD8AnNA==
X-Received: by 2002:a25:be06:0:b0:dc2:2ae4:d639 with SMTP id h6-20020a25be06000000b00dc22ae4d639mr7027145ybk.20.1708103927069;
        Fri, 16 Feb 2024 09:18:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d848:0:b0:dcb:b370:7d12 with SMTP id p69-20020a25d848000000b00dcbb3707d12ls605312ybg.1.-pod-prod-00-us;
 Fri, 16 Feb 2024 09:18:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlnfS9GdPPVpT1OVIDvxxvLot8AO3I0W7yRm4MrvBu4jQhteHTwrHFUtfqDHE29UzM+mnRAPB/9KYXxNHGqJSM3mNvjlVYXfYZVA==
X-Received: by 2002:a0d:cb01:0:b0:607:ecae:159d with SMTP id n1-20020a0dcb01000000b00607ecae159dmr3234122ywd.0.1708103925988;
        Fri, 16 Feb 2024 09:18:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708103925; cv=none;
        d=google.com; s=arc-20160816;
        b=x7R/dtyd2jpXdffrIS7Cd1tk06FLsTy4s8js0X8BZp1dj1M7YIVc5SSwxf2Clzt3jc
         HKg9igHr7DPmtFNCmyqd39WAgDdE4gebkDzJFiiuzOsL11Wr5tAdK/ugOROslAvbwWxM
         Sy0/BwYZ3qcLvvHR8sKzdE5LHyQXonh924hUgXVvm0S/nXCqc0QIrGxecVkrAagp/cUL
         JBTWzYx/1mrE06uknHV9kIgGAfjUoswf+GvyuCrUDIV63PKYVa+Teu06V/h5728gHBea
         IHu9NvnqVOrpPSXncx1r7xmW8jwXL33+LlKdhUjRgZf0FL+rgd+vmdnSjjak1D1YfsBl
         ERWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ttXNwKWugMJyygslP182txVVK8JBh5UVtMFEymJTCI0=;
        fh=f9dnvl97gmaS6Q5jLhcq2icRI3DlaSZaGFEQbEbCsW0=;
        b=SIc0VqlYElyEUYal2uAZwPQuTHtCoPMsllniI8leuCr2kr/1cHUlE2X3n7EXPVNGfL
         3uP+qeuq1jt1ERogZoh1nSiLcmmCXu73p7NWNHjv5JT/7Aemlbo7qppcX/ZmnOXtSqWJ
         xXxZmRL6hqUSoJ5yo1zO5j6OCsoCWBi6aZ57mKrY+fV8zIWm82k6AfOA8qXNpTSAvvbW
         Nybz9jPhQYDbwfeha1gIo21lO9cpB2VUj7JrGahQnexEf+y5+0Srgh/JiJvds/+qKYyH
         636hJueTVF429+LISupLfazVAbILtHK2p6vRy79n7GvYn/aCOaShkLbFXmSaVPHodxBy
         g7/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=09j42fcg;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id hd8-20020a05690c488800b00607df849f43si89003ywb.1.2024.02.16.09.18.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 09:18:45 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-42c758f075dso27988491cf.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 09:18:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVMp5nnY6tG5sPKvROE8eSl0zxF9tfzMnmkKmpomHBlPosIIr4gdNpkYKibV4JLmdmmaFl+gpI3MBr4h0oYd2VS39qjvxBMK/MOew==
X-Received: by 2002:a05:622a:130d:b0:42c:7b12:70bd with SMTP id
 v13-20020a05622a130d00b0042c7b1270bdmr14455790qtk.9.1708103925488; Fri, 16
 Feb 2024 09:18:45 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
 <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
 <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
 <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn> <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
In-Reply-To: <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Fri, 16 Feb 2024 12:18:09 -0500
Message-ID: <CA+CK2bCsW34RQtKhrp=1=3opMcfB=NSsLTnpwSejkULvo7CbTw@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
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
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=09j42fcg;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

> > Personally, I hate trying to count long strings digits by eyeball...
>
> Maybe something like this work for everyone then?:
>
> 160432128 (153MiB)     mm/slub.c:1826 module:slub func:alloc_slab_page

That would be even harder to parse.

This one liner should converts bytes to human readable size:
sort -rn /proc/allocinfo | numfmt --to=iec

Also, a "alloctop" script that would auto-update the current top
allocators would be useful to put in tools/mm/

Pasha

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BCK2bCsW34RQtKhrp%3D1%3D3opMcfB%3DNSsLTnpwSejkULvo7CbTw%40mail.gmail.com.
