Return-Path: <kasan-dev+bncBDR7LJOD4ENBBZXX46XAMGQETNAQDZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 76210862599
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 15:23:35 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-6047a047f58sf21675327b3.3
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 06:23:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708784614; cv=pass;
        d=google.com; s=arc-20160816;
        b=IsgrsYwvRgb4f92RDZJIVMcuyGqRLROl3l4MJrYGhTP23MUcWsBM7axlwX8p2iB50a
         lHutNLYS40ZlFtBBVc9wIIvJX1PJ931b90v6iKwRiiJxVRDjR/Anxv4vFPQWmyMHHhjN
         ZiRnjczELkfEQVL0yeWB25jUNHz2JzvQOVcvIuyHJjTGki9opzB2mVKuQCbsJBfvTyY9
         sQ/pbFwBv1AvwU71a6dmdlsGxu54Y4u7caYvM7DJ+UJPzaiAaEQM+bMQCjKRkUiwoN9N
         80BqIgPjvUuZGIaziCF2O8nh4QsIoA8ViyD2s+KFIgbIz4qHCrMd/BD9erWv/rTbQqEr
         8VOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z/0psOHkB3mwDX1QUv+DkFsIJNKAO0E/zad91mBgnNc=;
        fh=CAgPJlozV1b/px33k43VdczCmokStw2GBMg439DDqoA=;
        b=INfzjptvcQIwROOq8M/vPQX77WIGj/keLe7O+Bgr08IIzfdYxn6m+RJ9A0SqT9r1jE
         9VubMPqEC9CrNps194FMws7rm780NIIJiFj1vLCd6awLgV+Y2sCNzSgsRSG5I/BRWzZM
         B+QN8AbqtqYU/rcLfy5f2iczEL/gqSeMcmuCGU3/Kgu0aAQzWFfO6yfHfz5bONYzxkMz
         pEwSS/Gn4qvMSyQC/NYc/HKp4qNINuxo97bD5q2sDN3f6qp3EcoyEphwyVBF/4Jjg6Na
         mWMBam5cJXmP+kChmWRxcUgqFS4muQSGWveXglZU+Ru/24e5lAiyEPlgi8dqwyv4ZMXf
         I5AA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CmuBM3G3;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708784614; x=1709389414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z/0psOHkB3mwDX1QUv+DkFsIJNKAO0E/zad91mBgnNc=;
        b=HAi+SqeyxEmAhxqWWtcQeSJAQlZUY+APr5Ykbokrv8iGsWTM1D1ygrtc2AFUa3a3fk
         R+3cc92JjevDuz1nY121SF+g7vTeeZ+GlZ50qI3nMMzO5r7/+Do8fAo9+RKXauTVZBB3
         cbHxj9bmdm5YvQ8eGo7/5FGhxg0b0uDgwTcKfPVUmcLPNTEURPe8IxqRgfaYDQfVWFd3
         7Gc0vzSrbRZW1mt7OZBHBeJR6G3sNp5KXPIwJRZI30gB1vbZX7UQsW5Cuh1c4JI0y5+x
         ZuPv74hVPv4abIoFBwdYcM42phh48YrV9Fn5QgWdsK9OIOoQ1ytLWlW0Abnb/gMvD8KV
         FH/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708784614; x=1709389414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z/0psOHkB3mwDX1QUv+DkFsIJNKAO0E/zad91mBgnNc=;
        b=wNCGszGpRSAwKcihBunu0lnM4Lc6eiy+otlB3ex5pCMZ2RGTiVaaco2HosE7vmlWuR
         4afyYKkjSDX8yDtrjDwnfCstN5bZu30uj7PrEoHPduibn/p8WVdsZ3Hdd5fbTwtLKp3N
         w0Vt6XeKMHMnU13aAottnH3ZvCAGpSMFZ4wj/7CwOCpkrATIW+r7BRvIBZjHaNIzv7rs
         DYSb1UNNclSp8QB21XyBHDsZZ7gFc46GQFUZHrdpZU3OfHOdQ6DqMeB5j6XP2ay3xadb
         kz7zBOU3qSkcOrpgBTQp9eI4OI3An2GnwjOjbft00mlj/0btUpBF4i/DaaUFgtDVcjay
         jY2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUb1rhKUeB0vgrnBHvVO23SjhR+DH6HeoukHPuYJP8bLoGHaaQeABQaGKuu9+GgXpsC4701zbFcUFHDmRAu9akcJz6odjNfxA==
X-Gm-Message-State: AOJu0YzBqYhINTEGL9nCwwgGyjHK23l8U0brdhlRUl85tcRox9xO5hZW
	qZZoCBz78rAF2BthMqL7z0jIunag0NP4o3r9LEnicwGNiFf2+0h7
X-Google-Smtp-Source: AGHT+IHsM528gPnx1ufBtr3wdNj7c6wGj8dmlca2/dGAl5daEVvTaI8IrdSPLkbb3kY6SgXh6W/kyA==
X-Received: by 2002:a0d:df54:0:b0:608:d05c:a6a7 with SMTP id i81-20020a0ddf54000000b00608d05ca6a7mr1412580ywe.36.1708784614151;
        Sat, 24 Feb 2024 06:23:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a10:b0:42e:77be:c079 with SMTP id
 f16-20020a05622a1a1000b0042e77bec079ls355225qtb.1.-pod-prod-07-us; Sat, 24
 Feb 2024 06:23:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWgf9odsfRNsRhqlk40ixmQf7tRFOIValfTp/CS53V5iEAPgM0VzoJXOuJsWqlTmylZ2aa2v4PBhJToYrUnVkUYHPTNGXhoorKvQ==
X-Received: by 2002:a05:6102:1892:b0:470:5667:5d6a with SMTP id ji18-20020a056102189200b0047056675d6amr1785725vsb.27.1708784613067;
        Sat, 24 Feb 2024 06:23:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708784613; cv=none;
        d=google.com; s=arc-20160816;
        b=uS7P49tbhw/GIcIiRQIufiRtmQiiVZqe/lkqLAFbsdFVWXlEI0VIlGpaNcCaA0uWnZ
         ywo3qbMgZOSeVN39e8QCIe9tz0SrrbpbgDjiG53clm/GntKFT8naHCNbCRuwIKK3uiOb
         waqLBMTZL82lht6r4TyAhI38vKdy1ldQqMci4p/QiLcMYHjpZK1yEjaqZSdGNEYtNkgH
         lH7G8XtuRmIdbiBX6oqnuolgBlVQeCKUlbfDIlCrmqCir5MhC+K5G0DiGykDEDq7o9xI
         0jco6ssQ4VLFrv1geQm00Cw8cF34AYpNK5iydgEPhkPg0p5RGNHJ+RqWh9Zp3rY1NiFA
         dmQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jyxe1ZyHEM1T2r2O7pII63uf5/ieYPDWx0PKMOw5NQ8=;
        fh=fTcrlst7CA6wQETkuQWAF4TaffGII1LPV8usU9+C0IA=;
        b=PBgUuiCesKYCG+fa9VPQSrn4+IySWu7HUylXc61v3d7iZrq+R/mTqu2oLausd8slHv
         24ue02nR4ISmbQWwfWycqGmyPJ4YmXIf06UNPTGngCrvN/khi5txDLRqbEDUy8KUdzgq
         n12gQ0pL2GQ9Po9YHaC2qJ09OXI42A3xqZFtXWNlv42LlDaNOw4hFBbI6OkehQ19jOkN
         9enM/RG6Nq7VJaEPb/6WNcrxrnvFzKWSd+IItkME/ZwZSAkL2iUWDZUUQjAHmgw+5Lf8
         1ghCdnk7Q30yG8dTdfWWK1dhKgEArkq3EO6EZWb/sc5Htfo3LLv3+eewFw+FymniRRqQ
         +SrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CmuBM3G3;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id d16-20020a056102149000b0046d3986403esi133387vsv.0.2024.02.24.06.23.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Feb 2024 06:23:33 -0800 (PST)
Received-SPF: pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-299ea1f1989so841815a91.0
        for <kasan-dev@googlegroups.com>; Sat, 24 Feb 2024 06:23:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX2ZcbS7UbInEAOpiN/AbgjU/jxu3jOHKXjgZ0L7x7uXUwXcOkHRz2BnpbA589+Jwh1rWDj+PJcrrGNdw5CTXL4U6Lfk9O/WCff3w==
X-Received: by 2002:a17:90b:4d8c:b0:29a:9dca:e85d with SMTP id oj12-20020a17090b4d8c00b0029a9dcae85dmr673401pjb.41.1708784611993;
        Sat, 24 Feb 2024 06:23:31 -0800 (PST)
Received: from google.com ([2401:fa00:8f:203:927f:4f5a:8fae:16fa])
        by smtp.gmail.com with ESMTPSA id bt12-20020a17090af00c00b0029a73913ae8sm1274980pjb.40.2024.02.24.06.23.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 06:23:31 -0800 (PST)
Date: Sat, 24 Feb 2024 23:23:27 +0900
From: Sergey Senozhatsky <senozhatsky@chromium.org>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Yosry Ahmed <yosryahmed@google.com>, Nhat Pham <nphamcs@gmail.com>,
	Minchan Kim <minchan@kernel.org>, linux-mm <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Mark-PK Tsai <mark-pk.tsai@mediatek.com>
Subject: Re: [mm/page_alloc or mm/vmscan or mm/zswap] use-after-free in
 obj_malloc()
Message-ID: <20240224142327.GW11472@google.com>
References: <d041ca52-8e0b-48b3-9606-314ac2a53408@I-love.SAKURA.ne.jp>
 <20240223044356.GJ11472@google.com>
 <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
X-Original-Sender: senozhatsky@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=CmuBM3G3;       spf=pass
 (google.com: domain of senozhatsky@chromium.org designates
 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On (24/02/24 00:22), Tetsuo Handa wrote:
> On 2024/02/23 13:43, Sergey Senozhatsky wrote:
> > On (24/02/23 11:10), Tetsuo Handa wrote:
> >>
> >> I can observe this bug during evict_folios() from 6.7.0 to 6.8.0-rc5-00163-gffd2cb6b718e.
> >> Since I haven't observed with 6.6.0, this bug might be introduced in 6.7 cycle.
> > 
> > Can we please run a bisect?
> 
> Bisection pointed at commit afb2d666d025 ("zsmalloc: use copy_page for full page copy"),
> for copy_page() is implemented as non-instrumented code where KMSAN cannot handle.
> On x86_64, copy_page() is defined at arch/x86/lib/copy_page_64.S as below.

Thank you so much.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240224142327.GW11472%40google.com.
