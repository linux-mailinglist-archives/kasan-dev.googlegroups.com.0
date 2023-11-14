Return-Path: <kasan-dev+bncBCF5XGNWYQBRBTHVZOVAMGQELKRAAXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DC2D7EA9B6
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:42:54 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-58a1131ef74sf3304006eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:42:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936973; cv=pass;
        d=google.com; s=arc-20160816;
        b=BkNAu5VJK10qZLdWG0IYYhIhnMJEmej1isMZQ4tAzrBjPnJib6iYIcDV/qDOPN05of
         vMm2wY3mprOtPmmtNT2XtlZRh6yjxLSDTi6HlvnQjwytwxVdx9UQGXrtz+Tng/m/tTQH
         OGaSt23DkUE5jlui0+gVVIo3BcDe6rbWMLF8VvT4eBUn9pIiGatfiyQpRHBcwp4JbG6F
         kozauUKr9TwettLDg2vt4KdeHL9tB71L1fWguguCwrW/IpO9Xdn1cycd3rzLzQl6Ioit
         7BkO9Fx2F9ku1jmLjPecdZSIa8o0xYavAD+YIHyY4ZPSa7oH+Ntjk6RELlLEXMtB52JF
         g/3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=porACnljGnKU3Cagn0wnPrErjrNHVTYebT4RNgX6t+g=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=xqBVQ1tgpAnvoBBGDuzylSI2uvMiwCipTAh8i2PKfVCqTNE7LfmN5K5XD6Y86CDJYf
         XYxq5Dl5qkI3Ucdo7MgW4YTR7HQO6WucLvexmGcPSbOm2BbO30agj95EYQT4CBPJugTy
         ULlAct1PbDKwctEOXCXehZtX1aHCCgA865M32TgXTiac5hByhftsZrXM3eujjMUKKCz4
         4nG+CRgwFsa94Gunw0DAvLr2dsMhrGqSabTKKEGeRlG/209b47B7hCs9BZ0JpWhyWsYQ
         e1q4n3hhLJXdgN2ZPM+FLcZY/i7pbh+xyewcBJxGB2DHvNsz1RJGN5x9yANV6fK8C3xv
         BoGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Or9dkrBT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936973; x=1700541773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=porACnljGnKU3Cagn0wnPrErjrNHVTYebT4RNgX6t+g=;
        b=NHwYucFp6QlZqfYNTgzlVObLYptKtjcb1Id2EnyOcYw4Ut0RiHxQ68i5FCOGoYKX2G
         JotpmaEjl5UHxIvYqoaKphCngms3vWkwtZFqM05YIUt8d75ZSEHlQde//WOp+tOhkSHM
         b7g6LurMvKEVcmiA4/uraF7D3U0oCuZnRHuVYo2LzwZ6QtOtPpVA8wnmPPPlW+vOD3Wm
         /KbuKmE+j2nu+K3QBKPwIrxmBDBapuhaq4idZiqcflu+XpceqZoz8l+x6tTPiM7NEcMT
         +uDxxMKYhD7U3n1zNP0B1lYdfq0QRLsskRHnvUFJjV0CYJL9ewiMnY64UMln2C2hzYKy
         ramw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936973; x=1700541773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=porACnljGnKU3Cagn0wnPrErjrNHVTYebT4RNgX6t+g=;
        b=tkMrg2EsdXKrDyeuDTGOnA/FyA8whSUahYUiToHAR+LM//Y84tc2XXywWaKPLWqyPN
         dflaByWHHqfctdsfMsU6Md+CbK5GSVmBFEqwlEeZNbyGVZa/nHcqx5R9u1YokCkN29b/
         fikzoUx/XdYV1a/639gk5tZ2OPZsNnxXkCWo2r/8kXv7pqaatwiAEKDLOaXCPFN28XpZ
         HAMhijniRuXTgl4tSRO/FNpeKonN9Khq8JUZl3y8tmby2Jgg5m1W6SP8Bd43PLFxUU/O
         NkMQWlThpk8hlV6xyUUHYc89ySdBDSS1cMIcC7kzcsHy5aRAnYZ9EUactTl6r0z04Unc
         IN8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw0Oa6UWvcH3N8FwKwVUWtz6RLTOI8U6g8b/8MXI+lhTIHXlNJg
	p6j4FTDYJAZhrHm0hkSKZ8k=
X-Google-Smtp-Source: AGHT+IFLfpfJVKRNU/Z8l4D/fvLBLN0kLA21ikHU4TW97Gb+HawOkmslE2BOfo9VKrsOyMIUE3Iojg==
X-Received: by 2002:a05:6870:a792:b0:1f4:e209:a7ea with SMTP id x18-20020a056870a79200b001f4e209a7eamr8667655oao.42.1699936972869;
        Mon, 13 Nov 2023 20:42:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:72d4:b0:1d4:eb1e:6831 with SMTP id
 o20-20020a05687072d400b001d4eb1e6831ls213078oak.0.-pod-prod-03-us; Mon, 13
 Nov 2023 20:42:52 -0800 (PST)
X-Received: by 2002:a05:6808:2123:b0:3b2:e761:fadd with SMTP id r35-20020a056808212300b003b2e761faddmr12449022oiw.16.1699936972192;
        Mon, 13 Nov 2023 20:42:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936972; cv=none;
        d=google.com; s=arc-20160816;
        b=CqVyzmqW9Y5iY5aDNJU33Xvqq/lbIYzeF8U9qYte1LBRbvhwl3SmVfayyocClHWPgw
         qP10osS+PfKEJod+9N/LNU65zKlxFaiCo3vO6E+Imw0LGHvCFy9RrOaR4G7siXmJo3CC
         qV7kO/DezCNqgIfNLexKad2gTaC1AuNauSPnG8txZdzmmatdD7o9dY/8ufFBfSFhACJK
         oXjEQC2LWvkl4rJMWRLbndfS3erN4vbzIY6O1UXYxlAYR+fq1w2nVO0/D0EzRkGkpUsB
         PMrhWFj6EULNoceZwlhM9S9wbwovjwUqKutbsvRxRvb138w8ANIT1TAzGReTO8BBThFL
         aHOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sCrSsxjAq1jCq+B2JpsAc9Scn9B6dHAemDj3eFlW1CE=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=FGKuyF1Z+kAsoSKjN2FgNvwpoM8XTq/MI3kp8w3OrcPY6SR+hrZWCHffymRWeFjqnT
         ms/w1m7OadA1pfI6AYyu3yoFl1e4PkbSnj5iJp9t3G1wMIuexC+87W3sVJss8C5pCViJ
         rE9YBDFqZ0kPhmGtG0oMppF3b/OXnZ2JJj1sF0CFyrm1DOBi234LPGwwU6Xj8AmYKK0c
         IxY/Fj34lbVR21Y0m+rhq72H8szXamQnpktA4WB7Z3qGbKSMHJIRrv7dD5bygeBDzKRD
         S74S/1tgnRG56Oa21SiPM9kuRMoK3B1K4vCJ700bt3W8VyOzBI9ky/7xGc3fh6DW2xkA
         Tynw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Or9dkrBT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id m2-20020a0568080f0200b003ae5482a7e2si438912oiw.2.2023.11.13.20.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:42:52 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1cc3bb32b5dso46531745ad.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:42:52 -0800 (PST)
X-Received: by 2002:a17:902:db0d:b0:1cc:4467:a563 with SMTP id m13-20020a170902db0d00b001cc4467a563mr1181743plx.3.1699936971495;
        Mon, 13 Nov 2023 20:42:51 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id z5-20020a1709027e8500b001b8622c1ad2sm4947830pla.130.2023.11.13.20.42.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:42:51 -0800 (PST)
Date: Mon, 13 Nov 2023 20:42:50 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 12/20] mm/slab: move pre/post-alloc hooks from slab.h to
 slub.c
Message-ID: <202311132042.CA0081D@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-34-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-34-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Or9dkrBT;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
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

On Mon, Nov 13, 2023 at 08:13:53PM +0100, Vlastimil Babka wrote:
> We don't share the hooks between two slab implementations anymore so
> they can be moved away from the header. As part of the move, also move
> should_failslab() from slab_common.c as the pre_alloc hook uses it.
> This means slab.h can stop including fault-inject.h and kmemleak.h.
> Fix up some files that were depending on the includes transitively.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132042.CA0081D%40keescook.
