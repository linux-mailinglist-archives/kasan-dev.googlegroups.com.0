Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUXHZOVAMGQEX2JQMFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 991AB7EA960
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:13:08 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1f50a75ac0asf1687019fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:13:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699935187; cv=pass;
        d=google.com; s=arc-20160816;
        b=LOkuptOYBA413qB9rT6jecsjlycnJEK1wgJfl3x+OAEG2hk6jxsnUYGHcrMO+xXUz6
         VWolothydPALwcrqHL2jeu1UhSNpnSjFPO8Yt36RcCoO2hj1DliT0BETXuEgyXp/xm8u
         AAWfoTgzBcX1nfz6/vuf0ZAVPlcWH3/uQuJDDv2siRWz+eXJNSWygdAWvx7XZ648hAPH
         UhILPq5etCQYoFPUTqs3RJ+P3DR/nehe8/QtidBRerwnaOvzUXCxl4S8ZJtQcWe7qn3W
         dWUZykRGJjZoKlUm+G8fPLRAVHjb8MSqkQYoT70hhJ56+uGCr//AZ95O3BErL7EsR4em
         Xi6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AqNxGom6aLbrdOG5GzTIYCrCxpYeDlATuqVjF+Mo+uY=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=B4SdlDEElUuZEzL+b6dHQqwXRuzLLfLK4rRrcxd9Je/F+5XglpCFMxNey9mUnxH7Gl
         6yTHngjGgH9+fFuPSfz9fsDpO0a4p71jUz/StkYyD9gmXeX2eZXyOvxb/Y7WP1Vtl8+K
         NXNPi0MgK4gg1gSZUripoNoiA1/Cm2bXp0MqwvquAluSqd4H2YfD39NRS0fLGq/+P3nF
         mu7/eHptzIva8U2rWqGXnJ8yY/isvvlaSRlmVUnWLJv6xz0HEMuGWMFJ0eZtwK8JrOD+
         NBhNbBxC7XBkCIvJYQBoVlbusbKVcji7hxzbqVO2swW7cS84WIFyFcWlZuw6+kzdlddG
         tLXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Cl4nXYDv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699935187; x=1700539987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AqNxGom6aLbrdOG5GzTIYCrCxpYeDlATuqVjF+Mo+uY=;
        b=LITZk67ocdDHPS1c4dcHVg8JbQpDcTPfnQJh+V6SpKb2O8V5gSJs/HRZWqKYskcMTf
         1jNl9LIzKMDGGtxgKFwPm6uYijXoL9qcTgx1AlDbdFox5E2E+hoxKvXFfnnGsJ2fXzP8
         8YcQY3wT8ZmDljFRyXNKHC4SJQpkwEE+k2NJkXX9H/ITqKplLb3GGLT3n79I0hB7blB4
         95ifNyMh+1VVc4b66LXgs8uAYcYqyk6jn/uqYxBFpnYWaZCCLQMCjld/sE2jJsXG6JEC
         frv1f/FsmRYG1lrtJwF4rVj4I0d5o44U3CC7zEOHq0wxBUwkS8hrowwGtY+IgfdYnUKS
         BMAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699935187; x=1700539987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AqNxGom6aLbrdOG5GzTIYCrCxpYeDlATuqVjF+Mo+uY=;
        b=thFvDq3nO0Ns/Kjj+v9ztiOIndAPzzJ6Zlse1EEQCUn9ji5O7ofAz90BmuWVv0d58r
         EPD9GgPioY/k3JhZtw3+Ke9p4ukqqNMlvBcl6yO04iNrklG90Lo/XijF0UY1eNpEe3iV
         bvsBtLfUP3GU4yyh+8NbrRsGCFW09Srb+7T1Hcio4XW+kaCnHea1jvrVsmWPrHd1rEkQ
         8PXNBV+Q9zlRxFWKVgUVJ/xhc6qTCBiqi+ZwLRwHJI9ERK//gt0jkk8hyCgy5X4X+qyW
         kgoxJ59rPh4CiGoEUbk7OWnhmiEeeocJTFQk2yQ5v296BpHwpdUv162G2/zg3/Z1U2ZP
         f9EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzCEVo4wp/G8hANC7mOW1ag9ZgMRJnMSMeoN2dSYYDYxE9Xp2sO
	fDhmX9UFVRNwItbyjFjd9L8=
X-Google-Smtp-Source: AGHT+IG1jrxOQ+N5/DWrEfUHlpPoH5PSaINeGfq6eLOUD9WSZVaXBcRoPZ111vI9PKr4SF7n1SkG+g==
X-Received: by 2002:a05:6870:883:b0:1ea:a54:c276 with SMTP id fx3-20020a056870088300b001ea0a54c276mr11119382oab.29.1699935187084;
        Mon, 13 Nov 2023 20:13:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:df93:b0:1f4:88df:8b64 with SMTP id
 us19-20020a056870df9300b001f488df8b64ls1803158oab.1.-pod-prod-09-us; Mon, 13
 Nov 2023 20:13:06 -0800 (PST)
X-Received: by 2002:a05:6870:4c81:b0:1e9:9aa6:eeca with SMTP id pi1-20020a0568704c8100b001e99aa6eecamr12399430oab.1.1699935186491;
        Mon, 13 Nov 2023 20:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699935186; cv=none;
        d=google.com; s=arc-20160816;
        b=l3M1aaALRlYbaBG77ktnF3FHWnU3d554qSheORys6rbMKXNG/maBsKiWdXvo6SjgQl
         7YSrmnsmKXWvWSop7l23WkmE268FLH7DYdMyxa4O5x5jbdfXxjZ1kQ8PnOHv3n76aWZT
         86NMcs700cQbltQM7DvyoZoCOc2nh2lHd9MuMIigBxv7KhJkDPnLtot4+T2EQ1sD7BqM
         UGjV6Y3rf69iJdXsMNY+JkqMMcpT7jgFfkVS4+8QIbNmVZPjES5izOKvt9F8BzwDlWKD
         Aj/csWk/1Vqf5H+3qUEF4B5ICXD3bHaIl2SK84M5UpS5uLl/XPNdFI43i0z3gLkSNPFy
         Qxug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+59LbEu2KNUEAvaciP4no1NYqRz3c5xA76P/RF2+jHM=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=u5hoal3eJbjgfNpvxcNWBMUwpnuDQEULz81LbZxOZNHX4mPCQiZJ3/wYgwMI0wffdT
         BDFJqNDCgEN/RkBzydxmrA2QeJWifjaBV3gj7zD4aziUrBCyBwc5E9F/ArUd6JjS8gEx
         cz98vNWrUS/Pfklhu8XJDoAGTSl0YQiDeBJBK6uHTjuce84K8EjH/t/Y765OMPHSnnZX
         EOsJQQETYTAoOp/XgqA7ETsQSmItVyHvJ0wFvbBg1wb6WjjBtSmGUzBSS3F8elWYROQe
         8Q0WpOl78xTGjGU7+DUyfo3kzj42Cp/0YFOSlv1MHvofDIa5JwU9+jtV3UDT/8jg6Kr3
         P+bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Cl4nXYDv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id wx24-20020a0568707e1800b001d6edf0fa0esi626205oab.2.2023.11.13.20.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-6c34e87b571so4299191b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:13:06 -0800 (PST)
X-Received: by 2002:a05:6a00:2d82:b0:6c3:45bc:41f8 with SMTP id fb2-20020a056a002d8200b006c345bc41f8mr7440255pfb.33.1699935185790;
        Mon, 13 Nov 2023 20:13:05 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id p28-20020a056a000a1c00b006933e71956dsm353045pfh.9.2023.11.13.20.13.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:13:05 -0800 (PST)
Date: Mon, 13 Nov 2023 20:13:04 -0800
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
Subject: Re: [PATCH 02/20] KASAN: remove code paths guarded by CONFIG_SLAB
Message-ID: <202311132012.142AC3618@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-24-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-24-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Cl4nXYDv;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
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

On Mon, Nov 13, 2023 at 08:13:43PM +0100, Vlastimil Babka wrote:
> With SLAB removed and SLUB the only remaining allocator, we can clean up
> some code that was depending on the choice.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132012.142AC3618%40keescook.
