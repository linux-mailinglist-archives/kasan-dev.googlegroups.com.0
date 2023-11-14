Return-Path: <kasan-dev+bncBCF5XGNWYQBRBP7WZOVAMGQEJIEON4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B687EA9BC
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:44:48 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-35aba810a61sf17220335ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:44:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699937088; cv=pass;
        d=google.com; s=arc-20160816;
        b=RByzkB8arZeBTq6+lZaSVX/r1Dsng+EBDCLAQ4uzOG+BZbj1UDCg3NiOSKYcPl2g4e
         naB+zgLGuJ2s297FYlXwnL+IqS2JBMv7zGMr1A+ggYOqZonTg1ehjNhd82cXH/diQpUl
         xTXANxjo0AJjeq8x/v/6F2dJBCPQ+pQl4yMozA6iyQKlK+fpjScFpMWSX6zsxFo4jwTE
         ZmBDvJE1MBv3K0r/wuIjJRmsd4zKU92ZAXoPe5CrjOfgr8tO+Kz2ETs7T63lht1Ikkdc
         efLvrFZIfjYuGeNrqXxssNTeLzpLkHGdm7/K7DFZwLTyjOYjW+QwLPhOW5HoZNU26UAu
         m/tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZTgCsFKByoJopQFbKG9Iaipri8ykPsfvl0cVpNjUUX4=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=Fr39LHm4WaA6780elzCqF1mRTNZsRLlMiGQhWWb+AVZXT6vgnu6F32J2SvOWvggkJY
         DOTsNnGsecX7RVGupXkT6B65q9c8MIjLrrt/D45Kbd2UO4PLvP8ojf4o9KpwRm8UAjru
         4U4fq7ZwvkUGDOoQ3q4zJ/2ZLQDN5Ma1c3ud1s9Y4boxBOsaFhZY3VnvpK8yyDJFvjxj
         5ASxAnLDcKfeM6PXDpPtTQNh4MBeJYfdef2jERTL6V+BcePqU+RFlpidXp+v8m8gSQeH
         pWKlxN+0RHtmxvN9YrfFIBxWQFgOMu1WTXLPImO4wyGF2FQCQPX5/us6tEYfFiediS2n
         IMOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HRF58Fkb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699937087; x=1700541887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZTgCsFKByoJopQFbKG9Iaipri8ykPsfvl0cVpNjUUX4=;
        b=pie+53+/XU37ibBIFjIC2Iev9Ooi1eL1II/yGyNUrwOivxfdXtwP3tPgHWVn6WyiLu
         5VxpZVjqYp7cGn6OQFVTNQNfTJhY8qzZ5Ob2hHDgGV69JHH83C0ZAyJ8lySuD05P8wn3
         rXSuhNINFhkOfhLHeltvAEFAD75ipC5V5GsDdIOZen8csOsoAEigCjHFweyORMqtb8qE
         xnmKA3z84CV0nf6zZW/S2RbotvzaoYosJtS2dzERAsyPgzQiNiMqmoE5aFBTfM3BUCE7
         btui3IMdB08XpOR3a08sH3O582ZUbLZad8sCedkDViGI0wmew3FYnY0lQ5vaf8hbnKpL
         pSxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699937088; x=1700541888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZTgCsFKByoJopQFbKG9Iaipri8ykPsfvl0cVpNjUUX4=;
        b=kbdvVjpt8oeCaPgjixZiYGaNTqaNJgu392ziErRes+O5mon80WoelD9dhFdtLZVdH+
         An2sCeOFRNh/Wn8kDFihFEJkKahf2WfTyKQPDnemkeaie47XbTB04vnHRH4do/9afXIA
         vNkn4A8q942whRyavVx5xNuOJOcos4poUTQtHMQJh4XhZCl6biO3rZ6Vulb9eeSqFJqz
         ISaUuSrtyNTnW/ZNO86rz77s94yjiAwdnYMitAIz45zyeh6ThEMpfqmZ7WoyKR3xChOe
         u4NsK+FuG5JxVoj/ip/LRhJYZnFsMQoC1MZ7R5lTDgOWAFjUDmSdtwMWqIHqqngSEH8t
         DULQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwkWJS7BqxZNOmyvscMivTIrlNwN9x3UCzp+rddrWRaadeMr2ZU
	jaGmucup5iuCKMk3FfLs20w=
X-Google-Smtp-Source: AGHT+IGQrmG5XCtWycRnaHG3z3hvlWDwaUuQbFM7l7KjdkClBlXLj3vvjwsCW4X4oarJ2em8wM9/SQ==
X-Received: by 2002:a05:6e02:1baf:b0:359:d2ed:15f4 with SMTP id n15-20020a056e021baf00b00359d2ed15f4mr13435952ili.8.1699937087856;
        Mon, 13 Nov 2023 20:44:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:32c7:b0:34f:be2e:4505 with SMTP id
 bl7-20020a056e0232c700b0034fbe2e4505ls3486683ilb.0.-pod-prod-05-us; Mon, 13
 Nov 2023 20:44:47 -0800 (PST)
X-Received: by 2002:a6b:d903:0:b0:7a6:9f67:6085 with SMTP id r3-20020a6bd903000000b007a69f676085mr10593174ioc.8.1699937086977;
        Mon, 13 Nov 2023 20:44:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699937086; cv=none;
        d=google.com; s=arc-20160816;
        b=KnXomHnpHJyZxs+38ojpDTexK4Zp8KqtHIT1ok+X1xIaz5wsHTW/S0jFI2Q4BZAn57
         953ywAy8gHcG2h5S0D0PNdNa41orogX/TlUnDcU+wZTlfZPp7C3Ub6b73bQlSn9mOqSH
         jqjPPr3b3FMpuyha3kwt6m6A5j3oXrqg/epmeUxz12jwNf4xODPsTAKM7jEzeu9F/YJb
         QcJy+9Ku/e9MJ0JYf02ZMEY8b5nYj/GfJqw3HDM0t6Hc3PUXqjJyQECHtl0CjyXzLawK
         hE1ALdJ8uYnC9Cm2nixZ+P2RiAMA9w49JZOXu6zlO0g7gXX4ypbhmZNkAzUGlLgdCCad
         PI+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dTW82VIg1zc6gWMgLEgKtR0yngdsI70qEuPsuyspTwo=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=qTNaZxATmz/k6kVxWOAxDV4sL1aSrzijqvlAtqz4F1k3KD651Y6idhz4ohbu7ifKN1
         M5qacIznLUqBz9BHiPTF9wlI2+T0QMBAquQWbjfpCqLWoq5NMGRrf8s1ajTJIcohk8sv
         Q4Wsccf7Wfy0cqxPfwQSxlQLGWfMOY4xfwZuIR+xWM6pLbbr9KGFai5UfiXeeckSvI4E
         SMGZg3BwaL0Sem3AaS7TQJRwI5mx81kHCl52MttzFJ22yMSejuzCtOjE/JYWiEJgHjA4
         4qJHQ7oyMpF4152Bx7p4SfFNvTQ2yQeBRKvYOmZbYCoZFibk/zAflEYR5eMhtxT3dqRD
         Lrqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HRF58Fkb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-oo1-xc32.google.com (mail-oo1-xc32.google.com. [2607:f8b0:4864:20::c32])
        by gmr-mx.google.com with ESMTPS id 197-20020a6b14ce000000b007a692b26f2bsi642719iou.3.2023.11.13.20.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:44:46 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c32 as permitted sender) client-ip=2607:f8b0:4864:20::c32;
Received: by mail-oo1-xc32.google.com with SMTP id 006d021491bc7-5844bc378feso3004610eaf.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:44:46 -0800 (PST)
X-Received: by 2002:a05:6358:3411:b0:168:e614:ace9 with SMTP id h17-20020a056358341100b00168e614ace9mr1513512rwd.11.1699937086576;
        Mon, 13 Nov 2023 20:44:46 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id s16-20020a656910000000b005bd3d6e270dsm4044377pgq.68.2023.11.13.20.44.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:44:46 -0800 (PST)
Date: Mon, 13 Nov 2023 20:44:45 -0800
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
Subject: Re: [PATCH 14/20] mm/slab: move struct kmem_cache_node from slab.h
 to slub.c
Message-ID: <202311132044.6DE1B717@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-36-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-36-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=HRF58Fkb;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::c32
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

On Mon, Nov 13, 2023 at 08:13:55PM +0100, Vlastimil Babka wrote:
> The declaration and associated helpers are not used anywhere else
> anymore.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132044.6DE1B717%40keescook.
