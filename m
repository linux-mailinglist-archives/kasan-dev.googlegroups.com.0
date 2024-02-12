Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSNQVKXAMGQETCTUWJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C88BA852125
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:14:34 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-363c06d9845sf29726215ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:14:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707776073; cv=pass;
        d=google.com; s=arc-20160816;
        b=lOVCf6TM6lj4aVOzEKf9QPbeaSw2BUvFIrwLsHwoZt3X6afv6SiM71kpPogh9tUkiw
         hKa15vUHV+7BJF82ZKDZuV0uSt5UCtMRSZjDKnimErqaN3B9ur1kdonj1y50cQuao0jJ
         6YS6YSdfpOibhfpOUMLeoyZQ9zLIRI6AJzHul6/fi4lvThzj+e+Mm6mHsrD+mRq93K8x
         B+pwg6wksNP4LFaQ5OUwIrxmb0WY4x4JGs9IItDKnYfBZHmnzJr0RQx0kxyL49GSUqP+
         8bDXllQhNUrpLXHxKEN99f8eLhtUirhsUuNl9kkIYACbJGDY6yQzP6lDp3yUhK+P3uoM
         Rlrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BbCWV9mm6QnLJMTT+Rb0qWlsPOJ/OQqneVHlxaQ2UHg=;
        fh=cbOeAYJy0HuNW8b+vEoII01cBj3/hkz+wdJl7jlDUgg=;
        b=za+bcvC+FmtZ/kl/tCfp+NB4bay0j/GLRi2GQ6aE23d/irWMwc3GhbE5yWwYm9SsJr
         HSoDVx3rSY8rvFRREYJ2ZlcQ4HqIZpiXUKN1OtDLVZNWgOHPSJp196dSKjJfFeczDodX
         j5Rm6c+fIPg3cLiBGDjNzwbtHLsmpzmCunhdZ2Rr2ZgNkCJ2ofzvsfxcnLjbJ1dbFS+r
         wBfanfgKy39Ymw9uIBkGPaF38G0gA7c49g4Ho6///z8WWSLmRIh8WKat85bcndIiXO7I
         XimA7Li+Za659QjO+tiWeJvOJvKbmL3gUq/4s8JRRW8F4DpgRlPbBe3kF/kKVQVhp5z8
         gHsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ebxay+aH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707776073; x=1708380873; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BbCWV9mm6QnLJMTT+Rb0qWlsPOJ/OQqneVHlxaQ2UHg=;
        b=vq24RkdarKLVyUX60Kcrm1kvu+8b0R1Xj+6RN30YdZ0U6RUzCaGRC5PEv3RYNmRXt6
         Ij86v6Y6S9qscatizx8g2xjsC+tJP8xR9sDsKGUUQ0oLSChQ+BKziwUlo7OmpnRRY5IM
         ebx5oLmg0+wy4fxpGAVN1VOX0DSn33fGuSir4ZQppFwZzBd/KGqjo0WlkGp202vhoxzv
         W2rxBLT1jTw38odXj8p9syPTJZuErkf11OWOcc9KetLVSkySZ66aPxalfj0gvx3NdzLJ
         xObioCtxkqs5ltdBXLCrW6j2RRc7HKjC1pJqdE20pr7zFwvJNtb540KhHFSszOgswYCu
         +K0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707776073; x=1708380873;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BbCWV9mm6QnLJMTT+Rb0qWlsPOJ/OQqneVHlxaQ2UHg=;
        b=cOV4EH+baqZPtPmbz04dgC45gJDw3LhFVTBn5pCqrov+IkhiG++3r0/GLMCbPsXdeL
         rXMG4rKjfXoAJ7oiecCFtgzI0qCg8/AVYJrhtTUmycyg8MOq9IAIZqBQsGDiWW5Gor7F
         N34vhQbIIrkXDpqLW27rA6Dj5ayivnWJXZ9/Vvtv+2RqaguIT5d8CMOs54uT4XS+wqjB
         QEdFA6ytME0CerISyduSYJXjox60hjKP+TIY4gvxjckw17hOrgMYpY63NmijVdiMBgm1
         7UmnDA+VncW0TDgYRT513d4+r2tjAnC6c1LZ84dDfXH9PdVT94DoKd/EFUyixvBAp9EN
         8IXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyTKqbUK+/XZA0a6ZeO3YZ5ZQlVGurYyoLIJRYGur1bsYyZp1QCJBudDtrHPfQxEAq5c7XkF5Nyw/iOEqnDBy9XKIbwJ9Hmg==
X-Gm-Message-State: AOJu0YwsntAlTpi4hq09hGkrN4IjTIf6ag+pazZlqvZFf8iNC+3pCD1r
	TEMaKFKZC7cuWlxdSKVRv72ocdl1YLY7NuPQvjzHggdfxMRu7JTB
X-Google-Smtp-Source: AGHT+IGwQngkCBi/ZXNqpfuIbFTKuebp/rYYrvvL5wLhfcrutxbaNh2jfPs9+NdOlsKjWBDHXowjXw==
X-Received: by 2002:a92:dd12:0:b0:364:1af1:a49e with SMTP id n18-20020a92dd12000000b003641af1a49emr203787ilm.27.1707776073649;
        Mon, 12 Feb 2024 14:14:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3184:b0:363:d634:8954 with SMTP id
 cb4-20020a056e02318400b00363d6348954ls2243737ilb.2.-pod-prod-06-us; Mon, 12
 Feb 2024 14:14:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWIDz6h76oso72EBFsXVuXSDkRP89kAerGpM331a0vyrBv2A/BdNQzRKL/6DGx5by8WeoFDz/zAPuWxZdyK39N2y5XOXoSty0l6GA==
X-Received: by 2002:a05:6602:2bc4:b0:7c3:f8ea:9dee with SMTP id s4-20020a0566022bc400b007c3f8ea9deemr8993180iov.1.1707776072757;
        Mon, 12 Feb 2024 14:14:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707776072; cv=none;
        d=google.com; s=arc-20160816;
        b=vbQGOvOnUJG+G9AnX9u2cZTpmJzZC0XQBXUBTMFEttphv+wg6WqcjPP0qheYYlDU69
         RYJ4wlveZid/Bp854qCc7Fn5WoIVxbpDC0DTsq/Zs6p/DkLlmrxLUPrylLkeSbfxZROP
         rOCHKazJtbzDDFdvajj6j12fbbz+8L+E2dCzAREghg/dXMNLAAR1RuCs4R7uD7bPM310
         +ibN0Q8TAfhAx4WxgEw2GwSi9mYTYEX2ClfCuUOQsKw0Pn8TOCSQad3Y3csyR+6mbWpu
         TwydVkV6vX4QsKqbdUWym8MDpLx4TAbN73boMTwUDmaJX/Xrni+rK8EfPgJpgyMQvao8
         blYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RIxrgJSE63hrU/LEeVrXgeewq/cIy3PkJ41qNbyzIVA=;
        fh=+3isrHCdyIC8MtCqLMoOw+LWMiPEcPZDMaJ0yHEVY2k=;
        b=JNTZRyjienC7BFlnkQpliSudepp5hkbVtjBmsE8epMIGelRyqFj9A9fH/Sf1gOOvBT
         lZlo8GA/eW0iWT2QzPRh5x5vHZSZqLu5O0YcT/JaBDhQs1piu2xsf0qg2NRKYQ6cWk2W
         GCPKUoPz92b8oao7LGLqi9OWOvL++sIba85+cT+n4dDlYBpyDoQc3Gl0Gf/mTkEkaQzT
         t5wMZ2l0NPnm2sSjSfJxTPuQIJv3WNXeu7w3W2DtF/C7lO2xiMGwQacb+uklG2D112Bf
         3ds/vkNzGZyDPS9Osd8KcbSgs0YKB+8CLcK+DaSDdQEqObdlksQQt9YSnHhoYxCjHj7o
         CWnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ebxay+aH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWqWgFTJH/LCdRUiJVkjIOuTIK7chGb6F2KQD262NyLwWYi0lb7Selef0FGLE32fr5x+BMwVTDTMKN+dUPvETK5js+t/dlwnv+C1A==
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id v13-20020a02384d000000b00473ac84c0c0si369730jae.6.2024.02.12.14.14.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:14:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id e9e14a558f8ab-363dfc7b029so11024985ab.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:14:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUaDxtYD25u9DbGoyXS/Z37jgJDBf9hgmT01eDZ7rD29sDXiqi3vburQYhu4YckScRA1n6at1NVzUQeaQ6xt5HvRMhB2nzdzR/yRA==
X-Received: by 2002:a05:6e02:2142:b0:363:c79e:fac4 with SMTP id d2-20020a056e02214200b00363c79efac4mr11358032ilv.6.1707776072456;
        Mon, 12 Feb 2024 14:14:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUfZsqRih2m+FDh4tQHU5XO+l+HULg6RfthjSPEgSF1L8lVb2/Vo5WZOYP5HB0ZQYOavxVxHn86LvXODd9uMevp7XfKPmmuZmU503c2+YOfzx0fusKuIWes56dUPhSnTCMS2J7qag8NQJi+nznp693wuuryCcNp0AjGzYZz1wtsEPcN/z6xE1gU+wygEMZ0d8WGOdzW9RvnygAEbmsQqmTOIg2c4HiOY5Z/CR4aWgH5gd3UcxAAyyFVgPFKLRed2QBPdUhs6peGVTjf2XDBijnCec3jKK3OZfczOVIShfLXRXey/wzfmYmtP0ElnxQetrli3GIKszGKX1P8UJgpSWnEw5DOomehPD/m/0Z9lp4wZNoZ+khtQJqwX2v3qdi2rlKGgIWdtuM+GDhQ+aIVoVEuEZZUk3LinCiXuAIHv0fCBXbopfztp7Zxu5WcEppXB8D0yxdZn0DNW+w/cndsVY/eKSTHCwe6g4MWEk6+Sw6sTHrh4ZWUGUhmKITdpt0vkLgV2jEMqjGdHA07ipriVZAwtC9tdnH+FeN3YlOZ6YqceujUTFcqXx666Qu6N9tPpRYtbIF5UAd+8fb2a9xC8+/rJyJhqciPTRKzJcMafdN5qVlzr7qgJdm6gfc0nSY9rfR8Fz7EhZy86HndK8RiZU8TzYtdtq2enCcv3lLxMMVgILgsh2hlS1t3PYAgVwehAxr18rUL1wGD4bAz5HD0LL7wuZgqhklk14gt5X8qYZ0m9xg4UOsYqpOwQwJiuKFRbaL3hDf2R6eyEGB7QC7EloiaNicvA64pgIy781Demj6wez1oZG2ytX5WG9RFu4i5ccmeCQS5t7aQiN3fgpFsFbkwJjqLvwuj3ZmppJte3OrzBQCgBhToP/Hfso0bNh9adEjqiV/i0kpTbCKgj7OH5gFoIOTbCy+Wb7fARaSof0IuY+K3N3OY5f4MV62Y3sn/87kG/v
 hrzUdWGNcSNaakr7J2etnPaENDkJ+52cddx/aLcRvgmVv+Zb+N88XBdYdTbdg0KEil/IvhZ5TrsjL2kwCyeL28+6L5fMM5Zp82EDeLEVZ+dhzijPuYd5Qv+Eba+6cwn8lnaOp9JbzT+33AFuja3tjrSG9oszhkhTy53A6aAv1hZ+DjU/13rdyIyyTxbqZ0HqQPfydVtO4D+KibeIZ85r5iXR5cve/fOtrhQbP4yrJVidm4I16seGlBTrQvXK/de58LVInMtGGFhSjJZvK8NBFA8bxKlIKe+3pbgp7ss/HFGZWAr2rqtEqCPa6Utg+hKOLTfNyzSYYBkXaeFf0H4vFLXoCptRX0cFzrBdQy45EsC6SAebZFYe9HnlRSkHkm1FWC5Qu2Kg8WCvY77Ys5NHUQks5VGg01C5Rc6BBgNjbFmJe3gEWZldNQCuw6/EQ=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g20-20020a633754000000b005cda7a1d72dsm922541pgn.74.2024.02.12.14.14.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:14:32 -0800 (PST)
Date: Mon, 12 Feb 2024 14:14:31 -0800
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
Subject: Re: [PATCH v3 06/35] mm: introduce __GFP_NO_OBJ_EXT flag to
 selectively prevent slabobj_ext creation
Message-ID: <202402121414.EACBD205@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-7-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-7-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ebxay+aH;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::135
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

On Mon, Feb 12, 2024 at 01:38:52PM -0800, Suren Baghdasaryan wrote:
> Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
> when allocating slabobj_ext on a slab.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121414.EACBD205%40keescook.
