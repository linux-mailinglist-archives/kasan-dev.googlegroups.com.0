Return-Path: <kasan-dev+bncBCS2NBWRUIFBBPE6VOXAMGQE5DWBIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C61D852745
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 03:09:01 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-410b8e90b4fsf11628845e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 18:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707790141; cv=pass;
        d=google.com; s=arc-20160816;
        b=fTerYR8/H8MgiSJfDksScd8wnIR7upjhj8UAvuCVgmi1wXx1wWZD1Cyc4gn/qqld75
         BfOR32ZUBgcY5uYzvRN7cwHIw4WiunXYaLHJNI5P9bl1aiV2h9PLV5toCkBT6EkgLjqH
         etdnLYKro++B3TcmnLKYQeunJzTWHaWyti/GTK0uHDzZXEfconFUNDI4iFEW6580IN7v
         Jxpco12jsqOKRz/pTlWTju1YSfx67CHud4pltHjaWx3VaS08jNdsqzgYGRNDFdrnF2PD
         WLHs4qGipUsm3fz2WpBcKsO56x90o3BHAddlDhzdsb06dy6k+f9GlFLYj+ypKn6UQK0W
         c2Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SIxIsY0zH5tNJ9PikwunnGVNx8DDBIKYGcRZ6FFYqe0=;
        fh=lWxOxxGC30J72+n9a6RsFaF6oxZ5PSHvzZ4cUNY6Vzw=;
        b=dUZptmWJJUcJwtyNV1IVY0RrdObVMWBvbor6yyNTgn3yXea1pTfmxyv5jWezwVDI+B
         sueL7c+/Ev13S7Fszjh+YyIrVJeyJUpUIMJPsQ60c2DyOWw1d8hX8BKXzRdWlMsKrHkK
         kxFf4Ruu9114ySZ9Ex/TIGRwkFC4OMTzirm2kYEdl6NoKyKxd1I5GFxOjsdYPVm6ASm+
         +krwA+SLBBPCj+tLhv5MmiGoxRaX66DQg78VUeZ9+YIwm5AtXJ5qsoemi4WkICL9RRQf
         /kXxhVV8PTBMeQ/MHl46Fv2BIC0YrnIC+8EPLkBmjCST9AOxWs0THkUynafU0N82IBUs
         WXtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jB3cf+to;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707790141; x=1708394941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SIxIsY0zH5tNJ9PikwunnGVNx8DDBIKYGcRZ6FFYqe0=;
        b=e8TyZ9iYZIVzsQKsT0SrxnQ7YbbltmHW756x7gXj5+Nvf0eUqaAK9E/2Ozi9B7SHGG
         7QP1m57KW3cg6sLXqz+bWb02Rc9aLieN8WVkyEh5yZA2IT2nkkkwt7zt4TflZ8UVouYB
         simu2vp2/kA1D6nhStGnn///h2HU/uREZFVBoUqn+FWtRf4n6hClZVNFfIQ2xqQg6ES0
         286RFx2PMsQkXEqUjVj8MFP3BeGU80CNZOtgZ8q60h3uyC8EqvvE8rcyGMewzGpANMGB
         1dRuI+9VNYjCAgWj5DGgIYNC4WrGmK7mZ3N3hO+xhNLZesobbMfHdZA4vzKgm+I02+4B
         A18g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707790141; x=1708394941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SIxIsY0zH5tNJ9PikwunnGVNx8DDBIKYGcRZ6FFYqe0=;
        b=oKzWpd4x/7OGAdmaS3FeC0HFdH+zku+eJ+kNccCet9/qqhxVLkAVA1h8lFxSA7ytFZ
         /CuoDqHO+fWqlwMHYSalevAuaZKv69201/uSE2E6lmJHJzYdEXb3mmEaBa8cVooD18gi
         zSPwZFYGxBaw8rs4fJo34AkvLbur0FvJbePIfBeV9Sybk+NQIBmZHM1dEi1nxn6Q3VrD
         W6UeuS6QJBxZMwo0kpUpNNtRoVjuDA+Kh2PIGZ0xDMO14J//CfUXVtWGZhs0oliXBckT
         Jn9KdhWOhZMTtzW+TCi+AbuZSG86hS2NXst2djDinqlFLG7wB4K7N4NJxYff3GW8Lhul
         U8KA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWioWXJbzQ0rKlQ9eYPXJQu2xmlF+deKIgUaX2ve1+6tJEjZ+5WUMiOAoYG1qeuLipyjmwMvvaCub12i1Ty2Wa5UD2Cz1mMgg==
X-Gm-Message-State: AOJu0YyfNDGPmSv1mqkIVlwLKSsPJcnpXuAf7M7NpfZLtnQYFF/vSY5E
	YBzgn6suMR+zyoRWcab5HUEoUPqcanOVY2W2OVsc1UbxqdGyjozt
X-Google-Smtp-Source: AGHT+IErSyvyuBqs77piGroWJGjw1phbqWUI4Ho9PyisBk9kQfOHHeuaOFG/0A1fNMKffn9ID3fWWw==
X-Received: by 2002:a05:600c:46d2:b0:410:8c99:1836 with SMTP id q18-20020a05600c46d200b004108c991836mr8112411wmo.6.1707790140660;
        Mon, 12 Feb 2024 18:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5006:b0:410:c9bf:31b2 with SMTP id
 n6-20020a05600c500600b00410c9bf31b2ls926861wmr.1.-pod-prod-08-eu; Mon, 12 Feb
 2024 18:08:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVqIiQ62Sbk6n0k5NgFdoSoxr4rDm2BglwEp0zuiewOQlN7LnOg3zJdEqNMov9mPLYrpQ0keYtLjXlKitC7pbiWg37smBqjqezBzw==
X-Received: by 2002:a05:600c:5192:b0:411:2f1:3ead with SMTP id fa18-20020a05600c519200b0041102f13eadmr2748800wmb.29.1707790139088;
        Mon, 12 Feb 2024 18:08:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707790139; cv=none;
        d=google.com; s=arc-20160816;
        b=h/2tg3fxpQ6DANlIriMdJ4+4sfS/kMlKEeb41DqdVKyiJbwBmBrqowHd0CPRlfVS7u
         xSLBwmhPnOVyd5Qz+PVYIcuyb+/p0Hqgn1BjWpofI7qy9tY8Zni3Sqogrv1x2eXfJXP0
         OlRW79DbG6Uaf+XC9WcggBkA4LXjKa7eq8oxGkX00Sz3UJVHE0qy+GgFUsLB1vS2Vcrq
         7ziyC93rybFcFDZM4jx8cgk1cp974hHII9VviOmXE3aTZ8n8EVH1DbgWJm83Ae2lSLUJ
         Sg+2gZqsuhpXGio7cHf7D3v6U/HMfCstJZeuZwq8bx66bwFKVEOEzYWXRnxsc4c0mKda
         Qf4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=lKnD7PD7vHFoDrdYFBy0aSAjzzsTiox2zmAp9jUaeUo=;
        fh=Oa5w4ySnO2aMW2sIRYjStrg4FmDBqiCJ4zFRIAnwhDI=;
        b=B5NyWP/us7t59z3Ss+5bLtVzzcBa7C+vGmulTTFBfLOb4NhdsnpWrkjLiB30MuB1LW
         3yYBdZECDFNpyaLOZ8V7eHoTV6BpSGrhVXKpyR/R8PHLFt0rbOGCQb9mKYrQYOgb5Mo4
         mkhMgoVNpiM3Z1jC/qG1eGnHG8JFBwdO8mQfwc1T+9a6GSvvXKoD7kgA6k9vgqpD1Tp0
         Xe0b+/CODk5PxXMtLrq7FX1s9IyKExX9ABS1J5vZ5qBcMgfdV3Wg1lZoidh8ypyfrphU
         /wuhGVV9JAwZqY/1F0DPWJp79DAW8Vory/5huXNk48LuZr7Zg92VAw0dSyV8n6ioWKWg
         Yn1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jB3cf+to;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCXMOy2+2nTh09YqDdpwG1OafW+pGozQwiMaagdxSqj+TdkrDvlDUrPNNmG47S/e3WtgNaUXeTcx+/1o/3aI5et2AV6Z1NiGvALLlA==
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [2001:41d0:203:375::ad])
        by gmr-mx.google.com with ESMTPS id cm2-20020a5d5f42000000b0033b1589d9c3si445915wrb.0.2024.02.12.18.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 18:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) client-ip=2001:41d0:203:375::ad;
Date: Mon, 12 Feb 2024 21:08:48 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
Message-ID: <3xhfgmrlktq55aggiy2beupy6hby33voxl65hqqxz55tivdbbi@j66oaehpauhz>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-24-surenb@google.com>
 <202402121631.5954CFB@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202402121631.5954CFB@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jB3cf+to;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, Feb 12, 2024 at 04:31:14PM -0800, Kees Cook wrote:
> On Mon, Feb 12, 2024 at 01:39:09PM -0800, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > It seems we need to be more forceful with the compiler on this one.
> 
> Sure, but why?

Wasn't getting inlined without it, and that's one we do want inlined -
it's only called in one place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3xhfgmrlktq55aggiy2beupy6hby33voxl65hqqxz55tivdbbi%40j66oaehpauhz.
