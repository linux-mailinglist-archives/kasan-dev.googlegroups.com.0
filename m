Return-Path: <kasan-dev+bncBDCPL7WX3MKBBJUDW24AMGQE4BAHYPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E4A7399D870
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 22:40:07 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a3972c435dsf38562645ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 13:40:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728938406; cv=pass;
        d=google.com; s=arc-20240605;
        b=R9x+Ad7OKcWgUdevodX2l0Pl5hn+NLp5Gvs5KzwlEKdXGmvzXp4sTIyxvTz7vK9aEp
         0Hbz7C6PJj2XpqTE3tG0B5U/nzlJbbvXaYcK3aUEpioT/fDGmdU05uENJAo2F2V+Jhqv
         wmV7SrzDuos58xjhKzDKJLt8NdDS2f6bhB9VjcShW88vAYyMXNTKeeeKMyX+/dz0NIOj
         ijwGW87rpCqYAat7nBy07Y9QdlZD65WpUQPJ7cSZ+4uZOn4UNOshsbuah7Ic3HyfAdt+
         J+PlIvcEtYLUAwJ0D8lY0lTeuX63y26EhL6gJWuVDeoLq2GoqlFK/xjQNryVXo6+O4vk
         QP1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=65lwIPF6hChuzet5Xbbe5wfYotcGnI+ERO0dTNHYRSE=;
        fh=oFUP4grIgWnTGeJI2eQPLjSlIQnPJlsPjO4nDtrTdVM=;
        b=Z8N1BrWaBNHmiv+fQHXbtHuaUnXm/qKRDmbv/CT4jQdGopQVQhofboRZT1zrb8fiiK
         Ci8jhQTdNvO5yuJAk/0IUJWKQKgrV2w/zzPy7M3tfpMO25UIZJQDwtDRlP+NK/fz3xpQ
         CYal6+sF0Q/L5VmbW82eSZLknsT8/kDG8HdOZK/CxAcJH98B3XWEnqPESMGNt0Bv/9Jd
         qNLLHophGDWjljOJltN2AYj4ywfIQR522k6R0pPqJZWjAE9shHKWEJo8kIt+vqH40ACa
         5sSyikFBDxofoI1Ti6sMZHMVmO3CMsPdUl+kP5w/19aX0P8s5XV+v2aaa5BVEnnkTWkF
         F5cA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HFuElu+S;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728938406; x=1729543206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=65lwIPF6hChuzet5Xbbe5wfYotcGnI+ERO0dTNHYRSE=;
        b=wNy+7I2X8Lx67eRWp699zf+7mAMiMihnU+r+RXDbKTWMLlXmV9oAsacGAYUO4dL2iz
         FeMOcev1MBc2SBuhcBcrwRkmDsAPuQsdkRqDbng1n6zLKOGutaWxdmfbUIb8zsvImm6s
         RET2+1HxW1TNLXnptm69j2bEDh7gsfN54mRi9QFGR0axSrtaW0s5gZLybvyhFetjsAGH
         RKGWDBCGOqd126+1JKufjRXFZF6bwoGHkEIW7zacSTiZlQzHeulw/oyZvyACuVrKOfC/
         PPEZ9HXvPvu0FDWvG3aJ1CVaKRKYr0Me7hmCUfKLW7sI8rW2i7fdd3awOcf0i5wNgojE
         w04w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728938406; x=1729543206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=65lwIPF6hChuzet5Xbbe5wfYotcGnI+ERO0dTNHYRSE=;
        b=sWLn76WkOul41FUwpGdLxmTbtq0o3nHyyxHsy7ouC8nCaTIYytB8xF96XJbdmGqA4M
         4E1hc8vrux3p/mFTahjVDCX1AxQi+xuS5eHEWqZLJO9Y74Go3riI94UGGykd11sDbiHV
         Im1z1jKekD7VEAfXe0OmrZazwNqajebUn9WwGyPlzaNBjUDDGMp9EqtBcM7oit2ji4v+
         6cF4DQqvQAkXTRexJdu0h7WW1a2X01scHyNBasmjpFeXcPCX0KtZTKcNqfcbAgLfm0nm
         +9ktnqSI2JKDg/aEK1+Zxf0Nnwk+pDyN8WWKG5q1BFRs+CkeR0IBbaGhw35+N1GSqE/Q
         AuQw==
X-Forwarded-Encrypted: i=2; AJvYcCX2kZSTsXR9b94pycs+b9XuaA8j1EwwOzBDtq2DoDEfCaWe1bcQMNScmwPPZ6IaajDB41J4dg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5A0LyJT+0psO0eqMlqXm0igRbn7RW2eBqV/6C8UATwNMHaVut
	hIpqgtnNJRoG0AvVLN10Aegh9Ea4duT9w9pPfEBj5G5M8Dx5r715
X-Google-Smtp-Source: AGHT+IHrF40fsHuL8HXaPA6GbqvJo+i3R95lI5DQBT2S3MVl7xNVM+Ww9Bd5SvVlD3nhDJH25bYiSg==
X-Received: by 2002:a05:6e02:3b0a:b0:3a1:a57a:40a1 with SMTP id e9e14a558f8ab-3a3b5f233a9mr108913865ab.5.1728938406470;
        Mon, 14 Oct 2024 13:40:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c24c:0:b0:3a3:9c22:3a4a with SMTP id e9e14a558f8ab-3a3a736d09cls4448425ab.0.-pod-prod-03-us;
 Mon, 14 Oct 2024 13:40:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxL18i8k4J9cYF1Xzl/zY3nILME3+d7hWvLrSDZXwExsYYpRH53pWY5BGwWIZT7CN7ahIKnMjoD+M=@googlegroups.com
X-Received: by 2002:a92:cda4:0:b0:3a0:98cd:3754 with SMTP id e9e14a558f8ab-3a3b5f237d3mr108901665ab.4.1728938405691;
        Mon, 14 Oct 2024 13:40:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728938405; cv=none;
        d=google.com; s=arc-20240605;
        b=ZXNONupBLC62gP1niXy9JJhaoxCdB7m08V6V8bx7+OFVc6avBTCiKmU51ESHlleAnB
         Ei3AoBeaUrsc/NOIJTOtN6q4e7fHgbtwOgE1XxwEuO5QDcA/cXtpbtuaxkiFTFZuXRwo
         X2oDeuAw+nx+KYBqRyRrGAIACrkwWaFjHYx3BzaLb8OwIUQG4PyeEpWW4ZCf/M3xMC73
         odvznGGAcsPwRWCwHbnyieF3xybjmbmIJ033eUzTrxz898EYsk3LWpt9eFFWiKVcHo5E
         47IK94xILCoC4zBiMmqLUGWwT7lVugi3plZoid2W3RmWRX4pCC0bJEO3EujhFSr0SEv+
         vBxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JpA8isSkiSsTyZgcyEd6H9Gd2Li40TbqfNGJk79VMEc=;
        fh=LfiGFaV0Bke3jCLi0K7su87y5qYOU56hXww4ZTZKj8E=;
        b=A25N+4IrsZHck931/agP1tWM89A4I7MceIolRMs5YKQYdgsPW1vtIix5G2uk4vlPo4
         xKMymoUN4sz8sj2SANaNszwVmYMZ/tMrX5bo7BatooZRfW81gXSz0zvyWGr9x8wYEUVc
         lcgVU82VlaGCycSGpA1mCu9qfcReuzodb27IxbhfnXUqPt/iKE+aX4vrg/DrvFf74XYz
         nQRtnt0i6TM/KBwTW/yb0FMM+bd5SEwntzMEUJVsw+jLbHWAtcMSQ85voCDBI0gXePmj
         l8pVg3w83E52C0VurKIf/1nHYIRmLg6UQi+sL9NAXCV85+wuE0JMm5c2FGmo/YqjQ4xo
         VSMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HFuElu+S;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a3afde5fe1si4292715ab.3.2024.10.14.13.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 13:40:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 058D0A4105A;
	Mon, 14 Oct 2024 20:39:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7A439C4CEC3;
	Mon, 14 Oct 2024 20:40:04 +0000 (UTC)
Date: Mon, 14 Oct 2024 13:40:01 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Eric Dumazet <edumazet@google.com>
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Message-ID: <202410141338.EA1D30F3@keescook>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
 <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
 <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
 <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
 <Zw0otGNgqPUeTdWJ@feng-clx.sh.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zw0otGNgqPUeTdWJ@feng-clx.sh.intel.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HFuElu+S;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, Oct 14, 2024 at 10:20:36PM +0800, Feng Tang wrote:
> On Mon, Oct 14, 2024 at 03:12:09PM +0200, Vlastimil Babka wrote:
> > On 10/14/24 14:52, Feng Tang wrote:
> > > On Mon, Oct 14, 2024 at 10:53:32AM +0200, Vlastimil Babka wrote:
> > >> On 10/14/24 09:52, Feng Tang wrote:
> > > OK, originally I tried not to expose internals of __ksize(). Let me
> > > try this way.
> > 
> > ksize() makes assumptions that a user outside of slab itself is calling it.
> > 
> > But we (well mostly Kees) also introduced kmalloc_size_roundup() to avoid
> > querying ksize() for the purposes of writing beyond the original
> > kmalloc(size) up to the bucket size. So maybe we can also investigate if the
> > skip_orig_size_check() mechanism can be removed now?
> 
> I did a quick grep, and fortunately it seems that the ksize() user are
> much less than before. We used to see some trouble in network code, which
> is now very clean without the need to skip orig_size check. Will check
> other call site later.

Right -- only things that are performing a reallocation should be using
ksize(). e.g. see __slab_build_skb()

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410141338.EA1D30F3%40keescook.
