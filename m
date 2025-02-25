Return-Path: <kasan-dev+bncBDK7LR5URMGRBTEU7C6QMGQEJKU2FQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB334A44A22
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 19:22:05 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-43ab5baf62csf5309625e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 10:22:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740507725; cv=pass;
        d=google.com; s=arc-20240605;
        b=S1UaBKo6umov2jh3atlcS4Jb+hb1yS0nCNpKqHZOmx33+7KxBCAZprDFk4yngULeOV
         9wR+TM9xu0GAZy1m214pZ/IOK6RwRYfOwfEZl/KKiGmv6jzRnjsQ62mft5rH2iN79RYm
         DAjxCNsYtTlHRj1ppBT4Wiz0c5orxFuv2KBpb3FTE2/pDEFDGeQNRUXt1D7tIt0h8aub
         lXM9GqGee2W6wQF2LpiU3cHNpTGgunyoPcPxcocXyjbYmz5MDcprfsxNY1skezoZv1Xf
         vzFS3SnCg5+wCDHQuQpejT2OJ+miqtrCR0n3Vja67G83QQt9MKvAnWFld9gAelQmsIma
         J5eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=BiX2w7zfYLuaAmLURxTb/pimO+8cSJ/UgFR/161WoYo=;
        fh=kX0AAitfx6dayvgVaGVXZt7VFUqOf8wneUyXGj+e2gk=;
        b=F1ciKWBHrkZqi7Ue3bSDwsxBsA7m5ZvTUsb+BokcmAPxyDH+IfWgX9AV8peMHGqr0Y
         XHIcFHvmKl64Kjo63Pq+1G5k8VoCTPVXeNHYDNiIrWSmCy6NB4wEWF1GYwHAvWSrzrMt
         HXZUFlCzuTBypyNLo2+eIB+48TtcZbL/6uB4EOifSXcsx0lXdDev6eF2UXm3a2Mo8Lu2
         t1z5/jj1GvxVFkrX/XOxTFG/0pZWfbA3BgRqC3hjo2qRfIcPOnWW9i9tqYLz2eY2kuqL
         rEN12qPAb+qo+gbx+OvIsYo+F3ybGuJNUOLIkTbc9x7I4LJ0odKHz/dBXRoJvbb0YQ1g
         UCVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cBki123X;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740507725; x=1741112525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BiX2w7zfYLuaAmLURxTb/pimO+8cSJ/UgFR/161WoYo=;
        b=CUwUgKs3XKfkcJGWHRN2RDRraUOSiyeIz37Q89JHL3hmf3zFR4Ep6Bm4LWPpkqFM2K
         4nxsy/X50Oey+rM1Mmv/it4S3UyODuI9oX0g2p+8ww1fd32LjmhFFUSfy/yZmYitwJ1t
         I5KsU4Gs1Iq8TWu3V8q3SrBs7qE7API7skypIB1qtzQl+99rzOxSNsfxeEBTrPln0stJ
         K5V4z4jXZPhJFL2Psgq8Wx1v4fMoRnMcv/ywq7J/9d94+fD41/gMrJKTXxyhwGInFmn6
         5pOlMIEQIjZyML3FEEHc1ya6mfU9BouLAtkK6gg2uEx022fXInjiSXlG/0C5rqSQSKuo
         NCrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740507725; x=1741112525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BiX2w7zfYLuaAmLURxTb/pimO+8cSJ/UgFR/161WoYo=;
        b=KCuiWIJAq9wtFd3XDn8d1PGnWBMFXSPDsaGKzhbEccX6TzmhyZPfXZtnkxaoX/MGlU
         /j2sS+h53rm68hus0ZjIAGFmjAaL5nOpifnxlDWBl8y6ZNmDcoqFd3Ohm/OysxmFNOw9
         vIYLmSe93Le4l4mQxUGz90NWeKF3HfgS8r3qNECmfvmX/PZ5qwePJb5F0yrWENTcD1aJ
         /ljyHz+3iJBNHYYEIzUr4LhdPAUaYf7latwsf+hLNnKR9Yy2vokvF/aER6G1ASKeoKhe
         i6N2CAW6/JjXD9ETqwfm1SZ9csm8c0LKbjZgDzvad7eToJdro/HUr2VhqfmsME21Xaeg
         EG4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740507725; x=1741112525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BiX2w7zfYLuaAmLURxTb/pimO+8cSJ/UgFR/161WoYo=;
        b=YSe7U5NvIZZNldwXfoCDcmdHTY8+4nhzQOxAZ2vjdM97HU6YT1P+9JC9klkLm/OAnW
         h2aCqH66WW0tBNOqOcx/IisaJKlQn6ffn54S1Oze+yF0BW1HABI1+R0A6VOAjM+y71KN
         ++aTn2hnWZjkF9f6tEkgeKTVxoXbDOnxSH55zg9rQfhJlAwwy568qFxbVkAjS1cVuBiM
         4fpuzjH3RiB+6dYphoaiiUjbwFkj1fHeIYZAP4uUy/zosCmvS4UJOpnsTgRVN/gyQGRv
         Q0loDK+oLX/ozZfCromzcupssnxQT08WtW2v04zBy32e8/T7B2cZNPDuw0nBj8esr6q8
         tTTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbI0qw+oiuOH25uhkD1uegFPm3IQsJ1nKd7xH9uevZVH7/4cixHeYZxHDoAWUOcFBzuDdjNA==@lfdr.de
X-Gm-Message-State: AOJu0YzxWzAyXxF1JT1yMQ6cnzl39z6h6bxB9h/db+FPZw09sZ+LbiE8
	Ol1UFUBbU9R8xogPT6Ix425HCRRBVIHjb3a3KwyuGP8SoIPjcKgB
X-Google-Smtp-Source: AGHT+IFoR1TTnPfD/8QYv2gAVARL95VcTQ32gMFLhERDdj4DvMqnL0PV4Dn1fLMBlMnZCZBwsq2nYQ==
X-Received: by 2002:a05:600c:1d0e:b0:439:6712:643d with SMTP id 5b1f17b1804b1-43ab8fd8620mr4823295e9.9.1740507724473;
        Tue, 25 Feb 2025 10:22:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGDxHkAm+/Q+jYw1rPeVrNSsPpvbrNhofMTuOkhfTKakQ==
Received: by 2002:a5d:5f45:0:b0:38f:2234:229b with SMTP id ffacd0b85a97d-390d4fddbf0ls24469f8f.2.-pod-prod-09-eu;
 Tue, 25 Feb 2025 10:22:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVcywBeH623EAjm2T5lrAaalftgH412w/pkZpeD4bAOJANhx1tY1d3oIDkA7VVI7w1EbhBT85i9/dM=@googlegroups.com
X-Received: by 2002:a05:600c:4506:b0:439:6e12:fdb4 with SMTP id 5b1f17b1804b1-43ab8fe90camr6034425e9.14.1740507722518;
        Tue, 25 Feb 2025 10:22:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740507722; cv=none;
        d=google.com; s=arc-20240605;
        b=TfZCq5S4uTEPtL9a3kIoxgzLW+8PAwu/na2Ddqvo1qt+koSvnQ6sOcdcn82F688gW0
         +VUvMVqJgBSUG+nJ/xBd+LuQeNJnEP5CfV9IgSZO8Q2BjSS0H+ZwGgk/JW6xJ8UmoQGT
         QYLkXvcV5a/gqBgIFOsk/zAuAVwsywCDCL1yfsVFwBH4rMuP/fSmUO+vzU3Bq5usMPWy
         1dBZ4hNmyMhOzJ1qDTwyg3QEr1LJi9+tILOzGl4Z05mmeJ0QrvU+GffJL4qk83NpHk62
         XkXLANg+kH+fzEGMq0HtK3a3RRxGjlzApSJ1HuAzo36ZILqj4c8eMrc3XIfnBv1tsZLY
         dalw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=CAEEVhldvoc8F0ob7ntJxWjSZWN8MGyNUwWibkuTCoo=;
        fh=N5VpJ1A1OTdZ/O4EwczOKGahwN7niSBjlGTc4KlJ/sU=;
        b=ejGK1yFLG4N4NW4yNhnzWorUmu/j6sp1OduhoZVJCXGH5P6QfKMQXQANlLDoVjg2Mj
         AKCGL5vVWqTwNdZtdQYcTND8nYsHCFofaj5ixcFl+c/jBo0txQ37LpR6uXCEqb66xIOi
         2zYfc7FANCoPt0/6vJPelGgZeSIaL4LxLv+z5ZtLBuhdx6XuAe2h8vyrWKR+E+gwcsF1
         0Z9XBmmzAnPtYV9x4ni6KFlb3a1fDjKxdyvW1lTJE3kGcAJXy+MjjnO9ulntkockPKOD
         eafzkuitKTjhDelDqanJuddQUcitKmzGqG0Rt/VsKeIjORkCmHe5lMKGBDYoAXo2hTxJ
         0eZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cBki123X;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390cd8fb00bsi107337f8f.8.2025.02.25.10.22.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 10:22:02 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-545284eac3bso5766855e87.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 10:22:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZz6zUy8o29HfhJfPKNWJq4LhWyEcFwq/HfkDJfYixOH9w+4aA9DyCV4l5+T1BYBSMShztbG3fPM4=@googlegroups.com
X-Gm-Gg: ASbGncvelUKsTgRunfXEiHJsLEWjWjS3O53qJe8qT8779x9eheVqzeM8zlkDrnbqOcd
	qwalbuyp8cXTHkjlUrDpg4YjyA/LAVQbdPOeB2swAdcefA+KzISeN/sgrafk54kZQLvNx1WJXJk
	d8E8q6ouq508PlkFZDXPN61sdr1vb7PEzdfKNCEg2xSk4Gf4fjA2eynnAehxzdPhYPK5qLHxUq/
	QHAznvlq+k+OvX6mfR7AVg2cuKdL9TNVAq+uzaSwL5gRdb5MtravRQXFRk9JpnHpnu9gOPjpnjC
	cwNtMOEy2uJfO9BxvOaMo1uadi7RYES0ePSmt2Idj05RvBnK
X-Received: by 2002:a05:6512:3ca8:b0:545:576:9df8 with SMTP id 2adb3069b0e04-5493c579f97mr311547e87.26.1740507721477;
        Tue, 25 Feb 2025 10:22:01 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-548514f9ee0sm241429e87.219.2025.02.25.10.21.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 10:22:00 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 25 Feb 2025 19:21:56 +0100
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Keith Busch <keith.busch@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z74KRHzSNbmUJUWt@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <cca361c8-2f03-40b9-872c-0949dc70cde8@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cca361c8-2f03-40b9-872c-0949dc70cde8@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cBki123X;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Feb 25, 2025 at 07:11:05PM +0100, Vlastimil Babka wrote:
> On 2/25/25 18:41, Uladzislau Rezki wrote:
> > 
> > but i had to adapt slightly the Vlastimil's test:
> 
> Great, works for me too, thanks!
> 
Sounds good :)

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z74KRHzSNbmUJUWt%40pc636.
