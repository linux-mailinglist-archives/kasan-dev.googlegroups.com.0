Return-Path: <kasan-dev+bncBCK43AUPVMGRBT4RYCRAMGQE4T3VMUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id E447C6F3610
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 20:45:36 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-751613a8f6esf307974285a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 11:45:36 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1682966735; cv=pass;
        d=google.com; s=arc-20160816;
        b=cB4GWxGofs1vYtU4eyz8ORNpZzsyuuo3DG+goPet4UJrA6DtOKy2qhm/nUA9LiEhJ3
         Y5547DqgSMq8XdP3NWx/d0jMf69lMWtmvkQwFsy9nqQs8UMsVSy2NZicIOy7FivB9QD0
         VOrhPiD9KSd4fcJ8NamyPSz4dnxfbokda1gSxrkG4aOdZZxF4a7rFvSvI67nWfed/pp6
         v6rX8ql6UOyILkkf+zkXag/3bdvvbwQ5CUQGqzBoT+LBEVm75arhmvHeaZYtJVrlbkSL
         fbzGlXjFQu+ag6RJgb1L8RE10abzIM8xtx/Oftn67vvZF4n0RZcgP++Hs/p8KuSiMLKk
         gQtQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:mail-followup-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=AlGfxJegiYg2BJEZfk41ML+PiH+VmF2bMlGoa1ebUyg=;
        b=HYJ7qggm0GBeEXJ2hBuUM2TFTBblJbypMGZFjXxuMVMOZCK8GbNTJNA3bDYFHMBYo8
         1CrgKKb9vTW1WLuqCB+dtQ0MGF4nKgD9L+qMEcz4PYTXAMATQK3jAjxfbJKyjfcciEEI
         m/YyiVWS0d/hQJ64k0QL725GS3qV6BGEVBbSZ1P+bfHigGcKlRy56SwQ5QMWzWo6G4jg
         aCTc5MprVC25tjkl7Qm6UX3NYVFU45SKuncSpFZwa8I7qWL75MP2Q9vaFQC/cH7rUShm
         6u7yWVLjiGQ2HE4oQx/Mc3Ct6HH/56xMRQ8ogScZ1sWZ5IAC3Uo7aWsN8ZnLi7wpCTBY
         DJ+g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@stgolabs.net header.s=dreamhost header.b=M4zg8dWD;
       arc=pass (i=1);
       spf=pass (google.com: domain of dave@stgolabs.net designates 23.83.214.25 as permitted sender) smtp.mailfrom=dave@stgolabs.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682966735; x=1685558735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:mail-followup-to:message-id:subject:cc:to
         :from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AlGfxJegiYg2BJEZfk41ML+PiH+VmF2bMlGoa1ebUyg=;
        b=tX1HtocPY07EuywhVfVtn3rVyRMtgL3ny1ZFtNjHUgXwJ5hQX0vvkRiK6nTOaV0KcE
         Y722dG+igaZkh420XDr/d8aJ2tBVmDGxNPFGIvjkIVDrERT1KwXefTMzVEdmpvZewwzf
         V7acpgbX04sR0NnVhegyurxIkMSVnAbIvimDgzPR8ojaF6OHLkLvWdhtL9znvnlly8fs
         RIvgWwim5p94GDsM2AeEOUYrmsdC0oW6qXBhbIGLfxAseOJmB6dMd7brq13exETsIYOA
         21GJdqNutNJjpJ6G/sa+UU62Wd39Jt3NyOTv9QQIjJhtfaMCNu2K5/9P5NDXmyj3Pt2+
         2G0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682966735; x=1685558735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AlGfxJegiYg2BJEZfk41ML+PiH+VmF2bMlGoa1ebUyg=;
        b=X9z8Ocf6wn/WoBMjStN3eT5XKlv6+h2eZYPzv8sqFb6aURXEyV9xn4GdRo1wYyAvYz
         ImqI6+9/Fn3N5Ow8dnxhE/evsPKGYE2UVnSDvuCeyv7W/cCHc0jbEZ+zetOF+/Ojzde5
         JTTDYhjr/GeUOO4PmVhTGPHCgQkPFrN6kqBptY3Z4IW23uL5m4/3hvXXkxAQdmq/ia4z
         0qjvoa0UKQVZ8vZd3Ec8dTe4ys/cVQzatQbxasA0mF9CBLc1g8mrqwiyLNzB5/aeD8EB
         MigXCYtCsuD/jI06uI7uJHFqD4uMT4CJiasfdEC1Q0WiMwVUFWRCBIRnRxtqf5d+fQUJ
         5jJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxzBjoyEUhV3KdMWCp/O2Ir723FU0FbQbSTG5e4tHGpI2USuTSv
	0mqOJM5itJbJXWb1qKr4VGQ=
X-Google-Smtp-Source: ACHHUZ6f6whL7rRGNdjW+O0f+odtzTIXmFlCKqWy12sEbDmwzBDtP21b8JJydcEy3MnqnYGfCWy4AA==
X-Received: by 2002:a05:620a:4f:b0:74e:324:d6eb with SMTP id t15-20020a05620a004f00b0074e0324d6ebmr2486959qkt.7.1682966735641;
        Mon, 01 May 2023 11:45:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:be86:0:b0:5f1:684f:420a with SMTP id n6-20020a0cbe86000000b005f1684f420als7557004qvi.5.-pod-prod-gmail;
 Mon, 01 May 2023 11:45:35 -0700 (PDT)
X-Received: by 2002:ad4:5bc9:0:b0:5ef:41bf:d567 with SMTP id t9-20020ad45bc9000000b005ef41bfd567mr925208qvt.43.1682966735008;
        Mon, 01 May 2023 11:45:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682966734; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjUSM0alWcXFqc1XXxTpQAnXW1UyZiK3t8HVqnSIQv9Fovs59TYxa+mtcQzCqXVWe/
         vWplFf1BhfC2N4VrWm8csMPmtSrubgN/YnGq9dFHEOoy0B/F+UTrykPUwilaqhBarpfJ
         dLtf8UecrzLJ4PW2//1zLVHoEIDb1shKwYPLXasBQ7e8WQ8LlzmALYDw7nn4Zt4kMGcY
         lUippBIjMELnLayrKP3JrHF2+J1iVLUTvARfiVjb5SSnjqiWEirkXGooUoFsbtn5g+8a
         UlgOxoKGjwEyv/BLCLz+cvcAvnwJWKJ512b7g48JC41IsfBuxjtPMx7ARCNXqJQ2YMON
         LuZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=cQvIokD2K+NzYNjjiFicwOdl/ld8t+K11AzJBztMv5w=;
        b=F9rWGNTJmgAWGy/E8yYf659PqBUeIuA1hBX73LtfXEsP6bEktHWTBoMQ601wB7mK34
         j3kP0xQnJmpITk1RAthiw2fcGWrwDuehBkAHxzhpG3KxYtZXIb73vw8DswbVlPdrEMtl
         ZaIDzmfCj2T2f6KUlhMI40KjOUqXXpVPzdqoSi0sb0/GD9eDjr16Z2zLNJAmFs5YBC0J
         hPowalSDk6lQ7I9eWRNmnkP4gv2xLd0/DCuhsYEeMh+MB5ZRLAmBMdjHCHR8S8n/2qoD
         jLfev5kcbxaUHe11i4bd7DnPk9KAW0AfMyLLnzhERZe6Vph7bdTLT9fLg8ekNZF3wEOx
         Jbdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@stgolabs.net header.s=dreamhost header.b=M4zg8dWD;
       arc=pass (i=1);
       spf=pass (google.com: domain of dave@stgolabs.net designates 23.83.214.25 as permitted sender) smtp.mailfrom=dave@stgolabs.net
Received: from bumble.maple.relay.mailchannels.net (bumble.maple.relay.mailchannels.net. [23.83.214.25])
        by gmr-mx.google.com with ESMTPS id ok24-20020a0562143c9800b005dd8b749183si1627008qvb.6.2023.05.01.11.45.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 May 2023 11:45:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave@stgolabs.net designates 23.83.214.25 as permitted sender) client-ip=23.83.214.25;
X-Sender-Id: dreamhost|x-authsender|dave@stgolabs.net
Received: from relay.mailchannels.net (localhost [127.0.0.1])
	by relay.mailchannels.net (Postfix) with ESMTP id DB3ED7E1DB2;
	Mon,  1 May 2023 18:45:32 +0000 (UTC)
Received: from pdx1-sub0-mail-a228.dreamhost.com (unknown [127.0.0.6])
	(Authenticated sender: dreamhost)
	by relay.mailchannels.net (Postfix) with ESMTPA id 9AF237E1DF5;
	Mon,  1 May 2023 18:45:31 +0000 (UTC)
ARC-Seal: i=1; s=arc-2022; d=mailchannels.net; t=1682966732; a=rsa-sha256;
	cv=none;
	b=GssPTgy1netZMUY1dJt0qOqi2uu9o3Vc8I2Q2hinJ7JOiCOZViTldSNfO/nBcMXQgOajtN
	EYXr10Fn0G0mRRqbCwSJrj2q/P3PkGlzYhGgJ0uLpN7QFyO2sZUZmFG4lFmWNu2/vli5fl
	jTON8ykcoO7+o4ene9gDc26Kwo8yDZi9hvGBGs/9LPjU362yBlkzunPloDcGZYgAfIDci+
	B2jYyj+2R9cfE96l3nJC+U5qRf772uAQeYYvtaMnjc2iKpvnMGUmFzUKpBq1wJSi1d2ct+
	UtTFiWo7CciB0Wj9mznOiyAvEJKUmoOZrXdQjofgpOM+ejk7kOrpolPvvxJefg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
 d=mailchannels.net;
	s=arc-2022; t=1682966732;
	h=from:from:reply-to:subject:subject:date:date:message-id:message-id:
	 to:to:cc:cc:mime-version:mime-version:content-type:content-type:
	 in-reply-to:in-reply-to:references:references:dkim-signature;
	bh=cQvIokD2K+NzYNjjiFicwOdl/ld8t+K11AzJBztMv5w=;
	b=jW9Gv4YuaLPxzt7XbgIjiWNRg2GEkK7Qbzju1txTOuEK2rpEH8cEkbCUI3sq6pe9UsG9ZV
	6IwEqJNz7jFrF1ygiAKottFAKdPu0H3zJd2u9SR7KL5AM2Bi5WrCcWDE9Zh+ORlAHBL2H7
	3ANisEfBrkW2ZtUUc0bX3/9D2UepfzREnOivCi5iab55OAz1z0/joTMZKmUZv1df5sWqrt
	jj6SCIQpXYuiP6ivY5gur6dvtEGSyRsfzzpBWWyztLcjCFtqspyhHlK3OrXJgS+UJsqbUe
	NYVxUMIkkHqUog6dw8yKSk3XIutkSo2OkeuakUWds+Rm8Sx+d167ZmQQ0/EbTw==
ARC-Authentication-Results: i=1;
	rspamd-548d6c8f77-xstz6;
	auth=pass smtp.auth=dreamhost smtp.mailfrom=dave@stgolabs.net
X-Sender-Id: dreamhost|x-authsender|dave@stgolabs.net
X-MC-Relay: Neutral
X-MailChannels-SenderId: dreamhost|x-authsender|dave@stgolabs.net
X-MailChannels-Auth-Id: dreamhost
X-Minister-Coil: 6b0da0540eff8ef5_1682966732575_399059909
X-MC-Loop-Signature: 1682966732575:498050640
X-MC-Ingress-Time: 1682966732575
Received: from pdx1-sub0-mail-a228.dreamhost.com (pop.dreamhost.com
 [64.90.62.162])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384)
	by 100.125.42.148 (trex/6.7.2);
	Mon, 01 May 2023 18:45:32 +0000
Received: from offworld (ip72-199-50-187.sd.sd.cox.net [72.199.50.187])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: dave@stgolabs.net)
	by pdx1-sub0-mail-a228.dreamhost.com (Postfix) with ESMTPSA id 4Q9Bwk670Cz2r;
	Mon,  1 May 2023 11:45:26 -0700 (PDT)
Date: Mon, 1 May 2023 11:13:15 -0700
From: Davidlohr Bueso <dave@stgolabs.net>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, 
	Jason Wang <jasowang@redhat.com>, Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
Mail-Followup-To: Suren Baghdasaryan <surenb@google.com>, 
	akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	Andy Shevchenko <andy@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <20230501165450.15352-2-surenb@google.com>
User-Agent: NeoMutt/20230407
X-Original-Sender: dave@stgolabs.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@stgolabs.net header.s=dreamhost header.b=M4zg8dWD;       arc=pass
 (i=1);       spf=pass (google.com: domain of dave@stgolabs.net designates
 23.83.214.25 as permitted sender) smtp.mailfrom=dave@stgolabs.net
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

On Mon, 01 May 2023, Suren Baghdasaryan wrote:

>From: Kent Overstreet <kent.overstreet@linux.dev>
>
>Previously, string_get_size() outputted a space between the number and
>the units, i.e.
>  9.88 MiB
>
>This changes it to
>  9.88MiB
>
>which allows it to be parsed correctly by the 'sort -h' command.

Wouldn't this break users that already parse it the current way?

Thanks,
Davidlohr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm%40jkgvyuyw2fti.
