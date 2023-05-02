Return-Path: <kasan-dev+bncBCS2NBWRUIFBBJFKYGRAMGQEPSSDIUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D1BD6F3B34
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 02:11:17 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4f00d3f91a3sf12877998e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 17:11:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682986276; cv=pass;
        d=google.com; s=arc-20160816;
        b=HieGLoF9YCNZsPmBP0wr6IUfsGcnudjFvf3Efr6vaqALgeBsknMnYlWHqaUT5svlqh
         PsN6zkX5Pp9gx1JU9uuzqakhzvPnUSVjh6lqkiWERxF46oir4YYbJOF8s1IEGqI3XqZh
         FHwZkih6yuCs1nrdI4BOpXGNrU8k2cWbwoSnEzqzan+W30DyN0xQf8M4PH8MwgB1fbpc
         QRZK/EOwfmd4UHffajGqYw075jvtr1dFbyRkQlAYpuu/4OpSPgcFG6uS07x+zVxiNxnQ
         cqwvO6Gvs0VmCZZgOqxhz9kf8Y3Uqch3nGowlQk1+rDCeXguTnInm/lif5lvMQJwEB/n
         NrIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:to:from:date:sender
         :dkim-signature;
        bh=aRm+ktkEY8TsSBVZj4YGblUTPAUo+U8DxEJ4/JEXF7E=;
        b=j2R3l+h5ugCt1YjySne49mqT4P548WWdq+vqAaS9BATM3Jt6hB0XiPOYnrUZKVV7w1
         kPxL4wljKRzJ1511bWSkYS6uXtm6S4VLtYpvH6vN/capwyKu3HGAfnv9wnxK/PRLLs9/
         Tz//Ma4BDTiQbV2V1k9JVyki7r5mdRgPUS+PvhSXjx9duD9VnjDbr54CXf8w+hiVE6hG
         e6Wqv1iAfawHRowNUsGsiLjMl5zLFwsT6V0NEJcVAQ8wW6XREbopn6qEyIs3RBZU33Jx
         DjEFm+k/UiUcdyD8Glhp+8AHe0q/TygJzQRaiZo1eepelznEH8tIxo88Oc73nKqvsTVx
         SPQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gmp5ZD9n;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.57 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682986276; x=1685578276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aRm+ktkEY8TsSBVZj4YGblUTPAUo+U8DxEJ4/JEXF7E=;
        b=F3mMWf6BjZH1+eFjQuRFIvKE6Q4tvvE4d0SnZceVkm147f84SUcnSj898BPcocpTDs
         +DQuxlXiHb2hiUfA1sYwj7OX1ifBWQh2kpN5LQIzkptLFbgaBuldgNoMt5lgmrfOYhnW
         JFTHDaFhNWnC+5a3V99I9xYWqP9MF6TeX2oVrz9Z5p6I0tQDSXvIdXrDCwLM1JLNmAUZ
         ZgRLtbHTlHitxwl3RsH6P1WMzz4t/6i+xCCZDuhddAGxAppKN60b5o8buhLJPqOxddjH
         qJeLHIpJgCRfWafbS6ZFlC2/GfNw5ev/L+mlYKsKt+bJ5PdiopoyEm1E/TRcUCfMKZAL
         NP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682986276; x=1685578276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=aRm+ktkEY8TsSBVZj4YGblUTPAUo+U8DxEJ4/JEXF7E=;
        b=LKjGZ4zBl/dtLBnilKyqDyuQdz6NOkb818McTzpab6mBf79h2s5noiwvWCjMSZ/KcF
         PaPj1tF7lb/wE1NIpjIzg8xSGz994ygb9HfLJ8DhDREvaLYAf6v6zCesQYbpfvaVb8hQ
         PTTHLZ2B3vayNUfbKsEpPbC0iYqqG22SHDcnk2plhrfSz5Kack5If/D4xvcp/33rAyfj
         oENhV7BerqSgbi3PUoSLVn097mySOu/CeQsEERlCkqQ66GHtuv1Z0k4vLjW0qbxyq6GW
         kmIL58sRjYll6tOUpdvwZ7ZSTiR6gh5K875cHEOXXz8tyAMeYcYByeLG9KJbAMU9y9CN
         atTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwgGxQMzjQ9DxZGStXcpjAs1iAOh/7Hwfb+yq5eu/cbICpJqQH1
	3/7MzNphfy5xO7UvCJsH5LY=
X-Google-Smtp-Source: ACHHUZ4RKZUTNeHBLq58Hj+GSwHYIacIUyuO0Ulo6O3N6KzbahF263lMOVgzcpQk4LC14IsADUaN/A==
X-Received: by 2002:a05:6512:3e08:b0:4e8:6261:7dd0 with SMTP id i8-20020a0565123e0800b004e862617dd0mr7229218lfv.4.1682986276574;
        Mon, 01 May 2023 17:11:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d29:b0:4ed:bafc:b947 with SMTP id
 d41-20020a0565123d2900b004edbafcb947ls1459409lfv.2.-pod-prod-gmail; Mon, 01
 May 2023 17:11:15 -0700 (PDT)
X-Received: by 2002:ac2:5686:0:b0:4f0:dd0:eabd with SMTP id 6-20020ac25686000000b004f00dd0eabdmr4745253lfr.21.1682986275204;
        Mon, 01 May 2023 17:11:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682986275; cv=none;
        d=google.com; s=arc-20160816;
        b=zBrYe4JRwPqAa8IuReJcIQ+QG+NUO3Gh5J3erVXD/sFPJ3+ORa+kfdm07E4GG3tBRA
         3OieJTWiNHa9wB44qNR2O3CvQzNZVLzp0rYlo8WFuh6vRIFoSdH7gnWgffh4AsnDCGVG
         Kk4k4YanuAsi0/78xy4pl1l6X8lALkZHuvbttMtAtBmmlDcJVt8DOoOrCulcUaAm94Ku
         2f63cNFQUaIAgZVLb+PPr4FpSpsBAlryeujMM+s2sENnN6Nwpfbpuw6P64Km0Aq3tIKR
         pMMS6GIJgZQV3Zl7bYTz1ptRi7J6ZtyANX0ZrZPRIRYDyiLgokQkPvoA+PJ18mOOcmdq
         /33A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:dkim-signature:date;
        bh=LGkXxcXbL3GK/fmGgSEfCfzDoWKBFDwYj9o6aWx8/Qk=;
        b=wscIKhfy4MteHE0jWJY9K2l2/zJ6LhwnZ2iL0GYuyksjtYrp5/MmHZUeY/JnJ1f4Bg
         RyW1nKPhLX5KU+wvZOOhP6ihw+bRXEpK4SyJats/QK/AZbucveXokCkL0xHLjl1eyFQL
         LAaCHeuJPJXjiDrNC7Zbe/gcCcA0EOqaDRCc83AHrN2KjNI1xyT2f3ElfSbzw/Lq3zO6
         Gp2ru1l/7iDlQg7JzWnmmEBmKdQdN62rTe72jl0bURP5vWJhBaVknNL1QMtQVAYBw7zw
         dfUofHUxS23TT34eqmz9zaR6L5FWLKFQUUgTQdoAiRnsDkBvvoBe2e4LFhHsXSk4Wac8
         I0HA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gmp5ZD9n;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.57 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-57.mta1.migadu.com (out-57.mta1.migadu.com. [95.215.58.57])
        by gmr-mx.google.com with ESMTPS id br35-20020a056512402300b004dcbff74a12si1927603lfb.8.2023.05.01.17.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 17:11:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.57 as permitted sender) client-ip=95.215.58.57;
Date: Mon, 1 May 2023 20:11:01 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Andy Shevchenko <andy.shevchenko@gmail.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFBVFfNo3OHd3izd@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
 <20230501213349.bvbf6i72eepcd56m@revolver>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230501213349.bvbf6i72eepcd56m@revolver>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Gmp5ZD9n;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.57 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 01, 2023 at 05:33:49PM -0400, Liam R. Howlett wrote:
> * Andy Shevchenko <andy.shevchenko@gmail.com> [230501 15:57]:
> This fixes the output to be better aligned with:
> the output of ls -sh
> the input expected by find -size
> 
> Are there counter-examples of commands that follow the SI Brochure?

Even perf, which is included in the kernel tree, doesn't include the
space - example perf top output:

0 bcachefs:move_extent_fail
0 bcachefs:move_extent_alloc_mem_fail
3 bcachefs:move_data
0 bcachefs:evacuate_bucket
0 bcachefs:copygc
2 bcachefs:copygc_wait
195K bcachefs:transaction_commit
0 bcachefs:trans_restart_injected

(I'm also going to need to submit a patch that deletes or makes optional
the B suffix, just because we're using human readable units doesn't mean
it's bytes).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFBVFfNo3OHd3izd%40moria.home.lan.
