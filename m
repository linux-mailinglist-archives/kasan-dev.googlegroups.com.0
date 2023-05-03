Return-Path: <kasan-dev+bncBCS2NBWRUIFBBQNLZCRAMGQERQUIL3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id A4FBE6F52A9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 10:05:22 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-30635d18e55sf709231f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 01:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683101122; cv=pass;
        d=google.com; s=arc-20160816;
        b=l8kaUt2u70oP4RSoaylpxQkqQZlFVpPX1isyTxhGC2EOFdn2NKSdHunZvbDhlkZwdC
         w6OdPK0taY7EvKBlKmMJmeM/BrTDTYLJwNE7J2S52i0kDzHLUiMhyIhQ2vrzjaqQD/De
         7piYBOS0XIqhmD+sfXwmXSgNKQhzU3vSzYK+T+kC5jmc9dCrhjDGIiyXU3MJdBi8BFkE
         rxW1MLtMQMUJhwXUD7aGvQR/H7aRROm7NdoHbUyJRQ8yBJ/0sMHm/73NkNJM5zYDiZ9z
         W6QvfkLLB+vnYdIKAHxB6tAOifWu5vVLl8MNdmNLPKHqvI5CMqfHXqcyuEKTVvZYntiB
         h8TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GLDfx4zTD4zCcUYWy5KmiH7B+buymW/ce89hqyZGKwA=;
        b=cYjz/oBn19ZFAubqfFBr4KVk6axkEyxWkbwpV0besWNE98C5Lx/eDcLVOSGNR7SWNs
         lyhHVoLqYDfAT5PL1Vth7xB1raS5e+H5fQa22giEhvYBiZy/E3kfortgHkpIr9TmimuJ
         6Pfl4PCLj+M5A560ewL4PhvtJhwLt7tBk1fWqOJOOiwaQb0bCY3CazSzeA4uo+30+BPO
         H+J72Z8iXEav5Ia9BKTRZiucfAt+w6UPFq9J5Vse/3tkMEcnXmu+5Ne3x8NC/5ldW2DP
         5SF31/LoVTNf3BZtuUi6IjPSiqkHwPfjy+TcV38bzzinUYA248YmWdg9CEFCmivXkAdm
         oaHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rqHkCee1;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::39 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683101122; x=1685693122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GLDfx4zTD4zCcUYWy5KmiH7B+buymW/ce89hqyZGKwA=;
        b=DOR36YmHHK0TTdKkw7ljBwTHJjLCN1dZlvQPFk/7tbSEmaLuh7vmbs40RffzLRY1tp
         EHJ7gvb25oGH291DrqWcSjv1LCzV6FGPeQU/gYYEpXTk3nSX7Jta59W0XGBeJsmOIfMJ
         9TsRbZ1EKYLHYXscg/0NePWW8V5WpJAcSIdZUGKWcL2dLgkO36DJaMWmHqajJIUQsK3K
         aBLeJ51oX4u3tNLejqh2CZVtYZuLpgKUtQLYF94ManMTuqWX4yrOqusK7uuM/E/ov6ZV
         IUQX3pM2+6HC777I+cUerGQ970N9MewG7zs/FVgJmrtxZB7k8PvJWs+vTXccc0hx0lUv
         Pu8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683101122; x=1685693122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GLDfx4zTD4zCcUYWy5KmiH7B+buymW/ce89hqyZGKwA=;
        b=NieM8hAVYMyOCZZDm15cdcskLdqGVk8FzIh6sXmjkeQYJtxVB/CGRKhdUmj93umwSO
         eX2s/Is1VZ9wxRk0lIef2cryT93n6S0RmwtROSgb0MiALEzPwbL7vrhxerw7DXTJgZwl
         s9odNsuTLLbMfAjjiCFsYnb+QY2t761xBtGK56CDIXKzls5ipseCftkNzn2lI8inYtT4
         dT1U4pG3Raa3BLH9sCHEwpyy6dJ+p+HosPq0xFNXRtZzpnuKL6DJbfOXrH6+6rIyCylw
         o6/dKbZ7O9L8UaKBIrJFkqsTgbITenVLbldWPEAn0sWOajCEG40R0+TyFvRTIZnOdaR/
         UJaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzxv7gQ07OniTM5UCJMc5WMil3DdqhWNkoqBBkt9huM0N2oh2U3
	YJIiVWBxlG3vpcCGn6a1mAE=
X-Google-Smtp-Source: ACHHUZ77UbMibVuYYvVL4kQrE+Wf+duy0SqIqJStZdTgJ73J2yQb6HSKAGuena5kdSTicltrLyzDaQ==
X-Received: by 2002:a5d:65c8:0:b0:306:2ace:54c1 with SMTP id e8-20020a5d65c8000000b003062ace54c1mr1263904wrw.3.1683101121636;
        Wed, 03 May 2023 01:05:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1787:b0:2f8:4432:9c7e with SMTP id
 e7-20020a056000178700b002f844329c7els4319280wrg.3.-pod-prod-gmail; Wed, 03
 May 2023 01:05:20 -0700 (PDT)
X-Received: by 2002:a5d:6dc2:0:b0:2f2:9198:f0f with SMTP id d2-20020a5d6dc2000000b002f291980f0fmr14212252wrz.10.1683101120401;
        Wed, 03 May 2023 01:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683101120; cv=none;
        d=google.com; s=arc-20160816;
        b=Op2ekGuV7JnIYtnRS53jXBGhA0V800xNl2z1TLvBePpqc0nVbbYbTEjFQxVbHB4Jbz
         dL/VmgPN5K888AcCfZi2LNTTR7M8W6lOaMmbpYWkGi+s4xXWaF/hTO2qo4kjZsSvpy2/
         YDu2W1nSDyO5SNUdQYR+0SY4hHTH9G9ff6w2u00VkpH+z03+UaGtoBh2z8nW8eNih9M9
         biBBa5bZjF2cg02hEHEQ+la6RTpSxe+nV9fvvBOUxQ5SLpayvJ9aZoJHNrMhIHhN7MeC
         RJ4bNocPCpaiu12bfg6mmbYZTMAJjjnvkB1SOZu36VRy3YWINfgo6OfBA3zITYARdUcN
         OIHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Af+2O/2Jo9IC9XECoO60Ibec+DnzA9yRBnuv4Bp8O9Y=;
        b=FDBlD873uvTSP505SS/7YBR5+ETt/IvuuEyLegmvBwJUhMqZVfJhvv1IvxaRorH/y9
         42ZN3WIy3w2VsSmVngF3ipPn4wYPjZAZcon/9vUf3Egsi0RXaKSAZqtAROm+BAONGgcK
         tb5q4CBFBJX/hE5LIAc1rE6GszNvIow28O3fwUaNkp0j9d3jPO2fOfG5Vqy2HPESs//C
         AT2GL24OKYwQ7+FPzs6e7Ry+dQWyvOROt4OKvlAmGcybVoCDwcTMTDx8B1TZFKpsdUm4
         BnftevuQhvGw6R1nRYRm2AtxM8vNahYtR1f/7RZ2houbevclCsWF7dN1Aow1rzOdEthz
         vZeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rqHkCee1;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::39 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-57.mta1.migadu.com (out-57.mta1.migadu.com. [2001:41d0:203:375::39])
        by gmr-mx.google.com with ESMTPS id co24-20020a0560000a1800b003062830249asi564570wrb.4.2023.05.03.01.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 01:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::39 as permitted sender) client-ip=2001:41d0:203:375::39;
Date: Wed, 3 May 2023 04:05:08 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
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
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFIVtB8JyKk0ddA5@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rqHkCee1;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::39 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 09:51:49AM +0200, Michal Hocko wrote:
> Your answers have shown your insight into tracing is very limited. I
> have a clear recollection there were many suggestions on how to get what
> you need and willingness to help out. Repeating your previous position
> will not help much to be honest with you.

Please enlighten us, oh wise one.

> > > - It has been brought up that this is duplicating functionality already
> > >   available via existing tracing infrastructure. You should make it very
> > >   clear why that is not suitable for the job
> > 
> > Tracing people _claimed_ this, but never demonstrated it.
> 
> The burden is on you and Suren. You are proposing the implement an
> alternative tracing infrastructure.

No, we're still waiting on the tracing people to _demonstrate_, not
claim, that this is at all possible in a comparable way with tracing. 

It's not on us to make your argument for you, and before making
accusations about honesty you should try to be more honest yourself.

The expectations you're trying to level have never been the norm in the
kernel community, sorry. When there's a technical argument about the
best way to do something, _code wins_ and we've got working code to do
something that hasn't been possible previously.

There's absolutely no rule that "tracing has to be the one and only tool
for kernel visibility".

I'm considering the tracing discussion closed until someone in the
pro-tracing camp shows something new.

> > > - We already have page_owner infrastructure that provides allocation
> > >   tracking data. Why it cannot be used/extended?
> > 
> > Page owner is also very high overhead,
> 
> Is there any data to prove that claim? I would be really surprised that
> page_owner would give higher overhead than page tagging with profiling
> enabled (there is an allocation for each allocation request!!!). We can
> discuss the bare bone page tagging comparision to page_owner because of
> the full stack unwinding but is that overhead really prohibitively costly?
> Can we reduce that by trimming the unwinder information?

Honestly, this isn't terribly relevant, because as noted before page
owner is limited to just page allocations.

> 
> > and the output is not very user
> > friendly (tracking full call stack means many related overhead gets
> > split, not generally what you want), and it doesn't cover slab.
> 
> Is this something we cannot do anything about? Have you explored any
> potential ways?
> 
> > This tracks _all_ memory allocations - slab, page, vmalloc, percpu.

Michel, the discussions with you seem to perpetually go in circles; it's
clear you're negative on the patchset, you keep raising the same
objections while refusing to concede a single point.

I believe I've answered enough, so I'll leave off further discussions
with you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFIVtB8JyKk0ddA5%40moria.home.lan.
