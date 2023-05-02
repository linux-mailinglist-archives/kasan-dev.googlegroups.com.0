Return-Path: <kasan-dev+bncBCS2NBWRUIFBB3EBYKRAMGQEAV773QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A27136F3C4B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 05:18:05 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4f00d41e0a7sf13117718e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 20:18:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682997485; cv=pass;
        d=google.com; s=arc-20160816;
        b=AFKaLTkPUfOqmvMt5P04B74nY8orRyEvQjLeI8zxMBfN5/6VqJhW3PZ0T4vouOY0vF
         fuyuI/MzvD80bRKctAF/vWvPqY3Ll8gKn6ua6hASLPTdzIWTQxKIM0BKBc2yf2WfGdnQ
         EJYJeQoRHWLKBSNX3vE/auTAvQ16R1qchLaMpanhUWZjGrq4RSnVDJbBjYzNUBoeCk6h
         VxrebuXTi089C6rlElqkOhLKwD4DV3+D3e3XwsZMCLgJbLOSOsBYsnyarKOyry8XW+ua
         EyTLRZP0bGRg8SXIY0rju7W1yBxufD8D9vclzqn58eZaZUzlVyicJQCinRB8nr25gVgl
         nWOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ao8HI/UnVVXoZAwMnOn+EhkYD6yn2RtSGJIlccPKU+I=;
        b=PUKDHdXMvBSMmrxwIczIO48yHaw82xXakS+XGRIRj1kCmn5I19bvVstlzuQDL0vPsW
         fWsfxTtprVG+QXVuASFGFZqc4uz7sizzgqXj+ymg9vSl5VZcrIJxOLLKgwkoMAWNtqXg
         fyCPx+sHLrOUnzG+XZXNvBvDshEFy1fsh4jAH44Mvna7Vwnh3uhMu/VJM9lxrK+H1pML
         rCyAuaNoWgKZRkkkCUYOg74ssPLkFwa/jm01hCrkNx1Lh62rpGbtdZkA8565P6bCyyOU
         xsPK9m7I3i+Zon46vp6+jMDVisDG3k4C0peZSypilMzhq4axaysnluvI7jxX85rttUeS
         dNAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L9Ejkbdl;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.61 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682997485; x=1685589485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ao8HI/UnVVXoZAwMnOn+EhkYD6yn2RtSGJIlccPKU+I=;
        b=ZNcyNsJAVzpG7yEjhQKxX7Ih3MRZmDHgpm4QtMBzAFveSHTzgJBUGZGCmQFRQsmE8a
         XlZj4D97Ad0FAPWjBznVheHDd1ItbRM8Zfqwu5pekLpSSAhGB4FsVQhQUOawVIF1kfZ0
         0RGOApHUfO9XttCp7ThPEE2IBYfTbKbgbvqkY0+8d0nOUfAOUOZq15U6iAuJU3HtpZQS
         h5kqx8z4uRXYtW7VRC5+Jbh/ak6bw7uePbmuP2BbsXUtKeP0O/TaCu9AjdOQDk/UzdMq
         fnN4+/iUhRnD1ZyF1fhtRYt9VmkD0OEBD2Vz1u2aITjj3FImz1mIJCynPSQlDEcso2bU
         a/eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682997485; x=1685589485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ao8HI/UnVVXoZAwMnOn+EhkYD6yn2RtSGJIlccPKU+I=;
        b=cr+qWsLTeXpdG3w9ZNcemWMIsPAmJyPLxd7puHMQQBGfSMbmuL7mlppQk2289i4jbP
         iB5R7roSdbrXZqs8i3BfuMRkYUb+II1c2yGyWQwbnmU1oxzSew998WEam38Gwj+NrZul
         g3OSZ3ljIb2VM8S116JEBvDv2HGKCyeqTRhukamuJ5VLyYBj6g3HZBfaRy6BWRQ/wZTg
         phJmJOaXEeEVXCCa/e2LkC/dqSgRD9FZBRWChUrS7HtOJjvLWRbR80zzEIHdhU9uU/WF
         TI4niTk0z9EjhZRE2HQjHNcOymEQ9Y1mODE8F1U2h7SjVfsGukmDrzsxax9UM2tby7lr
         TRsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxpeChN45VcHPEGTnSSCdFV8En6Nt8lwEkfi3h7OLu0/PmrTATg
	7fhOUFZCcaw8iH6XAk5rziY=
X-Google-Smtp-Source: ACHHUZ7AgsL15Hu22WoLePkcfWh0xy8cGE51GZXfnefLe3pyD765icUlCDXDu4W9x3WEIC11BKTs3g==
X-Received: by 2002:ac2:5296:0:b0:4db:b4:c8d7 with SMTP id q22-20020ac25296000000b004db00b4c8d7mr3819114lfm.2.1682997484778;
        Mon, 01 May 2023 20:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2342:b0:4ed:c108:7214 with SMTP id
 p2-20020a056512234200b004edc1087214ls1623976lfu.3.-pod-prod-gmail; Mon, 01
 May 2023 20:18:03 -0700 (PDT)
X-Received: by 2002:ac2:51c5:0:b0:4d8:75f8:6963 with SMTP id u5-20020ac251c5000000b004d875f86963mr4612584lfm.38.1682997483267;
        Mon, 01 May 2023 20:18:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682997483; cv=none;
        d=google.com; s=arc-20160816;
        b=B8j6N7dLRg1Ft/h2Z2wbwiQD43mb0XJQhYqrw4yN369VbSS2L18N4IjDNxAgf1SHLV
         +daC3xQJWMnIpKfEy9haBNqCLjepTXzPukLDcSCYhHG+3BlbpOvsRdXmSVoGxUuJM+2F
         3UIjbWkrmCZMDiryamo3IMwXomitIxCXFI4UJ1hCVYd6rP9WaVXbJ/18OnaNYZXdwyyK
         CLehy9joQ43Y436Rp6Camk/oC127YYB7GMmwXs7b7MOe4z7HCGX+wcZqa7cH0QYsTSDk
         52wg/c3Gpz0t80zx63MelZP9O7CuhH4mdaXhWRF/U86oRbpx1RHDeGUni+4G9PZMRVeT
         f3dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=NNVXUMOZeoGpfLU/g3IFEb1hzaUHRqGWiLOTQQBIzYs=;
        b=kKac16odnRTUOaj58fKEEptO97RzcE9vU5Q0qxR14lpR7J6SLMiexyzgjG2oBi6V08
         3r8Ffchl6yKQ8In7Y4l15HJVFh60k1snojW1fDQ1z03QFgOmO8SEJbOOEt9qEcgzFl0D
         2Chce7eMOtfctO0I2Zl11l0xQy2CpwY6iaR8q8B6cSs9NJZ1Ec4QR+FNDd/ZAT6ibgnY
         qLYLUMdxqvAV82WEfCm3+uLZeayQiFLIQ73GJowN6JzU43uyiSy1+8eUeoWve7HH2KWj
         CyyE9xe5ZTrHH4EgfUsngq0euNqL0N10OsccrjPvtNLC/DMG30QeDhoHltH2cYpvNC6e
         +gBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L9Ejkbdl;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.61 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-61.mta1.migadu.com (out-61.mta1.migadu.com. [95.215.58.61])
        by gmr-mx.google.com with ESMTPS id d29-20020a0565123d1d00b004dd84067a4asi1990148lfv.4.2023.05.01.20.18.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 20:18:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.61 as permitted sender) client-ip=95.215.58.61;
Date: Mon, 1 May 2023 23:17:44 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: James Bottomley <James.Bottomley@hansenpartnership.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFCA2FF+9MI8LI5i@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L9Ejkbdl;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.61 as
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

On Mon, May 01, 2023 at 10:22:18PM -0400, James Bottomley wrote:
> It is not used just for debug.  It's used all over the kernel for
> printing out device sizes.  The output mostly goes to the kernel print
> buffer, so it's anyone's guess as to what, if any, tools are parsing
> it, but the concern about breaking log parsers seems to be a valid one.

Ok, there is sd_print_capacity() - but who in their right mind would be
trying to scrape device sizes, in human readable units, from log
messages when it's available in sysfs/procfs (actually, is it in sysfs?
if not, that's an oversight) in more reasonable units?

Correct me if I'm wrong, but I've yet to hear about kernel log messages
being consider a stable interface, and this seems a bit out there.

But, you did write the code :)

> > If someone raises a specific objection we'll do something different,
> > otherwise I think standardizing on what userspace tooling already
> > parses is a good idea.
> 
> If you want to omit the space, why not simply add your own variant?  A
> string_get_size_nospace() which would use most of the body of this one
> as a helper function but give its own snprintf format string at the
> end.  It's only a couple of lines longer as a patch and has the bonus
> that it definitely wouldn't break anything by altering an existing
> output.

I'm happy to do that - I just wanted to post this version first to see
if we can avoid the fragmentation and do a bit of standardizing with
how everything else seems to do that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFCA2FF%2B9MI8LI5i%40moria.home.lan.
