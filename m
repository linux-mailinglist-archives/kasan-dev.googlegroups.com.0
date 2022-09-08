Return-Path: <kasan-dev+bncBCKMR55PYIGBBLV442MAMGQEJ5A45MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 17C5B5B15EF
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:47:59 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 6-20020a05651c008600b0026bda5a6db8sf200644ljq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662623278; cv=pass;
        d=google.com; s=arc-20160816;
        b=E5ByVwbeKvKkz8/RubMoRWKbwfj9ft+39p6R6OOWyWh6fhW2lKe26IZOlsBe7j4kzI
         nkkp44U8cq0llZkAkd9FKFbPbLpjr0iixPYH3AewqsU8CCKgtFuCfshSU8x+Fq0YOEFN
         YgN+Qrfyf8AnHgGAWP1iQ1ljw2e6ECryTEvhQWSwpgcRrZxALC93efIrEAsv2DC90QQA
         1pOnuOMk4W/zZcY/Be1vYN91+Dfgcvsk3Hok/9jZmETF5mad89bSwBy6NvNfr2noxyTJ
         nCSPgzFjaVSqccELK5WfRoUDBfgP88Yo3HQGYd5/7ayrUNmTgBi6hIT7W3SK23PvemSn
         klAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=g7E/wEEUGSjWZm12tTWzxk1Agc+oooZYYjbPhQQg0d0=;
        b=I3sEkedsyCCy9knoZfZ05d1eE2idIt90/kJcCRaKv2/EksU2qOpDXvE1AmkIzVtdbH
         0QMy3XpejOl0hu2zaorxNLs8FmOJdJ9d29wPVCh3G+/UfoNar2RrLCTOm5bKXiGkoB2f
         7mPeF7KcjNLG/R5HqRK5vVP8aSHUfUL2JMbWp1nUiwj9P7gR9ui8yKVon6A+/p5N+NNH
         ceYAcilPr4Ato7XDsyMqG3LdY4gmfIdTsoQDLnLjgCn8UwvabBSuq2jSQZ88nhEGmNfR
         0sRueyl3KqQ3OJMCPcHyYrkH7LKf8VUyEMgXRpyQak/AqZbcB0BjHah+wDVEdkefp2Mg
         OerQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=q2uaKkC1;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=g7E/wEEUGSjWZm12tTWzxk1Agc+oooZYYjbPhQQg0d0=;
        b=P/RPN+HpAOheKCf4IiTiSa2he41bpTA6c+t1gfQ7HIX6c2VhHP+MRxhKiQTfZycUF7
         yfFw30NlhGWjoolj90p/yuRHGg4XXsAfFvEgas3I81wcSMBbovYuisIrgDeG4XevOhYd
         wI8JrTOW7Mc3w3RRfZ07ICjtmLRmuIXVu3goDyAeMLfwlOI9AZWAN3F2r7FTsN9jZXCL
         g06SpOxb61eGqdOR/epfL/YB9XyVMLzSQoz+iQqAaBFUQjauenXaOEQca8RkkB46lHtS
         6TudXBPh6oQmuZv/9lqvXJ0jtgchCKVe5BdmvocLkjQ6SxjV3LmbYWAbSbS6UInrRdMb
         s96w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=g7E/wEEUGSjWZm12tTWzxk1Agc+oooZYYjbPhQQg0d0=;
        b=LUrpol8rJ6hZBrsxkzZCJCa2vZZUFa4tcg6mzbEELstFkPeEPQZH8hzKb6RfHILclZ
         WZnPQwsZ6Z8lhoCvlQOQ+TGcehzeNjR6a2D0FZOUbPm7AiT/jQU287A8r0ku5QhsoXl4
         8xNhRQkrRZbhipV0XrYA9FdOAPNpwKXzIPa5RIoxS9Ewf81yAvB8wurBqu4KbllBp+Ak
         0+69+y2JDOgeUQx3NCV6LUQ/Afu+zbF58zeGSFvKkZv41a1OUkOC01p67XlXJQgsHSk7
         5XmE2UQupHTh1omyj+pywme+YB/83H922hjMlq4fmR7H6ETTBUHTDgBOrrBxv2JPCoFk
         Txeg==
X-Gm-Message-State: ACgBeo2VZoZVa4itc/YAzwUXgjGeUW8Sj3wK3FDGcFcT9XuBKPQOFGeb
	+O0nXiWtM0ntsDcSL7KGoC0=
X-Google-Smtp-Source: AA6agR5vL6QgGjzsJrVQ82txaEkrLfX4h4RgmIiyU2CzxMBSD60btLVp7LyGCXuVtGzoI3KaeJ5TUQ==
X-Received: by 2002:a19:4918:0:b0:48c:e6a0:c8d8 with SMTP id w24-20020a194918000000b0048ce6a0c8d8mr2318009lfa.679.1662623278276;
        Thu, 08 Sep 2022 00:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d2:0:b0:25f:dcd4:53b4 with SMTP id s18-20020a2e81d2000000b0025fdcd453b4ls132019ljg.3.-pod-prod-gmail;
 Thu, 08 Sep 2022 00:47:56 -0700 (PDT)
X-Received: by 2002:a2e:9988:0:b0:26a:d12c:3739 with SMTP id w8-20020a2e9988000000b0026ad12c3739mr1510429lji.291.1662623276726;
        Thu, 08 Sep 2022 00:47:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662623276; cv=none;
        d=google.com; s=arc-20160816;
        b=drsVRKU+zjzPhK5os4WfDuBH2O5LIgaD5RA4IjXySFqmD00eWzl+2Dz1rJ7m91V/0+
         jFy6LoJQaVIG99MZAibreMPAFSL4+4XJFg1KqnaSR2GlQl0CMNuOpbm7+8yJgOBgILhs
         4Op/CGkb6gLL0OcZWxi4aJYYBxrYvrUr3nJiUsOAto5T4UqwLgSrg2xYQE4BjipqAUSy
         KZRmB0UE0Wf5Okx9hiF7vNTv0yaP9zXGodgZXRDiAc1PNqLoF6DrrFI6OoQqBJgm8rmB
         d3P7uTM3+QwRxVBr1L6n+u9Vj9K4CpqED/3B0CTvnUdzxBf/fbPjJ+YOE5bH/bTQpMn5
         P5bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4+jY/L5+xe35wjNUaKjbU+iCet/hLbz6TyCvxP2dmm0=;
        b=l2Nw0iaRzTSBQNDdxvR9JBrFhSZbfET2NvoBApwQ73xzGtntvS9hOLH+smFO8It69C
         q4DmLoGz/TdXLx+jtZvY9Xoq9oCFUo1mN56C5YuambmK/uKtXIoh4tuUGpnj/OOg7meR
         9R0F5vXLsG9ik+pHFmOOgifC8LHHk/DtlXmCg5ybcpDFDFkbpUH0JfGx/71KRzkILuif
         XI/RnmNRNoWfZhrLVVuP110VkUP/ae8m1x2Ut76HpjvNR/EwJ4Q+FwSfvJopIfwQmOMo
         xuibWTADvtm+D5gz/9/jjaODqaGuUFLLP/VHjgaZwOXTeXOAygkLxDNzRT4XAIAaYRCr
         W0fA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=q2uaKkC1;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id x20-20020a056512079400b00492ea683e72si761686lfr.2.2022.09.08.00.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Sep 2022 00:47:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 116B433BAA;
	Thu,  8 Sep 2022 07:47:56 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DFAA713A6D;
	Thu,  8 Sep 2022 07:47:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id v6YhNiueGWPJGgAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 08 Sep 2022 07:47:55 +0000
Date: Thu, 8 Sep 2022 09:47:55 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxmeK2/HHS4AkXh0@dhcp22.suse.cz>
References: <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
 <20220907130323.rwycrntnckc6h43n@kmo-framework>
 <20220907094306.3383dac2@gandalf.local.home>
 <20220908063548.u4lqkhquuvkwzvda@kmo-framework>
 <YxmV7a2pnj1Kldzi@dhcp22.suse.cz>
 <20220908072950.yapakb5scocxezhy@kmo-framework>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220908072950.yapakb5scocxezhy@kmo-framework>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=q2uaKkC1;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 08-09-22 03:29:50, Kent Overstreet wrote:
> On Thu, Sep 08, 2022 at 09:12:45AM +0200, Michal Hocko wrote:
> > Then you have probably missed a huge part of my emails. Please
> > re-read. If those arguments are not clear, feel free to ask for
> > clarification. Reducing the whole my reasoning and objections to the
> > sentence above and calling that vapid and lazy is not only unfair but
> > also disrespectful.
> 
> What, where you complained about slab's page allocations showing up in the
> profile instead of slab, and I pointed out to you that actually each and every
> slab call is instrumented, and you're just seeing some double counting (that we
> will no doubt fix?)
> 
> Or when you complained about allocation sites where it should actually be the
> caller that should be instrumented, and I pointed out that it'd be quite easy to
> simply change that code to use _kmalloc() and slab_tag_add() directly, if it
> becomes an issue.
> 
> Of course, if we got that far, we'd have this code to thank for telling us where
> to look!
> 
> Did I miss anything?

Feel free to reponse to specific arguments as I wrote them. I won't
repeat them again. Sure we can discuss how important/relevant those
are. And that _can_ be a productive discussion.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxmeK2/HHS4AkXh0%40dhcp22.suse.cz.
