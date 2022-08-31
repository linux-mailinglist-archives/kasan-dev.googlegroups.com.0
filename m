Return-Path: <kasan-dev+bncBAABBAF6XSMAMGQESAHWD2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8F325A7937
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 10:42:40 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10sf5023327ejc.16
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 01:42:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661935360; cv=pass;
        d=google.com; s=arc-20160816;
        b=h8FZl453f+3gRp10GM1M+O+OAPpL06ZmLlMH/7Koe5cJTVOEbMhwsEz1nhYx09Fjoe
         W6040vYfAUDh1kejy0HZR8i+Bq+HtaEa5d1KmtIvMCpPEW7Op1bY5YvAxNPqB++dkBCP
         4UyaJmTzmnqx4GGvVvibdLb1MZ4Tdto1hyA9q5WANVijcV/GCRPS8r4Pexak6Qlum2T1
         EEKnhlLaM/LLMK2mjGhRyKwNLFRRiZ85XxxzTfNdHhC7odobBDKSbdWW4pg0yt+Vq7Q0
         T80e1JpuV96/g4NSgzo5JCwbT+efhpyq5ykqUzu0b8FlJC9r5FkSilNzuGyjr0X/N/qw
         Gn2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zdf7xlFXpMzQXZsedHshteDLR6n8U5BA8xfH6i6Jxv4=;
        b=cLSxSSGwF1Za7AaELLBZfVV7pB5ZK9/iFJ2rC+e0jpk7/1ffYM28VWOAAzwN56Z06y
         u4OXZfhmjZzu5XIqJE+7O/+y+jB3awD1IIhKSssY4l7kU3KjNPgcjPyEcOxcKXZsp25E
         d+9DS3M7v2KJC1fPczx3dyJ122y650PZQxsPGJ+X9iskPQtcq9DwK0X4MzS5/cZsoS/f
         wH82MA2IbuOzE3ygPH2vq92U1USQqRha6JFfMzkzR+nx2/pBeQpixnCoyqqm1rJHktWy
         vKz0yrcrnxyZkvADgh7/MehDo9LMvtMDMhLyK3iGeGuIOGxOUw7gihuoxhNDx+Z+y3et
         YpMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="n/WRdO6w";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=zdf7xlFXpMzQXZsedHshteDLR6n8U5BA8xfH6i6Jxv4=;
        b=Oe/W0DJB32cWxcbJfikTiLguujgJcvxyy8AiBXpo9KnLsy/XTxSUVln4nyVIIbyN3R
         CFMxiC29TWBRUD9RaAZRiUHwrLekH37x3I+iAn+JTSrEsutYguEGNzY16a288+hcUUHA
         TzO2MVcf9r6Rd59ie3I8PvGBVRoZhXC7/ofKdM/zLQJulSx1an6iZYE9jFN8lOXPe/6M
         jBtnY0ReITVi68ZhsNC0VflOTof2k28Z9s/sOSzq5zMsezfbW8O3CpfdKnpaXa9oyg4u
         amED2AAy8AMnmiE+eYG3QPnUoFTvWjopFfGkps2noTAwA65fH5H+f3xYAixhMcAE79uC
         52+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=zdf7xlFXpMzQXZsedHshteDLR6n8U5BA8xfH6i6Jxv4=;
        b=oZbAmLIQk1s/MZ5yRQ3oYVyquKLmh1M6iithbUa0gYI5li6/ig2OZUUpLXbibYrF6U
         Fq3t/yUNoQ3w84Gkn6Hz7VUlugfy+0hRxEqYjRQ16BZjt3s3/EvFeYRHWDGga98pS5ev
         Voce/uv+ARQ7/ErmUtyttBBO6eILHMyAf+hewq1ueCeI9OeA+rizIfXjXw3ZbPh8JEHI
         gQHXdcMqCZalVB29s9v6GXnSnGVFese+LNW4uCUdQz60OxRLD9NMMpUU+4MYI1JJ32VF
         V0XMiXfgAWlHOgmYdJWiTJqQarBevOzJ7/afRbUzzFNqdlnZaWno+01GsG7/y6Cnnfpj
         VvsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1nXwIsMhAEZwnYfb4G6aj2RNFiQnvXvJ5/Up4W6GjV6q3yzTzb
	8+TkErOJWnLBPUUIQDSAmTU=
X-Google-Smtp-Source: AA6agR5X4pFkrBQ91nCaaqs83A4/XDqJ9X2/Z3fUT2kGPJx9PjKsdIFOX+de/rTxuTxBqg0rCHUR9A==
X-Received: by 2002:a05:6402:5110:b0:440:4cb1:c137 with SMTP id m16-20020a056402511000b004404cb1c137mr24712342edd.262.1661935360312;
        Wed, 31 Aug 2022 01:42:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:ccd9:b0:726:d068:52af with SMTP id
 ot25-20020a170906ccd900b00726d06852afls2341875ejb.1.-pod-prod-gmail; Wed, 31
 Aug 2022 01:42:39 -0700 (PDT)
X-Received: by 2002:a17:907:868b:b0:741:8f8c:6ab5 with SMTP id qa11-20020a170907868b00b007418f8c6ab5mr9399792ejc.194.1661935359509;
        Wed, 31 Aug 2022 01:42:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661935359; cv=none;
        d=google.com; s=arc-20160816;
        b=NOAMxH3M0lVzgeCq79cFXGIAGhGFBl0Dv63FBlgo6N64gxUoXyi92mgxsiswIXoqkH
         IJzdL3QeTWQMH9IS07FkL1udI7z7+WDtgsipiOX+SMQGp0zKP7jAi/YHll/ccak37HVe
         cKTaF1LsOa+H/gDMjO75BxarGvYKrwbbZGJqdO6SKqNs/9hsavbxcl9G2wKs3yCsVufq
         yTWwQgM+bPAW4qHNWhuGnBLt7beNwepOs/rSdd6WmydVyKPX0VML51HdBBczpTw4DiIZ
         XTJw7JteN9v4F+eXI2NYZnpZ8kNpSmpYhsnwH1yuxRtpVfTPHwSmLxG8X1tvqx5SU0a8
         WNqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=mmxSzJIEbF0byhuM+VO8IRNgyEUbvUgCaJEiam4Pxpk=;
        b=cY+GDLMmW7k9jn1+BlHWzUEykKwzm2gbc1lNE+bgIait9gUggWfuQhYtjwM8Cq1i2B
         KLO7WrYg5glZKbYYbjIovrFU/o4bFchV/JtiVQbZFmvI0Vu7QE64TuZm920UudeaRTUD
         xttmg2nfISNIUV3aVRlhyf1dpQ+YVkFD/TbUoyqGFOuV0+cH+SZ/5KxI+HetUTfL8h34
         wcZIWCkmDb/rhGeYioNiNPEmh+9VY+RCoUUyqjZyzen3PrgmqY7ch4hbcgcC6HgdmURB
         soHbJW+RW1BpWNXzCVUdoCq9nrQQjGKKvAwqnHq0Eb5V2d5v3TJJt7ECsDVMCGESM12x
         s93w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="n/WRdO6w";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e22-20020a056402105600b0044608a57fbesi766643edu.4.2022.08.31.01.42.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 01:42:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Wed, 31 Aug 2022 04:42:30 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="n/WRdO6w";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
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

On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > ===========================
> > Code tagging framework
> > ===========================
> > Code tag is a structure identifying a specific location in the source code
> > which is generated at compile time and can be embedded in an application-
> > specific structure. Several applications of code tagging are included in
> > this RFC, such as memory allocation tracking, dynamic fault injection,
> > latency tracking and improved error code reporting.
> > Basically, it takes the old trick of "define a special elf section for
> > objects of a given type so that we can iterate over them at runtime" and
> > creates a proper library for it.
> 
> I might be super dense this morning, but what!? I've skimmed through the
> set and I don't think I get it.
> 
> What does this provide that ftrace/kprobes don't already allow?

You're kidding, right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831084230.3ti3vitrzhzsu3fs%40moria.home.lan.
