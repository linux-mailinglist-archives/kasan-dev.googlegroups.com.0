Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVHRZ2GAMGQECKSAZ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C12F453358
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 14:57:41 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id q17-20020aa7da91000000b003e7c0641b9csf5623579eds.12
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 05:57:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637071061; cv=pass;
        d=google.com; s=arc-20160816;
        b=YHkHaiUrqvK7yd5wKsIp1ndMo/UeXkxmgdyLTFfkGMYu0YOrrki2/uA748zR30Kyex
         1ILO7D4WsKG/QscBjG0bL04hOfjoKkKCuN1KX4E1FwHMbG+O/BuBOuTBIzMLeK4aJkQt
         6sbxS1pI5zhP7Y1tSKyN+kkYpqD4SFKpOQiPXGsuerCIJu5oNZePGC0fqhd1byQhdSKM
         Oqq6qeJCRdqfbOZ0V8RvRnQYpTw2WHtpUTJ511O6zkthebrjZpPFEkc6DfKKgvUNldq3
         1GNWzj3+Un6SpUY+m61667WKkWJ8xmrAY31K+lQXbSNKpAikNZHYEiVL4vS97h7d0lXv
         4zzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uta9+qMmiK+hpecH63vvkiia/6k8p9LII8hvDjaKgZQ=;
        b=ntbEd2ggeGrq0CVXCGpK8J3/tJ2g/1e1HvrvCfOhbxuhqO+IOa0Upe4y0Fj09tO0hs
         dz0kiY8sFeevUQt2HL6Sm+zrlDzbQKJbKEAQ2iLAoS2uG7ulWSQZbJ7WobXWi2qD7Oxc
         1s7swxd2+VSutb+yQw4f5Za6B6m4yoGDLA37S6pS6N4kqfpuMJIcYUOJV3fYme7Yq35t
         xM6Z4Uhh9y6pYDIFE6chRNi41Alu33r8VYfeCOzJoBep+Hx0mmzDApSJ9fQ5hfWQDeNm
         vl+ayqS3NdO5wuw5ZId54ZpFdSfCWlNimGUZH1G6/SrGf1EBqkgark7r1zuvLpDJdahs
         UFYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hv5EIh28;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uta9+qMmiK+hpecH63vvkiia/6k8p9LII8hvDjaKgZQ=;
        b=iJhoOW7yMe9ZB64yaOJnW4mManYWJmI913F523bS5eW1Irn4ngzjnA1B4/2uJzvKEU
         b9NDc5dRC562DUotrgdknyZtuM2tNCnf5XvV0BOXuCRwQsSZ5n8jrDMnrdKAESr1fZhp
         qhgXLIm0PAl1kiTS4l/aw2cu1QtcYlfna5XTzEcKO18vXSdTpNBrmXeRzaJNpVUk37yU
         5e2+w22aPD0jFX5ajIQBjQOe9eRWGjc7t7SwAvqCxHyYj988NxvOqSgzp7g0VEcoH7O0
         hwcJko56Zjectk4gz9pj0Jmin12gfmGtwDAkr52VUSlRqkSX8nGYYqVZq79YHmxd0SgV
         oz0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uta9+qMmiK+hpecH63vvkiia/6k8p9LII8hvDjaKgZQ=;
        b=ei/Eiz9baZdElpIu2lyT20nB5wrQNXaJdO4I0+MmdyvOPi92xXiaQ7e8iV9jw4kb7f
         9nQZOwGIuZYjeFT9pet/37IlUMzaWJiAf7wqywqhdWano9HPVzQK2UhMeDTNyrpJBXNz
         03eCz99aXyQCerEc7hEapxBZg2BoIk7IdPcVui2Ngucr1QrgoljHpR5Qt4AD0WQBCGLZ
         f58EwQZD8zTgRm2j4C+oG6ZJGvuasKb2zd1BG7lstCnjGHNqjhZeIksUaeLzM8H1vbCs
         ArJlugizPBAwvDPPP6TEjJQUF6rn8fQ+we37gmmlydcVCxThv2J11FNSR1T4v6iQx/ff
         7l4A==
X-Gm-Message-State: AOAM531sdVu1jXcwnBcuEwhQc6j5OnZtmvLaq6z6e39GjnyzhSaGBci2
	mIVhaxdNX6W1nTEMa0N2rFQ=
X-Google-Smtp-Source: ABdhPJxmXbOfbR+GdybWBq+uoaYWT8+Ov3GJRWOt0jkoMTCHw0UJCRL6cTD/UptZkiQ3oo+E3C2isQ==
X-Received: by 2002:a05:6402:3590:: with SMTP id y16mr10625046edc.343.1637071061149;
        Tue, 16 Nov 2021 05:57:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e93:: with SMTP id qb19ls5210396ejc.4.gmail; Tue,
 16 Nov 2021 05:57:40 -0800 (PST)
X-Received: by 2002:a17:907:7244:: with SMTP id ds4mr10447853ejc.55.1637071060175;
        Tue, 16 Nov 2021 05:57:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637071060; cv=none;
        d=google.com; s=arc-20160816;
        b=k/YjIZxvOxoPtKpVu7kCt+xUHEvD2Se98mrb4mdAKP2Os2RJEvmK85qFXfO1xetuGZ
         LdCNdQXRyqVKuloQIbJ9JfQgWQI278rQfcAQTBxhPBZW0TluNqViprhMxDTAFcFkmkWg
         2va7U1nPBbR+RyI7R2nNKnTYeO0cH3J13JEL0z5qHRNFtUte6e2EAyhI2YR44lb8TUeV
         Y4ps7HOMp+GwGeRmgeSjPM+6HSHuYaSIWkmcXIUkkO0o1+V1l3Y6vBgB5++SPAGrqerC
         8iY6mvmjkda+4f3x3ZyQbhWap+mdmoVqZ61NW2o6cNOFOVplQ79fjcWVUhFhrDPGtOs3
         bw7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=czQYblp0zgAV+YCvrQJmphHgmDDB70J1rcuR+hc1jL0=;
        b=TMjCISD4caXu/rMjKJW3pcnB2r+uccxvGPX8AvTar6yaAASHSzhE5KbSJEOv2HCItq
         21m/Irmp3XlkqLKYHSNmebe8biZBHuJfAWsyMH7x4mHW/2ZC7qkBSdq2Se+Imak3ZaDH
         CH9jC84XWQNa6W5QCxvbeYvk8Wk4bP6fs8qS6ieQGfllbvCEYLDfr6hRfpmVENrc7zDu
         x977vqQ04NjPb1/U63EYtIO9xBHc4keUeXI2V0R0rCe8SknjOLZuU3IF4PDvd1yuPpj+
         mYUPuHJh8aqYTIH3C1n+noOSj2QtJajofc5z/6jCSiIL1WECVG1QmmOZ8l8zRyAhnIPz
         o+1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hv5EIh28;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d2si1005208edk.1.2021.11.16.05.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 05:57:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id o29so17051710wms.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 05:57:40 -0800 (PST)
X-Received: by 2002:a05:600c:4154:: with SMTP id h20mr67679498wmm.189.1637071059802;
        Tue, 16 Nov 2021 05:57:39 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ee27:74df:199e:beab])
        by smtp.gmail.com with ESMTPSA id t8sm17491703wrv.30.2021.11.16.05.57.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 05:57:38 -0800 (PST)
Date: Tue, 16 Nov 2021 14:57:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnaldo Carvalho de Melo <acme@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Fabian Hemmer <copy@copy.sh>, Ian Rogers <irogers@google.com>,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] perf test: Add basic stress test for sigtrap handling
Message-ID: <YZO4zVusjQ+zu9PJ@elver.google.com>
References: <20211115112822.4077224-1-elver@google.com>
 <YZOpSVOCXe0zWeRs@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YZOpSVOCXe0zWeRs@kernel.org>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Hv5EIh28;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 16, 2021 at 09:51AM -0300, Arnaldo Carvalho de Melo wrote:
> Em Mon, Nov 15, 2021 at 12:28:23PM +0100, Marco Elver escreveu:
> > Add basic stress test for sigtrap handling as a perf tool built-in test.
> > This allows sanity checking the basic sigtrap functionality from within
> > the perf tool.
> 
> Works as root:
> 
> [root@five ~]# perf test sigtrap
> 73: Sigtrap                                                         : Ok
> [root@five ~]
> 
> Not for !root:
[...]
> FAILED sys_perf_event_open(): Permission denied
> test child finished with -1
> ---- end ----
> Sigtrap: FAILED!

Ah, that shouldn't be the case. It's missing exclude_kernel/hv, and this
test should work just fine as non-root. Please squash the below as well.
Let me know if you'd like a v2.

Ack for your change printing errors as well.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Tue, 16 Nov 2021 14:52:18 +0100
Subject: [PATCH] fixup! perf test: Add basic stress test for sigtrap handling

Exclude kernel/hypervisor so the test can run as non-root.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/perf/tests/sigtrap.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
index febfa1609356..e566f855bf74 100644
--- a/tools/perf/tests/sigtrap.c
+++ b/tools/perf/tests/sigtrap.c
@@ -46,6 +46,8 @@ static struct perf_event_attr make_event_attr(void)
 		.remove_on_exec = 1, /* Required by sigtrap. */
 		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
 		.sig_data	= TEST_SIG_DATA,
+		.exclude_kernel = 1,
+		.exclude_hv	= 1,
 	};
 	return attr;
 }
-- 
2.34.0.rc1.387.gb447b232ab-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZO4zVusjQ%2Bzu9PJ%40elver.google.com.
