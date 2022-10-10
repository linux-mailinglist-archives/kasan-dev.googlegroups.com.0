Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAMMSKNAMGQEZYD6VLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E86735FA692
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 22:52:17 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id h129-20020a1c2187000000b003bf635eac31sf4466440wmh.4
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 13:52:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665435137; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZmCdlNmtlxMHwIxCF1QtcbMouxbcfN3WM/tL9fOy448/inux2vKaVTYHP/EfZ2/F2f
         efMcF+v+6nQcxjjK+U9v6UIwqBPRREB7OLnUvG384m0Gz/b75ExYR0ud1DJef1pNVnEu
         fhySpVvyiBGzF2Wpw5zR9sJj9ly6mKqRWXZuhANYy7WJzgPfExq1rgO6KBdF4LUY3rgN
         YacqodAmiS/biN8sz2VkP9peGqr2hCQmm1vwcSBAFDkD5igzhbJlBlUDzQsUf83Jn3Lc
         X3LKnxhsqjyhF69tY97OnlGGFiMagG1ppVvtJfqijnF5mhuwAkMpnGoB4Gyk8r0yr2mb
         B0xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=esnulzZha3Ubk+YCIrVpPSFY1QFIMVLy3y4A96TMyGc=;
        b=I76hehkN54E37FA15vTg4KFFqho0Yol0IoD32+WYDcirQHcpDYaAttafG+tYnoL1+p
         FYNjE0j/UKcVQKIoqsAtYCHhnYRsmOC2tTvCPzDazfcH/Yuw0hsYfWPd8byAdeVX9Qs1
         XGh4NR0JEbPBNN/ZsWqcj9nLSX8CZgeCr3ZrG/SxQGhxqJtt6Yy3M+OUT3DGHwvqHix3
         gosXvo0kCHj7AfzoMXlPHQjzV/XEE7CaMsVyi4OACzEeGzCqMDxu/ZCN+WZq1H9rBray
         LUVAJX/Ov9ker/5HLcVthQOIFBEMUjZFnAuA0HBDrQUmwrFqJZjPOWFWBLNxtmEwgcGc
         U4VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hs6aPu62;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=esnulzZha3Ubk+YCIrVpPSFY1QFIMVLy3y4A96TMyGc=;
        b=cIRUyvQLMer8h4nrrPPOSq4JTyh9oMsxwcUN+Yep8eJVUDdsGrWncPtijMS1apFnfy
         x1jU4boSEAj0/M235KkBlyxAWtx1jVokT0ft3yFBC9QiFW8sNYy5WXOdfFiHA9LaDg8i
         QyuPne6HzrK09jLMz4wWGicdlaCSppbSGEPw0LqXxqt17q8LGdSRaOskCWwlikPhkGlJ
         3agolNRrvs/zvUhYE/5V3560df/6DBAWznrixP5p44GEGUwf4Q0PiqQzRZRffEi+2huo
         kBONs0FAgvQ5EDrLBTPRg/JdmRZiB5UpzrPrkURoSJcJLT6CfjA5I2H/1NCm8YpPSpX7
         BH8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=esnulzZha3Ubk+YCIrVpPSFY1QFIMVLy3y4A96TMyGc=;
        b=d9t1VYVd1vGfW/9tSKmArwhx4UmH88Afpuf2lo/p382aDB78+dpIaa2gKY9pfn0f+F
         TW6NROYL6JQys8f0/XHYy9OS+tZdTi4YM+LJ6FESqdfbGjJvutjNMXcc+uJUIBOv0qhC
         sPZog0Xo3++3/gwEwkrw5faeNDLrLYOPZmgWNlxnyFQPzHAu+pqs+ePZ2SZgFE8h4y3C
         z/+YpvSbx9H4+G94WaFMzeq1x552zJbebLqCz2Z03IPJsASQvrm5Ht/zWez1Rs6EkLP1
         46QC8XCZOba33GkE70zvfTLxj6SeDlpW2QtiBQ/Fn9yTpGB5fDkddMfOOkPQamCpFqYz
         DVxg==
X-Gm-Message-State: ACrzQf0d6VrkxeMMpWXxxjDkwaDVzOv5mxnkNMI4yP9FWJ+ODiPjugOZ
	4JKpDDk9two6wPaIzTNEvFg=
X-Google-Smtp-Source: AMsMyM5R+YMOCLF7ZLs/UXMeVCSu3vcTGEvEyTt+CHjP+QxIBU9nPRbZnIjlGomFj/bCgmJaLTbyWw==
X-Received: by 2002:a5d:4950:0:b0:230:cc5a:f6b0 with SMTP id r16-20020a5d4950000000b00230cc5af6b0mr3227028wrs.656.1665435137362;
        Mon, 10 Oct 2022 13:52:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:23c:b0:22c:d34e:768c with SMTP id
 l28-20020a056000023c00b0022cd34e768cls11868699wrz.0.-pod-prod-gmail; Mon, 10
 Oct 2022 13:52:16 -0700 (PDT)
X-Received: by 2002:adf:e60d:0:b0:22c:d483:5ee1 with SMTP id p13-20020adfe60d000000b0022cd4835ee1mr12488980wrm.641.1665435136067;
        Mon, 10 Oct 2022 13:52:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665435136; cv=none;
        d=google.com; s=arc-20160816;
        b=fUKG9o1J/pth13VeCP4NIi67aQBidZ5Frd1vydmUdgaBYg8ftAXjEOoABm9fwBHlrL
         +n/aNSDJKXk8wXMBfFk5CQP5gRuwUY3/oVaSHIQNqEE/7tbJmEt7mbpiHGZFmZ+1K5iL
         NcwkoHEDzQQ/kS0KjXLgLVY3X6RPiDUjQJBK1qX+dH9qFON7e/vp12eTnvnLlH2CXaz7
         LxFE0CLUPnpCcIyRgf/f6XcL3YO9SB+8scAJCa8n0xsGk+a8T30EaZFrbYnGRHLPio9M
         mDdLk24dB0c3toLMwMt1QE0Ww/p/6p3KYBnYPHCfsFRhmeTqj3oE3mdB2NVAhQ2bJQBA
         5m3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zMCdZsgDT6lSEa4yNENSrXv8jGmGdcVyTlFDM83Wjjs=;
        b=Y9TNbjvEWF2J4V8rZecxHRtrn6uwOW5P6RnPyRmQfy1y0He7/5cxr9rqORfDb+gD+O
         BZ2Mp6yn+s/6T88PB2a+3qYGFEvDvBuZRDJlqGmh3k9hDmuUew4DlW6EDcg5RqTUcQlO
         OeEOA740iQ++sUGQOviD44+G4PD2UYfCB2CDp+R7PN0NDotx8baaBufYb+iskAJ0JC9t
         4+3aRaDwSQqiBoN9KWPpJzJEyNjmgXdHase5uf6RLhomlNMd73jmAjkEHeQjP1F4SnYq
         cXEPMkw25TPCCDhZinMZs87Am7xSORZvh9D3+/6cQ/HRqkyy4BoRf5DTaZKunFhNUVg/
         3mwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hs6aPu62;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id d14-20020a05600c3ace00b003c46c479be1si6305wms.0.2022.10.10.13.52.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Oct 2022 13:52:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id b2so27348317eja.6
        for <kasan-dev@googlegroups.com>; Mon, 10 Oct 2022 13:52:16 -0700 (PDT)
X-Received: by 2002:a17:907:75f8:b0:78d:9f95:bddf with SMTP id jz24-20020a17090775f800b0078d9f95bddfmr8880685ejc.588.1665435135679;
        Mon, 10 Oct 2022 13:52:15 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:a8e9:58ad:3b85:de40])
        by smtp.gmail.com with ESMTPSA id c18-20020aa7d612000000b0045720965c7asm7692314edr.11.2022.10.10.13.52.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Oct 2022 13:52:15 -0700 (PDT)
Date: Mon, 10 Oct 2022 22:52:08 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0SF+Gkdl4YSqFF4@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
 <Y0BQYxewPB/6KWLz@elver.google.com>
 <Y0E3uG7jOywn7vy3@elver.google.com>
 <Y0FwC1yo1pcyL9J/@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0FwC1yo1pcyL9J/@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hs6aPu62;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as
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

On Sat, Oct 08, 2022 at 02:41PM +0200, Peter Zijlstra wrote:
> On Sat, Oct 08, 2022 at 10:41:28AM +0200, Marco Elver wrote:
> > The below patch to the sigtrap_threads test can repro the issue (when
> > run lots of them concurrently again). It also illustrates the original
> > problem we're trying to solve, where the event never gets rearmed again
> > and the test times out (doesn't happen with the almost-working fix).
> 
> Excellent, that helps. Also, I'm an idiot ;-)
> 
> The below seems to fix it for me.
> 
> ---
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -3441,7 +3448,8 @@ static void perf_event_context_sched_out
>  			perf_pmu_disable(pmu);
>  
>  			/* PMIs are disabled; ctx->nr_pending is stable. */
> -			if (local_read(&ctx->nr_pending)) {
> +			if (local_read(&ctx->nr_pending) ||
> +			    local_read(&next_ctx->nr_pending)) {
>  				/*
>  				 * Must not swap out ctx when there's pending
>  				 * events that rely on the ctx->task relation.

Yup, that fixes it.

Can you send a v2 with all the fixups? Just to make sure I've tested the
right thing.

I'll also send the patch for the selftest addition once I gave it a good
spin.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0SF%2BGkdl4YSqFF4%40elver.google.com.
