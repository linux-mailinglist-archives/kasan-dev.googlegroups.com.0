Return-Path: <kasan-dev+bncBC7OD3FKWUERBNEMXKMAMGQEYOCTJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id BE23B5A6FBC
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:45 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-11c438debc2sf3596975fac.14
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896244; cv=pass;
        d=google.com; s=arc-20160816;
        b=amnGtVbmO3Tr3Ep7f8OZcwoKz41npV+/3Sj40v0wigWfWnZJBAXnVW3u7B5wBnuvK2
         BBm79RRha6B3zUhr9O0eVXL8RPjTf25hogJ6HiKHU5AxvOotMR6aHxB65KAvraqAttLN
         swHWP35MA4Yv9vQAygJ9j/hhXVwm4QoPfI6s7oHS/zXEp7qVTNyqvFeObSfCOiDrOeXi
         St2BePy714pC9VBmS1i41TyAqstVqsUdRsQhJlgH7yn821x6/JdynUm/3o73/D/7kHh/
         zn99MDL9/Vf9swyo2q8L5ILKKiTHXSYCZyA5Ldl7Ud1XYEzhyC0aw4IwqdpKaRY6HUCh
         MTig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=h+ZthPLf84f1fkPdWUdXiW/V886EgHZjTmPLUzokpM0=;
        b=IUb3r8GCUZDzA8tDDgEmQEhx7D0xFkdBVc7BNyj8f6EQMOyOHeq4RUpJdqky3gpBaY
         WKxBdazfm/k+KViVJJNmKrFnTFrFFI4KNNmX8vXZb+ODLH83ly66q2sNb5QoRF6lpEQ4
         raPmyQLOwhOVafEPkMXDxVtQ/OLZGD+YJwUQCGd3/4/gicZaI+Z47bKuxr1zvHOBTQap
         xNrGt08UPoYhmaxnduwQrHWWCq9V2GimCamtccQkywqRCFeHoKg2S95C6Grcw6/blD8S
         Xavhw1uU6kvsRIcOm6MifKpk5UxVwF6/rv4E9z0tuUtOKKSPFffwFaprznXIwQMNu1/3
         bEDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C8JONxxX;
       spf=pass (google.com: domain of 3m4yoywykczgkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3M4YOYwYKCZgKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=h+ZthPLf84f1fkPdWUdXiW/V886EgHZjTmPLUzokpM0=;
        b=Xm+TIDCblewzUTbRddcGbdVghJ5ORroMjMRLXUhtVvLQ0jJCq+fP/TX+JgdhIyyvaG
         J+UiVTmKSqD7P9NIzpa+BqczMRIizyMcq1Mtg5R/1lfvVQlcHn4qFQ8dMyQtdbQXUZYH
         kTbO3ZcKDHvBhfGOWmGRGW1Ttj03tYbep/1Q4MMxByoCymab3RVXdkE+wVEDfiSvMhlg
         6p05JMgnJHRPDmexcEOfc7k8Ggx+ugHIQ/gq9r6M6aw6fp4sJLNTtM6X6plQPvih6p9K
         xD2bCqOQBR4Af98lW53BkYy2qpBXSsPQI3hYafXNl+yzyO01GU0SR9TUwhUJSdDcjRPw
         wqqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=h+ZthPLf84f1fkPdWUdXiW/V886EgHZjTmPLUzokpM0=;
        b=CAlx1+b30lx2jISOGpP/PVcXCzJt3sGn8/08XJ8xE4JhysMmiLX4tpiiHSDeT07pmc
         dwIWkUZcBQyKzUXVJNQ0IbBruaJpmuLBMXoPqwhssWAwmCUNHxD7lL0G12m2bYbZ0BTj
         sUpf2ngDKutU7mCuPH6cbMw4d81lQWC6uE8BxGQp88iaXZtloxP8ZfWXn2jdRCLNL2vs
         OvC935/5O+oT8HlFr1dozAwARqIJGTxHN9nzPOaNiiAz0O6I5h9p8pGdzQNlB3ECkbr/
         VPsQrtvyMxyCdscoRRdqs2/U2wUnWmj81D3RMkm2ylM3BEUQ/u6MOXIBpFNgcTlPLykg
         N1Eg==
X-Gm-Message-State: ACgBeo2VpEbsQbcX3GG9hc8P14VyAQ7ODd3EkYYWDt3arYLddCvQ+9T1
	eC18V7wXD32JDm57+BAZk6c=
X-Google-Smtp-Source: AA6agR6T0A7T0QV6Q8AzM2dbwOT+CgnqsHkL4st3+xNzWmsXKYpmeZIwN7ES6u0bFlenTLBpmxOaSg==
X-Received: by 2002:a05:6870:210b:b0:101:cb62:8ccc with SMTP id f11-20020a056870210b00b00101cb628cccmr47824oae.26.1661896244705;
        Tue, 30 Aug 2022 14:50:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:8d8:b0:33a:322:8c2e with SMTP id
 k24-20020a05680808d800b0033a03228c2els3889584oij.0.-pod-prod-gmail; Tue, 30
 Aug 2022 14:50:44 -0700 (PDT)
X-Received: by 2002:a05:6808:1896:b0:345:32dc:a152 with SMTP id bi22-20020a056808189600b0034532dca152mr20190oib.103.1661896244305;
        Tue, 30 Aug 2022 14:50:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896244; cv=none;
        d=google.com; s=arc-20160816;
        b=BS0D9bqm+dfiHV4xmbr6Yui1AeTymzq8U5ZVZoCjp9h/E6zn/vqJ78nhQgr8tFBCEa
         AdR/ZxL6MgXwssFl7pdECxqOiy0kfoejKRyWhvb2kB08K3k/ppNJMiA1Aa4jKpkaGhjY
         nQhLzSiElH+CjhzbowqoLCfA0+Szu8Hg7rHzJ5avoQ0K/T3qqjlpg0DmmnbZyN9sfCvo
         CBlixFuQURlJiG8bvh2t5iK3Bpli0DgavENQYUpiSsY8+gqfacrz2Kl9MtW92VfgJE3n
         Y+1vkObK9w+UUZ2IXkk6WQsF8nolwpSsDeA3QhwQKjdpAGEmAZ4I1Jd6V6V/t4WCefqd
         6ipw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=q3DJ62FdAkc75G5f5TC1WQpGOVt3l/MJJCNdx5cTnOk=;
        b=knpaHMJfTQSlPwCcem0ladrPFh7uqM3IacZKdzSUobWofW8dY52wvlABtN3DrDTcf8
         Hcv5ALL92deQDujVCtpl0chIVm+zWpg5a7aKYqhy59Zi8+bQppdMaREMCqgGGILPx7vF
         /uMcjqJk4aqtIPhxepNCp3PsNzh5TvuO13C712oxhXdos6fEmgpyVIxpT3WPTARYQLuK
         3I+keQgL18Bo7MVLOs7+U7AJZHCgyT1whrxFqd8VUxY2KmSgqesdQzm/aVdH1WlI42wd
         v5e6tIkPZyqwTMdGnJB5MIFV8VK0pIq+jvKoq99vnPtrTguPc6Sw93HERsBYVsQpefAL
         sfcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C8JONxxX;
       spf=pass (google.com: domain of 3m4yoywykczgkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3M4YOYwYKCZgKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1292006oao.5.2022.08.30.14.50.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m4yoywykczgkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id d8-20020a25bc48000000b00680651cf051so725955ybk.23
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:44 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:8a85:0:b0:671:715e:a1b0 with SMTP id
 h5-20020a258a85000000b00671715ea1b0mr12680068ybl.98.1661896243785; Tue, 30
 Aug 2022 14:50:43 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:19 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-31-surenb@google.com>
Subject: [RFC PATCH 30/30] MAINTAINERS: Add entries for code tagging & related
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C8JONxxX;       spf=pass
 (google.com: domain of 3m4yoywykczgkmj6f38gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3M4YOYwYKCZgKMJ6F38GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

The new code & libraries added are being maintained - mark them as such.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 MAINTAINERS | 34 ++++++++++++++++++++++++++++++++++
 1 file changed, 34 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 589517372408..902c96744bcb 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5111,6 +5111,19 @@ S:	Supported
 F:	Documentation/process/code-of-conduct-interpretation.rst
 F:	Documentation/process/code-of-conduct.rst
 
+CODE TAGGING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	lib/codetag.c
+F:	include/linux/codetag.h
+
+CODE TAGGING TIME STATS
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	lib/codetag_time_stats.c
+F:	include/linux/codetag_time_stats.h
+
 COMEDI DRIVERS
 M:	Ian Abbott <abbotti@mev.co.uk>
 M:	H Hartley Sweeten <hsweeten@visionengravers.com>
@@ -11405,6 +11418,12 @@ M:	John Hawley <warthog9@eaglescrag.net>
 S:	Maintained
 F:	tools/testing/ktest
 
+LAZY PERCPU COUNTERS
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	lib/lazy-percpu-counter.c
+F:	include/linux/lazy-percpu-counter.h
+
 L3MDEV
 M:	David Ahern <dsahern@kernel.org>
 L:	netdev@vger.kernel.org
@@ -13124,6 +13143,15 @@ F:	include/linux/memblock.h
 F:	mm/memblock.c
 F:	tools/testing/memblock/
 
+MEMORY ALLOCATION TRACKING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	lib/alloc_tag.c
+F:	lib/pgalloc_tag.c
+F:	include/linux/alloc_tag.h
+F:	include/linux/codetag_ctx.h
+
 MEMORY CONTROLLER DRIVERS
 M:	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
 L:	linux-kernel@vger.kernel.org
@@ -20421,6 +20449,12 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/luca/wl12xx.git
 F:	drivers/net/wireless/ti/
 F:	include/linux/wl12xx.h
 
+TIME STATS
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	lib/time_stats.c
+F:	include/linux/time_stats.h
+
 TIMEKEEPING, CLOCKSOURCE CORE, NTP, ALARMTIMER
 M:	John Stultz <jstultz@google.com>
 M:	Thomas Gleixner <tglx@linutronix.de>
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-31-surenb%40google.com.
