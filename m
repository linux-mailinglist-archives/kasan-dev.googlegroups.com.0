Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBPLZGVAMGQE632IULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A327EA364
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:14 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50798a25ebasf2737197e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902854; cv=pass;
        d=google.com; s=arc-20160816;
        b=fRAPkUWNQvgAOJcpE+fHCdcZ8EumCG6yhlNu1A98nrb8NbVkToMpezTYRE1Phl8WQZ
         GBaejH+6LUXzBKTaWY2d+Q1vzH6mZ6smDrBdwHx9WmiwUOOOKl32yoGTiqrt6VjxNqoQ
         ZykTbcmoG0/1Eh5Srb3mxDFWY0SH3BZjmxTPuiY9rjFe3UbGe18akRfWEpVw9PGUjyPU
         6hJtI7XlfoAAKNdOB/lhdbQhtyCQvCUipKKy1bW2Kfb9xCZOURBGzSUBYJbLb4S3Z/zr
         muu+l9bew9O9HSP3bs5dyDHc+sqTeHJGIg+TSW0jVRNqGXuR40xomRK+bdIkJjBeGyu9
         eX2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=92aPGlwf6nAIRD9CJ1d1D15c6Oi31mwIAfiQlO9gbPo=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=jNObjeiqXQfD00LaXV1l5UVxxRda0Ql8PDT/b3UhG+qP3jC27PqD/eOf7ub845L2hZ
         601KrFHx8zBhl+BNQMVP4uJW644TKRSxiNOT+irnMCTVro/o4/jXQ4lJ/9VAJPNP4cq7
         a4e31yhDwvNHeWbLU1zmpVcqUEEB3IwXIE0tH1iycTFg8gDUntaaqnUfYkBgRy5rRtLr
         /Dj/T5cafg34pvH2+RUv7j7zLCNXJMmxMAWJLBVmprSS9/0+52z/771Wb3hAxpEbHlQH
         EIjFxORJUU0XcMq9VWtGz+6YVVOoBn2XSKWbXqFKXeNxFLyNyTfq6u18hezwodBmhQfw
         pgqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aPJLjdUI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902854; x=1700507654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=92aPGlwf6nAIRD9CJ1d1D15c6Oi31mwIAfiQlO9gbPo=;
        b=NdxVJ1DZqEa4um2Zb8iFCmvDXQ2Uo2t7i7QR9F+KPtrsIM8u6t/tHqzTHsafW0ogRn
         xeX+LHQGmO3gzRu1xcVmgaC54WDXoaZF5PLKIKK7/it/a2hJrqWxkYMh9VEKMJUTOweg
         9eOrWMAQLF/d03GNkHQB5B1uSZFJ4VsK+KOva6PbkzWSJiSb1ytkmlXl45EfYwQObgW5
         Oslot1bza6Mn/RQA4gehkTzXHsN82VpOZeE+6ejnaUoMLXu+MwfzUCMBZzMw7aDeg2jT
         TC1foWa+uHxuyNTGbEkz3enMJ2qrSZXrKnSu/NeEsTyErUPGMTAlPirxhXE72kM87YrQ
         DlqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902854; x=1700507654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=92aPGlwf6nAIRD9CJ1d1D15c6Oi31mwIAfiQlO9gbPo=;
        b=WBeq+f72XQStxWQJkoxgrph/Xaf65k+Z1ckiOoN4wA7fRk3hUWHtwBGm5YQB8yDeXj
         Rq+o+qmmpVXbtDH0lBs/rJ7YFHUBunUw+W00IKxeohk+EbgZJ0hDnxxqjS2jzF5QRDuq
         b4+qJ++j69HTkGeFbb/uyOhYBNdW/igR5usXxwuB8sh5NQQ+O3gxUaw50knRSLa1SRTm
         giLsNVKfTHH/FMsR0AqmHWT6lzDC4WIox5dVMXl/gVvnvqh1q64CPOcBi3ZO9MYEPa1c
         xQu1NiGugOnKDrZs0vqtLxwJS/kq6kcEi5TKb9SqGvFnTwNfIpZvy1/pCM/cklR+/6ZK
         M9Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3Xp3eozSyUQ5N1h5sQYqfiIMSlhyMLDPNT910P2P5JmvkTGkT
	zyP1FH1ZF4fQuzGZo81Ra58=
X-Google-Smtp-Source: AGHT+IFYRNN9M2O577Hi9FL+agXR3FCHVCDNeU1G4ineNhN3gY6t3q+BypKFzZiT+RwPhEmQlYSp0A==
X-Received: by 2002:a05:6512:695:b0:509:8e3e:6a2c with SMTP id t21-20020a056512069500b005098e3e6a2cmr145935lfe.34.1699902853588;
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7002:0:b0:2c5:12ac:1ba5 with SMTP id l2-20020a2e7002000000b002c512ac1ba5ls731500ljc.1.-pod-prod-00-eu;
 Mon, 13 Nov 2023 11:14:12 -0800 (PST)
X-Received: by 2002:a2e:9e11:0:b0:2bf:f90e:2794 with SMTP id e17-20020a2e9e11000000b002bff90e2794mr18078ljk.23.1699902851707;
        Mon, 13 Nov 2023 11:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902851; cv=none;
        d=google.com; s=arc-20160816;
        b=QO4fUm7S2p9oJdUg7/Lz3EGVQkIDa0OlJbOXOUt9ufT1ewxwmGV2ZW3EdFD9XLh54O
         2K0GeqHFb/7uEku6I2wlGzZp7WGkp7yi/+7wHHitUV8hKXKv/17b/LDRoFwxCFiM90pg
         aEmMqrVOE1kqpmCUpFmaSt7ZGbeM32IuzsU4ESapFKqE3SYFj4Cpg32yxPwCk3nuBRTN
         5KH3lcsS7xhbIvE1cpwGpymKi5iXft5Ex3PYb9EtgXoSJAqaX4BSCNiQdnD23L5vA7VB
         J5GAxl6HVQ8MbCml3YejMl8RFErI9IqI+TUnx3Qq6JFlPLf4qPUwRKM+hOIpmUTpeP+M
         s3ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=UZpP3yTw5ZZBFa2ECQqDZfpxxgpcXUank5jkC+X3eYo=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=fnX0klYTm2pCXwqelEJQ6dHoVCOsMB/m1kAsqjmPlvEoolD1yA0JMATvIBdTPzwVw7
         44BjGBFOsIecOtNbRoEXVvAB8MnSqIowZ5hxvfPLBZe1tEt+/xPSbVdl6OWRmhwAABti
         vVHiIjUyMLPL48abH8HBbJMTmrWwmOVbW9fxdfmdUpGg2ERmbU6qoL4UPbx/fvc4zsLG
         xotesV7hDiaV0TdXWn0LTqU6sVp71Q+v5fx6kWkIpjjRmZAzXEYdJgJm9ab72d8LaC5e
         tBukoNShoAFuCvqtiyTNzg42j/raYMVQ1SlbTH13t0sSF8MTvQHYDoRz/jXsc7mpgF4O
         iUcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aPJLjdUI;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id k5-20020a05651c0a0500b002c820f71e0bsi229796ljq.5.2023.11.13.11.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 116C31F85D;
	Mon, 13 Nov 2023 19:14:11 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B52FB13907;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id cOyQK4J1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 05/20] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
Date: Mon, 13 Nov 2023 20:13:46 +0100
Message-ID: <20231113191340.17482-27-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=aPJLjdUI;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
SLUB defines them as NULL, so we can remove those altogether.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slab.h | 8 --------
 kernel/cpu.c         | 5 -----
 2 files changed, 13 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index d6d6ffeeb9a2..34e43cddc520 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -788,12 +788,4 @@ size_t kmalloc_size_roundup(size_t size);
 
 void __init kmem_cache_init_late(void);
 
-#if defined(CONFIG_SMP) && defined(CONFIG_SLAB)
-int slab_prepare_cpu(unsigned int cpu);
-int slab_dead_cpu(unsigned int cpu);
-#else
-#define slab_prepare_cpu	NULL
-#define slab_dead_cpu		NULL
-#endif
-
 #endif	/* _LINUX_SLAB_H */
diff --git a/kernel/cpu.c b/kernel/cpu.c
index 9e4c6780adde..530b026d95a1 100644
--- a/kernel/cpu.c
+++ b/kernel/cpu.c
@@ -2125,11 +2125,6 @@ static struct cpuhp_step cpuhp_hp_states[] = {
 		.startup.single		= relay_prepare_cpu,
 		.teardown.single	= NULL,
 	},
-	[CPUHP_SLAB_PREPARE] = {
-		.name			= "slab:prepare",
-		.startup.single		= slab_prepare_cpu,
-		.teardown.single	= slab_dead_cpu,
-	},
 	[CPUHP_RCUTREE_PREP] = {
 		.name			= "RCU/tree:prepare",
 		.startup.single		= rcutree_prepare_cpu,
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-27-vbabka%40suse.cz.
