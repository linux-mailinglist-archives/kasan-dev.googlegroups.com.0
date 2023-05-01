Return-Path: <kasan-dev+bncBC7OD3FKWUERBSG6X6RAMGQEVPUXWNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 168606F3404
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:42 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-187e7e6990fsf2418066fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960201; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDBnbMpYOvYkTRAuP2IkLnaZoo8/Wj0uMHxD94DOJiPcIvB6zrX1kBCr5Obpk+RzkO
         q7xsaxGmPFL1zjYHNjQvfOjrn3IFFWGc4xN6bQ412EjaG2/NY4lcnLljnhzzrIyZRwX/
         cfjlv9taUEMNTqN9RNaGRESKB3HTpFfkd5/oNRd1Ai9SNuTrFYhe2ENWT98OK0LzVsh1
         exYKaurJya8eso6Pt5uB+vEd/+afaSo/Z0gO6+QgCH8idTYfr/qvtPAlD95U6Q72CK2O
         5ZFnhRBx3r0jyKR+VGUgFNDQAViT5hKaphE2meDRvr5IsSZ9sF0paNGYNhsiH5I5YpJy
         09DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ueq0hWqFCAvkRWwQLJWQK/GEjIIqP2B7OH22I1JisZI=;
        b=Opm0lg6OfhR6w37DH6tJQEa278q5y+XTQHEHD2qsj8cdcdyWyyk7rH6g0DTUpU9LTW
         /sSnJ7xBVIJiMcbTVuxOuCAI3ybjwX/cnugNw3OEKOiCJQL28YhmdFfs5+Obwj8c6OqB
         SmEO7tBH4xioiWRQ7T+uccTvpYXegeGtWeu33WeuIaptveRz+IBxlLHzfeqw4wZPEdtJ
         F87UMZg5PWXN/3BodcSsxPVq91y1oPwY2fXeeQ7xolNtMC/SyPOtzsuHqRgkPgJJExY4
         MK1sbGkaqhd+idUar8iAsSzY+EJeq+Fggw4ARHg9UKp0e0/U4zM6+L3T5PLBCUBpMh5W
         lEpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XY3g0fA5;
       spf=pass (google.com: domain of 3r-9pzaykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R-9PZAYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960201; x=1685552201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ueq0hWqFCAvkRWwQLJWQK/GEjIIqP2B7OH22I1JisZI=;
        b=Oh8L7UVYCjsCc9G7YqosHHjbSEydYij/lPgQDlU5d+ztTgT1qnkJPn6YGUloIsbb8A
         XdmQJnNjxCaIlo3dhpmGTMf8LUodbVyr26F74yGRJFokzfgmtBupw0HiVNHeM6+3qW5Y
         xkmd1c+ByfxE1wkE+HjF0nYrPkVSdESp7dY9OqznqRy2YgtDuM6YAlBby+moHiZ3FEH+
         hLq+R6ssr6/7uWJmG3v/FTZ72D+P7ZGbRzIa7gyc+JrZtnrbg3dGUB3p5qbDB7JIKq72
         HxVqxwmIuqn8aCmcTsooQ3ma9wLwR8YqVpRyzatlrmAqnDaa3W4OVB8ZVfD1SaCV38aW
         kaWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960201; x=1685552201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ueq0hWqFCAvkRWwQLJWQK/GEjIIqP2B7OH22I1JisZI=;
        b=J96uuSjFLP544O5ZNhomxst9TF+BcGyE7ptbp+Emqdpzy+9p9xx8x5XO5oz4ANWSrt
         AbBd1cM/WLg/5e/1UV7NKg21iAUfnS4ASorE9IeRoqzqu4cQAcqgZOou0GcpIWXJdiOK
         6mkFIhfSdYn2+AiZp3EivNlX6yLfykHJ5s9O00Pvhyx4NgsnJuMEj4/9r/F7dyX77f4E
         w3RJnfPVGJIom6sWSKi5yDyvTCvoEN/QeUSAIfyv3rRM+H5gBgcPKEbmNs0dYLrV61W0
         mchMJGdWsG46G0PO62D0uCPBOQXs1jfpmsjzko0plrzDYfnlQuMIIJxQte6NkDzuwaLL
         QEzw==
X-Gm-Message-State: AC+VfDygSlVLz/AUN8kSSjHhVwyODVkWUmyU03pmd4gk5CzDZwOTfx4i
	KWlvCMoJT40HEKfjBAcLqYo=
X-Google-Smtp-Source: ACHHUZ7vjRqdv/pLqPhKjM9nlflr/U8m4DJXhw1V7pBk1K8rp8+PwXXu4P1isTkGdOeC4mLMlzpX4g==
X-Received: by 2002:a05:6871:4495:b0:17e:7304:6a98 with SMTP id ne21-20020a056871449500b0017e73046a98mr5140436oab.8.1682960200746;
        Mon, 01 May 2023 09:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2712:b0:6a6:5398:7457 with SMTP id
 j18-20020a056830271200b006a653987457ls1804321otu.1.-pod-prod-gmail; Mon, 01
 May 2023 09:56:40 -0700 (PDT)
X-Received: by 2002:a9d:65c1:0:b0:6a5:f682:44c2 with SMTP id z1-20020a9d65c1000000b006a5f68244c2mr6687882oth.14.1682960200303;
        Mon, 01 May 2023 09:56:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960200; cv=none;
        d=google.com; s=arc-20160816;
        b=F1uFc1LcX7TCH2Y5H/TutbAxPAp9UTEvCBoAjgmZE8scNGMmOhfOlHySajB79CGhDS
         6BLR4a2pMA/6YZ8hXMlsZx3hmLQPEqDzYnOFCfnEd1+wirrXMPS1zDjVSO6ph7Fk+0/y
         neFvRuIrkjVf8qWVgyYXgYkL3zkF3Pfn6a8AYov7Jdp0vtoDirQNIYr41kxkW1q2D1C7
         mOFw1kffnvMPhkpuMM1bQCaSg488SRgNiSNUqcZmYUdw73p2iEI6uCS2l4SYlNU3pV2p
         CP4N+j9jWK+ZVWnDlJHWllVGeuxDKhCWnKxUYtTeLRPDG8q/vD0d5br+5jMIJr3zy0l/
         2sxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=voe2xx017YXPnsPA1F569u968pU4cdVPLrVyFh58V3A=;
        b=l4ZI17hEGTuUZ1Oc2P/LeCS8Sjg082btZ68MpxqYWRQdiGR+BjocIkErXEJjjW9+Nk
         iu5d7lBtwTYC9OoAN/2Etsd68WSH+/ZQ1rjT6VKb4rEidJtwZhItZI4VGFzZdtwPh0Nc
         1eSHZSGAk0jF2tscAStCglZwdp6m+25nnQKkZ/93b8ZQpFr5jPrBNxet8EHT8VY4j2gZ
         yEDINOymBW6lrNjvXu3o/3HLLXZaWIg/16X25S6jo2V+s/1S7dIzp4QmpHzSW+cshyx4
         +HteElaHGZqVwe0hWyJu2M8QHcFbMy8gG3bOx/BSZV1GAgQTrTwTx9bfdRtVsE8R+u6y
         6dZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XY3g0fA5;
       spf=pass (google.com: domain of 3r-9pzaykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R-9PZAYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id br26-20020a056830391a00b006a6203c4bc5si2321633otb.5.2023.05.01.09.56.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r-9pzaykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-559e55b8766so38382727b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:40 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:de0c:0:b0:559:e97a:cb21 with SMTP id
 k12-20020a81de0c000000b00559e97acb21mr4262900ywj.9.1682960199781; Mon, 01 May
 2023 09:56:39 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:50 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-41-surenb@google.com>
Subject: [PATCH 40/40] MAINTAINERS: Add entries for code tagging and memory
 allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=XY3g0fA5;       spf=pass
 (google.com: domain of 3r-9pzaykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3R-9PZAYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
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
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 MAINTAINERS | 22 ++++++++++++++++++++++
 1 file changed, 22 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 3889d1adf71f..6f3b79266204 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5116,6 +5116,13 @@ S:	Supported
 F:	Documentation/process/code-of-conduct-interpretation.rst
 F:	Documentation/process/code-of-conduct.rst
 
+CODE TAGGING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	include/linux/codetag.h
+F:	lib/codetag.c
+
 COMEDI DRIVERS
 M:	Ian Abbott <abbotti@mev.co.uk>
 M:	H Hartley Sweeten <hsweeten@visionengravers.com>
@@ -11658,6 +11665,12 @@ S:	Maintained
 F:	Documentation/devicetree/bindings/leds/backlight/kinetic,ktz8866.yaml
 F:	drivers/video/backlight/ktz8866.c
 
+LAZY PERCPU COUNTERS
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	include/linux/lazy-percpu-counter.h
+F:	lib/lazy-percpu-counter.c
+
 L3MDEV
 M:	David Ahern <dsahern@kernel.org>
 L:	netdev@vger.kernel.org
@@ -13468,6 +13481,15 @@ F:	mm/memblock.c
 F:	mm/mm_init.c
 F:	tools/testing/memblock/
 
+MEMORY ALLOCATION PROFILING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+S:	Maintained
+F:	include/linux/alloc_tag.h
+F:	include/linux/codetag_ctx.h
+F:	lib/alloc_tag.c
+F:	lib/pgalloc_tag.c
+
 MEMORY CONTROLLER DRIVERS
 M:	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
 L:	linux-kernel@vger.kernel.org
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-41-surenb%40google.com.
