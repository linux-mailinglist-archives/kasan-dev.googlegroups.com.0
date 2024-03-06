Return-Path: <kasan-dev+bncBC7OD3FKWUERBOXKUKXQMGQEZ6KXTMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 408B4873EA9
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:26:04 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-68f5184049fsf64056d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749563; cv=pass;
        d=google.com; s=arc-20160816;
        b=r2kBCDn34tLvrZJ2qaL/3h1RQiNHgOHpwBut6wgWXKlSLD7xIrGa3vMiEt+2esueJT
         VF7w7YDmJhtu0tdZYToh8j6FG+5SzYNk9TtrW6XukWnUUzthIsoRCSpxQ9eVZVr00k/E
         G/vheo7iqiNcbM5RBZYBiyXnAnwpEn8V0keOXCZn9lE6OkvjClMriXIWlBN28YbZImLt
         BtVETC9OJs+SzWrwO9C2OwdiLeoalln2eD8Al61PeIWAzc8mTBWLHp9itB9RnQw2SipO
         rcluRPxbpVtW9OK+/XYYm8RToB6CW6X4F8BVVuRRqxFlJn8bFZB2e2I619M/hN4QvpzU
         aGYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Bk3qHBJ40qdubqjB0if5swBboPijzjhMHQrdFDxfdzc=;
        fh=+SEntXLRyQ+YJ32wOdeEV62kMox2awU2JBBgVnuFJjs=;
        b=rhwoz5BEZKvY2HflPN95shxTNrxzs49Vz8G5WQTZm8qzVP9wL+j3BYIkkEeSROdZFG
         dAeGtxKK4YO/m3kLvTPrC9DVwkAjd6PpOASKvAwHKSKAKG9vm+m535QYXmA8FE5fH5QY
         DB9TP3i2nCRI9wJnj/a3r2a2ywMTk19rbc0QSFUbsyMMSG8tbO3mVl5/k6TtJvqWo4Eh
         /AnB0tIG7zqE5EoV05Zlpru9GoArSs22Hs1gv5tvLnGPwgseWKjm+gYEKo9TjBffExf8
         XXaYgknSsigirGztFq7bdxJq8TnfyPcbj2X1cyh9lpPREcS7Jd6VBh5aKN8x/RGQ2Lsw
         Oaog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Mqnl99eW;
       spf=pass (google.com: domain of 3obxozqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ObXoZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749563; x=1710354363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Bk3qHBJ40qdubqjB0if5swBboPijzjhMHQrdFDxfdzc=;
        b=YkDwovrFZMwyL+4u1z4LW+vJv2BKRINF+e3G51cHReOBcAoeoJcKICGcM1x2vKnryk
         iU6v0oALWkKsVyUCvvysrt/jiwaDfXidH3/3v7jS9zOrZDYusT5wTsrahNa8OZmDsJ4G
         P6fbvdSB9l6ppgB6ZrIFaIGzMOv51zR1h1/ZuXSWofDr9bcxfonLvMZkK4/7hiJA3j4z
         ve0lEFcHugRpUX8Q1I7cu94j9wiIgCM/+OyQU9Rp8iv1eC9n8AXumpTAmB2VkOPWoOQJ
         cPxLWIc2kTQ4xebKcDR+TfbBTvZoQdBe1sI1M6rk2FaU6dfJ7u1DcP9bG/IDt7dcaFKn
         C7iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749563; x=1710354363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bk3qHBJ40qdubqjB0if5swBboPijzjhMHQrdFDxfdzc=;
        b=wH59ma9/wb5VjMTtiJdX5XL5okRAcjDxlGvImFpzIcFotqHK1Ue3XmeBlRUHEPQ8ip
         9uVhd6X89sGUMILsO45yRL8oz2uQJsM3UgunvSd+ESdSkCQIhNPyZfqFJZoTK8rfXZOn
         eRpqNWwfqw0gP7ZibZRCThE2O5Nd5M8qXtxlk/+qXoMMicEpOEmY+gzHvE7U+axc+qnO
         QAOAuPIbI0PFy1mUdLS1ulSku91NXbndml/CUh4+CgrcUi3UN2BCkNjxqP9CThe0DeWw
         X5xL4a2TsHCySiqE6Jyfu8Pz0hiKyX3XNImQ+PjGHWhWlc0nJl9/vTffSz8OzmNL20Lm
         iyNg==
X-Forwarded-Encrypted: i=2; AJvYcCWp/Cm8ZNpycL/aqylCdjfG642B4NsdPvU9xATBvlMMbkECPR0Yv35DHHEYhfPJ36y/Pz6sBCg+IOPsDlHoxcLYivJlhswzSA==
X-Gm-Message-State: AOJu0YxqnE0BR5XZVXk4cyXCcMRQ0cdYXgxMqIaEMfQovOB857ueWpoi
	auun7Xd59i/rlHAJRuiXk+XQTbmC5k3cDeMlegsIUWrF6M+0sYkM
X-Google-Smtp-Source: AGHT+IFmdk57GdY0OcPB4c2G3TRcs4yoFQjspb4r4/bbrBY/dquXn7WGtHfy+UZ1sOXSovs7M5RT8A==
X-Received: by 2002:ad4:43e1:0:b0:690:5edd:936a with SMTP id f1-20020ad443e1000000b006905edd936amr5906573qvu.44.1709749563029;
        Wed, 06 Mar 2024 10:26:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:400b:b0:690:6d7:8276 with SMTP id
 kd11-20020a056214400b00b0069006d78276ls81884qvb.2.-pod-prod-05-us; Wed, 06
 Mar 2024 10:26:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVt+cuDzv9xVBROhxL5/mjujPGZBgucuUv7NteeMfSdx1jSeqIKuLjX9pVH+35breaniGmISuWOK/frWA3beksY8kdgm+MZIyfNcg==
X-Received: by 2002:ad4:4429:0:b0:690:591c:fda4 with SMTP id e9-20020ad44429000000b00690591cfda4mr6053677qvt.37.1709749562337;
        Wed, 06 Mar 2024 10:26:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749562; cv=none;
        d=google.com; s=arc-20160816;
        b=kGKcORu9rQOocRrTDWieFBXREAG48nVOxGSiGOzHW7IEPLnRoxK4tOOIjLwBlPgI86
         DPmrZY7uJC0/0tvLIEu1I7bOxUeboGPCAgbiakW9luE27J0skYzA4r4s/dC8S/spjnej
         fodcrwCgLixaCULGpBch4csIiifMHlUme3T6jz5AIoUHUeAwErEjB/S3nblYKmXbcAbU
         DqUuRmzo5f6kCS5HCrXFd3c0GgfoJfCefDVvWFi0vRxeJqc60KIuKgPtw4r6EHRaDYpx
         /gVJ5+WROisZLKG/wFv3rVScB44dm6vPb+vDhsFy80pH8zzoRpHqCpa4+ot90+oxf+4Z
         PUKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Jq5e0nRnwdhD4a9FMTFm9DydRhfgPVhlZe9ht+OK6P8=;
        fh=3vpIvAYLo65eiFAaYG2yOJD7o99LtVzBDbEwtsi7ifw=;
        b=vcaasSl1V0ydBU+fcWZxJsXJ2NQ9ds6avijXyE//gueQDeUtRDLdEoVEvGQnGcg4fU
         iFoPCxaJX1IrdKmjbbYT9STqhosKeY0udukiFbmi2dhX4sfZny+UVfOZEcrWpC88fnZD
         ZIkeKLpBridqD3KaEr/mKU1YTaLDXEx/2n1b6g7vpMnqK0suMWgXS2DBn+2I4VcQUBaJ
         wG2P8iInUlelGF5ZWhEqm4PnETxggwwHrM9uTM8E+QZjAttpgYJkBCKgfbHxYxCdbOEr
         dOJD2XL4BPAVXfK1S/G005+zCVq8JgbH/4COZZaOVfi26dqKIOxXY47EztnOEbJe2You
         3PKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Mqnl99eW;
       spf=pass (google.com: domain of 3obxozqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ObXoZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id y12-20020a056214016c00b0068f10446451si1088412qvs.7.2024.03.06.10.26.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:26:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3obxozqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60832a48684so472937b3.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:26:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW9wEDdc/AHnVzkiY4K3WtwNHZL2CkfJECtzGA3jbR0vLlnzSFXFMnsaOdCvU3Zux8cjh+4dmYLyni2CFm5tiJ/VQiINOc2O9Qi3Q==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:fce:b0:609:e1f:5a42 with SMTP id
 dg14-20020a05690c0fce00b006090e1f5a42mr3594072ywb.2.1709749561828; Wed, 06
 Mar 2024 10:26:01 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:34 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-37-surenb@google.com>
Subject: [PATCH v5 36/37] MAINTAINERS: Add entries for code tagging and memory
 allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Mqnl99eW;       spf=pass
 (google.com: domain of 3obxozqykcxwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ObXoZQYKCXwxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 MAINTAINERS | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index f4ddbcdfb29a..03892d8032ca 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5210,6 +5210,13 @@ S:	Supported
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
@@ -14062,6 +14069,16 @@ F:	mm/memblock.c
 F:	mm/mm_init.c
 F:	tools/testing/memblock/
 
+MEMORY ALLOCATION PROFILING
+M:	Suren Baghdasaryan <surenb@google.com>
+M:	Kent Overstreet <kent.overstreet@linux.dev>
+L:	linux-mm@kvack.org
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-37-surenb%40google.com.
