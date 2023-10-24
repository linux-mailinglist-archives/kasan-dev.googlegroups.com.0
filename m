Return-Path: <kasan-dev+bncBC7OD3FKWUERBGMW36UQMGQE76WRPFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B337D528C
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:48:11 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1e9877c1bf7sf6334824fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155289; cv=pass;
        d=google.com; s=arc-20160816;
        b=PKdtZcHVNGovaibYM6xj7NWrRwtQ38lv9vh/fXsHWqREKpmtVGV65Jo1hCPlft8yFs
         +CdmffqTjtHcCUjkMDq7s7eCKjDGbvzczMrTo9EHgrQ0zDWaoDKT0svsShd5kpvnMgxv
         RGLCDsUrSX+XDV5SckV9EYmu96Gikbr+vZ22KhLZrEGt4APEBC6YTZCcg7p/464fIZFx
         IAqEeiZvRCzixyHpHMGWJJEAFcHice0s9bizjGcnwraPWO7WxkbS3qH8KfGv4Y1gUhWz
         7BdtJidZmvd/NFLGL3+x/MD8sMeT1IR1oXvNJ5r9WxuQ8+/xrVx3PaNVFt2bo1V8xMqc
         P4Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5gZag2m2eQKdftOpPBOuuAhsOhy6rBtJzS8ohNaiAY4=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=qv8DEmhRYF6DIWVI7Jv7rjzaoPBMD6JFL5m0e3mEZ2CgGFEJH2wL3WBwVq5oiyHkOz
         K9AfrwXu4e4jAdVwEoHBkviTtPsP/8sJXdqWZxnBPDRKJWQezdkg78HUiFjapj/h47Iv
         QLtiBRVUyp/IlH4YoViJ0H9pAaBDAAuUIfuMeDKOd6lcJ7GiFLisiTgz90AIP1mDA6zj
         ImhU0lyIapuMdHD5l3qAVCqAOzlJqNkV1K3jEz6avgDWpLeq6n/p0I6LxouabpgiZcFh
         miyd1weaNezb8EC+6aRXf/hPwPwi2S9BaeLWrWkqhGE89g/+ZWt4U0ausJ1kq3RvEpcD
         vJmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oBrv+V76;
       spf=pass (google.com: domain of 3gms3zqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GMs3ZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155289; x=1698760089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5gZag2m2eQKdftOpPBOuuAhsOhy6rBtJzS8ohNaiAY4=;
        b=YcfoF9OTZ+6SoC1UFYymQHmXWAkFZlt+KiT5+RohWg+m8qRBon8nnWwm6U1ZKypj8G
         mAQ8LzXEP9dQOT7D9jZPCr617PaeUw0fzR8dm+jse3KaCY6zOXhy6Iz9EjIPQQupr85c
         k/y3drvuDqKzJmkp3g26/Um16iBQwSY+AlRXtV3sD/xi4FX36AwpPu9kWJFizq78Vo8J
         DaYYj05IyPOyVURU8EFgokva/Xz8wMAIyBb5YcRBbzePM53/zPxwM5QwR55c5AJddgGy
         kyctavucdJSW0tYOSOE8HYQMWkLtRHDdWcN0c5va1z1fSQqJ1Mfq3qoOXLdQNMZTLbal
         qAnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155289; x=1698760089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5gZag2m2eQKdftOpPBOuuAhsOhy6rBtJzS8ohNaiAY4=;
        b=QNNJvE02GBlmO3L2mUwln+EJO23iTkYx6HZ6Skw45KGSldL3jQzpjRt/nkaWA5ckVS
         6SRmBRCJnpGI6HlVddl0cTZnP6jnclP8XpoLe4gZ47hulmNiaQXemxp8JP8VZp0KX21H
         kwa+G9hV/myBiq3V3hkotq5e7+GPPLGbhvjrL/ZXutZStJY3D2fT9iyTW9abb6yaM0is
         Ph2bJgVz3aiaNgtVJw1NSIULHCbelyyZi0fgYtOkqrWcd+hvN79DdTWxLFO/Y5bGrzDD
         ad66HWC0KuimXlfF0zxRbQPpfEGGZavV+iqDcbMxVkKAJVfegW4nXS2svzS8Jj6WwJxs
         kiBQ==
X-Gm-Message-State: AOJu0YyL2T+PUZfOm89L3zvNqZSqLlydIOGyN7rdkpq9mWLuV9wcTTKQ
	SC9HnXuwbd+g0cq5E1jLn74=
X-Google-Smtp-Source: AGHT+IElMH3W+Vzeo8afGUy6/aozhcpDwsh/SVteKkof3WHM41GaopgIO/rsqkVHyLYHbq58FyEWeA==
X-Received: by 2002:a05:6870:ac0d:b0:1e9:dfe4:743d with SMTP id kw13-20020a056870ac0d00b001e9dfe4743dmr14553006oab.16.1698155289537;
        Tue, 24 Oct 2023 06:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3b0d:b0:1d4:eb1e:6831 with SMTP id
 gh13-20020a0568703b0d00b001d4eb1e6831ls2189081oab.0.-pod-prod-03-us; Tue, 24
 Oct 2023 06:48:09 -0700 (PDT)
X-Received: by 2002:a05:6870:1396:b0:1e9:faca:bd1d with SMTP id 22-20020a056870139600b001e9facabd1dmr13048212oas.24.1698155288913;
        Tue, 24 Oct 2023 06:48:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155288; cv=none;
        d=google.com; s=arc-20160816;
        b=DvRfi2tupUV7gmH2l0+HH7JFV3Q70mjyfMivTtrrVDvoQt0NQQeukuTi6140/SDUmE
         bQTmsZXuY0h0p6Tf65ko0yy3rvJ6hnb6Zta28SqiLVmUGVYxYPQDxbmRhjfyykD+JgLC
         QHuBXIMtIVi9bP1vL1KO3qAeIULEK/pMKq4U6Tue/QglSBg2ZpkEOdRWyDRjqja32T48
         ydKcUsfmsUdqWclor1lOtpnRw1MTw2g6Ykd7fUo0foJhz7/Dr8wC+tJODHFNTxhoVUeg
         E/tbO+fdiwY5QrLbR14v7OimU/n8x1c1QPiREk4TNAxd5FAv5tMDe04i4AQIxGnWivBG
         JZFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5iA9XL/oyX6Tyl0rnn5vdBOVip3jqaNokzkLete42fs=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=CNzzR0ONQbA+zLdFNbzZNPxyyR9pmLSxygjgEQuhhc/7djHMD40aLZ0T9y/rqVhJUa
         Aoq8Y9NPWAfkiJUo0XsooXoN5Vttg7pfgnHyhl/LUk15V4pE6053+AoLft+9res6Jsvl
         zoWZ0ndksnza8GTuBE+kOiEZ7o4AeQO9B0nowhtILgA/p4A16xlwN3Ku9UMoko+Hd/7G
         9xYPi80J8wW/Io4pMICynhtWrVMI3KwsNxoD2kmetFua/Ee4dtzx5fFAKde4weJfQQQH
         Dy9L9xxcqUqi9R7y61Y7EphF4YLj172llIxVGo6o7aNhgehC/+XSmAbkeVqYkWJ/P5m8
         A1hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oBrv+V76;
       spf=pass (google.com: domain of 3gms3zqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GMs3ZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id nw34-20020a056871742200b001e99e02fa4csi1182885oac.3.2023.10.24.06.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:48:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gms3zqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9cb79eb417so4174467276.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:48:08 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:ade8:0:b0:d89:dd12:163d with SMTP id
 d40-20020a25ade8000000b00d89dd12163dmr222107ybe.1.1698155288323; Tue, 24 Oct
 2023 06:48:08 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:36 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-40-surenb@google.com>
Subject: [PATCH v2 39/39] MAINTAINERS: Add entries for code tagging and memory
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
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oBrv+V76;       spf=pass
 (google.com: domain of 3gms3zqykcb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3GMs3ZQYKCb0vxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
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
 MAINTAINERS | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 2894f0777537..22e51de42131 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5118,6 +5118,13 @@ S:	Supported
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
@@ -13708,6 +13715,15 @@ F:	mm/memblock.c
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-40-surenb%40google.com.
