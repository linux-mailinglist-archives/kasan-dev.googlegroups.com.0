Return-Path: <kasan-dev+bncBC7OD3FKWUERBBWF6GXQMGQEFUCVWZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AF0C885DD5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:32 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-221a566a435sf447648fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039111; cv=pass;
        d=google.com; s=arc-20160816;
        b=q2pj+0faBLKMixAgmnYodtR6Pmwm6jzWQukjDJRXttym2gmFXrac3Uf+iQPI0A0/Iq
         E8ExlMyNDEVZzDAm+aUToIygugwm9beGvpmPEVQ//BiNx64h4qFmh2MAxq0eGs32uqp1
         jZQsex8idpz8VVz1GH85B2jlON8qcXwTvbpbkSRkm19b8KlCmzPcfkfWUx4dfj+dLUxz
         7G14dNH83RLG+dSTIbX7TJ+Y38m8I+G2zlThGk5nnXAYJOE0Ky7VWOx4d/Ry8XEef+gb
         Fyb1nEHh68TCvOrKkXh5St4oBQ/yRmao7oOXb992iplN/ju9ERN5b54tQ4b4uf0/fslb
         xWeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qcDJ/laUBrX3w5/9LJ40ve7tA+BBScqMeRdhKaE/5To=;
        fh=Hc1G/skkX0BIlQUh+g+6SsTAPLDjHu7VoKNjHx1ZyAk=;
        b=0b9ghmQSKk2svp5mwNig1VuL1A5IfWqHxPQ0J2jLcLE2M0HxvBLieMS8VkElxmSE9q
         DgBcP+F7y0AOij8HadQrDqCQotEaU/iqU5GURXDAd75QXZrS5vMdPX1iUdfMvHZzOuMs
         uwYm+UU26IDzz/IIinHMRWFgAk/80Q6e5jF++Yu2NAmOZDiHLaAmsoqgsXW838qDsOM7
         i4Opt9ESkBMzors4u3YPGoGDEfbQmd93nz2h0wP1Z0J34httnlBvDwnLneC8bzazQBjA
         5viiOBRGSg+m5fmSOZc/oQ/bCShKXH77kDh7fUsnNSdwx+8Id3W7br3JY/+wSk0FpPFx
         SWlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ilCCELTh;
       spf=pass (google.com: domain of 3g2l8zqykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3g2L8ZQYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039111; x=1711643911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qcDJ/laUBrX3w5/9LJ40ve7tA+BBScqMeRdhKaE/5To=;
        b=nsWCzUD4xckfcz+RLjWbm9Z8xrdT2FQTOFOiPerUeT8Nme++OVREjpoCr7bc0CuSwN
         uvDmIRqtkcXWtT0+r06JQT905yD0QYOmR5QN4VZDLanwOV4p2yA77ER1QI2s4aTDxRdW
         C/LIXenOfngKjXRq0UwEsZGfF0/dR1BzEBUwj/4bTM9HcFptpBhu+A4IWGWOxlLecXko
         lkNEljE4cJ7cwVjSrCEgEbYWQcVHmEGDv6GJF25pGuvcTTG3opW2MmIwiFD3GV7U2Q/V
         XteggrrIybaK/S/ZdmtMOHv3TBisi4wHEsoXEVU7FElFLMKULBRaxe1ECZl+/+GRs3Jw
         2+9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039111; x=1711643911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qcDJ/laUBrX3w5/9LJ40ve7tA+BBScqMeRdhKaE/5To=;
        b=RojkOq155KKPXNUDrbpJYzYaPXIxhzBlPA6qahCtwoSnrQbAGtwg0LAbM1c1feSkG5
         MPVdl1jfuBH9MOTmARtVhk5CiKP+DEZyGMrAN5qIouwtICSaOPvC48V2mZBOcmdk1+1P
         xJVtZoDT581pWCOZ9L5XHKNtIcNaUcmFh54STJuweEB71f4G1/LHMGPryv9oe4xlvJMG
         GXyKg45qV5uRSGUv5yHaBcBJjaIv7jWCaW15vfU7Okcnqs5LsiWZvT5t8eS9CJUon34H
         emaVqrQOYO7bkkWcxRoDV3LTcTZhnXac4fEUUs6mxU6rfcK0NMVcrDkWiwVq7UDDjK0N
         0Gag==
X-Forwarded-Encrypted: i=2; AJvYcCUCb/HJytNTp9MoMZq1dXoyDvvxFYbwF08jA4ohHy9gqWDccbtLvVHGF3UkjAqEcgdd9hOGTfskBBULFGgzceGkb05LWvK4sA==
X-Gm-Message-State: AOJu0YwS6suS0Spj3lue2FRHCebfDgRWpsnoxnWzCfP20k3LTuZ8VkSr
	yNrhysjzx/K8xWrB0EeShOqCuXCqOKz0Spo3C4qvgWz5qxl/wxqi
X-Google-Smtp-Source: AGHT+IHrUBezMQn1EIkARisqppQS9KsxYvdyH/UGvvI3G/sXB+kbKW2kofwA3zxdc2Cq1Ozj3lLESA==
X-Received: by 2002:a05:6870:958d:b0:229:a28b:d089 with SMTP id k13-20020a056870958d00b00229a28bd089mr5524725oao.3.1711039110717;
        Thu, 21 Mar 2024 09:38:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:138b:b0:6e7:275c:c487 with SMTP id
 t11-20020a056a00138b00b006e7275cc487ls891150pfg.2.-pod-prod-01-us; Thu, 21
 Mar 2024 09:38:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFhXJ/Wh7ZqRjM+xLtn5ux0emHlZknsXouwc/s5n8R07Kmx46EZdRPTSMRqz5mpVtN6SYNFVoJesSOWODSzOl3jhorZ6e0A8ErmQ==
X-Received: by 2002:a05:6a00:174b:b0:6e6:46f2:d4c8 with SMTP id j11-20020a056a00174b00b006e646f2d4c8mr23436834pfc.23.1711039108900;
        Thu, 21 Mar 2024 09:38:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039108; cv=none;
        d=google.com; s=arc-20160816;
        b=b3XHT4UgsGjHSbT2cdSKzvXePH+oIyJfIie94BBpJldgrZFNKKzsah5Rl2WZjNFEdr
         1CIBSVeEplIlBxMht/ZZUp6OpFZ4mi5U1fRVemrQSalQBA58NdyQi6qChCweboXWAeUi
         7UY6Ei8ooiq/WZcVTj/pNuks5U45hCs9PMpzmloVZ0KFCPANVmBIgyKIiZVONT4i257n
         wWm2yCt2G3cg+Iyz7l+xkXKz8CiE+QBgqKCemDMlFJOLLOcTurckMHYikRotOBiA3TLt
         errjvZQHonjROB0s+KIJh8nYS4yOXkRuU4Q1mE+/TNhZn/WiL8CYaQAOiPLoT95Cp8t7
         WB8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AW33WX/ioh4EflqxU3ax5xPoUVjwxdtM7w8zUOaZaKk=;
        fh=SiaHCu7RDe9BC75HJlmCxrVEHby0Mbf0RbA8rrhTagg=;
        b=bwnD0JmG4lAIJ9huvLPPGCW+wI0U/Az3PJHbK8a7s8PLNEt9K9KCV/wQVmKGiZds+U
         ERul1hrZyIqmiyNvvjz8mwhmTlZ8GxhjhOmsLuzSRhHPRNBtp1GKX3nAq072i1CKe/Wt
         4FQZEVTwPmAXsYhDJ65glKDSZgT3UKsZ/A7H8KSlkBN5RfyWlOU17EUojmKN7IInF6gW
         0GqfgV/AnidBAZJfc7bWRZ7Q3bT7vs95UzvkF7vqyAF0iEbcBWlED1fL3P69rheV7aKX
         152gOqCbimwQRFQkEF1bLUYxeIC9BKNIDLHgr1AspVATPgTEqmF5spggMLOBVhS5vXOt
         yuyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ilCCELTh;
       spf=pass (google.com: domain of 3g2l8zqykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3g2L8ZQYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id gl3-20020a056a0084c300b006ea7b30555bsi3250pfb.5.2024.03.21.09.38.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g2l8zqykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dd169dd4183so1350838276.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVvdD6pQ+rK+Kja8OPbeAQHfsrZBlXFsWVueupAq0ZOyI3FBMkpCyE8jEkoIgGPQgxKS7Vb5QfW+YMMTGein43ZjYdh9ODaYw02mw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:11cc:b0:dd9:2789:17fb with SMTP id
 n12-20020a05690211cc00b00dd9278917fbmr720825ybu.3.1711039107919; Thu, 21 Mar
 2024 09:38:27 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:58 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-37-surenb@google.com>
Subject: [PATCH v6 36/37] MAINTAINERS: Add entries for code tagging and memory
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=ilCCELTh;       spf=pass
 (google.com: domain of 3g2l8zqykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3g2L8ZQYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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
index d5f99cc986d1..84c1505bc62a 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5241,6 +5241,13 @@ S:	Supported
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
@@ -14123,6 +14130,16 @@ F:	mm/memblock.c
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-37-surenb%40google.com.
