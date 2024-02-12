Return-Path: <kasan-dev+bncBC7OD3FKWUERBYVAVKXAMGQEIDTC4QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F51851FF8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:51 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-59a3956d3d8sf4725008eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774050; cv=pass;
        d=google.com; s=arc-20160816;
        b=wrkou7vtZdZN3WFzMuJQ00Aa9vaR81erdKyb/Um1X00qkFn3p4I9NznRVwH11lF4ZR
         DHHz+dj6oV/iESQE+AzIaVQrYeVH2EbZBlTmrMRK0FBwf+caX+/9JZmUFwbGfogpM5BE
         lbs5ycWHJzbJMpVnlNVk8idG3phSzUuH50X7YC+2V2LpKI9TivTcVGD8VGysEOZe57Pa
         hCxZX6vVN7e90aDwwGt3dPqwhVdtl834M3NPcz89dJ9y4k8iSeSoxG+PD3qrSmAuf3Nc
         fmG2TGtPCadUpcvkBO9yL9lCp6pP5FVD+zZErFZ/6SWAQ73m2koW59fPaPkvvlHHIRZP
         /lBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dhEN+mwX70zj0D3f2bMHL1sZIhB0FvkzfOqaBE7O/RY=;
        fh=60EWFqa3GyNsemVl8drxiQXmBnr0hjWkRzOSluKz0mY=;
        b=zUI8jH+kUceEJSZAHHQcKyDIR0dkgWmpGWjhNJ9fzHBW+NRXHktHJ6y/JN5l6joXmG
         S0IiX5pL9Q20wnRwzTJHTIGO8m2UdFYdQEJDGm7W/66uW5dFZ2PtS8k0z40uR+Vc6d01
         XdViiL2THBNvjDYieo0A0+Ui7ZGnfMjyjx/mrTcRzQiRQWViP/zwjpVhdb0rhhhJnQ/S
         8eLCcMzXQgILxlLRknRDvBqDN1y3g1XSN91Jww7LE/krHt6zxtHTICAHi4dbpH/+AR+g
         whlzORtj+/skgh2+Ollcu0Ap3krcHWooZ4hbS2s78GY9GNBaEm6eLZ7cOfdGXtO408tQ
         v0qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SQmOWKlF;
       spf=pass (google.com: domain of 3yjdkzqykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YJDKZQYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774050; x=1708378850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dhEN+mwX70zj0D3f2bMHL1sZIhB0FvkzfOqaBE7O/RY=;
        b=qENZ5nwZCRTKyRsbzq9GGpUi9qilbFNJ98K1ADmTGF+SWfYcemJZIa8AqvqtWLpiXe
         11LNzRdsMrL9z3M9E55T60lJQMDWXklZFQ81XXlmxbgjgrzKbTEvRydcj5HUy0Ispv5P
         Vptd2rqs87hdcMlhJz1diy3oLvTaiEpl4H6kwPsHEPc/aVhy0x8C4ZS1ONsYBbxH8fsQ
         tDDRGy3VkFVNgozBxAlUixPvvEVnetuSAffYBfu8EMAtia5OgGJxuOioi7ohSYjcunnA
         XJt9DVEBK73IgLajAlQRgGfetpwpWpKGgg0BwzN5jEgzmPfmVDmRdaQYZRi6fyIsWCKk
         1z6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774050; x=1708378850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dhEN+mwX70zj0D3f2bMHL1sZIhB0FvkzfOqaBE7O/RY=;
        b=pgyrHz9ZdsnMMmG+5sdBcCfp1vGf39siSp9gfK9amXeeqnJ4QR3Wl3a+MU6A74BDFj
         ta9Oq9aqWPEPwyytqvwNPqmipwapuI/CDtCEqjTexMQHH3EQcy5fCb3hgB3XkFHEh2X1
         TFtfZliOr4Fxkdip9Z764XehAsyOZ3vFStOeDwxkhw8MWs3x4xn4KcBELogzc02qzPZM
         CdmwBOAnOGJ97QSfKbf3cDRFeSgkd0lLQVJQcikwuJy4OBlTfIr1L8M8E7il4pJcgI3V
         yr6+6ja9l7pp2SHnirRzT5Y5Il/MmghdrKFL/W7L8tb3rBUPhvPUqoshq9L+lyEZfcu/
         kcnQ==
X-Gm-Message-State: AOJu0Yzvtsdbbe3YGkYBHD4opZUA5/WpM2sSk/yoCqDg4pL+V+/wvmEi
	IYQERbyWHbmsbnNEDGGBPuphu8jY5I3HB6MhwSCzmYEeyVriHEPI
X-Google-Smtp-Source: AGHT+IGorpCzhwptRB4qPKc127tMBB1/SAeREC6/ltlUq1EoDAOdIUhtc8d05LZkf39NEOmQDiah8w==
X-Received: by 2002:a4a:6556:0:b0:59d:4c13:8fd with SMTP id z22-20020a4a6556000000b0059d4c1308fdmr4700613oog.5.1707774050157;
        Mon, 12 Feb 2024 13:40:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:584c:0:b0:598:c95b:c3bc with SMTP id f73-20020a4a584c000000b00598c95bc3bcls782957oob.0.-pod-prod-05-us;
 Mon, 12 Feb 2024 13:40:49 -0800 (PST)
X-Received: by 2002:a05:6358:428e:b0:179:28:8056 with SMTP id s14-20020a056358428e00b0017900288056mr13377897rwc.22.1707774049267;
        Mon, 12 Feb 2024 13:40:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774049; cv=none;
        d=google.com; s=arc-20160816;
        b=K7unY+b3EJAEg1P8gr/AG+aLTbMHu1h7WljHpdamUSmCcLWbHJLFoRoUoL2wu0zoML
         vvv/oTHRM6CBDe4xKU6MWUW8dQLOa1DUOhyyxBjUc9v3p6UWxK1ybxcfyr1avxXSPC8n
         nf16/Gj4jWTCduLrDzKnCHEnMu4pc1o74K/qjf+XaOzQiUklbFXKY2sDAOH8x1R1nFCo
         Q6xSB26/btqy6DU14I96UppMW369OvPkruE/RNawnBgI8sc4NYxF55/kdv1jp7JvFKjO
         0k7SCqtuq98+NefTIedwh79WaN5mR1gq8ME6WzozkQTO8U+fLS9RzRwDjntvTqyvgHp6
         qp9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SBX12uj3ZhdKUrlA/PpkAMdvyZt1FRyTju3ec31OSZc=;
        fh=60EWFqa3GyNsemVl8drxiQXmBnr0hjWkRzOSluKz0mY=;
        b=YNjm8qZ7tZPICDuebWkB9UWpxnSQ2ITj7cN5VRnJSd5SvBbZ1Yi92p3/oM4Z4cJWoc
         rW1h5+LLoCJr6ZO/7qpFGiNWdjWEPPrbwtdUYfgyS8dut4lvpRSdqErr8LqIljxBokke
         Ihlce3rIu1jaQVhGcFdW2395C+to/FwIvdXJ9/S7DSWllxCa9iO+Jq1I0LM/MCUWpj2j
         sm6v69tSui0VpblnCAaAAtOp9PvyQePYCjvRxF50ljTgO5J8b3/YQC2CRx320My5tjpk
         vLTFYXJZwhw/KcIH/dpZSS217aR0ubQNHHZlP7XqX9eRHx9qf48lPoWaIkkpqDogdITi
         d3sQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SQmOWKlF;
       spf=pass (google.com: domain of 3yjdkzqykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YJDKZQYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXyPuYlYIMJjviCi/iMU9P0BAOFMYddyzHy+vpjgHEA7+56t2UtlxPwSNYQts1S0lpDRzowQpdhXzrbr+1eSDo+iqGuiZhU1H8rUw==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id bq9-20020a056a02044900b005dc1683daa5si40397pgb.4.2024.02.12.13.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yjdkzqykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-604832bcbd0so78727857b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:49 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:ec9:b0:604:648:6dc0 with SMTP id
 cs9-20020a05690c0ec900b0060406486dc0mr2354569ywb.10.1707774048308; Mon, 12
 Feb 2024 13:40:48 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:21 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-36-surenb@google.com>
Subject: [PATCH v3 35/35] MAINTAINERS: Add entries for code tagging and memory
 allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=SQmOWKlF;       spf=pass
 (google.com: domain of 3yjdkzqykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YJDKZQYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
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
index 73d898383e51..6da139418775 100644
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
@@ -14056,6 +14063,15 @@ F:	mm/memblock.c
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-36-surenb%40google.com.
