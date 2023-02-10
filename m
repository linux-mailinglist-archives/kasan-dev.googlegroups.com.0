Return-Path: <kasan-dev+bncBAABBG7ITKPQMGQE6J7MUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B2B96928FE
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:12 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id x44-20020a2ea9ac000000b0028fd85f2e0asf1889927ljq.22
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063771; cv=pass;
        d=google.com; s=arc-20160816;
        b=NainhkD0YedEm4XmLbbeOxLvUxjL3eBSnOPdb9+mZhyqSoFOr/h80cRpp/+n+t3/2q
         X35cCRftI6CS0rD+El79FHxX3YL76p4gGKp7pVMaaDfGgrs4WKUh/hK2S/xVdXR9NKnk
         gBxYHQQLs1D93cCvctZxeIerCzMh+htsh0z6VydolnYUA3SQnm3Teey0fjMynqSTSEB+
         dpT2+V3+l7r9RJfsYnNOuqNxtkdDnUeR4r041arTfnhwsvPSXdbv0bqC3cUdf+nTnSqQ
         AQRCPfI5OgaVd0Psm/N91g3wWA85OAtGkHEoPRtMHXAk0xrnjs//PEHtwSjZU5gi9cAO
         /YKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=wXLwyhH5S/SZDn7lnmjWDDjJx74HwQp+w/Z/OJmOiVc=;
        b=yyVNb5LrXJxnMLNB226CJuNtTr5ErAmHIz4qWfpEwpCIjzmL5irYFhF9Z3Tlgzwt1U
         qr0OplfJwtrEHxvLBrPadKRdXrQg/F2UfnXDShlrSYXF434wKh40AHVdQSzNrkDl710q
         kcJPiJuUIRMEbmu76d1s484TjFnzvveisMMRXi0GdrLcY7t0jbzB0p1thKuOOAYMuNAW
         1TJz7Yj8zL+Qe141Y6vK8dUM59eFrmtKTrl0ebiJ9y1Yy1k8IaBLr6cegXWys1KsvHjE
         EVXhCwOtyPhRQXjMkfLx9swn1frgrN+aItu0FjX1buTItEFJ8u/VOzjqFozmnskvoaTu
         cdlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=g4VXUY+C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::2f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wXLwyhH5S/SZDn7lnmjWDDjJx74HwQp+w/Z/OJmOiVc=;
        b=SmH+QnRja2z8Hjg0/OFpxwSDFB7XtlywczUHgBNivYIwZi1LxnorM1CGz3uHxbtwiD
         rwPisn1LsYOTt0woV9R8z5L4w8/plHgyxD7nqtdLkghk/TqpmNRX2jw3LkU7HwAEH6Ru
         3yY8a8uQ9DaM+XWvrxWxVbIyrqHj8OsJg7Qw3z3KLpf1ItxUzFlGQem6umTG4zW1ADL4
         STPovEztJ3Db/hVBAOr6Py5UxSiTOAPa4feQCkVTYvFmpEE0VvMq/zve5aR1qruSsi8Z
         5GpcgUmlEWp+j+H2opd2qlJtIE1U2Q5FcURIAPnz3n9ZadioyImJPgGwcQm9GO+4rFQD
         Y1bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=wXLwyhH5S/SZDn7lnmjWDDjJx74HwQp+w/Z/OJmOiVc=;
        b=AsLPDLyVEzLMramsUsbp+1Y+BCPcJTkj+UuMpYWrNjfHpkLKF5hgk1rTkofYLkPUYS
         cvzbk79fnNIEK2IWmcgkZP1hmPOoXLvXm03j9F6rJLI0XCYeKEpmp6xhCnobmip0TwQc
         bvz+T/XHR/HRN0quHx3gT8IcCYXfL1GD1mW+KnjA4BKU5T1sO+WxKI59GLKyGPHZF2vp
         KRHx75SeYL6gJ3RIsy0Bxn0/4Z8+T+wTQUAiQ4MPyXewBy+dv8o6LIEnS+qv+IMszEPe
         kwS4YLhZnUURaVIQ+vvtZ/bkK5Bn+Ye3paOWP1TVO8zuwnDYwKlzc1T1PtAKy1xooBHA
         Bkrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVLXuZvF/wcqdfeS5908K0U3xosJhw7Qn2MG6V1CFDfDUx6K1WE
	wv5p/bQuwVpvyuwv/gve0qY=
X-Google-Smtp-Source: AK7set93jlfV0FoaAMd3T0uvubYgnpGWhmS5vah/3F/FS3y55mOzuGIENIZWijjzLJmnkt2I4i8r1A==
X-Received: by 2002:a19:c217:0:b0:4b5:b87a:3271 with SMTP id l23-20020a19c217000000b004b5b87a3271mr2925778lfc.18.1676063771695;
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:4e12:0:b0:293:186a:1056 with SMTP id c18-20020a2e4e12000000b00293186a1056ls1112839ljb.10.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:16:10 -0800 (PST)
X-Received: by 2002:a05:651c:103a:b0:293:301e:9457 with SMTP id w26-20020a05651c103a00b00293301e9457mr2065678ljm.9.1676063770477;
        Fri, 10 Feb 2023 13:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063770; cv=none;
        d=google.com; s=arc-20160816;
        b=E9kNbOwWnwIam48Ania4Y/Dg77FjFMtKLfl8gmAsVJXV7UpbRjOh9eX82P7Y9duAlx
         fDY2x5WONfrnYvIQzWiNrWndl1qxE0AY/FpbbFMNWI7WFS5y5nwCrjJtPcCT8VQ5W8/e
         hZ3UC3VhCrCrbkZGaQa2WvFfdXTmEn4RTorOGxbTK3qfn6iL8qoJ/oCkRqiW6MawcmaU
         FC1GK+OrryFgebO4ZwXqn+gEK4ufFPGeL3PLdoWdMRQnlqhE61Ca/MVsOnNuE/6nD34Q
         HOlv4vvS0PnYYl08JYf3AgA60/tlno1Vjzq/iZh6R96+9QnyDJbWVELVHP3IXwguEQrE
         v9sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SVXQhPxtDUlvcBHu0yCHUaIQvvsOva2Wy+xT1T1B0xM=;
        b=nF/gULESZNTthip7ZSmUNtrizPkZr9uGd9x0uc0EwNM2PqzcTcPU01vuE3qJJUDAqx
         gdG8GlAct+Q9GtJkr1qbngRXn22KRkyQnR+7sSrRk7eIO8XNpeO6ZJO5iB3gFV2r8iVQ
         MwFkjSlZ207aovx5MG99/s9WNevMbVdBJtjsWjBBbuoHzScKCVvQK4JdcQMscYMolWnv
         aTeDhkRohtsuD4ZyVIq7m7b2jO7+wuhAj+u1i/FBfcjpE3fF7IYTVNG2+Hg0Qq10+fOH
         q0EAAXFUvbEROH656GgBQ4D8Ros2WXQ0Moo0n20ZZ9xKod9f9Mt49U0IuY8wfShqDu/0
         tz0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=g4VXUY+C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::2f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-47.mta0.migadu.com (out-47.mta0.migadu.com. [2001:41d0:1004:224b::2f])
        by gmr-mx.google.com with ESMTPS id y14-20020a05651c154e00b00292f86f4312si306244ljp.0.2023.02.10.13.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::2f as permitted sender) client-ip=2001:41d0:1004:224b::2f;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 00/18] lib/stackdepot: fixes and clean-ups
Date: Fri, 10 Feb 2023 22:15:48 +0100
Message-Id: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=g4VXUY+C;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::2f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

A set of fixes, comments, and clean-ups I came up with while reading
the stack depot code.

Changes v1->v2:
- Drop "lib/stackdepot: fix setting next_slab_inited in init_stack_slab",
  as there is no bug to fix.
- Use "pool" instead of "slab" for memory regions that store stack traces.
- Rename next_slab/pool_inited to next_slab/pool_required and annotate its
  uses with comments, see new patch #13.
- Use STACK_HASH_TABLE_SCALE as a new name for STACK_HASH_SCALE.
- Mark stack_depot_set_extra_bits as __must_check.
- Only assign extra bits in stack_depot_set_extra_bits for non-empty
  handles.
- Minor comment fixes.

Andrey Konovalov (18):
  lib/stackdepot: put functions in logical order
  lib/stackdepot: use pr_fmt to define message format
  lib/stackdepot, mm: rename stack_depot_want_early_init
  lib/stackdepot: rename stack_depot_disable
  lib/stackdepot: annotate init and early init functions
  lib/stackdepot: lower the indentation in stack_depot_init
  lib/stackdepot: reorder and annotate global variables
  lib/stackdepot: rename hash table constants and variables
  lib/stackdepot: rename slab to pool
  lib/stackdepot: rename handle and pool constants
  lib/stackdepot: rename init_stack_pool
  lib/stacktrace: drop impossible WARN_ON for depot_init_pool
  lib/stackdepot: annotate depot_init_pool and depot_alloc_stack
  lib/stackdepot: rename next_pool_inited to next_pool_required
  lib/stacktrace, kasan, kmsan: rework extra_bits interface
  lib/stackdepot: annotate racy pool_index accesses
  lib/stackdepot: various comments clean-ups
  lib/stackdepot: move documentation comments to stackdepot.h

 include/linux/stackdepot.h | 152 +++++++--
 lib/stackdepot.c           | 654 ++++++++++++++++++-------------------
 mm/kasan/common.c          |   2 +-
 mm/kmsan/core.c            |  10 +-
 mm/page_owner.c            |   2 +-
 mm/slub.c                  |   4 +-
 6 files changed, 457 insertions(+), 367 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1676063693.git.andreyknvl%40google.com.
