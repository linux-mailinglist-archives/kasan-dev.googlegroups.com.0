Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRG4VODAMGQELHEKNSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 066E83AAC8D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:40:06 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id x4-20020a5eda040000b02904a91aa10037sf1175955ioj.17
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:40:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912005; cv=pass;
        d=google.com; s=arc-20160816;
        b=lhK/Z1AkTa9u4elWjdIzAA4XK59BfTfiZzbaC7jeqO7Z3qGQWm+EUKb0BxW3sCKpfJ
         om7AZdTAhPik7asiAublSvgyL9ecPB2jgyFCHfan+TnaNKOSxO9J3B3jcTWM8U0WB+wt
         XaRS6l1Tb1rJCVlKhMuq6YSUm1iQxnTyC1y+RXXJJpc6npY95GfRbXXXhgJiF3HMHCRu
         cFi7ueoGeC3uyLXyB9hGwuYUZRMFbnJm/MI10tTV0LCdQJ1kCFwrW4uSHc9EWyhFdY9L
         EpPjvnZXdM5Fq2VyiuM6POinvVpfa3aZ448PRTKv0MpKJ+cYtn5e9hwO9p2muY1Ma9LS
         bu0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Gp9nX2Q0pauxwYjck2jmasZjHtk2ZlouwF0h+BAdHGc=;
        b=kntHnPhzvQWbOlfizNQOn+ZvU7zjPUhyi86HBc1fZWnkCRJXefLctcPLMzvEtbv0qh
         rOVnI+p6bToIgZP6f8kDG8QSG1Oy6euDcJabTGHTT5Cj7T/k4JhSQJqaZ0+CrB3ViTDa
         kb8i+/kifrxMtPZrILl4Kp1WfBUYzYgo+MJe6TSLXXwtulYZDst0TyPa6pSecCGcO/1z
         Ytv1U0xPKy/KzRZTm3Dnmi6PR87u0RC5ddf9GHkm9fIbPdZYsgfQndjMyLhzRsqgjboa
         ArTlYa62mbwlGLN9Y92mgoY26QC0g2UBq7De9KT6xHOu37WHtwBdzoZ6slmBFQchuA/7
         ri5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZvI05WcG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gp9nX2Q0pauxwYjck2jmasZjHtk2ZlouwF0h+BAdHGc=;
        b=H+3TBwx7LVrW8x2e3/SN9W/SqriF60C/GPMf++jiyjr8LlTClB9DihObZiOsCEOpPe
         YCjzLCekVDHMNiBfKv82hVP3pyKnjVFv8RuixNd07Bgk035Bsn5uEA2wFqpyVSXpTqiH
         J0En/Xb57J6cMKVAEugmV2LMWNIla8Bl2HaWPJpc7sj8tDlvIoteZV0z6gJfpcbLmTds
         7AeoOT8fv0b/aJ5IAvyG3aw37FRbjs3G+evSXIyLWgWizC+EZ7Qp4j0LuPz+iIxwVOwr
         x9FzNH3omIltZNehujgj4v5m6rGOsv0rphL7F4GfigsT//0LQ59UiQJVlvphdHF3OlxY
         B/7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gp9nX2Q0pauxwYjck2jmasZjHtk2ZlouwF0h+BAdHGc=;
        b=qycTkMasDKpxKWyb5kcfEadT+14hhN8AUVlkjinKoKcyaMtdXMdGOl9EUJHXQ1EixL
         p2jBzwRaL4LQ8z5eD3dI+eEEd9yYW9kB+3AISVU3UjDxlOLHDgU29UuVKUpC58PepoNk
         me2OJgay77HwOcgUWrk1Sv9P1M4iGgU2wSgNs3n95uIKwMtGsZQcf9zLcYE5mNAeF7PC
         MuUQsobnDgcs2dvNZbEIkdpR858D1LaL1nYs0icIahGxq+/MIyz6Jig+sf5qRNEzlHGL
         udIR44ElZwjocBYe70jBcTuu2gPhzkmIj6I5riGx8l5e7qDQd37z5SZjWiLjUHWMmfq4
         5tDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WHDp7gvHTjU4ioFvMmO20ITFWgUni01DzWr2TRR7lAfW5mI9s
	CePasVmEpvukvoDo9iMjsaE=
X-Google-Smtp-Source: ABdhPJzMw5IRXzCI2wX7nd9+D0KavEPcBoVMYZkezt+lGRbLflduwqZEFLL505wOD8Lb8IAwu2Li3g==
X-Received: by 2002:a92:8708:: with SMTP id m8mr2466444ild.295.1623912004957;
        Wed, 16 Jun 2021 23:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:da:: with SMTP id z26ls776075ioe.11.gmail; Wed, 16
 Jun 2021 23:40:04 -0700 (PDT)
X-Received: by 2002:a6b:490d:: with SMTP id u13mr2589510iob.176.1623912004530;
        Wed, 16 Jun 2021 23:40:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912004; cv=none;
        d=google.com; s=arc-20160816;
        b=LqsWTk12YsqKeCnu5hb57PHABJ9nXXrDoGXs7xzzY8IVYyQ9ycphaX6qRYgiPcgQEC
         azOqxi0dkaxTvngCD6mcnM1oVL7hmf+0v6YkYiMPa8GZvRa3aEChShLfQqsUm51hEzRS
         UiCwmr+7+QEEJ0g8dN1ka/PGvrY5p+z+xJa1PaOTB4qAJUTsUIokuyIxTUMsTcrbhI1i
         45gre+ayHjHB3rq6aDTE4bOqmxcldOQyzPIIww3KuSrCWn93EzQ+0XC5obJGjsbJ2VvJ
         AbU5Gmb58V9+81paRAkiB2VL5WTtHj9+g3jEewe0e+3uk4p2vJ3wYtoMbw9ZSEUxjAW5
         sM6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z5tXXD3iVvEIVZ0tTMhEKfG6zykuiGGLtMWYWjRDWYs=;
        b=x+eFIaihjfF02BnCaCD5sM2uGhlrwGydMwm+6yUmFJmNo7Kq7lSUYcR25ilSqfxKqp
         HnjO9Tf7NJDfZqLqC773KV/KzUAsodguSOVDE8zyDx8is21xntoHVGDqgJP26V8x311D
         6wDgvq/8etmwUfpN0QOFywC+gZRDhVKQCefT9pWaIHVSsTWSGTtASuV85xPZVxpddYnO
         KLT0QjE9t/cGOW+z9b3hOoSKwm73Ap9opmRbGtqNBzAB3I/iPaALuyL9pzso2CufRgh1
         C9p7VB0YpmxOdA3UmpavTtxEa/Lh1xRxVRLU2lRWSMasbc9U74+5dzAhabBgTzq8BUQx
         O3bA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZvI05WcG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id r16si546103ilg.3.2021.06.16.23.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 23:40:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id m15-20020a17090a5a4fb029016f385ffad0so425820pji.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 23:40:04 -0700 (PDT)
X-Received: by 2002:a17:90a:f193:: with SMTP id bv19mr15312947pjb.86.1623912003744;
        Wed, 16 Jun 2021 23:40:03 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id b1sm4112148pgb.91.2021.06.16.23.40.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:40:03 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v14 0/4] KASAN core changes for ppc64 radix KASAN
Date: Thu, 17 Jun 2021 16:39:52 +1000
Message-Id: <20210617063956.94061-1-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ZvI05WcG;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102d as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU. I've been
trying this for a while, but we keep having collisions between the
kasan code in the mm tree and the code I want to put in to the ppc
tree.

This series just contains the kasan core changes that we need. These
can go in via the mm tree. I will then propose the powerpc changes for
a later cycle. (The most recent RFC for the powerpc changes is in the
v12 series at
https://lore.kernel.org/linux-mm/20210615014705.2234866-1-dja@axtens.net/
)

v14 applies to next-20210611. There should be no noticeable changes to
other platforms.

Changes since v13: move the MAX_PTR_PER_* definitions out of kasan and
into pgtable.h. Add a build time error to hopefully prevent any
confusion about when the new hook is applicable. Thanks Marco and
Christophe.

Changes since v12: respond to Marco's review comments - clean up the
help for ARCH_DISABLE_KASAN_INLINE, and add an arch readiness check to
the new granule poisioning function. Thanks Marco.

Daniel Axtens (4):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  mm: define default MAX_PTRS_PER_* in include/pgtable.h
  kasan: use MAX_PTRS_PER_* for early shadow tables

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-1-dja%40axtens.net.
