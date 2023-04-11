Return-Path: <kasan-dev+bncBCS4VDMYRUNBB4OO26QQMGQENI4XSEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CF5926DE7C0
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 01:04:19 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id m20-20020a170902c45400b001a641823abdsf3686917plm.18
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Apr 2023 16:04:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681254258; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECRMRCARDbqobciFNUVgDTc8Vs8hJ3EAIkicrSqRaYZJgbLnJRgC4PEf3O4DEnJUnp
         9vhgem9De2rZ/LuKHubrNYo/VwXdsDxn91HUEuy0OH4z1/ZTMaamM06AsaGgUOBGZBED
         +DjG6tPrHmZ7hBuSdz/b9npE/PRVxJXEYaUM7pJeakPHgVXtM2zcNYJtdA0S5Ss7AV3r
         t3+71/23bXp+FG/eiiGxLl3HNmZ580YNzPSk8sE2KnMVAiPgPMljlWHWOH8LXSh25LUX
         mGgA1Y5G50R6Uq28eq/BGSYCZ8zaJ6d4PkAuRLbuqx4Rth00l/h4q3E/618A1QgSKTJt
         ErVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hZGbsYex5g5Em7CrIbiNH6FrlI7FgRMUgas1bFeUfsE=;
        b=e6HKx1W+5Dn3kFBzthofiQ8tHqpkTVkDFzqRp0qy1fvJaklV5s2BDCBgd/wNGMtB7J
         P6hn5tXz92An0OL6HxNj3w0uG2yMJMSHuvaIPuOOU+gA5vpoHPl6C5caUQ/4xhIT80OE
         0nTaDiiQwpMGE0Fz60qkeqY/RzNjNrIwKXoDuBA9WTp29zY5Wlt9BpJdgUBfp3OjBzBB
         m7xyi4vDSiiQHwlX143zHNqI6QYG4uViuTxUE0+IvLaslli5wRdYREfYorY7JHhyJOlt
         KDcklpBVrcLCo8TCKGdgf6/9EoOjVEjg+epHcQUjPLtC+KauL8ptDuchdsoY9uCR0RbA
         JBRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AlKHLzQ8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681254258; x=1683846258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hZGbsYex5g5Em7CrIbiNH6FrlI7FgRMUgas1bFeUfsE=;
        b=ovaV69OXs+0XIHm7hJ9jIgeBYbGfiRYfXmgAjQoMVZ7geNK2qvTR04oNd/vvGrQmYX
         zbEvWU4zaoHhjAA2Et/Bj+Jr/0OoON8Z9LvMpnts1+/5Fczgit4yuFlkSVzpwQN9EHqn
         npbgBvFTfx04+L33V+T3BVTUI84el/U72+rvaRK/YITGU4eScoM2zghSm9tWfuDZ+NSU
         4bXNbB2KX7545CPlU++6i65XG0AwU2GG5TJ7JaM6K/M3rm0gcC9Ch3+AQcWlDZdRyDNG
         vlG54gVPeEGVKgayYgYAdV1q7EVffMhokDCfFtqFT430JE20xKufjxbwSXxHY6rLYVY0
         GLtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1681254258; x=1683846258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hZGbsYex5g5Em7CrIbiNH6FrlI7FgRMUgas1bFeUfsE=;
        b=zK24tQoYzbmcLa4BeXc60VRMSHtTpYO/iYGT51OUAutrVazqde7D+r1fOq3PGYTR66
         kkS9dsxQQoixoq3Vmwwg1NxOgxB2HtqQ4eY2LFwsGsGDuQICMWm9lEMXSiCx/7ZE3QOg
         ICL+DgIyqgyxNerZxMUeXq+XcJuNOR5O3+c0D6tstMHx3OYCFWnetssz/MxplIn4Oe6t
         5rXtYhtVjWOsOB5G+TJA3hKi0w/DGvfNOBL1IQlErWbbT1sFSmFKikYhVY2zqNhbP2B/
         Tye26aGxncl07fF6HzCbkaJzKD7nJ8wBYV1wPnyEXsHsqBRlLe5LIkFplSadBx38v01c
         +lGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fmbxfNTlRttTAQKvfOjp2qnVytxGhdAg2+nQvMxbBpdQklytPR
	3eIr5Cofo1n33fHsm9H/W9A=
X-Google-Smtp-Source: AKy350ZvvQCYGf4uCDxXnUAlspq2Rue+wMNJz/IcXpjvWv/DjScmgqGUJ0ImkxEpl624GOkZPkCCgg==
X-Received: by 2002:a17:902:6b0c:b0:1a2:185a:cd6 with SMTP id o12-20020a1709026b0c00b001a2185a0cd6mr24841plk.4.1681254257855;
        Tue, 11 Apr 2023 16:04:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d512:b0:1a1:a83b:2ab with SMTP id
 b18-20020a170902d51200b001a1a83b02abls32593607plg.7.-pod-prod-gmail; Tue, 11
 Apr 2023 16:04:16 -0700 (PDT)
X-Received: by 2002:a17:903:2903:b0:19e:7a2c:78a7 with SMTP id lh3-20020a170903290300b0019e7a2c78a7mr24791plb.57.1681254256845;
        Tue, 11 Apr 2023 16:04:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681254256; cv=none;
        d=google.com; s=arc-20160816;
        b=Xd7bdIxL1ZgFUs9vpjMtg9UfVzZtJgO0o2ZoUNRvq6Nq3TI9BN9OVIRPXm3HPpopZT
         3mKcwi72414XZIQScIFzIBb9cmGnldbr+VFoMlp7TSxSV0DG5rTthGD6/JQ4W5CLVRuC
         FHnN2UNGURDj/TO5Q8XSehjKA2rLt702tM04WWcoJeR2bQbRIy0VoVVDwxDEB233CcN5
         aoTOXHYOsaMvLz4q3tg9cy+/+oeGQBfMbB11MdmrQzU9gPS9aLwoRIgnrxXohgtVtNlJ
         XtX4J/m61O2oEN1SCCGm4bNHMNxZ5IQBdHyitNthM0iFTzsToPaVWnV9LfAE1hdxz9RT
         BlUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=X8zeolWUmCi3VU1yLiRBmAoGfPOaKuEBbMzG/FFUJFI=;
        b=HTh2UAnEhHvSvkVK4Dbncq5ad6ItIgz7bXMnwnvn/E+LIz5R4TbSu5qu5dtWyuBV2r
         G1mHIY0T4+OE9fvDll8wZFzqGD2odi+e96/0Vo6GAiTf8SYnMQhTydtacpjCQTPd4eVN
         HaJsxQySGD9WqnQj+tV3cz6h7RV6aSKliP5Hy6X4wGtu123SHCh0n+qbu9MqxCQZloLR
         MgBAm5B069JhuIUbHdFCrQRPROUa+S95BkCFcxMMwq55S+JgnZbZSWwUgeRWeIzhmoEU
         /pQsWYXblHY5V1wkxQFpFBSJz3vm03taDTDWCBk9wofYovIbRUH1GGCFWocpWzxRVVzP
         Vq2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AlKHLzQ8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id kl4-20020a170903074400b001a64127086bsi308060plb.0.2023.04.11.16.04.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Apr 2023 16:04:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 45C0A60ED2;
	Tue, 11 Apr 2023 23:04:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A7979C433D2;
	Tue, 11 Apr 2023 23:04:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 385431540478; Tue, 11 Apr 2023 16:04:15 -0700 (PDT)
Date: Tue, 11 Apr 2023 16:04:15 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kernel-team@meta.com,
	kasan-dev@googlegroups.com, elver@google.com, rdunlap@infradead.org
Subject: [GIT PULL] KCSAN changes for v6.4
Message-ID: <147f3556-8e34-4bc3-a6d9-b9528c4eb429@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AlKHLzQ8;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello, Linus,

Once the v6.4 merge window opens, please pull the latest KCSAN git
tree from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2023.04.04a
  # HEAD: 8dec88070d964bfeb4198f34cb5956d89dd1f557: kcsan: Avoid READ_ONCE() in read_instrumented_memory() (2023-03-11 12:28:07 -0800)

----------------------------------------------------------------
Kernel concurrency sanitizer (KCSAN) updates for v6.4

This update fixes kernel-doc warnings and also updates instrumentation
from READ_ONCE() to volatile in order to avoid unaligned load-acquire
instructions on arm64 in kernels built with LTO.

----------------------------------------------------------------
Marco Elver (1):
      kcsan: Avoid READ_ONCE() in read_instrumented_memory()

Randy Dunlap (1):
      instrumented.h: Fix all kernel-doc format warnings

 include/linux/instrumented.h | 63 ++++++++++++++++++--------------------------
 kernel/kcsan/core.c          | 17 +++++++++---
 2 files changed, 39 insertions(+), 41 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/147f3556-8e34-4bc3-a6d9-b9528c4eb429%40paulmck-laptop.
