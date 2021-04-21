Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMHQCCAMGQEK2UFSKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FE1536697A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:52:03 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id l12-20020a056830154cb0290286784bf0f0sf13376011otp.13
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:52:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619002321; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZXsfQvCjnK9SYvLdQYiRZVlwF2BRer5MotALRnu8INKuPDhRqStTCp/nrjEN+RAUnu
         e0lGHq7OAknvETeataDW1Rm0klgSm5S7GBz8C91Xo6zJO8TvWZVxVAWigxwiBXGGSxy+
         qPbYOb7F4VjR2QO2UIaq0SNttIuec6dieY3X1oSe+ghxHhM0h/5qSlf7l73LD56hUBYo
         m+qD3IS8ktxrAKnwBS1qOT/oj4XVXXdpzVDEbaxfJkQsU8tVtfZ6v7USTY2YhOVUvYJQ
         RONSI5ZPe32ZMq5XqLfXOhi9yINls7FVw13WtY4W0z+idDcORnMJzAsya3dGGxY20/K8
         2/Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=yK7HCp/JfDf3z8dHGY39Jf/JThcCyjadi7F9dYIMVec=;
        b=e6ssarl2Axwsp8aXnOZG/mzpi1W5n6HOuXZsxnPVen9CH36T2nBSM0T5aHx+aLkOm7
         SmfD9PyFKJoAxZly0K3NaYJVlhVmq7CZhU9Y/zJ1U7mhQLnXMtj2hzgdZ9Bq5pGOy3QF
         0FVeAeXAqzpzNIVFsDUVpYqMzn+kEGOyp23eT8PoGe188hP15IXH4wq/ZqSMKDws81LX
         4F4F/Hy8oucfoUzC4LgYXgi33qfKpCVi4xgxFEV9lt17Sodssx6+0GVhS5tMHJh1XWmA
         9RayPWu6KbD8s+dIw8uYIiruxYwTs4yESD6SpeQydRHsW25VBhvW8AW6QFOtMYVLkIix
         EOxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niS9o6XJ;
       spf=pass (google.com: domain of 30aoayaukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30AOAYAUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yK7HCp/JfDf3z8dHGY39Jf/JThcCyjadi7F9dYIMVec=;
        b=PxoGJ4pIySS5phnBEO8RomUsIfQd+1SVriYcr+s2IKSZVvQ99bu0FvTgXvIc3mNCE0
         Cib0XEflTkk5QBclO68h1ymvbDywameapK+gmZRQo1LrqGfa0OQ6cGmeyWROdf7Xzd7P
         I5rs4e5Ksd6sXQvcf5rYlJp7KknoiIs6iLUvY29PDybLoySlBoFyO+gA0Il+83p6yQTH
         HlW1aC469EjfjlovWSs7ffB0G060ELv8Vf6Oq1SAMXZn7qZymKd6COswHf61eBb61HI3
         AwjToWXNaYgxCht+hgKWQ4nNDhdQYyCSIp81k6z6X2Fnn66RaBOvNraSCqji3N7/Bk4w
         2E/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yK7HCp/JfDf3z8dHGY39Jf/JThcCyjadi7F9dYIMVec=;
        b=Mo4YBDB48bsC9iajvFIMTO6usAIHr9ukaPifyhadOBuPThjRCB65I+Y6V3AMpW7spp
         qm0BmXPiSW926DHLrGATCdVR5+oxsD9xGZ8cR6LJ0IFQ726Lhnb+k+/i/c+EyzTPfH5A
         zJmxDhdjbh6TlMS+Fw3GuBAVC5sjiUODZCE/msA0YMvc+kRJVEXZ5K858/PrgfHPzMLV
         T8LCOKqDcSsXALUb9GuEx5IkATqU1ZtAQAdNQxJF6hte931RJZCklbfD048AxRpqjzEl
         Lm2OrEcnRBtaV9pyH1zGlkkJiG9dcYLG9XQisdR6/kC93X3kjxIV9hg4Htrbe/9/MVpd
         Jo3A==
X-Gm-Message-State: AOAM531jL0hTwO3LFZxQkwa5elR4kE5VHDNTAD47JQ6UrobKBsOjAsgw
	CpEopG2tAB5zrGNgcII0EPI=
X-Google-Smtp-Source: ABdhPJwDsJa54MMbcN27XG6SgJsdhBeYNhJRa8SxukzJhppw1NT6Zb3fAORWLtjunAGshlZVygx5xA==
X-Received: by 2002:a9d:4907:: with SMTP id e7mr22500381otf.320.1619002321173;
        Wed, 21 Apr 2021 03:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:590e:: with SMTP id t14ls464945oth.0.gmail; Wed, 21 Apr
 2021 03:52:00 -0700 (PDT)
X-Received: by 2002:a9d:6e97:: with SMTP id a23mr6917671otr.280.1619002320761;
        Wed, 21 Apr 2021 03:52:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619002320; cv=none;
        d=google.com; s=arc-20160816;
        b=Lp1lW/22mHxo8wWqviKCU3xTx5EygT4bceE5M+sHlpqVokTf4VjNgjfCETnPdsDkXx
         igx4UmuIUQm9Gx5RwLpGxwxMDLS4cHiBDoPuUYG24omZQe3jt1S8VRgZaVkCnQ+gTFfp
         40jSbznppdEggGZyIcJVBgEDwKV2e1U8Uuz6UAGpNl//EJZ+R8/g+wTPuj3EKaeQ0jz8
         QFBJUUkF36MLoI4rq57sbWqdilBgdMYh0tr6w/0bYaP03QUyOsd+ylLvLk3+Hy1NlhYy
         CeH8+Hbt3REwTTG/JO6IGkmVw2IewnrHtfIpf9pEE0c7zuM151/gVTsc2AaCO+qsF8hL
         bxDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=sw+9jYBxrqSEYlhC6g7s4hihWn7xQEI251/x8DCExM4=;
        b=VpOEaDAlyzdgOWi+F8njIabthDCf2SXqFqsE0ItzW4JpaLn1F9TY1SE60YvmBc2V8C
         FnR+/bLsKRUdAwAjCDopRcrQ+ym6RwesHWbW2f8V0K82jiBWnYB7YVxyMQczcZiy24gt
         BYBAf3pmmiqiokk2LK2DFufuA+9F2M4vNFzxSZU9zrCc9ojVFvkIXWCWHy0rQ0BYfFEw
         yPV6VsU0/BHgK198vm7cYtYkIXzBSYB49nm3BuWjNofiD3idMQPengvXzbef/a1NDkWD
         bBW0leXHv2XQ8gVplH1upMED9Pv+3w6WLzsi81ifcL1EdsnESKLTTyaG/r/gNKDFesPa
         K/uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niS9o6XJ;
       spf=pass (google.com: domain of 30aoayaukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30AOAYAUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id a7si193053oiw.3.2021.04.21.03.52.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:52:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30aoayaukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id g184-20020a3784c10000b02902e385de9adaso8794132qkd.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 03:52:00 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
 (user=elver job=sendgmr) by 2002:ad4:5be1:: with SMTP id k1mr12623987qvc.55.1619002320199;
 Wed, 21 Apr 2021 03:52:00 -0700 (PDT)
Date: Wed, 21 Apr 2021 12:51:29 +0200
Message-Id: <20210421105132.3965998-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH v2 0/3] kfence: optimize timer scheduling
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=niS9o6XJ;       spf=pass
 (google.com: domain of 30aoayaukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30AOAYAUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

We have observed that mostly-idle systems with KFENCE enabled wake up
otherwise idle CPUs, preventing such to enter a lower power state.
Debugging revealed that KFENCE spends too much active time in
toggle_allocation_gate().

While the first version of KFENCE was using all the right bits to be
scheduling optimal, and thus power efficient, by simply using
wait_event() + wake_up(), that code was unfortunately removed.

As KFENCE was exposed to various different configs and tests, the
scheduling optimal code slowly disappeared. First because of hung task
warnings, and finally because of deadlocks when an allocation is made by
timer code with debug objects enabled. Clearly, the "fixes" were not too
friendly for devices that want to be power efficient.

Therefore, let's try a little harder to fix the hung task and deadlock
problems that we have with wait_event() + wake_up(), while remaining as
scheduling friendly and power efficient as possible.

Crucially, we need to defer the wake_up() to an irq_work, avoiding any
potential for deadlock.

The result with this series is that on the devices where we observed a
power regression, power usage returns back to baseline levels.

Changelog
---------

v2:
* Replace kfence_timer_waiting with simpler waitqueue_active() check.

v1: https://lkml.kernel.org/r/20210419085027.761150-1-elver@google.com

Marco Elver (3):
  kfence: await for allocation using wait_event
  kfence: maximize allocation wait timeout duration
  kfence: use power-efficient work queue to run delayed work

 lib/Kconfig.kfence |  1 +
 mm/kfence/core.c   | 58 ++++++++++++++++++++++++++++++++--------------
 2 files changed, 42 insertions(+), 17 deletions(-)

-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421105132.3965998-1-elver%40google.com.
