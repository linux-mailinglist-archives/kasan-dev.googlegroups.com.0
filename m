Return-Path: <kasan-dev+bncBC7OBJGL2MHBB34I6WBQMGQEK4HDUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6010F363DFD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 10:50:55 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id v5-20020a0564023485b029037ff13253bcsf10792223edc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 01:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618822255; cv=pass;
        d=google.com; s=arc-20160816;
        b=iu0VSUHDPxNLUDsAEVaZx+PbFNEJareSdZ/K65HkdvtKATVBgK9x7RuF+KIrISGt21
         FnSna8x0M4LNmgXc+ZXEVmyJKoWuuD3J8sXT8bA33u1QJ2kG8HNMquMH4kOaf1taUr6U
         +7rMJHN0i0iGwlzmkiNWhf2YOIVRAcFM4Q+UeqiuNPcK/Eau5QwRbYFSDXvGeX5Pkhcw
         7PD+QMExoVCLrLNtEIz//Uo0qT8Z0x/68mnPTWl21o2SRmDQsBQ9moi3Fi6cRGmq2TBy
         WkY/NOd60TVXysvizwKExssNm6SxuvochdGvkWkBvn1HEXDw5amDZkFK2GlowKAe2d43
         1G7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=e8bMRsL0CkA9HwDhWgP9QHkFs33EV0wXLjbq236RBjk=;
        b=Dct+Asbh8MT1H9cro7OzZOjNAtyBJ10qU3ynWdQZB9gKgHLeiuNUtuT7IYMardMBE3
         dUBPD2xZ8l55sCEREWbTxhovTocYiA/atXcZNrJdUwp3ifc6LTN6RBRDPlA9q8BnA0Z/
         5HfYE9Sy3QFq5s8orwhmbS1QZhupddoWBa+FmkuFwU5e8hJzoPpvF9f1K/j4fLN+6Dt1
         Dlcs3N3Pccvq/Ba2RCfSXIKdIuRpL5tcMeKzL8CVrI82wOdLfALqy2FSBjYd5jM5YLRm
         6r5QkB6Ym7MQA1HZ36iOXQgZIgzMgTc1QyMCdzy6uvSqpm+yIWHPBYdqrKegxW0lsR+b
         6xJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jqi15edE;
       spf=pass (google.com: domain of 3bur9yaukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bUR9YAUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=e8bMRsL0CkA9HwDhWgP9QHkFs33EV0wXLjbq236RBjk=;
        b=KpIfxvAKBvRHxe9BbbAWF8WPenmP2Gcu6LhECrxoCijO0Had6kn+4NIqfKdgsNNfL1
         S7zhcRqBPU3D33ad7B3QBurZjtcOMRktyMH/dD1pDwNh+cL4ojKIt/0xsv3yVcixf97i
         wA+R30VNlv4FU9ft3spI1ew8G/NCLD2lg4HdBdb08ew3fCHtW0Br3ZFjfcN65CjcxxI5
         S3VYLZlclgvEbFuPpAsuu5wKKMTwMOs2jbO/LbmfCtcjS/6POjqMKlnKlotgfF6ZfOUx
         cDImViikAeKeZ6uRyc2PbIRKQA7a0V2gNr46dXrWa9tuLIKxVGZQHkAGq47IkSR3P4aM
         o1JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e8bMRsL0CkA9HwDhWgP9QHkFs33EV0wXLjbq236RBjk=;
        b=CgAuX2ITHvRrZ+BGYVbGELy5kJOrpCqi2E4+MISJrWf59ruADdi5hDrMtBPbYUbkI8
         bi9p/ibqDI9O4P21wC/BtAIY6ehJgMgCD/LDvqzFDujqroCvRU5lup0NXvC+ajCjx8Y2
         LbQ3Qh7VJG8Mb+JQhxiqUBmOCOl0PJ5HHlkydQQpZFdo4DhDXajbcp4YxxmVlMZ9b/3o
         rFNb8UKAr94HaKf/G3yw34cQOUebYzawy8SydS7snPSjgP+3xSJu4nPDbDEz2gBjqqad
         AxIBecdQWsciRCkOodXmsJwv8m/CU4foYxQ5i3PYlBrwNdQrQu8OBJDEmld2IVa2phb4
         4MCg==
X-Gm-Message-State: AOAM533A9Qfna6NCFoFvWgR5n+vG57ExB3ReOdDG5eTqkPlk0eQV3lBz
	BVfJkA0WPXJrQCw2s4DQoKQ=
X-Google-Smtp-Source: ABdhPJwedsJW/bGkulU+5QCwsXVnVbCSju2cxTFXoWnbt4zD57QgCwogb0XOU0+NYT/R79waWH3FzA==
X-Received: by 2002:aa7:c746:: with SMTP id c6mr9953271eds.169.1618822255195;
        Mon, 19 Apr 2021 01:50:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:e299:: with SMTP id gg25ls3477903ejb.2.gmail; Mon,
 19 Apr 2021 01:50:54 -0700 (PDT)
X-Received: by 2002:a17:906:6896:: with SMTP id n22mr21041999ejr.316.1618822254228;
        Mon, 19 Apr 2021 01:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618822254; cv=none;
        d=google.com; s=arc-20160816;
        b=QGPAR0OLPGyxf2iWRrvhqiUk9jxrHebU/e5u8bfrExmbCAohFcD+lE2CGiBMStz5X1
         IICvrTOVHhPtrg/KO0NaO02WeZdeUsBwNIqGzicpGA483xeMrPMdBX2ZZWoDtZJf5ipE
         pZ3EjQKPlFWZvxjqkpUP7eYi/7bAnpcqlQHUc1Doy5Nse0fdcU/1UaWCHnRzb5dhl/y3
         DbWbWggpo3ZhDAYhxe0WquNQEDcJS+uE0n0wTxUqzN8qmfK65UiyhQIDnnhnfix+nWTV
         oyHPC3IzFkTuUSbPTxdNxhj24BG0irzKCRDsiglXNMobNQYjgTZKp3lxCPcOnA1HcDVN
         Cmfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=VPfpXo1xSfALIUwFMBsi0FLx47EowiBPs3NWCkZXP+I=;
        b=QIch0hO4HTjhxLW1coVlT8bgmuXZdhPebaEdkTBMEkbutosNt6cqD8LDxN7zxmsc4X
         h2rSnPvCNwDJlsoPwqFHrCDEQgP8porPzc4+8YKthZ+yGX7CLyfJzkvVERU+tO1X63TH
         d3jxs9qXpR6q9+ZhaY2EmRFwBEtyYRdutXlpvcQ5Vjjgqx/X/14xitLVkb9kaZGpphLa
         UH0edL1JSoNObmcE5Uvg8tKBTZ+04rgFnrkIM4g5JJRcDd5bltLfGvlb70L6CFk35x+9
         1vkl/ILT/vaTn+yZHWlUhdpDEHEhVgEzDd4uJfCToMc97lerJkSsmgJvwZKXHLYbXEEw
         ZSPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jqi15edE;
       spf=pass (google.com: domain of 3bur9yaukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bUR9YAUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y2si471524edc.1.2021.04.19.01.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 01:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bur9yaukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t14-20020adff04e0000b0290103307c23e1so8689069wro.8
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 01:50:54 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:92f8:c03b:1448:ada5])
 (user=elver job=sendgmr) by 2002:a05:600c:ac2:: with SMTP id
 c2mr21244847wmr.23.1618822253817; Mon, 19 Apr 2021 01:50:53 -0700 (PDT)
Date: Mon, 19 Apr 2021 10:50:24 +0200
Message-Id: <20210419085027.761150-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH 0/3] kfence: optimize timer scheduling
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jqi15edE;       spf=pass
 (google.com: domain of 3bur9yaukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bUR9YAUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

Marco Elver (3):
  kfence: await for allocation using wait_event
  kfence: maximize allocation wait timeout duration
  kfence: use power-efficient work queue to run delayed work

 lib/Kconfig.kfence |  1 +
 mm/kfence/core.c   | 71 +++++++++++++++++++++++++++++++++++-----------
 2 files changed, 55 insertions(+), 17 deletions(-)

-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419085027.761150-1-elver%40google.com.
