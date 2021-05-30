Return-Path: <kasan-dev+bncBD7JD3WYY4BBBUFRZSCQMGQEANMMMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB55D394F99
	for <lists+kasan-dev@lfdr.de>; Sun, 30 May 2021 06:47:13 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id x12-20020ae9f80c0000b02903a6a80ade45sf6655925qkh.22
        for <lists+kasan-dev@lfdr.de>; Sat, 29 May 2021 21:47:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622350032; cv=pass;
        d=google.com; s=arc-20160816;
        b=fgiRUg86zwqHoJ9xrxlIXDihVO+iiXJ+KBXLk9RkXPBF+E4lbQDYuyGT1UWfb9M6Ze
         5N6vlUesBeM99/cmwoSRAbEr75u8Z0ip9efJ2yGTFgkbOXQdcePrCAA6KNN2T1bozrv0
         TiACmRQyeGC+tkBERNStJ3d0XTqpqWKh4h88ejen7an9QagoFEoeCM1PUnNcVBhlZsDr
         SgjDddlgBSbndxQkAns9j3zKsLtMgB5ZhvKsaIeVz4iu97mhNAUWbtluOFmlGEFhvCEz
         qSoUyLe+axFa3aNQvd7DqHaR5AMSPdlSqPdYCi6cu1eByAzf4QBqWhUAu7nozlnKRkq1
         trMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=l2KyZarfUDOYZ70gvZEbFtp6Hmc4pwIoJHEVjsTwOzI=;
        b=VuZZYDxf9U9bZqu/fERW5vz4lIhtUBsGdxATIE4Fa0yjA1O7h+8wJqwNRjuw2F1vOV
         /dE3b8/+4Hp0CFRj8Y/2TjsI9gG3VzC6XvlhjHY5TpMSlb16k8cLAnBt18My06CnVfj6
         rLlDkhqskQ5rIqpIPVZ2hsncXtLMLFBwPeW+1qRiM72JRdyTg7/7HQbVrdqTEu5iTpwI
         AAo6BoDK822LwVKKy+i610beHmSpI5r5m6v6JFBXQAlTJD9t4OIj8GPrgmBzFBtHRP7n
         YaE9R1o9W0yEH+mqiTtynBJH1uGkKHlZ5tUNHHcPoyp6WzhcQHom9I/lJDE6hNWzoGSz
         vHww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SzdHbLf3;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l2KyZarfUDOYZ70gvZEbFtp6Hmc4pwIoJHEVjsTwOzI=;
        b=M9QP0bWCZYNja4nllJ4Olhjufl59YRGrF0f8ogAB8eBM67z1PtGizxY+lL8Prpgp7D
         8ndLLTSxQ3mNT85mP06wmdLnOgNBygjz0keMWcTAWqnrK3TzgbXKHQnHM7PK2fOarsG+
         6osLYtVvY7xVx+4NHij0fS2gNsvoZG+qtbrvY08ivjJOkSui7ANRHk7kXhF3R+KwIeRv
         bUmCC7nCGXutvidde/Ihj+Dzi4fYz7ZtubjV/x0nSYPSdG10bbKLRugk1aEgcnGtM0uC
         UVQclLiHC+XvG6N4kb6mQGn7JYUrW1eq8/mJ++JHPid/7sE6woHSAvPXEBjjkSa6dz/g
         n+Ig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l2KyZarfUDOYZ70gvZEbFtp6Hmc4pwIoJHEVjsTwOzI=;
        b=Jk8Dpu0j8+R1qiwUmtt/CQAamTNW60eg78rexmJf7ciTjNX71RqBwTWyvB7jfHwuey
         bMHyLsGqI+fMLE0ZdFvr/JWuOC/e9kTd0gWrRhjRgBH0YZdBLYNealXDMPYofftUxlL3
         9P6t8EcWK/ypSt+QTPRXFP7D/EIXXa+fOnYWmFs+4+XfidfPm9pHGw8vsFszZBcWZRj8
         BQg+3CEnwjV6r7SjBNpJ6E5BWMS21kPwh56XOvDSrxq61SZv/3Vyf15ygSmic3bQeI6F
         zri9/UDZe+32ZlMO9buQvh1DcrkdQLQl3C5hX7x5HiiXijUkjiqXAd/jT+NHwLV0GH1R
         o2gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l2KyZarfUDOYZ70gvZEbFtp6Hmc4pwIoJHEVjsTwOzI=;
        b=TWCHaBU6+oijNjEwVcnddabm6ITeyCMOEM1acWv+YdxqT0uzSA/8fWcqnC2lSnphbu
         4IeajmOeXoq414cQyEt1vRZ2FGaE6ZSPcupX+MDQExq8sjnejVqUd8u4i5ftFNxHsOL3
         R6crUk2yJmlfgsYcje/axL3mO6CNFId6wwCtrTDaczpwK/2aXEH/FR6nlKwXGXTPnUQ8
         yqSn+Kmc48vCGaLdOQNPHMG3kZPuEv1TbS3hTelOMTQimbNybfDeYB/76UzMyITxalNX
         r1VKGmLuyLGLlTuF9shCfu3JImj57NLxE9Kh1HK8O2trSCp6VfSCpXF9RafyDT2SzBeF
         D3Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NscBPsmrGZN/+JS5KxQ+fU9AlNHJ9epRIintWsHoIXrGpltfC
	Dm76LpsyEJHieskR+n6hahw=
X-Google-Smtp-Source: ABdhPJweNqMBxk3kEdhyfaa3d/KHLH7CSVZ7y/gYXEZgrVwmjRoZ85pqMK96klCqOFiBYhKLOWwjtQ==
X-Received: by 2002:ac8:41cc:: with SMTP id o12mr9780678qtm.225.1622350032538;
        Sat, 29 May 2021 21:47:12 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5f44:: with SMTP id t65ls6954539qkb.0.gmail; Sat, 29 May
 2021 21:47:12 -0700 (PDT)
X-Received: by 2002:ae9:ef4b:: with SMTP id d72mr11101147qkg.242.1622350032181;
        Sat, 29 May 2021 21:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622350032; cv=none;
        d=google.com; s=arc-20160816;
        b=jMYPsG4VUcysQpLueFHgEeD9IyFmZIwhzlOwtdSgjFRIppIFUGIYdPfh08GcmXKzQ1
         Onzhw0kqijJd4lRygmwF6NNkv1rRGJbH7jNbkYEitfJwf7D+47M1d4f8NZjIWTeWp6T4
         HoGYg/G/Cv7W9DbVKHf27+PM3gZPqHfzsAnt4rdQIfzy3lkS1oBfiFmh7VLHrbnX5Cas
         rox7A+jKE/Hj8y0Gq1jZy3QO1becuaDLl5EH195x85ZHPd/MNiUHAXsRaNh0FvaU7E4l
         UN0olu0lzAOw6KA4gKEuoCLHL+Nsu4FQjTVPlZzGWV5A7UXyJGNE3vIMS6pVpqAw5F6J
         j25Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=BcaEFmIjiTlfRXL6Zs6sX7KheP8a63KO4TggeivHn2w=;
        b=En+aOIJMZgH58SpZd6WbrtwZNAe01KPJbmdAskiu6DCsMfNJUIY/DhsQoW3iOcS1tU
         NmbyAKQZRD3vuO9sqBBD99ZDF6itoPxtA780DO7R0jGqI3OXTERA0qzDO/ONA7Qnx28T
         fHCGJNYRU9p8sNvvKAg/Lp/s6KXO/8jLH0xc7TGgJNozyIWm22yv8zEFqvy0QQxNsygW
         n06c0bkUgcl1zaIMsNXeRSzFkZYQHG7wEBHiJO0Uji2w0VJFubO6RjTd7OwXw66Ru8Jc
         mc0lJT2RdCRztzu5xwsfr9m3LlNGZmUGOrr9KHr8OF5o1x/rIHR2qmDL8G0iYYn7eDoD
         nd+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=SzdHbLf3;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id j15si319940qtj.2.2021.05.29.21.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 May 2021 21:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id 11so60007plk.12
        for <kasan-dev@googlegroups.com>; Sat, 29 May 2021 21:47:12 -0700 (PDT)
X-Received: by 2002:a17:90a:e7c8:: with SMTP id kb8mr12092421pjb.60.1622350031432;
        Sat, 29 May 2021 21:47:11 -0700 (PDT)
Received: from localhost.localdomain (61-230-18-203.dynamic-ip.hinet.net. [61.230.18.203])
        by smtp.gmail.com with ESMTPSA id t1sm7471108pjo.33.2021.05.29.21.47.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 May 2021 21:47:11 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Kuan-Ying Lee <kylee0686026@gmail.com>
Subject: [PATCH 0/1] kasan: add memory corruption identification for hardware tag-based
Date: Sun, 30 May 2021 12:47:07 +0800
Message-Id: <20210530044708.7155-1-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=SzdHbLf3;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

This patch is for hardware tag-based kasan to make a good guess
on the kasan bug. Report kasan bug is slab out-of-bound or
use-after-free. Refer to software tag-based kasan detection
mechanism.

Kuan-Ying Lee (1):
  kasan: add memory corruption identification for hardware tag-based
    mode

 lib/Kconfig.kasan         |  8 ++++++++
 mm/kasan/hw_tags.c        | 25 ++++++++++++++++++++++---
 mm/kasan/kasan.h          |  4 ++--
 mm/kasan/report_hw_tags.c | 28 ++++++++++++++++++++++++++++
 4 files changed, 60 insertions(+), 5 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210530044708.7155-1-kylee0686026%40gmail.com.
