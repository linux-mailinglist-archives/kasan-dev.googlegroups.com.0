Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFA2LUAKGQERHIGVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F00CA57F7E
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:05 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id b197sf1954482iof.12
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628704; cv=pass;
        d=google.com; s=arc-20160816;
        b=oikHRiK4T+nIfvDOK8NeoxptNFzFzFyruSsN/ezmcxD2tq58uZT3b8ORk07bX/3Q/K
         GzWXi88BnCG3HwFH4oTJolA21sf8lXGKyrbJGnkdUsXqRc7W7fMbsO3/NcrKiPFCFWs2
         d/4yE9ENqjgQjI3UB2ObUNoZwfqrrNfVvInPr1zs68SfhL0EA8kW2b84kYxdFcKJbj21
         NM6bD1N54XhW/pDjdwbF+YdPxvB1P6Qnh/qxFspi67WDpTn8Nf7GEHtKJ9roc64Ia/rO
         lw1Y5LxLSIHq+7ibk6tkom2wl2hqnuvuJErQ2A5abAA3W6yDXmwYh9y8F1oRZ/+PpV0y
         lozA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=o73Wktdugm/CmgxG2xf2lKCuC1B+N6jwbHqB/JHi0N8=;
        b=unQAjIKxgoZpuMm0OGbpNgRjiahP6TLZbkH1hOOF32HSnZmlfFdutf6BlTA5oxTZ/b
         xuqJY6pDe8RlD3vLLDN/DgPWm+C0p/kn+lEQsdR4Uu7adIz1OuR5CQhW/Eg3xoFpa3oy
         My87QxybzOEBu2yepP8Q2Y8mypcLz5YhNrbcdAhiyGKiYAoxlUCiXO/9X/i+dCmttIod
         qiL8fZA5mWttg+5e+3QnTdLWZC7fi992yCWVpHJstOmwaxqOmmQyomT5uYoROxDFmhf5
         IJmqXya5BbYUaXo7PZMpx11vbr1TAVEGRvD22RkANEP+pAqGEua8PB9U+OAn6001gTlk
         HbBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iIFIdW8A;
       spf=pass (google.com: domain of 3h5auxqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3H5AUXQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=o73Wktdugm/CmgxG2xf2lKCuC1B+N6jwbHqB/JHi0N8=;
        b=Rm7+vdQTmBef8tjehNrlvEWq8LTn5WVmweRQVfLq8Gdn/EknzAITATQKNyV1RRJ0jt
         Esz+O4JzAMIP3e2m45S26oiwRP2PFWgk62V3fXFwMFbckp0tEghJngqGv9UfaxsahTVV
         oqUoYaW+AUqUlIiFvL+t94eYG9LvBsVUXOvOlAEqvLVrFewMO5UJ6kARe56jweyXLKGm
         FigE31tKjCayvN6/BXAU2IOTiiUjVxeRshCnZnjpJ11y6kStgYCSMRf59fU3PMQxKpE5
         //7I2s/1xIQztJFcFqSi0mJVZszuAr42KRqkdK0uCnimuUVG7iwsk5e3zvcjV1qSjL8N
         SQqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o73Wktdugm/CmgxG2xf2lKCuC1B+N6jwbHqB/JHi0N8=;
        b=EC6NE38F5nzoBYVVZ0RVOE6jxrOmq2bQckoqafwf+SCGL8kgK2IL8iSyLosdop4Pij
         zt6fpsP9fAnRhttiDpcvx35jtw7oQ5X3XhzaQCsTZpePf9q5OUuRwVbAtDRy/uBUPvaS
         MTGWxRQL5ZFt2d1PQa40SlphVYsfvWgTgEwIkbVY/NvzefAq/jw5s860OMiqcD0yLE+x
         FNQfKnZWG3LZKZ6YjBTjdZfqEeBLnJ9k+grFdyDw1NZaJREa5tbslSCNwRk7Ljlr11jW
         0P+DNGO9OgIU7y9sGDD1zE+dlaS9dq+wBoLr+lqZWgx0LSTejK58uIhVItti7z7I1fBg
         WwrA==
X-Gm-Message-State: APjAAAUgGfzsYqvO+Unw6hEy/hbn7aVk6YZ3OkwWUC2cTHfRopHwM+/y
	+fmMKXWnyzy8cMIH65F5FIc=
X-Google-Smtp-Source: APXvYqyBABxkwfMyVMhECJvMA0wfQHTQe7w4YcWR/G5evuIj/DNlxJGOgLDNOHP+9r5yNdyTEleRuw==
X-Received: by 2002:a5d:9291:: with SMTP id s17mr3516740iom.10.1561628704714;
        Thu, 27 Jun 2019 02:45:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ec8:: with SMTP id 191ls659158jae.8.gmail; Thu, 27 Jun
 2019 02:45:04 -0700 (PDT)
X-Received: by 2002:a02:3904:: with SMTP id l4mr3402844jaa.81.1561628704449;
        Thu, 27 Jun 2019 02:45:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628704; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/tyOOle0nXUMb5iqysy0mx1Ut2Zv+MeszegIbR+EO+kGx2CRHiW3zcXaP7j1GXWhW
         +85RWustiVV54knlzvoBIQXI7a/yFFaLyinALfrZtOAt4PmahvXLAylmtkkCkfQWRQUX
         YqMAe2GfvCFBXo2YyStXmS1Mj/gPmXgT5iOmBwSHy5C8jmgOfm9UmBH8ZbxdDrlUe4HV
         vz+SZxJ25MvF5Ocwe2ySG9QSahHf3MfPNXMbxnU+RT4w3o6kP3m1iAz26pbHxKXkFcrY
         /gIIotRQduEgB+3J+sFZ5xvA54/MWPPbqvUdJcc5xWG5laVbwDJL0qi7jQ+Bavic0WI3
         87Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=G7q4MddQh2Qki7wvcHF8MIsvZAyVqJ4sXwbvqTqIetQ=;
        b=Vks7mgKohT0PScJ472eYkzduYoDySjCQnC5dWmq699jQacr/QtaD5sEmMPCgfBb2zJ
         nYjmOgOM0hC55ZkZnOBkJTXLv73RlQqRYg/5STMMAzJyDRGA76ALQRcIT5hCoZTwBFgr
         6IB5JuBAsBMujan8R46zI16OkHx7jtv2yfwMxoi7wlp3NYEQs1ehtS/4alS6BlY7dzcX
         Grt+uG0jyrJIMH6xKsxksy56bkV9mwYLyi2H/4N9YIh8fHJ5pAiUDqn3K4Xv8zIomiZR
         6CMyuZnkOVyZUNQAkOBpijwWlCC8jQzbmwZb0cmpnLEZ2NIT5Gs25EC6svKx2J+iJuBt
         9vGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iIFIdW8A;
       spf=pass (google.com: domain of 3h5auxqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3H5AUXQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id n7si99615iog.1.2019.06.27.02.45.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h5auxqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id p193so519434vkd.7
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:04 -0700 (PDT)
X-Received: by 2002:a67:f795:: with SMTP id j21mr1954700vso.226.1561628703889;
 Thu, 27 Jun 2019 02:45:03 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:40 +0200
Message-Id: <20190627094445.216365-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 0/5] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iIFIdW8A;       spf=pass
 (google.com: domain of 3h5auxqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3H5AUXQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

This version only changes use of BUG_ON to WARN_ON_ONCE in
mm/slab_common.c.

Previous version:
http://lkml.kernel.org/r/20190626142014.141844-1-elver@google.com

Marco Elver (5):
  mm/kasan: Introduce __kasan_check_{read,write}
  mm/kasan: Change kasan_check_{read,write} to return boolean
  lib/test_kasan: Add test for double-kzfree detection
  mm/slab: Refactor common ksize KASAN logic into slab_common.c
  mm/kasan: Add object validation in ksize()

 include/linux/kasan-checks.h | 47 ++++++++++++++++++++++++++++++------
 include/linux/kasan.h        |  7 ++++--
 include/linux/slab.h         |  1 +
 lib/test_kasan.c             | 17 +++++++++++++
 mm/kasan/common.c            | 14 +++++------
 mm/kasan/generic.c           | 13 +++++-----
 mm/kasan/kasan.h             | 10 +++++++-
 mm/kasan/tags.c              | 12 +++++----
 mm/slab.c                    | 28 +++++----------------
 mm/slab_common.c             | 46 +++++++++++++++++++++++++++++++++++
 mm/slob.c                    |  4 +--
 mm/slub.c                    | 14 ++---------
 12 files changed, 148 insertions(+), 65 deletions(-)

-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
