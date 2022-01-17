Return-Path: <kasan-dev+bncBCXKTJ63SAARBF42S2HQMGQEL4E2HAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 95F1C490B7F
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 16:36:56 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id h15-20020ac2596f000000b0042effa72823sf10233327lfp.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 07:36:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642433816; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdgp7tu4VL4Uz7bmU/VqIzmCGBgxEuoBxgA37/JJeNerTi6EsbgQJt9Ym7mEdclcZJ
         fkZzjnkF6JDAj2ioFUGu6ZT6f8Yzv0OCBdeArRp4m+2+cDwzr7qgX8k2uHSukNko4T5i
         T/scMKWd9Y4yxAHWIRmnJSssO1E5Q6/lftCSGYMGsHJTPgfn4fKFI9JoN1nDB0KG7OFj
         +WpVMKhp3aBLJv1be74/QheXCFvus9E12EI5SmFwkwn67Gi1wB65LMDkGvsucHaNGJvO
         GHHhP3PQB6rXsb337f4F4DsECs6mvvjAIzlKwi8d97xSr3Yz6+c7Bgt2YJPaGrlr5jf9
         MPQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=KhYG20lCPrHbxikDf2bYXlqp2b4GVPV7cXI7FAjHsx0=;
        b=0SVZgtC81GaaU+2W1q/40EiPy0eebMsC+SaNG0NMlhLBM3qxslJ5/n2jGqR8XqhUaI
         IlzzpOg8Li3uWA7O6BihjtYoRqnqON+Lw12NGXbYWTQbzWNrhLepdAsPw7OnRmtqU1Rs
         BptvTCRP3JWGAMNyqGBzSMn04wsD/wnEEfrPixiANblQS9lBkjT92UkuaF/xQfnGPRT6
         mVToGppmnhhToSAnAtp85znBxw+OjuQyAiv5forOc1wllknbOGNrg16JH8DxU4/6TFXQ
         MoAnvF8dWYpziZEN0Ayutj+3f8gmcSDTrCsxDOcrAqfntEbsD+dzz4qbk8LPEfAcSzBP
         IHIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a23bcaep;
       spf=pass (google.com: domain of 3fo3lyqykcdskldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Fo3lYQYKCdsKLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KhYG20lCPrHbxikDf2bYXlqp2b4GVPV7cXI7FAjHsx0=;
        b=V2cq2AHMlUE6bpgkhjgQQqWnTpEfi6agZTxvDHK9W39We0zSFVdvMNZnY512GJZH7+
         b0wGLm2NjSP1MKX77o4lOO5BZ3NES3ij8JPhnwNRb5rTJ3IfthlHGq3492OvcLM9bgPi
         45IBGt02Q+5Y10ekLty1GQiWyWedTZyvcohyqu1uIE4cQ2sqmEkfOsueorauP+6d89rh
         7rxtyJLPckRH8vNmhtuoblK/AXpAd8iVCo9BdmeRoEBESJzggUnc8Jpzjbce3jZuwwVM
         VwKHqiLvQHFxwJzaKQMkDa36dp5I8YOr3FaX9R1MRh7OVJkqq79Mnrx11aGm0mcf2Lkg
         +K7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KhYG20lCPrHbxikDf2bYXlqp2b4GVPV7cXI7FAjHsx0=;
        b=refvczvMtaCO807M6R92G6UsWWOIOZ8S31snNQhCvogQKnsEoX2SKrZBohTTnXcjWS
         32phlhaTVGZ3cyGONRwZkE1OE9aiN2OQXeItWsvG+CjzYiWrl+b5PXP9dX9cQ3iAPwpd
         rMW52CoIIO01sqEoo2cu7OJUZ/TbKFNkYtnoRsa72qyzaiRHX6mYiMso7qwDwZRB6vS9
         XXP/LWibLjz4Vcsx16q3vO0W+YGNPQx6yxuob4Q5fjxA0KEZLM+S+tiPtSml+UFee+d1
         YS1jqu3BC01I11Yc1vW0JX5ugXIDAGSnNRkj+hxN54aLnNmF62iINbqnHlGbQACRaT7v
         6kOA==
X-Gm-Message-State: AOAM531zwnuJQvVUi0Tc9SjF7mzgV/wALcmT+mSf1Drb1Z5VENx3Soq3
	fzKIJzdThkH4lq6khJ8aWjw=
X-Google-Smtp-Source: ABdhPJxp3pznVkEd/s3PN7AAnjkLUWStFU7raZcH0ATlE2dYybm2L1IEB+pm3AW1f4PolTRpeR0KdQ==
X-Received: by 2002:ac2:5f98:: with SMTP id r24mr13972831lfe.619.1642433815979;
        Mon, 17 Jan 2022 07:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0e:: with SMTP id k14ls2132377ljq.6.gmail; Mon, 17
 Jan 2022 07:36:55 -0800 (PST)
X-Received: by 2002:a05:651c:10bb:: with SMTP id k27mr5477136ljn.310.1642433815040;
        Mon, 17 Jan 2022 07:36:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642433815; cv=none;
        d=google.com; s=arc-20160816;
        b=sIrRZrE+joIxZPRtwMNpYx3ZaeWmG//2lvzsiw0q3vuBHtxf7Y9Wz6imB1jJPed+sT
         e3ra/crFRrJdej0i+XdYXv5Nyg26Q1qQWVpGTYNSYTXDOXqDIzLQrH5d2IjAdHv1GeVJ
         rjlmc1VqRprNhihPBRYGqtiUmEsEiKBfPnFczEXiqaCpyw0mYeqIRem9R6s97YOxANIM
         N1gNJYXdSdrxIVQBhGlgc70PqPyS/2zS9MKVv9mLuBD9wVXru5sHMxzepVInqTbQHnOX
         Py4dxUy1p6l+6RQ1o5RvqHs8Wc+TU2AaC9r38XTEIeVFYoz5DoB9KREJCkrqydSr1VuF
         r+SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=D5zXK5qLO3bVoV33LMvpL2FWcVowRu1hQWlgAbCJHpA=;
        b=ro726u3kYBLHCO3TNG4l2RZMf8V+KGK23Rap3TP8GYFDM4tC/wIkiF2Ig2yQPyFmO6
         51zZvuThZz3rAuVf/6s8mYY0R2udzDsJxqFCzb3NvTGB3vBIqSxnUL1k8mbrWkCRB4Hr
         caqofI8GT0rkQfKVxgSrdpiVG1OSysAeD/I9Z2Fz2RdCb5AhLhpKXqbGwuZcjJaBMVyP
         QVDuWhDTov+xVzwSdFn5OdVjiFIfl+XF36BQc8nSDlYPmEh0upgUwBerC0whrdL+lu9I
         h9xz3QacMpAcB4QhvsUmEEhNLacVapEdWSN5tGaTHU1FV8WSoofe5N1YaCD0EjeYg2tX
         6Cxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a23bcaep;
       spf=pass (google.com: domain of 3fo3lyqykcdskldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Fo3lYQYKCdsKLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o13si475364ljp.3.2022.01.17.07.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jan 2022 07:36:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fo3lyqykcdskldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id ej6-20020a056402368600b00402b6f12c3fso3057844edb.8
        for <kasan-dev@googlegroups.com>; Mon, 17 Jan 2022 07:36:55 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a17:906:7301:: with SMTP id
 di1mr17404761ejc.94.1642433814284; Mon, 17 Jan 2022 07:36:54 -0800 (PST)
Date: Mon, 17 Jan 2022 15:36:32 +0000
Message-Id: <20220117153634.150357-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.703.g22d0c6ccf7-goog
Subject: [PATCH v3 0/2] kcov: improve mmap processing
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=a23bcaep;       spf=pass
 (google.com: domain of 3fo3lyqykcdskldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Fo3lYQYKCdsKLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Subsequent mmaps of the same kcov descriptor currently do not update the
virtual memory of the task and yet return 0 (success). This is
counter-intuitive and may lead to unexpected memory access errors.

Also, this unnecessarily limits the functionality of kcov to only the
simplest usage scenarios. Kcov instances are effectively forever attached
to their first address spaces and it becomes impossible to e.g. reuse the
same kcov handle in forked child processes without mmapping the memory
first. This is exactly what we tried to do in syzkaller and
inadvertently came upon this behavior.

This patch series addresses the problem described above.

v1 of the patch:
https://lore.kernel.org/lkml/20211220152153.910990-1-nogikh@google.com/

Changes from v1 to v2:
- Split into 2 commits.
- Minor coding style changes.

v2 of the patch:
https://lore.kernel.org/lkml/20211221170348.1113266-1-nogikh@google.com/T/

Changes from v2 to v3:
- The first commit now implements purely non-functional changes.
- No extra function is introduced in the first commit.

Aleksandr Nogikh (2):
  kcov: split ioctl handling into locked and unlocked parts
  kcov: properly handle subsequent mmap calls

 kernel/kcov.c | 98 ++++++++++++++++++++++++++-------------------------
 1 file changed, 50 insertions(+), 48 deletions(-)

-- 
2.34.1.703.g22d0c6ccf7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220117153634.150357-1-nogikh%40google.com.
