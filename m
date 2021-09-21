Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGG7U2FAMGQE7QVO5KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 99DE3413151
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:10:32 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id m1-20020a056000180100b0015e1ec30ac3sf8376053wrh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:10:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632219032; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZzOgjUjlFidnf+DOGDnuhmayUlvDiybkQQPqxnK3zQRoK+kkoSo6vLETeexRTFVoI
         feTUoQ2/gDRVIRR8ToJTJD9bRbpwySlxEd4D2myn7e071PBttTDD4nvzmuFveHvVf9yV
         3JWnkdpZBZt8ilnForE+tNRLsCEAQcdayfotgkJbuZEmvbwmMlIa2BsknSk3vHfsmeTO
         b5RufuOoGoxcASKmyAucUbs46gSfb9D2Vp95UF0yeeR5geFVbYUORNBU3YIl0m9nvKXV
         bLd0Xig9cNS4qqsWaiI5Dz2KAfGUHxNiNOt2+lPmp7zUGtyNf86F2PG6VjowHGjlU6qm
         iazg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UZfDSlqSDROk3TZtN1mLPlubQ2dMJJZT7OTkBkuJL1w=;
        b=q6tv7AHhVkaoDdYFLILP7C+JHkZ3tC4Patsz6Om6gHYLnHn1YdZCBgMoWILVN0QkYT
         ptHVlFVN8EAAb4EJfFekYdvYlZFM+pUVC4oQiWoXDZ18sDKcTrf6M9o6Ue1Z06OunpGl
         7PHXQcEX+9z8TAVxG5H1T0jXxhI1Inqo5JdooBPIlQhN5/OTvITYSIFthTh+nbhX/HY0
         Ea1vycgesNs5HF0Q7hql+fFzutfhL0d4gbuTYygTdKSr2s4EFVbihNqXvR8qSJLDknrq
         8oso4fxg6H6kMcYFET7fuNHkN8MgYYkcbBcPG6qwY+J9hF7GxmEiifCSn82TP4keK4lZ
         eeRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aFGoLLrF;
       spf=pass (google.com: domain of 3l69jyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l69JYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UZfDSlqSDROk3TZtN1mLPlubQ2dMJJZT7OTkBkuJL1w=;
        b=GoN4gakOaUMNkyFUdLpmt3MJKI/vBQvf1N+BsSuzrsPkl9JIlNIzIRVMnCFnEsBb1h
         GA52wboUqNlk77U/Obb6zM+inBSyneR8oIe26VM4DpzQ+eMxFfovq+PRinkbWvc4CxN6
         UemrhpU1ss+Vy0ksjrmscHIn11YSi3OReEdoqHqzr7/3gDBkOIBY5t5ILk0aHQsTomuW
         cX2RGrxa/ck5MwXyttUdO9pddM2knQKkoQzhqPzFBvcfkTX0U7Uq9ok3PhG2vvWv/+fJ
         NDzm3EbcHGrIrsy8xzcwnTWIjUilDyKUVPfyQdVyiQ5w7k47PgrZP3FOC+dF+DZm7WWu
         /MMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UZfDSlqSDROk3TZtN1mLPlubQ2dMJJZT7OTkBkuJL1w=;
        b=UddzwAeiWhdjSajptFaSQYZ6bPLG3QsYzJO1w3ADSWE5zgT+LRxD5FLd9Fu8VNB0PD
         A6jXSUN1zhX91jk0Yx6Z37vq4Bnsroab0lCg/xGgjWJ552tZtFd8pNN12ZFrS74fSJen
         FgaPsx3pcsts4/pTyWorUgN9SQBU2+zrmU/l/X09hJAGhN/4YSRbXLin9M/CbObR23Ts
         XcWD1Mq4H3rSHBrXLwjpKNRAPLgpJCOd6JBLwgUIqCYrAmwB63EREx90dOqzrPrW2SZx
         BmBT3RxWfNOm6Mx0P9CMEvh7qnh/Sus6v5JoN7L/883SO2w+tiMBgSi/aWoU5guGsVoT
         Kg8A==
X-Gm-Message-State: AOAM532+WwThc5kTV80Cu1gKG+JlD5L7g1371jHDpzGcnEbAyhDIOl4q
	Qpn0d2tV8OXaT7+gHGL4gLw=
X-Google-Smtp-Source: ABdhPJy7TKekaKKtR4PSaamCKZTUli39ig+nz2kV5QSF3+76fS8QoLkbsFabm91AUc69GzZcSKyAcA==
X-Received: by 2002:a7b:c350:: with SMTP id l16mr3499134wmj.151.1632219032343;
        Tue, 21 Sep 2021 03:10:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aacd:: with SMTP id i13ls2209511wrc.3.gmail; Tue, 21 Sep
 2021 03:10:31 -0700 (PDT)
X-Received: by 2002:adf:e485:: with SMTP id i5mr33057187wrm.22.1632219031408;
        Tue, 21 Sep 2021 03:10:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632219031; cv=none;
        d=google.com; s=arc-20160816;
        b=iIBIm5YWHMswBiPJpXKg07ZYnZoHiogvHzzU2tSVWFkYDTrVv1EueGkLfpMMkRxZro
         6MOUGS691uXXBgt0QRN3kgKwFo2O8ycgLL9m324UX2eoP22oIthejxgO+0HO6PyLA13a
         4D+zfGMzVUlDRSZZg80FeIAsKPgzq17lprZvLfoNhvaPMsvodVdvyTLSznfJXdcX1M4u
         fD3CfxCLIKJFdvf8R7NK17WPAI7TDFZ6SOChz/dkiNW7QU8bQq1Ze2U0sdB4lNtQOQcm
         rWXnSoPcm30x1etC1vbqmdhCH1F137SVYHGDW1qotewlwFZISo4WqIrBP5441WLiYpk2
         Q8Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+aOzJl+IOHEzliD/59W8D7vvkFuM5qZHbYDQFSYPXT0=;
        b=QHSweg9IDM9/QDPkylVtsnMWNHg59kWs76QnSAon4LAksKc4Wrz40DtKZQtQw8nbbo
         bjoeqdzty1jCNADQOeCK4XbdKcA4L0HWY5H/bP4SgoEVghbw00ejv8CPL9iT5BUYg1Wa
         96j12iatjyTIBG7xcMj6YG/xS55v37mi3Eeq9ymbpqDVjaMrx0sbKWf2AXRjKcApUu2n
         ySPPSoBmVdXXhfygsKw4+ZI9vAqWe9ubVNJM1se8tAeRAwIVFkFrc/ybrlnqsZaW2rwZ
         bHkOAwFp8a+J1Oc3OtDQPwxjzBxGQ5SnDyF8B7wJm95R9n1ViP20nyYtGJh0Hh4eXZHp
         QhzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aFGoLLrF;
       spf=pass (google.com: domain of 3l69jyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l69JYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f5si1311935wrm.5.2021.09.21.03.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:10:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l69jyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u10-20020adfae4a000000b0016022cb0d2bso620022wrd.19
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:10:31 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dd03:c280:4625:60db])
 (user=elver job=sendgmr) by 2002:adf:ea90:: with SMTP id s16mr34027049wrm.235.1632219031088;
 Tue, 21 Sep 2021 03:10:31 -0700 (PDT)
Date: Tue, 21 Sep 2021 12:10:14 +0200
In-Reply-To: <20210921101014.1938382-1-elver@google.com>
Message-Id: <20210921101014.1938382-5-elver@google.com>
Mime-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v2 5/5] kfence: add note to documentation about skipping
 covered allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aFGoLLrF;       spf=pass
 (google.com: domain of 3l69jyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l69JYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Add a note briefly mentioning the new policy about "skipping currently
covered allocations if pool close to full." Since this has a notable
impact on KFENCE's bug-detection ability on systems with large uptimes,
it is worth pointing out the feature.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Rewrite.
---
 Documentation/dev-tools/kfence.rst | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 0fbe3308bf37..d45f952986ae 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -269,6 +269,17 @@ tail of KFENCE's freelist, so that the least recently freed objects are reused
 first, and the chances of detecting use-after-frees of recently freed objects
 is increased.
 
+If pool utilization reaches 75% (default) or above, to reduce the risk of the
+pool eventually being fully occupied by allocated objects yet ensure diverse
+coverage of allocations, KFENCE limits currently covered allocations of the
+same source from further filling up the pool. The "source" of an allocation is
+based on its partial allocation stack trace. A side-effect is that this also
+limits frequent long-lived allocations (e.g. pagecache) of the same source
+filling up the pool permanently, which is the most common risk for the pool
+becoming full and the sampled allocation rate dropping to zero. The threshold
+at which to start limiting currently covered allocations can be configured via
+the boot parameter ``kfence.skip_covered_thresh`` (pool usage%).
+
 Interface
 ---------
 
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-5-elver%40google.com.
