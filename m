Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB5V5SEQMGQEWWMYU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F3724068AC
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 10:42:47 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id y13-20020adfe6cd000000b00159694c711dsf240702wrm.17
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 01:42:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631263367; cv=pass;
        d=google.com; s=arc-20160816;
        b=U9aAkTDM4sbxNQ+yDvMQTK5XMOpLJZUe4TAA/Pz0qMUBEQlRzeHMtd/iNQw3XruN6w
         iMnof4vzdVFT9SJhm6j469fkzaes/ogsYIHWhAYDHP2F7A51mpXbGDFqTNNDYS5eC/GW
         7xwXwDMjymDWo/NWend0VvG0rVT+kACdEg0ReO/8b1QwsSESeiabYPNwGVjtqHVFW19U
         xUdPneATt4runrv+9RNnsKnWFUuhwYF7txgkrG2ZcC/r2bkwaiY8lDbzviLPpXB2Wxny
         455WscIM5jOEamjmVKQVs/4vkaQIq493ATwafofAZBHQEPs56O+xh0cIHcNVlc5h93S4
         2pfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=yy/VEra9A8srPOxCpyS29aTLFCy7YuheUYbrhdwkEzk=;
        b=hz1e0oCrEwbocQSv1Ohi9P9Ssyyq4eQ3qB/hGcTSoMRqTc6vJ9zr8RM2/eDWUJq0/p
         6Ggh7vuJ6slaRHoAEMYU8SFJjXUonKkXQMP9oK+1ZTMda/25EfGw1jk3Z1+csyzk2OI9
         Fj9V75z2i7BXUr5CrmMtwo8i8xl13m9n6gVUZdEyPS2xe+LSNFoxYtAKINIOJaQLJ/6j
         aesJYtQDtQgRwWwRpvqEjDABuct8FriPwhau6oTbbzuvRN/SThqdqzSctgtkXjzFdS99
         4bRd5tJjJvTrDiR32pXC9ia0+l61cALP4nvQFKksCiqFEhTFnlR/mpCFWGo5j1CkZwZq
         /Nsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n3pl4+LN;
       spf=pass (google.com: domain of 3hro7yqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hRo7YQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yy/VEra9A8srPOxCpyS29aTLFCy7YuheUYbrhdwkEzk=;
        b=quprz8MiuFX/G47JfQ83zGSqvQzDdgS4xfdGTx1O9GVfhUcGIBdI00mY8TBDAsoAkr
         jwR+j1YhcdiN6BO8II+CSlxYarDzWnBj0CUzmN/DVbSLXziqyQ7pKtMRFBUrw805iCGd
         UfFE+wmnskgBK2tksrkW0/i7OUkXdB9wjdDqg2m0lpgdOWcXc6ZI22qVtGpaHp7I/y3c
         zRGh4VswRLJFXbQVTirsCvK3xAZXMQVGsldZ413LWQ99q6rM5gctecNOo+9CRXTt4nQb
         jaLiKtzRHEihHaOVTMdJmxTFo/5cvYfWD400U01nvdHMD3VG3WTVyuEVzCyx/kfwZGHf
         +Swg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yy/VEra9A8srPOxCpyS29aTLFCy7YuheUYbrhdwkEzk=;
        b=KxOAci0TWEpJFniGPfw+mmM9xvCFqRp8zy0fm0C+AH7l4e0KARQmedzlGRxH+wlYuY
         ePl2f92hNvf4kf+Y7wBYmLMQcfdtl8s/Qs+i6cBA5OToIGchBDmRt5ewBUpR4IJ8bBH3
         mDT3L/OPt01c8C0YW1hceFq5OdbnYLQ/LPOJdT4KsDqZPrm6C1RpgqywG5ax19dRvJOM
         D7GcVU4Bx/jHBc/mMc5U0DF87KhI+epowAvf71khiTHWFG2RnJrTFmWYpgOslypP0cPh
         2IUVyCwtuyKrV2pi9dCRuX4b2Npl4CEyfb7tn+BNdmstBIY/dqsLF4jXbLeaytLpqtBg
         0PFA==
X-Gm-Message-State: AOAM530BITOiS3yMA0Ep6MVxOhHXCF7ozdW+vWdsxPJqe7U8EF9wctkh
	w4vytPZpFtv8ZYJf110G9og=
X-Google-Smtp-Source: ABdhPJxDfvz80GeZhG/NM8Tv416EC7BpDIgRJfEaepHYySDZ0zu1u9NTiSBLvNdl0fN1bCr74z9HOw==
X-Received: by 2002:a7b:ca43:: with SMTP id m3mr751552wml.50.1631263367233;
        Fri, 10 Sep 2021 01:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ba86:: with SMTP id p6ls6160697wrg.0.gmail; Fri, 10 Sep
 2021 01:42:46 -0700 (PDT)
X-Received: by 2002:a5d:58cf:: with SMTP id o15mr8262638wrf.312.1631263366291;
        Fri, 10 Sep 2021 01:42:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631263366; cv=none;
        d=google.com; s=arc-20160816;
        b=uoI0RGx0G7CW8sBKLZw7JuUG522iMruNx/cJWyglMOgCRidklqOImDC1Q4bOJCFNfI
         ZYmZ9IPNW01zvrZjjsWzunReBgSHA02moIYyaE1uyNbzvfXCT0dAXamu4iGmrasezf37
         Y/bfNAH90/m50ivMQbpifRBwfySa/1C1nP7kvO42IXM55lJ0m629ooO9KCkikHpXl7f8
         sFEjWqThpr7IbLI29RPsnRae48wvMN2rXhtzCYd98F2NjQ7VR9dSa6Eut8jxGyPChChY
         uaRZTPBGC1H2FsY6pL/+I5xLHUJngjSjAYpBcN8Eqf3vRfA2oVvskOCJvxB7gwVBHYzE
         A99w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=U1vC9mnO0GBdoKpseWlG9U1U97SJv1m6txgMtoboTzg=;
        b=GHKVJGByTG+bJjVXTiHusAUiB6JELYzSOXUWNuEk2wGVJRQ0QMPqwqMihvafZvJSl1
         zvotCqAO9C+7zKJXKa9kWwUE9Q0MM29PDCcDtuSqPH6uFT29Qxn3UnJfnyn3JxSHvbxK
         s8ZoMZPqIb+adZp/kvLdZpHpDtY2tQf0UeJ2ZXAus4+SEu3u5xIKhn7xoPCubHqdW2Bc
         doXGWc7Ziz2Q7T8KpJIWxFV/lhWSxwcJxn6fICxx+TuHLZc3bvT27avpGxy6PFq7EYP0
         vUt7JtwqRmplH1eFMGOXtCMcTxgzAmZS0TpNcY7GtACKZKsbFjvh8/wRBtubIECR6ThA
         vSww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n3pl4+LN;
       spf=pass (google.com: domain of 3hro7yqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hRo7YQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id h9si55911wml.1.2021.09.10.01.42.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Sep 2021 01:42:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hro7yqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id a144-20020a1c7f96000000b002fee1aceb6dso519118wmd.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Sep 2021 01:42:46 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:98f9:2b1c:26b6:bc81])
 (user=elver job=sendgmr) by 2002:a05:600c:19cc:: with SMTP id
 u12mr411559wmq.0.1631263365627; Fri, 10 Sep 2021 01:42:45 -0700 (PDT)
Date: Fri, 10 Sep 2021 10:42:40 +0200
Message-Id: <20210910084240.1215803-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH] kasan: fix Kconfig check of CC_HAS_WORKING_NOSANITIZE_ADDRESS
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n3pl4+LN;       spf=pass
 (google.com: domain of 3hro7yqukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hRo7YQUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

In the main KASAN config option CC_HAS_WORKING_NOSANITIZE_ADDRESS is
checked for instrumentation-based modes. However, if
HAVE_ARCH_KASAN_HW_TAGS is true all modes may still be selected.

To fix, also make the software modes depend on
CC_HAS_WORKING_NOSANITIZE_ADDRESS.

Fixes: 6a63a63ff1ac ("kasan: introduce CONFIG_KASAN_HW_TAGS")
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kasan | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 1e2d10f86011..cdc842d090db 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -66,6 +66,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
+	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	help
@@ -86,6 +87,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
+	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	help
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910084240.1215803-1-elver%40google.com.
