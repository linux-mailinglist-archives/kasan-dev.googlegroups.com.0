Return-Path: <kasan-dev+bncBC6OLHHDVUOBBCFU6WKQMGQEDP3JATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id BE35456142C
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 10:08:42 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q8-20020a632a08000000b00402de053ef9sf9346277pgq.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 01:08:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656576521; cv=pass;
        d=google.com; s=arc-20160816;
        b=kTRB980AVm5n4HUoa/3efdkX7gu6tIh3dZUHRo4529+IEw6wdvMriT98Wn/qZb1sgg
         J6c9HvyIixjibjaX25yeQoAFzDtqDRsgaKyfDrJsot8j635AREHVIrJEbYdcDCK3PZRO
         4ArtUtfWSzsU6M3deCUXGHV7JBo2j8GQVPRb9kH2BvnK6oPN++mOp8CK04knUMH5+Sdv
         PWKTAEPJs61puyw2RXPGAVi5YlztgFcG6M99eEAuNZo3mcAXSd+9ChdS5sxKFe/HnzQ3
         C6yRwG5sNHgNyWE1l1+LVSfSYL433ZrwmsjJN5XMp1/HIIORDI7mSqwKL7m0k5lSdHqN
         OM1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pwy4pL7tUWzkFPws3G9Pupj6CP4ZUiht7UnKgNo0J3A=;
        b=vxsk+FfovPD8IOTx7hDMs1n5hUnmjFXK8ZqhgFbhfy4dkO7RWWFB6l78gIwt2XoZRJ
         VQdJACGPgS9UiU1TnGcwRyU1rthB0JeVaYuXlBJG4eWjHxlqW06dCjmWNDCmwNYEeN6W
         kp2XkRJDnys2wcMqGD/Mcs+K0Ktpv9j+0JdHXST0GgUjao7dtUkXo932ZanVdIcohi3V
         SU6jG7S8vIDByaSTUb4CpNjKMpil1Y0bt+KgFPpzQcGGdLf+fJMUS3cPQOZWPSYs0XC7
         ZnGlbAaPcY1Y//29XZsubZGGYqmQMPPpvCxftOtxiW66oDRLTcY3KkFPsQdZ4c+IaKSc
         THAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C1EfKr+S;
       spf=pass (google.com: domain of 3b1q9yggkccwvsd0vy6ey66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3B1q9YggKCcwvsD0vy6Ey66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pwy4pL7tUWzkFPws3G9Pupj6CP4ZUiht7UnKgNo0J3A=;
        b=duGlNM211cjBZ8ZNW6cwAiz6kx3ATFKqHuAWMngKVXFprgW4FzUg7MbLBNXxPfRr6G
         qeEw7qIl2ZJybrB8i5S647X866G/GQpQEaK6VrbCFAWQwEVUX0IJB0aiS94gilqK157G
         hecEBgKrBYBZ4exnefkTfk5TM0524NMW7t0+4lBkhayqcS410LEeKh4BtyVJcw3d8Oo6
         PM+OWsyhJ0PYdDpEwr9fE+qrrlLaqNVD0vjXM9z+PZnREUEU9sicKPwMpps4kzLUPgw8
         HMeo2cU35zsPyB20GhIyaQpmIon/mjbXXrA0gBn7FOHfCZcF+JCS3LS/J8d5R31aYqBG
         FUWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pwy4pL7tUWzkFPws3G9Pupj6CP4ZUiht7UnKgNo0J3A=;
        b=Ed/pxiALvjVT5UEnSKcbDcSRSbWOeHbmkK8dAFvc+iAqbB2Lp3q23jwf9WssfaIsmo
         wiBRspef4iN5+qcXZR2wei37jG94TFfA0QeGulAFRml+hlQvQju86h81jDSWgahblTBc
         umiYPhrwaWDOrAbSo8Z7ZNB881SpzW4MyMzmglBCh+qFJ1hCAJ3IQZLw2I2toC1NmrmO
         8/IgimOBmcPb1zQyCfitYP/85yJsYCIjg1tt+GiGNTxG3aM1MmnMx0Ha2v4vndUlJFrA
         pOiLA0gHu3deF0bODu0KHD+eRvZJU716w0Vlxn/a9jZDEd1w5LLthZJonAXKujDb1n0j
         1Gfw==
X-Gm-Message-State: AJIora8r4YJcy5vMgbugF40u4aSnwm6sI2oxLdbCvbuGHmgeIA6ABmRC
	Yf0baTwYbphDeIbAHxGOc2U=
X-Google-Smtp-Source: AGRyM1uzB+nKWfUdjoG3vVRzOeV3xfyfvVkjPrrq+QqfiB7XE2kibaqdyLKUPhcb6RMW86fEu9bXow==
X-Received: by 2002:a17:90a:3e04:b0:1ee:e899:4eb6 with SMTP id j4-20020a17090a3e0400b001eee8994eb6mr10507801pjc.187.1656576520825;
        Thu, 30 Jun 2022 01:08:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a884:b0:1ed:4fc3:d84d with SMTP id
 h4-20020a17090aa88400b001ed4fc3d84dls85374pjq.3.-pod-prod-gmail; Thu, 30 Jun
 2022 01:08:40 -0700 (PDT)
X-Received: by 2002:a17:902:d4c8:b0:16a:480b:b79c with SMTP id o8-20020a170902d4c800b0016a480bb79cmr14742665plg.15.1656576520026;
        Thu, 30 Jun 2022 01:08:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656576520; cv=none;
        d=google.com; s=arc-20160816;
        b=VwPZ/sY3YJalQigkEoSkOXOv08d7EtVC2jFGscOmivklvdWghZjRhvJCj+diMJ++Y5
         LYXwcnIEOUJTojNf0cYDczafpwgANeojerEVEX1j6DmmpLSExvu86fC1o7f2B7vISe1z
         +nq4HRkrlbdBhe/+T0ODlG2FffiyDHuS72AlTEuPFTCNQk49qmeMVjuKkPihhcNApQHa
         2mnDLUMnlmpMzzxsfH6QgNx+5FM+UiYTkCUXCmcvDWAY/7iOIC00ThbRjOsM5sYriTd2
         Dsx5+vBWuknWzE6x2tgEqKdM/1m8/99coVvU+hmNiiQRdf6QxwKQulh0qUjCyznlV69n
         v/ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=GYiA9a77cHEq6HAaCDmf6SI0OmewmuXNtKGENJPyeDQ=;
        b=ikWV1wEapweZL0hb0d2G7BcU0DPLYdEO26ZRnDQV21Uf17EoVwYNO6GPjXqdbCZKzU
         +S7igWGrR1EmhNP02XtAzORYJyFc5a1tBMC7NFrgffiuELYDJ0vMtvbwVbS6AxPsqY8R
         GpdNgq74AY+EB6+xwx05KnVdgSvQSjmv+hkxTYdD1gEK8H3cO6WkKjgGjLgEbnImLSsw
         IUHKsVDR1J1WY9zWYYHuW7IRElZGUtmVzuqPNdq01iBuek0WIyEOXpr9132lulQgMtta
         1aIT6rqfTC6KXv19KtwaIHftQXEJZv5f5PQ9/QeL6y/1Om6TfAJdQfi0y1ATd6UntV9Z
         0RZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C1EfKr+S;
       spf=pass (google.com: domain of 3b1q9yggkccwvsd0vy6ey66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3B1q9YggKCcwvsD0vy6Ey66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id b12-20020a6567cc000000b0040d0bd431fbsi738400pgs.1.2022.06.30.01.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 01:08:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b1q9yggkccwvsd0vy6ey66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id m68-20020a253f47000000b006683bd91962so15849740yba.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 01:08:39 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a05:6902:1d0:b0:668:b5ea:10ec with SMTP
 id u16-20020a05690201d000b00668b5ea10ecmr8084737ybh.419.1656576519392; Thu,
 30 Jun 2022 01:08:39 -0700 (PDT)
Date: Thu, 30 Jun 2022 16:08:33 +0800
Message-Id: <20220630080834.2742777-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 1/2] mm: Add PAGE_ALIGN_DOWN macro
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: David Gow <davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C1EfKr+S;       spf=pass
 (google.com: domain of 3b1q9yggkccwvsd0vy6ey66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3B1q9YggKCcwvsD0vy6Ey66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

This is just the same as PAGE_ALIGN(), but rounds the address down, not
up.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Acked-by: Andrew Morton <akpm@linux-foundation.org>
---

Please take this patch as part of the UML tree, along with patch #2,
thanks!

No changes to this patch since v3 (just a minor issue with patch #2):
https://lore.kernel.org/lkml/20220630074757.2739000-1-davidgow@google.com/

Changes since v2:
https://lore.kernel.org/lkml/20220527185600.1236769-1-davidgow@google.com/
- Add Andrew's Acked-by tag.

v2 was the first version of this patch (it having been introduced as
part of v2 of the UML/KASAN series).

There are almost certainly lots of places where this macro should be
used: just look for ALIGN_DOWN(..., PAGE_SIZE). I haven't gone through
to try to replace them all.

---
 include/linux/mm.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 9f44254af8ce..9abe5975ad11 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -221,6 +221,9 @@ int overcommit_policy_handler(struct ctl_table *, int, void *, size_t *,
 /* to align the pointer to the (next) page boundary */
 #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
 
+/* to align the pointer to the (prev) page boundary */
+#define PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, PAGE_SIZE)
+
 /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
 #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220630080834.2742777-1-davidgow%40google.com.
