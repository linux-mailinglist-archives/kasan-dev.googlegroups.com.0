Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PZUL3QKGQEVGFWZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D66021FB0DD
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:37:02 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id y16sf15708434pfp.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311021; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y04Uoyvp6KMu1SWktGRlSIkV0biKIsXMDAvSTl6NG5iqNnFox7KEWgo+M8LEnftdUA
         Ivh9GjAevuskmPGth8gbwR5elSfjHGdoEfQrbFZr6839iXHrkUYxMcBn35tB+mjshqK/
         gBRMxWmUmi4ZkQQQkiKv4TPqVrYm9a8/PtVxlZKtB303p15PwLzSgNx/gBoWpu2MAHkv
         u5PG35dQtdtCbQkWNzhsnri4pIC6rmNf//5Q1XTYh6O1f11mnOpLnHPasp7sgMBTgvWU
         Sdfm1tlvsE96Z6OzrbpY0ySD6RdUHmEmkLsDkA+hdPOHTSpoUksZB24chunG2qt1W+9O
         56hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VNNSRUlFik0mb5s3vh6PQRvrrFIV/zHjCU0QWf3ee80=;
        b=FguWdG6cXPIV2DM9BCYxcE4COzdwE8M7KsovaPoS7z9O7+9Kl5F1++OpIQmCxGaR8b
         hekrAGdywu2guqfIrZq04Co+1n0ULTA5O0gk29lHELYJfkztuQIA68PvT3hM6F4lVunc
         JeIcRLSBUJjUdFtf2AbkxLDwPkYgNltKvUNAB8rEsJkC3yvLTNmwQV93HDvDdGS9CdBo
         R4dgJaHn5ncNwtMMdytJlDusFjQJZJKABj+iXNpRgQVNaPA16Qrl1mAEbPbPtJLzcz2b
         6gym4qmCcr2kcm9GVYfKWWk3m3UsuoHmFFhlIZvaQcQ3IB/TsadjkZf6KNB3wETYM+/m
         HcKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WRXFFBCd;
       spf=pass (google.com: domain of 367zoxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=367zoXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VNNSRUlFik0mb5s3vh6PQRvrrFIV/zHjCU0QWf3ee80=;
        b=sqKYpXNxBk9N+buiTrLz4o1H0Z36STwk5dp6c+kfkhPTl2NreOxwf1KXx3GOEuCTd1
         +4wf2QoAEQ5le7AtgJKbZBBUwgd8PvW+7+c7WV2C1g3K/BWc53c3faJg8rwXLYM3gOqu
         sBo0kJr3xA1lMOH3yZosADbdTTtfrDyLrEYMUdqC5SAMBG7ubM1cPQZWfS6YHQ7blr0Y
         gfNyzHa6bUSkA+F2kv1PF15POVjVe7Uvldxar6hVevVQVR1TOEoeiLdEwI88lOn04Lsn
         KIjy/TRpO7eh+NXIfZBKyzBZRYUfXIX4IljLb5Qd+qv1b89mNtZSoDPT93O1MNppzOZZ
         bb5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VNNSRUlFik0mb5s3vh6PQRvrrFIV/zHjCU0QWf3ee80=;
        b=iqmnRUVnB1B/G0OtBMtNWcXe0We99PDwxQcK4RMdWYY5b4+AmGLp6hHENJYvSSobvw
         WvYGTb6PpUnuEZGDeJ5Q1A8grPi9cQApiQtLJlQLmvoW8lfWZk1LzaMMFeXFSfewRG02
         ER22I+llZLCKvf0b3GP3Si7dgPBkGLIYHVo9qdZSMGq/7bxyB6L3VekJIWKdEt/7atiR
         R8uzbOFJqKxe6x9G6cT+OrqxGT4wQh5toJfCUtb6IGuizIa8h4tc9cxMkUBnZnHLW+of
         mcdeuyvp8X+SWOL3+i3WoHdhdSC64xXVX9GoGeu5jToQyRErLl3epUsnJEk2Pjr7Ms8s
         4cZg==
X-Gm-Message-State: AOAM532nBTy5FzQJ8GFyR1tr4y0N6SwN79yYQyEKJey/BwTiYdzW7RXr
	RO5VgFPmuy3VqMuyVMhbtZ4=
X-Google-Smtp-Source: ABdhPJwCCliQ8XNUhU44fXwmvlsTfGzjMfe/Phw+UzsRdRqYqXwflGMwZxzRaSC0JMW3ZuZ4r6rwzg==
X-Received: by 2002:a63:5f8c:: with SMTP id t134mr195482pgb.74.1592311021133;
        Tue, 16 Jun 2020 05:37:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:788c:: with SMTP id t134ls124741pfc.8.gmail; Tue, 16 Jun
 2020 05:37:00 -0700 (PDT)
X-Received: by 2002:a62:dd51:: with SMTP id w78mr1970301pff.28.1592311020690;
        Tue, 16 Jun 2020 05:37:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311020; cv=none;
        d=google.com; s=arc-20160816;
        b=N60LDiAu8S5FX7O8EJeK19m70pnKvuwesPpuh+FHCa8XWNlGimjlWqk1V4Wm5LUZ3Z
         jrHid7gaB4Dj+vZvUDtMJnQyxslZiYO6rpA1dfMERF6xHTfHS/+YWtjp9Z470ezKagoJ
         ZfokuN3MHBWMMltYG+qideLeWKh891sN7Hxp+rhEkWFhUNITkFbXbmrg67pV5Qr7LNpQ
         IBucj9G0jOu2ZeT3naA0Way4lKpIv1/2+mfOo95pUmRxebq+xBJtxDsHyAYswFrhbMpj
         AuYeudQPSFVlJqBCrwjG3DBz8dtRz7Fn6IilUNx5WmcTSK5H8+yMwPhkwfLnAkfuqVvl
         eCHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Vg6gGhm8RLyRRWmBBuD4VJ0tZVLjRg4UH9yY8TubE2E=;
        b=JMQntwuU6V1eFi56BIVKxbaFCESwvSo5j9kJBCxIUpQrbLRtJSXaJrPLKx3qXUpP7f
         tUQtSdxrui11UsWmsCDl2KXPCwY8Mw+JEX2puCYKcVWyyxj0xWP80Jx59y74Tf3N8fyZ
         ZX44bSeDznnRVYpjTzg0Uisa4NeD2FKZ5odOrzaWCZ2OQdoIhdiguFBkm5FbIcJ52j7N
         4ofrQrezvW9jPy/UcHRnPjxfY7rRJ4rQEt2PcY8fJ88bV/P1IDcQ89KaxAMFYkqCjW6r
         MubEU72XwXuX76gBEewc4nrn3aaG4x42MXVyTKd6QpkIlNeIiwzDTjT1GKGu9y5dlJUg
         OsUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WRXFFBCd;
       spf=pass (google.com: domain of 367zoxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=367zoXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id l137si1100636pfd.3.2020.06.16.05.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:37:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 367zoxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id w9so24970734ybt.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:37:00 -0700 (PDT)
X-Received: by 2002:a25:df0b:: with SMTP id w11mr4044370ybg.449.1592311019895;
 Tue, 16 Jun 2020 05:36:59 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:36:24 +0200
In-Reply-To: <20200616123625.188905-1-elver@google.com>
Message-Id: <20200616123625.188905-4-elver@google.com>
Mime-Version: 1.0
References: <20200616123625.188905-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 3/4] kcsan: Remove existing special atomic rules
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WRXFFBCd;       spf=pass
 (google.com: domain of 367zoxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=367zoXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Remove existing special atomic rules from kcsan_is_atomic_special()
because they are no longer needed. Since we rely on the compiler
emitting instrumentation distinguishing volatile accesses, the rules
have become redundant.

Let's keep kcsan_is_atomic_special() around, so that we have an obvious
place to add special rules should the need arise in future.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/atomic.h | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index be9e625227f3..75fe701f4127 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -3,8 +3,7 @@
 #ifndef _KERNEL_KCSAN_ATOMIC_H
 #define _KERNEL_KCSAN_ATOMIC_H
 
-#include <linux/jiffies.h>
-#include <linux/sched.h>
+#include <linux/types.h>
 
 /*
  * Special rules for certain memory where concurrent conflicting accesses are
@@ -13,8 +12,7 @@
  */
 static bool kcsan_is_atomic_special(const volatile void *ptr)
 {
-	/* volatile globals that have been observed in data races. */
-	return ptr == &jiffies || ptr == &current->state;
+	return false;
 }
 
 #endif /* _KERNEL_KCSAN_ATOMIC_H */
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616123625.188905-4-elver%40google.com.
