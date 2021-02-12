Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOHQTKAQMGQEKDOIVGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E3B1E31A365
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:17:45 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id h10sf3181690ooj.11
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:17:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150264; cv=pass;
        d=google.com; s=arc-20160816;
        b=aQVdhVNDYmCzhTM6wbJWIIv99V3O30dwv+Ge+GBNvBnfkk/tS/ffCU8czO7Q6636o4
         AeKS3aNWi66t88gui7mMcmgX/pHkyysxZZD85DM6GtIXNLja3Bzi/J3SrPLHs9j6WOdK
         QxhdNgsACuYx4puee2C6QzAg80B4t/h924ePT3qvCmsIy+qufrDWBx9aYXA0WQFWps8d
         tXE+WZYpf26CmnBiBKWIzPoPMNlsejzg8GIi5omV6tlEeEQOYKArJBz1NxQ89mJQUiMo
         dmkQyaqo09s0TGx8UEwJKGCihGuGo0CqyNjqD4bAiwojJ1vlo9ylPjCeb5eIfXno7Cby
         hFWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ktHAfSWZoUlipVimtEYbyW1fQNs9JZUFd1Z28nIZU7A=;
        b=pRA1Y4diWiBiJ/W9uDppSSS4obVLXyvw747jUO5FDikqtBOczTy8Smnjvs6COdNrMO
         sgxijZNyCPC7QOV0zh1tcREKpYNkiKdxqESFSxbMoCVt6ck7dmnLvi+t2mbv3ZkV2rDY
         rqjVMrcSLClQf30DcJOXDVwZaU0S0PqQA6D4J4F9xWWTxPFxPNTL0BWrtbuLVKl0Des7
         W1sXMZVpnjND30img+uVI7j+HKTeggZvwqAUZMB8iprLBenfQ80lhkIjPmv8eAxqcfy7
         aknNxW+5j9Q62gYOufYrSSMWTxYIoebOJdcZSbxIJ3oCisGGRo71Mi8lcZuCbIRLqyk9
         aD7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dlkmLNSB;
       spf=pass (google.com: domain of 3n7gmyaokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3N7gmYAoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ktHAfSWZoUlipVimtEYbyW1fQNs9JZUFd1Z28nIZU7A=;
        b=Zo6dYidqiwLayPeZSdKGbriGq7YThK5KThpVHEZQYFI+usebViSdBSvGvX0ytap2DJ
         knWMNpVHQ2ey1jkSiEfC0igtKVW8nilzggYAw8y50oaTfuMTbgwCb5OScggqRYuEGgsZ
         B+iXWHW1TdXUCd3tpxidob5GAg+D+3Pf+qYjd6czDtsSZJYawKxayjxZTZZb3xn+NGCM
         U5ROYUznmuZkTCTeKmd/vxdyXEOMgX8+4j7CDEAksw8KwSDqdbYA2assP+nqQi7P8z2X
         0/NpxcKywJZR9kaJhMvZWmeNwTqKaZREmQf7XkEVDHO6mJAGyVseJxmCIuZwh/CPq/2u
         YNEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ktHAfSWZoUlipVimtEYbyW1fQNs9JZUFd1Z28nIZU7A=;
        b=UbGnUXXmxqPsBtVY9ZDIW9DMdfAP4tN2pDZ69YY9HvF9jt55fcIG1VyA1s/UF/cUev
         sQVe2vnHyUAfDoDTeJcE8buD+r1DYfVNk9K4SjwCrQtz/bMM/GDgdVYmFCtgChkmg370
         /FxpNr4AizUQexEYTDqkaRTVAejfJPDn2sQ+NckDcJd8f3bmpNl27suMdz/hPnBRvzFK
         HNvh3zgdnF4qkSPuoQetxWfEJdOOxREDvlB1PwLQNt+RUOwPl99vQbIZJ8EgkK+hNP/3
         zdmbATyKvQ8XR9PQZDjAgjiUbWonAx+co7i8jxdtBSMHoskLx9Lpij6GOuEus3a59enU
         UyrQ==
X-Gm-Message-State: AOAM533hRrdr50EHS89O2MuLnj+jpVeOVT0JBbBVRRbD9aDn78O/SRF5
	KyIMM+kBtm7xBaUjIxSyr5o=
X-Google-Smtp-Source: ABdhPJxQrRIVXfY9qeXRvjfdTduZN9mhgmBSl5MDFBDQYnbjxmURw49zJUuBhp+uKBCyZnFQ4GneFA==
X-Received: by 2002:a05:6830:146:: with SMTP id j6mr2875546otp.231.1613150264455;
        Fri, 12 Feb 2021 09:17:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6e81:: with SMTP id a1ls2209958otr.3.gmail; Fri, 12 Feb
 2021 09:17:44 -0800 (PST)
X-Received: by 2002:a9d:7841:: with SMTP id c1mr2558837otm.31.1613150264025;
        Fri, 12 Feb 2021 09:17:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150264; cv=none;
        d=google.com; s=arc-20160816;
        b=Nd6cFCKO8Xc1TF96qUKGGwBW2vXKSsZ1FdHTOs/K813ttIu9ANCvov+yLc3iIcxACV
         fDh5VfAU78dHR9bkFADgVOcRgBi6+qX/II/3IfK9vGLp9YPtRDfa3HJ55C7CjRdeYppc
         9tTDCE3KmCkvgRrv80ch2zZYFAV99W1wpU5HbkrZA+gCU/Flk5gzZvo9IbC9kUxrBHBE
         hwPGuvl3os+JN5scUPwrBnz9Q6dEGOjWIE3Q71Y8oVTrS3ey/Vb0pAOtswjT9vzgaCjo
         okYbEmSCs6okr38/KWW45QNNRVN7QVNhA21DfWfyisAqcj1WJeMHQfJFjo1kIRfdkROd
         gCNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=c27ilmvc3s9n2liXWjp43qscJ0lbHohh395zb9zfzbs=;
        b=twGFwD9VN4bBj1EXVxMjaGcHTynoYoxw0ijBCsiTCchD3e6VYIK6GDUrXslqXQVr6V
         eSIFGp7zUsbn6q9I6uMtaAVu8kwbCRhodkK35mNeTsrct8U8xkhMz6fBSAbziDLWQ5MK
         BSqW7IjQOzV0ICLUIGjsiM+6K/9FOXjgbTdBW4qH8T8nEeI8ewSGVNWU2g8Q++w7Mki7
         4vt8hpUupNR/rWMGyDxlcp+Q6WsK+z1NVAzmCP114VBqdqRUGNe0pvVJ9eMvvwOZS4nL
         EWSEN+NWN0aKTpSh4JMA+IGJky0xgtaiZX1b4w78rNNWhYDNDZtbs1247ZhTo4pYqJL+
         2BDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dlkmLNSB;
       spf=pass (google.com: domain of 3n7gmyaokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3N7gmYAoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id m16si651567oiw.5.2021.02.12.09.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:17:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n7gmyaokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id f16so60609qke.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 09:17:44 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:19dd:6137:bedc:2fae])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fdec:: with SMTP id
 m12mr3542611qvu.11.1613150263425; Fri, 12 Feb 2021 09:17:43 -0800 (PST)
Date: Fri, 12 Feb 2021 18:17:37 +0100
Message-Id: <7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH 1/3] MAINTAINERS: update KASAN file list
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dlkmLNSB;       spf=pass
 (google.com: domain of 3n7gmyaokcuomzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3N7gmYAoKCUomzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Account for the following files:

- lib/Kconfig.kasan
- lib/test_kasan_module.c
- arch/arm64/include/asm/mte-kasan.h

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 MAINTAINERS | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/MAINTAINERS b/MAINTAINERS
index 64c7169db617..a58e56f91ed7 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9565,10 +9565,11 @@ R:	Dmitry Vyukov <dvyukov@google.com>
 L:	kasan-dev@googlegroups.com
 S:	Maintained
 F:	Documentation/dev-tools/kasan.rst
-F:	arch/*/include/asm/kasan.h
+F:	arch/*/include/asm/*kasan.h
 F:	arch/*/mm/kasan_init*
 F:	include/linux/kasan*.h
-F:	lib/test_kasan.c
+F:	lib/Kconfig.kasan
+F:	lib/test_kasan*.c
 F:	mm/kasan/
 F:	scripts/Makefile.kasan
 
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl%40google.com.
