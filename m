Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7XRZT5QKGQEFLSYSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C16DB27CF69
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:39:11 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id r2sf3116022pga.12
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:39:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386750; cv=pass;
        d=google.com; s=arc-20160816;
        b=zKuwHSolo4oA8qyd0nlsvhuPlWffpsZePjDWa7I9QJti/pPVeFf5jFWSDrtMw83gyP
         Oup4YFdD09UA/E82YfO0anNF/aGaRMbBRTkOFFxTE//I7z9gz0Bd6OGhAbA7ZhZSyPRy
         KhtLiNX6lyFTcYeO+jQZBxRx7z/9tq1DZKFLjrgA7E8A6vGgMVHDcQGc5M/dDQPNRBNK
         /btQ3WJihqWIS6aA4Dv/malqfI0Z1argPRqec8VJJBAVtpw+PNL8dJhQXUoGRlbZPHwR
         deBwSffVApuWZUVE8RL9VV4Mxd/ru9Uwr3rLsU3evoOj89BMCnhF6Apg34icM2PAzBIJ
         Bdvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TW9yyLSCjes82DU8Hjugcc7J+9BSFHSc7dUkiyvBCCg=;
        b=aY+k0eaJd0XcZyLEY7F0shjO9PMnnboDWA/LI/42daz7AUBvXdwZsgce0xMUZbMomI
         xU8VzLLmpbyyFhHh3kIq0CgGt5VqV665vBmoRb3g5uK5VVhEdY1qH7aJdRZPCV1ObCbv
         3Dnua0T798zlrCdz82ARSmLNUDkMBNxbc8UZrMzw0c1XEdJFAd27kYCWeSPSILR8UyxR
         lSsQToiQ4jfBQAf0WbdrwWV6TfAP7p0Yi0RrmXPNTYkFcgS4pebmpt+PPI9iMikx9S67
         2B7kkFQvld8RJ/PB4CAtK9kfgnC6ATxji5fr/FHvGxEAxldycSn0CmQoGhtxb81DAyTz
         5w6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RMoZt1N1;
       spf=pass (google.com: domain of 3_thzxwukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_ThzXwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TW9yyLSCjes82DU8Hjugcc7J+9BSFHSc7dUkiyvBCCg=;
        b=byJdB5ewhWwA3ogDQSX6i5bjjiKwD/sS3QJLfz+a9oQGGtm83oPdSwOKnpZuuoH6dn
         ckBG/D3VKBCb9dZFTiH7OD2q+op464gqkVUbxwTPNNwADRql3UzMGOAKXnPTc73yR8J/
         Ew+hZPMa0G+NbsE8HAkSpJzj+idCclpef7iELCJQM9/zGVl6y2S7Y4FVOmd/M2ulHESS
         AEBkGYoHvA3E35PUBgaoN3qKAgBTxW2a4PQRHWQvt3TIkphhYQK7Ir4OJW6tMFR+Jhoj
         GhOf5tchW20XtN12yuyN1ZD+4u7tHZM0OpWF14ROUh/V5WPCIJebb5Ecx5KGygwLXeyO
         Ua1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TW9yyLSCjes82DU8Hjugcc7J+9BSFHSc7dUkiyvBCCg=;
        b=O4YqKNMNGPu2Hxum2b25LnEDk0B1nvz049Wo05XnAd0mwxJXfxmfguB8kxyY5qGJlZ
         X5rICJSHuU9YnCi0MGhzsv5zH/YN61n3wbwea0JAxdplr3/dorfMoDugOEPzBCEiBh4c
         PkACBxH0acAjBAHU0v/7npWMcMyUtd5b5vGX+WYO/zj+/PYlpW+kKrGI1pHJdz5KDS0n
         YHQslmjcKbnPRtIeCzNB4qbMmBebvhOSHbTnrhUKigZYVG2PDu7qWZfLS3tbDzJOnQQ4
         1jj0AXWOHe8z+VfNDJpnV3KVZeJR1NGttuEym7RKRsUi8DTpdvj+ZsTUxrUeVU2CXE8W
         TnLQ==
X-Gm-Message-State: AOAM531kvlpNr6mRV77P0V2GUMETDBttvpJp4G4T8+kKrL4OjUM1wjBE
	84314zUHnBVdrNCrCjdiB7Q=
X-Google-Smtp-Source: ABdhPJwLtensFsY9RyAPnqsc5LKUSHcRsdNn0U55pdZMKJ4P30M/idftx6/8Xx+PcZSSlsQzubVQaQ==
X-Received: by 2002:aa7:8ec7:0:b029:13e:d13d:a137 with SMTP id b7-20020aa78ec70000b029013ed13da137mr4175665pfr.31.1601386750463;
        Tue, 29 Sep 2020 06:39:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9007:: with SMTP id a7ls1228420plp.2.gmail; Tue, 29
 Sep 2020 06:39:09 -0700 (PDT)
X-Received: by 2002:a17:902:b685:b029:d2:1e62:4cbe with SMTP id c5-20020a170902b685b02900d21e624cbemr4661343pls.58.1601386749798;
        Tue, 29 Sep 2020 06:39:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386749; cv=none;
        d=google.com; s=arc-20160816;
        b=u0LOrQYdx1WgjPqbaoMAXgWl726V3m1YMZf3rTUXdAZeXJyPNQt7sn//NY4d7bdjGv
         PhvppeRQXnIqe3sgLFbkz2I5dIkLnM/ftXZebUqX1obIu5xt8b3RKqQzzx8m6a/MJTCf
         7EMkkchJljLrhgIw7WIEPyuFZvKTRkKqAQduvDKS701XlvO1dX6Z06qXgEOlc51hkxsK
         3UTD53I36jSPUu5JCVezYERGs/2graxTPHE7t6paNpWZi0Uyncxowa3fXRb6EB8Jx1MP
         ft5R0S+Cpt4TgbyIsGgcwzCajiUjjZ4kiQi0CPoc949ctQOBjdfOBt3SdPJVfyXKKDCh
         tdNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yRZiTM513RUM1qA05tKNAK84aK8AXWt5NeOVqEsZqzg=;
        b=cwxrNy8WPnEMbjO4F51Gg2k6d8ux+/QQE7X+TW+5PYYXO9SYPrsAi+lih7UMDVvP1X
         3I3O2iAYd8FdKDudQ+7cMis0IkO5E6zEpdWWeoKYPxvuXQ/k1kdcFger8fi/kqH0gREK
         8KCyfge51d+HvMr+Q1XDCrLVARO23IrHaNlM2neTdp8spiKrIWoavmZYN9hBamQ+Vryc
         dluWAyGIxbBkc6iBujSuOzW+q4YnP3NJsKD7GMtDu4lewHpyWUOtclt/qD0pf0tsSIb3
         2rLdZSr0ncDnS3+r395PhVLgFE/G9vv3ed/XR3h0w0Ylq5T1dr3WAtfqCG+qXv3+BVU+
         ZBMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RMoZt1N1;
       spf=pass (google.com: domain of 3_thzxwukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_ThzXwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id n8si357655pfd.4.2020.09.29.06.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:39:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_thzxwukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id r16so2492579qvn.18
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:39:09 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:58aa:: with SMTP id ea10mr4618135qvb.58.1601386749025;
 Tue, 29 Sep 2020 06:39:09 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:14 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-12-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 11/11] MAINTAINERS: Add entry for KFENCE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RMoZt1N1;       spf=pass
 (google.com: domain of 3_thzxwukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_ThzXwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Add entry for KFENCE maintainers.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Split out from first patch.
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index b5cfab015bd6..863899ed9a29 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9673,6 +9673,17 @@ F:	include/linux/keyctl.h
 F:	include/uapi/linux/keyctl.h
 F:	security/keys/
 
+KFENCE
+M:	Alexander Potapenko <glider@google.com>
+M:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kfence.rst
+F:	include/linux/kfence.h
+F:	lib/Kconfig.kfence
+F:	mm/kfence/
+
 KFIFO
 M:	Stefani Seibold <stefani@seibold.net>
 S:	Maintained
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-12-elver%40google.com.
