Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKGCRODQMGQEZ7BKNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id BAD303BBB55
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 12:38:33 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id x1-20020a17090ab001b02901726198443csf8400645pjq.8
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 03:38:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625481512; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDbID+YcYFudzyKFErOJDCUxVnoOzN/qRnn7D/J+L3ndkXIiWZD3mxyiO0hGLS6TvF
         qluGWlqehqIzQcVXHq9+vR3JJDmVbkyn47csar3zerpuN5Fx5Dn/HqVp/bI4dtZF1YPd
         H/vcKSg066t2OMpKEAFTY3vrBIHdQwsC0KHnDAUlX7Kd6HkaPW28pNrA9xMMrpNOl26k
         CWkfiVje7110JOXgtuRMrkHs35Zl7AWBMPsTnsql3ZCHwxHrYS7UFypM0gNFflA/sIzN
         rMXw91cikHKS7YZvHKgPROwE6pbv/RwcqKfIWNBCRH0kwTihqYRGQOwALIPiCSOqOo9p
         QOWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=iPoPh7i00bWBBqNZJvqQQfn5MUAWG+mdOcJ2rhYmztg=;
        b=byRBQBUoKrxIqdNlJNECEpTJTSRsLrDsYRvVQZHMDUjW4RaJuNuxwZu7GZ/IurSnWi
         ps7vCY/Rq7E5WIzegesDxBPeGNjxooEsuJRdqV0pzPt5JKyiAakQm9t0Szi8+1F9Pjoy
         H6t8F1bm/wsAV5RbV7n99D3Zkh9A4yWMp6XmzRd/6bhXybBp/YGSBi7REdqhqREor/GV
         fCSOIw8GDZjhT+YTFI3emgYOTqE5t26/FgRWxFzCQkgwTKbB9QgHBUpk5qWPOBiALgjg
         ZoIbOhK+50tncsu0RyDElv+nisOSuYfuBrNAZw1suacnFVru3G74IDGgK3smpcin+/C6
         Rg1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uWq6a/+A";
       spf=pass (google.com: domain of 3j-hiyaukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3J-HiYAUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iPoPh7i00bWBBqNZJvqQQfn5MUAWG+mdOcJ2rhYmztg=;
        b=GkPul8GcFVPpjAUtI5Igi9F1CFGunOjWVrE6tRsWvH6sjdBKqwvXBhOtNLPXOKgxcY
         plEdWjmIggVN2rQtdBkwuIdR+Ld4fYtai8tk4MK9DHFnUhkbNaQ3zPFjLqdszeSqjWVQ
         DmrzQnESVFV617Lb71PmK748DanP20ge1PNEZTCxNgHXDqSEBDuZJwtx4wBMLYuvYWqe
         suqGuSVHWQesHsorttDTyEDBbND3zf9CagZI5iE30oRWdUyfZZDr8GeQwg9QVJIO92B9
         pwwosXtnLvc2QF+nCD0OjoV295Z1ww6YaBe+Zj02LqVaSysI8w98QPvzTqoUaNvc9vGH
         T97A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iPoPh7i00bWBBqNZJvqQQfn5MUAWG+mdOcJ2rhYmztg=;
        b=eDByMgxQjX+kO4yGmFmVmZfPqsf46YnvPgMKhGWthr24KEKAnjOfzu1/0YZnEZBp7q
         9FKN0CamidUFaXpVF5jrNqgQxCcDfaymSmDouOYEBHluEPRmlLcKgWuUOcyT1iRJhjqi
         uxX8L+8AD9mjyFJTspx8gKH1wIGuBjCt/dDBVq+tLiE9/YgLMT9G+OE5HxTDuvmD6Jbr
         gmM/3JnccSGNk8JuYuIKDaix2YsWAu5BRih49jEoGOhHkzw+p0CHjasaA8g84FZ637DW
         PapQXaPluS4xGS2rVj7quLyYTMMot0z2Zzjw2o+ZjF2FYr43tX7XaNj7fXCCXiz6+a4y
         CQsw==
X-Gm-Message-State: AOAM5304vOq3SdLyCDUQ/SjGluu2nlWmcd0DXepCHk9qjVDadiLUlyUH
	U9e4rkToTmAwcKjbV+iR0hI=
X-Google-Smtp-Source: ABdhPJwAhsWZm/FqXxVvhrZrEnx1RKITN0tOIdocHROoYfYjmFhKI0Fk2grsXa9txCMV2Pn7mIpoZQ==
X-Received: by 2002:a63:5450:: with SMTP id e16mr14363222pgm.50.1625481512262;
        Mon, 05 Jul 2021 03:38:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:834f:: with SMTP id h76ls6912087pfe.7.gmail; Mon, 05 Jul
 2021 03:38:31 -0700 (PDT)
X-Received: by 2002:a63:505d:: with SMTP id q29mr6242521pgl.137.1625481511678;
        Mon, 05 Jul 2021 03:38:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625481511; cv=none;
        d=google.com; s=arc-20160816;
        b=Y53HVO/1OVvudtxxlHhBoWuEkvooD7cSqYSnOxqO1sBoBX6eK9qjZ9DjjJt2/hmuWS
         f4G1SDc1euy9Z1EGPPo/RzBzbaXTgwxsx2SHmMBFwTTwt3lYs0XQ010zpYeGv/hMzb8i
         KBsJrgDhnP+bpUMX0URodsCs+zRMWrjPE8jchTg+RRlINqPlu/0K30gN1vPUyuPyp3r5
         nGm1AeVToCDZa8L3M+iD78M+RgFq9ihHfmpD5YJbBS6KaM2p+ruItE6JDMbbB/pZngFk
         p1St5ACh/MBrY+n83dCM5T9E9JZnoClLX/rfxffZ/l+5a6043XEMkDeY1LPGnvNFRpTY
         NMHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=IGdOeKuUWgjZXs+/OzVZm4qLwJ1bVY9XzV5XRDS7Slk=;
        b=0Z3ZMHGeiXz4kSKmX7GueOtuCdMPvZRTDP1RlO/ngMId14X0iBIGs2dfgePjFYQ0kA
         d0EsiI5x4n6rIj4AE8wWS3Z00AYDGBiIACRSlboZoVXlLG+X5IHnBuUS2TJpsTpnELPJ
         l5ixH3Gan6hQT4sh7mVNTe2JLkyeyBteCzFP7S0iZetpCecAsUhuOaw7jE1I4kzhaiEk
         JWBbgcJ67HSQEuNAhbATQtGXtEuz5lJHixhgrGVNatifEdxle93/8Hn/zXCj1XgZJ5cN
         F2e32w8YxIQ7tohM7R+u8P24T/0Kk6d2xsQjSt20YYGbhXF84h4M/aVnHa6iZWTmRE+4
         2BAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uWq6a/+A";
       spf=pass (google.com: domain of 3j-hiyaukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3J-HiYAUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id o21si1072858pgu.0.2021.07.05.03.38.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 03:38:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j-hiyaukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c17-20020a37e1110000b02903b3a029f1f2so13841491qkm.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 03:38:31 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dddd:647c:7745:e5f7])
 (user=elver job=sendgmr) by 2002:a05:6214:1244:: with SMTP id
 q4mr12258497qvv.50.1625481511074; Mon, 05 Jul 2021 03:38:31 -0700 (PDT)
Date: Mon,  5 Jul 2021 12:38:06 +0200
Message-Id: <20210705103806.2339467-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH] Revert "mm/page_alloc: make should_fail_alloc_page() static"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Andrii Nakryiko <andrii@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Vlastimil Babka <vbabka@suse.cz>, Yang Shi <shy828301@gmail.com>, bpf@vger.kernel.org, 
	Mel Gorman <mgorman@techsingularity.net>, Alexei Starovoitov <ast@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="uWq6a/+A";       spf=pass
 (google.com: domain of 3j-hiyaukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3J-HiYAUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

This reverts commit f7173090033c70886d925995e9dfdfb76dbb2441.

Commit 76cd61739fd1 ("mm/error_inject: Fix allow_error_inject function
signatures") explicitly made should_fail_alloc_page() non-static, due to
worries of remaining compiler optimizations in the absence of function
side-effects while being noinline.

Furthermore, kernel/bpf/verifier.c pushes should_fail_alloc_page onto
the btf_non_sleepable_error_inject BTF IDs set, which when enabling
CONFIG_DEBUG_INFO_BTF results in an error at the BTFIDS stage:

  FAILED unresolved symbol should_fail_alloc_page

To avoid the W=1 warning, add a function declaration right above the
function itself, with a comment it is required in a BTF IDs set.

Fixes: f7173090033c ("mm/page_alloc: make should_fail_alloc_page() static")
Cc: Mel Gorman <mgorman@techsingularity.net>
Cc: Alexei Starovoitov <ast@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/page_alloc.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index d6e94cc8066c..16e71d48d84e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -3831,7 +3831,13 @@ static inline bool __should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
 
 #endif /* CONFIG_FAIL_PAGE_ALLOC */
 
-static noinline bool should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
+/*
+ * should_fail_alloc_page() is only called by page_alloc.c, however, is also
+ * included in a BTF IDs set and must remain non-static. Declare it to avoid a
+ * "missing prototypes" warning, and make it clear this is intentional.
+ */
+bool should_fail_alloc_page(gfp_t gfp_mask, unsigned int order);
+noinline bool should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
 {
 	return __should_fail_alloc_page(gfp_mask, order);
 }
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705103806.2339467-1-elver%40google.com.
