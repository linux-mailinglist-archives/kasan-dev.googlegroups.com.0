Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLURQWBAMGQEQ7O5Z4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C35AC32DB72
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 21:53:02 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id m71sf8331165lfa.5
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 12:53:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614891182; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0f2YbP0mTjofIjPKgQUOYyKS+64rXFHCLfLql28Fst7IhB35C084d31IaeS/uuzR8
         fp4Of5ESh61e9CLv7sTcWtCogB139VgsJ1w2nA1qYMBIHTnV6BgIz/MrrMXaB3Bz35x1
         GM7q5f0cXo1trC+EVWWSOn6MzVVBfamsWDVJZAhXYLShHdeKSFHteucCgmUZbOC+J477
         YIxEj97+pnihgtk5REXs1EMmOOOiAhOCktWlc9BXUW2H8GieMSFJwjNe3hmv2batHjLL
         iv3qh9t91GdUORh0E4plwXK56N09PTQQT1qKI53hDqR0gMkFADERwvA2LZE7qbnOykYG
         lUhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=MAonQuFw9y4vZDVcs4BUDeH3CdmQ1aXAjs4ipiEsx48=;
        b=iMLCxK/EjQPU5uXilCH3RSq0MgfIRHAcxKWgg7wjz/CHNZ3YwjZ+Ls19u+yd6NT2/e
         rSzKwR3VMDKFGtyazbCu/EokBTv1F6jJMTiU/RBjIOoXGOzsdC0adlrpik9Vm5qICHDJ
         znhWTfoE0PpIpxb5AzCI06Oid0yuhfTXgm66sisv4jCcFptZIuzTjSx/70ncwF+izJLd
         BDkbPNVX5zJnVHwOfcH/dovUVdbsX+eHMR1cXiXkttz/cqlj5BPOlI/wjrIOxM4r7RFF
         EVL/cKIOgGFe2em7InrbkU5Mi+dqvm1QS0sf7XJgH1YLKrbZrtyF6zwHqvoYjQvohLwM
         Sgzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kQcOCQ/c";
       spf=pass (google.com: domain of 3q0hbyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3q0hBYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MAonQuFw9y4vZDVcs4BUDeH3CdmQ1aXAjs4ipiEsx48=;
        b=r/LFzzB9sswNgcSPsJ6wOefggxHRG9CDezB9i3dcJh6L6jEKNOk6tuovuTnkxc9u9n
         nlX6fzY+RF1Kzg8DuisOfEBcbqTkiPk+UGqFby3mWXuvlmcBq569e3B3jjDBx6DC8IEd
         Ob5Vn8m8BKHeahkZ1sSUubobW+j0BwP9Fsx4ZR7S9ptdunGcWYB7MbrfRixDY0+HvI25
         jbLQM5ZO+asi3XWosV0MP6n9QmuHY8KrdsSKqzi9kuKaNd3NkpnrwGY0HVS9wTlMLYsJ
         0S4bzFVwg4ukafuB0lRsB8cNXyDES+HNT3MtViFg5LRyOsMxf69zg3w/nLTptOXIMPSt
         bnSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MAonQuFw9y4vZDVcs4BUDeH3CdmQ1aXAjs4ipiEsx48=;
        b=jocec38Z/7kf8G5579KenXt+bSqEkgHjCXhcaulV39xGO6XWaLKzjZwK88SUjqopV7
         foOIJD3AgJrkv9dvuv5MGNOw4jMU4eZSMBdtgIabxmmz4bJDE4axQjlPtdTl8c9hFddA
         uat/wZEnskPLqPDuw8D7Fs2hRpph/BgI79iJLhLJ+8g+F613N4ugS7VloPY/g+Ww76Me
         LoHhnUCatnHH5m2Y0taSED6Inmo9tW/KyfiYtroiv6qyO/s7PuBQSzWHahEQpgSb0dl3
         HQ1gYv7csQg+mV8GTvZpEDM8N2EFVDuNvn/hiqfxXTR8aa7RNqkJyT3SSJ9D4N0I0O6I
         1MWA==
X-Gm-Message-State: AOAM531kNA7B9IFXQhrZOUcQF0v+trnhfgnI2h72oNzWYFPrFwku15VA
	/63eqwxx+OvXTFPgDvtZLPU=
X-Google-Smtp-Source: ABdhPJwM/GcFGZ+hD7tuVj2LIdSFUCkFS4eFu8mb3hqC0sLz2w9UgV3Bq6q4gjtv+lbjDPQe6BMydQ==
X-Received: by 2002:ac2:53a3:: with SMTP id j3mr3298091lfh.92.1614891182385;
        Thu, 04 Mar 2021 12:53:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2023919lfu.3.gmail; Thu,
 04 Mar 2021 12:53:01 -0800 (PST)
X-Received: by 2002:a05:6512:224b:: with SMTP id i11mr3616144lfu.652.1614891181205;
        Thu, 04 Mar 2021 12:53:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614891181; cv=none;
        d=google.com; s=arc-20160816;
        b=kv3H2xoju3B440VVI5TJ2xYNlFi0V6NQGuxBULjm799zeCyn0WmfLN+5SXbnIVEKgC
         9Odc2racDOa5cCzumWVfCuobN22jCnaZcxG0xZk6qe9qoR79Qco+n4QgIb5GfbbKE7Yf
         jinys62Vvw60nR72q65xbzgtcAUT9sufh3ePbEyoN3hAigV+yFbAa42/+d/SwgOgYJ+t
         pTZtJl9NyX9+oDYX9Apxr00h/agR59RsOKSz0tivnuPwCAnHZ31/UBxyXSO/TJ7KSbm4
         4BSUbmDV9U5M3X/VIXHTAMCl/FKENBiWA/Qrvy/t5MGr98e+gggwCEkUUMxvnF+Thg8g
         8E5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=4CjcEvJ61GkUIoAFgSTKRu5Tq1H6wn08RVLBK2Lt0I0=;
        b=ot4QQ9aMo1n6oT8oIEHQFs+RUrp1TlsQ9JUz3XvH9hPhvjZmz5ADfeJhINEQKHlKel
         4tyLvaVg1zVhsJd56gOumcJrhDZo4bLAkZGRZN3Oz4ztySk+sCwkLQcGJ2f1Ckti2kW3
         ld7ck+kXVulUKUok5UKQF4phikkA4eMUGCBREpiQ/SFdDIu1+jJKidicuhL+pKr6iY5J
         LjM0NYOh4iZDbJkAaimDs5dBzNe8ydFjKcYgIZ5QKYg6IV+48JdNsQLeEpmzndx58ZdA
         jbM1AU9F+NQxKzKvpH2WsmnkrSWZTyL2RdVBORh59bFk0eNC867rbjYTE4zrzVd0vH+T
         dOdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kQcOCQ/c";
       spf=pass (google.com: domain of 3q0hbyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3q0hBYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 63si24681lfg.9.2021.03.04.12.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 12:53:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q0hbyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id f9so4984532wml.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 12:53:01 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:adef:40fb:49ed:5ab6])
 (user=elver job=sendgmr) by 2002:a7b:c18e:: with SMTP id y14mr1459027wmi.1.1614891179563;
 Thu, 04 Mar 2021 12:52:59 -0800 (PST)
Date: Thu,  4 Mar 2021 21:52:56 +0100
Message-Id: <20210304205256.2162309-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH mm] kfence, slab: fix cache_alloc_debugcheck_after() for bulk allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="kQcOCQ/c";       spf=pass
 (google.com: domain of 3q0hbyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3q0hBYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

cache_alloc_debugcheck_after() performs checks on an object, including
adjusting the returned pointer. None of this should apply to KFENCE
objects. While for non-bulk allocations, the checks are skipped when we
allocate via KFENCE, for bulk allocations cache_alloc_debugcheck_after()
is called via cache_alloc_debugcheck_after_bulk().

Fix it by skipping cache_alloc_debugcheck_after() for KFENCE objects.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/slab.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slab.c b/mm/slab.c
index 51fd424e0d6d..ae651bf540b7 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -2992,7 +2992,7 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
 				gfp_t flags, void *objp, unsigned long caller)
 {
 	WARN_ON_ONCE(cachep->ctor && (flags & __GFP_ZERO));
-	if (!objp)
+	if (!objp || is_kfence_address(objp))
 		return objp;
 	if (cachep->flags & SLAB_POISON) {
 		check_poison_obj(cachep, objp);
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304205256.2162309-1-elver%40google.com.
