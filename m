Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBAFG6GSAMGQESAPINDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C13C7741515
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 17:34:25 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2b6ad88815esf20261701fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 08:34:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687966465; cv=pass;
        d=google.com; s=arc-20160816;
        b=hQUx2+KmltN3Al7e90sx17WJVyrp8bODE7fAhQ8IagaAi9BYrPZ+b7AXHuGq+BvYM5
         lEWd1KnTekRs6JjPGyuN/SDwpahCsNmVZzS+twbzXWO+VEf3kHe7RkkxopOjJ1njcXUi
         8q4VAgPAZSytjmFDJLbEWImFMnt8+nO+T9XuZS/nf2qPPs+iFNuiivL+OMgf1ILYvNkX
         o5TkElrCcuNQ0rKEgqSGXZ96fSk0lUiuX18ATLfqeGJzmC14SaEbI90xipYCFweKaGHB
         9NlXFuJIxL1+50VeToefZ+CqSQK1spwZaxOL519KaxIHgE5jJHwHCEsNblJDWaHLqCLE
         vR8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Mea/XLhMOfln2CZzI/m2ZEvOEU+uTK65mla2oEswRzs=;
        b=X/jkc9HkoQfKaYvWfd2CmzMW06fiavyFS2ESDJ4Upkwxj3mGaoeotvL3xiUTU7yLeM
         Rb91hjXCyrpHRmOiqfp99wkHxbKN+FYdlFTohA6lv+YWQZk3MqkKSelpGTVRzsRP3gI0
         02zyoAkFY++tTcSpbDuUC7xIPJ+U3pIPq+sH9l3hsbUChBJMjtZwfvKhtLi4+SynWITs
         m7G8Bwf6V5EnidW6DPSRUlWuolenxqeNufvJ2mB/u9vZVumbf1lutg6qK7RLiC9BT9J3
         RHsdLHZq718bnrfkA5JWt2GKtu9Kio0a/EpFcNCaSBjkA1yMorAl2g82s5WCKoevMxEL
         EYcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eE4X3Ir4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687966465; x=1690558465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mea/XLhMOfln2CZzI/m2ZEvOEU+uTK65mla2oEswRzs=;
        b=R7nvsy80z/9LEf804IIh1M4UkF/R47QLmkBKD/AXGIcW9jvlRzBjUErfIufR8hhBlO
         N6pq4mZHcAB1x1G2HnI2xVgC+Ixt8Gm+QbhDDxpwb+qfp7zvurYGxzbji24D/rzWST2M
         f1ZC+mUy0O3p9cOCYORzLdEc1Ws7uHUc7VEAQxiAOtaa9NexGnTKnAegCcTCA969VwTt
         6Ye7GRG9CDnQ2bsSDC/AexbRMGpPRL+O6eCFEPoA136+EIy3Ubg5JZUhq78/L0q98KdK
         VQ+Yi943ZgoZ7VxV4u56hoY0HbwBmCMUtjFC16BcM22ULNPYNJFeobD54DepeE7a8gYh
         rCCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687966465; x=1690558465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mea/XLhMOfln2CZzI/m2ZEvOEU+uTK65mla2oEswRzs=;
        b=hbK2QnUTgLU5MR5Fdic3wL2Q/Ir42vVRRBsEqPvb9lpn8zjMoUrfRugWe1fiet1w8O
         Wvn7g8q7QhB+gM2Jfxru1nlGqON1JEF5MgL5JyCz7Wu4ptZlhCfeAHCV0Yl9jGO8LI2E
         DnQpSF3jjwb9Qb0ApMewnhbsM4m5GrGMhixmR9E1FUiuT0RBqyLkiGTmrFvJT2XHo5Fv
         FHaFCij2vXIN9OsgYDHwhs6/DdEPpNKTtDcEq+llrEilOLqXpwouDLHwBb3Ief0SWsZl
         rcnBu6ntEgoLQGUXeZxIg/RgibOKzDC+NihsjhwmdtCymf+ed/nKPxpUEmh/L7AEsqKJ
         WKjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy5roZx/SEc2z5ZsbDivDC8wdffLA0hd0w7VF2b9cCiv/kpfw15
	y5yM/qvi2O4PVHOC7hpVPoc=
X-Google-Smtp-Source: ACHHUZ4wyLozQ/TZyuAVX+XD7KzKM8w92wW8c6hoaD57mYcg9PY+j0FoPigArAabVKFSI6ljwytxEA==
X-Received: by 2002:a19:644d:0:b0:4f8:6833:b13c with SMTP id b13-20020a19644d000000b004f86833b13cmr17448677lfj.14.1687966464516;
        Wed, 28 Jun 2023 08:34:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c2d4:0:b0:514:a0b8:647d with SMTP id m20-20020aa7c2d4000000b00514a0b8647dls2179345edp.0.-pod-prod-02-eu;
 Wed, 28 Jun 2023 08:34:23 -0700 (PDT)
X-Received: by 2002:aa7:cb17:0:b0:50c:2215:317e with SMTP id s23-20020aa7cb17000000b0050c2215317emr21790756edt.15.1687966463071;
        Wed, 28 Jun 2023 08:34:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687966463; cv=none;
        d=google.com; s=arc-20160816;
        b=hBn8fypGFaXWPzlQj70fDAncadLTnMm+1qUYFhlygNpdOWv/tdOnd9n4lROrzto5mW
         KEpE0Q1WzWTvoRKt42DY0qjZ9YOEupJZi3poiblJ7xLX75x25hnQz4SJFG4Pnh+gHS6r
         Sr40deWu+neenhn/JnmH9v7dPPuVsojZ0OhibK7BJeNClmcZaaxJkLA1UPgQPkriGO/4
         kSGnmV6KtHfOS0erDBYbZfNBI5a1JLxCTcRiq8Ta3CaI101+LNE70u/bXG4Zt9KyltYp
         XEDzkecNDUSiFXj142v45EXA0QmyDcI7WB84DndYSzqXx8raTUG6MBNWCwu/vMB+u3w+
         iTpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QUot3id03Fi4Q0nI8wc0vO323eixpfAxso0J0rUzMvU=;
        fh=YEBSwHLBxseWd1htZdUMtd2T+IT5f789+YFsDanJEZY=;
        b=NFwfQKFEpPyctNSf71WBsoCrbycCUeKBSANo+CXqymqaH8CvaiRHy9P18jtok0Rr8F
         u7V4yiEWPDd/WUaPxRw4xpZP6LBNaYLBNuc8wJgBiJGG2tgIIpbpoppyt/zC1RahM4fi
         7bEiNKjByCD7gF0N0xxsSokzkoe8vhIE4ISQf87U7sZbZlrCERmrs44Y9K7o7B6MAeWY
         QEgPGDciXyvRyp1gmYNOUvB98YvxA5txF1o4AJeJes1ftvdHXTHENpQMXo4enri0OPeA
         syEPQhtorfemBYuD+vhioNNXW6NK3RYaMQvEad53v1XnT/UbEyreevKXkFRNl3lC5Qpu
         PPgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eE4X3Ir4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id h12-20020a0564020e8c00b0051dd142f452si105092eda.3.2023.06.28.08.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jun 2023 08:34:23 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6600,9927,10755"; a="364427616"
X-IronPort-AV: E=Sophos;i="6.01,165,1684825200"; 
   d="scan'208";a="364427616"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Jun 2023 08:33:50 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10755"; a="782344837"
X-IronPort-AV: E=Sophos;i="6.01,165,1684825200"; 
   d="scan'208";a="782344837"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga008.fm.intel.com with ESMTP; 28 Jun 2023 08:33:47 -0700
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 4BDDDE1; Wed, 28 Jun 2023 18:33:48 +0300 (EEST)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Subject: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Date: Wed, 28 Jun 2023 18:33:42 +0300
Message-Id: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.40.0.1.gaa8946217a0b
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=eE4X3Ir4;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

We don't need to traverse over the entire string and replace
occurrences of a character with '\0'. The first match will
suffice. Hence, replace strreplace() with strchrnul().

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 mm/kasan/report_generic.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 51a1e8a8877f..63a34eac4a8c 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -264,6 +264,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
 	while (num_objects--) {
 		unsigned long offset;
 		unsigned long size;
+		char *p;
 
 		/* access offset */
 		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
@@ -282,7 +283,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
 			return;
 
 		/* Strip line number; without filename it's not very helpful. */
-		strreplace(token, ':', '\0');
+		p[strchrnul(token, ':') - token] = '\0';
 
 		/* Finally, print object information. */
 		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
-- 
2.40.0.1.gaa8946217a0b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230628153342.53406-1-andriy.shevchenko%40linux.intel.com.
