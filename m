Return-Path: <kasan-dev+bncBD52JJ7JXILRBKPUSCRQMGQE45YZH4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 71E69705D0F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:21:30 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1964cb38b6fsf52519fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:21:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684290089; cv=pass;
        d=google.com; s=arc-20160816;
        b=W49a2spt6Y8NkvDzTFWlIzj5V4u4rfFU4+1LoIIRGcFZ5m2km08g1coAPVBoZwrbFb
         mlLzBtuqfbu5EXIHPFkSmYBO0+AHtu4c1rP92LqSYHwB2i/fzT6IxlVGGWiQj7D5BelJ
         LHq/yWw1u/k3RKMal5y5shlVKVHpvkLpyW5hRUUpON+2X+ee9r/c0Arbk0AV9qH1/7Hy
         KHo2BKICSL+jizEq5H/xGKwQ6qnGSqUGVeGwOG30gW1LdYoq8Ad3HGEcnYRe22Fpw0Iy
         e7O1wC7W7w+2A+T7Jqy2HHgmp7SCa2C2Zl0mJnEAMRp9nZb6wSZzyyXomMJI4xCapDSG
         Jfpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=y76D1rOSLgrHAwKNQVObUj8s8AMxveeYnyi0bUWL4kI=;
        b=F/3oV7XdM8exv5e66uxp0OXB/ZZ1U32N8kMnEho+FHOYZ5Qy1MH1JuRW1IaXyHEwff
         OMIJbulOUo60h+ynMfUuxD3un/g4+RYkMkUGOnqlL1yEaVXIveNHkNzM1SaZqOh9KLIo
         xK5HGfMN22TvrZa+oO+/7UePP237prpiM8thfN7Ct607taqVPiex5yxeKb2GJUh5pvfi
         DQLNeH+o4JKbBqlbOtiKAVy9NSzozIEOdilZ4Fp3FuOXhyNB4tuVbI+QFMn1Bqh+kV0K
         HeA6bBtfk2aVNDO9LCTW1kbF2hItrIPuR2hEtKvW7nwqAMQf+fSI50awxXcQovQNf6XB
         sAPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pXVJppsk;
       spf=pass (google.com: domain of 3jzpkzamkcvyd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JzpkZAMKCVYD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684290089; x=1686882089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=y76D1rOSLgrHAwKNQVObUj8s8AMxveeYnyi0bUWL4kI=;
        b=q9Elr1WvP0CfaSv2Rus4jCTroI68XqO/0FZ/5fodTBVx8aFG1lGbv8fP8/cg3OZvsV
         ftp4WrEsX0N2ENFgXRMxLwobT2CEwGV4zcB7GYLLCykchUmK4/eGUHFiJng2adzRSa9o
         JqsKnNVEemDyvhQDrSw8KUD+FoB3WElY7rqAUxIlcGx+YDJmwySaVO6UPLqzX71Rn4au
         0E0Y2m++n2cfyXeTix+aqndeZ/M65EJEQWvAIqKo3toIaPMejnWHni6KCy0zer7QNZsL
         3Ia6Q8Gh4qCrG1jYB24mYHNL1EgBvMft/CUX8PtOCkaN8mltd214CbBq0xHc6zg8CmQy
         w7TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684290089; x=1686882089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y76D1rOSLgrHAwKNQVObUj8s8AMxveeYnyi0bUWL4kI=;
        b=APgJjuEIHBSnHIW7bsHxLj63SYoy5huQ0zbM49I7gDQ+NEOCH82+o62Kb68sqVF77E
         kopfIIMPueTMEoJAN0fhpxNK4Auc2il40yQABemOXQO3ZFyF8sdflbiks942W4QxiTNl
         IWrHyAyXy5xe2j5t9iWO4N+3b6azaaOsA//djr2jCqRglFSor+BI/XrmK3bNyOiZkSbJ
         uw+2Wm2yoMq6Y5bT//l0yP44I5EJYKhyONsVwcpgFswqgZqMYEDMR/YQp3f+tpXdODrz
         AOVTjgMp96EG/heCi79tgDRs6XWujco6fZvsk44xJs+9JztPDG+uXFYUTf8jMyP2vDyf
         urQg==
X-Gm-Message-State: AC+VfDxktXgRe1KZ/x+fNs10t2ksWFbDV/lwnlQEGhpRuq0g+8RqUzN+
	qlhgfPGBAhfZtlKFjEt75bM=
X-Google-Smtp-Source: ACHHUZ7N6rzYmT4Jr4ZX26iqXzIc95+YftRBRW+zX+V67P3j/O1AVseYNCSfQUCG/ozJLYKoX+T1RA==
X-Received: by 2002:a05:6870:7d05:b0:192:ab56:ccc9 with SMTP id os5-20020a0568707d0500b00192ab56ccc9mr14826130oab.1.1684290089108;
        Tue, 16 May 2023 19:21:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cf03:0:b0:54f:f771:42f3 with SMTP id l3-20020a4acf03000000b0054ff77142f3ls1698873oos.1.-pod-prod-05-us;
 Tue, 16 May 2023 19:21:28 -0700 (PDT)
X-Received: by 2002:a05:6808:df7:b0:38e:a824:27d3 with SMTP id g55-20020a0568080df700b0038ea82427d3mr13549973oic.27.1684290088147;
        Tue, 16 May 2023 19:21:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684290088; cv=none;
        d=google.com; s=arc-20160816;
        b=BvzApeNK0ohabbXu5+9SOBAwhEWpc7ttvD1Cu6sxKMz6kWkN7Mr/9oMvoFM2LV6gLN
         i0feJpXZMH628XB0UazXbFfQd57bMr1s2K1u/OnPFMZnjwH+rkBUZAAFJDW/+GM1EpAR
         cHeO8i7zAsSXDiAer2U+GFVPeAtBOBDn8fDJ59f7exYp1D0jnKkzNpElWDvj0TN5e+/7
         d3UKDjjolgSKL43ntZOTQX7a7FGrRcigSI78DzFzgMVdCRAP6nt0zG3wnF4TGFUzRx6Y
         tlUgtenLHAD9uwvMlZTFVqomoT7Pzu5QDfXKf+FYCR/RaaahpB+QF+mHVodu0GcqXQGK
         LhAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=DmZ7qJu2QJbmubDEgRMJhswdry7Qhukww11ZPOJRgvs=;
        b=j03KWfWnoDCji/r/ihX3JPIYLqsv5c26NR6LSw7IFy8aHK4gbRTgPD5zmjbUQzO0Oj
         UtkeKrk0dNyerk/nyOcy05gMNIoysa6rBRm9CEOTCxENF3mvNJYEd7tJ+FVAwz0wARPt
         iP+HFIpDGJPFmCrptemxhHYPNXGUENDY9unE3cn1F/hXEy6yI2qAurVM3+ztS9Dp1Q1v
         LZn25lgRwGZQCoi9+H0fT3qMC8E7Ug6TVRj/XP60cTnjpZxUH4mgbxqK8UyJsapH/R40
         wDCMQf3LK1Oz/Fivld9G2xz5owqPzWCKwhgQkL16Yi0rb1JDIlGx2qE3O5JuyZx3JvP8
         AD0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pXVJppsk;
       spf=pass (google.com: domain of 3jzpkzamkcvyd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JzpkZAMKCVYD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id k5-20020a4ad985000000b0054f1917acd1si2734073oou.0.2023.05.16.19.21.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:21:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jzpkzamkcvyd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b8f324b3ef8so158768276.0
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:21:28 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:b3a7:7c59:b96b:adaa])
 (user=pcc job=sendgmr) by 2002:a25:8407:0:b0:ba8:4b22:4e8a with SMTP id
 u7-20020a258407000000b00ba84b224e8amr1065312ybk.0.1684290087741; Tue, 16 May
 2023 19:21:27 -0700 (PDT)
Date: Tue, 16 May 2023 19:21:12 -0700
In-Reply-To: <20230517022115.3033604-1-pcc@google.com>
Message-Id: <20230517022115.3033604-3-pcc@google.com>
Mime-Version: 1.0
References: <20230517022115.3033604-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v3 2/3] mm: Call arch_swap_restore() from unuse_pte()
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=pXVJppsk;       spf=pass
 (google.com: domain of 3jzpkzamkcvyd004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JzpkZAMKCVYD004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

We would like to move away from requiring architectures to restore
metadata from swap in the set_pte_at() implementation, as this is not only
error-prone but adds complexity to the arch-specific code. This requires
us to call arch_swap_restore() before calling swap_free() whenever pages
are restored from swap. We are currently doing so everywhere except in
unuse_pte(); do so there as well.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a99ae05d6bbc4f
---
 mm/swapfile.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/mm/swapfile.c b/mm/swapfile.c
index 274bbf797480..e9843fadecd6 100644
--- a/mm/swapfile.c
+++ b/mm/swapfile.c
@@ -1794,6 +1794,13 @@ static int unuse_pte(struct vm_area_struct *vma, pmd_t *pmd,
 		goto setpte;
 	}
 
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, page_folio(page));
+
 	/* See do_swap_page() */
 	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
 	BUG_ON(PageAnon(page) && PageAnonExclusive(page));
-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517022115.3033604-3-pcc%40google.com.
