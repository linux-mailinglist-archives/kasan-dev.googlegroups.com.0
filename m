Return-Path: <kasan-dev+bncBC6OLHHDVUOBBR55YSKAMGQEKRCLDEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6083453673B
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 20:56:09 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id z81-20020a4a4954000000b0040eafb31c81sf2827575ooa.18
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 11:56:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653677768; cv=pass;
        d=google.com; s=arc-20160816;
        b=YM0wEdH0ERvpN1J+ILPtdtvt+F5tfU3N0nImwLoOzDBjg5om6ncdJVr6CAf7HC+X28
         1WtSGE1mZ1PGM1uPGZcu0dwVBDUt8QNb2t0d1YahTyQ55wZO9HsQw0drQyNY6C80w/fF
         NE24rsSE+JS1otijWlMfS3+2YbaKMDhLnseOOEXdO6b1V4C9NW2c64JiYj/UFhFp+mLS
         n7izXICh/uaPFOxSI2JA9NgEsumR125g7RY4PRA6F6QwUvqdE81NIvXa1/M59PRMkeZi
         f8fLoyHUPG/32Zxt6KyGtyd8Ns55EULCusHThk5uxfmUCf3pVkMLKB3N3jgwCXINeON2
         2CGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=r71tho6GbPDoLP931TGNfsP5lmqVj2+/mEEKRyrDv/g=;
        b=1JxwlDKbh748hNI7FGfBSCvY40YbBJhKqAVVt2DhnDbqFPl/qn3KaXxyVVeoCvnt6q
         8GBhnpOKPHi1VjwDeG2w8dZf7ohDk70UCErWtu7CkKkJsc3snAtggh8+7oXLWL/gAR1r
         k+vL9pYpu2r1MDV4NbTVyxgF4Tk1MzLc4x3N9FB1jFVojCoNFWUYU1iz40o2BBAwiwKa
         cvxvivjgcRpy3KG24db4ErTSG0SJDEHc7I7NZr9C4vM4UAoV85YYrL8/gzmzrSS+nJBU
         /JBdsYouA6vjPlQxHGjFLdEdhnfH0HrKp39QzH1Yqhc0ETV8ptw7+v7nv2FNWTVr2XBv
         /9hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PYF1hpmp;
       spf=pass (google.com: domain of 3xx6ryggkcwqfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xx6RYggKCWQFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=r71tho6GbPDoLP931TGNfsP5lmqVj2+/mEEKRyrDv/g=;
        b=riwi1/V7Aswe/aFmwJ4vmdqB62GSzqNH1Rh+paZZsLH0ja6m6zI6uYUqm+6vKr4SDD
         ChOVB0jbyCm519AnPryDY/R07TKTXTVVlrzXwuG/gSoBuua8f4mKrvyv6t3cKRMyI6ra
         YgbxU7Be9NAuKm01XtNbWT7keFWRVsgOIwtD4euk1Ctp8O4Zh+HOONmux7giysJbID68
         vzWAlvcBtPCL91PMpFnqlr2rS/Z2+M9nVSJXrrNkMgmuH24ObggtPP45px1XEjSyOx0T
         f5OaNts6DhdX91MNh6XL+V7UxQUIc6W1QNNI0uuSJhjs0+Vf0FWm7luM1PnflD0bk1dw
         m4VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r71tho6GbPDoLP931TGNfsP5lmqVj2+/mEEKRyrDv/g=;
        b=b7HSlDgwatohW6tl+tNtwt6Z03BNTyKxwNx3UhLeXumH6QZdyayjEu/fl3x+4mj4wR
         NclITBnAbn4usLzbj2a02LKKpIohsWbKkIHL5S+yfJtM0TewerbNNzwaGLHVzNH39X8c
         IPAHxtL7DYfwvIVeNi3C04AcNUCKP8XCk2mm+UOfmHdeUa0FSsPAtwxkyWvUvPhJX0hG
         47ha/YN3CVJXvgi2Tt/GwGvNWTO6iSyD0lWcTVioZK3ZQb1Rh9a1iqOpjkyziJ4PUyC0
         CYiBEpWjtOF/kz8BBX7VQf0fOc5vPeXRtgJanL3XYE/NpLnNRGeo/b/fHUX9DDtMeg5I
         XEMg==
X-Gm-Message-State: AOAM533bolHIvhUHwXgj3LxRuBxjhBsR1RuYLmpwyIqoOUn89JTwzxNP
	AyeOEoG0kXSuB/3LqSS8nyI=
X-Google-Smtp-Source: ABdhPJz9qXlbg0v82bSfSA5X53FfveQegMwP0gV0Dx0cO4aXIeJWv3HfKjW7xnD0QdWQl4OHSLhJjw==
X-Received: by 2002:a05:6808:2cd:b0:32b:7fb5:f43c with SMTP id a13-20020a05680802cd00b0032b7fb5f43cmr4936478oid.4.1653677767968;
        Fri, 27 May 2022 11:56:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:148:b0:f2:e941:7ec7 with SMTP id
 z8-20020a056871014800b000f2e9417ec7ls1535904oab.2.gmail; Fri, 27 May 2022
 11:56:07 -0700 (PDT)
X-Received: by 2002:a05:6870:c1c1:b0:ee:5c83:7be7 with SMTP id i1-20020a056870c1c100b000ee5c837be7mr4890879oad.53.1653677767584;
        Fri, 27 May 2022 11:56:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653677767; cv=none;
        d=google.com; s=arc-20160816;
        b=OAIne+R1hbRXSLS0EoVgV8+LXBbfC+baOPp7gC2X5cnsJ6wQnPXGbxK1uPt5gBsjDt
         MdGwebH4lWaz64JdlzqUfTtJxk7RWSqCBbNb4PLm8khBxGnazBos05uIl4rTk3RWwG4Z
         +ksbzmVy53XK+COin+o50zJcIQvuJX0BTrz+AzYcLXl/jPgwdk6lCtAUgQjoF9nOLVCf
         M/MntSL9qKNyJ6QnoOHxfRtN3nyxYgMZQ5nBVoksHaPNrxEMDP9jaiZxG6KAhN4nqrGt
         R4eiUCaPbSM+1oYen+NEvso3UpSRo2cBTIFDLITiS1AbcPTSC9m+wSknMvFnN5L/Ko4W
         +CfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=342jTvfgyTJ/fKu8Bj0JFN4DakYoNTyydnegV/i2TgI=;
        b=iGIa7JW4FFeRReMwkuiY/oQpYRjxQk6YSWLt7NObUI9d6IJ1gVldU6PoOaFvCCy/xx
         gr3WqCTje2AIZLUFeeu/oP5SMPXdHpTq5Vwo7lpwRfzgVJTgbUjd/Vo3nY19UXceM0kl
         ujnU1xT4Gcl8TbFbA5+6yLw/QfEarkTEgr3kCxsGypkCRzNECmjAQZdNo+0oMuJbVBc6
         97OwZgN5PBLrNjUMu2jz7bPfmDC25LF0rVwcA6BS5SJ/r+vsoiE+WyGbbfnTD9UqmoNi
         B6WsvOYTlO8TWo1aUYyrJDBkLa3/rh51Rhc1ELS6BHxqNc1N5qy8BXh/k85oWH+d9Uwv
         objQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PYF1hpmp;
       spf=pass (google.com: domain of 3xx6ryggkcwqfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xx6RYggKCWQFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id r17-20020a05687002d100b000ddbc266799si434317oaf.2.2022.05.27.11.56.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 11:56:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xx6ryggkcwqfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id e11-20020a25d30b000000b0064f6bcc95e4so4864013ybf.8
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 11:56:07 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:122e:1813:2b92:fe8e])
 (user=davidgow job=sendgmr) by 2002:a25:9742:0:b0:64e:2c40:b33e with SMTP id
 h2-20020a259742000000b0064e2c40b33emr41935567ybo.455.1653677767170; Fri, 27
 May 2022 11:56:07 -0700 (PDT)
Date: Fri, 27 May 2022 11:55:59 -0700
Message-Id: <20220527185600.1236769-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH v2 1/2] mm: Add PAGE_ALIGN_DOWN macro
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: David Gow <davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PYF1hpmp;       spf=pass
 (google.com: domain of 3xx6ryggkcwqfcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xx6RYggKCWQFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
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
---

Note: there is no v1 of this patch, it's just part of v2 of the
UML/KASAN series.

There are almost certainly lots of places where this macro should be
used: just look for ALIGN_DOWN(..., PAGE_SIZE). I haven't gone through
to try to replace them all.

---
 include/linux/mm.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index e34edb775334..e68731f0ef20 100644
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
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527185600.1236769-1-davidgow%40google.com.
