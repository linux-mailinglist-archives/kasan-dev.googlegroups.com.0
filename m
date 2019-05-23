Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXG3TDTQKGQE2DD5NDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id A25D927566
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:33 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id 129sf934022vsx.13
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588892; cv=pass;
        d=google.com; s=arc-20160816;
        b=Op5UCpyf8ymuM6+gIxXjGbS4gfpSHv4D6dzKiTeQZlz2iV0hVXs2vUJxz8E2AhPr7V
         AgAX/QsUHcUGzyQKl1fTyuU3k8Vz+HaXVwDtjtcQGW1+CYfu9XIL1UDtajk+ZgPy7S+/
         KowopqhbU32hRwvNn6/bAuDe082gN58uc1KGd/Gg5FSsCjdb3T0a3ANsts6GboTXY7DL
         M0uMM97JMaFn872Qu7loVHQOjPkwZGr79SM2FLFUKXkQq1SL5UXrLt/9J/YqQpGDFsnb
         R4FsRHj32sdCF5BVCqXC/JxkAAACumr5E+0R2Mfe7gm3FFQwumrmONixD0t+Tx1ixFZQ
         nfGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=svYRhsXdKeEjsblGBcWA26XMhfkljy72zojJIxznJlU=;
        b=T9FfXXUI+FqKnuo9UupLLajD7p0JOPf6ZE0sD0XAjDNXjrLRcBRkNlDJk4CPwuvYf2
         zDL+2RUBk08aNAoqVUFOuV0AfPOIxcH50EmlTjdhiupdLQvQN9KiGHW8NLse6epSIOdR
         GmYJwEwUkicd/4nOWX4lDnxJAqKtfXKHWyAI01hsjzdD214NnYBmZK7ixXJ0t3gidEFy
         WG8pSUlEWwR8BPN5rQVuE+dxR97zbdHOyrgLdmCjypySAMT+YrBsTrJHPbnPew6gnG+U
         AVMhrak/f1rH0rApq9mAD2x32Lc3klFJlgFBX7jHjF/pIGwMHLgwkp5JQmJWLojzc8xp
         u0YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XTURjqfJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=svYRhsXdKeEjsblGBcWA26XMhfkljy72zojJIxznJlU=;
        b=KftcAEriDa7iGdKW8OGIrxKpqX6sOMeoxugzawmZ7UL6hKRhSmVBiMCO82H/SiTHIi
         6lkl6aH3web6iRnibkOVnbz49oPChyJ1V8CfSBMf4nKH8IgjnN0SsebS3y8Cw/SvT4mx
         BSGhfWYUm8gaG7ih57r/dc6OVUorjo1A/C0HJSW6+m0uyuq7bsR0xvHZ1M1hHxyeXVge
         dMV4sLdubUPXRTQc2fb/2eWGASkgzgPY1+OBS95xiIw+MRUwptGzeueSIIgoYGGzXXv8
         JvPJ7hBNHE9NK+2JHQjwy+h2XOQVgTfeVHGMov3t4ZYH5jRw+fVzjF2RbusqCCnRPL9v
         He1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=svYRhsXdKeEjsblGBcWA26XMhfkljy72zojJIxznJlU=;
        b=TNqv1PHmkvqROPTyjYvtf7w84P2l/E95EpTZRrPIem7h6TRcT3gZJARZmbwo76VVNv
         6OWM3FNyXm8w61ShDxKcdmUSwinhb8qTRZfDhZWMCq5mP2s45p90+iF3qQB4FUEzz4PN
         pZOEOjW1LmhOW72EUvNiblSOFBikKdv68hUrzmmeXtOx7ZNa5I8e4sOF9pSKpVK3JfcM
         gfmM+kp/9iwNsqPrLD0eTyS7w2Ke0xNvUsaw2REdxHsDGMUGlz4RDHce75kw3Jyd+R/0
         M9wuOh8NQLOKuUXsvD9pVOh81xwyzWb1ovpadzjs6C3Q3R7C6mLQO0iwfp0iokZaX2Ao
         NzSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX2U6xA/DiWfmRKQEG8ZFBb2E1koTtB3yPQ6szCm8+u+3cckwy9
	A1bD9P5v4/YOpCED3LBLTCQ=
X-Google-Smtp-Source: APXvYqyHFpYfNGCtsyOZtLi1+65OlLniVKtHkSzhDPL51nijf3aUnSFY1ULanpXEGoDPHoXAP3SrmA==
X-Received: by 2002:a05:6102:105d:: with SMTP id h29mr38715360vsq.84.1558588892389;
        Wed, 22 May 2019 22:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ef93:: with SMTP id r19ls454275vsp.4.gmail; Wed, 22 May
 2019 22:21:32 -0700 (PDT)
X-Received: by 2002:a67:dc98:: with SMTP id g24mr35409108vsk.27.1558588892151;
        Wed, 22 May 2019 22:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588892; cv=none;
        d=google.com; s=arc-20160816;
        b=cWyzASufujpduD3PtYKGvevSnKzpZiDYwlK5Kj5XOumo0Eb0uTNvBm6IzRadgp482Q
         X5dkjZQDmuxCSpkGL/5igmLuP70jsBcm0G9JugrieWGXGiPt049J3XPOl//lkeA9J3N/
         E31fXUFZajM2ubYp7xh4UsORhALZdO7ZqUWVCWyQOf9tsdSJxvCyGiM0FQ6sE2Tm8Gq8
         pNZ0IK7ymrcBpz0/6+TyM2VoPSqA5Cf2Qu9d/EQW01lICuWieOyS7lx/uAUtiWIdI4eL
         J7o5KQseFMCXJLzvbA/pGVJr3y/2nKeSVyef6lfkhHTVxpnq2hJBiK4UrUIjh8pxy+US
         9QNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5ekkHWOem4di90lP6xcBDLaMXB0oWvbPWZ8H23b29xk=;
        b=dikaXbAEz1jtdt8YJA45n3F5Ccss4RpgiGFLOMt9tjBliEUY+JXg71NlFBmauaEFjp
         eUqinUYSdfwWv83VlClEa585nlI48RWQsJuk/VQVBd1aMmAgDm8geoRkCfLxNq4KWbWr
         r/gxNrC1RF6DcBsXRrtUb/DGRZbxkwpVEKO8jL/i3K4wzdFz5DFVawaEAfqWdIcEyIZc
         +Wum20ezwWuH/0ICiL5gkI46XvrHab0nbCINUhxcX5M35rYSlI1SG7zFeYh3s25fcOlE
         2JMok/Yd0JX/yDeLRLG6HvR5+uvgkBU2o3OgjBK5eKkQ/FyR2bYv1nKGAxHbrtJ3l281
         3g1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XTURjqfJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id v191si1852298vke.0.2019.05.22.22.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id c5so2175645pll.11
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:31 -0700 (PDT)
X-Received: by 2002:a17:902:b191:: with SMTP id s17mr72951266plr.262.1558588891187;
        Wed, 22 May 2019 22:21:31 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id l7sm29300717pfl.9.2019.05.22.22.21.29
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:30 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 1/7] kasan: do not open-code addr_has_shadow
Date: Thu, 23 May 2019 15:21:14 +1000
Message-Id: <20190523052120.18459-2-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XTURjqfJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

We have a couple of places checking for the existence of a shadow
mapping for an address by open-coding the inverse of the check in
addr_has_shadow.

Replace the open-coded versions with the helper. This will be
needed in future to allow architectures to override the layout
of the shadow mapping.

Reviewed-by: Andrew Donnellan <andrew.donnellan@au1.ibm.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
---
 mm/kasan/generic.c | 3 +--
 mm/kasan/tags.c    | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 504c79363a34..9e5c989dab8c 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,8 +173,7 @@ static __always_inline void check_memory_region_inline(unsigned long addr,
 	if (unlikely(size == 0))
 		return;
 
-	if (unlikely((void *)addr <
-		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
+	if (unlikely(!addr_has_shadow((void *)addr))) {
 		kasan_report(addr, size, write, ret_ip);
 		return;
 	}
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 63fca3172659..87ebee0a6aea 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -109,8 +109,7 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 		return;
 
 	untagged_addr = reset_tag((const void *)addr);
-	if (unlikely(untagged_addr <
-			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
+	if (unlikely(!addr_has_shadow(untagged_addr))) {
 		kasan_report(addr, size, write, ret_ip);
 		return;
 	}
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-2-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
