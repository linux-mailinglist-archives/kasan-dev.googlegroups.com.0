Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFHR74QKGQEEG2AH7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C65AF2340F6
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:36 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id b13sf6120697wrq.19
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183456; cv=pass;
        d=google.com; s=arc-20160816;
        b=1G4YK5O6skEkshslvp4U/e3ECxl7bXvm/E+1WHB8UfNq6mTBp2E3dQvRhqauVCFseq
         GW3BmzZbv/mUZjjoT9PAHbVdXNURwb5j8vOpVB8IcnoZsIXUrV0cEq/tJNkNcXkFPCBt
         5PiXnnvSsQ0ybPKfn2x2hFLUAsGjk5ByPIEoyz3a+i2c/KyxUmfVTjyltA5gzHxXAsnm
         aPPLxsgmZ3GFngUTMixPIF9PCGDIRszeeKCAjyRIjavhi2Rmx+Aa9CN/BW+fwcBujsL0
         40XD1rEKzSI5yYJnr39x0K/CewZS6ROeHciIg8+8J6c1N2rcxkQHPJf/xdEvgGBFXbjV
         cXJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=UOi7RNL4d8XyuWh5yIijvFtSfhyJsUy5RoZqWiVBkzQ=;
        b=zvtJmCdSMMcloaI6HbmyMchextKvZehGEWibh83c2ySymWBomHLZIBE6Z060O8Lt9s
         xOniWbtMzMxj2fvRDd6pZL9sHyreI8jDbVb8raO0ChYXhagwUeChSGaXJ6zNd7iSJxIU
         enylHqae9K1bFltHi6mwchF6eCcXd2+gEWnMZnQH9KJfy4EfwNPUNbaFeOH3JLsrHsFC
         BsU0eZ9V41tQCRAb79PYVpPKHjqNn/Ob51BM6TcT1RbHB9PRMH0fPe3DZ49XddvDwFXU
         ceiXWNCgtYAL+VEtlvaGgT5gLJsIZdh177Q0AHHrKBSpbnQnMESl2TnoiCLMg0hZ+VcT
         Vfsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uKRgypIp;
       spf=pass (google.com: domain of 3n9mjxwukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n9MjXwUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UOi7RNL4d8XyuWh5yIijvFtSfhyJsUy5RoZqWiVBkzQ=;
        b=dKhWLwLsIIcNhXa0nNY6efZBlzOnN3pYZPpEaKwCEY3cUzEHay30ssThIMakRXA2Gd
         ZJkPlhlG1ZJ6Qv854sTwQfehnm/lbHIBoesur2TY35w9k8fX1vEiTaMWAsls7WE+Lhg/
         aJN0Ej0tan2nkImgZsmS0rn5oafIVrosYMRzfTbwogLYM8T2468BHrJyyxOJ8cfA0UlE
         sWeMpXIctxmouZlqFp13zjGLbyQzfn46V+FFaDVg9sAv9PGy99OJVhu5+4Zz/dZHwWmq
         P0PGukqEkXf6YLw6WL3TAqf6XdFHa1V57ea3x4PdQUOm5tSCXmPwtDMPNllEF6SVhdZY
         b6gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UOi7RNL4d8XyuWh5yIijvFtSfhyJsUy5RoZqWiVBkzQ=;
        b=fUhM+zzfGe1Q5/IXEYIn6qllstJxJPkFze+d4NleoVgdM/eayuLKiWQW1w7VzJsUxi
         uDoRHqkNldmRjK6p1srlJ9Auu0eiwKHL4XLaShGn6Yl7NYaaBiA4kVmIAlf1w4Sdmjvg
         8VB7E3v1HF+mtZXw3MIvrp8H7kn3ujegnb3rZUQl89kRbgQsjdjLGJ0m5AabRzIcNZhK
         PXrqqoyBI9XhyKrgZfsrTKE1U4AP7rMLoSBO1nuBTUJrsuJvtIVqI0CuhwFI+snOniLC
         aXdy5fZPMcglUhHLbcipj+FEbjjPMz/mtsK2R4DawjOeX6mmh57qM2VDXtlccX2NqqPy
         f21g==
X-Gm-Message-State: AOAM533sfqLEmBBzPpT8BYuybyUE4BVau25ItWEuESokhzgCLojPswt9
	rHfpnLucwVY5wjbVdb4FcOQ=
X-Google-Smtp-Source: ABdhPJzl2JKmpQOjWk+sf27vWtm7/wRR70t0BvhR5tdYGLYNvJ0H9CQv6tXlH1VPdX/H+4V0/GsFtA==
X-Received: by 2002:a05:600c:21d3:: with SMTP id x19mr2910984wmj.174.1596183456496;
        Fri, 31 Jul 2020 01:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1cf:: with SMTP id r15ls3116312wra.3.gmail; Fri, 31 Jul
 2020 01:17:35 -0700 (PDT)
X-Received: by 2002:adf:eccc:: with SMTP id s12mr2676842wro.157.1596183455822;
        Fri, 31 Jul 2020 01:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183455; cv=none;
        d=google.com; s=arc-20160816;
        b=z1i3sZFSWjAJbL4+49ow0vtzgdUHON4iLhtBIY9FAeOihIo0Ic6zDfsQOzpfopHcbU
         rLWT9jnOP6VNUE94ZdRyQbZM66hLkzyww5sZEH66WF3TCLQQklpqS9CmrqHlWjEDLAME
         xF142/sC+Q1w5MWyJxlyAQkKdxVK8SZYkq0N4oDPmWdTpylOfAK1y6V1HE8J/HDMN5iR
         MEpR18rSUwsIAZt0bKPfJRjCbX3AP+efP86KrmPyPH8FqAz1kYmnwTd41I9iuIXOucak
         7A3X5GJLpdjkcN+f1aNa0eXmrN38nkpCDELc9aBatmYUKioxWzvnOrLTZG8xD5MizKAz
         7XPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=bTFDKHrOr0tLXLfJr207JWB+wcjynanq3pgWKIqA4K4=;
        b=XF8e/cB1GiQdH7/DbCrluLu2B9ov6d0HS3TgQzAfFkzSlwWFG+212h68EB3ujXMuoV
         FUFQRMPLePnPEaiBPXzxlkI1iI3yLKbq0dZxzFllPdIc1ys8YfVAE+KwLI/nuEP8zrpb
         ldzzlgd4DLOTTaq/mL+cRgYMgtBCmV4ehsk79/9yLwdajtWCLeti3A8if1KHLRYU6PZx
         0A3Wu96svX1kM7unaJtoR1yTv87ggcfszv3ED4oZComUxgNGFVnVD0YvIo1gXZGAzmwt
         FfNKUH22GNMIv3UGCgQsbD4Tncmi21DmaZBJuKTLAbqPQnpjuAPfiBgJpudgoKvYJu0d
         39jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uKRgypIp;
       spf=pass (google.com: domain of 3n9mjxwukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n9MjXwUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j83si910863wmj.0.2020.07.31.01.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n9mjxwukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w7so6537040wre.11
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:35 -0700 (PDT)
X-Received: by 2002:a1c:6604:: with SMTP id a4mr2728713wmc.81.1596183455023;
 Fri, 31 Jul 2020 01:17:35 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:18 +0200
Message-Id: <20200731081723.2181297-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 0/5] kcsan: Cleanups, readability, and cosmetic improvements
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uKRgypIp;       spf=pass
 (google.com: domain of 3n9mjxwukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n9MjXwUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Cleanups, readability, and cosmetic improvements for KCSAN.

Marco Elver (5):
  kcsan: Simplify debugfs counter to name mapping
  kcsan: Simplify constant string handling
  kcsan: Remove debugfs test command
  kcsan: Show message if enabled early
  kcsan: Use pr_fmt for consistency

 kernel/kcsan/core.c     |   8 ++-
 kernel/kcsan/debugfs.c  | 111 ++++++++--------------------------------
 kernel/kcsan/report.c   |   4 +-
 kernel/kcsan/selftest.c |   8 +--
 4 files changed, 33 insertions(+), 98 deletions(-)

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-1-elver%40google.com.
