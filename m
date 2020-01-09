Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2VC3PYAKGQEFFQ6DTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7013C135380
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 08:08:28 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id t17sf2984504plr.13
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 23:08:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578553706; cv=pass;
        d=google.com; s=arc-20160816;
        b=COUr6TcLlUedLcSNyR3rC37MnlnLdKh0+0vj9/BIEmW/CB2M9PFRquGp6rD7i5zigI
         H8Fi30eEEiIOxHaEyOzmy6j9vSMo6gXyk6mOdg1H9hqtxWnTZkCTwrqewFavf9isA/JH
         VGiqmQ483JFPowC8aPPeP47ePJJT3FyIzf5+PrNKIGne6gsFJtoQZy8zQRMYywMPibsK
         yMtUiv2NrQ/DC9K5ahOr9rIZdWTyTnXUFacxsAjEeaVw1aX/iFc0S6L9PYaG39wPThG4
         LxYQ2FKcDn3wcYbeEh6fioLGhYzRTOePfQFjLvNoxGeQPU9a4IQHukzb962pMJKcocTX
         RmCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rdLjv8V3ZbfP8ASpzLHF341XBdVyJcuGbGqWsAipJDA=;
        b=HGEQM6ZhEjqMcqG4fY8VhWEtiu1cZM7Hu02DguL1vIn71yX9AYEuXAFtVHBDdkDO2L
         TY5LVZdlhGqGC6bJH56XI4FjJWMQg4iczt5tR0JMDT2IeFOgZFaWSySL8/u+ulcANafF
         m77zlLDUxtgYEZC3yS9yI9wBWvY49KcoIpWs2gn6Eu2l7uSyTEe60Aq8fvtRhqxHwo6K
         eMtjS3V9KQbEZwbavugrNWNrhkhd/qtV1JE/Yns/X/fQAQZk/EHHNdEuc8YWOSQb5j+c
         +ffmBsDAW1gyg068Tcfj+eAn+LX6kt87nd/anxIcxJ9kVmsRSH0hbGAnpQQlp74upzVp
         OtCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pDcMswX2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rdLjv8V3ZbfP8ASpzLHF341XBdVyJcuGbGqWsAipJDA=;
        b=n0fyN32NJPwm6P0oIAtXq6KCKMpDhJZ/xDWqm8dhN3T7GNWDDQWUq/tZJ1oCW+vFfJ
         YnzBN3fgMRRU40lkZou1v88pXpm6DyJC4eGWHr4SePSytWWLV+o8INxb8Aagq4obxBFw
         ejZ///NSxHIK9hoiJDmnCdm4ZgYUejHN8skwed1Dh3Y2yh3PDgrjCD02x7Blyq7L25Xl
         JOW95l+0vtlxDNwRBaBvVLU7uNLMMwyRYjhhz+EAD7zAQGHBrardFqJI1faHPmNwGj/w
         7COxqG20kk4Nq8MrZ3xbhv3TbXRviGjTVtPbbCL3FG/D/mUseLkvVEmsoTjBZefw72d8
         Akrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rdLjv8V3ZbfP8ASpzLHF341XBdVyJcuGbGqWsAipJDA=;
        b=SsJVdHUcl+z6+Uu4bGnEwbQ7ikwaWkGMwmRY/Pig4X553Ymb+ExF0x6zH6p710tD9z
         +nz1KvdLawmCuPA025N1RS31VpHLlVO4XvRVBTTlWeTGzv8jw3IlfKU3vwPsdr7pBm/R
         ciswRjTXY2WYYfAXRFCDqqOVlEeWGdB6wOZdVopIfFHnwoqJ2MGIOMqjzJ3i4pz7LNL0
         48IKRAopyKBDTy9yjDrSXF5WhG4BFZt1ttWptNQ/DtTP2Rhw/UpBUgF/UEphLyWpnINX
         MB4Gp4Uyhf8mFRza9Btos/l1YhXPEn49pTHT7sv31kjFkKcmYUe4KayY4wNikCQ+AFn7
         H3Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWIXBkJFmyyEmXW0h8gOKzUOJqoFjuqh83mHIZCz7SsL+1xZYJA
	XeHtZOckK8sd/mlcV9KkJzs=
X-Google-Smtp-Source: APXvYqw6E7ghjgBiAgbHOrWDNy0a8Xx6ouDMNdm/R4TpQGD2nKM+Vifgd175NuR6hjKBw3XT7qQtBQ==
X-Received: by 2002:a62:888e:: with SMTP id l136mr9885835pfd.80.1578553706484;
        Wed, 08 Jan 2020 23:08:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad06:: with SMTP id r6ls376293pjq.3.canary-gmail;
 Wed, 08 Jan 2020 23:08:26 -0800 (PST)
X-Received: by 2002:a17:90a:3487:: with SMTP id p7mr3656596pjb.115.1578553706137;
        Wed, 08 Jan 2020 23:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578553706; cv=none;
        d=google.com; s=arc-20160816;
        b=taAVzgMWPNJZP9UfW0U6IofZfTfsbn0G/ec01705j8W/XvSwxr73YvcF4aqwbuy9ZO
         igO98SqxsWsGtwY7tMOLYEqBU1iJDKvZovDAS8c/nYBdlf0AZDDKQzYgVcsPdWQigkxF
         k+hg6NBh9SbvEArJmwrSBT5UfQ0L9GD9Yu9/ZgtSOdkQtdCbrhlGGIuCZvO63lO6ZfiV
         /COT7NWFqmuTMBsQoYiN8tcGHqXIsrPU5itmWheg4coSRz4d2kHKBk0B/CYX0wWPkxaU
         HrQIZJQJjlyQQy9ZaTETffdQmwYxMwUyOfiMHut+TyUORhWnjf4tUlWLzgWgSQVuLgA9
         6c4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2sxbAlXpABK/W64yfjeUTt7MDV8jfwT8E3maFR+CaL8=;
        b=LblMsc85wlashkKsav8kpX8XT6mWoZ9NcdqRR4TDACOpbQQz+0cYfUTQ1rezeKv9IC
         C8oRCc4eo/78G9Gk1cJNoxTRo7cDXUrHDaRX9cgAa06gtnZtP/IYcK/OkwPjF3BOMRYs
         cGy/zq3otsICErgp03EFihetAPf0/nehakXBQVkRcHi+pdAEVSUsnlaaKo+QnKRNbLs3
         3CbMEcMA/IP1Gu28/TpafxT341L3HfZ6dwwEmoDCbGUgVxuj3CV9nDHMU9/9fFrTClTM
         F/QvNMjuH6Ob7aYK95cVHTs8OnpUPHFcHMT4/1E/EC0ggYYzCU325LEjTZy09MQi1cwp
         cWDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pDcMswX2;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id h19si262196pfn.1.2020.01.08.23.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2020 23:08:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id m13so750034pjb.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2020 23:08:26 -0800 (PST)
X-Received: by 2002:a17:902:788d:: with SMTP id q13mr9716939pll.210.1578553705849;
        Wed, 08 Jan 2020 23:08:25 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-5cb3-ebc3-7dc6-a17b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:5cb3:ebc3:7dc6:a17b])
        by smtp.gmail.com with ESMTPSA id 3sm6228356pfi.13.2020.01.08.23.08.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2020 23:08:25 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v5 2/4] kasan: Document support on 32-bit powerpc
Date: Thu,  9 Jan 2020 18:08:09 +1100
Message-Id: <20200109070811.31169-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200109070811.31169-1-dja@axtens.net>
References: <20200109070811.31169-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=pDcMswX2;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  3 ++-
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 14 insertions(+), 1 deletion(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e4d66e7c50de..4af2b5d2c9b4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+architectures. It is also supported on 32-bit powerpc kernels. Tag-based KASAN
+is supported only on arm64.
 
 Usage
 -----
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..a85ce2ff8244
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is not currently supported, but modules
+are.
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109070811.31169-3-dja%40axtens.net.
