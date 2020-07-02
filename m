Return-Path: <kasan-dev+bncBDQ27FVWWUFRB6MY6X3QKGQEP272HKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 766DA211A54
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 04:54:50 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id w13sf3980154ooh.20
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 19:54:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593658489; cv=pass;
        d=google.com; s=arc-20160816;
        b=nZ8ua4foAgZqvTaMeKUYQ2UTUjX2I1jEMSMhgpj7YuRwRSzNUyfMQsN643mltZAXeH
         e5P3OWnOr0ypfeezhU8xkuDFPwECjnwWEbJVNXnsPoY7viIPry3fXcryHLWDipu63C4a
         cIi54jwqzZQeTICOTRi5i5hM1xNdVPkPKsPq4wMQQFUmUOMGUhRSAV5OwXoC9Offytb5
         oN9tttVGdauzRJZJCaTiIRy4vX8ZvLCYcqceDMMPQDjIBZfWsI8u/GZ/+HDyDMKFRQM6
         rGTVA8QP8ICTCioYQ9oQ6cMPJfV+Vk7XlThMRPbYO5PI5PETLxaSz09xikF+BLckN6c7
         HbWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5OHQn1m0A1RxNq+QpC/WKQ3+49OeLdtocmB3vMV3yx8=;
        b=h85tK84VUb3nWU+CdoYohnxowNek3N8XsjpxvraG9+aNjr+KAEfs4zkhUT8pEy0osA
         KyYXMT8PEIl68Bq2vdUiI7XPJtevHb+i2pMFEQw0oWfTBJIVi0Tl+sERdedcO6Taiu2g
         ZbasnFHIDez3LOFyZsGBALdGdqeNa8g3QhfPf02otepfLoEzvxbZDc4GHagjfqhh+HrK
         x8WXPG79jRcb8FdyEkn++x4hOslLRyEAFavPZvTyAH8KrLWOGOfBxxMzO7bspu0/628E
         O5cnvhy5Y7oUzoS1V7aw7Ggrv2Eks6RGx7E7mOCCIa0iccgzLn4UaAebJE0vnVQfelmG
         aM5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cPFe1UFu;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5OHQn1m0A1RxNq+QpC/WKQ3+49OeLdtocmB3vMV3yx8=;
        b=PnliuRoasjD81S/s4JDwi723U9gvJwmJvjOulqMrJBIUVA3khVEItVpCD5Zjr006ln
         zg9JoVobutC1EyoIfO9zPFGbX/Vv5TwIUlaltohq4nqHHGUpC5a+oGHum9aoTv3j0sEK
         ZPUIABYDlMWi7zdk+7TTLE27id0JWwg0V0roxlj3bJMSwcnLLYQ5YJGrb8Ha0rJYnF29
         O4kW688hYb44fcqhZSYgTqi3A7EUDAaSIFknCox2dXWyAw8cYeg6ME2gz9xnfcrJQert
         p9A8HkQ3Ub6Tp/yNLcgA9AjIeglMGB0Lbw+ACGpblaHni0wE76DXHS8K4bQx4K8wn0gG
         LSvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5OHQn1m0A1RxNq+QpC/WKQ3+49OeLdtocmB3vMV3yx8=;
        b=frvuV98BW9IoPDfF8/y2Tn+XXJewrCUSmQ6ckT+pKLnTwk2Qy8Rkb+aveaslMlyIAe
         8Q8aPC6Ymhube0U3y9H1LQ9tl1UAKGOgGfu3sORiSfWys/imNnjavdhMr3IWVFlg7b/L
         ndzrzub/juuQ7Y3Agd7hqutTPTIXLnJpVKiuqJW2/PeQin7QeH6VksKgz3VQ+xsO4/vs
         Tt7q5C6KUhBNS0Nk08gQxSd1o3Qxs5l0+cdwBGHWnH6g2vd8mCDqvlJwCL2GTBSyKt7l
         8Hkg/1r7YYcpPmApwKO7sn+YWtN4BDIrPbqBp0UTsg0Oe6C+7VqGkgdHS6nNkpPgR9PX
         QLig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IlS8XTJQvH5Ns8ZvUniHJvhhq4WY3fQN0Ju2Bostw4md6n9f7
	xEZdp0tqU4RuVbU72A4DqH8=
X-Google-Smtp-Source: ABdhPJw/d4CR4Xl5X9ZbZklMyqgfRMuXVvrGnOaKsoghY6WxrvhRvAkezUO1NpXsRyjbF4THO3tu5Q==
X-Received: by 2002:a9d:6a11:: with SMTP id g17mr17522325otn.50.1593658489479;
        Wed, 01 Jul 2020 19:54:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5016:: with SMTP id e22ls810828oib.2.gmail; Wed, 01 Jul
 2020 19:54:49 -0700 (PDT)
X-Received: by 2002:aca:5007:: with SMTP id e7mr15052011oib.70.1593658489149;
        Wed, 01 Jul 2020 19:54:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593658489; cv=none;
        d=google.com; s=arc-20160816;
        b=rhk5xIqHwz1OiI9sFlGtc54jjK1rv4Li7lXgGvaKwA1I3xkptbL13wfN+y3YGt3B3s
         9sTbQrEQQLLcsmdrnvpw8vz0Uy9OjEI13sSEaNi1fpEANdX3tY8Yn43YVyFTxePJ3tXL
         OnDG2axyQARv0NcI3coRgHb8pP9CWHEUKFXT6wEIY21EKAhgK6MciqE1Tsaqy1TnSkaZ
         Vyg787EEZJgL1g0JTYelnzGmbP20vwU4WxvmWmRV9IyQhQwimEc0I5SmH9Nk2MzEW8sO
         lBg2yzvDDsY/WG34aEiaN28bZxVWPxwstMFkhLmFzoLonCVjoc1KmQR0vreMG8vlrRe6
         V8iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s2vaNiCstBIb+WWFV0QIyynMgzg46gv0imUofC6H27w=;
        b=CSL4cLQWaLxMitX5h6CGFzBqd0KHAAdg4mcJmNCOAn2+FARzwvjDFKlU79PqagsrDJ
         nh96jpt7sQP6JyNFTKvZVjOjwi4ycY5IQPsqCAZf1ehDRMqoE/bhr3nyXK31axYM3NgU
         kJLnI8UPfkOyjJw69y93n7e2qvWxKTwWYo1pkMrO8eAk0MRXBFWUclwAcDM8GLyRVNwY
         /nIB5XrDQ3G5KJzsnfASy1qygyLDoOBiHb/2LWUz1B9imcrTlhLOAVeO7bZHvSzxgcc+
         8R2KskqxjM4sYk+L4plAFsRwyO96PToe7NhrYBeIiqc369dRAqcA8fpAO7CMkIyuCO5Y
         u2CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cPFe1UFu;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id y16si274260oot.2.2020.07.01.19.54.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jul 2020 19:54:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id w2so11926513pgg.10
        for <kasan-dev@googlegroups.com>; Wed, 01 Jul 2020 19:54:49 -0700 (PDT)
X-Received: by 2002:a63:8f58:: with SMTP id r24mr21924594pgn.379.1593658488570;
        Wed, 01 Jul 2020 19:54:48 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-3c80-6152-10ca-83bc.static.ipv6.internode.on.net. [2001:44b8:1113:6700:3c80:6152:10ca:83bc])
        by smtp.gmail.com with ESMTPSA id c19sm6198267pjs.11.2020.07.01.19.54.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jul 2020 19:54:48 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 3/4] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Thu,  2 Jul 2020 12:54:31 +1000
Message-Id: <20200702025432.16912-4-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200702025432.16912-1-dja@axtens.net>
References: <20200702025432.16912-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=cPFe1UFu;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
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

kasan is already implied by the directory name, we don't need to
repeat it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index bb1a5408b86b..42fb628a44fd 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,6 +2,6 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
 obj-$(CONFIG_PPC_8xx)		+= 8xx.o
 obj-$(CONFIG_PPC_BOOK3S_32)	+= book3s_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200702025432.16912-4-dja%40axtens.net.
