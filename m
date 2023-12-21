Return-Path: <kasan-dev+bncBD4NDKWHQYDRBZXKSGWAMGQESFS3B3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 109F981BD2F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 18:27:04 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40d307e1d4csf1029855e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 09:27:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703179623; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sx9kIz7DszVZTRsILRdnYMUhtrvw+9UD01KFKmqNhXT6gjyrz8U7pVFW1eBDgNGJQQ
         jCnQj88Sb8RkrN+WsD39zt0Fr+HscmOD2dULOetEESUt+Vzh0yshMq1GsZ7H7O+4nqLW
         6GVZA4G5O3NcinIuzxzbDECD1t/GGoi51FVJXAX4MipehWK53PmPw3E594EUw32iXOae
         PiFZHLHwDL4jDWi5orvQMSgSBt/2aBIopAt+RbaOxbmDk4dTNf1yverbKTErDVK5OzPF
         2fs+Cj23YmEcOzTZxHH//YF0tfe4acsKtC6xLW7pHZSESaXadwLX5gbqcs2vmsqzxC1u
         2C3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=7VxVAkFvuCy2Lw2da+qDQ98sJVc8eSwNZXpH3lXVlLc=;
        fh=3JmZD+y0QcUwBNAQapTg4JqVNWDxKIHOr2qfdV9IH30=;
        b=HN8cjXO9BCnwg4MkMZw0ew3vAFc2OYh6Odf3xlLwunrvA53tS4h1WYYfPiBS6JiVk9
         qglzE4JvUU8QnP4lcBDlxQuRG4HIwg/HcG/9ncuVaKpD9gB3+VFk80zV8CGAwAiv+i6v
         5XbGlaYmy6ya+YKBYrGgy2LNsLilKXWuN8qMAVCAndQH+i1D24jIatXBsR4kd/o555UU
         gaqKqCzYHkJjNyMm46fJTiE9H6gLMDEMJNzEFt8Ojb21CvhOtz1ZSbUsGVjlCklUVPjC
         xYOekAOHoJRN+hB3KVkLOczvJUp6c889G15wYKCkY2Acc68AN7MIQxM6cK5tF+mQ3+FC
         Rhzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vgr1nOMV;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703179623; x=1703784423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7VxVAkFvuCy2Lw2da+qDQ98sJVc8eSwNZXpH3lXVlLc=;
        b=I3AfZJsaQ4cxaH86UFNHDIP7NEvtv0XqWkjNgrsednzlDJ3mJ6bJpQhNnwC/fOha0E
         JxxKOxBXHcWm/cChLwF4qH0Lg3SUhEetFWN9R9KpeqrT65SRoX+3uZuqG/uW3OcrC0ld
         lo/TJSg8bfLO8hrubEZbEDkaO89L61ZCN1QdVn9Xo99nHxbyCnQ/Q6ORG4hHhm17F1D6
         hz3m7pkAdW3Qo2K66mDhRHlYrxNduy/0+Rk3WjwjpOJQxpBAojQ9R7yHz1EA97zD3wI6
         AwDOXLF07pYfB19oGAR5u+aSLXLj+ce4VxhKWm3zdyRp2wi5J3iW+oR9VKiBcX0o5oHE
         FtTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703179623; x=1703784423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7VxVAkFvuCy2Lw2da+qDQ98sJVc8eSwNZXpH3lXVlLc=;
        b=hzfpEQjDOg/dIsVpZM+7TgFPsibBdArlPpyosn88wL/pt8tNDTStizhIaa4F69eMsj
         7/G/c5BDGAQ2/HpAB3tlGO62Pbwby8fs2Q4dkEMBL+S46n6avGvb3Am3sZI5zR99Kfe+
         isstlFtTRi/Cgf1ngaGQZqQOXqrz2LINhuZUySH72s7DmSGP4X4NsP3UeXTHd/pyE/qB
         G2nF/84gP2z/Zg24wkeuXr4qT/Wk9q4srJbcOt3MGA189EYpK2HlsaYTZEqevD9GPZB9
         NC/gRJSq2PmK4fzE0i89Z/Si7CmTjPP2AxED/Tjr4Ua1XSyall3TLkD7UyZzrvA8Y9Ph
         6KZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzfw8/IHn9K7IrnMWc0yM6VUVGVr7e1GPv41xv5UrMqnGiEkRkw
	rWdhE5AExlXVYVysYQESekk=
X-Google-Smtp-Source: AGHT+IGvQuUbxkrkdo2boOnXrqkZ4E+EhBJuhMGZDjDAaFqgs9bEWyPUsX0LuhCzOKCXvBzH5lYyZg==
X-Received: by 2002:a05:600c:1d99:b0:40d:3bec:55a with SMTP id p25-20020a05600c1d9900b0040d3bec055amr114315wms.5.1703179622875;
        Thu, 21 Dec 2023 09:27:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:524c:b0:40b:33a9:fb68 with SMTP id
 fc12-20020a05600c524c00b0040b33a9fb68ls130134wmb.1.-pod-prod-09-eu; Thu, 21
 Dec 2023 09:27:01 -0800 (PST)
X-Received: by 2002:a05:600c:1e88:b0:40b:442a:f589 with SMTP id be8-20020a05600c1e8800b0040b442af589mr37450wmb.18.1703179621016;
        Thu, 21 Dec 2023 09:27:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703179621; cv=none;
        d=google.com; s=arc-20160816;
        b=iK1wOcj2qmpMsZvYpqSnXU8LtlxxTFJHdU291+KD7ff+k1vx4LPGyd929sEWAQwQLx
         KazdltlsMw9lokWDbmpNi7Jrnv9hmPr7uaXgV2LoYI/3qnscYYel37aqKIICmYDTnUF3
         jUwTeByNHV8fB//vtxeVKmS36Nzwf/UDTO5EGssyTMyuImXwl+gwtBW9xwIZbrFKyHEo
         hVqu3QFp7xiIWX8tSLs8a6ZFcSO9l0dbIItI+h6R2gjtFvRX+nGog3UcyUOm237x1zjJ
         dERF9zxDaWtIRagMWeh9qld5a5U6S8yzJMOvRnugXJPSMQ8r6li8ZDvc5qX29XXCn/wC
         xorQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=PV3quVy0tEze3ufNVKy6BNRxqcnzU9AraZuJ7Ir+LBc=;
        fh=3JmZD+y0QcUwBNAQapTg4JqVNWDxKIHOr2qfdV9IH30=;
        b=WkHhHV8NDPfxHrtv3KU66lBtzHUMGJ98cxHwMCjhUW3yXSf/B2+Eb/TAQ7kfvBlU13
         w2QQj6V69Uqcu4PqIWiC71QiZ7FtjB7ioWw2igPYk6x09THrfrYlslk4bNeS4ZYo5vst
         PGojqXThFVgIQPLz8M5WnKFbAMzsufbfhoFX+ECis9ZGs7CatJ4+ob/bWMIQqG0retrO
         83h6xeTltLQOXwNrEWkFStQby2KDJ1nwypftne9pzsSKhX7cjMWKMSjuCXHRPIcK5lZl
         L83XuI1Ban7GCfhGCDSo74VCAqn1bMA2tEqOZhesGxKnd5SZp/WE1ZfNuUZMzukh9Tz5
         rjQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vgr1nOMV;
       spf=pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id j24-20020a05600c1c1800b0040d3d072c75si63356wms.0.2023.12.21.09.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 09:27:00 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 97BB4B8216C;
	Thu, 21 Dec 2023 17:27:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68D8EC433C7;
	Thu, 21 Dec 2023 17:26:59 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
Date: Thu, 21 Dec 2023 10:26:52 -0700
Subject: [PATCH] kasan: Mark unpoison_slab_object() as static
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231221-mark-unpoison_slab_object-as-static-v1-1-bf24f0982edc@kernel.org>
X-B4-Tracking: v=1; b=H4sIAFt1hGUC/x3N3QrCMAxA4VcZuTawZsrAVxEZaU23+NOOpoow9
 u4WL7+bczYwKSoG526DIh81zanBHToIC6dZUG/NQD0Njsjhi8sD32nNajlN9mQ/ZX+XUJENrXL
 VgIOPREdxJxojtNJaJOr3f7lc9/0HtDZ9DXUAAAA=
To: akpm@linux-foundation.org, andreyknvl@gmail.com, ryabinin.a.a@gmail.com
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, patches@lists.linux.dev, 
 Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.13-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=1506; i=nathan@kernel.org;
 h=from:subject:message-id; bh=j7IMo3IslfxSy6UdippjFzjMlbpaPfIPQIQ0OgZlg1w=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDKktpcmvE2Ulrdl2PGyrXvBlhcbuZ6K5C74t2VYu42ZRF
 TtHcbNmRykLgxgXg6yYIkv1Y9XjhoZzzjLeODUJZg4rE8gQBi5OAZjIrTOMDA+btzpWWs18o6Ju
 tDyp86WrKqNz1+FXL1oi7N5Kp27yuc7wv2TPynymQ72Lr/y08BNzFc4M8jn0RXyrw4Vyzu0vXO2
 O8AEA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vgr1nOMV;       spf=pass
 (google.com: domain of nathan@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

With -Wmissing-prototypes enabled, there is a warning that
unpoison_slab_object() has no prototype, breaking the build with
CONFIG_WERROR=y:

  mm/kasan/common.c:271:6: error: no previous prototype for 'unpoison_slab_object' [-Werror=missing-prototypes]
    271 | void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
        |      ^~~~~~~~~~~~~~~~~~~~
  cc1: all warnings being treated as errors

Mark the function as static, as it is not used outside of this
translation unit, clearing up the warning.

Fixes: 3f38c3c5bc40 ("kasan: save alloc stack traces for mempool")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 mm/kasan/common.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ebb1b23d6480..563cda95240b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -277,8 +277,8 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by kasan_poison_pages(). */
 }
 
-void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
-			  bool init)
+static void unpoison_slab_object(struct kmem_cache *cache, void *object,
+				 gfp_t flags, bool init)
 {
 	/*
 	 * Unpoison the whole object. For kmalloc() allocations,

---
base-commit: eacce8189e28717da6f44ee492b7404c636ae0de
change-id: 20231221-mark-unpoison_slab_object-as-static-3bf224e1527f

Best regards,
-- 
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221-mark-unpoison_slab_object-as-static-v1-1-bf24f0982edc%40kernel.org.
