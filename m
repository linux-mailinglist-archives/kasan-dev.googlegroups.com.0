Return-Path: <kasan-dev+bncBAABBHFR5KIQMGQEMTX2U3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 726B54E4BAB
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 04:48:45 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id y140-20020a376492000000b0067b14129a63sf210739qkb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Mar 2022 20:48:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648007324; cv=pass;
        d=google.com; s=arc-20160816;
        b=LIXHPik7HDTo3lxZ695tuGbSgoj9xblen4Nav8zTIYyC+joRoERXWVTvlVgsfJxtKj
         f7Se3APLsjPc/qh9XDX8lw/aYJubFPOqMfZ7HR4ZvF3WsscflpNkJZj2mcJjwflHtzBV
         ygTQJQgVW3FF91MGiLylpDco/ARKCWEp4aQdjJd7X0JwiwqIRloOnm5Z/Pp8GKf59xij
         zP9dTeJBYAVSytsH5801Ujr+Atlql0pCOHgiHv/yuE4X3/P2Pwxt7QuOR0AWyl6lhg2X
         xgYXDQmT+/F2RYw3jSLmdcB6mTlTzsA25qI6kRI2lvXdth+pUwMi0Lhp044+8R7EkcBe
         GEHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:subject:cc:to
         :from:message-id:sender:dkim-signature;
        bh=Qn4TYVNjylXjRTG0tMTze8z2oSmjaFH3bx+v63ERaAo=;
        b=awZu6HXxBCiUEdlNuc7La0M3NLYmBKPAybFYgyFg4PhpqOhjZbodGaECKXU24tUGt/
         5I0tqflMoZpgztr8tqs6TEKIiPWX23Thi9M9vHChiGeOpFNNoEYZ/td/JORb/3Q9ZDxY
         6OK2iqjci13FSNvTrroO5trw1uCNjhjunHO6PotOOiX5nhfi/nPxEiZLdnwc/1oYvMYN
         1WszJM5JvImsfFeeIKBmSZ3aMcZTL/IKDZuET0fUval/4kjCzLItN0yIyVMA3JloaH2a
         cK5XPRdbJhXir9T2PMmNLob5hlVvlKXwQc82XFovlbkbK+79aZ1FnQ9zRhbF07Xvtlq3
         /UOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=Mmc+oGhq;
       spf=pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.221.202 as permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:from:to:cc:subject:date:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qn4TYVNjylXjRTG0tMTze8z2oSmjaFH3bx+v63ERaAo=;
        b=mTni8IAe78asdStfbhp7qmvsgwzEZUr5BWYuNmCYsNTYre3IVfLihb3P/MqmQs2tNZ
         uH8L7W/7OM0nMG6KDMdeqCvzgQnhvr3awLVqXaz67QVZTG8LhAdurKCuk6PE1GEwNZeu
         SmviTxgK6jH6MIzWirLICMeLpdMHGCF9RY7eooae6f31uwaxkIyHwGwgxTCCdDE3ZHxK
         Du+xkdz/ugmZnY7IzTMZpX3C6JPTLDd8+ZDH6T2HIyNfA2FhJ1L9vkqgJCY5e5Nbiimf
         y170YoFpyviRFsmKgEunFPZbI284f8AQx07+XGYV8MfmKq+hXpenFkujWVSFQXf8ZL16
         /c8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:from:to:cc:subject:date
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qn4TYVNjylXjRTG0tMTze8z2oSmjaFH3bx+v63ERaAo=;
        b=PaXRUEUe1RQ0kKwCx18nRkrL/KsZHgeL/TGlnsBodm7OXEdHMl0eEOe8pYkyYlqdMj
         eni68jM29Q6Sv6u2wGyKlxF0WNbKG8fWNSEfDVl7fd+sDxkBzq0xORGDcIYNTayEg1SC
         04gvSJHCkLPuwhTcGs5aHDvFqYdJKxvSbK2shyIMjv3v0Ea8q2oOJiC5gr+82evVFn+S
         PLBm3J9ra8JHXOuwTnqFFM2NIoI9/Rln/Y44BJGVLC2nEN28b9u9zPE2OhcvJtq7MGYM
         3pD7qGhPHoEAWTPm+InsmsWdzsfu5JRcYR0plEenzCG3LxWT5FaxQoERhmr4SCxsMQID
         qEqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NGV4l8NBV+C6a2wVd7qD0Jk0JVz//CY9iDmsZLnteMQUvcKBb
	iaxI+okkn/5mOETPXKN1MyM=
X-Google-Smtp-Source: ABdhPJwNaGh/T7sGQzxQYTXJL+oIlb+mpyczDgcWfFEwCQGAuTEBsJjREoGSN7ySO0jnpZNvTIVuZw==
X-Received: by 2002:ac8:5bca:0:b0:2e1:b94b:4ebf with SMTP id b10-20020ac85bca000000b002e1b94b4ebfmr22362134qtb.71.1648007324336;
        Tue, 22 Mar 2022 20:48:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a1c:b0:2e1:b5a5:aef2 with SMTP id
 f28-20020a05622a1a1c00b002e1b5a5aef2ls10981475qtb.8.gmail; Tue, 22 Mar 2022
 20:48:43 -0700 (PDT)
X-Received: by 2002:a05:622a:1753:b0:2e1:ca6b:b7b1 with SMTP id l19-20020a05622a175300b002e1ca6bb7b1mr22868617qtk.82.1648007323899;
        Tue, 22 Mar 2022 20:48:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648007323; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJKhDxmAsysaMbbYw+Pf2JqoSL7VpM3gC45VYcFlaNTnMySsQRIXQAGozwmG/Hq9G3
         cw7qDJK0+VxiVW/0N4jAOPMWJqzHfPFLbSHwglxBR8GiHZ+KPq+cjkIyCNZfd2DcQU/0
         IlrER6alUyyebjcsAslyA1NdsIm2eVrbTG0OMDXpmNFsPrySeviaBmemsi11vdOM7WIz
         VQb/EyffgvV02CWa1FJbFrvEMAd+nytP/pJ0/MJPzWExXzyWHjP/HYUXgvxk5L4bVF2b
         5HFJpTmSdXE9NXNWRnMl2AbKWJlh8Yyd0rsBjXp/ppmO/rrK7Wbvi7tiUKHruT+UXFaH
         PwEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:subject:cc:to:from
         :message-id:dkim-signature;
        bh=aPCfa2VR27sIrzeHgV7GyBgO3tUA+0rcNecygkJYcgQ=;
        b=gFP53MTeBTr62N+OCdkDSUpI7uhHLgolb3+nYB9qyoKMnLEUvOX2rl21O6wsEC++l9
         Wt21R1ehYbbbvJXCiYVFSOIVb7X9t7dO1is74MOGgRQtQcRl5th7z4RoNoZz1QBPB2kc
         lWUZ3Z43BHtOc376VapZ/Ze5a3fHlzxfHssvN98OepXpixBqJvyuda6y8xSPjrOudVcM
         5x/WuwxCp+23e7uruFzFoRAcWo8r3jqka241TdT45S+GdpakpHd4U0hYZTlhAWTDR6Ub
         RYoorr+zT75+CmSCvyjhMxI17jzXz6pEeE7YdwhZ91QZgdsyPU1sP9vWGsEwtAf7STM4
         J6Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=Mmc+oGhq;
       spf=pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.221.202 as permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
Received: from out203-205-221-202.mail.qq.com (out203-205-221-202.mail.qq.com. [203.205.221.202])
        by gmr-mx.google.com with ESMTPS id p20-20020ac84094000000b002e1e5e87168si1228220qtl.1.2022.03.22.20.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Mar 2022 20:48:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.221.202 as permitted sender) client-ip=203.205.221.202;
Received: from localhost.localdomain ([43.227.136.188])
	by newxmesmtplogicsvrszc8.qq.com (NewEsmtp) with SMTP
	id C242AE0C; Wed, 23 Mar 2022 11:48:36 +0800
X-QQ-mid: xmsmtpt1648007316th29usvoz
Message-ID: <tencent_7CB95F1C3914BCE1CA4A61FF7C20E7CCB108@qq.com>
X-QQ-XMAILINFO: NQR8mRxMnur93WeYZSV4oqu8CMBJfbeHrGR5Ufzg0ImwLGgFHkCDtc9aEgz4Yq
	 NGeDZYXHFyzLjBKNk/RIiHuLbFczN4z8nCi1+byjjaEsg0lGS7ubJznSqXmEBc7eSfkIgmer3RI1
	 ZdorD4YNjQYzly7jxbkJnu5e4FlNVXQDl9z02dsS4RlkizNLOPKW9Gbn5NSvb8fJA0V9O1JiovYY
	 t2g2wgMCC9ZKAM2rWSMFUuroGE0pjtCSLoAR88Q6TDijBdHTUV6dwH5oOTuv1xWKS+aHd/KwjhdX
	 Z0bWhHL73BjBUgAsZ93CSUbV4KOKXkYz0vA0VZQQJQcNCfqiEzdWUPygEbWBXWFy5t8ms7MEe3Ah
	 V820Atney3HBHBPtsR0yTU0O+Ix5daei5nxB5rCDKImY6oI9G8Xjh0valst5TUXEsVR4GmP0va4n
	 QGXiexvDOA6V7nfF7peIFql3JNHE8chLIZKOaqEX2W9LpIFbjun+OkgT2UZn5ydo1yqNwm9IKWxX
	 syDDdfgvv7GM3PA0ggcle5ngFDKXPgE4xTvKG5hEtLFa2qsEklAT1oCNsp9pbbiPW6flTvO6xbb8
	 SJXOhqSuEyEywpdMQW9XwBK9ERlekOnrDhJpl1l1C1VX82dlzVa64SAfkB6YB9jZy+bkevD2O7vo
	 8IRDGwkqCmUwzsmVrhnH3djC7aiRun08g9oLfQykm9x7+1X0FFJf8CPlx/hAwUsA1p0Oek2mmug6
	 X5+nkMBLHCdW12YByAhJMecE2c7vs++PZBw0peFXuzdTd06QnRiTg+XUwMcqKmVP/0BvcbcYFVeF
	 z7mkSntim5zCXfwKvf60Q1z89Z1iZvfw9VHXh86Mr/dSxh1dbxFWFNUcenrpMEqgm45QVHUa1OYx
	 gIcynbaOD1jWv4FL5/INMC90Kx0Z55Sst24Q8Dj3oQt7NdGAvDt/UacLLQSUyrOsKtIRTcuBAX8R
	 n6pGNs4A3VLVapGaICeKn/fkSstcoOzrGWa6O7KromO4VGsyYdIEMiKKmbbNc1
From: xkernel.wang@foxmail.com
To: glider@google.com,
	akpm@linux-foundation.org
Cc: andreyknvl@gmail.com,
	elver@google.com,
	dvyukov@google.com,
	ryabinin.a.a@gmail.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Xiaoke Wang <xkernel.wang@foxmail.com>
Subject: [PATCH] lib/test_meminit: optimize do_kmem_cache_rcu_persistent() test
Date: Wed, 23 Mar 2022 11:48:24 +0800
X-OQ-MSGID: <20220323034824.2026-1-xkernel.wang@foxmail.com>
MIME-Version: 1.0
X-Original-Sender: xkernel.wang@foxmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foxmail.com header.s=s201512 header.b=Mmc+oGhq;       spf=pass
 (google.com: domain of xkernel.wang@foxmail.com designates 203.205.221.202 as
 permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
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

From: Xiaoke Wang <xkernel.wang@foxmail.com>

To make the test more robust, there are the following changes:
1. add a check for the return value of kmem_cache_alloc().
2. properly release the object `buf` on several error paths.
3. release the objects of `used_objects` if we never hit `saved_ptr`.
4. destroy the created cache by default.

Signed-off-by: Xiaoke Wang <xkernel.wang@foxmail.com>
---
 lib/test_meminit.c | 12 ++++++++++--
 1 file changed, 10 insertions(+), 2 deletions(-)

diff --git a/lib/test_meminit.c b/lib/test_meminit.c
index 2f4c4bc..8d77c3f 100644
--- a/lib/test_meminit.c
+++ b/lib/test_meminit.c
@@ -300,13 +300,18 @@ static int __init do_kmem_cache_rcu_persistent(int size, int *total_failures)
 	c = kmem_cache_create("test_cache", size, size, SLAB_TYPESAFE_BY_RCU,
 			      NULL);
 	buf = kmem_cache_alloc(c, GFP_KERNEL);
+	if (!buf)
+		goto out;
 	saved_ptr = buf;
 	fill_with_garbage(buf, size);
 	buf_contents = kmalloc(size, GFP_KERNEL);
-	if (!buf_contents)
+	if (!buf_contents) {
+		kmem_cache_free(c, buf);
 		goto out;
+	}
 	used_objects = kmalloc_array(maxiter, sizeof(void *), GFP_KERNEL);
 	if (!used_objects) {
+		kmem_cache_free(c, buf);
 		kfree(buf_contents);
 		goto out;
 	}
@@ -327,11 +332,14 @@ static int __init do_kmem_cache_rcu_persistent(int size, int *total_failures)
 		}
 	}
 
+	for (iter = 0; iter < maxiter; iter++)
+		kmem_cache_free(c, used_objects[iter]);
+
 free_out:
-	kmem_cache_destroy(c);
 	kfree(buf_contents);
 	kfree(used_objects);
 out:
+	kmem_cache_destroy(c);
 	*total_failures += fail;
 	return 1;
 }
-- 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/tencent_7CB95F1C3914BCE1CA4A61FF7C20E7CCB108%40qq.com.
