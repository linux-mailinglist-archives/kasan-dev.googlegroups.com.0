Return-Path: <kasan-dev+bncBCG6DVFRXMDRBEGUYCSAMGQE2EUX2MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B39F77351AD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 12:12:35 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1a9cb0db139sf2960154fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 03:12:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687169554; cv=pass;
        d=google.com; s=arc-20160816;
        b=TypdYcwo6i368dMr8/k1xK1jka+qDKzvfLPAxhWeGtEVKAndgy/WE5Fko1tHC85A/T
         1pSa7fNP5S6B/b+XodC5oqLvhAzA9LaXP4ZYfRYBHouI1QQ8dz2KplNME2um2ldVpYcj
         BPYoc3Vik+Rq/e2d8fBxcEizkLpg3h9S4zMDMdYkH56tgTQA24kuSupJuIstmbO2JC8o
         sgcdKzYROISOgwgF3U5S1JAhyZ2bCkQtq3d2D8Tofd9J2u4k6bL2CzfCdPr0y5eNrFpa
         Nh5G27nd/4RayEz3q3z22aLstan4qCOcAgX32v6PlYNYeAGL21Vdw3ac75ThCxgy2it0
         BoKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=3Vrv4/lurtQN1i/7aRx7POPw3DP3T+mZ19ehFJ5+QQo=;
        b=BEgvRtCEHPb9NowA93Gl0WKFx09IpXF83Ojewo2AwdFFHaTkP5VuTpyE7UfAADLk1C
         v3TWL9vdoiDXURxZ0UsutxsKgU1vPHgt5+GaZ+0v/UoKYwd4tbTI9wsCjVE2kccApoKo
         g9l5LsMezcrXw6hxaxIHmX1XADqGOilLHZswZd2abFJhmy3j9HLMoyB7cZUru54Nri4v
         mPxjHceDL1TzU0vjKwh4d1KzcQvZQwJMIxF9M1DXjyQoxaOsUGkjaReri03P+lhlQHzz
         OjmS4oPdZy9gCDm01zVjDeWVuhfoyOQlU4pTG7GBuQOyhkYioAEuDtW9fdiv2+iZbGUH
         0hDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chanho.min@lge.com designates 156.147.23.52 as permitted sender) smtp.mailfrom=chanho.min@lge.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687169554; x=1689761554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3Vrv4/lurtQN1i/7aRx7POPw3DP3T+mZ19ehFJ5+QQo=;
        b=Sq5zggvX9xd86/fA9BX4xzfTezLV34xm9mq6sjzCBFDjAEUM2qxJa2wPAt0I/cRBvb
         kupdDFRzzuPFUfGYoprd7vJRSNeBnajxCJ976YHpRVgK+lY3bVH9cOgRlI2ZTQEhOgND
         NbZphPjlC2ThlVIjj0HaPSyMyUlEVG94eEvTzHrz/nNuD6x/L+WCA0BBN8KK42ed22g1
         42RQ86U2XUdPfHimccRktWJNaj5SqZ4Ax0BBKKmW7iYkIYScRbz7A10RMX+Seai78XvQ
         9ae+OqrpccGieQ3lBeEC5F4thwmUk6B9IqYWaCRy0BkPjYmYuwQSspN8ITYAZBygHQ4N
         h8BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687169554; x=1689761554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id:date
         :subject:cc:to:from:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3Vrv4/lurtQN1i/7aRx7POPw3DP3T+mZ19ehFJ5+QQo=;
        b=FrBNt0FdcZToGQFV/CwuROuAp2D2v8hhz+y9pwAYBu/fboIGfAe+aJa3HkeUOFNHGJ
         ngomu1Yu8rzzKoYE1FCaNSzwf3AhULHyc7aPGpGb/Zy691AdsjPhdYLB4JJ3iu6rRqFq
         ADbBauaGis4ETfuGhPzgSQ4Rrob3cOUJkfn8TMjvmWM+nXuy/0fjZLt8YQoZ4t0tlN9D
         3QD+dn22vRfq2WkZLqpbuJbpKd8LqK5mRXbi927wX7lQUfNny9PP736im1FsmWDL8Nbt
         CrUL2oFXCoDYSvAoNu3XGyXXtCo5IpcuAvdbcViygcAxULH5ZODUc2MRlMnJqDW4X9fL
         cSuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwwd7j+z8HF7ILNkgRozFtLrSX9a9U9NGBajD2LocoCKfe+dK59
	NEjbtv4Xyd9SaL+LaHnwJ54=
X-Google-Smtp-Source: ACHHUZ6VBv2PL7ySCGL45+YLNFJZW+9kURiwOs20coWXXnPF+WGj30BId1CHUj8y5V+JY3Dbp84JwQ==
X-Received: by 2002:a05:6870:c341:b0:1aa:2b62:6300 with SMTP id e1-20020a056870c34100b001aa2b626300mr1780531oak.35.1687169552756;
        Mon, 19 Jun 2023 03:12:32 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b50c:0:b0:555:5bba:2bb0 with SMTP id r12-20020a4ab50c000000b005555bba2bb0ls1945893ooo.0.-pod-prod-07-us;
 Mon, 19 Jun 2023 03:12:32 -0700 (PDT)
X-Received: by 2002:a05:6808:d51:b0:399:8529:6726 with SMTP id w17-20020a0568080d5100b0039985296726mr12195192oik.51.1687169552318;
        Mon, 19 Jun 2023 03:12:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687169552; cv=none;
        d=google.com; s=arc-20160816;
        b=j0VpUT6nHmPse0IgZ/3iXxC9/29ddgCxcPxOlrC+/pBZ36nVBQUaHUNP9oLvo10YK/
         i0PadmcBZ/PRozdChzTEo7q7sBXYrWO711kcd/+BW+lVZovXKlv+b42Ol2jwaNd+mYcU
         74CT/sC+nCucDT5+Todsg2P8VH+XNTcpJhpFOiZmsFytwHCcQtkloHLsjKuoF2R3K7dz
         fNqjWq2csxC/arC4mLgvOvQts+EIw2UFwxjI/g1Z1DFeWjSwvVra8Bm/6W3/mfYFlkG9
         9CU8yfYu5fPbuUaFBKCgBPpI/J1q3de9YwpW6CV+5kBS80VN8OpUawjZC9COEIyjNvEw
         Jprw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=dDL3HfnfFnFVUg7hlBOR/VHB5GPixD1jEBHXrBBxcNA=;
        b=UPzF6vQ18A062wAIpuKLWiXSfZGEzDEIQ4RAwiyXgUZGV9kq3oZ3b2XURwLAPWcNlK
         qKYcm+iZzuVar6uFeP2q2g6VIhLL449urpNbQQ2aRPgxChzlIKCEmg/n+xYpMhdEgqX/
         gRMDtwQmFgCxQlNcvfrPr9fvaOzmU0u1cCH6X6v/GR8ig7Lfws5xO7f3A5mGv6EbabNK
         4c2eXXu3iLSeCOdMuHPL5Cu1hKvk/Nw+1dHubZQ+UFMohCd9w3GNinvykZjPtCwE/dPg
         Nfzmj4yTRuY19XpZg9RrARB4c0qyFN5DanwmsrIICXU1iF5QakjVj9CEeetciRKFG6dB
         SMIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chanho.min@lge.com designates 156.147.23.52 as permitted sender) smtp.mailfrom=chanho.min@lge.com
Received: from lgeamrelo11.lge.com (lgeamrelo12.lge.com. [156.147.23.52])
        by gmr-mx.google.com with ESMTP id m22-20020a0568080f1600b0039ee179478csi76387oiw.0.2023.06.19.03.12.31
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Jun 2023 03:12:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of chanho.min@lge.com designates 156.147.23.52 as permitted sender) client-ip=156.147.23.52;
Received: from unknown (HELO lgeamrelo01.lge.com) (156.147.1.125)
	by 156.147.23.52 with ESMTP; 19 Jun 2023 19:12:29 +0900
X-Original-MAILFROM: chanho.min@lge.com
Received: from unknown (HELO localhost.localdomain) (10.178.31.96)
	by 156.147.1.125 with ESMTP; 19 Jun 2023 19:12:29 +0900
X-Original-MAILFROM: chanho.min@lge.com
From: Chanho Min <chanho.min@lge.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: elver@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	gunho.lee@lge.com,
	Chanho Min <chanho.min@lge.com>
Subject: [PATCH] kasan: fix mention for KASAN_HW_TAGS
Date: Mon, 19 Jun 2023 19:12:24 +0900
Message-Id: <20230619101224.22978-1-chanho.min@lge.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: chanho.min@lge.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chanho.min@lge.com designates 156.147.23.52 as
 permitted sender) smtp.mailfrom=chanho.min@lge.com
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

This patch removes description of the KASAN_HW_TAGS's memory consumption.
KASAN_HW_TAGS does not set 1/32nd shadow memory.

Signed-off-by: Chanho Min <chanho.min@lge.com>
---
 lib/Kconfig.kasan | 2 --
 1 file changed, 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..5be1740234b9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -124,8 +124,6 @@ config KASAN_HW_TAGS
 	  Supported only on arm64 CPUs starting from ARMv8.5 and relies on
 	  Memory Tagging Extension and Top Byte Ignore.
 
-	  Consumes about 1/32nd of available memory.
-
 	  May potentially introduce problems related to pointer casting and
 	  comparison, as it embeds a tag into the top byte of each pointer.
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230619101224.22978-1-chanho.min%40lge.com.
