Return-Path: <kasan-dev+bncBAABBR427KRAMGQE6SPWA6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id EBA7E700F20
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 21:02:32 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7578369dff3sf2307329385a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 12:02:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683918151; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZCLyj0ImJv/ARr2BdzQ3tlsqPmZpudz/OktDcABLX6XkK9UFh7agl2DZy0Dkczhi+y
         e8U995fkvp9APW9K+O8qoYbzt+EtybaxvyzkXUkLF32A6P1lji3IFYDpIkRWHoMnSkYV
         pJgmPzRTiIWIi8hScXRlo96ai4rIsyvWwm7h4EkkbjWLtCfV55vIIkD7dP26zdsK83f8
         7nNXzhRolKaTMnwKVUlUxCjmIRwiRtPPHRfNFWaNnBuLUdoRetET3WebsG6DXeHxEgPw
         0nkQ4vhnMpa9FlgAvig0Gp0xPx49J3JOkPNbAxOiRWXPXUOLvnzr/LWF3xRWtskCvmOG
         WPtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:cc:to:from:subject:sender:dkim-signature;
        bh=ytbUBf7E99NmVBsteW80mBdyLLBxBYJG8IHC7E3Oqkk=;
        b=P7AZNwqTgQNxssqHOo8axttvycjCey1YNDuu8RgmvlwZay1UuCsbKbJimrvz9dXcq/
         +QKWOCwq7x6EcKyt+QLz1FL2VjWKfG719ffa7M8kvx4K9FoVdtZu9M+4EmbRBMSIgKyn
         2haUM2VOTjN6E8CPL1iyqbCZUaWltBKAzHhbTj0XZPpfebfQlwKfCjzHlcCmusmNabur
         f6T1TrdQnScjVQeGpD5h2A4UsSS8FJi+vlT6n3ldhaOj27uk/Fv5IlfmwrQpjt7Vhh9S
         U7yE5D+8zGTnAZDNhSKBVgV/ZXw9gL0ChHITbblo5e/lBYYfd/Fu70aTNbSxjNdAyI+i
         L6+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=swObnCJr;
       spf=pass (google.com: domain of cel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683918151; x=1686510151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date:cc:to
         :from:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ytbUBf7E99NmVBsteW80mBdyLLBxBYJG8IHC7E3Oqkk=;
        b=ebdqcvsF1yX3jLjgQlqL5IrDO66HCjVznd5GbxedG3p1xBdwB+k6RC+9u9YCF5RvVl
         hop/XgblVStmkocruqENvAD9yJbjxWaYfc3PNViPHNJoey6s2CEcveCsBMAFi4hJLD+5
         wlJn9q2nwD00sfz/SEg8DvbB+NxzN3aFuCorpzkkK4w9SBhEVJCr4dzIujVoSNxR6YVh
         GZzrYUeUuHfO8frzzutm2IrYqbqq8uOP7GHCK+DagfnpmpoIKbkAFxmj/qVLuFW9fAzc
         5FbBUO6GSbEypFAzvwO5UdwCmL9/7Y8GqNtm0oapMJuNYVrVeKAuC6oX5ls5jI/ih5NI
         tn9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683918151; x=1686510151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:cc:to:from:subject:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ytbUBf7E99NmVBsteW80mBdyLLBxBYJG8IHC7E3Oqkk=;
        b=Zk/FNuGf8qskwzk8SieVZhc5Ho7A2T9dfSkUUGyEJEGNf6pjhyp+D4nzj/tIeGKeF9
         GoRA/XPVnfWFds7Vn3almo2OpfnQrKqkfbaat4RLn+cpaDsMUCTO9mQBP4g62UL9iRzt
         XussaWW4ofBa+XZM5QvzHBbAe5pSeTZVhfHlNwJl91PTrDNjQsxEjlsGCCYnu1cpH6y6
         4sfCttWuRunAy0XJc3g0cvI/DrghctH8Z/wg9vQc9FvaIvob9l29uLdVfhxmE5JSdwuC
         dt0lLcl2mRS9LW0lVOuvGkvJV3/jNVeMchOoaZ8TpNeEBqhuXnVokOwjUBCu1YUZybCN
         5+OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz8dBKc/2hzV3IGX1qAaqiULc41pFW8jYNc5XWOote6bnjfq1LG
	2PercACXY60N+Vo5t5OvEDQ=
X-Google-Smtp-Source: ACHHUZ4ItPfRXFiCYA3elWh0ap9sacTb/uNiQXdOpAG/H0mTrtva3BpG2j6+gNL2n6T/r/WgYpbCCA==
X-Received: by 2002:ac8:5a4f:0:b0:3f0:abe7:24a7 with SMTP id o15-20020ac85a4f000000b003f0abe724a7mr9179054qta.6.1683918151560;
        Fri, 12 May 2023 12:02:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2483:b0:3f3:94bf:529d with SMTP id
 cn3-20020a05622a248300b003f394bf529dls11647496qtb.6.-pod-prod-gmail; Fri, 12
 May 2023 12:02:30 -0700 (PDT)
X-Received: by 2002:a05:622a:40c:b0:3dd:a248:5474 with SMTP id n12-20020a05622a040c00b003dda2485474mr36815972qtx.34.1683918150848;
        Fri, 12 May 2023 12:02:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683918150; cv=none;
        d=google.com; s=arc-20160816;
        b=VWz/l2wQzi6jVFIpfWeL7iT6/rp2bttYBhm0PRDi1/g3SBEviL+KPRBuNscqbnnYbh
         fiuTlGZib1gvjoyIs1J/0UzXu0cirwSDsR9PDucyEF4I0walUNIDhLISFhaOKsQ9qfjX
         uLpM7wt1eMbjecl2jiQIA9w+n3t4f1xUjWzgbcnafe3A5KbxmOEz6XTgR+MyB4SjgovJ
         T6WUfpIwsYfScJNf7ZGX+McNceOE5RMwnqrgFNcdIQYAkhxqgRlrsRKxk03uajDRVW62
         xxJJc8STttDGzbVmWcBSdF7PVHxe3fLyokX41XbD5Vwf+/+dxtQgYGBgwmC8GdKutAO/
         ecWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id:date
         :cc:to:from:subject:dkim-signature;
        bh=yY4d6vwh0xC0ZfTmYEWLFzoS2ClDKn2SX9+7JF1UWAY=;
        b=1I00ZDT3nvHV1WCp0/W/spU7xqO9tpLCg7ENv+7gfFfWFFlVJOvQSK3MaBo6lC5Gvk
         HlSO+xcUXOX8SVP7QBl6PdU5CcLTwvSC4YzICDF9n4NXVzNFwxidjQy52CFJTiJ7C+XG
         9UqbuUhXWzWluGpK13jSdNva7RZ5zORPqXiGih4eMIwyWLPm/tighi/G/gLK/ztFs2z2
         piLvxTh+J4ZIhiy4csVpnWWId43He32/qiPc8wHF9tLj5uZW/tfNtMI72DvOgEjP8zfc
         YEArBCCWez08v9cV6Y4GO8CHtoWRwsUF97C3x6OETpqoLhCBaAwVy3quL3eQE36aIBeA
         Qa9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=swObnCJr;
       spf=pass (google.com: domain of cel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ay42-20020a05622a22aa00b003d2b5e4bce2si724526qtb.5.2023.05.12.12.02.30
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 May 2023 12:02:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of cel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 682E563B2C;
	Fri, 12 May 2023 19:02:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9BBFEC433EF;
	Fri, 12 May 2023 19:02:29 +0000 (UTC)
Subject: [PATCH] net/handshake: Squelch allocation warning during Kunit test
From: Chuck Lever <cel@kernel.org>
To: naresh.kamboju@linaro.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
 lkft-triage@lists.linaro.org, elver@google.com, akpm@linux-foundation.org,
 mgorman@techsingularity.net, aryabinin@virtuozzo.com
Date: Fri, 12 May 2023 15:02:18 -0400
Message-ID: <168391812685.21298.13859211358278163731.stgit@91.116.238.104.host.secureserver.net>
User-Agent: StGit/1.5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cel@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=swObnCJr;       spf=pass
 (google.com: domain of cel@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=cel@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Chuck Lever <chuck.lever@oracle.com>

The "handshake_req_alloc excessive privsize" kunit test is intended
to check what happens when the maximum privsize is exceeded. The
WARN_ON_ONCE_GFP at mm/page_alloc.c:4744 can be disabled safely for
this allocator call site.

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Fixes: 88232ec1ec5e ("net/handshake: Add Kunit tests for the handshake consumer API")
Signed-off-by: Chuck Lever <chuck.lever@oracle.com>
---
 net/handshake/request.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/net/handshake/request.c b/net/handshake/request.c
index d78d41abb3d9..24097cccd158 100644
--- a/net/handshake/request.c
+++ b/net/handshake/request.c
@@ -120,7 +120,8 @@ struct handshake_req *handshake_req_alloc(const struct handshake_proto *proto,
 	if (!proto->hp_accept || !proto->hp_done)
 		return NULL;
 
-	req = kzalloc(struct_size(req, hr_priv, proto->hp_privsize), flags);
+	req = kzalloc(struct_size(req, hr_priv, proto->hp_privsize),
+		      flags | __GFP_NOWARN);
 	if (!req)
 		return NULL;
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168391812685.21298.13859211358278163731.stgit%4091.116.238.104.host.secureserver.net.
