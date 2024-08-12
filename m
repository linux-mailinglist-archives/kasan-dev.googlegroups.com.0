Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBAXP5C2QMGQEIFY77UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id BD82894F40F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 18:25:39 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-44fe92a34d2sf65060271cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 09:25:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723479938; cv=pass;
        d=google.com; s=arc-20160816;
        b=0BDOpOiJiZoUDUUhGJ90P8bPObjly86Uy/AIbhvp/bld1QI7WJEOsQSvQ5GZf5jpUP
         uKwgBbGBYhpqpV8/dQvuWvR2brqOYaKfDYhjSmD17sK6vfRE8xgl2rLaoDWECLonns9U
         Bm4RiIEcy3T1nYv1kNDNbMG7dOADXj8o5b3teMT6gcFcrugdj8NMCXAxEK4oe3Vqx2MX
         PSscj+SaFCEgktVjCKwFXiy0ela0v9tWqpPx6X+azy+wx2wJFU4BLoc/Kt0SRJXFgtMO
         gbuFLERVWGaIYSrqtVxO1ceozTwfxxpCxfQ6zz7dBltw7FBNn/HKvz9zaUeD867obt0/
         LKSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=GfnT5gSaBMk4cSKYQYN2eJ/PC+NvMpEH+dSHMep5A2I=;
        fh=UwYEjMgwtSniw1Ui8/6u41zxkk0RP7vVx+X4NWW4wGI=;
        b=Ih7/2EW0BP821RVghG/y2BMTwXHGgnLof+p8i0n6Ez7PqxeeYKaB58E4GFXjNm1UtM
         pFh47rXS1vK0wpGjjuAhKim33xF0zVsnx3z3Ob/slGt53DCEJZ1ujBAYT16o09OFsT5/
         v7e6OftzjvDS3xmc5G9tjx5KfhLF9m7tOiLdJ6Yzazv/3MzVqa3FZ+5cGgvJJDyeD7uZ
         UtePupsbJCxMWdcFoIzOPoTK7Kc3Ke4XKbHSDe5JBTOVhc7d7h+Rmb3yvwBYe891ODrx
         WLYeCCtF3cbZO52qYz0JEIjgp4Xi0Vl4TV3HglgMnryXcnzsxzLkmQ0l4S/dzjK+nxNy
         Rp4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=CPqrfZLU;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723479938; x=1724084738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GfnT5gSaBMk4cSKYQYN2eJ/PC+NvMpEH+dSHMep5A2I=;
        b=hjgcPrEpfTAiNThglMWvhMvAENoO6H9u84VpYrr3/sfLInPrCY8Iezts6gN2O+60nf
         8MCGsAI2rDduOBKK5Fyi24VW27ulpAIOnMkmvFQHOcGckQUQJhob3m5jHZR9rZuBfife
         /KZaB8JLoQ8FBRR/w6WiepYwNsvMGwOQePGfKltE0yAhmV4FbMMnGCQ0HCbIXeYZdlbH
         sYquM6K/q64azOWhDpK0CmZuEjEBDHYY8287p6Be8SUnbhgibk5fcLhD4C4Z60waV7g1
         3kkGJIWkH4nrOTy1RPF6gW/ULwQUoZns4t6KZCQZrhw/BfOgY4YpulcbOYFNeK3VeHR3
         EgtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723479938; x=1724084738;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GfnT5gSaBMk4cSKYQYN2eJ/PC+NvMpEH+dSHMep5A2I=;
        b=IzjJmMXfcxGzD9bA9G9nSwyncpuLi1SB/FsWWa3A4D6kVOS13FcckJsNEouKr6VVRQ
         3JgttJHN8lm/LxK8ks5iX1bPmpWbxHg1Vs4kYKJD5+5nuDV5ovSiDVIsgQKWbkQIpWVE
         7TQUl3QMhKouKxBOVjqd/QZ1WY6LrPIyZuWOfxaGdQdIdlyeGKStjcKMG1dRqKYvo/+P
         JAIdOgqLH/w4/D+jgxNjWoMO6mpAp9XRpKv+sR8fNdAW3kZxu1UR5SuaGvD2+LioM045
         +cYKt8QVD825F7su30uhCG68zl1r+229FHjgwrv+hEdyUH/cuRSyKekiyVBV1aWN4jLC
         eR/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3xBvt8gPpV8qR0ZMklK9rs4VTaJCbX7PQkYkHJ7GWdXmB+J8a3vBRXt2IX70ZloVIzqtLXIxUj9AjcBwNoAHXiFd7TLn2KQ==
X-Gm-Message-State: AOJu0YyCIUb0n0K7Cjqs5U40aqVw/XPXrZbjHyM/UFo4kn7IG5GaNj++
	4KSmiYoKgngOGsxTcTh+ukdiH1WOZpQXa/DaKI4ni1CnzSsL9di7
X-Google-Smtp-Source: AGHT+IE4aWt/PY0jt0MGCJUfmTKal5gYYjoNEk2EO4AFiCRjiqSwF99yiP/gidGO/n161a9wpFh1Yg==
X-Received: by 2002:a05:622a:1149:b0:44c:dadd:3dbc with SMTP id d75a77b69052e-453498af86dmr10560741cf.13.1723479938396;
        Mon, 12 Aug 2024 09:25:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5813:0:b0:447:ed03:aa4b with SMTP id d75a77b69052e-451d12f6c25ls73937281cf.2.-pod-prod-09-us;
 Mon, 12 Aug 2024 09:25:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUT7H+PeETYEoqwHeetzn98nD1OB0t5HvFBVaTiEv67nBZYHAq6cp76whKgbkHbeaRFV1dDWo8rO0d07aI6PI5+m5zPCowY3Y2Xfw==
X-Received: by 2002:a05:620a:2911:b0:79c:103b:af44 with SMTP id af79cd13be357-7a4e15cff2emr71693385a.65.1723479937745;
        Mon, 12 Aug 2024 09:25:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723479937; cv=none;
        d=google.com; s=arc-20160816;
        b=cmRnc0XK+E9VtB2Boliu5BsBGFZoT46bvkIcmvgS4FZRLBTm8oU7vcBhYScC4vUgl3
         JMkjTgIQ/IXgdBSTf77q7TWrzlqMj0ODPgzuwdXC34SPDptf05X/+V7pncD+tW8NeBXp
         8lo+CC8s1zcjIqcAngyQtn91bhI7oCnd791nMVXhT6YPLilMoHfmX9fMpbB+fRpwVDHY
         ws9dnfYMbD9gIL7tjKMcuI2DNI9/dkFwdDg2V1ewYGf6Nu9p6aoqp/GmLI6ixenztkDV
         2z+bPSQxgg/qYkCOfsiHCSN2LAe8nyk5GxtViWBpsQrEulW2mN7rGnMeXF63VrlcJHPd
         rkvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ldt74+jppEzrGPgDUWu2o8jcX3jFQC2t2RZRPqJVuU4=;
        fh=+Zf9XVYT93rNkJvMi/4JPCjvm6CKgnQ5JePRwHTRxAQ=;
        b=Von2uNIJK6xv6fcCk0cUICzcgXCT4aIXRN6+6Tg8nYNM7jeeKE5ydKnjWAXOVK5B3M
         whWX6MktLagXRzle8RKkAlfI1tqLD1gRz2BoMBGeDZqdST4MhrPcdD2bB0kSyIHQ6I1/
         32wuTiWZs2v+pJS7ZW+54R0jXSIesGTOoH8k3z4ty1O1ULgcdQP5cWZHdGume7RnHTMW
         OaJAoVgauadfCN1REUC+vui5+ID/siOWee0OEe3fG9tKvWFDJFGGbSTPFpx/sjSIAhsr
         cdvmcfgTn3oHXWe4eXJ3WZ8l4slsJtma3U9vVK2/WpqaLX316heFCdPqMvtwiPMCYYvb
         XzhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=CPqrfZLU;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e0213csi19218485a.3.2024.08.12.09.25.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 09:25:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5802C60FA9;
	Mon, 12 Aug 2024 16:25:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 88901C32782;
	Mon, 12 Aug 2024 16:25:36 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 6.10 045/263] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Mon, 12 Aug 2024 18:00:46 +0200
Message-ID: <20240812160148.270053242@linuxfoundation.org>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <20240812160146.517184156@linuxfoundation.org>
References: <20240812160146.517184156@linuxfoundation.org>
User-Agent: quilt/0.67
X-stable: review
X-Patchwork-Hint: ignore
MIME-Version: 1.0
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=CPqrfZLU;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

6.10-stable review patch.  If anyone has any objections, please let me know.

------------------

From: Paul E. McKenney <paulmck@kernel.org>

[ Upstream commit 6040072f4774a575fa67b912efe7722874be337b ]

On powerpc systems, spinlock acquisition does not order prior stores
against later loads.  This means that this statement:

	rfcp->rfc_next = NULL;

Can be reordered to follow this statement:

	WRITE_ONCE(*rfcpp, rfcp);

Which is then a data race with rcu_torture_fwd_prog_cr(), specifically,
this statement:

	rfcpn = READ_ONCE(rfcp->rfc_next)

KCSAN located this data race, which represents a real failure on powerpc.

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Acked-by: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: <kasan-dev@googlegroups.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/rcu/rcutorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
index 807fbf6123a77..251cead744603 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2626,7 +2626,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
 	spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
 	rfcpp = rfp->rcu_fwd_cb_tail;
 	rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
-	WRITE_ONCE(*rfcpp, rfcp);
+	smp_store_release(rfcpp, rfcp);
 	WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
 	i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
 	if (i >= ARRAY_SIZE(rfp->n_launders_hist))
-- 
2.43.0



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812160148.270053242%40linuxfoundation.org.
