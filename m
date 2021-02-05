Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWED62AAMGQEANROLZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id C395E310ECA
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:21 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id m64sf6459427qke.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546520; cv=pass;
        d=google.com; s=arc-20160816;
        b=dEo7UMfwXOFqemXk6MGyGDyf8NhuUjP9JRSAXWweCpe8ScIqCluu98Fdu7TIHKWDeG
         YPr8hzaKGWcp4JdESrsZ/OUTL6IeC4R3fAwn0FBm7q9Ar9ytHhkkWJb12zpJzsUxxSrp
         Wyp7oRVJtgnIIYBZTvLUfu7SlQCbRnVXQWoBaQgOdjVrvyG4CIaO+YOZLgRA72YbApyc
         B44HGjHrx7f0QJfs301XbjPCTnsldGbUTYgbwZgdY2eD2mnbq72X5I/MW5erqOQAW0t5
         9Y1QQ4jUtWcxDKrTVryV7Jvb/sz4uQSvGvTeITBHZI+r2MdP/sA+Kn9HRvab9VXehU1x
         u3UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vcjNXUktZXVjYxgHIyrVwLHH46/jHXLJMNRFBZta40w=;
        b=osURBXLDxZ2V3woIPbOnSiQpDsUvS3ptDFTNw8FCNiqaq48DqEcqOWH2908w465lfJ
         ETk8mAs2iV56FFe2pRBLpJLQZKGVyPZvsOsP/iW9hX3qAXOjQDaBAO+0Gj7qF7tK/ylt
         ZfEgbibpA5Y9obHq8tHzJ6ZXKSHUlM/J4zwuiVCcmLJbpN23y+LXShOxDVhSvn2KSHgF
         i2QXklf7nnTgaIwOoQX1u1saUYP1d1w+8W9a5fTOSK6urxdTDuVnOirS9UVWjHLS/lkC
         Ju2ARKpVnXf+oWfG/vxzK7m3w72v72qW5m4MScdFVdHxk6O9oWbs/PbMP1eyHNgDCElT
         aqqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AyFbGRtZ;
       spf=pass (google.com: domain of 314edyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=314EdYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vcjNXUktZXVjYxgHIyrVwLHH46/jHXLJMNRFBZta40w=;
        b=FJTXIh5nRIpGSHuCKWmGNVUTPYhsE8OaeNKVQ4EdF5234Tnm85oGNnhFXWsO6zDmXT
         R2C0lAMlAiMz2IElP/8GFHXxpMJ54eoADkNb8OOUo/b0q4/cjQU/k5BzgMHy+Nff1bWA
         NWARPQJAWBdhhSoRLOT0NmXnMivGNh0SjSKIo+QvDEKcPtw5p8pcX4c0Rq3MblrSOBBh
         xW6DGqu4gjmuOZZkV5/CN/hff7JNdj9YHeAlzdNoSDzKZw1gYJVJg1sru/K2gN9sjnfK
         wq2pn6vxGjDicvlF1A5rvVzdzeZWNeL0xKk7UK5dO26mOoV/3+wQaOIHalfZPGUpCzqM
         5kBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vcjNXUktZXVjYxgHIyrVwLHH46/jHXLJMNRFBZta40w=;
        b=Bsdgyi6XJmaIu5h/DJgtXkbk0VzqL8re56WmjS8SqlzjTzckoEnwc9iQbIgY5FEFMI
         +AoPoPA4z41Jjuf7UKfssNpFx5d4vaty6px2ahE0+EuBLftEF58jbws0eyDJuer5u9N9
         6QbadgrTsg7T+YzKu8uxZ18sWCfyacYsamk3Wy6/ZlSMF9ltg46G9TRKG0TXRHlZzthc
         MVOPcToEJWDNBv+FCo1t2c7I/pO26ILwqJ6Q3D7xe08ExLTyBD0zGdPFzeTmEFxQa1ax
         s8oPAARPdS3jSPdgS6AxoCww5hQXJoRC2e7IqrpzVKneVuDDwqSRvbG+zexfvdYTPXte
         nYbw==
X-Gm-Message-State: AOAM5332GKTeSB8CgYwgG2aDm4OiVWkNo2PwDw7XmwLItPSzAAKITE4e
	qOg8sCNahIxHF5Am3C5dfyI=
X-Google-Smtp-Source: ABdhPJyURBCwZqx3tc+zw/1gLMefWg7XgsggJJKM/li1KTYCIbxCUOVDTLQ4LZgpocBk6tuS0Y2Jog==
X-Received: by 2002:a0c:e109:: with SMTP id w9mr5310985qvk.57.1612546520413;
        Fri, 05 Feb 2021 09:35:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:d2:: with SMTP id p18ls3729593qtw.3.gmail; Fri, 05
 Feb 2021 09:35:20 -0800 (PST)
X-Received: by 2002:ac8:5289:: with SMTP id s9mr410624qtn.56.1612546519930;
        Fri, 05 Feb 2021 09:35:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546519; cv=none;
        d=google.com; s=arc-20160816;
        b=scxNjyQS7m6nsqcyeCAxPsyYGw5QU0grCgFeenNElGrMDpph8Zt4IpaRyjFnJp0Za/
         8TfI3KVyVO0K9RNbkfMTOTFwhMW03yfy3vvdGWEVhxF04hVdI1lGcjPdSkP6JnH0B9He
         OCer5u5C+TpXJKSSgM5g3xGvOyk7M21Ug2LjS7Wza8LcWGygh2JdDCUGCQYpg8mIvmTI
         DO253TIFfNTjuOKylgU98unC+KeIOZq7CKqIWCvkgbG1cTe+iE48kD3PWYcxJVwlGmo6
         NIndgEuTGUz7skGcA04N7/3ky//XnF5/wNUqXQld8uQmy+uNHxUB1cPeNDEXVH/JXC7U
         DpiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=V3NcBz/sBuF9R5rbEs4mkivGfi7JQffIAtJVZQe6PVQ=;
        b=YSPWoQiYL02LqERSBqt0+nwvE/l5/HySSucksoOlnSRLkI6vlzeS0kuv9g0OFMtoB2
         bCxQ8EvfoQsE2MzS3PDbjtOXRFrcIjevSmuR+3kMLwT5jaPssW9WNzOdMh8yg0MnUyGf
         2oN4xt6b2XUDCpO82m5fUgwstVfRzvpI5Ofrc5Q+NR7bpC/Sq8GR0s+GhGYX0ujdrNiP
         l5aYzxNI2tqJ8uQgWqCHLZcNv8ZPQV+ZStbiQa3isT1RBW2/bvG3eMkCbgr2N6EjLhz6
         Sxt2tMQW9v6HChp4uaHBw+GxspqeKHR2YNy72RfnGycqxJt8R4e3/5TE15b06MDJxKr6
         B3bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AyFbGRtZ;
       spf=pass (google.com: domain of 314edyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=314EdYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id j40si886457qtk.2.2021.02.05.09.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 314edyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id o14so5769380qtp.10
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:eda6:: with SMTP id
 h6mr5378538qvr.19.1612546519544; Fri, 05 Feb 2021 09:35:19 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:46 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <14da91876a25a6ae5b2096f7c06ebbc6deb3cf6b.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 12/13] arm64: kasan: export MTE symbols for KASAN tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AyFbGRtZ;       spf=pass
 (google.com: domain of 314edyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=314EdYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Export mte_enable_kernel() and mte_set_report_once() to fix:

ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/mte.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 203108d51d40..a66c2806fc4d 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -113,11 +113,13 @@ void mte_enable_kernel(void)
 	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 	isb();
 }
+EXPORT_SYMBOL_GPL(mte_enable_kernel);
 
 void mte_set_report_once(bool state)
 {
 	WRITE_ONCE(report_fault_once, state);
 }
+EXPORT_SYMBOL_GPL(mte_set_report_once);
 
 bool mte_report_once(void)
 {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/14da91876a25a6ae5b2096f7c06ebbc6deb3cf6b.1612546384.git.andreyknvl%40google.com.
