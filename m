Return-Path: <kasan-dev+bncBAABB2V7RXFAMGQEKKFZWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 53688CCA06C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:59:08 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-8b2194e266asf38018485a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 17:59:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766023147; cv=pass;
        d=google.com; s=arc-20240605;
        b=lHRa86i0JGhPhWxlAJXHs7xx3TtFxR+BkxxWZzhTYj89oD1P6Rm1O0rJCOF1ZvaOk8
         u3XDHnKX6kSaxxYZzwCxEcrlnWXyO0e3EpvHXIkfpCZ6KmuZXVQzskWDycmJU4CwwP/4
         No75CPxmiPmi7fZiL3bIPGzhFx9F3PDWGI4cx5/5V27PUhz5oi7bnRaYh4Ssu5+psDt2
         /ww6BUh3qfnmm9mKyb+XeENBm73sYZ8+lXAfqLDh7bGEdGpbEzYhl78MFI9NYjp1Ah0W
         2nESiPhNbCi+14HQLc/HNj8luZbPIpgacmQ1R0n8XitGIXAlyz8a8ORPLAPPLyMKukGy
         ceXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A2uh+ZUHsTv0DYgZUKPm5fZUmcgt/wPVurfB1UYMWTs=;
        fh=cmQ4+tYIt9XU0yM/NR90jSpbkzsuNGnvYZ5u1eCguzI=;
        b=EnQMRS9z1H0LDFsCXNhDxVnWa/4EL14Hw/GiYKMYSWa4G+Bdr7bVY1xmCEK9fynMmO
         jbZbUfjHt4DC3fBTgvul3VN3kIav3M/HTJmhTAmc/RE15i89D0F9dNHQRMa6Oa//T+Bh
         WjWQGp6aUlmxnNvxrOC9o1sw3wZyMGxqQeI+sDgE6plUB3hwLZUZ7m7kx4LHTVG8qCc+
         jK/z9XfcVkytD4Z/bCN1natk3/s7xCKECizRFKa3+pJIs5ZI0CdkKV7F4rqQeTJ3rUR3
         bgObEB5Wyrf6FKf3+o42xFiZa1G4l3tlsdVHzmH6FivrdVsWSkbHC9KoRjjmFxxJP9iX
         rVmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766023147; x=1766627947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A2uh+ZUHsTv0DYgZUKPm5fZUmcgt/wPVurfB1UYMWTs=;
        b=pKXpz56DUvR/DmM9fcCOoEJGhFGLNZUJ/mlgHIdMFLZhbtzy+coKH6uuZ0SHY3QoVz
         cO4w7nz4FS+GK/ciR1SpHopxzKtoeinGfsi7yNMiZZPjsgXNWKqzXyujEtuLqQ6+lCo6
         6Ho/MqHk5AEDoT9K4KzDR6eql7dB2Tru4ZWx7b6KDVY9wY63Rxu5a6unsO9w03U3Ol2A
         lyrNaTpm0cQ+MxFg8suK23WhYrNHbUaoUyoA8tcV51Qu3DL7fRArbF/SM480kl2aW3pk
         RAGAoJJ/yG24FcaKQCEMICvLyOYxY6cIf98MH88AzUV1fjRURXFm9lKla0UhWKEirBai
         ICkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766023147; x=1766627947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A2uh+ZUHsTv0DYgZUKPm5fZUmcgt/wPVurfB1UYMWTs=;
        b=U1MWBlUYlOmw3t9ZYDoTladM1swE2nPFSp6bf2R7eht96kLYAHJFy8/3mliGU81w0Z
         JSqVw6oGjz+sl28GP0gVvMczERkW+jzYGz1BrcSCi4bSRIOA/V/k1q98fqYrcu5KaB+N
         KmqLHR3DuT1KWZLitRlP+vpOfEk8V1kIvUdv5yw+PuJPvsQPtWi7oMXWr6/SA0AX7mh0
         iJsifiJLXi6nWrPMhArIROvQYRsaFmVj+HlSAIxAQraoxcl/iN2IygewIKumYTc8nK6U
         Uu601bpospvR1LHVlXuDrZAYngrB9tMkCeeYu8JhntmurAOyvqw+7iNpt+WTW9IWgzbC
         LMRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV40ReBBWatoOkH3/giOuoWapjoHWwoCCfxcSq+e5iLBzuStup8QLOZuRT2Gky123N5cGH25A==@lfdr.de
X-Gm-Message-State: AOJu0YwOrhuj/LzgYTkGUy09nZAXeqyp72estsWkgLe8NEKsW7h6J4CL
	QimnEbpPE9jpo2WDx9+GcX7OCNoaK7JZL+Ke2oG1YYH2iTxfUJvcV8Ox
X-Google-Smtp-Source: AGHT+IEX1EwwtdY+ZxAjh8zlj1RkF0h0sVNIuFdK0Ztp2Vl6LA2DsyJkuiA13ZIIn1GEwuQ69qALIw==
X-Received: by 2002:a05:620a:4015:b0:8b2:dccd:7315 with SMTP id af79cd13be357-8bb3a39e901mr2739334285a.88.1766023146766;
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ2uJjgud67blJWax/SdBtvjH2qHSIQXVximWEygPWLyg=="
Received: by 2002:a05:6214:766:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-8887ce46bdfls121837566d6.1.-pod-prod-03-us; Wed, 17 Dec 2025
 17:59:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW2d4cxAJsJzb36LHhrQEsJ76aw8Xe10EmPOHykkaC+4KYADW/vgroaPSk3gtdQnEqyIqhdATIbSRo=@googlegroups.com
X-Received: by 2002:a05:6214:5f11:b0:888:3d3b:c9f8 with SMTP id 6a1803df08f44-8887e1332d1mr326102916d6.32.1766023146188;
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766023146; cv=none;
        d=google.com; s=arc-20240605;
        b=MTamL8lPoyoNVU85TNxubfFxs6BzSZ/LpCK15fJdEMgeaNKTuVQhyrsGs7WjugVbHG
         jZdRcsGN+YVdK0LjMAmsG+ibN3dT9TZ20uZmbQHQUtgUs21owzvoqd2SojzRBiNbSUQx
         KPHN2nFAjwKhIphkxYRwU4ejDHD1BIa/Eis+MbNMneNBTPS9R0KckjLxTzvv2DL/cPnI
         L0jU3SvVTvZb3Ezrs/3f/ZDv48l6X5pqU4ajTsNYv8DGyEVI1NlNmB2ApQn0eU/zRJ45
         P2rYF1gQxZUz5r0R9J4H7Zlo4Gh/3AQmI2nULOhk2FyO3Q3/w70m90VXbSF87jNp225N
         sIUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=iNL6Xv1UwSXA/ER2aXrzKwOgt7RZH5mqkcbw1XQgSPA=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=JkU6fVXSQwwrcwHNw3m5qZ77lghEEOqKhmXDeuRtnYW1BBbhJ2901ykebOqqdMoE7L
         TiYxLWweKS5xQQFC5Sq3yVX7wmOSeRhEGOushUlNwoFlgBhmgedUwOVd/Q/3ZvF8nSCk
         BxtdH0qdyOXzHaWSlbsNwagC7CZ4vP0/bEdukd//Qkh06Pg5jf30dASJuASnKQycN9jf
         gNJyqilu69Lml5Jr1OaCGJ37ObiOlb8L4NHdRNEUyeZ4J9Zb+u4YlTX2hDScfgS8W04Y
         EmcgvKYAOOCAEqua43Dhx+EzFrR7cvaBwV2W2Tkf6u3HMqurlSYiLSEyFAtqN/ffUyfi
         sa3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta21.hihonor.com (mta21.honor.com. [81.70.160.142])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8beeba3a74fsi3738885a.8.2025.12.17.17.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) client-ip=81.70.160.142;
Received: from w001.hihonor.com (unknown [10.68.25.235])
	by mta21.hihonor.com (SkyGuard) with ESMTPS id 4dWv0T3PyTzYnWDt;
	Thu, 18 Dec 2025 09:56:25 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w001.hihonor.com
 (10.68.25.235) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:02 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:01 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH 2/3] kfence: allow create debugfs dir/file unconditionally
Date: Thu, 18 Dec 2025 09:58:48 +0800
Message-ID: <20251218015849.1414609-3-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20251218015849.1414609-1-yuanlinyu@honor.com>
References: <20251218015849.1414609-1-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w012.hihonor.com (10.68.27.189) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

When add boot parameter kfence.sample_interval=0, it will not create
debugfs dir/file, but when user change this parameter after boot,
it can enable kfence, there is no debugfs info to check the kfence
state.

Remove kfence_enabled check in kfence_debugfs_init() to create debugfs
unconditionally.

Signed-off-by: yuan linyu <yuanlinyu@honor.com>
---
 mm/kfence/core.c | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 577a1699c553..24c6f1fa5b19 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -782,9 +782,6 @@ static int kfence_debugfs_init(void)
 {
 	struct dentry *kfence_dir;
 
-	if (!READ_ONCE(kfence_enabled))
-		return 0;
-
 	kfence_dir = debugfs_create_dir("kfence", NULL);
 	debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
 	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218015849.1414609-3-yuanlinyu%40honor.com.
