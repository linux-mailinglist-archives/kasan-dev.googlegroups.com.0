Return-Path: <kasan-dev+bncBCS4LXWYTMCBBI4WXODQMGQE7AHDXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A95A3C83E9
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 13:31:49 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id t6-20020ac5c3c60000b029024f8f474366sf509732vkk.15
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 04:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626262308; cv=pass;
        d=google.com; s=arc-20160816;
        b=ABo/tsEVNNFEGmLaoq50e4JsTY0IhtnQY7qQrkFxBMIZyOu5vWLCaFK8vf/7iDGfkB
         QYKNjaZ2o9qNvwwMYfR0HOJQPksKTTCmGnJPPN2/2Hlv/tWbHAmd3vmj+67SSw0ImTcb
         iu3FxKL+R21nbyytfQJKmp+XO4EUSZOo0f1Rw0xfQvoG+RdQw44Nrl0iVU9/WD+eoY6i
         5INH9kgz1mJ1FhR07ePK5NLM5eZbEw6gmcDV0BZew+8ELkJDmlTjL7lThfFEGxFmpopo
         hTHGmR8P/aEQakkfmZTHbFKDuxXNBL77zWbDWhqZuMZjmc+QrLer0Rl48HjnTj6w8tzi
         mE4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=kz0jSEPqQepuY8uvhN7x4hB5PF7UGoEukXl07ETEk98=;
        b=WOkYSgKEP6/XTV9mDVitG+AOJZak9vycSeraIUV7uaUziwoZoP+fjYVQP6cJ2LI01O
         OdUZkpyaZPSuzFhOs1gB0OKSUwh0+pqoyRcGQVBtz+wPM+bDVQbGUlLyakVKyQ4DQnl8
         LKGkShMBv5tVJM51V1LiOLDbMj/BazSwyRfryBmjDRMELEYVVY6RreNR7wnULgWlgF7R
         N/GBANx4JShdt1QT2BIc3I+cMmFUsjsKMtBvLOMbJ5UXNlXPc4Fq2jwtgGUpvWp6hhWY
         fNGJ2bTimDrzLx5BrxsFq5FljkJyual+sb9W1i4LxROruvFpwTrUPbpTYAfcRR7bhMQs
         Ql4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qBF4f564;
       spf=pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=o451686892@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kz0jSEPqQepuY8uvhN7x4hB5PF7UGoEukXl07ETEk98=;
        b=O++eSN2uS3v+HHp6RvMd1VaKNaEMAr1Udowp7GyZkzGo9D2mGRhVnWoXORCtdQL9fh
         rv7WkN9NdP+UTzUfQqWbQMPsO4slmou09EfRE9X7VD0A+eY6IjAnASP2q6q8O8Ts35Rw
         GOSRH0okTWW+iqxZi2252zjswTvAo5E3stEFXN1v+cx/n9jEabmDK+HVT/P3Heo5GiQE
         Le4NUGjXg8UBbbdPnFnbc7XEKpxtjh99WsSUwriU4j8VoAOY5clBauDLlkixKIiUbTPr
         VLLIl+dkUR+d1k92UjYOv0znpJRUU+XW7oI6inyaZTOuDgRgl4EgGR2kuA/ZgUKQh2E/
         3GHQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kz0jSEPqQepuY8uvhN7x4hB5PF7UGoEukXl07ETEk98=;
        b=eNBLEH3fyrnxAnISi4h6y0642gnB0k+Y7cfsJdBYj/bTubewV8+z8ro+yfmAfQPaVW
         znZGeW/MFOoTHhDn/SVRqOYbuGZYY9H9+UcigD0AuN2KWBs6K4j38vWdiYWnFzshJlHq
         GJDkvzQZwwXrbyTO8fIkzb263gugVubQhxUAqVWpkvnR7MMSoLFZkzRgqPdhqiSt3wVE
         tj934/ConA/BSe5sZVzc0Np6epnPhJIBWAhugBFOoXQ35LymVpGMMBUxLpTk/Ih60y1W
         CsV7HSc0C/sRuuywgzN9lV9XY7W65decHQ70k4lpHHUMXZV9ipYMMeJFBE7ABd/PfbLH
         fjAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kz0jSEPqQepuY8uvhN7x4hB5PF7UGoEukXl07ETEk98=;
        b=SwLFp+Z2dU15VioHSDGQycuAYlfNP4pkmTm6T6nkHUNhJ78t4Lp8sa5k8QC96NCy7x
         P+aX1XySkfx1mOHGQUKXqK7mp+Z5wrtw/OxR8PJ2YJ6up1RP2OuwdOoyINbl0p8kHy4n
         YP6IebBII7W8c6Tfq21IBZhRd/eKG4OgFLfXv4eAcI9G8I2lLSZp4CrxdqHtlNqWY+gK
         JP2cDvkeqeKRd1MbreVsNsvymm/41kLrm1mvnfluaxNBNI87FetzVxLEX9QwvpPjeLUj
         q7QBGpJISVx02NmZ+Hf69VzFHpx0naNwbzaWDztYZmb0kuIYRji+vYKiA1YSmm/ZlhCE
         2YTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531N2sY9UZRE2YkhWMN8k0/eZJ9c7E93tYOrrfqwPlQh87Ts6eOi
	eXtbHgCbX3k8ZtqrbJabpZI=
X-Google-Smtp-Source: ABdhPJwJ5WtArbAxPnVH3Op2RwZpQjDY10alUoZyAG6cMCrCiqU9B+aTSlouePdvq58ISsAnQ3Gndw==
X-Received: by 2002:a67:7381:: with SMTP id o123mr13460283vsc.47.1626262307417;
        Wed, 14 Jul 2021 04:31:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7682:: with SMTP id v2ls407419uaq.10.gmail; Wed, 14 Jul
 2021 04:31:46 -0700 (PDT)
X-Received: by 2002:ab0:5a2e:: with SMTP id l43mr13209376uad.4.1626262306894;
        Wed, 14 Jul 2021 04:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626262306; cv=none;
        d=google.com; s=arc-20160816;
        b=O/7LsS1fiZn2rvRSpMC2NGENmzfVYMHF89/Pgbkg1iIacTLhcWVWVwOo5YCsQuIWo9
         PTb+VnsYjV0VBb7Cn4Q8aLwAMlNoSay7TdaoTN/OGSgi/VcAoVrut24h0yUMrLEno9Kf
         N7OxzDiU6mXJZkG4K/ppLjDHaKeMyQxoWYsWtM+SJ3K6UX34gTQIEy1hkIg8RIdmNzgD
         F5/3Z2ycGkdTUsQ4pBTS3QdkunIlrmUbzl28NeZmZr2CbdyxQ1fXZgcSowKoEQMJo/G3
         LOWPOidBh8ZKXQfP2HsPEpsbxDAAzW6q281skcZlc13IlNyxDqwABMOgSOedRIC25jDM
         1Bhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=xzP9JfDqYJBn+lgkJ5neqY7O14ZLPqoi6I2YFgNMZsE=;
        b=H82+hyArMQsCdCoo+JLQlRIQArxHAcgliKOOQSlSGo/tBySMcMf2J0VVNtqMKBmqEq
         nwhbQw2joJWa27IFBHHWdUnJwchufS8D/WsgJQOP1fLvlB1zdOBoTo6adXQS4op4j1KG
         1JQtpUKSmG9DLKi5V25iUCqG2dm7QlsL5ifHehRhXsw+qkFdnJt/nUFIoVyIeXk1DMZj
         BQeFCcOLuv9VCEceUaU83E5GiWVx66JnY6ynjN4hbUuA5/51dkfjjy71RdOsSvI81mzJ
         etDUepVYjn0smCEaABfQhxW17HGcC7oUxunaQEdcyqsKYuXfopxM5OruMTuQcVSsxujV
         3E7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qBF4f564;
       spf=pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=o451686892@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id x20si225913vso.2.2021.07.14.04.31.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 04:31:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id bt15so1378308pjb.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 04:31:46 -0700 (PDT)
X-Received: by 2002:a17:90a:6be1:: with SMTP id w88mr9400355pjj.121.1626262306372;
        Wed, 14 Jul 2021 04:31:46 -0700 (PDT)
Received: from ownia.. ([173.248.225.217])
        by smtp.gmail.com with ESMTPSA id r15sm2830316pgk.72.2021.07.14.04.31.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jul 2021 04:31:46 -0700 (PDT)
From: Weizhao Ouyang <o451686892@gmail.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Weizhao Ouyang <o451686892@gmail.com>
Subject: [PATCH] kfence: defer kfence_test_init to ensure that kunit debugfs is created
Date: Wed, 14 Jul 2021 19:31:40 +0800
Message-Id: <20210714113140.2949995-1-o451686892@gmail.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: o451686892@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qBF4f564;       spf=pass
 (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=o451686892@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

kfence_test_init and kunit_init both use the same level late_initcall,
which means if kfence_test_init linked ahead of kunit_init,
kfence_test_init will get a NULL debugfs_rootdir as parent dentry,
then kfence_test_init and kfence_debugfs_init both create a debugfs
node named "kfence" under debugfs_mount->mnt_root, and it will throw
out "debugfs: Directory 'kfence' with parent '/' already present!" with
EEXIST. So kfence_test_init should be deferred.

Signed-off-by: Weizhao Ouyang <o451686892@gmail.com>
---
 mm/kfence/kfence_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 7f24b9bcb2ec..942cbc16ad26 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -852,7 +852,7 @@ static void kfence_test_exit(void)
 	tracepoint_synchronize_unregister();
 }
 
-late_initcall(kfence_test_init);
+late_initcall_sync(kfence_test_init);
 module_exit(kfence_test_exit);
 
 MODULE_LICENSE("GPL v2");
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210714113140.2949995-1-o451686892%40gmail.com.
