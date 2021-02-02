Return-Path: <kasan-dev+bncBAABBH6R4OAAMGQER5RANWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7021130B764
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 06:52:33 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id 22sf12272276qty.14
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 21:52:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612245152; cv=pass;
        d=google.com; s=arc-20160816;
        b=xo8tSqYnKdteUsuaK2PkxtsoIfV+9/8dvb9wDdjW+nrkduW6bVZtJWT/4fI7+OTKwR
         mScnywJF7+wMV25aeZeMwDRFppccr7kDges5KPVjAglYgqeiRqVqBFLPlMi9Qu/2M4M2
         O3qhwvtUauFOrvJ92iEbGRN+KTduCI4HT4QSktRkmD7PMUEPQpTTmzkOGdfTCd7XxQnk
         RN2ms8cweGSf9oftiv9vw4t2ofnOlA4pkZqprEksvuD+q9Cr8JLrWKZEel7zA8XUHNcO
         u95Osrsx1iDXEXT40HEPOUJ4d8IPM4xk+jwU+LD86qtXOMMjMnBoLqDbQqBQ1vPBW6B1
         V3fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=QJ21INgO5tdIHrMIVGZ7En6jr/Q5dYZ3g2c0oVdZj1s=;
        b=KnuPODJPxhu1gOck+FsINdEZT/AqOdnPraLnrma+luUEMNDVI8pm+SPvHshRkeMD43
         wp3iSq6Aw4TTvL7QG0PoZt6nK9uGJyxoh9PHpmXp0IxeCBbusMb6qkC0zgyc5/AnAu4d
         VvaZsRM6zM1hE5oZhRgII9908m8YMdcwNdzWF+2TKSOBWs15dmRhH221mUC4pd20tHO0
         c8fpmooV629xaG+Cj+HRAT3u/0ovlybAlcSDzAgui0nPEk2nHutSZJ8L+mUjh0WDXLcA
         e+KShOtpOORRRum+S8uWwtE8T5/yrbQKx+t0fE61qKC/cyPl0Wn3kQtJMnsYm9SUz5YM
         Swnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yang.lee@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJ21INgO5tdIHrMIVGZ7En6jr/Q5dYZ3g2c0oVdZj1s=;
        b=bwpqJcY1DqWtzJfcjtW0n0FTwIXYL8b0kc2pDTVRXt08vM7baBk0b1eln7DIM/Bxj5
         ESJ26eyFh3X/w8gLHEMcygM5p06mxqb4XAvzbiyJ+1kzWIeJW11QwV62jx7GEejx65xC
         Rl88ajtlLCVWBs5s8JR684qzRRUISs16LnBS4YxsQQHUCaxrm7HdQ4Ug8OSZeGWGjaFx
         WYfYROWhnta2sHblBTgrJ1QuFIke0FO0JEYwasu5usUfRDJ+aQPJr2XR9Y6BWFjCj884
         yqboDZNlwDQT45o4QuTrdB//ZE9m8clg4htETZlE5lxIBEB5KktxhSkPEu/sp5urhhr1
         hU0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QJ21INgO5tdIHrMIVGZ7En6jr/Q5dYZ3g2c0oVdZj1s=;
        b=fiLfTFqAzMN98H5twzEYoUeATzoUdTbClQQ844XVhyBpLDpUqP1nBvbD+3zo4UV7+E
         7LKQpXQE16QqBPCXCxzjl8YLOuQNkizCcG0T4raBBPrEWTXpuJsRT8v738YNe07kN/kg
         dQbfjGu02x+eQC858LXadHHS/GPpxXqvRukZblDAvrxNS0UbwMDO60Qd+bPhxU18sJx+
         Uwb1WWT48wzlE8f8SSLwO/nU9WmrjKqJjjz4cEsbfLu4RVzFln0erIt2JypSMTKSQlzB
         EnDgsiD5ZbVKPGamkoyF3FKGpHqei/tbN7mDgss1FzpfJvF/hCWRVnJom1cdEGhnuZxX
         KX1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Hwrh58WypURxiL6OId0Of3paDvSQ6PuL9raLxUWdlLobAvnw1
	kaf6SnScb46azEi+sX4tTcQ=
X-Google-Smtp-Source: ABdhPJz6+OYXYShhAuEdqLWqZdAQP2Om/QUUlhn+oD7yQURdkPziINENMaHjQIMu6Q8DeBvS3QNixQ==
X-Received: by 2002:a0c:ef87:: with SMTP id w7mr18371608qvr.44.1612245151913;
        Mon, 01 Feb 2021 21:52:31 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:bec6:: with SMTP id o189ls9935178qkf.4.gmail; Mon, 01
 Feb 2021 21:52:31 -0800 (PST)
X-Received: by 2002:ae9:ef55:: with SMTP id d82mr20816856qkg.243.1612245151551;
        Mon, 01 Feb 2021 21:52:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612245151; cv=none;
        d=google.com; s=arc-20160816;
        b=N2YTY8uVdwjeqDOxFUsfZanduU4U8E0+Q9v1aFkXPb6VykBHeBCBIAiFTQuGkKQM4U
         BP4ljH4WY6L31LeqgoDQoNHWL9pEMpieCHP12XMw8W0cmEgkgN2KmH1WKfLfHxPZl4IY
         YhW6VJvaZ2ugqOIZO2T7PQokhqZ3qzblHwm3LKaKjmn7vo+bYszE+IcaoDxnblmqdBnw
         kFszjFWzFPzrusOXd+SOC9cBXN5lGSAqppICBthZZkxlo9OAHvXCG1O40BdXHguYAbph
         Qhty8GaXp5zxJ0tVgsaLhn5IzRuEmjw1tRLp3n8IyfFziPRsgiffkLl0l+Ut6Bn1boKS
         EKqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=eRsh6LsdrAZ3ZHfiIYChMhfWDacuVcarWVTcRd6TQaQ=;
        b=ivtkDyflb9NnB+ab5TVqLuCViIsqILFzxMRa79nj+Ic82MsfyDFbRUD3uVsG4nBQ2+
         nzM5g/eNcRkiPzybjB64Z7ewRy36gzlyHL5APM6B0pagmOrEqmjHF81GM++MYvXR/j0M
         4+koudvyxN6Mc45y++v7diRGCrG5cO/G04vbPWliwMtOW6twc4NkvqmQoTVf9jo0LFyN
         7U4xKY2VY+I0N7HJg7UlKqQn9Y0JF5k3kVU99FFvKb/IZZI2VnovvN3Pz9hFcM6DZqtC
         tWSjB92yVYIRjf2IjGtRs3oehmHCttBHhkICmRn3GpNOpnpKGjOsvzqK2eDOljLZx8U+
         Mh2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yang.lee@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out4436.biz.mail.alibaba.com (out4436.biz.mail.alibaba.com. [47.88.44.36])
        by gmr-mx.google.com with ESMTPS id q24si549366qtp.5.2021.02.01.21.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Feb 2021 21:52:31 -0800 (PST)
Received-SPF: pass (google.com: domain of yang.lee@linux.alibaba.com designates 47.88.44.36 as permitted sender) client-ip=47.88.44.36;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R551e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04394;MF=yang.lee@linux.alibaba.com;NM=1;PH=DS;RN=10;SR=0;TI=SMTPD_---0UNeTSgy_1612245120;
Received: from j63c13417.sqa.eu95.tbsite.net(mailfrom:yang.lee@linux.alibaba.com fp:SMTPD_---0UNeTSgy_1612245120)
          by smtp.aliyun-inc.com(127.0.0.1);
          Tue, 02 Feb 2021 13:52:00 +0800
From: Yang Li <yang.lee@linux.alibaba.com>
To: aryabinin@virtuozzo.com
Cc: glider@google.com,
	dvyukov@google.com,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Yang Li <yang.lee@linux.alibaba.com>
Subject: [PATCH] riscv: kasan: remove unneeded semicolon
Date: Tue,  2 Feb 2021 13:51:59 +0800
Message-Id: <1612245119-116845-1-git-send-email-yang.lee@linux.alibaba.com>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: yang.lee@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yang.lee@linux.alibaba.com designates 47.88.44.36 as
 permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

Eliminate the following coccicheck warning:
./arch/riscv/mm/kasan_init.c:103:2-3: Unneeded semicolon

Reported-by: Abaci Robot <abaci@linux.alibaba.com>
Signed-off-by: Yang Li <yang.lee@linux.alibaba.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index a8a2ffd..fac437a 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -100,7 +100,7 @@ void __init kasan_init(void)
 			break;
 
 		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
-	};
+	}
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1612245119-116845-1-git-send-email-yang.lee%40linux.alibaba.com.
