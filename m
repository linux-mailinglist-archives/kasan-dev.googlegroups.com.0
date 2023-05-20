Return-Path: <kasan-dev+bncBCAP7WGUVIKBBAPAUKRQMGQEUPF5GCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 729C970A78F
	for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 13:33:23 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-54f867d4624sf1113261eaf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 04:33:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684582402; cv=pass;
        d=google.com; s=arc-20160816;
        b=NeKUIz0pejlLjAUvAhivZyuqYSp3cMf83bfAdE07ury8TO52vzkFMLdjcqGJ2me2lc
         y4tO0zep69NqIKvTQQD/lfm/Tb0h1P8nFPpBiVcpPCsBPlDPBKyLREKSjCKGaUwyNcOt
         YJanjJFDHvrA8LqW2WtrAtgEXcIruOpIBeebHpMs6vR1/CvILs/yloJZHVqD1vqXNI/Z
         OVF/gXSeJWWJUnPQq06rKv90GgJwYD9gecjMqy9o3jVeYIZQ35kyrcsmXo0XnPJ3eyII
         lgFgoKEUhYnsJI7jBBo56qfwtngPZ3TUhGSl3SuhQ6kumJLQAyZm1c6gPqqQR/2bMj/i
         2qjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=0/OqG5AV/jFDCPaQQ31weyigyGS0tlZwWLF4aJ29+hk=;
        b=hllQHNo1QVGGPm4F0bRm/vFEXnGTxgObjxRAqvzHq/UXX6Vip/q1Gk58WNlPKckLnF
         2QBQp42+UKSm5/mnUalVy75zcGX4Nkx30FfHteiY8g2rom/uwXzin0ZJODMpvmwE2tKL
         cno5nTgbxGfwM0w7tN584SECHWAY4NsZRxscJQiFLH7zePJ+w727Vc8gGfQS7CUF6xIp
         3EWPtxYlBJSGZZEFcep7rTKB1t0ELzPvGTupxyvDB29dHQHm4XPeCdAeSCwoY5Bsok0d
         uo0V4kRNtaxaBhbT4fVA+5dWDsGnYH3Ih8cATzgHNKQihN3RqPl5jmqSjYREI1FEYnmX
         +M1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684582402; x=1687174402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0/OqG5AV/jFDCPaQQ31weyigyGS0tlZwWLF4aJ29+hk=;
        b=RnInpW3+Eg+6ZAZn2y89fZFCJ6DJsGUqBQIoppxE9z2TAX0u58SOTOnkXdXcm9GWjl
         c6jfBcFqebIKDCrmnPBC6u8S6pPBw6ZQ3eb5ojipiq/qZ8zbTOkmVMJO1PAnQbSfPZbc
         shxyMD8hp5o79m44Fyg+UZLCaDo8QsK4mF0nK7IRYEt2UtkXCjV4zIOAH77fwDiTM9hR
         K/+inXKZtVoCedOnb7l5mEpueIjZzlpyZl6vKT43dHoTvGv9CVPNUw+EWFOsxonPnpZ3
         JjZKCiDpH36INmmHzUwLucpHVg+O62mUhMRk2Mg0auGTlEaZ6DsC17ghy8biDsEKggQQ
         +KNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684582402; x=1687174402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0/OqG5AV/jFDCPaQQ31weyigyGS0tlZwWLF4aJ29+hk=;
        b=RNuNyONKiufHL8BpyzNtH85J1ksYOuFQpALjAG8koA5uWWdF7i6/noXlU98B1tEo0u
         DNOKdhzgd/LnkAQlQ9bt5AKavlxiUH4tVgKmX5ks9Fvpkxg0Ff5ZeEbRaou04TLmvcZL
         OUeflK+8CfLF2eXSp6JmH+b3R2NGORa6UkKTORFg4rnC9w88RZ8AasOQIzZ5dP3PyVUD
         U7JvKxXiDzGAw+bdVS3RrLEODOK6mWq93ED46CcHnLCwbs+Eq5NmHq/wnmjeFwm4917u
         J7u2tNVyeDbPm1CcUWnr57r6HdOrNIeJlcYSM67x586URdnoLq6Sx8w0R0M/4kTaRYZM
         dECg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyGzT6F4fRrUhBSCpv6llQKsVupdUPDZJUGyu3mTdZLfOhuSD9W
	B5IXzRVweiQxfUhW3QQvG3Y=
X-Google-Smtp-Source: ACHHUZ7VrRQ+FdXdy9kLQJPBUQiD9ysoNCkTK52suEYjPjsOzNVdpJl4jmrPHST81DAic1QhQZZSzQ==
X-Received: by 2002:a05:6870:9571:b0:19a:2452:328e with SMTP id v49-20020a056870957100b0019a2452328emr1389035oal.8.1684582402023;
        Sat, 20 May 2023 04:33:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:6b9d:b0:195:d294:2d3d with SMTP id
 zh29-20020a0568716b9d00b00195d2942d3dls1581459oab.0.-pod-prod-09-us; Sat, 20
 May 2023 04:33:21 -0700 (PDT)
X-Received: by 2002:a05:6870:3492:b0:19a:cbb:b3c9 with SMTP id n18-20020a056870349200b0019a0cbbb3c9mr2566012oah.4.1684582401330;
        Sat, 20 May 2023 04:33:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684582401; cv=none;
        d=google.com; s=arc-20160816;
        b=uaEHXgKbySYB10QL1gUyoBH336EHESBikZzJ0u/iXQjS67Fp+Arhz8fbxJz/3Z00R2
         FaSPyu9C6f8CoBRSeEdFdo9BaFYDJidZKGMTQDoRiDDWSku8VMGlhY8wBG/2gfxSphhf
         b/Za6pd+5EZ5r7wdguFXaRkcn0MaOataidMxviW7ptXXsGVB0pEeW6RMKuVO7wmOiamj
         aye2mS6SzMnjoQIEBr8fGvZv6gsaootwTs8LnFvIhC+uH/h0mWWx1yjoKyXD8vimwoCg
         p6miag3xN0Wg+RUI8gL7KxKBV8mtNMSbIv97JFY5+WW2mgvk5JymPcQ1cNobuUPcV5Wk
         4ZVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=uyy9//M3BwBqmLOoKOJh5JZwBZicGYDNipme9R6fLug=;
        b=i/6F6yVSXRi0LGeecFeZyfpeMJ/+mUWg5lq0mMv6jLrQt2P53nj/PVkKtqYgVaQsZc
         0aWiCwW9rATO0NWYcRpRvFm2cBf7fFrBB49Srapry2SnUJrLKpDVtS9YCb/QqYdAMvIx
         cUbhfrbDEsNvF2R+BC1H653M7hTzB47Z3E1E6qVtXdf/dlLOqosrf4Zr4XOS9BEkBqr/
         de1BuZD6mFmg15WrchZyZRBt+HTgzH55zFeS7AoS3cvP5XjjSDpC9T7J9oa6GoiJi037
         DqbLjWi4Kxv5ZjKKnfPHLCa3a6zL9aFfsaeNwDID1ba5C53DhSeAJuHrQ3BWwrhfL7FS
         8R7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id pv27-20020a0568709d9b00b001934f67653asi66475oab.0.2023.05.20.04.33.20
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 May 2023 04:33:20 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav415.sakura.ne.jp (fsav415.sakura.ne.jp [133.242.250.114])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34KBX4GB028805;
	Sat, 20 May 2023 20:33:04 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav415.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp);
 Sat, 20 May 2023 20:33:04 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34KBX4JW028802
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 20 May 2023 20:33:04 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
Date: Sat, 20 May 2023 20:33:04 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: [PATCH] lib/stackdepot: stackdepot: don't use __GFP_KSWAPD_RECLAIM
 from __stack_depot_save() if atomic context
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        "Huang, Ying" <ying.huang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
In-Reply-To: <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

syzbot is reporting lockdep warning in __stack_depot_save(), for
wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath()
calls wakeup_kcompactd() when __GFP_KSWAPD_RECLAIM is set and
__GFP_DIRECT_RECLAIM is not set (i.e. GFP_ATOMIC).

Since __stack_depot_save() might be called with arbitrary locks held,
__stack_depot_save() should not wake kswapd which in turn wakes kcompactd.

Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>
Closes: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Fixes: cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable stackdepot for SLAB")
---
 lib/stackdepot.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..5c331a80b87a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * contexts and I/O.
 		 */
 		alloc_flags &= ~GFP_ZONEMASK;
-		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
+		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
+			alloc_flags &= __GFP_HIGH;
+		else
+			alloc_flags &= GFP_KERNEL;
 		alloc_flags |= __GFP_NOWARN;
 		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
 		if (page)
-- 
2.18.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ca8e3803-4757-358e-dcf2-4824213a9d2c%40I-love.SAKURA.ne.jp.
