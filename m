Return-Path: <kasan-dev+bncBCAP7WGUVIKBBTWRUKRQMGQELCHYTQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id ADB0570A778
	for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 13:02:40 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6237c937691sf11029356d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 04:02:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684580559; cv=pass;
        d=google.com; s=arc-20160816;
        b=TyYGbsRZQ1+Jo/4w5QGj24atNxqHAEKcg9LFmIAFRp2p+ytBpX58jFDebu/l5D/ae5
         ai7vIeP+jC29qu+AbfsMZCirFZQJUcYcIEwES2KV1Dk613UC9hfjo1zyqa1XZvbQawv3
         kVWx8SEwwt0FkYu8lvLUbyTYOem0qzNiSJEagcNlWeezXJGt9B8KKhUEsp4H6MKJwtUz
         2w2ir5LzeIRqzqrYdYiX/FAalM2jI/J5taYjuXKz8xIayy1HuutSbLJlzRUEWyGZlLaR
         XTdhjWLP/m+5pyPA9zZXNgrl1xXMrkBJiUZckFCeqTLdxKuIIprO2rdtQteit1oprV5O
         7jkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:cc:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=zDRXDZtCaCJGCE1NZ0dvOwkPDW+ag2+r8L04nXXvun0=;
        b=PhCl1aysbCWXkHmHhyDK49IZpU3SPjlwqtrf9F5MsbkBSGltZE3rWnu1qrF4e/KtMG
         GoO8lx8/t/XDQYxcTUnw8uzd8/AteZJbJFIj3O94BZTE8Wo+ZKBO4GUH48N5H14Oc4Dk
         lbFeacVkj3VUxXPtW1K/ZtxSPAUancY3CkRpo24lLaLkqKgu4A8RQB9EJmXk7StjLbdG
         OTZ3Tu6JY/c8F5dER/yixqhn76XFNWNywRtb1AIfAe2U/n19nVVTk9460pampT7c1o0h
         l/+SpJJCWa2LnjJtEdg8hG+h4fY0uoSXLLvbKZQdDQfan4+ToeYb+w0QRUeqIH3qgmNr
         mNtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684580559; x=1687172559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:cc:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zDRXDZtCaCJGCE1NZ0dvOwkPDW+ag2+r8L04nXXvun0=;
        b=GD6g91xwl5XuuLtFwhmMcM6DmXgJW6UbIWp9n+Rf/ZlsV5qwDhDPyIVvRUkbzPvmdC
         vX9BNbKihs3hQmcwoPCoY/HXgitF09vw6DOR+Ry2WKyk23oeg7F+pq1x3vMmDibLtauI
         MN+foLTh9oKdTyYJuj38GkZeE3LD3qo8a102ko476ElQ8DzMbuYNJbMGgHeEYJkvSRFO
         uqxu6LZAZN9p+U6QX+Oc0dGHgmHlSTIMbRT7flusiNNnPOnfe65ly9a4FISESKUKkQN2
         PPouzbCH5K3R5s5o+Z89TCX5CXSa8aGfHBCpDtqjrX9L0f+Dhci/vrO/osHQWZ51q2V8
         YZhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684580559; x=1687172559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to:cc
         :from:references:to:content-language:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zDRXDZtCaCJGCE1NZ0dvOwkPDW+ag2+r8L04nXXvun0=;
        b=dgPN2nDyIgWPrccKpSvgWfcizhnUjWIhBioxeCJzK52XB4tPV4scaewEYGak+W8t+B
         f7NlV2mQenhEPEjXtOvz1A1TRfKhWx+ZOBT2vCsoykpZSV61GIbLlojjO8ochMpqX+PY
         KPhNt+FUIS/jK7Aiizq/oBHK1vFOdLJxjsqSySbv+uz2bkpFbf41UvWlLNpOXiuoDsMA
         Hm3XMZBNPho7YxoK2WNBwLyqrqNWykiGYSl3ImQHnI7xkRp43b3F3sLIx9uLwXfGEnWi
         gXCWpFuZYhCjpo0ewan7XXcPHQtHxLKfc14Cu+PUU6TXCXw43UO/yQIZ0L3wwYDv1Aiq
         v+eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxGNsmB32aHD1sJZEunbcmq5siPIPPB0e8Dpx8lqk5UpGbs3NLm
	U440ry8nOkVcJTUeQryRyPg=
X-Google-Smtp-Source: ACHHUZ5i38MsFclh5i5QFhOr/1WNMfaricEEoThZxxxRW+gfgV+To3/ZOkygJx8rEWIQOkPoGN8Dbg==
X-Received: by 2002:ad4:57d3:0:b0:623:9a31:8c1d with SMTP id y19-20020ad457d3000000b006239a318c1dmr916960qvx.4.1684580559414;
        Sat, 20 May 2023 04:02:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4447:0:b0:3f5:224d:adae with SMTP id m7-20020ac84447000000b003f5224dadaels4871245qtn.0.-pod-prod-03-us;
 Sat, 20 May 2023 04:02:38 -0700 (PDT)
X-Received: by 2002:a67:d081:0:b0:437:d7f9:741d with SMTP id s1-20020a67d081000000b00437d7f9741dmr530835vsi.35.1684580558329;
        Sat, 20 May 2023 04:02:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684580558; cv=none;
        d=google.com; s=arc-20160816;
        b=RxPz2d+8yWQqHpu27Fi7Qke1qmYwh9q73VLHz5K/Jiwp7D6e8qO9fwYqoD4iJL4ka1
         92gXeGuQVxDk1eLHfFz+rhVTR1UMJNSFcTo5GIyx1sF4PIE+0tzHY9NQj8JNc3bLB6ki
         sBkR+912QSvfESn/Zeu+gm2NqHczCtjsqRhSAGzyPb0hUu90BphPH/1DQ59plxUossDs
         jryqYd5ZSk1/lRoRJ5NA/5S3aX1376IFMDnMFo9rMnaja6K102L2X2xkpHD9cbpjkErT
         cZi/5gGmnQ++t7cE3nPhOx4Lv0VyAH6Nxmb1G7jEvugm1qpWALBIeoEfEF3EELlGsoI5
         uDSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:cc:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=UB87Qxm6VXCS3oKzpqVPOcl1eEVAXFIPzkt2NHVALW8=;
        b=lTMWhEo9yhr9Z3zaXsCUxvdhWQ3w0jSx56op4p4+QFkVUAvC4OASJw7rkOHEUxl4qN
         9xQmeZkpw3iuy442pNSh99D7sOFlAgTGq/hc8nY/Dy6wp1hOn8j9ObYOArOVcXQHb3NE
         xgpvRdK0SoVRmupMkgqT2UMJtlH+u0AgaE9TNMQL5vDDqf8Y8aBXsEA9p9T6EAHNTFqN
         pEZPBc6Rp8x4IJtWqzRWSrlbRmi2Z00d6n2Xj5sK9WFGWdPEIXCqLysW+wUM0TPZLQNg
         3CQxYNXKskdttK/v834cw2TqjQCN3qqqL+HrojehB33ihE3VSmTz1el+7w2t/9cwgueL
         aqdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id t71-20020a1f5f4a000000b0044f89ac0658si125382vkb.0.2023.05.20.04.02.37
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 May 2023 04:02:38 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav114.sakura.ne.jp (fsav114.sakura.ne.jp [27.133.134.241])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34KB2PZM022470;
	Sat, 20 May 2023 20:02:25 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav114.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav114.sakura.ne.jp);
 Sat, 20 May 2023 20:02:25 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav114.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34KB2P26022460
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 20 May 2023 20:02:25 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
Date: Sat, 20 May 2023 20:02:25 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [syzbot] [kernel?] possible deadlock in scheduler_tick (2)
Content-Language: en-US
To: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
        syzkaller-bugs@googlegroups.com,
        Mel Gorman <mgorman@techsingularity.net>,
        "Huang, Ying" <ying.huang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>
References: <000000000000cef3a005fc1bcc80@google.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
In-Reply-To: <000000000000cef3a005fc1bcc80@google.com>
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

This looks same pattern with https://lkml.kernel.org/r/6577e1fa-b6ee-f2be-2414-a2b51b1c5e30@I-love.SAKURA.ne.jp .
I think stackdepot needs to drop __GFP_KSWAPD_RECLAIM as well as debugobject did.

Like I wrote at https://lore.kernel.org/linux-mm/d642e597-cf7d-b410-16ce-22dff483fd8e@I-love.SAKURA.ne.jp/ ,
I wish that GFP_ATOMIC / GFP_NOWAIT do not imply __GFP_KSWAPD_RECLAIM...

On 2023/05/20 17:26, syzbot wrote:
> Hello,
> 
> syzbot found the following issue on:
> 
> HEAD commit:    f1fcbaa18b28 Linux 6.4-rc2
> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git for-kernelci
> console output: https://syzkaller.appspot.com/x/log.txt?x=1332a029280000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=3dc1cdd68141cdc3
> dashboard link: https://syzkaller.appspot.com/bug?extid=ece2915262061d6e0ac1
> compiler:       Debian clang version 15.0.7, GNU ld (GNU Binutils for Debian) 2.35.2
> userspace arch: arm64
> 
> Unfortunately, I don't have any reproducer for this issue yet.
> 
> Downloadable assets:
> disk image: https://storage.googleapis.com/syzbot-assets/f9e1748cceea/disk-f1fcbaa1.raw.xz
> vmlinux: https://storage.googleapis.com/syzbot-assets/6dea99343621/vmlinux-f1fcbaa1.xz
> kernel image: https://storage.googleapis.com/syzbot-assets/f5a93f86012d/Image-f1fcbaa1.gz.xz
> 
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ecba318b-7452-92d0-4a2f-2f6c9255f771%40I-love.SAKURA.ne.jp.
