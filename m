Return-Path: <kasan-dev+bncBCAP7WGUVIKBBYEPUORQMGQEPO7WNJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9736B70A848
	for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 15:15:13 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-19a662c8ef9sf872163fac.3
        for <lists+kasan-dev@lfdr.de>; Sat, 20 May 2023 06:15:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684588512; cv=pass;
        d=google.com; s=arc-20160816;
        b=AlzMFYHNp0VkjkNDzb4RdVi3m7coBJg9d+5DUGMGYFcsmmpDEoeq0tt2w4aprQzTyO
         XYkP0+umcqv+GyPUa0zXVPc/XxKLc23ZdioDS4Ofo1Iuqkq+0eISFsmPaEnyPj8C4ORJ
         J9saT4WpEPymmu2hu7NF8CPdr7rTu05+fhgN02IuCZHVLk5FSBdxE5RucrwKQ2RsnOei
         gMAHL0+w/68ABPWdn+1I4r2UI/lPtUDn9Bi8D5qeblJHXppkKX8efkrCrUcccbqobpSV
         kkM+CrjLOSQiqNKmKcve2Uc6BnOjogfY6VGncU8RGLm0rE+ts2qJ3fUWhbSMreSQbvCf
         jV4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=gkk9OJDkMx2JmkEy+Bq15c5s4fiexCHN8XpOL6E0cHk=;
        b=DXVwfGRpDO3lm2KibSPMI208fbJYe7f4k8LmzQzHj9i6HeC9uHb19YEnavMJ+aw4ef
         FIVjWRE7YCmJHq24kjGlDCIc5eKRWl9w7xKmt39JwklrlfxgVXccPXK4SgapCwxfEhf8
         aYXwqeBsUt+DLIpHl/lZe7oLytUPIzRQu5YH3SUmSgrSkUI8/3cgGpdj7xVxU4j6Ci4l
         juQSRhkKI8EPyr1z9FXSKuGFQ+C3R3FGczgHMPjbjXPBzLByYBRCu/7lj6DXxAFomPX1
         LVUeXPXWbKmScVlupDw1RFSGHnUE+vtsoVY/kiCvGOKL2SENfYMuqVIFUVBe3c/U4yN8
         mogA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684588512; x=1687180512;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gkk9OJDkMx2JmkEy+Bq15c5s4fiexCHN8XpOL6E0cHk=;
        b=LT1IZRLyshxVN1wDmfFGN8DBDzl8Y0GWHwsOfxgIlyGLLjqLrFIXRrngNF17jDeD5D
         PxiwKJT5ByPtFYeRSCjOOwGEtMrl4Yd1fsGcD4RJSyM/VdjOIe7nR/PeQUsuY94+g3wp
         QeGXmdnkS2eZB1SSL7OjUrmxkVFl02gVpdHvMJxD1yCMXSAgRVuh22FL0e739oLVXPA4
         beXVL0vv1nTak5B/8eVZ3p+wg3s1vdwczBUParPFaZ4/i+SXOkdI30aYiDNaGlqln3Kr
         Ny7NL89LWogY7EXqd2nCA2xw1CODFiHKu0e5y9C0/NOjN6DfcXTsio8s1/ZkTBWDaCjT
         KWag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684588512; x=1687180512;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gkk9OJDkMx2JmkEy+Bq15c5s4fiexCHN8XpOL6E0cHk=;
        b=Vntz0NVj0WL5SSJ2TwP8I6tszQF6H3QJNhVzmghYXbnTLc9Yy3N+0wRgd62zXRurVM
         VIqJBAxCqgCvMgRG0K2xtISd2oa/chEDeJeP24B2XMJRGk5zHrfxOkFRT11PexeS3FST
         SHJJaksycwwCsWJzGOflQT/wMYNEvfvBZLNaKlAzrAN62PZEWy+UsIOkpjjApV3Yz5Jb
         lxaiPdvzlqAI108VKVegZpXMA8OCDgFgQppS4M/vU7iFM6a7O8WmFiDPRhBCsMaoydsR
         f6en0do/gJZiEGBJszjKT3mmjC3wknxeUWSdBx1GLJOM0eO3zcBnBuheTrX9yfPBBCbM
         xfng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw97Ww3HHzPUbrg6MqyRWGXCs4NJ1zRd+1ZrAIFcuIzjyQZm74Q
	gzjbu8yLO/DwGfhkCqDgvQs=
X-Google-Smtp-Source: ACHHUZ6H3FFqF6Ph5+4D4eKKhJdk5xw51amzhSsnlAAWwKUhKS2JpgbfkEM5jA6hYMmZdqv6vo89oA==
X-Received: by 2002:a05:6870:7a10:b0:192:ad93:b17f with SMTP id hf16-20020a0568707a1000b00192ad93b17fmr1927107oab.4.1684588512354;
        Sat, 20 May 2023 06:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d043:0:b0:54f:f848:3950 with SMTP id x3-20020a4ad043000000b0054ff8483950ls2205534oor.0.-pod-prod-03-us;
 Sat, 20 May 2023 06:15:11 -0700 (PDT)
X-Received: by 2002:a05:6870:8c26:b0:192:a274:3280 with SMTP id ec38-20020a0568708c2600b00192a2743280mr3694101oab.24.1684588510990;
        Sat, 20 May 2023 06:15:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684588510; cv=none;
        d=google.com; s=arc-20160816;
        b=gKMAkZfFQSLLxfH0OuFzoYQyEi98kt/5cugjox4poRfVn6zl4RtSa9l4HHnqIITNqt
         syJueS6xrQzNnQ1MN+yVvdl7oZmh6Gs6IBabivF/bDPjiS3AMnqy6oaZzJdjuFpMvyVi
         KITvfO9CFRaA8OwgvKZBQa0s5SlVXsfRma8lWoPkv9/Cbf0ymUoZgfIesSKdjlyyysla
         aO0pNq1/2ZicGRJwfKuPPyqIYoE0PDw6HfbXeFLxRXkx8IIXjX0BGAWRMEVn13DCqRXN
         ZWIcPe2drahjGBYI2ZxR/utzI22nIaMoEvhdvtdGkUvmu5x/JUoAFd/SWvLs7E13P/QS
         QlsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=9mz7P0EQo3p6haHvh5dWMU2NhC4jfyI0Lxc3YnNkFJ4=;
        b=mPRIQFbs+ho/HaJWNam1xDUaQerB+wpgi2dNlAHx5XTFao2aKAciiqgvO2mGC3eEjS
         ZL3A73ijzPi8WWbyT7eYy1xm6iDnSSMXtGInnS+5KUl1wN9yLxF0DRQ0DHCk2KlGf0ff
         lQL0z+l5HwElreLk1Vy1/E+GXWpP12ac2YnviNdL9AUYfo8qKRRD+bCt7649KjbB8N0Y
         O+/rGBtfMN4dTmEFh8tbGgsfKwzG7OxKbA0mxTEVU0eKYJfZw1T9ULb4DhpujKd+97UC
         rRhgviy0eo/Rmc47B73bCk4edR0PB0UaW8kXEVe4tGjuX1qfjfHlUFVhmnAyueWA5EKH
         EmsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id pd18-20020a0568701f1200b0019a232f5a23si100402oab.4.2023.05.20.06.15.10
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 May 2023 06:15:10 -0700 (PDT)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav116.sakura.ne.jp (fsav116.sakura.ne.jp [27.133.134.243])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 34KDEsEQ048495;
	Sat, 20 May 2023 22:14:54 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav116.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav116.sakura.ne.jp);
 Sat, 20 May 2023 22:14:54 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav116.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 34KDEst4048492
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 20 May 2023 22:14:54 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
Date: Sat, 20 May 2023 22:14:54 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
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
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
In-Reply-To: <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
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

On 2023/05/20 20:33, Tetsuo Handa wrote:
> @@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  		 * contexts and I/O.
>  		 */
>  		alloc_flags &= ~GFP_ZONEMASK;
> -		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
> +		if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
> +			alloc_flags &= __GFP_HIGH;
> +		else
> +			alloc_flags &= GFP_KERNEL;
>  		alloc_flags |= __GFP_NOWARN;

Well, comparing with a report which reached __stack_depot_save() via fill_pool()
( https://syzkaller.appspot.com/bug?extid=358bb3e221c762a1adbb ), I feel that
above lines might be bogus.

Maybe we want to enable __GFP_HIGH even if alloc_flags == GFP_NOWAIT because
fill_pool() uses __GFPHIGH | __GFP_NOWARN regardless of the caller's context.
Then, these lines could be simplified like below.

	if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
		alloc_flags = __GFP_HIGH | __GFP_NOWARN;
	else
		alloc_flags = (alloc_flags & GFP_KERNEL) | __GFP_NOWARN;

How is the importance of memory allocation in __stack_depot_save() ?
If allocation failure is welcome, maybe we should not trigger OOM killer
by clearing __GFP_NORETRY when alloc_flags contained __GFP_FS ...

>  		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>  		if (page)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48a6a627-183d-6331-0d8d-ae4b1d4b0101%40I-love.SAKURA.ne.jp.
