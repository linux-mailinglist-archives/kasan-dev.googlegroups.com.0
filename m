Return-Path: <kasan-dev+bncBC5L5P75YUERB2PKUPUAKGQEC6PSN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id ED6564A3FF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 16:30:01 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id k15sf21562550eda.6
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 07:30:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560868201; cv=pass;
        d=google.com; s=arc-20160816;
        b=NUYltJQG1kwUT/+bmL3dg5+JbtfzZN7SMtGRh7N3nLJ39Gg60nbWswnFq0dOy8zCRt
         LtFoC2bSSZlLPmdidOukULdDbn8pl+rFCXrhoUvJ4O+39g7wIZSJ0y+Z6dTIlfjsfo66
         ZeN6Tz8Ix8gGh338bkWTPJLvfurLhZn5ZWU7xcFgjrXeqWcJ0NOvDWlqR5P+t1EfZ7dG
         33j/7uJmmZbOa2tXYiQTGmEgku2vtx3K4lJapPqYyd+rIo5dV91vxXxJSPnYT8RP05os
         jAI90zkgq67E4+86GAtREHY6/pMenlQ/fBaOVI25aNDPSiyqkHA4io0ijQgfIUFvLkyT
         AIHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ncS0KKOOmx3nxPLoLoq6mQR8t4pEnvYjRL33udA7IU4=;
        b=O5neFlDj6NaDIk/yfzary48e5gmNKMFyqXsR/ZT6HnBF9S6qbLVg+mpex5E8SQibqn
         8hMe81Nm2vOXeaTjcjwy8/y/DhERwfP1d/BtTcrkH+U7HUGQd4njKNrWE2qrZWYxW4wb
         9ojAn74k06wEn4CKLD+akACqT8sEo1NmNImTO/swpi0fATq3Lzybci+wVWqpw9BWe3LB
         XJn80B4ovzDuDX5Cc7e0O3rjszkAxDYfZsh1jVyBOqeEfbEeJWMAZwe999DVe7XhamZz
         /x9icbUhxlIHpzUCFhULdt1XwEWynEFvUU2KHyPNmSwLQNuP8uUuoquHu1Uc2bEmjyuz
         TlRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ncS0KKOOmx3nxPLoLoq6mQR8t4pEnvYjRL33udA7IU4=;
        b=WxVqE4O9AmhFfU10AOC8JJPLNCX+0Q31DvRzd1zYTkvdzpwoSD84tU34O+miYqjlCJ
         tKFLbKPMAlf1Mu8i0stnRqPjhyDRyGcJFer9/dMX5we4Zgew2YOVyz0ZLbfjaKw77XUM
         BC5p//aGjl4zdkj6oCbK5WaTFddoWjngdbtn5qBVsD2EnCVTNxCPZ2cDB7K1P02Hp8r3
         eiXQ2qY2lCL3zNeLEyp0Dryf3VehafUccirUNawk3HGvNDKnMcjMY+v8nrhkLI7hmpgk
         A95CqFddBtt+mMhYy50/IUqRSwkzYuyaOlNqJVtY4B4NBcqLog//8enTnmEb73bNKyMW
         6/iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ncS0KKOOmx3nxPLoLoq6mQR8t4pEnvYjRL33udA7IU4=;
        b=jengu+uYYfLrtiTiO6q8bYbbu5SXWvdJGSd61qg+dfaff9K7WXhQLOXvTn95VoqAW3
         PMMkEi/TASXKO32sHKkLsD3UXoiM8LcCYr87i1nq2DFX3EUo5BtvWXdpExi0jY+S050d
         K8c+UwYV5AEdXSOA68lRZJLbADeE6ciqpu+jgRMGgCl1dyOdWi/wcidE9ccCr0F8db4M
         Azozf4kN4Z/DcyQFib0w0FYEOtfSk9bJGrylGr6ZuAvhllxKza0g2sS6MkzXBH1irQiU
         EKjcbpptRnLmPjEtHwMzMnLFHExX2IHJC8hbNaPq86k1dfMRCNpzVh93huNPyMCMASKk
         wlZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX2OEwSHZfazWaPIncvAAZsJIhboOLsp+sHw0R2CQwqM8HvmgvC
	byNCbjavS41kPzrYDCELs7I=
X-Google-Smtp-Source: APXvYqzWov9pRpAy9b5lP6KOZL/YbXCRdH/Abnz+LKSf/fe8LSjfaHi3revkCXAH+o3RTRxXVGHi2g==
X-Received: by 2002:aa7:d30d:: with SMTP id p13mr43638344edq.292.1560868201721;
        Tue, 18 Jun 2019 07:30:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8975:: with SMTP id f50ls3210120edf.0.gmail; Tue, 18 Jun
 2019 07:30:01 -0700 (PDT)
X-Received: by 2002:a05:6402:782:: with SMTP id d2mr4754880edy.80.1560868201274;
        Tue, 18 Jun 2019 07:30:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560868201; cv=none;
        d=google.com; s=arc-20160816;
        b=rVJ8SJhBb7zOTnM39tYeUELuDNoNE1Zoh4ArLIzr9it8aVIDWKjdqTKJ4diklUf15O
         O5XnlsG3PLsvJYBSVPr9O/aeW5DewKApo7wjOpKB5O72PhGMBdtMXBr+ZuMu0VLWws8l
         VEzgIf7TaoPz8ZANuxmSC60ZoOZB5uGtP/+QCWs25WNSI1MkDrdtHvckzIjZo7CZvfhv
         fIdSUnHskqf9maRNp+qdo624b3ODg2VtdrN/X7B6b5lBRkHZGEFoJ+Nfg/Usfh4+YUvm
         xRAI+wJxDz2BrGXjbsLierN9Qmd+PhvME2EcfWqrG5h7JKGSzty5QxWDyLAdyqcMyXVM
         tktg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=hBJ+NpZhxOYKRrCNDnK4rIykmHUYap4lZr8Y18iy/+0=;
        b=Ko4c2prVn7tX3z4CfloeNeIJAGBsHGDY99avta1gZ+iUZrTeBBxEgOZ4QOwkYAA9MO
         cACCnBykMLBY09HxoL0bBZIfrKvzVdJgZWYNjSpH5ZzUNgMGUs23Yx30HOiLBieVFbuX
         +1TNpxFz6R3rZwzOsd5kP3DEzhKmoVLxGe7NVz7LLfA765jxf1k+GQdhtOFtPdcLW39x
         hLpqgrAj5qpViqW1SzGKRuhFI3Hob9KkisGDPZ7W/HPvqW1AzpwIm07Z/Tz23hyQHTQ/
         UdqZacGlQVGV6859Ce65W3LodoMweSKVyEbOGaiXDr6f2RA2T43JgU5cS+qbMKwhPNKv
         ch+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id e8si601441ejk.1.2019.06.18.07.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2019 07:30:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hdF7P-00025K-Kt; Tue, 18 Jun 2019 17:29:51 +0300
Subject: Re: [PATCH] [v2] page flags: prioritize kasan bits over last-cpuid
To: Arnd Bergmann <arnd@arndb.de>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Andrey Konovalov <andreyknvl@google.com>,
 Will Deacon <will.deacon@arm.com>, Christoph Lameter <cl@linux.com>,
 Mark Rutland <mark.rutland@arm.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-kernel@vger.kernel.org
References: <20190618095347.3850490-1-arnd@arndb.de>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <5ac26e68-8b75-1b06-eecd-950987550451@virtuozzo.com>
Date: Tue, 18 Jun 2019 17:30:02 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190618095347.3850490-1-arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 6/18/19 12:53 PM, Arnd Bergmann wrote:
> ARM64 randdconfig builds regularly run into a build error, especially
> when NUMA_BALANCING and SPARSEMEM are enabled but not SPARSEMEM_VMEMMAP:
> 
>  #error "KASAN: not enough bits in page flags for tag"
> 
> The last-cpuid bits are already contitional on the available space,
> so the result of the calculation is a bit random on whether they
> were already left out or not.
> 
> Adding the kasan tag bits before last-cpuid makes it much more likely
> to end up with a successful build here, and should be reliable for
> randconfig at least, as long as that does not randomize NR_CPUS
> or NODES_SHIFT but uses the defaults.
> 
> In order for the modified check to not trigger in the x86 vdso32 code
> where all constants are wrong (building with -m32), enclose all the
> definitions with an #ifdef.
> 

Why not keep "#error "KASAN: not enough bits in page flags for tag"" under "#ifdef CONFIG_KASAN_SW_TAGS" ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ac26e68-8b75-1b06-eecd-950987550451%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
