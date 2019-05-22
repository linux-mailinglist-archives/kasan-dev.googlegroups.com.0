Return-Path: <kasan-dev+bncBC5L5P75YUERBQX4STTQKGQE6QEQXHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E375F263A5
	for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 14:19:14 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id b79sf489858wme.5
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 05:19:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558527554; cv=pass;
        d=google.com; s=arc-20160816;
        b=Szwl40AtJNnLm53vKDubxBiE7uYiqMqmqQ/TUCrX4gVGrhWOwiHf1LPAezU80qNYNQ
         /KChs8WQokqlfYp+br3z3mlidQVg+R1EDzkXQPOzDd+OzZdw2zqnxn18A2cXuBVu9OnM
         QqhwBkrlqTPmfl4vZzYFoPqLijuFe9EUoTOU1uHBQldSIkGtKS33tLIvFJpbxUSby5Cm
         4uxbbbPnv25eE/+xao6nntCs8jrBM0Z7NMjHfQBOMBHtFIJ22Gtq3oqMhAYrZFUbzO9M
         8wpgB9Uco08+D+irCaZ7wSpqBkMXW05ObYjKKGrsnkNp3XX7/Qg1/tUXz3xb5mB+1m/0
         HGzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=bn9bf2OLFsePjW+iJ+GEU+xKS8LsT/SOr3V7gpOnAU0=;
        b=NCIWZ21Me3NrB7CrfH7848KuKR2ObY5qieAlXe7+V/KjJm5kyIm7yezTHJ0XD0dafP
         qYoOVCnj+0DGVnKKs+APPttt3LucEVTQp/yD+U2VjqBHdglFTESgkDbq2bBK9IfsliES
         K4Og3u5vp7spDkc4ykhQuvr9KoasidA1CDPkzeSicQJcthOlKLFvmzKjyOQG4T5UV2bG
         afDjS+gVfrbGa2TUk+Px1dubt7U7FywZxBI38Uz4Xv6Jv1kZtE9jkOQ6z4f/OmQEUnVY
         RFvVIUrvrVoZ1sKIlYkDBvKQ0Tz1AcAQfJ4DIl6pTtU/3PF2O6BvnkIpHpcdBD7lOn5L
         yeKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bn9bf2OLFsePjW+iJ+GEU+xKS8LsT/SOr3V7gpOnAU0=;
        b=tgQu/M+av4NyNGxcPJBPyby/wrzCFbhmbzAGzBAPnBK/WJu8WpRrTATPTLdj0tVxUs
         MZKDYZmJAGTu7UT5vmsfB9Emq5ZxCfAARDQTB+MfG7Xbz1yoc2aV9ycnlFYWAzBuqjN2
         k+UVBpWv6vyICmU9hDbEMSiHqZJ23f2vZYXKrwv6RltxFgP2dz3roGutd0LlV9OBXZhT
         9+3qaoFDKvh4fpxtSQAZimhUCG+u4ApjeMoNd8UHwfQZ0dqTR+lDRClI8Flhnewh44UE
         Gz28luALXVeckJ3XFoDZmDrCwlO8KNpAG/ObixpE6RTH709HSsaPzAY3RHTtFYw5RPQm
         Pelg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bn9bf2OLFsePjW+iJ+GEU+xKS8LsT/SOr3V7gpOnAU0=;
        b=Zb8Eirn4jS3WiAiCO95IjhRh3Nv6VMDwIzpxUomWsk84mVOUQ5orCk53T/sxgOFram
         qbLe+RtpsZhH0btu884sGtBH+Q47q9adAbYBpV2s7uZt645mHw166xP0Dx5/5k5hjHH/
         mZ32PpGGxN8wacFmqQT+uXtcCvBuXtOHnAH5/U6/c5OroO6zh2RAhmurhobs5rbPEeZj
         nSYKAL07TJ7TTX9tt4bMd9xoErl5vKQN2hjNtMLoe5Gp8phZ3xdfvqT1znRboo/IbrKI
         cvvdpGMkb9oXVyYw9j3ykj5AkFV4Z27w7YdShFwNCH65NeEoDwK5vEcsUFVwfFT4VDYb
         MBpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVX53rVEYAqDf18Wfg3E/Io06qAxI+tLtNPJw6VEQSCvlsA8jV
	E8KR0BMi3SpHRSjDUtBgYiQ=
X-Google-Smtp-Source: APXvYqywIIq77R+sHDFJEt32ezFU3mnAk9yLmX5Vx09k7/BQc4flRjiArSU7Zbuy+BS/EDvor6dLiQ==
X-Received: by 2002:a5d:4647:: with SMTP id j7mr19639625wrs.280.1558527554620;
        Wed, 22 May 2019 05:19:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2dc3:: with SMTP id t186ls63329wmt.0.experimental-gmail;
 Wed, 22 May 2019 05:19:13 -0700 (PDT)
X-Received: by 2002:a1c:e3c3:: with SMTP id a186mr7466590wmh.5.1558527553864;
        Wed, 22 May 2019 05:19:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558527553; cv=none;
        d=google.com; s=arc-20160816;
        b=B+2zz7GCZ3nUoxgj/RpGqn++siExCdCxaGglLDumvSM4ETs5YzmS0qhch1sMqmsCV1
         I0GQIhz9eC9AsCBuPVjVzBSNcQ81a2TQEVwjwVfAul75YvbGY+zKGlcz9p4EJiLQJ8uJ
         0BIZUzBat7O18+l8/3fqwtRJi97Fqxs30VU5z0nj3OHbg1ef7WE/Nd1jWG9Xe/nxrOkx
         dsX5pb9CN8085WfksPti34+3TZ+iRb4ZBbDUYV3UZO9V6bMX+k3DWUTQg3WiGe+KFekR
         L2B4vy8m+bOyRZ1DGsz1vj06YmaLBIfOYpa2mQqyiNtMgahsLqKaqDM1qqeYgSY11c10
         EjhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=+9fW0PRxz+4bfLfbCFiuVFbnUn0YIXpiH5KfbMS39MA=;
        b=R0SWrCeZTn9nLShOGJTO27p7KHKDgpuQV9qrWn2rTQO7fB4bw3JD/Kcedfi/InZX8S
         n7kgju6vrXmqYXkWI4oedHzEQESBTTI9Fncnvk0rsTf57c239Lf5iGq6MeDiHZiIt+yt
         wvBsUqPjDKmX960GtflpvqkIf6R1J30P4DM9MuksGdcg8yc4qmFPkg0BuDsZkr1EgYGS
         kE9v8MT6Sax4dam/IYFCwIceI9vcCTeoFMCv0egEAt/hdw14MxJKgFB/qV5eCig0IBFQ
         1VjZ/uiGX3b+RreTHTnlyFkl4LsB1/NT/CFpOlPZnvhV9stMYi1krU5Snv3KwjysIv9i
         OzpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id h126si349266wmf.2.2019.05.22.05.19.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 05:19:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.91)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hTQDA-0003Xw-1H; Wed, 22 May 2019 15:19:12 +0300
Subject: Re: [PATCH v3] mm/kasan: Print frame description for stack bugs
To: Marco Elver <elver@google.com>, dvyukov@google.com, glider@google.com,
 andreyknvl@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
References: <20190522100048.146841-1-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <e607a134-bea0-f662-2aa7-4755708c8aa5@virtuozzo.com>
Date: Wed, 22 May 2019 15:19:30 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190522100048.146841-1-elver@google.com>
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

On 5/22/19 1:00 PM, Marco Elver wrote:
> This adds support for printing stack frame description on invalid stack
> accesses. The frame description is embedded by the compiler, which is
> parsed and then pretty-printed.
> 
> Currently, we can only print the stack frame info for accesses to the
> task's own stack, but not accesses to other tasks' stacks.
> 
> Example of what it looks like:
> 
> [   17.924050] page dumped because: kasan: bad access detected
> [   17.924908]
> [   17.925153] addr ffff8880673ef98a is located in stack of task insmod/2008 at offset 106 in frame:
> [   17.926542]  kasan_stack_oob+0x0/0xf5 [test_kasan]
> [   17.927932]
> [   17.928206] this frame has 2 objects:
> [   17.928783]  [32, 36) 'i'
> [   17.928784]  [96, 106) 'stack_array'
> [   17.929216]
> [   17.930031] Memory state around the buggy address:
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198435
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e607a134-bea0-f662-2aa7-4755708c8aa5%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
