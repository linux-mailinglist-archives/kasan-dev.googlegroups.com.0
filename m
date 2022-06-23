Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZFL2GKQMGQEC2MZJSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C984557974
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 14:00:38 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id w6-20020a05610205e600b003542828af90sf836683vsf.17
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jun 2022 05:00:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655985637; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xb8gdc3bvF7sWomeGo6Yhi3R0LJ6mACgcynN2jYYvI5SvlVqDjRZLeqy4/ZHwVlgvi
         FJrxEjF7eFb9rKs7VwraQmwB1aOTIcIEnoC+EI5ZALWrTJTpX/53lM7eYfELBL9qay/4
         D3enbRqX+4TPTMJmGuJ1KGk1j4vttkw7GmQ/TQJhsYmyCxxca/OG9Jd+EyZ06kqEwVme
         rL7hc5k8IGL8gBdzbBqxpkAEmrsBAnQodcErwW8RIRAVas6hjHBZrWgQdysF+Gks4KRN
         NXHfOnUGgXeH71obXXlMnwkkffVGSIKJJh6jPJXekdDu+vSVT3QfwQd1MImzkbbysuAy
         rHBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1UqQC17X38R+VY1ecxXgH/9SXw9X3Y2U6jup7buV768=;
        b=fH2frHy5lmq/Wi4Beo/qY65gxv5OgdE37R79/AF9vnkCI4JdtNMLVKBS1fL3T8tzPN
         CeuxjepiGFjdFDrHyfZEb/y8a2ksHLuFvT5GYqyCfaAAj46K6VuijI2JL4K464h9Io4x
         JpGMeG2s8VsyiW6IdQ9WKsYjuI24ZWUYk/9DZSC4qUAnOY0Qmi3GVf5B7Ac3x/818gZq
         cwiNFvTnj4+TrhUQtXTXa4KuPyDJB7DoZhtpocanHKv6sk9hK0Z4vqO2pf5d405Xhhs8
         R59oNkelxUX0BX2VrPFgQ21SrABAJOvQlbuxpsWZ3DS4dIEt9j3IsksIj5FRi9AHGJWr
         GjPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SQAHvCcW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1UqQC17X38R+VY1ecxXgH/9SXw9X3Y2U6jup7buV768=;
        b=FATSzodtF/FLwy4deWOisxmOQBnfuTfytTV/Be973+22xf3dY9Kp38N28kgdSPOV1i
         Ysy2FkSHvuNf0ok/PlOMjKRJF5E5irs3kHCHRcgTENPr3HlHNEnXvns3JJsKQJy5LB7J
         2M7gSlro4HEqBEClMUjJ3jGHiAH7ee/rt9NFiqVs8e1GbD5lHhm5I4H2puBoHpMXqI0t
         Iy7zQXSdYXBTMqcH9dbs0elauz+4Xd/RkfS1KuqfS3dyye0GnCE/vas+GykJzigoDlsg
         YhBHRWID2zAUZQC6ypSgwA5cvUsIueTN2aRcW/IfHvSSoVVc+ti+QvcwP0w989z8ymkf
         Osbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1UqQC17X38R+VY1ecxXgH/9SXw9X3Y2U6jup7buV768=;
        b=nkIgT575GMCe0+F6Tr+kmu1iItnADFNZlGEGTp/mytrIT/K8+3B9LUJKyAQrHSoezl
         EgV/JDaCxZCZVANmq1c9AFOT+m9F0WPvQtvqshsRYxqSMMNAfWXhdGoxDCrTPHtTdJF6
         s5mp53BJMMZQEbYLIO+oaoefdgMSez/63zWPSoWw/qk/zbV1jhy0mlo2GUO/XZYub4yY
         +sbdW6ylSMLlxImQOl6CUH6+yfdEpoLbGPO1vVXETd/ZvnpYFOCNHmy8vHvZ8et7+1j2
         joboVASsDcLKkB6PdsCKDSFNm9SWf9qYGK3xlSYP0yak6uSvFLQzhezW2tXfMYnOTdZ4
         up7w==
X-Gm-Message-State: AJIora/+T6r7xH8kdA0iqtgVoaGcKBxEPOG++tAHjsye4wjJut+nLILV
	BUjHuJK8CgR9LOkA3BmW348=
X-Google-Smtp-Source: AGRyM1vIEhvML6oGmZd5CnG04w69mwG1INQAFYj5rIS88rQeYrdRJUz/lBhKsoDdSlX/b2EDgpt4cA==
X-Received: by 2002:ab0:5781:0:b0:37b:de3d:5d4e with SMTP id x1-20020ab05781000000b0037bde3d5d4emr3897042uaa.1.1655985636963;
        Thu, 23 Jun 2022 05:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1581:0:b0:34c:3868:f9fe with SMTP id 123-20020a671581000000b0034c3868f9fels3740176vsv.8.gmail;
 Thu, 23 Jun 2022 05:00:36 -0700 (PDT)
X-Received: by 2002:a67:6ec1:0:b0:354:37fb:d77f with SMTP id j184-20020a676ec1000000b0035437fbd77fmr8952304vsc.37.1655985636305;
        Thu, 23 Jun 2022 05:00:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655985636; cv=none;
        d=google.com; s=arc-20160816;
        b=d0zQ9vhk/5q/ymYbWcewthwToYgtKBSX3a7naeJAgPRJhQypPWlp2gCvc9TSo77KfE
         rpjSOyXEyAtKFPtWNe4NcCKPQngfwDgoZm1tp6jH0heWtbJA7zqKJM8NYb8cGPJotWVg
         IhB5L3TVcJpA/S65AmRanXltFy9BF2agrvXQXAXQfzpX9qg0VLKrcCoW8GKPdff/3Gb2
         BgqRBZsvQNYQ3ZW8bF679AiIVHyOEgVIqwqbmMP/yR+o8/P+XgABvZasELUTKbcu2Lse
         UByFxWuxa3OfGyjt+BTucUvJ1YVo+DOwqQdyOmtv2dwRJs7h1q8gJXPp/7fbNQ2WFd3l
         tMvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ACxXBxS9wLm3s0o360W5tadVCtNgAfMCjbW4/7oTcA4=;
        b=xi81gUm73enw82hj8sNWnSnLXBqZ5QdBCbYaVb3SLTaWl93HBHM/VWwF4ZL3wOmxxS
         K9jhW7enuf1ElHXkne+tIySR2YZtKfSHQEqa9e5woVrmQ/ubcu8GapebQcrBmZ/n0J7U
         1JG41bNJqvLyrmqzywafbpZQmexXGsgHK8HoGszUacwvc9cXRBKgAZpQtKTpKAqIWWzV
         BoG36PNZZw/M5wl4xOtGYmR7hSuVa1AEllr+pC0Mv61Lkmn4Q7+gy2bXdXMlteco0+XO
         ScRgt09xBwD1cqFF1BVrp2mdQgIPNRuLQrAV3HKzXS4eWlZoR590J7Zw0qlU/bEhnspy
         u55Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SQAHvCcW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id ay14-20020a056130030e00b0037f13500ccdsi1336234uab.0.2022.06.23.05.00.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Jun 2022 05:00:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-317a66d62dfso130786807b3.7
        for <kasan-dev@googlegroups.com>; Thu, 23 Jun 2022 05:00:36 -0700 (PDT)
X-Received: by 2002:a81:1591:0:b0:317:bb1f:fb83 with SMTP id
 139-20020a811591000000b00317bb1ffb83mr10329151ywv.362.1655985635802; Thu, 23
 Jun 2022 05:00:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220623111937.6491-1-yee.lee@mediatek.com> <20220623111937.6491-2-yee.lee@mediatek.com>
In-Reply-To: <20220623111937.6491-2-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Jun 2022 13:59:59 +0200
Message-ID: <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
To: yee.lee@mediatek.com
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SQAHvCcW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration when
> the kfence pool is allocated from memblock. And the kmemleak_free
> later can be removed too.

Is this purely meant to be a cleanup and non-functional change?

> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
>
> ---
>  mm/kfence/core.c | 18 ++++++++----------
>  1 file changed, 8 insertions(+), 10 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4e7cd4c8e687..0d33d83f5244 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> -       /*
> -        * The pool is live and will never be deallocated from this point on.
> -        * Remove the pool object from the kmemleak object tree, as it would
> -        * otherwise overlap with allocations returned by kfence_alloc(), which
> -        * are registered with kmemleak through the slab post-alloc hook.
> -        */
> -       kmemleak_free(__kfence_pool);

This appears to only be a non-functional change if the pool is
allocated early. If the pool is allocated late using page-alloc, then
there'll not be a kmemleak_free() on that memory and we'll have the
same problem.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-%2BOYXpik1LbLvg%40mail.gmail.com.
