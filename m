Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU5RTGJQMGQEMBNRMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id F032150DAF2
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 10:16:20 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id j18-20020ac806d2000000b002f354e9bc9esf4612243qth.10
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 01:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650874580; cv=pass;
        d=google.com; s=arc-20160816;
        b=g+rKjzj0KUY4cslH7MzWmlzGGfjcBTomAZKePnzgILF433kRZQbNyYTzW54Rp19F22
         aLmONSd/3RWlRkijuYsTIo1CAX3DFyWnBgAFptLJrvE38gZ1yAeZXMAN55m5qB09sSGd
         KRKb1/JAj88L+ZCdSKY6vdy+ZwrJCHjs9XT+EuGS0LoSxixi4++LsVx4IrDhTLFWGrkg
         aISLwUcMzNQDfC/xjwyJ0/PlBFxpRV9qqWSvhjXNAEX2F3n1ZItEa8EYtUVg/BgNiNRS
         IF2wVhj7g+JnOfq2lHkRxX88sUp7AhLRljbYuZobGHxxIGNGDY0kWVPe43rRz0rOZ53U
         fUew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tzrtPuQOs+rnKPxGtzVp76NrOlP+SnZVDTYVdJnP9l0=;
        b=sQffXqFBwtaJnmQU/XYP7wECrGI1Bgo+X7DgezT61zeEAcvPRyNIZ+8YvK/vYDQYPv
         aJdN35ikWCpmjTJXkqsYoIkgd2Ao9io36MG16Pyx8z7r6uP6qRk+FCtUVOdr/DZmgXty
         Fo6ljZDz4H+gqu2kCexIflrBV9TZfOGwCyY3h2YbBsOpJFe3DGRUXeMJjKSeHwAg3Kmr
         9sAU/RREwpIAxgLdaSpMYZsyzc0powek545FNjVpU74DsyDIkul//hvRScoNLiktAx3c
         VjJ5GgE73asGLF+3UliuuF1p3b1lvB70Flxku4U6xXkcGEIacgMlha+cdsaZ0tFweITK
         nDbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BTqz5xSn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tzrtPuQOs+rnKPxGtzVp76NrOlP+SnZVDTYVdJnP9l0=;
        b=BuRu8fi9NbDGO2orMzS6U4UU1nSCl1hN4inzG2xEGDdxFMctYKKJ9xgs5t0Fl11bnB
         vKn1M3/tYLPxtUjukzva5VvtDEOu+yMSwkjgSiLK/DuWSViMFrFeEz2nkaGZPcOWql4D
         kfXfmKMUEIAh+17C7trBkbmDgZCB2bbc6okp2x8LkO81Yfqq239YJcmhJZrl1YCmnj16
         7Cmg3mFEy1wfgnG5YshPdQz1sD4vwyRHb1ijGDDIcd/bArT2JRd73pWp9Adz5OMArUQL
         JHHTjBUu9f6PIwFVEM+M2n2TFGyIXHfpIDC9NsJXiN4gC2W4xWhwrUqkdkYxc0cczUgv
         HCWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tzrtPuQOs+rnKPxGtzVp76NrOlP+SnZVDTYVdJnP9l0=;
        b=kDw5zea/yk/m1YlIhmYQfTdsGRel7xwAUMuluRVQLJ6tVujJzgYxZ5wVKi6TDW3L12
         DUxn8IgOEhjFY0ogDKys8c7gfAq3CVyWalsh9/79vQEEkpwZjcvWnYqqcanDxVCt3m2i
         cSrPJL8uK4GGUEy/VYhQuBdOnY2dd3TpFulKA6vDEe9e+hGvDSBuZjFNF46L7uvDc1rS
         aeqBLaCNUmGZSnaW654vM//GNvM0iVHnt0DGPMrzCzfe9meulbhw/MqRqillLYtWoY8K
         6ibOkc8f6hi0yz6uSi1jUAe8meA+3GkiJn+TDehGIL4ft0aey957KYNsFMzzEM+Pr3ZW
         PE5Q==
X-Gm-Message-State: AOAM530SZo7txg/GPNwZoG8Fw+ScWG620/T/X0lejTh+zeB/jf7yt36Y
	SLowNDvY9jB1yE/6T7AOklI=
X-Google-Smtp-Source: ABdhPJxPPf+i7ZDxvOUzB2MuUaRd51vpUIzyEPptmKrZvYCfRwDzoFbF8XGDnc3PlZ3f8iTReTskpQ==
X-Received: by 2002:a05:622a:406:b0:2f3:4f4e:a75 with SMTP id n6-20020a05622a040600b002f34f4e0a75mr11043219qtx.495.1650874579947;
        Mon, 25 Apr 2022 01:16:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2585:b0:44e:dd77:819e with SMTP id
 fq5-20020a056214258500b0044edd77819els4387703qvb.2.gmail; Mon, 25 Apr 2022
 01:16:19 -0700 (PDT)
X-Received: by 2002:a05:6214:f01:b0:443:a990:4ea4 with SMTP id gw1-20020a0562140f0100b00443a9904ea4mr12018014qvb.42.1650874579381;
        Mon, 25 Apr 2022 01:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650874579; cv=none;
        d=google.com; s=arc-20160816;
        b=M9MTX6hMDIRc23qIHwjizeEHhI8Zkwn9P0/ik2DJRLrssK4M2LREkhOncENqys34PV
         HU1KFNiZkJ1jpGKGKfO1zZftProDvMNbB+dVv4jcqlVKdbGq9HGqUeexpWaO9LJE7sKs
         iM2aUFqPuK8Q2l/YWFqxoc0k8YjTIiEaWWKr2V0YLtZUkB4+Yc+b5OG8Bt8h7t63b20X
         wCaqaxmUirLWOgZaxLtUy7wYK/Udvz6DqRYL5ZB08N3OOycVlUbAoW5Nd2lTBGpItkxv
         GKP6L1x432w15jvNm1Y221Fia2iVfbGwGJVzBNXQ7AewwRzsPT1+iOGpyYyBCVh/h7N5
         R6mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GvlUCJWkTnh5l62OzSLwcVwwIZnTQuRAwqmMP5qNiQI=;
        b=UvToRBZnmMiAICZwo4uSvyp5GszZSi9C4l3E/GEdlIYAC5GojUctKVN62vUVEdSWQ0
         QkORuNDb8YyjduJROcH3S+K/pKNNwmK/zfPHxUXH4vWGwtG0SPMQh1x9K0u9HYRs0foE
         RuMtWUd0S03NzBfRFlr7UUcAvUlobBdyzNa7aAgSmX1jrgx+56qrn8JakFtvY+/G2Wn6
         rEJ3KlRcIg6qETAcXStd6J5x2i4DsvnDSDNtZqYw4lDXL2Plz3kA1cVv3lNH8i9q8rY1
         Uc1L0oO2yXoKSkFrss4Cf+f10HkOnmbloENv/RKyR3c5/qZPc4YOjtIDJg+OPqdk8hj/
         C+yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BTqz5xSn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id h17-20020ac87451000000b002f36f4c45dfsi16801qtr.3.2022.04.25.01.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Apr 2022 01:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id w187so16234675ybe.2
        for <kasan-dev@googlegroups.com>; Mon, 25 Apr 2022 01:16:19 -0700 (PDT)
X-Received: by 2002:a25:9b89:0:b0:63d:20e4:13e7 with SMTP id
 v9-20020a259b89000000b0063d20e413e7mr15601411ybo.168.1650874578954; Mon, 25
 Apr 2022 01:16:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220424105949.50016-1-huangshaobo6@huawei.com> <20220425022456.44300-1-huangshaobo6@huawei.com>
In-Reply-To: <20220425022456.44300-1-huangshaobo6@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Apr 2022 10:15:43 +0200
Message-ID: <CANpmjNO=Qo_wnZ2CH=GqPzyUwQ3jGq_Z9FNQt+Sc_=1ZMV2PfQ@mail.gmail.com>
Subject: Re: [PATCH v3] kfence: enable check kfence canary on panic via boot param
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	young.liuyang@huawei.com, zengweilin@huawei.com, chenzefeng2@huawei.com, 
	nixiaoming@huawei.com, wangbing6@huawei.com, wangfangpeng1@huawei.com, 
	zhongjubin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BTqz5xSn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as
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

On Mon, 25 Apr 2022 at 04:25, 'Shaobo Huang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: huangshaobo <huangshaobo6@huawei.com>
>
> Out-of-bounds accesses that aren't caught by a guard page will result
> in corruption of canary memory. In pathological cases, where an object
> has certain alignment requirements, an out-of-bounds access might
> never be caught by the guard page. Such corruptions, however, are only
> detected on kfree() normally. If the bug causes the kernel to panic
> before kfree(), KFENCE has no opportunity to report the issue. Such
> corruptions may also indicate failing memory or other faults.
>
> To provide some more information in such cases, add the option to
> check canary bytes on panic. This might help narrow the search for the
> panic cause; but, due to only having the allocation stack trace, such
> reports are difficult to use to diagnose an issue alone. In most
> cases, such reports are inactionable, and is therefore an opt-in
> feature (disabled by default).
>
> Suggested-by: chenzefeng <chenzefeng2@huawei.com>
> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>

I missed one minor issue below (__read_mostly for param), but with
that in place:

Reviewed-by: Marco Elver <elver@google.com>

> ---
> v3:
> - use Marco's description replace the commit message
> - keep these includes sorted alphabetically
> - "in panic" replaced with "on panic" in title and comments
> - Blank line between /* === ... */ and function.
> v2:
> - it is only detected in panic.
> - it is disabled by default.
> - can only be enabled via boot parameter.
> - the code is moved to the specified partition.
>   https://lore.kernel.org/all/20220424105949.50016-1-huangshaobo6@huawei.com/
> v1:
>   https://lore.kernel.org/all/20220420104927.59056-1-huangshaobo6@huawei.com/
> Thanks again Marco for the suggestion.
> ---
>  mm/kfence/core.c | 34 ++++++++++++++++++++++++++++++++++
>  1 file changed, 34 insertions(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9b2b5f56f4ae..06232d51e021 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -21,6 +21,8 @@
>  #include <linux/log2.h>
>  #include <linux/memblock.h>
>  #include <linux/moduleparam.h>
> +#include <linux/notifier.h>
> +#include <linux/panic_notifier.h>
>  #include <linux/random.h>
>  #include <linux/rcupdate.h>
>  #include <linux/sched/clock.h>
> @@ -99,6 +101,10 @@ module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644)
>  static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
>  module_param_named(deferrable, kfence_deferrable, bool, 0444);
>
> +/* If true, check all canary bytes on panic. */
> +static bool kfence_check_on_panic;

This should be __read_mostly, like the other params.

Sorry for noticing this late.

> +module_param_named(check_on_panic, kfence_check_on_panic, bool, 0444);
> +

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3DQo_wnZ2CH%3DGqPzyUwQ3jGq_Z9FNQt%2BSc_%3D1ZMV2PfQ%40mail.gmail.com.
