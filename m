Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY5CSWJQMGQENKYUEPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B13C50D210
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 15:32:20 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-2f4dee8688csf69232107b3.16
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 06:32:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650807139; cv=pass;
        d=google.com; s=arc-20160816;
        b=V67cd0AZ5SLSr0Pwo6Slic9GPWcKGr2RmpN1atBMknxcVIPPkd85kvhgs/0sWCcPsm
         DuJsI08VKFbFb8MXz/Ic+9BfpW9SD5nm48WtLViTR4jUF647XWVtQS+4e9NbSJRGVP+U
         enDPdhvEhY7Sg1wDd8CEbwbaCZqrQmc555/MN9PDc/+TyLfZqsxxUZO/srxM6rsUGezv
         Bls/tC5wczplIEuZ/G5/49PsI0teFrnNW7TDzRKTg8SHDz+qfbcNRz0+cCamc/EdIKBb
         1yD7/4VuUpbbwO9GOShEAt+ZNQI3QIhWv9KFPS0OWHQOUM7VfUbt5D7Xb1CJbbjVcUuT
         xFtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DNbx1F5hMC05qREh+rfmmlyJxgTvjjjSft4L2msAeyc=;
        b=mfc81Ouy77CWZISzIptn00mat4sHh7ql910GE8P+0psAqhB96bKm5ttKwipso2pQUM
         oJJQq47G+k2x5PNnGQUtz6n/RInjoaTdjmVowJO8sm+qVlnQAuM6s1aVZd3TYb4NK/ie
         57nSTa4OVIrfUncF0XxM30lls2zoda/99FQ83css0me3eIJZuh236gb93oo1qdERRLul
         Dmfdl8RjuZl4ktf70VC8RaO9WtfUT8mNuH/qrM4G0lUioWqfMcr/4b+836vKDBweIDwQ
         dGOpLXpjAutdhi2k2cHRP36w1euUbR6qKbep3qnx/GsmKMSh8k4ciIg4u7uyZB02a22I
         eTNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qca+pRIJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNbx1F5hMC05qREh+rfmmlyJxgTvjjjSft4L2msAeyc=;
        b=bISTB0nvNKYkg8iTq6A8/AxYltqKcPc71n1bMw339grthJ5FSFw1u6gf3tmPCVzbhN
         oFtuyMEFs7LdjyqqCecer6VErdRUQB/LQ+UOl12YrIslos3EZOPnKcqmCcP1YYB7b6S5
         NpKgv9UYlLLbSiIuRQffALnY/tCaGvcnK6x7VisFhM9TeerS5CIEMdUcnB7d9dvhyfEc
         BGEFi0SYsa4tfilnSZ58n/KQJ/niog1RKmlq2FrxoOb9p+MuId0WOLO8klfiucIrP3DK
         Xezym7nRmp7fEmyi3h3uaM57gpoayR5daXP7RKkPwi6FLLRpJ7UsRCqMw+t6pa7784SP
         rrgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNbx1F5hMC05qREh+rfmmlyJxgTvjjjSft4L2msAeyc=;
        b=4LjGO7nVrZfsQBV4EiW/Z+gQ+XQrkH3lNHoiU3L9wzaiNilM07ef+PEuCtYQiuI2R+
         oxe+G6wmCMV8Oy8iY8DCKXvXDtP3Vom1tBGctiydkBERepIH2nxBhMIHSCjHElN1DfhE
         NwyTsHT6RBcJwRXVkdG77jMEnxpncmaQ7a7ynEP07sYyWLraSJno3mZTbk9GMbpUGnjI
         22/9ewyfYyvR6KVPv7ILERoEukP1uO7tWIsaNqm/k7omHJKIl6jei3Hjcb4RXS0oINxl
         F6Jvu7+s7NwLsI5DIySrS63m/ta2u2WiIAUXyiKhl6RZmOk9NxaXnuqnsskzWoOYnk66
         eAmw==
X-Gm-Message-State: AOAM530yHBe3GmJmAtzX5k6ne25KWyK2lZ05We9DCbpJfddDTBcRLXgl
	dUd1UAluG+3rjjG0Yh7ZIQE=
X-Google-Smtp-Source: ABdhPJzPMzt3zSSrROtJo1RsZaFFgyxidIlR94WuMrpIPSaiSTEju6ncq7Aoh3PsR/y+aFPwBRkqWw==
X-Received: by 2002:a25:ec0d:0:b0:648:480d:7c08 with SMTP id j13-20020a25ec0d000000b00648480d7c08mr3541324ybh.206.1650807139169;
        Sun, 24 Apr 2022 06:32:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d54a:0:b0:2f7:b5e4:751c with SMTP id x71-20020a0dd54a000000b002f7b5e4751cls3107894ywd.5.gmail;
 Sun, 24 Apr 2022 06:32:18 -0700 (PDT)
X-Received: by 2002:a81:2f90:0:b0:2f7:bca7:3447 with SMTP id v138-20020a812f90000000b002f7bca73447mr8202260ywv.446.1650807138523;
        Sun, 24 Apr 2022 06:32:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650807138; cv=none;
        d=google.com; s=arc-20160816;
        b=JTyt9zQKiKpMmOCUbpH+vALaPYb7Ckr0VmRjgKMOidgLiI/BPz2CGh1YHwIQfl1TWU
         Dej6N5FjLkoGf+iNcdSU367uNej1HVn6XGmwZsXBiKkaTJ6rpj3jNua+M0qJIw/Duk7p
         6ya8nOWfeac6nLisEFLch1Rak58IKmHZlsfzN6rwSsi2LCrVbSZ1oErzJlxZGRA4+BT6
         FKqvrLB4YpHUSW5Chn4Cgs1pVNmURziZH3m2l2YFcw5u0kDPiuqLKFoWRKqa3zAE6rjA
         JLuvZO+x/Xunj0qXOmQLp9zQw0ItGmPDaGvuIwauAGPc+PJ2lvAk70cVEXY9He+1Ve0Q
         5Wdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IRmaRiNmR93d3ALdKPyXM8y47NNkfnslNRnhmG/iMDk=;
        b=RljM+r85WYYG32qhupqk/IZwQqycvd8T94PPjeOcTV9ew/TeWhV2G8JIF0fzsB3t9D
         pYLO3/NK34rxZ1KRZacLDo1sN9rOAKRIE7H/IyuBf5n9RSW0/OVDEvfp0jU7GjNqIyTW
         EKiaq6xDiCUB1bZ1704VzFGnkY6aznKsJidsb2uVIIbWGviy4FvUZv/Qx3Mu1sx6dYXS
         ieg++u+B4+8A50us2/bJanjunNK5GdVEwn4Xvd2gzpIzfm6Ey7f1s2HCCwiPoJP+EdzK
         eeupNUXy/O1XqHI5jETYnm1BMoJCBpit9+5lsK8QKarCcnqamkKxqYbXnn1Cxs6RN0Yd
         cjRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qca+pRIJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id r198-20020a2576cf000000b006483d0ae0c2si323297ybc.4.2022.04.24.06.32.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Apr 2022 06:32:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id m128so4717294ybm.5
        for <kasan-dev@googlegroups.com>; Sun, 24 Apr 2022 06:32:18 -0700 (PDT)
X-Received: by 2002:a25:cc0b:0:b0:648:4590:6cb6 with SMTP id
 l11-20020a25cc0b000000b0064845906cb6mr3692673ybf.87.1650807138108; Sun, 24
 Apr 2022 06:32:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220424105949.50016-1-huangshaobo6@huawei.com>
In-Reply-To: <20220424105949.50016-1-huangshaobo6@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 24 Apr 2022 15:31:42 +0200
Message-ID: <CANpmjNPEErc2mZMSB=QyT3wq08Q4yGyTGiU3BrOBGV3R5rNw-w@mail.gmail.com>
Subject: Re: [PATCH v2] kfence: enable check kfence canary in panic via boot param
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	young.liuyang@huawei.com, zengweilin@huawei.com, chenzefeng2@huawei.com, 
	nixiaoming@huawei.com, wangbing6@huawei.com, wangfangpeng1@huawei.com, 
	zhongjubin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qca+pRIJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Sun, 24 Apr 2022 at 13:00, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>
> From: huangshaobo <huangshaobo6@huawei.com>
>
> when writing out of bounds to the red zone, it can only be
> detected at kfree. However, the system may have been reset
> before freeing the memory, which would result in undetected
> oob. Therefore, it is necessary to detect oob behavior in
> panic. Since only the allocated mem call stack is available,
> it may be difficult to find the oob maker. Therefore, this
> feature is disabled by default and can only be enabled via
> boot parameter.

This description is still not telling the full story or usecase. The
story goes something like:
"""
Out-of-bounds accesses that aren't caught by a guard page will result
in corruption of canary memory. In pathological cases, where an object
has certain alignment requirements, an out-of-bounds access might
never be caught by the guard page. Such corruptions, however, are only
detected on kfree() normally. If the bug causes the kernel to panic
before kfree(), KFENCE has no opportunity to report the issue. Such
corruptions may also indicate failing memory or other faults.

To provide some more information in such cases, add the option to
check canary bytes on panic. This might help narrow the search for the
panic cause; but, due to only having the allocation stack trace, such
reports are difficult to use to diagnose an issue alone. In most
cases, such reports are inactionable, and is therefore an opt-in
feature (disabled by default).
"""

Please feel free to copy or take pieces above to complete the commit message.

> Suggested-by: chenzefeng <chenzefeng2@huawei.com>
> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> ---
> v2:
> - it is only detected in panic.
> - it is disabled by default.
> - can only be enabled via boot parameter.
> - the code is moved to the specified partition.
> Thanks to Marco for the valuable modification suggestion.
> ---
>  mm/kfence/core.c | 33 +++++++++++++++++++++++++++++++++
>  1 file changed, 33 insertions(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9b2b5f56f4ae..0b2b934a1666 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -29,6 +29,8 @@
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
> +#include <linux/notifier.h>
> +#include <linux/panic_notifier.h>

Please keep these includes sorted alphabetically.

>  #include <asm/kfence.h>
>
> @@ -99,6 +101,10 @@ module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644)
>  static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
>  module_param_named(deferrable, kfence_deferrable, bool, 0444);
>
> +/* If true, check kfence canary in panic. */

It should be "on panic". E.g. "If true, check all canary bytes on panic."

> +static bool kfence_check_on_panic;
> +module_param_named(check_on_panic, kfence_check_on_panic, bool, 0444);
> +
>  /* The pool of pages used for guard pages and objects. */
>  char *__kfence_pool __read_mostly;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> @@ -727,6 +733,30 @@ static int __init kfence_debugfs_init(void)
>
>  late_initcall(kfence_debugfs_init);
>
> +/* === Panic Notifier ====================================================== */

Blank line between /* === ... */ and function.

> +static void kfence_check_all_canary(void)
> +{
> +       int i;
> +
> +       for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +               struct kfence_metadata *meta = &kfence_metadata[i];
> +
> +               if (meta->state == KFENCE_OBJECT_ALLOCATED)
> +                       for_each_canary(meta, check_canary_byte);
> +       }
> +}
> +
> +static int kfence_check_canary_callback(struct notifier_block *nb,
> +                                       unsigned long reason, void *arg)
> +{
> +       kfence_check_all_canary();
> +       return NOTIFY_OK;
> +}
> +
> +static struct notifier_block kfence_check_canary_notifier = {
> +       .notifier_call = kfence_check_canary_callback,
> +};
> +
>  /* === Allocation Gate Timer ================================================ */
>
>  static struct delayed_work kfence_timer;
> @@ -804,6 +834,9 @@ static void kfence_init_enable(void)
>         else
>                 INIT_DELAYED_WORK(&kfence_timer, toggle_allocation_gate);
>
> +       if (kfence_check_on_panic)
> +               atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
> +
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>
> --
> 2.12.3
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEErc2mZMSB%3DQyT3wq08Q4yGyTGiU3BrOBGV3R5rNw-w%40mail.gmail.com.
