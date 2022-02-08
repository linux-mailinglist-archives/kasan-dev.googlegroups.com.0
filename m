Return-Path: <kasan-dev+bncBAABBP6ORGIAMGQEGHKSG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB284AD871
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:13 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id bd15-20020a056a00278f00b004c7617c47dbsf9727963pfb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324671; cv=pass;
        d=google.com; s=arc-20160816;
        b=OCjQhnQHVva8I61Mai9SRWmBmN2KYQv1Cc9iOwWQGsW8Pi7OKCEROSQWtDtvAZbbhW
         9B6u4NquY1oakodW1yjqaN8UpYEdk02/UMjurWKKuXToIVLvTjy4zO2lK1pScn1m/OQn
         ED6bN09nGu0JP/UjIQpP6FnXXqGji0oGw48p4xQ3nqmH8aKcoImZArscmXvoVyCnjzDo
         AmH4v31uQ7ulvux0jAZftt7IjuHfS3zdR8+Q83t/6LfvZrkq28cV2+d5KL8tTo8cakAD
         whY3z/suwsOaKb7Onk9yND2Q6fBmSO60dV/Qn/TndR/WXS6MVADCStuPiFM1KNtPlPbn
         fZgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=JGKMZNMdgqdctiIeCBGul2CzSkP5eEmoyZgCCNCyWZk=;
        b=mioXEQemZuR4ANni36liBQf5E1MEtcxZWUDSrMMApUnhzf55FnYNiN2qif19kRYq8R
         Wei7EjSCrRvAZ7ggslsoB5cYmqlzIXvoAr6618ulchXCBMaPEyKLPWWVarh7XW5wlBo0
         /7xE1aCgR84qIdp6mq8yeQJVdnV/W93iXoyARN1HpzzVuPefvnK6PqzdI7UdQTFC5mt+
         R10SL06KEvPXprSHDMqnJL4TXtFJv4g1v3yIXL0V6HotkkfKzDrg9N3p4a2wOyDkDJIf
         jcwKVkl97XVK9dQiFSzNpH69Y7XLPVH+afmNc64ydW4ZXFdxrJBdEaWjHY10HzfF1nmv
         5l7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGKMZNMdgqdctiIeCBGul2CzSkP5eEmoyZgCCNCyWZk=;
        b=bdvPwQxNam0mHxQTFXzR/El0kqZMwCvxfyIoyRrjamJ/MX/OrbiOoM55stNpO2bfmM
         ENLc1tqItu7hS7Ga5ialkYIGmT2hImHH87UF4K5B7u14+JD2OPh1dvSQTw0gujs/xu58
         1pha38IOqeWURo28E564+sA8gV8Z9AeeAbm9v1xz6Sb1crzLn9Ben/BjhhE05XpQnf2l
         C85MI6RJuZnrjivGLpAoR1+2KahrGeiRGLxNOG/UV0Td3ozo38yR7w+j23S8Mm5B7IXv
         rbkxDqNfGirFTutjWlyvekoZR2vMUoGPVHa9D+V+3rkZcwY3j+UuThPh2mbzK5CdnWcR
         hB4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JGKMZNMdgqdctiIeCBGul2CzSkP5eEmoyZgCCNCyWZk=;
        b=35q+VVlfMLfmBaaLNDJQjkId/J8V9E5QIs5OZSxTaxRN9jEfNT0u65fJn/CHEX2KzP
         JFioxY2lni1WWFCXvi1TcXIWbK8QDktHAMpF1ngx03fnP4SIBQ6kAWqANQyizPfwKhIi
         Mw1OkVN+ODfofQuev5HBLmTxXxpOa6NwQAEXFv5RAA7MFspIVOJCnzXbE52fN3W1ms51
         EsIiBMvl/M3q62MQLPOfsrZXQ1pz5SCY1ibxPJ04bgr8r1Zb6lZ1IfzZcUzoNiHoD9Ok
         xlHEq5fe77YNPZbGgtFa+oX12Bxt1e6IfbrUgC3J+0PRk42UEAEdgHKOJtNe2MG0q7Tw
         H45Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533m/o8OJqtvcAskMcqfX4GLjTjPHbKg0yH/mrgBeVBGsPOLwAdW
	7xKdbsuHf9YKhd9LE6quycw=
X-Google-Smtp-Source: ABdhPJxEe8IFtcDTt0SMUvY1IeKqvuqmFALJAGcB5vJzUyYBZ8FEjwFJv4CJfkdCktvlFfO3eAzhTA==
X-Received: by 2002:a17:903:1212:: with SMTP id l18mr4507832plh.7.1644324671565;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2295:: with SMTP id f21ls5878859pfe.0.gmail; Tue,
 08 Feb 2022 04:51:11 -0800 (PST)
X-Received: by 2002:a63:2cd5:: with SMTP id s204mr3386811pgs.218.1644324670982;
        Tue, 08 Feb 2022 04:51:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324670; cv=none;
        d=google.com; s=arc-20160816;
        b=NQbJ+02nepWgMj6hnqyylbe1B7+/Of7WqOpiaAXjbikrN79J87yDMlYA2rG0zCEeB4
         9WKxsKOKMCDKleOaBpbMNs0YAwwc9orTpC4sp5CavwhnrQIKU8ObTMpQRIA/+HhhCR6z
         KF0MA6psfZxITgpqKOzFtzDzZpwMZT9AdZRzJqoa0gJE7Mtitbagy+1eQIWeNEb1v30H
         C3ciA9uVjXeRq75U9addBSnTyxVTcxVCCt75IIv3HjfkF3CHrpFRG8oL+QSo6ikMGr91
         5CfHj8YNKOdp8eO6NPxaLc3vPClnka3B6o3lNd6Z3EHmMF5YRVBsfwL4ufW3QdmYbd8Y
         TvHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=QQB3qbsRCzgNl36swvCPyvB+VJqDtJ8QFOiJpJoK5EI=;
        b=kgTCM+b2HrKMWDNW936Ye/JPElwAU5aV0ECEPoeY38tEMKcInThJN7iieW0fe4E5LH
         EHCd+N1q35103F5TuypizFWUJ6TFgDODHt237SU8EMsCGUAIFXpdmdD7e0lgdSHcK1Uu
         kCFRz2tifYdInrIF8BFCwiSpqsok/ZpazEjSL4zsxIzJpyKuVIKuDMpuBSe8KeRZaWA5
         a+ii2LdWyWV2aWxubeUcIvQD+0indWfEbuZcCzeJT3ZgH399+/yxeUytrOf3fKV5IvgG
         VFWoNCo7tilMXx68arqOiJ8+nkiP0WNO1kfJ9CCcAfk6kQYgE/enuHNP/sNuYaTkTC3e
         HCAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id p12si445415pgk.2.2022.02.08.04.51.09
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:09 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S2;
	Tue, 08 Feb 2022 20:51:07 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Xuefeng Li <lixuefeng@loongson.cn>,
	kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 0/5] Update doc and fix some issues about kdump
Date: Tue,  8 Feb 2022 20:51:01 +0800
Message-Id: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S2
X-Coremail-Antispam: 1UD129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73
	VFW2AGmfu7bjvjm3AaLaJ3UjIYCTnIWjp_UUUYS7AC8VAFwI0_Gr0_Xr1l1xkIjI8I6I8E
	6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM28Cjx
	kF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8I
	cVCY1x0267AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aV
	CY1x0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAq
	x4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6x
	CaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwAC
	I402YVCY1x02628vn2kIc2xKxwCY02Avz4vE14v_Xr1l42xK82IYc2Ij64vIr41l4I8I3I
	0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWU
	GVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI
	0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0
	rVWrZr1j6s0DMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr
	0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x0JU6wZcUUUUU=
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

Tiezhu Yang (5):
  docs: kdump: update description about sysfs file system support
  docs: kdump: add scp example to write out the dump file
  panic: unset panic_on_warn inside panic()
  ubsan: no need to unset panic_on_warn in ubsan_epilogue()
  kasan: no need to unset panic_on_warn in end_report()

 Documentation/admin-guide/kdump/kdump.rst | 10 +++++++---
 kernel/panic.c                            | 20 +++++++++++---------
 lib/ubsan.c                               | 10 +---------
 mm/kasan/report.c                         | 10 +---------
 4 files changed, 20 insertions(+), 30 deletions(-)

-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-1-git-send-email-yangtiezhu%40loongson.cn.
