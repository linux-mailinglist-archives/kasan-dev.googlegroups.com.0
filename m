Return-Path: <kasan-dev+bncBD22BAF5REGBBOPMRGQAMGQE64XIXMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 884516AA47F
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 23:35:38 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id z12-20020a05651c11cc00b002935008af2asf1118073ljo.19
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 14:35:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677882938; cv=pass;
        d=google.com; s=arc-20160816;
        b=BsBpwTFWIDxrreW5dcJIil7oTEO06Lja8FgMhx76NqsqWQDdGzXsa8ukz0GEYfY+3I
         K9WeD2eZ2d4b7WgMkRz6L+hws6Kq2dVThbzZfTnaWM1l2giJjDx7UZIjDoSd7uP6FkkV
         Nk4F/l1QJlkaHF+FEqttX0IOPzMEwFZsIUmQDclZad7Z7qF64uCEggY+pzwK+QVQBS2u
         4Vn6PH4p+ICaPSYv3gg7rbna+MlizZGCLenysVWXYv8mpU/QXpyFdyt8R6Sq13MPTdf8
         T98Rl0oOshYe8KrOs4xiuY9PqD/p1sMGI7lo3QGHToGAHuPMeQNfw/fs3RJqrFPncTbt
         GwSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:from:to:content-language
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=FFcmL0gUngxWKK++k6Wzoe9DU5hgrdZNG3g7Y7o7A5o=;
        b=zennGC6SsOeQG/iVPzghwWkYPd4rUhmre8ITDVeLqpu1DQqFuwIZh+PU4DAvNo/grl
         vRW0avLWqd7QSFLJBvSyRQN3Pd1KBKiJXokyX/5e5LFZT29C3X0jKhOlqSRFIRq+l0GB
         1IsWFIhEGuHxia4bEy/Q34t8OcRI4ZrLs/718x5QqEWP37tncdMAR1YCWlMuFBRZaGBi
         1IvsjA9HBfSkhfGuwsSspX1yiGGK+rGMOpfJ5vSxT84AkJLbsD7uUrZJRx9c4rwe9FvS
         bEvlxvd4so0glhk9kQ3pJkLyiq7soN47YhxpIbFH9cLI4UkLjMiNF9Yi8Nvh0o0P/ldS
         H7Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="MU/X56/0";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677882938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:from:to:content-language:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FFcmL0gUngxWKK++k6Wzoe9DU5hgrdZNG3g7Y7o7A5o=;
        b=K7OoOkaXYdme4lyEASf27HhG/HpnEjqzy64NYZRq3Ekf4jXIIHd3I5tlGQps+CsosW
         jb3Nx1SuP01KHeA48L9SVRWxqgXrOgu/2tPviC4xbAs/q0r3La5OunZ+HpKgrsxk0Ep6
         MAYFTsg9EoM1cbZPdblhVXU9mYNuYmqTQcp/vMnTPDNDb4z0Ml/IuWrfAum9P1gCm/g7
         cPlHWL2URBbKRK8qUEMwFiapCvkLFa6cC0b/JS0LqVo3HZyNUnP9UIQSDbFKlBo2e3nm
         rGh6BW5IaEMyc7uJTu4zI8ZZvBdwxBH7G8y4pl+4Ce9XS8sy+K9Kq8g+6/i9Zamxo/+p
         cYOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677882938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:from
         :to:content-language:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FFcmL0gUngxWKK++k6Wzoe9DU5hgrdZNG3g7Y7o7A5o=;
        b=FszH6Kw0f7NTCFp8rf21xTNOBsFnsCb/9yWKPMzluqgr2o2XhUh9S7BVNu5dgFd7kF
         G88YCB6c7ZRYOQqY0ggK8UGUdm5wrGENzyur48m/I1HIjLXEJfrWmbsj+ySugp0GFZvx
         SAFvmSR6BBuBlrvZ2mJ5U/LJNdbCaFdnY13navFEjpSkzx/RbLWqGXabYJvEi0pkOj43
         JgQLccKJtaZbofc5ZLJdE/ENklp0N4MWlzr/n4HOyHbJ0lh70Is+Dm9fnXQkIAJob84P
         AwgmkVnryiSBeABpkXNkhNXOudIkGXvJ0n0nzDZJEIYjj0Or1gK8LOCruGkQyfhJdlQ7
         LOsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUcAtSKuJEAn3R7XVCMESXh+fpYawasGW9+6qtuRcKe05HVvHqY
	7zjYurPCGl7FG2Roa8BKJHg=
X-Google-Smtp-Source: AK7set9RxFfmWi5Sfk4b136iR3m6GvSlb1QBdFQHMmkxqEm2XBljuQDhaAOZQjF4JB1doN/jsl+xYQ==
X-Received: by 2002:a05:651c:2322:b0:295:93eb:bab1 with SMTP id bi34-20020a05651c232200b0029593ebbab1mr1064522ljb.1.1677882937479;
        Fri, 03 Mar 2023 14:35:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a2:b0:4dd:8403:13fe with SMTP id
 bp34-20020a05651215a200b004dd840313fels3604841lfb.3.-pod-prod-gmail; Fri, 03
 Mar 2023 14:35:36 -0800 (PST)
X-Received: by 2002:ac2:5391:0:b0:4dd:abb9:dae4 with SMTP id g17-20020ac25391000000b004ddabb9dae4mr1037800lfh.25.1677882935968;
        Fri, 03 Mar 2023 14:35:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677882935; cv=none;
        d=google.com; s=arc-20160816;
        b=sDpibHi4EzenPhi1MgBqfiSiz2t124nZiXfAbGDCqyYIv0RgkIqY1HqPVHUgTJye1r
         DYbQvbiR6udKBgAOnEH4GVvWAF7xV0E14ehR1NUTn+vd9W2iC6d+4Vb1wIH2F16ArUA2
         32kFLQTp2taDbQxUIdRxNLQEPvMgYkWh5EiLzuxveWZx39i6dc2LE1eHv6vo2Lqln45e
         WCwS2A5xts1wsY5BhwxA/8L+1uSlGJ4EcSq3zQG0CxNBy+S2+FZZyy6NOdSNwZbhezzx
         2xXiiqiZFLH7AcC7x6zWgE3frnOKSlzFpLg9/nCk9YqeI64VvYiiQtFKR0qhddH2OyVq
         z1Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:cc:from:to:content-language
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=2lrZa272NBBcD4X1VHImUZ61vhXPIaaLPfZ6TLCsOuk=;
        b=v4Gj8cMAeg/W3iharialn+QY7tZ1nfKR4Raemzp7Vgi3Lmxl7PSHJP3suRvUS6pFC+
         cWuV+8ws/7YGiRDtuIDeLU0JnOnAUmQxYV25wZFE0H2eDUgUsFGnn2K5A5FyyOaH46pJ
         lj3NXoEiZTO9jFFpawau/pklTTRNdUYhfDHDXNVP/weqKE/JrnTRbszKFwydO4EE+DGu
         8oBdLWBQ+upZnGWUJBvtFAm5Qmsa1bh6sqiASjbMh3i26iM1YF9KxeZP8E3YaWEk2fQk
         11c8dIY+t5VagLwGChRRALa4966teiWLS9GMM5LMBPdnN6ZWABrOEmPSoKk/hDHD8viJ
         urYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="MU/X56/0";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id i2-20020a0565123e0200b004dc4c4ff7dcsi207018lfv.2.2023.03.03.14.35.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Mar 2023 14:35:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10638"; a="399989541"
X-IronPort-AV: E=Sophos;i="5.98,232,1673942400"; 
   d="scan'208";a="399989541"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Mar 2023 14:35:33 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10638"; a="675521485"
X-IronPort-AV: E=Sophos;i="5.98,232,1673942400"; 
   d="scan'208";a="675521485"
Received: from ctretbar-mobl.amr.corp.intel.com (HELO [10.212.170.209]) ([10.212.170.209])
  by orsmga002-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Mar 2023 14:35:33 -0800
Message-ID: <299fbb80-e3ab-3b7c-3491-e85cac107930@intel.com>
Date: Fri, 3 Mar 2023 14:35:32 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Content-Language: en-US
To: the arch/x86 maintainers <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>
From: Dave Hansen <dave.hansen@intel.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Kees Cook <keescook@chromium.org>, Thomas Garnier <thgarnie@google.com>
Subject: KASLR vs. KASAN on x86
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="MU/X56/0";       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.100 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Hi KASAN folks,

Currently, x86 disables (most) KASLR when KASAN is enabled:

> /*
>  * Apply no randomization if KASLR was disabled at boot or if KASAN
>  * is enabled. KASAN shadow mappings rely on regions being PGD aligned.
>  */
> static inline bool kaslr_memory_enabled(void)
> {
>         return kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN);
> }

I'm a bit confused by this, though.  This code predates 5-level paging
so a PGD should be assumed to be 512G.  The kernel_randomize_memory()
granularity seems to be 1 TB, which *is* PGD-aligned.

Are KASAN and kernel_randomize_memory()/KASLR (modules and
cpu_entry_area randomization is separate) really incompatible?  Does
anyone have a more thorough explanation than that comment?

This isn't a big deal since KASAN is a debugging option after all.  But,
I'm trying to unravel why this:

>         if (kaslr_enabled()) {
>                 pr_emerg("Kernel Offset: 0x%lx from 0x%lx (relocation range: 0x%lx-0x%lx)\n",
>                          kaslr_offset(),
>                          __START_KERNEL,
>                          __START_KERNEL_map,
>                          MODULES_VADDR-1);

for instance uses kaslr_enabled() which includes just randomizing
module_load_offset, but *not* __START_KERNEL.  I think this case should
be using kaslr_memory_enabled() to match up with the check in
kernel_randomize_memory().  But this really boils down to what the
difference is between kaslr_memory_enabled() and kaslr_enabled().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/299fbb80-e3ab-3b7c-3491-e85cac107930%40intel.com.
