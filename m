Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFGJVCPQMGQEJOZMGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F496944E0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:52:54 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id o19-20020a63fb13000000b004fb5e56e652sf3032982pgh.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:52:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676289173; cv=pass;
        d=google.com; s=arc-20160816;
        b=jggJ2M6aaKe7D0L8GL1hOdg/iYsLwWZlJMa4XthnPcY7UAB0uBoq68iDzzgzu1oX62
         3KCmsGkf5YOY8UqRhkRrCn0lSxZH5xbI4TZbGhW+wcUFfMVA9WMmTTwJghXtd2s+VbBw
         1J7Cz4dS650NFmyxS9C62S3JmtcrjrZ5HtN5eceTwFuQXIIJY59hASd0er4640vfrPT0
         Z8NPYAhZYGFR4XYdUoIGDw67bYTAnToF9GXlmugFWQUEHYK3LmSzmXs22HdbCKFKKBsQ
         /+wUGwAQ+bw2RwVOSClX36LwZVlnTUWkErhzYEGt60Ju1kKQW6nsaGSTg+AOEOA3Br8S
         nFnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SnJ/DNIez1wz1g98Z6jrMTuENpbrbtDCnrhqfe/uMJQ=;
        b=zk0+m/KulryuDMeAipYyUWLt39yeXOj2oo5p7hwcoVTozEtaxXiDkb7dOrExtsWLNw
         xw7sGdOle02oTde2HQn4xAc55gP/cWdgWz4URZM2104lPvj4g9ZDWys5KJo1uvUZI0IC
         GDWfcVlzTY1FFgqQJqYnfj3zE/+Iwe1tZL50IoJrMGad2cGCHk6vADb1+yE5LM4hrvn+
         71SRJmIsxuFepdv3+h7j6iAI5OCVxyTlJRx5ebSH3v8JlzywjAd1DAeUyvIaKw/SI2at
         UDxdfS2c+21mQHkYptUl+uxVGkCEGDByj0sR97lY73gVn68D4I4P8Bwwj0r+pGcaIC60
         rKNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VMQNm0ei;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676289173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SnJ/DNIez1wz1g98Z6jrMTuENpbrbtDCnrhqfe/uMJQ=;
        b=gBsoBV1vttGkLl6R1PN33iTVjn6nibQnTE6hwwXBglV93CfXACGtv/nSeT7V+l1AOV
         Kn3jzV9vIn2CpdyU5qM1/+SDY90tzytqkq3itrV+AqsOIzvBnFP/UhKYTVZdMKcOehaS
         3/TjZqIQe3zy265JBqN2kOiF/g9q6s1Bg4+wQNHXi7DdHiDrOia2EinC4D7omt4LMElT
         TRfSX+s3pgGsR5rPR6uWYo21CykqiouXMvZWMs/mZaFgSjlWHI+8jZB4Sm/jOKOUa8y+
         6VDOuoy88P7vrPkXvdYL//gf2naXGPYqPRW+4RgRig9ckdEI9BEHHhyA0Q6T9W2E9rGc
         p6TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676289173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=SnJ/DNIez1wz1g98Z6jrMTuENpbrbtDCnrhqfe/uMJQ=;
        b=S6yaiBsD9dIFcvzjalVMM4wHEiM6SP/8AI/3kZSHtrG6wrVT63ITe3KIjx0CaBJEIL
         l0tHWfvZhe/T2LkdMdZ8wv05/kbCkAoMKUlg2grr0xzZLnIDaqmMjo630F9CX3LGU/BE
         x8P31xv7VFwSKCpMEo+rmEfBLpGKhxp5gfB2IY7pUB814XhmcuORnXtZ4ANPl35iBjmQ
         8UBLtzI11Lr/hC42TSlc4611fmZQon51tPWhGnImrwQboiEMMPHT87UlWhslLOoucs0Y
         6TNf1tgpRFL00P62v30c5Y9HdzyOJ+2Q3T/paF8Y4vJ4ZXhGYTkVnpto/SZpHdJE99K9
         NhAQ==
X-Gm-Message-State: AO0yUKWJ4mlHU7r8JRDzH6pf0DBCIacA1i/NU5M+7wRgDo1PSuofSpjN
	jligYCB1wlLA36Qj5bqfXpE=
X-Google-Smtp-Source: AK7set/PQQR1hIGFoIgIr2IRCJy12mRA6mfX/Ns3o6lRAwU+PrEI/sKrXGI7UR2sQsQOcObjsdNhiA==
X-Received: by 2002:aa7:881a:0:b0:5a8:bd11:94f9 with SMTP id c26-20020aa7881a000000b005a8bd1194f9mr460993pfo.12.1676289172734;
        Mon, 13 Feb 2023 03:52:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c690:b0:233:f0f5:58cc with SMTP id
 n16-20020a17090ac69000b00233f0f558ccls3265443pjt.2.-pod-canary-gmail; Mon, 13
 Feb 2023 03:52:52 -0800 (PST)
X-Received: by 2002:a17:903:d3:b0:19a:920e:9d9e with SMTP id x19-20020a17090300d300b0019a920e9d9emr4217060plc.12.1676289171923;
        Mon, 13 Feb 2023 03:52:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676289171; cv=none;
        d=google.com; s=arc-20160816;
        b=p3Bd7zcpZww5pZkwI4kaacycze51yGOIQlyvrUn27y+/0D1oCuTQONX4tlWPduedPO
         gEOao9avzyUXmTUPBTbUj50UDiC9b1xaCXOkgElhKFOpxssYoN6T/KQefTMyQvHUk5Iw
         N8gFuYFvZeR7HSD8QwYURo5iCcp6XEmR6G6jnjfJSHRmvWQnOfdy9R9i3dHSiDkfTjPG
         NC6UkNAVXGG7lh1Z02M9I+R2076F2lNciuAL1ZkK5TwFQ8WdI6q7+fjBnRqACHDS3sc/
         TPYdUJtIDE9hbArz/hLpwdSANSljaW/EvsOnqriXs/2TJUjha9nck0zDAbYX++DmF59b
         jIHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1TmLUW6hPremyHfH02mI1sZyfyvVZyCwA3fX+FOaBXI=;
        b=bJJz4pfp4ta0kW3HU6Dbz6ANXEv9eAeQW/QbHdqWbAVtlBJFGuuxJoilGquczjW+VW
         AgPfCaFTegN+opWF3V7OugwJfdRlJdafzqiubLtr55Wc6aNZHfFVsKfvX53hTbnTs9pm
         79gpwBp3wsdrumgt6/Wg+KWGJLo1uAjW2JGwlIXzZnY1ZPXHesAm2O2BCPTD8EQ2Degu
         h0VtI45z+AHlSR1YdhCgGyjRzuW/CTis/1UnSjDjoWIXKojHojep2s/o32xsZWJexY4s
         /wEXNnihlvdsxgc8wTZdGKF4S056eKD3ho9Xcex2kFwCZS2Ek3wkYarEVNJouljnIO2d
         sojA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VMQNm0ei;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id k20-20020a170902761400b0019a6ca00d0esi205787pll.5.2023.02.13.03.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:52:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id h4so1631386ile.5
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 03:52:51 -0800 (PST)
X-Received: by 2002:a92:8e43:0:b0:30f:5797:2c71 with SMTP id
 k3-20020a928e43000000b0030f57972c71mr13118156ilh.51.1676289171334; Mon, 13
 Feb 2023 03:52:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <359ac9c13cd0869c56740fb2029f505e41593830.1676063693.git.andreyknvl@google.com>
In-Reply-To: <359ac9c13cd0869c56740fb2029f505e41593830.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 12:52:12 +0100
Message-ID: <CAG_fn=WTXE67+zPc7frp7sPvJ82G+GCJe-0+Uz+nN4PUP7+uag@mail.gmail.com>
Subject: Re: [PATCH v2 16/18] lib/stackdepot: annotate racy pool_index accesses
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VMQNm0ei;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Accesses to pool_index are protected by pool_lock everywhere except
> in a sanity check in stack_depot_fetch. The read access there can race
> with the write access in depot_alloc_stack.
>
> Use WRITE/READ_ONCE() to annotate the racy accesses.
>
> As the sanity check is only used to print a warning in case of a
> violation of the stack depot interface usage, it does not make a lot
> of sense to use proper synchronization.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWTXE67%2BzPc7frp7sPvJ82G%2BGCJe-0%2BUz%2BnN4PUP7%2Buag%40mail.gmail.com.
