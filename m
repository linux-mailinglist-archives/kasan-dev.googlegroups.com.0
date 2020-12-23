Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA5ORX7QKGQEXJZBA3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 078782E1D7D
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Dec 2020 15:41:09 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id 68sf8607542pfx.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Dec 2020 06:41:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608734467; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJGeY3s1C+da2ol9sB8V/dgxLKhU6yvTOn0dcQ+8fqV7k1ffUOI/1nvJFoBBi3MJt2
         rZ/BpnGgErqKNG4jntOyQ4bwxPsftmHY4UPTfBMdYkqXj62Zwvy5xlcrMq0C4mHAiX+v
         8BN8AQDkSjCrlr8iGK3cnyYb67BwHC3oUlXEbcQsc9ah1RORWyp8VXB+ZEX43SHG4REm
         ZBj4TNKC4gWCia2Ss4BwKOIdcDS2YKNCZ6q6CJy/at9HAcHNv9ISN2sAmtkCe8JZiU51
         zORFutaz+PoqQMZV57uzep65pvAk9J1TYyw1/hmxM0jXr82eEkhDbvCzXQUYpJh3U/GY
         QgYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nG9VbNQbwufqXx6ItojVTFqL5eER3WGh7dnF6iBAilA=;
        b=tgECQDSBx27lnHPT5uFK+4E1P0BqafkwOIS7kAaPwsC4lKRejJs2AySsfrtRlJDrya
         XcUmDJAf7UllJvRGeSieBqNShL4ajq7hB2zVH5NyoIKs6BnMD0M8lSf3+HaWrOvo9ck+
         AZFSA+Rhv7vuOPVbq2cYpSndvWMN5/54ehDYYaLRIdKijVEpwx3N+gLutPCYKo/pVLGV
         kEQQ0kFsmqhqDVGG5/4fJVTaODKKJvgmA9goAwVCcaDB5IbX8WKx1HOJMEed7Cl5ZLRL
         lTQ35b7ehza1heW3Y1LdxujmHQaddW/S20nes/f35Yi81jyNHUy0Oeel0VQ3VGVNxTDt
         DOZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IgDeBDPe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nG9VbNQbwufqXx6ItojVTFqL5eER3WGh7dnF6iBAilA=;
        b=M/bRDiDnLOlJctCvfgIjumUVmFe3BeB+BJctfcSgWfq0JAelz7pS8LNz1EKaobE7dD
         D/6tt49wd96cjJAPPwATiVT+H4VxHDSqhZtPUHMxm5GIfLhNjYgg+celDhTA/zMS6Y1g
         TkyaNbW1lmaPHCUcpSXGbhqjf7IhA+bv43QKatsjrpFGjY7MnM1TRsvdcIveziwvqw0k
         HTv4rO/V7Sv5GFnxKopIEFtw4VPGRfUYFFncJIDPfpGYGjX4r/1ePKHJT/c1Iqz7mOxg
         ZmBfVsNp2DQZS+19mGyTzGufwho3Whs9k1xh0akA4JmOZ3AJMO58LmFV23JwPO1nRFDJ
         t8Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nG9VbNQbwufqXx6ItojVTFqL5eER3WGh7dnF6iBAilA=;
        b=sIx2Z88DZWG+ba5meovxhjjAhncu54jcA+A0uDp2IBZb3nm7jqupoGJMA1INvVjHAE
         ddKYWxP6ItvDpGWDlcd7C8/zE+NCqzDnxVobjcFZgnY9ioqKz9I2oWePe+w4tpcPu7e6
         pM13odhXrfcGaPWY5o7Io2evknyCOiGtDizJVjx5su/S8xkQazt48jsgNYsKYGAsCBBM
         U9DZV/rTYrBXsQtZ7Ni0/5EzAg8pGPeBCXT+2/2enRBRtJBplHtQGlNwyT1lmvzQs/EX
         Tbhcn3aZA1oYjsZvSBbnTO8ZeL6++2KGgG2Y7SRTpCItq0HDeb581QHR5LIwzDaepSwK
         Vo4Q==
X-Gm-Message-State: AOAM5331dysghfwVlGmJuurrSa479/xI3V11BETWMr1PIg0B9uuzYE6b
	414oTWwmnZ9GuK+GQlxWpN0=
X-Google-Smtp-Source: ABdhPJzKMjJtCIinUPClyWq2VBbJLF951hc/YHD4Es8bIoyApWKtkkrlaXwpwrj8B6UChpXEvl/tRw==
X-Received: by 2002:a63:f12:: with SMTP id e18mr25210396pgl.101.1608734467347;
        Wed, 23 Dec 2020 06:41:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls21903545pll.0.gmail; Wed, 23
 Dec 2020 06:41:06 -0800 (PST)
X-Received: by 2002:a17:90a:8e84:: with SMTP id f4mr40557pjo.129.1608734466761;
        Wed, 23 Dec 2020 06:41:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608734466; cv=none;
        d=google.com; s=arc-20160816;
        b=nWqohl+XZKefglVAJwMThGOQf7D1pBwnzGbasIK/fK3FERHZDADLD0G9ln0/uLurpL
         mClTW4KsUu+oXl3DnPpPx0nw8NQ4YOsu2NTP0uLN4ekOxZ0MBZxc5lSpBXDrGEsFvQrK
         M06Tf4x2kys40/HCVFn5DSZJ8kqoQQ2ObatbUNRPMntA+CIBJkksGiUETIjTScnnaqDp
         3CAayfnaFnBW3UhQH31g7brjA0lcF28cmBdOufufs1MAZ7UgOGW2v4IFTrywUiQIjftq
         qcG9tFJXuqYTbYm7DVsrMB3oxXNTtFYxeZ/WkctATIo2gZLy7jY1sXPLUa2mlnY/n7aT
         Cehw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TyB5HqZGghDqQHiswidE0Nhl7bc1fz9iuEH17F6HS7o=;
        b=CyLhGVWiEPN6a0uA2Z4bw48/TwTgz6bjR3fxGXSFPONDOT7rLBosuZE2xIyp5efY/G
         GhD1xKiD6ryJyNjEPDMCF6mRbs+H36G2Ts1CXevHrjWAkvRc5lAtbgejVtS31W4rwJKT
         4GGmltJDE+N3RmoY4syuZTKgfmyHwJ+Vn78n60UEj9oMi+mlcPrzsLgDLDxG9R4ZPO0a
         znYAVYaqjqnqlmA2YsfvkDPiJ284KxhMc9XjPdKcHuRXbY45YrVo+XQnI0/QwrG8t50G
         QupgcC4a1Qi/YplAnhQ0zWYAgAS+F4pWHQ7ZN3Khqtgw6fzQfyD2uvNED1JDtdwT0Qx6
         O+9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IgDeBDPe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id c3si1481829pll.0.2020.12.23.06.41.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Dec 2020 06:41:06 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id n142so15081029qkn.2
        for <kasan-dev@googlegroups.com>; Wed, 23 Dec 2020 06:41:06 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr27163288qke.352.1608734466216;
 Wed, 23 Dec 2020 06:41:06 -0800 (PST)
MIME-Version: 1.0
References: <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org> <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org> <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org> <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org> <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
 <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
 <X+EFmQz6JKfpdswG@google.com> <d769a7b1-89a2-aabe-f274-db132f7229d1@codeaurora.org>
In-Reply-To: <d769a7b1-89a2-aabe-f274-db132f7229d1@codeaurora.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Dec 2020 15:40:54 +0100
Message-ID: <CAG_fn=UUo3tP1XtdOntNG1krvbPV7pmE9XXwMyuhL2gMUoc4Jw@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>
Cc: Minchan Kim <minchan@kernel.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	dan.j.williams@intel.com, broonie@kernel.org, 
	Masami Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, 
	ylal@codeaurora.org, vinmenon@codeaurora.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IgDeBDPe;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
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

>
> Michan, We would still need config option so that we can reduce the
> memory consumption on low ram devices using config.
>
> Alex, On this,
> "I also suppose device vendors may prefer setting a fixed (maybe
> non-default) hash size for low-memory devices rather than letting the
> admins increase it."
> I see kernel param swiotlb does similar thing i.e; '0' to disable and
> set a value to configure size.
>
> I am fine with either of the approaches,
>
> 1. I can split this patch into two
>    i)  A bool variable to enable/disable stack depot.
>    ii) A config for the size.

I still believe this is a more appropriate solution.

Thanks in advance!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUUo3tP1XtdOntNG1krvbPV7pmE9XXwMyuhL2gMUoc4Jw%40mail.gmail.com.
