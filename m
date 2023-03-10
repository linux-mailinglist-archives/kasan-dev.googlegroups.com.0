Return-Path: <kasan-dev+bncBD52JJ7JXILRBRXEVKQAMGQEA4VNJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B56D6B359B
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 05:29:59 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id d4-20020a05620a166400b00742859d0d4fsf2427222qko.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 20:29:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678422598; cv=pass;
        d=google.com; s=arc-20160816;
        b=PSHicKEEEk8+tVBnm/j++1VuiooQ594+8C/KVoZU8LJa1qzvucZXzju2YUKwl2gdeN
         exlMN2FxkbAFN5cDqs1KwXbUZlOXkJ1MiADw0Wn9v183kkqaAbhSsd5jxdCoLSV3kO2F
         W4xP4ccaNe5O4TbyX9UHNoWv/kBMEQQ3QUA0DPSZibD4PL9E13nmzjAlOb1drTPxS9OQ
         dAl2P0tzrv6dGtIVXME0jHdTqM6o6aS9VywNHGOvnLHHTvCjy/5BBA5QC+vUO7RAKMOP
         m6akhFr2J3Ik0qLWlKbJBZOxiH1+aUfbrR1JizrnTorOcuYBTLg8966BvCwEZFvTfaRa
         UGvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=2CeMup1gNIe3+vg+zLtJ8IESvRhlGgVdbta12eCx8xA=;
        b=NMDNNAO3YK7DWMvn781dFrgxzrNJ5YoY1rTER1sKqvFjbS3MWbbsJuQkx2A92x2KHI
         xZJC0Gj50KRfj//jPTnoTZrMQQYC4UMAuQoGSIovEahAPl/gLOr/yqT4db0wHNsi4Rx5
         7iadTDwvLaP3lmJHSDBkmQ46ICKQTNwkns5phVM7biHnHA7CeFXtMeDrOpyKZjZIfKCQ
         93AgQ2ZwYj0kzftvm7ms87iyCSUqrL11mL+O0ckW5SQY8VVSsd/FI4VVf0/WH3Q21s/K
         Zx11x99KSW2Jv/wORXQYG8yl9Q4ORzlCs71INEIDHbHc7aaA/mKrcLcAjuK4hdSB13BS
         2ahg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XjtPEiOD;
       spf=pass (google.com: domain of 3rbikzamkcforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3RbIKZAMKCforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678422598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2CeMup1gNIe3+vg+zLtJ8IESvRhlGgVdbta12eCx8xA=;
        b=CzrRjclrRbk4wX/3Ypwddib8qe4GGu0Wts7r0zX0H/A7+SL2HVU8gIj9+byCYakz8I
         PJYWRt8XeW/9/a+Hn/keViD7gTpgb1m6V7vML1ZNy00Ux/brJKMpBT2f1P6PU9Pb9lpu
         U7NDL3roDy3pg+0rje/rooap1dq86PHaqKQnqIVyyVIFTmsZ40BzEUDWaCnUjnWA/651
         Z/44gEjsIvwTUtPSRX013QYD2SkP/k3mEO8Ot0F+C/zP/SGOPaTDtY4WujLudqBbgClD
         7lV4CYwPQYvjCZId+EREJnNjn3SmXukLMtMhKoQamBntztyfXkqFOcvDAS2dxOdM59O2
         KV0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678422598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2CeMup1gNIe3+vg+zLtJ8IESvRhlGgVdbta12eCx8xA=;
        b=GstHMJ11z/9U28YN4GqdAgJH/oTuJssoXN+aaoxjxL6CGvxk2gogi6ffKaF+Qd1ANE
         ZOv9sSgj2znqxYFPQaRfUwalYbgIKfbIqvCx1n6ML7sEj4d9eWQvae5+JpF6GgJpEiam
         xAMmujC7J1xJ6Tpl3mTMngbMjlFAulv/u9ia47EPpxw+MCqPi+1SsHkl0/tnxh77Ej1i
         DYb4TyiBoXDH8DVUkbyJVgCs4kDvao44cqCiEZg1mMtS2ApIckR2gqkRK/PnPWC+DtmE
         HyslNVrvUi04I5/lAfcG34UJI2noOAyhUpongrvb1lQRwIyrNN2gjI5m/oJ0kPDYJ5mx
         B8SA==
X-Gm-Message-State: AO0yUKVhIgIHtuTKyoGPCYt74bki5puca5tF+3l3jWIz8BMyE1j6org2
	c9mTyh+zUXYOdC6BCDoP/X4=
X-Google-Smtp-Source: AK7set+7tPMx3xEO+9sj3WFm6QbztqjGH8e97lk5YXgEsqjH7VWRm7wBaGVUV1xqwIRghunYkyZLWA==
X-Received: by 2002:ac8:42d2:0:b0:3bc:f00b:931f with SMTP id g18-20020ac842d2000000b003bcf00b931fmr7090441qtm.10.1678422598197;
        Thu, 09 Mar 2023 20:29:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1bab:b0:3bd:1964:3a31 with SMTP id
 bp43-20020a05622a1bab00b003bd19643a31ls4521094qtb.0.-pod-prod-gmail; Thu, 09
 Mar 2023 20:29:57 -0800 (PST)
X-Received: by 2002:a05:622a:453:b0:3bf:d9ee:882d with SMTP id o19-20020a05622a045300b003bfd9ee882dmr42487055qtx.40.1678422597643;
        Thu, 09 Mar 2023 20:29:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678422597; cv=none;
        d=google.com; s=arc-20160816;
        b=k8gTk78fUTzyevmxUTLW70pahefeu/nNuvK2EXqhC2X5tWm5mA7pDrQxjAqut0VUde
         W1HmlU1CFv6rukq65KLCasqJ4Y7sLR4uQEoJwwUXsal7Nz5jTMwX57Gzzool9OqO2E90
         B5cwlou1udyg3JEeLRY6ylFu0iKjNH4olEyn7LedaKLfuN+Kq05M4gpx6NQWerwal/Wf
         ZJo9rbh0UaDjkpZu9APHhnsK/56Ba5VIp4yq1UEjXrvBvv1pDSBuQr8H+AnCBTRm6K3P
         D+12FQoJQ6BMrdPce+GpE++tG+JzNcZnfG6r7xwdp1A4PcdPOHUJEFByA/NN5a4lauri
         1dpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=GUKa2uusB8tSAYQ+u1ZVbFlgu88tHbm/uy+GaZqUXqw=;
        b=qKrhjlgH4/zSkMJ/kpVEjZRvSFZ1UjkZ5PkQY1IGogkOfqJyYxwToljAif0Y4pfl/C
         kPn7DGpYeuM4iBXQE4u65ubmZQWJZIJoPcAi/Iwkafn0jjfY3oGyowJ+D0zMhcJWK0zy
         B+h/2x5kcQbyNBEAvgx2J3xZDJJ36lg9Yt1uiybJwCrdKLVWCJRy8DVi+QLYWq3JQRab
         te2S86IUJ6hSrvirntESZTQIX6bnvyk+hPT8vYLffRAWfZkXAiRTqSl1PeKAjNwx2oST
         wEg5p2/H8O5B4VXPao1DaYrlZqiSlboPtbsKrwWRWq1IYAWIczj7Kcw4A+ri59N/ES7K
         H92g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XjtPEiOD;
       spf=pass (google.com: domain of 3rbikzamkcforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3RbIKZAMKCforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ge17-20020a05622a5c9100b003bfa7f2df56si38575qtb.4.2023.03.09.20.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 20:29:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rbikzamkcforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-536c02ed619so41934577b3.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 20:29:57 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:4760:7b08:a3d0:bc10])
 (user=pcc job=sendgmr) by 2002:a81:b243:0:b0:52e:d380:ab14 with SMTP id
 q64-20020a81b243000000b0052ed380ab14mr14371711ywh.3.1678422597344; Thu, 09
 Mar 2023 20:29:57 -0800 (PST)
Date: Thu,  9 Mar 2023 20:29:12 -0800
Message-Id: <20230310042914.3805818-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Subject: [PATCH v4 0/2] kasan: bugfix and cleanup
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XjtPEiOD;       spf=pass
 (google.com: domain of 3rbikzamkcforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3RbIKZAMKCforeeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Hi,

This patch series reverts a cleanup patch that turned out to introduce
a bug, and does some cleanup of its own by removing some flags that I
realized were redundant while investigating the bug.

Rebased onto linux-next at akpm's request.

Peter

Peter Collingbourne (2):
  Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
  kasan: remove PG_skip_kasan_poison flag

 include/linux/gfp_types.h      | 30 ++++++------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 13 +-----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 84 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 49 insertions(+), 91 deletions(-)

-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230310042914.3805818-1-pcc%40google.com.
