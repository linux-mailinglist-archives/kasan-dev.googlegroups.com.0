Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLMA5WGQMGQEN75JM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E7225477337
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 14:33:34 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id q6-20020a056e0220e600b002aacc181abasf10556984ilv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 05:33:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639661614; cv=pass;
        d=google.com; s=arc-20160816;
        b=CC2kwP762F28lo+ZW0YH1Tp1U19h8+E8XxM5TANCkTMf2uzvQ/KxEeqf+LJdiCEzwg
         n1d6MWXuJ7Nd+pamO80C+bfBK4Chpt4YEIr2WiG1os3eFE3VPGYU2ahw8xsLviRt+BLZ
         cXGgPXjs8MND8DaQXpd4dN+HLHOTtyj0q8Jwp43JE78PyzvwnpTZFtd1L9qv99m5+Yu+
         VaQn9Oh36XpaIgjaQTSzOKdj+id4RSWyplAksKs9hfwY8SGcHEMn9ICJ3Adhj8s/2n5s
         Eg1+dRM1aCqpvQErNFbiME/BW0l5ce/6XisccKai4AjXQBQV/bX4edc2ZtydccZ2cbxX
         x/ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kL/0zk3ZCKyh+LThXGsUpGiyWPfdsUSwQ7c82r9hu8g=;
        b=QWABnSz8O2P6i3I5q4EyY63f82DMl1b3REAcmtLjBcACeFglLa9jTs1fu1McfA1xpg
         ZUJzX7j/Glh3V1rNX6MJiNdA6E6+FNKh7WHcMP0/6p2TephLbmXUQsdEqBwAkp9i5QxZ
         bpkyvsbhHVdXnkVo7ZASjzGgZr+tFVKqgl6sN+kS1ZEFATIuy/z8Kd7ZFkUHo8+JG76s
         QK37+XZT8FanF/H7xg7ckqlqFvFOr2JF2yviw2zo1YnGUVwUGshOyrGubv2HYWGCOaxW
         bL0Qlv6WgAjVwHqVrOWn1mM7je+v9djNfLzoToUc66eFoiGM81LeGHO96bZWIayiYonn
         ZhpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eupZD4nb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kL/0zk3ZCKyh+LThXGsUpGiyWPfdsUSwQ7c82r9hu8g=;
        b=Bt2DF0Rne+KP02Cj80IYNC6xuZG2ty2bMuJqZyQ9VRvhMYz+RIY5CE3l28fjmF/1ZM
         aLurAvPAWxloKM7kPQJTIw49PZZfJt87srgjU2Q+bTOw514VcCg6b0qAciXazUlDrmkV
         yvViyirin1w/xmdZNupwoFBktDsH+9S9qQ2/0cKWx5vG/z+zJA2I9Jx+M21eUmRpxYIn
         CKcjyxC7hfRvCqO+EPWiz17hSS5lzYrzu9+ZdVE8nloQQacPCc6ktK1fclo0Yesb2M43
         P+LCHHdqmBzdyK0VHEuaSDQ6UDI5+l/1XHQooLXZJ26o4SztHFR5fkTX8vAP/h7KY4KS
         9HmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kL/0zk3ZCKyh+LThXGsUpGiyWPfdsUSwQ7c82r9hu8g=;
        b=KJ4V6UAkOLiOp5jwySqLV9L4ld0W3apaj8uoNNWlBfqjjUqULvrGG+Zxy/LqbI021g
         z6bP7q4OoLCFtGM+mB3mp+lGR7ZAzXeuvUmtF5bgJIYR/hG8H4BLkmSD3ZcAV827RovQ
         81EKMPgfGVcDelB6FWQL+2GT32ye2COp2V1Nv0ggTE0OUIRIBKMADBYc6HLVn8pri4no
         tqRa5WO0h9bUlBl1vmjkePb7qALmPFm+CRVNfZyuHEVlw+j3HquTZpw1rAxRINZFRCtm
         Gy3XE0Y0g1lMV42msIB8lpRJf5m+O+USN0kaqYUwujw51RBh+B3YGi3JqdwntcwpFZHc
         mAgw==
X-Gm-Message-State: AOAM530X3cnNZV3GpUucs4b/QkTHxImUr8iEkFDD0M89riedK64cUOct
	iisuxphyMZT6EnAzsjhBUo4=
X-Google-Smtp-Source: ABdhPJxqbdcFgKdtj9NBWPRi88AgWf1EiUdii5aRM89ik+vMyq9L0IFQaahumCl1WEu2SmAlAZRcaw==
X-Received: by 2002:a05:6e02:17c8:: with SMTP id z8mr9483474ilu.271.1639661613883;
        Thu, 16 Dec 2021 05:33:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:24d5:: with SMTP id h21ls571264ioe.2.gmail; Thu, 16
 Dec 2021 05:33:33 -0800 (PST)
X-Received: by 2002:a05:6602:2244:: with SMTP id o4mr9312772ioo.13.1639661613587;
        Thu, 16 Dec 2021 05:33:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639661613; cv=none;
        d=google.com; s=arc-20160816;
        b=LExmx9Lh4fBGqCZUCb1q0jprerJ3OxeEdfnqfGfzfAge5M5pHXUSJ1oR7A8RjV5uTY
         hODcfdIGHpgIbLH3B4YHV+s6/ju5pHqOLwnPmGVsbep16kovnj4AgXdHZiWnYfei7ZFE
         X2rfUVBGTnb8fBet0aH1ekDInMsK/GA/i2kUj9aIMhA2DP6ZG2Lq61zvNcLhTaVUXWRd
         uH8OJRPqMqDQkBcErl01nxi1DnBVXoC6HFCriwSNBVyOc9H8xx47vbjnticEjrAk9rOT
         Ht4byOyE4zNqkSSIcd1zhok2uuNk2wk79TiDbLh2E3kCMbtB1v4WoNZw7eHmoravopxs
         7rzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DioPzCu1zsCkrV4YGIzTyYHRCTuSei+k8/YBOQlCxpM=;
        b=RepcWqLhtXltzdsbGOtXvRdCuQEQVXb+psBD12MkAsl34swaQDpiiGlLLZUZ1a2KRK
         7ey5pmUq4iPDgDtO+1Cc2Kj3WhYXvrNltmQj4QV51+b7u8IirR7GVhgFL0TVd9ElWImi
         knPbY6SK9Lr0KfQarWrVTFHRKQREGqXvevo3fURSxGWut8ZmSJFfn3HVHVOEw1YGiW5C
         TgamLmMIC77x2pagLl5somKoOXV442hM67imLjD9T1T9aox2tGY/AjIDFEZ8NeoFP5VK
         owWGPvmWSP0JNZQB2L+zfYqnO4aS9WpJXtcXZjSs5z14LW21QcL/BKktR5w28Ryj9IdZ
         rHNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eupZD4nb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2faa6b53fc6si830222173.7.2021.12.16.05.33.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 05:33:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id o10so2916103qvc.5
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 05:33:33 -0800 (PST)
X-Received: by 2002:a05:6214:5190:: with SMTP id kl16mr15576473qvb.36.1639661612968;
 Thu, 16 Dec 2021 05:33:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <fa64826c55c90d29f8ce2f71b588591fb9cfc23e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <fa64826c55c90d29f8ce2f71b588591fb9cfc23e.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 14:32:56 +0100
Message-ID: <CAG_fn=VVnpsiAP5zpOZVjUYSoVgFZtrPCkN8fzx1t-5OEGhcMQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 09/38] kasan, page_alloc: refactor init checks in post_alloc_hook
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eupZD4nb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Mon, Dec 13, 2021 at 10:52 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Separate code for zeroing memory from the code clearing tags in
> post_alloc_hook().
>
> This patch is not useful by itself but makes the simplifications in
> the following patches easier to follow.
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVVnpsiAP5zpOZVjUYSoVgFZtrPCkN8fzx1t-5OEGhcMQ%40mail.gmail.com.
