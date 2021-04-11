Return-Path: <kasan-dev+bncBDDL3KWR4EBRBMVKZOBQMGQEDSLNBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F9E35B337
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 12:53:40 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id e2-20020a17090a7c42b029014d9d6b18afsf4562263pjl.8
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 03:53:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618138419; cv=pass;
        d=google.com; s=arc-20160816;
        b=czR6XyyR/GZR+GLIMSFhatVSB4cAFf8tDphZedRh6/Vz0ytirhiwDOyv2u3MavPTXR
         LRj76acA2/BFQTOjNntdDlaQ6UgxLDIL/1D++pys+3XbqrYUu3crjteFVu9zXZlkWXzY
         j66tSiUDAPJydtIG8qmvPW+YAcL0zs3sfna3rOeIMClVBkn1yUJspVshehNpZGszmJ8q
         tSKIS7xB/5FdRfj6UQjq+0b+gjrv+N0y9IRvS5PBj+2l8O9/vz6uOJdMWvEP9VbPV/Vj
         GS0twPQpsF7BLnKhHS3/M0dKWghctMYyanvGtDB8ZKbNjuqaJwf9kl0oBOf5k/sk+ebJ
         GopA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GGJssXiFUbIC0aQ7nNwnN2+WlhezLrUYslpoCfMGwk0=;
        b=LNqPY3JPCTEdIsgZQMM9iYzxEIp0YxKVPoADNOZK6cBsJBJim0hdnXorHqPUY5emzx
         Wl5lq+vIOEPFMmWUrguglWHFrNlXenyk7M9or6dIbWQjSZmYmHqvnxN6UtwIlATidP4d
         8EtST/+Zaf+v1cwj1yx+fnztOw41wmiS/ZnfL/OQqlYBTxl80bNQAzWfYlgGUldueaOR
         csNcJLqynOowGZkHHsKzOSpsMmh7Prh1IwPSkXfwQhU4ZDAF+pNM5NmcPXsa0h/md537
         V87JQT63Jlp7zO5XLqZNW2TwuYzSVWQ7dQJQ/CQD6nt4JPD0nehmydJpFcC9++czdvxd
         oYzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GGJssXiFUbIC0aQ7nNwnN2+WlhezLrUYslpoCfMGwk0=;
        b=CNdFulANwfOwTOa5PGoxxLZVIfV6A0PDrVLNJZe490Nx4uhu5s7fEdMCSNvMLU5rpM
         JmjCVizdmOVFWT1+ay6CX+g3kwYgapRr7gNTsmp4W+hQYlMqNtAcV1Tc6gjOTrlOt7R2
         b7UZbUIcC4ilclhQe/NrPA6tAonBFjsn970Rj/NTjwFmGRpySYt9iMMDtnfvzuDDiZN0
         CUqSTxUIWOqtAGzjaKq0uAvLUJp1zELIPr3xb8u0U+1uaVkYV6gdymI/mVtbeNnSbnSF
         iH2lsr/jrcvKaRo/4Q1DCFH2BaHesg3G2y6IE/LQ1RHoiPxZg76OLlFj6b9VzEWPBHIp
         xFfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GGJssXiFUbIC0aQ7nNwnN2+WlhezLrUYslpoCfMGwk0=;
        b=RzLDbFVJLzjFMgxEc0bStJzEc9SuHwhvlByEGoHctdKNUn7CIW0gVkVCso7skUgpAL
         kKRbiq5pqgNHzo3ExqwqL8UGQ/++iRwOMutQFoqo1uGRvLc4nmlAjH17R6ldP2Rllf3E
         ammFjZ5r8gRlTWtdN2Wh2aJUgiSHKZaoQPsv20JBTVM/3ivr4g0PdXh15yMH2ZXGIA+X
         odMBiNUkBTdFWPstdLfIJzusHvIWYBGLRq9cuLhu9ktMBntfPil3JItWwWsOR4Se4mah
         5J1uoMtkRnwvo2rpG+ACAtiaZduqC5wKPJt+JXBi0ATjKTd47p+gXW7yBFGEj4GKTU5o
         Ipjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZMYAeslmLh34qJLM1Du/goIxbNXrSOmhrLX0xsy+QSg8aYBSz
	PCJkHKqFrFkPpB54gc3TqbM=
X-Google-Smtp-Source: ABdhPJx+Xm+RLbRXWM1xnh9twREpOy18LgyrBH7qZ3KURSZOJTjDoBzSQnoUbhi2lY5xiGvpOlHS3Q==
X-Received: by 2002:a17:902:be10:b029:e9:78a0:dd33 with SMTP id r16-20020a170902be10b02900e978a0dd33mr18668814pls.1.1618138419006;
        Sun, 11 Apr 2021 03:53:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:228d:: with SMTP id f13ls3210970pfe.2.gmail; Sun,
 11 Apr 2021 03:53:38 -0700 (PDT)
X-Received: by 2002:a63:1556:: with SMTP id 22mr22354452pgv.142.1618138418465;
        Sun, 11 Apr 2021 03:53:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618138418; cv=none;
        d=google.com; s=arc-20160816;
        b=LJJ+fU8d7+PvJEPvBhrE2iWxhAJesh9hwN+fCO83d5z5UCd1gvpqKxfcaO5h9Uj2fP
         d142n3TeufVDWz1cdLCF4TZcB5MOi6YwG9XJLOKxeYBHq5acixThpQn1oQkk59jwNRBz
         IvPMPEiu5M3Yf+2NwpFfk89crRe/8AoQMbuPZSHBFCcLRYmkpKzLNdkiOzILBi7JGjak
         pYx3tybaKDbGvUULmKO4hfNGzmlC0UYznCu2+ojDsvxivLl6fiRAqR1ydn2Qy02Fdns5
         NkvrTv6JkkbmvHvsgcaj0LLPYe+RCTFlx/0sL6qgUczr9xrcQn3z8goXAkIAf7nize1D
         lI+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4qNsrz6hVkBjp+T7AuqMxu3ZMoE0rcJnMKd3SW8mn9w=;
        b=zhEzsNiFUXbqW8/nyxsXu0lwgG7doFy6xFY3oXgc4lUEjQR6P+3e5ppiYrsnPbK5no
         oEk2qKWeTb9jX9bt78klYv1KzhW8sigjml7FWXErMBbWtrWcmQUNUBf/hdjPEd7PP4T8
         zCuhdfn/FQvMex/Bel+zbqSHBRU/ZpNHvGpZsjkGR8XYuMMfDueGr8a3ZjsJOvtI/wwC
         6H8LDQ77R1c76CU3yar7bACN6I0BWaJZizVAdOpXO45IVfRS+2Gtwiw4v6Lcw99/0Mpc
         mcHQuHNZtDTOpdaMyAB6zHPtz9aguuJcPOJBSETllc8cYymgi5cthZ0VZFi08U9IrLS8
         8nSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x4si421342pjq.0.2021.04.11.03.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Apr 2021 03:53:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 05C5C60241;
	Sun, 11 Apr 2021 10:53:35 +0000 (UTC)
Date: Sun, 11 Apr 2021 11:53:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nathan Chancellor <natechancellor@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>,
	Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
Message-ID: <20210411105332.GA23778@arm.com>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
 <CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
 <20210330223637.f3c73a78c64587e615d26766@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210330223637.f3c73a78c64587e615d26766@linux-foundation.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrew,

On Tue, Mar 30, 2021 at 10:36:37PM -0700, Andrew Morton wrote:
> On Mon, 29 Mar 2021 16:54:26 +0200 Andrey Konovalov <andreyknvl@google.com> wrote:
> > Looks like my patch "kasan: fix KASAN_STACK dependency for HW_TAGS"
> > that was merged into 5.12-rc causes a build time warning:
> > 
> > include/linux/kasan.h:333:30: warning: 'CONFIG_KASAN_STACK' is not
> > defined, evaluates to 0 [-Wundef]
> > #if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > 
> > The fix for it would either be reverting the patch (which would leave
> > the initial issue unfixed) or applying this "kasan: remove redundant
> > config option" patch.
> > 
> > Would it be possible to send this patch (with the fix-up you have in
> > mm) for the next 5.12-rc?
> > 
> > Here are the required tags:
> > 
> > Fixes: d9b571c885a8 ("kasan: fix KASAN_STACK dependency for HW_TAGS")
> > Cc: stable@vger.kernel.org
> 
> Got it, thanks.  I updated the changelog to mention the warning fix and
> moved these ahead for a -rc merge.

Is there a chance this patch makes it into 5.12? I still get the warning
with the latest Linus' tree (v5.12-rc6-408-g52e44129fba5) when enabling
KASAN_HW_TAGS.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411105332.GA23778%40arm.com.
