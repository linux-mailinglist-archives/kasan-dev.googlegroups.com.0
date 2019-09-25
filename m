Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHUVXWAKGQEAN7OIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D62F8BE006
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:20 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id r21sf2153865wme.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421880; cv=pass;
        d=google.com; s=arc-20160816;
        b=QvDca+lefewy2kkNCgk/u8PRDgtc/r3r9+YJA5PzRVjZK1unvNALFMpdA8dWu5B0Y5
         doTiwnGaNCwAVAtm3Dn6WRDvw9rtvzgMsfrkw7/W2/ZiDyQ5BLdg6qM5FjMZIOAghi/3
         fj8Blg+WrNPS7QaSK4Lq+X5VUf16n6Nu6vXJvdgg0iPB//S1OV05CouK1qRi2rI99hvG
         PU7PcR6YmcALSuAa2QJrytI6BHg4UHf6uBEgKzQJY3B2nCJerjH+Kgqp0RbbFmPC6ayI
         lqWbmdzLSWu79lvTXgT1ROkkLSSefcMAu6Uru/Cjtn1QP7XdaVaUQIJWeC+794IIH4WB
         4iwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=41LmalNb72sRxbnV2DEQCqqlCnm8SQ0D1ri/Lgu/f0k=;
        b=cwexVRmi2f5LAqnYOZ4flcj327rO9KkghF0ECOqO9e8KtrhInXeUrzjqfdkGfzyD0x
         OmcI0T1GvETfKBCLF8DqUHLlJgJp96LjpkAjwY+Ti0a2z+2Hm+pCAIZWgzVe+z/3dz/T
         Wt+t/YIg2fznrhxZcvRr5XX9KKW2dpghbTzZ4krDr60tuwTfoNpnZ6CUPMueVQSJO+OA
         +5ZQVH70uXtFZ6I1EzkGenck/bj9hWAxMbaMldzTLMVBpoEKYCyLBpXV1uUkmbXy4tC+
         RYcGP/kRW6Ol2TS4X6CPz/CPvTf7TQhCl5N8OwLMviB2eijLU3Hqu1LSUK4a3tWBpEol
         vf/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=41LmalNb72sRxbnV2DEQCqqlCnm8SQ0D1ri/Lgu/f0k=;
        b=YtSQ2nWZoeRP41lsXQqt3m5NNT6uC/00j17p/5hzGm2//lRqyaODPnKLyGB6DEtIUM
         o1Kr7EpJBcoSoNlds3CA9B8j8Xl5X11r6IitfvxO0A8AzWuoHP5AwR+qNRDoyUk6nqKD
         5rBhzXy9l+K8EKl4swhZQ37QwTXCqqHRAVIod2wf4KBj4nEmznEYuTFe608BBlckSJFT
         LGonDKKJ2+hrOriruk8H5PpPc4sn4vEIk8mNKdUxJDgzoi22k1EuHp2VY9RJKE4q7O8i
         63F5sdg4fbOThGvapCOamFmjyPQDW5iuDI7Plg6Qzk194cBmUGFVkQtqUt3XKcNw6n4a
         J1Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=41LmalNb72sRxbnV2DEQCqqlCnm8SQ0D1ri/Lgu/f0k=;
        b=p2djirpUzW5gSM+yt+CuWCtQIXFa+Tdw7GPzeY4myOIS1jWhsGDkC+6hxEEhDAa+iH
         9lgIDd0W4qlYBlSGVv6Ty9zB8iQDOGkscRsEpx3WmGcy2YrcKxWY4K6LdPWkB4lqFaZ+
         ZyDi1cdVvgCXfhzWNaNNYKIFcFbKcNRevxVQx+cEVSvKguqM4qGaibqB2Rpc2Qr5wsi8
         zl4wgkG/SMOEWMBnASPbjwu3PdghoWqXm+mouz7JgDaFKpnndgjjHktN3/2GkOAutcLZ
         Nj1RWIJRF77nyphMw7CGj8Ht28MPFuIduY7/5764nqyT+XVUt/7mYmpFe6HlZtzrDHOG
         ShPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWkG8ojQtxQKQgMVk9e7xDW9ecb1LNQs5D9Nhv+DHExR9vIgRBs
	2ofcR9wEfK6LL3Dl4KXaNTE=
X-Google-Smtp-Source: APXvYqzSuCHtwy5dZRNwU49j6ReeqSgKBSPJk9ZB2X9Z1pHxAUtQ8bRp4wfYaCbhWLezBnxSXByQWg==
X-Received: by 2002:a5d:4f0d:: with SMTP id c13mr9948192wru.317.1569421880549;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:d18d:: with SMTP id i135ls1852705wmg.4.canary-gmail;
 Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-Received: by 2002:a1c:c78f:: with SMTP id x137mr8666416wmf.42.1569421880010;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421880; cv=none;
        d=google.com; s=arc-20160816;
        b=kAYPZ4Mexw4160WzwyHQLV6GDE/5Egk7P1IqBzSnQC8OVQBTPBYrcqd1LSKDRwxpFR
         lA1MzhUzHsDB40x7cYhIBmhWv0jKBA+3zovlfxXT1XB8+6GzNhG9YZkfBgcxEsytpNLq
         pl1y/7STXfPf1oS+pcaYiMp5GFB7q/BbEIjrSqkm7IfjFlEgckpSEbpGFzpQ9R0i19v/
         RCAByY24uyogzdazzmhUb3E9YS0TYzZ5hukIhKknpxEBFWz15IWhEM3aodm3HaMsOUAZ
         Qq85la3tdMHsmBeZofdbsJ7Kq5Ur3ez38LV+drlP/temOyQ4Wgnm/jjl1Hlo3+3zcia3
         ikHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=JWiXi6QsLfAXvpxYYsutxFI2MiZqoFa7+RlJrAi0DtQ=;
        b=d7e5dy54Hcsc46j/UDF9+h1o80xAZlW83dh9iJql/mNBJOBY83b+3GcBSuf7t8RtYg
         jUli7FVSJK6PKnhaU/CylFcuZft8YoxTGHhfHU41tDTmcepQhwLHoGS6m/7Mo90QwROi
         ztXAbrW3nOnmiFTGtkrd/QNECXfJpMHpXvgp4W/wPmpSnV6UvcVf+PTQU7M5Nr4ErTNP
         j4mDSoiCWjA/u6J3FTgrx+rM1v6wl2mOAjMwTKPN6uxURNykKRLhxmTjist1WNf2OYx1
         KFYPqS8DlqiXdbFZYjSwkid4lL4l8K+xcebMYdJvUz52NNYcKLqrOU2Ad5yPiNFSeXil
         1NBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id p12si190329wmg.0.2019.09.25.07.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 093EDB136;
	Wed, 25 Sep 2019 14:31:19 +0000 (UTC)
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Kirill A. Shutemov" <kirill@shutemov.name>,
	Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 0/3] followups to debug_pagealloc improvements through page_owner
Date: Wed, 25 Sep 2019 16:30:53 +0200
Message-Id: <20190925143056.25853-5-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190925143056.25853-1-vbabka@suse.cz>
References: <20190925143056.25853-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

These are followups to [1] which made it to Linus meanwhile. Patches 1 and 3
are based on Kirill's review, patch 2 on KASAN request [2]. It would be nice
if all of this made it to 5.4 with [1] already there (or at least Patch 1).

[1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/
[2] https://lore.kernel.org/linux-arm-kernel/20190911083921.4158-1-walter-zh.wu@mediatek.com/

Vlastimil Babka (3):
  mm, page_owner: fix off-by-one error in __set_page_owner_handle()
  mm, debug, kasan: save and dump freeing stack trace for kasan
  mm, page_owner: rename flag indicating that page is allocated

 Documentation/dev-tools/kasan.rst |  4 +++
 include/linux/page_ext.h          | 10 +++++-
 mm/Kconfig.debug                  |  4 +++
 mm/page_ext.c                     | 23 +++++-------
 mm/page_owner.c                   | 58 +++++++++++++++++--------------
 5 files changed, 57 insertions(+), 42 deletions(-)

-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-5-vbabka%40suse.cz.
