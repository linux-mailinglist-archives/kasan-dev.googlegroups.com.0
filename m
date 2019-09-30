Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB3XTY7WAKGQEC6QPTZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B690C20E3
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:49:52 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id g20sf10293365ybh.22
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:49:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569847791; cv=pass;
        d=google.com; s=arc-20160816;
        b=fz5XxKwku9nfxb61w5oqYrNx427A8U9XbVItpSNNN7D5d9IRvghqF3IKd2sl1bKBTB
         QmLOwiZTMd8WGnIqdZuDucOjkfbZCO8uqYjyZSKCaFlrqU+kYKfwf5G5Len18eWsjwmK
         +9XZ8WgySVEZV1bNvMpNKyDwMJObmOa4O9ZS+ulNGy6WV/XDT5NAyxeiu/S5369VYDvU
         q/08m4+QI2pfXwXp3JeuY3C7kE9j4You5D0+MPLidvHGgoar1U9y1F724nXctbMvRxpt
         KUH9vKdSReL+vZW35yYgnlQpL8hKIaHMMIbNJm6F2Gn8c0CwYDfAj6LSC6ebZn61sCz+
         QpAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=J9lSIU3DQtZfprizDMhLo6cIZ6HeSbFHaECYGXDl6qY=;
        b=ktKtyhAPd2sQD5z6oFE5r8cNVD/zpVsQ/at8+SOBaL3F7RSjyoEQC7rAPvhZkevCtF
         HfQEOic67ncNU02VKp3eXAmy2sc/bjvBcnbd4ka1Eb3fDphuJ22QVWDyvcGSbNjr3Reg
         k+nalGJIOso9gCsIfrp8YA2UdhxuXrcrafyPQPlJRfFUql0voI0r946mHK1wec29Na9P
         8eVV6eOD6Hv9YCIl4AHRrWcpxAxkbe8L4PAUFXvPVdI5mgi3KPz4YABNZ9FFA4BNPPuF
         evbUKWar3ZGMTvXakmWH89YXv3RuO4XERRJLoPnZX8Oo0xJzV1pZ9OJQpZuyEVwwxStP
         Uwpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c9rl2ouY;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J9lSIU3DQtZfprizDMhLo6cIZ6HeSbFHaECYGXDl6qY=;
        b=DUc57qve33NK7h0+t/TN9d9LhC8Ue0IRtqVXFgj0z3YeSciVehzgKWmC1RPbjYhny5
         ANp9uM4n7fMpM6CihqHS/bL283kQFIa75Eb8iS/lUbPW88N8y7ghTu/sztkNjzxy0vJi
         f2BN7zEx7igQfjwmlhfIVpGDVMTGyreBLnMECqACdtsSCpTKUcCdyfWSMDLdtRPX5/zH
         5NOWAgfMJyjBTAY97gB0N1vlUkuUDSZCIpKvuTU/bWDWGF67GMZrUhR+Q3gasmGgrJlh
         q1nXjI0jA6woyJo0grZl2v/71BMi2TbAHT+948Em1byYwAhPhQ5842VPnKprjiEoPifO
         YvWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J9lSIU3DQtZfprizDMhLo6cIZ6HeSbFHaECYGXDl6qY=;
        b=PZZHr8fZsuBohSj83pKHaUyuXrpwhbB5xxIKa1i4stDK7gXWQKxDzAHlJxl+CVbnPd
         QZY2B38LHhD7df91d0CLX4WZiLXVtu//P9gwA2ckNCRDbOy9snsmK9vLHNw5heq6SXHn
         r9zu/5Ap2z18Z08UOSQxFEAiEzO50R3M9ptJceDUwOZLMX76GwSOxxehr/7Tn5KZist/
         /qyp8YkqCfQbL+QmnxB9FMgPP1VlMgpyukJHT5aPm9Di9ZKaw1BJS5KOzQYaWbPYrHql
         2IpTCe08ceraiqb61uDo5lYmxASNKHKDwVwS5O2o4rd7TL+mbRDfYobwJRGI1ysWr+Ip
         ZLGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVegdo+YUE/g2XozDoFfdpOBGvSarK4OlsxcZnu6v0emagIn0D
	T7kn3cJm/zzxkXe3p9nAuqk=
X-Google-Smtp-Source: APXvYqwfIrORI43Lc1BA/v/dYoDkRdYUAJHl+NB1E90sQddWQ0/9/sf9benQgGQI7mxGTuoEjMto/g==
X-Received: by 2002:a5b:c11:: with SMTP id f17mr14801219ybq.276.1569847790902;
        Mon, 30 Sep 2019 05:49:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bcd0:: with SMTP id l16ls363290ybm.7.gmail; Mon, 30 Sep
 2019 05:49:50 -0700 (PDT)
X-Received: by 2002:a25:81c3:: with SMTP id n3mr15422343ybm.370.1569847790596;
        Mon, 30 Sep 2019 05:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569847790; cv=none;
        d=google.com; s=arc-20160816;
        b=NfvEF6Kmg8UdMHKhFkEd8hYrRysDHpvgV/Gqid3zUTjxohEpnUvu3zdUZyxcYUxpaY
         zmbKnqzqZux9r8FPvQ65YVIkdYp61qs4jeObX5O2oaMKy2MCqlFkFjBfMWEqouroi8EH
         8H/y5ae5B7J4VU4lJAxLr8RgMgEf4jqgD8qYFNVk7hAKptgFxyYv1mpGBTojcr9B6vnG
         ybmPVLz4ex6iBtGzQkvIGD+78MUpg7a96zpFP6ONqPUcilZ7576Rgy372oYH77HUyzYh
         qBI9HsiTFE4S6DH8lgPAh3rwWMy+wqK0sb7EIQmhDGXguhYBz9NkIJxWX60IZQnJyjiz
         lLxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=6K4t2QaanAjiyfaxIbACT2mjoEJYSRRvAaJqq+DnP1g=;
        b=U180w3/DCfNBypiMT8AcrusjKlpqbvXFoOg9uacSubuvyZfZQBsGi/rWgw3TRAzdn2
         ckvU99xWonbrjfSFzc8PruzlAF1iKCnxdsNMoh9ITYvSOMR2c8eogK6JwhmgYWf7JzQ0
         AbC5jOZ9Ka75WAS5D7t1rX6Nhc/vNPS7sg8DSL2f3uCsRej7ijosah9zZFhj8uhzE/a/
         Ou+HaVQobydJfhMoBogJm4NrWGv5o998NBuYvCxvwl5xfy9j38Esnr1MIuGJqkILl4aD
         Hus116dTwOzojMrow7DPPSdhEwbn+7Muo3jm/G2dtCKA7Zob5HrxXNJkJTd0eAW3we7d
         cvBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c9rl2ouY;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id g203si583718ywc.5.2019.09.30.05.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:49:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id n1so16801003qtp.8
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 05:49:50 -0700 (PDT)
X-Received: by 2002:ac8:110a:: with SMTP id c10mr1071249qtj.259.1569847790073;
        Mon, 30 Sep 2019 05:49:50 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id a134sm5923647qkc.95.2019.09.30.05.49.48
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:49:49 -0700 (PDT)
Message-ID: <1569847787.5576.244.camel@lca.pw>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace
 from debug_pagealloc
From: Qian Cai <cai@lca.pw>
To: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton
 <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Mon, 30 Sep 2019 08:49:47 -0400
In-Reply-To: <20190930122916.14969-3-vbabka@suse.cz>
References: <20190930122916.14969-1-vbabka@suse.cz>
	 <20190930122916.14969-3-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=c9rl2ouY;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, 2019-09-30 at 14:29 +0200, Vlastimil Babka wrote:
> The commit 8974558f49a6 ("mm, page_owner, debug_pagealloc: save and dump
> freeing stack trace") enhanced page_owner to also store freeing stack trace,
> when debug_pagealloc is also enabled. KASAN would also like to do this [1] to
> improve error reports to debug e.g. UAF issues. Kirill has suggested that the
> freeing stack trace saving should be also possible to be enabled separately.
> 
> This patch therefore introduces a new kernel parameter page_owner_free to
> enable the functionality in addition to the existing page_owner parameter.
> The free stack saving is thus enabled in these cases:
> 1) booting with page_owner=on and debug_pagealloc=on
> 2) booting a KASAN kernel with page_owner=on
> 3) booting with page_owner=on and page_owner_free=on
> 
> To minimize runtime CPU and memory overhead when not boot-time enabled, the
> patch introduces a new static key and struct page_ext_operations.
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=203967
> 
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Suggested-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  .../admin-guide/kernel-parameters.txt         |  8 ++
>  Documentation/dev-tools/kasan.rst             |  3 +
>  include/linux/page_owner.h                    |  1 +
>  mm/page_ext.c                                 |  1 +
>  mm/page_owner.c                               | 90 +++++++++++++------
>  5 files changed, 78 insertions(+), 25 deletions(-)
> 
> diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
> index 944e03e29f65..14dcb66e3457 100644
> --- a/Documentation/admin-guide/kernel-parameters.txt
> +++ b/Documentation/admin-guide/kernel-parameters.txt
> @@ -3237,6 +3237,14 @@
>  			we can turn it on.
>  			on: enable the feature
>  
> +	page_owner_free=
> +			[KNL] When enabled together with page_owner, store also
> +			the stack of who frees a page, for error page dump
> +			purposes. This is also implicitly enabled by
> +			debug_pagealloc=on or KASAN, so only page_owner=on is
> +			sufficient in those cases.
> +			on: enable the feature
> +

If users are willing to set page_owner=on, what prevent them from enabling KASAN
as well? That way, we don't need this additional parameter. I read that KASAN
supposes to be semi-production use ready, so the overhead is relatively low.
There is even a choice to have KASAN_SW_TAGS on arm64 to work better with small
devices.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1569847787.5576.244.camel%40lca.pw.
