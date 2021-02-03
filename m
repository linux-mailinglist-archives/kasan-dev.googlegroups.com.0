Return-Path: <kasan-dev+bncBAABBLEH5CAAMGQE3WJRQAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id BF28430D129
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 03:00:13 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id c12sf25760867ybf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 18:00:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612317612; cv=pass;
        d=google.com; s=arc-20160816;
        b=KVrE6DgqOQuyKB/xgQMvHYI9etumWg/VWlNW0gs7DUjGBSkxjTk0rxRrbwnhb5Ndrf
         7363QLTHZAeyvOANTbgvwJLxpbbVKHEe8YVynIW+8ljX96DjoqNFRKqiah+lK3HV8jbz
         ePdwcDF1rSq257DJT3g7wS56xdFzwD/GZohv2XFTedTYDmUmvi4VF6Nfbu8bv+4PwyE9
         5eE6c3JzphvqaVDRR3KDJCB21pGc8W1tJ6yIWdnGzS5hv7iTWO6EN198RIfucxqcctaT
         wLLFJh7xb+pl7CMnK/PabwRSHtEETheEA0TqanDpr2YH2Zn4YXs0i5pRlPsPuHMPPw0Z
         4k0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=10cnk+/a3yWYWYUU26cGUcu/nTDlGOWDipMrdCn3ZRY=;
        b=AM1pIUmOcBEGbpuE5Lp+PdSf1Siwr4xeRmmV4ALLGdiwb/RClE3XchwcYSTxOEOWbS
         Ne8z5SmbQCUnM11fsy/B8zLr5J0+ADILP9rTtXJTQVNnz/j91HOKjPk+nrKETO5q9yAr
         BtCleXtEEKC/mX/NeNTbL39+A6Ia9Obzr52JOn2y5DhdBciAn09IEJz4Gd2p0Hf5m8tA
         AhrG+CrMcndcbL5W8+zx9H2pY873jvDYTJq2gJWrmXVaeLgUDxoz4UoRD7gNrQPEKsfg
         zQwgcJO228lH8l2VGyxzTR274Vh5Ulh0iQAlQz2uvAN7VOvy1JdWy8KwdF/YNTwUHtj7
         sOfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DkUxOCnx;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:message-id:date:references
         :in-reply-to:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=10cnk+/a3yWYWYUU26cGUcu/nTDlGOWDipMrdCn3ZRY=;
        b=Z56QvAs2kbs5i5o4r84uHYNnhzk41guc2MwCbRm0IdtUXvGBgtKOg5MpXLhlD8CNwt
         R4cVzEzCQs8addWFZYvHwGWHlDtAuVpxUzozsHPQAcrSZKLgzVAY0l6qUlKdowjFDU2W
         u2hjcJqcTfEA9t0CfHOLoFIFtInAZwqxm2SoDesZmF1b2BOwUNg0QdlJJpJg9bcFR9If
         k6Z0STUivO+vl2jwyUQOT5W+kg/prkhzUMR8A3ziXk2FuGY87Lqd+W2OkiC1db7sma1b
         3etuXd5IR+/s4AATS8i7sgO7/9Vhnw4kbi70gdesxYjN4yDNr9I9oJrIHyM9sNFIxlJp
         Y8zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:message-id:date
         :references:in-reply-to:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=10cnk+/a3yWYWYUU26cGUcu/nTDlGOWDipMrdCn3ZRY=;
        b=hAO4bXroYqmOP8UTeOjrcSek+iOIxzy0rbdV/mrCOgcriExFuOrPoGBAcOXvASHTs6
         5+rRRpqwu/QQIxp86PIsXaOsHVeAq7SQUX5yiHyDSx0sGlLnLUvp3K9iXWGFKBXYFU0x
         VR5PhwRTWND+cJtWrtFQpZaX0bN0i10b82n4xY5LGvSUTbaNDR+siduf734gh8Lyq+Hz
         9XeNDad0Ct5LkCL1TpmzJb4N0iQ0yVdYJP1ZdRgJF/zDwJZuB/AV2hK0QUAH5TWAW6yn
         PJOC9S1VbdIpVjboFeZU8NynpYx/doCPx6pQ8b5iM1Zynrvpe6vIwPNlV5dZz5TOo6C1
         eFBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZLrbxlKkFPoXdUDrKMJok8N5BXXinsPjzLimq7HGQY9luQM9s
	kO8/O6Nv9c/AkWKTEnNSH9E=
X-Google-Smtp-Source: ABdhPJx1ob45gG8uBENScikf5raSleWJeqaOtsPWSPDdZuL73e5zGhF+x8B0sc5F1Jh3qkUvFGd3Mg==
X-Received: by 2002:a25:888f:: with SMTP id d15mr1262980ybl.12.1612317612684;
        Tue, 02 Feb 2021 18:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ff19:: with SMTP id c25ls342178ybe.2.gmail; Tue, 02 Feb
 2021 18:00:12 -0800 (PST)
X-Received: by 2002:a25:9247:: with SMTP id e7mr1103692ybo.440.1612317612267;
        Tue, 02 Feb 2021 18:00:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612317612; cv=none;
        d=google.com; s=arc-20160816;
        b=DdGlZF6juUTteWky1evQzxS9TBK/GiuIgH0XdoKiwNJ+2Hm4mVqN39NWorsDXNyDmB
         2u+drLC6MuMJYIbfrEcldwjmRBaWPcoHUVXwrt3JAlBEe3ou+K7p4GCgfEUoricvQEZX
         LSgvzrpK2s/OlbjwKn6Z6r9p/ViC4fQ6zDMRncXB71PeEmuYAWyBbSK2ZAKMZLIdPVJa
         u+QRepo2u1O4iSuljSNIjIhEIL7yN+kCxpwxGAeuwyQp5xKtb9hEkJBxzdt9xTOldkmt
         XdqLZ/XjREMiwTcHHBuGz4nZJJqLZVmL0T95dg5I+DlfjRDwkZWo96Q/TEtuo8oErJx7
         AUqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=3PGZic4OzkYVa22xTPvO4EhyMZnZqOn+ZNaPEjGUJes=;
        b=xdWWhc8hB91JWmPp6b4veVXw7NzTA1Br0NqLGt8ukzVl2r8fGq17qMwwPsjeopDE+k
         gzbfnIvu9Sv6YaWJZjom+rMf1PsneCphCZKYEIE51oGEZUcun5hm9rROXq/gmb3XNBa5
         Yzqcr9e9SM4JdsoqcYtLe/A467DBuCXmmNbqux79gs3+dJ7Bit7qoDWb0jjH6JQi5NSy
         F5q6XDuHtuIKRdvBhkk6B5h0BR8ZLpHnE/Vqkz8dqfbfTgfCJTdg6X72wwCbQtJhcdfw
         797Q9LCBshlxUGVqRf0SZflEvJ1iP10sbkL3iWW7GgZE+h4kU7P5uOScSFlPt9mLAP6N
         ex5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DkUxOCnx;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k12si43479ybf.5.2021.02.02.18.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Feb 2021 18:00:12 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id F21E864F7C;
	Wed,  3 Feb 2021 02:00:10 +0000 (UTC)
Received: from pdx-korg-docbuild-2.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by pdx-korg-docbuild-2.ci.codeaurora.org (Postfix) with ESMTP id DB8C8609E3;
	Wed,  3 Feb 2021 02:00:10 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in
 skb_prepare_for_shift()
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <161231761089.3354.12212298299944124109.git-patchwork-notify@kernel.org>
Date: Wed, 03 Feb 2021 02:00:10 +0000
References: <20210201160420.2826895-1-elver@google.com>
In-Reply-To: <20210201160420.2826895-1-elver@google.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 davem@davemloft.net, kuba@kernel.org, jonathan.lemon@gmail.com,
 willemb@google.com, linmiaohe@huawei.com, gnault@redhat.com,
 dseok.yi@samsung.com, kyk.segfault@gmail.com, viro@zeniv.linux.org.uk,
 netdev@vger.kernel.org, glider@google.com,
 syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com, edumazet@google.com
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DkUxOCnx;       spf=pass
 (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello:

This patch was applied to netdev/net-next.git (refs/heads/master):

On Mon,  1 Feb 2021 17:04:20 +0100 you wrote:
> Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
> cloning an skb, save and restore truesize after pskb_expand_head(). This
> can occur if the allocator decides to service an allocation of the same
> size differently (e.g. use a different size class, or pass the
> allocation on to KFENCE).
> 
> Because truesize is used for bookkeeping (such as sk_wmem_queued), a
> modified truesize of a cloned skb may result in corrupt bookkeeping and
> relevant warnings (such as in sk_stream_kill_queues()).
> 
> [...]

Here is the summary with links:
  - [net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
    https://git.kernel.org/netdev/net-next/c/097b9146c0e2

You are awesome, thank you!
--
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161231761089.3354.12212298299944124109.git-patchwork-notify%40kernel.org.
