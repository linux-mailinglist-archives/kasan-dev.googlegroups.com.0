Return-Path: <kasan-dev+bncBAABBCHHSGAQMGQEIDBESNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D5303174DA
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 01:00:09 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id x19sf1184062uat.13
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 16:00:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613001608; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNu535gx1e5+s9YO602yVLOVKejeyPQViTu7nHZ0+46oXgq9jsGcJ+4qpmxN170DdK
         W+rW++60MtnGjFlHWFjMYkpOeG3ydLK1yvhzyPhijPoyfBSrDd3+iyftJ6FGI6gRkb4h
         VzcJbpC47XcafC8XXxna1Zw+JHev7226A54P2/81TSOUM400ii4cwrFYvGMTbyb/OuPR
         d4qqr1unqEp8yZr6jOz/rPdmx2d0l3E91GBpG+QiYoMJe5g9jGbgbn5tkQKPmHAptIXj
         9UM1zAtZ18/6m9ccnVkzuT30ItYf44eU8l2zfT0qYpkWtJH89kKgCPzFy2rvm/0tTFgp
         zlkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=oUQ6OKamcFcZYjFVygoOQVDpqGMNJemMRTjF2+OmGdI=;
        b=qmzbk/mnVzTbtykDwq9rNZ0fRvlDwgEPOZRbAdt3Y2IIl08JK0Qm3bS264dHSwKVXw
         uasvGMMYEXPvI0Koh6imEYp0hi8i/u1YwZ3YFo45mjzsobfrlHOkAMLia/ioaWVNm0uh
         RuzbwXR6WrHjnL42eIqk2JVDeXCy+pdzNm7Cqcy1rn2+BcfIjPiBDDSElV9F7m2Rd693
         s8mqaqqsMdySJRYHbkyJY6KKz3tRGj4or2wRuPV/3xdqB3IbPOLZOjo8mCNKdYrdBazy
         W9siH49qD/y6uhkdLRkXGZb/UKMFs7OxTacQaVn6/qfxPVpP94OCc9cOW/QiDeips4Lh
         f8Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VPa0Fkt2;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:message-id:date:references
         :in-reply-to:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oUQ6OKamcFcZYjFVygoOQVDpqGMNJemMRTjF2+OmGdI=;
        b=plSsfc5Z3TmRzSCQdC2PI3B83oN6q0khH0K7eTHacu16NIfvY2U9Mco6pZfzEUC0kw
         YgFKAFLGrbrwyl/NVLEswEH89XToec37SeCj8KKvoZRVo8VDUcMADucFDl2+jXd9p4ZV
         veJDGrIL2F02OLTCtabMeIcHfHTGG2aImWh7g6z5iDt89gFGetclXoy47AV1PS7ykR/n
         ba5sju//GjFFaXAekF3M4ZvgmKp5iPMTJ10HqrtWfIEfD7G20Z22g96eJYhEbXFQWsPC
         Hjt1fDJ4FoPufobcTsHfdPjz0bzEVqV5KmMrn2hTrUNR8zPrxws+WBWOmUpeu09vfIsB
         HYkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:message-id:date
         :references:in-reply-to:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oUQ6OKamcFcZYjFVygoOQVDpqGMNJemMRTjF2+OmGdI=;
        b=CYkeK6WxFTInUrzPolvbXD7QhnuPmvzkdx7h/qJfMLLcW4Fg20bYBaXlheIxqJ0VY1
         PagyBJ+GdggVqNnptWvCIoeWtgvzSSH4GQSjVHiBXXjRIG/YadZwAlFM/Th/xxoszwIc
         wqrD1ZY0V0K8N8AqPffcMSvCTap8koBszpcwG2tfYx7BIK6rxxq7UNkCB0p06Gh7TUc5
         /FCPQzIC2VQ3OMiZ976OyuMFZr10HU1lrGTMIQdbpsEbvrgJ6AE7aikBMZRI9UTTQsvI
         RsFr9BceRDtjmU7iVwqCGcnIvzVbqJDMpqItzQ16tLWMQdjQwHYFqAegoWhlmwZ2JADI
         oxLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53105y05u8k+QvYsdjUecuWFU3xN2VkaySWAQ4t7YqHk8TJA17qL
	AQspWiBy1oUYpgpN03vT0c8=
X-Google-Smtp-Source: ABdhPJwmGEurX86vNR39TTRHAKnUJDzhlNFJljhrpa+k6K6VbkT6zk+MZaa2UgouJjQtKVuWHAoKMg==
X-Received: by 2002:ab0:748c:: with SMTP id n12mr3799059uap.38.1613001608617;
        Wed, 10 Feb 2021 16:00:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3127:: with SMTP id f7ls301216vsh.2.gmail; Wed, 10
 Feb 2021 16:00:08 -0800 (PST)
X-Received: by 2002:a05:6102:8f:: with SMTP id t15mr3695501vsp.19.1613001608304;
        Wed, 10 Feb 2021 16:00:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613001608; cv=none;
        d=google.com; s=arc-20160816;
        b=nVVTKcMFclIboSIDYqn2Oo9u6T4ejGaXGFbefRc+iMyr3dKN4cbdkMMAI3dvCj/FsM
         VBIK5FvudjLJp2hGWE3LaplllGtJPePl/xni3XS37uYc2iHqyuAFUeUu0aTShnMmAzem
         IlaONIoOjjCeM4YlVLfnHc7yFq5kjWQ9bB3UZNOROWvbuN1yOkheqwOCigVOCAuN69jz
         kH2gTOrzN3UvQET8EzjSTmCDjampmtjSru/E9qq38d1rmAhROe7p9EE4xy7jTHKzHBtY
         LFMYMd/t7/xntzX/LMTyYOptc4xTrbzIWWGr5oA0OpKUh43BLzbNen7FZsk7nyFp78TE
         YwXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=WBGLHSSih90MVr6y+jRkQ3P8F80KnJ17IrPVdWsMErw=;
        b=w4aXHAoOxSo5c8l/L4fNTKqYvOjkik4WDtQW+0BBHtjBPk+n1mM1pPYDmJCBOea/s8
         guvHjvdI/cT30UnbT8CfeR6PGTx4XE8nGfCrsquGtGciX1qgU6rOpNnRKvZqEUHPotAa
         EGriFtGD6Z8C44M6pOpF7FwxQXUknzBQc1MMZ/XI6ONuwaYiCa8pz8w5Qp7swv4Nea3E
         buefqq42rQneagtNw5SiaYyShel5vsXnpRZSYna31Br21jNP/nAWqhml18OYU5wXngNA
         8vJhX8tMAWHpeRNnDfMKWwxxsNzPlz6UZFR+crfhBExHVUZcBcn+7Jq0KIZoPV5T9eM2
         UiVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VPa0Fkt2;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c4si248070vkh.1.2021.02.10.16.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Feb 2021 16:00:08 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3DFD964E16;
	Thu, 11 Feb 2021 00:00:07 +0000 (UTC)
Received: from pdx-korg-docbuild-2.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by pdx-korg-docbuild-2.ci.codeaurora.org (Postfix) with ESMTP id 2945660A0F;
	Thu, 11 Feb 2021 00:00:07 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH] bpf_lru_list: Read double-checked variable once without lock
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <161300160716.412.6891143842651326044.git-patchwork-notify@kernel.org>
Date: Thu, 11 Feb 2021 00:00:07 +0000
References: <20210209112701.3341724-1-elver@google.com>
In-Reply-To: <20210209112701.3341724-1-elver@google.com>
To: Marco Elver <elver@google.com>
Cc: ast@kernel.org, daniel@iogearbox.net, andrii@kernel.org, kafai@fb.com,
 songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com,
 kpsingh@kernel.org, netdev@vger.kernel.org, bpf@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, paulmck@kernel.org,
 dvyukov@google.com, syzbot+3536db46dfa58c573458@syzkaller.appspotmail.com,
 syzbot+516acdb03d3e27d91bcd@syzkaller.appspotmail.com
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VPa0Fkt2;       spf=pass
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

This patch was applied to bpf/bpf-next.git (refs/heads/master):

On Tue,  9 Feb 2021 12:27:01 +0100 you wrote:
> For double-checked locking in bpf_common_lru_push_free(), node->type is
> read outside the critical section and then re-checked under the lock.
> However, concurrent writes to node->type result in data races.
> 
> For example, the following concurrent access was observed by KCSAN:
> 
>   write to 0xffff88801521bc22 of 1 bytes by task 10038 on cpu 1:
>    __bpf_lru_node_move_in        kernel/bpf/bpf_lru_list.c:91
>    __local_list_flush            kernel/bpf/bpf_lru_list.c:298
>    ...
>   read to 0xffff88801521bc22 of 1 bytes by task 10043 on cpu 0:
>    bpf_common_lru_push_free      kernel/bpf/bpf_lru_list.c:507
>    bpf_lru_push_free             kernel/bpf/bpf_lru_list.c:555
>    ...
> 
> [...]

Here is the summary with links:
  - bpf_lru_list: Read double-checked variable once without lock
    https://git.kernel.org/bpf/bpf-next/c/6df8fb83301d

You are awesome, thank you!
--
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161300160716.412.6891143842651326044.git-patchwork-notify%40kernel.org.
