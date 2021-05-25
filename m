Return-Path: <kasan-dev+bncBDAZZCVNSYPBB7URWWCQMGQEXOTORHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FEF4390953
	for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 20:59:11 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id n129-20020a2527870000b02904ed02e1aab5sf43685753ybn.21
        for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 11:59:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621969150; cv=pass;
        d=google.com; s=arc-20160816;
        b=GXKqYg1u79jyAKJm65V1erQ1TocK9YUCr21Vgwy/54J2wKH39NyKXz1vbsRT84IPgz
         ZsZw0fytK0YUupzxTObXVnfhhB/Yd8kuYcFCl6UCethVReVf+9grG/li0GslNRBXumRV
         NMOUr19I7J9dMPNTSaatEUp+fS6a2MgIvfBVXm/T58blAVtGM1JJupN/lDx7TPr7Me7S
         6VVLoAFb9c0MQntilpgHqABTOEErWl/qebXsw3PHlunvgiXoouzPv0ARjui6HiZqpsGs
         ElwZtVaXi1NyATHC4+UoLWNUmSqiVWtGOKDqH0q1I4P31De032k4+tLrNMNW6pLuCJ4n
         sjVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pQ8JqPqKLeli+n1eSs1BWZ/yFB2WIh0bn5gwpHyn8Zw=;
        b=w2xSmlQvFD15AAT7XxbFOXOYBp6CTpnzYY6GsO7mcU+OhGoUIJOPav1lZTRGWe5pqc
         Sr4WKnm+PiqL3cBcylMkial2V+af4PihthW1Ne1B99rsB0eAZyZ0vTvB1XYZRx91UIvN
         KPg9psUlVSjT0QAvchZOZq3TS97p3EyMpGRSxyDW7EnZnCGiC7dtveozkQoKZeBN8Z2P
         mFGZyiLXczeExBA8XPVxUwrvovHM4piErvD5pDmFeHbjh/GMXjDBTg0K/ehcmaoAhyg4
         EbvNFXtJATnGouQkyc/Z7omr87ebesw9+6bY53pIDkBNKu8QhArtpfkNNHPYtpnSsujz
         fs0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RTwbgM7y;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQ8JqPqKLeli+n1eSs1BWZ/yFB2WIh0bn5gwpHyn8Zw=;
        b=iXa9O33DKpktgsRC0m3bKu0j0BcKbu9S7Qn+2NpjhM+dNNvokZmPUpUaos8NJm74n7
         JwUrCR7+Qu5ijw4kB+0pqkAqMBlv8clOIu4IqmRX0GWEAfmadUekjbB5SnVw7LmtG9Dz
         dI8t0vpfOZ3g56SnOxo3V1w79MRsmBAxq3Sqxl+Di0T8eef+ox8lA2/RVBqCAs81YO36
         psXCPLYIseyDqLcRYNltj0DuTFDQa6TTJyFePoe4F4q5K1Vh7TzPrZ3ou1DE4yQ46oz4
         F6qV01Q098qGeyvYgiznCRTcktZbQAWDyyQIepfNNvwE3l0dzX+ZFP2lrj6OZy7Iuk3O
         4x+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQ8JqPqKLeli+n1eSs1BWZ/yFB2WIh0bn5gwpHyn8Zw=;
        b=COl8Pt5HaRrZExCQ7kl5GkcnHbLQSMpZoiV/X8IN0Eq9fzdLSi2wq/Gp2zbvHqARXL
         iItaVEuG/b9xo9qGmdmY2iuGwWibQG0aJUQVQyXhh4HYIggMyzlQFyAMkqJaDw7eOR2E
         pk9OTJ0+YVivVLU1MXd0b6EcZ+KHsgE0cHbbE2SwA3wy5fjar0D5amrO0KVoCObzK4p7
         RiQedFZwQ7Pujo/Y2HYiMUquv4AcQcckq8OdrGrqBpL3ZhBfOWDfRHwZq+oUw5vXNC9y
         WLVV2rrxP8YVqpnwyy8VYVRC0Oio1QCMbIR4N+Xndfnr2bynQRexdD8u51zJPEjuTJXK
         yxWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xfbx7mvVvJSYYy9MsVyagaYc46KPF893eUVhxhqQ+zjbAA3fG
	t4lPBDWWyAGeq7Lr4WyM014=
X-Google-Smtp-Source: ABdhPJzAlxAtCzPQ3MW2LxhxgxsWuE0trnX2Szv2auKK3FxXX/HiwqDvU6dMIjdFRquUDbKzrh/kWQ==
X-Received: by 2002:a25:19d7:: with SMTP id 206mr41723795ybz.483.1621969150435;
        Tue, 25 May 2021 11:59:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a045:: with SMTP id x63ls9532563ybh.1.gmail; Tue, 25 May
 2021 11:59:10 -0700 (PDT)
X-Received: by 2002:a25:b9c1:: with SMTP id y1mr45077309ybj.321.1621969150007;
        Tue, 25 May 2021 11:59:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621969150; cv=none;
        d=google.com; s=arc-20160816;
        b=ZHEzjEHSPdNhn/tKkhnRNrXHSdtp0hY6whWfBGJdI4uK78RvxXk7pV6UsQn9Fz1Suu
         Re/eRZa95R1r/GpXZEpRsX1GnLVMXnz8kvGJPAOse+KIc1hOqRk+d1urYiyatrgj65z0
         4G3D+yS8E63WAw/3MDFCe4GD+8AHMRWLJtUQ93EXZLlkqsuYvGgWObMrtLl9ksc+JyQv
         1cD22NeJ/gJcGtYuot+sFA04aeuwTRHpbf2Gvz/G8hHO9rOrgdDVASCmFHtOBX4R2dSO
         lpH2Jk9a1RgAuHhl4hBBzAutJKZimOH31wdta+RgfY6bFHrTkQoFApcZIYQuynDZ9UT6
         p6uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jAv3cpD81TA2XZWWixz7240ecQPAM4oLJaJb8+CNt5o=;
        b=TyyCywfogCLb4+HLSZF9RABLtX29JRwKJv8XymVPD3Gto78T33yMk3FqWmEVVBlUWr
         tVWYS4UatLDvTRi3+p2QOZK/f0zFIpTpYksZAhoUT8kX6VhB6Wh8a36212RruVOiEBbI
         gxF7Z6cKPMCFuEFB/LRvXF240Bx4ED+q+t5u439oWegbEfuxtd/Xiv690KdppAF4lmb5
         vEKOpV19oZwifV0qRNXoqixqwJW9qS4IDaMRhXVvifIVx2lQJj3IeTmyivWHy7XGvARV
         Oby7tFyDFrYW/aBL+dXdCu7NwR98NgjGHvynyEv/lB7++tDRW/riG/8/oWZSM4BLd/1z
         Cjsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RTwbgM7y;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r9si2509600ybb.1.2021.05.25.11.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 May 2021 11:59:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D13DB6142D;
	Tue, 25 May 2021 18:59:05 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Steven Price <steven.price@arm.com>,
	linux-kernel@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>
Subject: Re: [PATCH v5] kasan: speed up mte_set_mem_tag_range
Date: Tue, 25 May 2021 19:58:47 +0100
Message-Id: <162196691854.2317985.15060469643983512129.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210521010023.3244784-1-eugenis@google.com>
References: <20210521010023.3244784-1-eugenis@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RTwbgM7y;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, 20 May 2021 18:00:23 -0700, Evgenii Stepanov wrote:
> Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.
> 
> The first cacheline is always tagged using STG/STZG even if the address is
> cacheline-aligned, as benchmarks show it is faster than a conditional
> branch.

Applied to arm64 (for-next/mte), thanks!

[1/1] kasan: speed up mte_set_mem_tag_range
      https://git.kernel.org/arm64/c/3d0cca0b02ac

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/162196691854.2317985.15060469643983512129.b4-ty%40kernel.org.
