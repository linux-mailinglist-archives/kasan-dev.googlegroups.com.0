Return-Path: <kasan-dev+bncBDCIDJ4RTAOBB5PL6XYQKGQE2MWA4HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A40E1559B2
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:36:38 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id t11sf856405ljo.13
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:36:38 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:to:cc:subject:from:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4qYUmzjl9CP0CR+I5EGEexq73dquntbyQsjZVqcjNno=;
        b=D9shgmlxQMMBkrb/dYDnPD2bqlamKyfPtJau01CKoVOy2R4TeKudIX6fRDopdDQGTX
         GaZ/ilZLtkRRlK98VHg4TiJUhX4ihOjE39WmCqa1rbCuMI/CsQycUScVmhj1VZWVBJzi
         c/ZCDvVWdHfSQ/jmSO6g6yh1R4wor5QG/eRWkrEHVOI7N+SgP/fH6kQMiY/RT8p318qQ
         MoZLVJFJnsjmXJmFKFmYvW4vaXsYn8tOHM73XCFVt7yip6yr69UBLTrHtKrmaVnlnnMk
         YmjtATfQ4jzbYubljlKRfY6RInP4DvwlKFWsf2PPKRjqN4UcXsadOAMM2aeNe1/85O7Q
         gOFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:message-id:to:cc:subject:from
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4qYUmzjl9CP0CR+I5EGEexq73dquntbyQsjZVqcjNno=;
        b=kybezv9MIHH8p4VVJXIs/YdXz0siqO5v56pTSi3Y/fjv6njVTYa1Q/La5cbf9b3tgy
         s+O2yWtgfUmkS5LUCvB6QBc19vWPPECDOJp1Xyl7iD16S6oGbeRi02zup0FnIzm3nc6i
         AlLCI0xB94yY7aeu9S4iM5wQ8FrRLQn+Y9G1eqW8Er9H4HcpmvHw5kJb/nwqUL1SZK0Z
         PuvMnCUhRrDkTLGeetlD/kx6FPGB0EH2+9s2dnpMQXM+Ol+aGcc0jnmy381GUMy6lW7A
         HFZW03XWJbNfaQgm+g1LXfKRPkbsUhfXt4IrXytUsw7aC9SxPTD3aw+5e9ldwWVa44DY
         g+RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXaASVHuSV0MdcLpJPhGFW95I/WYdje/qRYJcOi3iP7TEopm2ol
	3aylBcvHuW7DOQKHAwPplDs=
X-Google-Smtp-Source: APXvYqz0F64UkiseIHwb72PdtgLxAFzEGkG7MF9DSMmIGuZFOR9+L7nVckLHyTrIzhPV1y1LzSal9g==
X-Received: by 2002:a05:651c:2046:: with SMTP id t6mr5712101ljo.180.1581086197843;
        Fri, 07 Feb 2020 06:36:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a07:: with SMTP id h7ls2221125lja.3.gmail; Fri, 07 Feb
 2020 06:36:37 -0800 (PST)
X-Received: by 2002:a2e:88c4:: with SMTP id a4mr5681284ljk.174.1581086197292;
        Fri, 07 Feb 2020 06:36:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581086197; cv=none;
        d=google.com; s=arc-20160816;
        b=raMyqJI8FRY5ZK1D3z/JjjWl9gMZiozx/xxibuoAwtS9av2QGWozh+05veBaXglavW
         CJ00EvofMnipe+busugNHdih+oq8aNUBjrrfjsB54FMKHFoqx6VuxiD4C1HpBse3q/aj
         VnZmvcZMilwYoeSJXjYBhdIAQzI9vuwKU4xJBAAft5QKzreYW8NMHZWP/CYKJzizebdb
         kSIwom8KmphKTsLVqH+lmYIlnS+PjMmF+pxIHzd+YscyelytiSs6HCyd7ZACZjgBELUl
         IIuSu3rIw0K7SnFyFgxGXqMqbxNSnoi3xouOT2iE5JwlFZDtkuaCllQQ/sPxkWgIOYmj
         CmZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:from
         :subject:cc:to:message-id:date;
        bh=4qYUmzjl9CP0CR+I5EGEexq73dquntbyQsjZVqcjNno=;
        b=qppH1k/GnrZN4PElP9UWMZ1BNUXslQVJvcitLgtmQAdit+poVTnX/19T6s4W9oQNKU
         5wZR6Ol0LasvCVHedd7/jYU1OLTjukk0+oLBpVQnLJa5PrjbUW1mICQh7zhbRvE6C8PQ
         6Q+mT5sVB1Bj3WZIZ+4uUuassai9QVTXtTNjZbbnJaMoralUOzDASq9vVrVkUIM3ZXW1
         ZgoQfa5PpEo+mDIE0nRhcdEanJ0XUsPH9+Uu3atTCxHKW7B8FWmDvLd4D2mLGhel2rnw
         brWWXu+l9NzRJQIiHavWKIICJu+z2XQ0Hs3jquXWNchoqCKH9D9/R8/A+TTJA994M1ZO
         2ZPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2620:137:e000::1:9 is neither permitted nor denied by best guess record for domain of davem@davemloft.net) smtp.mailfrom=davem@davemloft.net
Received: from shards.monkeyblade.net (shards.monkeyblade.net. [2620:137:e000::1:9])
        by gmr-mx.google.com with ESMTPS id x5si136616ljh.5.2020.02.07.06.36.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:36:36 -0800 (PST)
Received-SPF: neutral (google.com: 2620:137:e000::1:9 is neither permitted nor denied by best guess record for domain of davem@davemloft.net) client-ip=2620:137:e000::1:9;
Received: from localhost (unknown [IPv6:2001:982:756:1:57a7:3bfd:5e85:defb])
	(using TLSv1 with cipher AES256-SHA (256/256 bits))
	(Client did not present a certificate)
	(Authenticated sender: davem-davemloft)
	by shards.monkeyblade.net (Postfix) with ESMTPSA id AD9F515AD7E0D;
	Fri,  7 Feb 2020 06:36:31 -0800 (PST)
Date: Fri, 07 Feb 2020 15:36:30 +0100 (CET)
Message-Id: <20200207.153630.1432371073271757175.davem@davemloft.net>
To: sergey.dyasli@citrix.com
Cc: xen-devel@lists.xen.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, dvyukov@google.com, boris.ostrovsky@oracle.com,
 jgross@suse.com, sstabellini@kernel.org, george.dunlap@citrix.com,
 ross.lagerwall@citrix.com, akpm@linux-foundation.org,
 netdev@vger.kernel.org, wei.liu@kernel.org, paul@xen.org
Subject: Re: [PATCH v3 4/4] xen/netback: fix grant copy across page boundary
From: David Miller <davem@davemloft.net>
In-Reply-To: <20200207142652.670-5-sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
	<20200207142652.670-5-sergey.dyasli@citrix.com>
X-Mailer: Mew version 6.8 on Emacs 26.3
Mime-Version: 1.0
Content-Type: Text/Plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
X-Greylist: Sender succeeded SMTP AUTH, not delayed by milter-greylist-4.5.12 (shards.monkeyblade.net [149.20.54.216]); Fri, 07 Feb 2020 06:36:34 -0800 (PST)
X-Original-Sender: davem@davemloft.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2620:137:e000::1:9 is neither permitted nor denied by best guess
 record for domain of davem@davemloft.net) smtp.mailfrom=davem@davemloft.net
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

From: Sergey Dyasli <sergey.dyasli@citrix.com>
Date: Fri, 7 Feb 2020 14:26:52 +0000

> From: Ross Lagerwall <ross.lagerwall@citrix.com>
> 
> When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
> non-power-of-two allocations are not aligned to the next power of 2 of
> the size. Therefore, handle grant copies that cross page boundaries.
> 
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> Acked-by: Paul Durrant <paul@xen.org>

This is part of a larger patch series to which netdev was not CC:'d

Where is this patch targetted to be applied?

Do you expect a networking ACK on this?

Please do not submit patches in such an ambiguous manner like this
in the future, thank you.
