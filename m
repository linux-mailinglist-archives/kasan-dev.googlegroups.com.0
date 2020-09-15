Return-Path: <kasan-dev+bncBAABBQE6QP5QKGQEF4QAIXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 465F526A702
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 16:27:14 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id e4sf535301vkb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 07:27:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600180033; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+JfWpg4KmN09/ayQup6jCs3OkqKXtE9G1EocJaBkny8WUC+B7MmxZNhoayobHMSvm
         w0lsPk2Iwsh+xuADxyMTmWXoorRBl/Yg2KvoyL7oF+XabKhPjiDepYWK+RP9/r2ZZA24
         6eOF5KkcaYxMU/ZSMzArYd/8+jtjbcs3ZbWEND7ggY7owsECzdWyKWXiXQ3tEYpLX4Ba
         9+C5DNJJYQzymsODonGRzH0XJ1LFdH82ZBNnPartFBXNbg6KN+viHFcTXGFCVJZxrgEk
         DCUZSRSE+8/kE2iZ6ZjiCXyCZ2COJLfPaZ4cXAZx4JLsEQXt5KssMKHT3rW4Lym6nCWz
         tthQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=foCR/OJao0w+aTdDa9IbVGbxMYJIFSRLM7b6k37WIus=;
        b=WCmQVKsBDZI1WfNuH7cIMixolu6yEYbAxcllMQkTXEmM3SOpRpUXnB5G6GYbZyTmmV
         rVkQUuJeNTpp35KRUH/xju/ATlkZ9JTmiFVWDIZNhrDZlWvyfTGwxZuwh20pbD7qVCMM
         oLq33J+pEFzL+cOvk82Ctf6f4NjcTeCVhWCcdhc9fjgY43xOvq5BryBHZ+grTlUZOWbI
         IEI0RWxwsypFMm93M5aGGFvoEgknKhunmcUhYgIpnU5wh35n0d22rJl8qhzmZu7CGAFp
         tvrbOoSNTV3lxFKAkn6ZaLQ2bh5zOoH+OHYyti7ySrMjzy+PP8ahHM3T7fG+j4sLSuIr
         lbkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=D50Q00pd;
       spf=pass (google.com: domain of prvs=52053af0a=sjpark@amazon.com designates 52.95.49.90 as permitted sender) smtp.mailfrom="prvs=52053af0a=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=foCR/OJao0w+aTdDa9IbVGbxMYJIFSRLM7b6k37WIus=;
        b=qBYSfcfj5en5ax0MkyL6Zlbjj1qscJFDHo3WL3QpXnMeQj2gWbddJTePpMGuZs7wuW
         TTmYhxwdB49iNVkCGEEIWUhivyZDKcLRGeuGdMbY9vhWkEXt4xTQK3CtUIRZYsYFv/Y+
         F+Vs2517JMKPiYZ1SwRYQF+EDtBBx7KDQP7QvZEoWPWUb4JTQZG5HZHQ3WgfoStejhN6
         KquhONGWX2ozRmAAWoafBU9ZVLJ0wGir+VUEcQtVP+eEp094jnzNBN1YFZXWkFpbUP8h
         rmt731h5A6Ow2/e+1+BxuX36jPWMgbWDlrutoD0OHLZf+VQOueHi6Fkmko/QJVW0Ff4c
         sWvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=foCR/OJao0w+aTdDa9IbVGbxMYJIFSRLM7b6k37WIus=;
        b=jtzaUWJIEsDRWE8MSym/4RAtmnCOkku8duxGrs9/BWrzKuHMEEk0BAnI5qmnMtBgOE
         nJgt8yAKoSCAsIVT6nO6IIy4HkLeMrzkJG29egRnB9Mf4fXSRbbjNB9VzFCY5Wpn4HIx
         k3CJBL7avUp5ik5gKz1bAL2JtQoeToowkRPRfzfkSVL5Fr8QSuCqa5mh6mbXLWLKokI8
         SvnbqAFlfoUa7lykAE6ZEmCVrkWp3ETfM5INoamMEODoO+9SgY/0zSSH42ha3I+zius+
         b5/bpXVjfazncm8mXEBT6GVtPLV1qrWIjWbo9PFzmiBcT9lh4VL0tpgxW3Mz/IGzpAWA
         TOnA==
X-Gm-Message-State: AOAM532phkEhWWdPx+wJBKZEWhJd9eWGt2sI4MgV67dR7EG617gxdkUU
	mPj5H7eNvreo0MQXo2k1DoI=
X-Google-Smtp-Source: ABdhPJwC4Zjfwg0AO74iW/A8g+yclJ9f4OEDTLPEGy0zcAHq6dsSfTUNoDo+uwO2QMQeahfXiPwGHw==
X-Received: by 2002:a67:c799:: with SMTP id t25mr1441016vsk.34.1600180033058;
        Tue, 15 Sep 2020 07:27:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:20c5:: with SMTP id i5ls1664133vsr.6.gmail; Tue, 15
 Sep 2020 07:27:12 -0700 (PDT)
X-Received: by 2002:a05:6102:259:: with SMTP id a25mr10701023vsq.29.1600180032575;
        Tue, 15 Sep 2020 07:27:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600180032; cv=none;
        d=google.com; s=arc-20160816;
        b=ndGIoE6wmKb2rlf4UO+MvT4mB10fjJgLp+RxrGz4HuBt/dH7QfcJADLpBc8ZOa0SZy
         qiNOJflbSY7+9TFzVGF4qPoUIc/8YBKq8/QAnfB9j/AfnObNuDO0ydxUaXCV6PBA2N5B
         DDTiig4NEOsj9q0FiYYQtG0MhmEdBNU4ubhWQzAfAfzOXomZtWWr+/MY6LU4WjroiB35
         PSsft09+mjt1RiJk35gXMDBOL1lmHjJdpwS5navRF7m3laVfMNRGmBm3d/J9QygMKp9q
         PbwwgUEja/xRyB9ZrJWXQO/Ilq8kU5CBh5fn9G+f5B5XuTWtjJQAFWTCU6Rz+Id+rQe9
         hbGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=i/LZXWaJ7nuQEk6+7RdDEQBLAnsXNpBBc/8bshAm45Q=;
        b=LcTcxNs/rZvM/zZVdrfNG2OuWtCy3TuZu0QPkSAZTXXyIWMOTCkg4DhSJRH8oXf+Po
         kwayPp81uD5aGeiiu3lFBGBEJwvKEUjTbPfAdrneSGN0twRNpyYJOE2rXdl9pyhF+yhv
         u9Hk7PRyg+ZCst5sb0fo9xPsIU5B+o7PhNXp9xXRgLF29/5go3TtaND1z3CcAcDuZFBM
         ztnR7Vrw61RkYJmSRFLh7P7HNRzShSY7H0ITaYgCO4NSUyD5MN0kbghl8hdChnLtTw49
         G1LT+yHkKmnIEvKolVo19OnqTn7SBiGPKs9VsZzN1l2fXribyBwWPA78uYgfY/S06T6D
         AqjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=D50Q00pd;
       spf=pass (google.com: domain of prvs=52053af0a=sjpark@amazon.com designates 52.95.49.90 as permitted sender) smtp.mailfrom="prvs=52053af0a=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
Received: from smtp-fw-6002.amazon.com (smtp-fw-6002.amazon.com. [52.95.49.90])
        by gmr-mx.google.com with ESMTPS id h9si514229vsh.2.2020.09.15.07.27.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Sep 2020 07:27:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=52053af0a=sjpark@amazon.com designates 52.95.49.90 as permitted sender) client-ip=52.95.49.90;
X-IronPort-AV: E=Sophos;i="5.76,430,1592870400"; 
   d="scan'208";a="54074202"
Received: from iad12-co-svc-p1-lb1-vlan3.amazon.com (HELO email-inbound-relay-1e-17c49630.us-east-1.amazon.com) ([10.43.8.6])
  by smtp-border-fw-out-6002.iad6.amazon.com with ESMTP; 15 Sep 2020 14:27:11 +0000
Received: from EX13D31EUA004.ant.amazon.com (iad12-ws-svc-p26-lb9-vlan2.iad.amazon.com [10.40.163.34])
	by email-inbound-relay-1e-17c49630.us-east-1.amazon.com (Postfix) with ESMTPS id AE2F9A1DEB;
	Tue, 15 Sep 2020 14:26:59 +0000 (UTC)
Received: from u3f2cd687b01c55.ant.amazon.com (10.43.162.35) by
 EX13D31EUA004.ant.amazon.com (10.43.165.161) with Microsoft SMTP Server (TLS)
 id 15.0.1497.2; Tue, 15 Sep 2020 14:26:46 +0000
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: SeongJae Park <sjpark@amazon.com>, <mark.rutland@arm.com>,
	<linux-doc@vger.kernel.org>, <peterz@infradead.org>,
	<catalin.marinas@arm.com>, <dave.hansen@linux.intel.com>,
	<linux-mm@kvack.org>, <edumazet@google.com>, <glider@google.com>,
	<hpa@zytor.com>, <cl@linux.com>, <will@kernel.org>, <corbet@lwn.net>,
	<x86@kernel.org>, <kasan-dev@googlegroups.com>, <mingo@redhat.com>,
	<dvyukov@google.com>, <rientjes@google.com>, <aryabinin@virtuozzo.com>,
	<keescook@chromium.org>, <paulmck@kernel.org>, <jannh@google.com>,
	<andreyknvl@google.com>, <cai@lca.pw>, <luto@kernel.org>,
	<tglx@linutronix.de>, <akpm@linux-foundation.org>,
	<linux-arm-kernel@lists.infradead.org>, <gregkh@linuxfoundation.org>,
	<linux-kernel@vger.kernel.org>, <penberg@kernel.org>, <bp@alien8.de>,
	<iamjoonsoo.kim@lge.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
Date: Tue, 15 Sep 2020 16:26:31 +0200
Message-ID: <20200915142631.31234-1-sjpark@amazon.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200915141449.GA3367763@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.43.162.35]
X-ClientProxiedBy: EX13D34UWC003.ant.amazon.com (10.43.162.66) To
 EX13D31EUA004.ant.amazon.com (10.43.165.161)
X-Original-Sender: sjpark@amazon.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazon.com header.s=amazon201209 header.b=D50Q00pd;       spf=pass
 (google.com: domain of prvs=52053af0a=sjpark@amazon.com designates
 52.95.49.90 as permitted sender) smtp.mailfrom="prvs=52053af0a=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
X-Original-From: SeongJae Park <sjpark@amazon.com>
Reply-To: SeongJae Park <sjpark@amazon.com>
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

On Tue, 15 Sep 2020 16:14:49 +0200 Marco Elver <elver@google.com> wrote:

> On Tue, Sep 15, 2020 at 03:57PM +0200, SeongJae Park wrote:
> [...]
> > 
> > So interesting feature!  I left some tirvial comments below.
> 
> Thank you!
[...]
> > > +
> > > +	/* Only call with a pointer into kfence_metadata. */
> > > +	if (KFENCE_WARN_ON(meta < kfence_metadata ||
> > > +			   meta >= kfence_metadata + ARRAY_SIZE(kfence_metadata)))
> > 
> > Is there a reason to use ARRAY_SIZE(kfence_metadata) instead of
> > CONFIG_KFENCE_NUM_OBJECTS?
> 
> They're equivalent. We can switch it. (Although I don't see one being
> superior to the other.. maybe we save on compile-time?)

I prefer CONFIG_KFENCE_NUM_OBJECTS here just because it's more widely used in
the code.  Also, I personally think it's more easy to read.

[...]
> > > +	pr_info("initialized - using %zu bytes for %d objects", KFENCE_POOL_SIZE,
> > > +		CONFIG_KFENCE_NUM_OBJECTS);
> > > +	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> > > +		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
> > > +			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
> > 
> > Why don't you use PTR_FMT that defined in 'kfence.h'?
> 
> It's unnecessary, since all this is conditional on
> IS_ENABLED(CONFIG_DEBUG_KERNEL)) and we can just avoid the indirection
> through PTR_FMT.

Ok, agreed.

[...]
> > > +	for (skipnr = 0; skipnr < num_entries; skipnr++) {
> > > +		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
> > > +
> > > +		/* Depending on error type, find different stack entries. */
> > > +		switch (type) {
> > > +		case KFENCE_ERROR_UAF:
> > > +		case KFENCE_ERROR_OOB:
> > > +		case KFENCE_ERROR_INVALID:
> > > +			if (!strncmp(buf, KFENCE_SKIP_ARCH_FAULT_HANDLER, len))
> > 
> > Seems KFENCE_SKIP_ARCH_FAULT_HANDLER not defined yet?
> 
> Correct, it'll be defined in <asm/kfence.h> in the x86 and arm64
> patches. Leaving this is fine, since no architecture has selected
> HAVE_ARCH_KFENCE in this patch yet; as a result, we also can't break the
> build even if this is undefined.

Ah, got it.  Thank you for the kind explanation.


Thanks,
SeongJae Park

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915142631.31234-1-sjpark%40amazon.com.
