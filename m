Return-Path: <kasan-dev+bncBDV37XP3XYDRBQV6WHVAKGQEUZ42L2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 647058683E
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 19:43:30 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id n3sf58653672edr.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 10:43:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565286210; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4O2derTg8kHuhT9uuvxPrXw2vg/wUQlcyeTL8IQsAsLvUmiTxjO09fSARrgnOSc5i
         pWOxQBcfcG2DPCQQQijGW+yYCibipZvVbTyMv84aqZ4IH86kDtvp+uOyCdgpaSCVbZG5
         zttJP8MfffM59Nn1HeDB0ioOKtqEh/GCF3IedldGRSwc5m8LdjUkjWLHzg2ayFjS4H5j
         r/Q96h7vDbLtHlKlWq7SUrFaMAbW3PC4R0TUpL0ayAw7gcJFS4QeGdNoVnSO/B8gN/BF
         H5R7+6UIuMRgXHoNn3T5DO7q5LOEa3jMtQU4FHtle3+PQNt+5Vp6fwvKX1Qjepqn6/BQ
         BNZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wA0x0hZnkmMIZyqv0LaClc+00VVXT8OFmSbLg5vEsec=;
        b=XjIN2Z8n/tbJVoWeoTFBWf45qsv5K/t6wrwwfgKYBHstp/yMAGmKbYYQBLFC12q2sX
         9c9I/eRhBbyTvqUvn78Oe4LWLCLrMVwosTdMpskgl3qdclmdwbj2JzhRp5pYgfGJNe94
         3FbZSohmbWaSR5jUlrVpbQk4g/ZewEVL3lKh87t5xFnl5qG6/uBWyA5pO0Ifra/B8WIE
         m34uVQWDhDAHvi4b55xbBBwMX4z7Sq+V66mCj5iAWzFeTcGpyGi3lzoCYk1BsJ25eucV
         +eCGsNHcX9MEdTBnyGBQfgbLYB6brOZCQc0h6W+Rwh9QZ9SWk9dxSS0Zv72h8IGpwwOJ
         nJBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wA0x0hZnkmMIZyqv0LaClc+00VVXT8OFmSbLg5vEsec=;
        b=sBWILxulbN3idCE4rlnjUUYQmPQnQKMbNoSVWnm8y3Fxf96uj8FDlenrwWFjeGtP8F
         8NNjXDu3WJokyoob1aEclooz1M6CRO+0ND478K5u2JxhowGQFYrKgc38GuDR8HB4YTS6
         ak45ClOzylai5bz40ad0VWgzZp+C2zuhExDxuDdJ5GaMvw3Lg6mRYU6vU+AtTDdjsxfc
         FRbnkZ0ZyUCa56jyTm9QFIFk4HBc4j1S0+lUHOJayK0iLV94fDP4wxlZ2aLvZR769m98
         RGU+EoC/jZarA1uMM9G2dOQgWzFramlOB6Sx3opISaC0gp2S/SR37lvJ/3QlOzOzsgMg
         IMkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wA0x0hZnkmMIZyqv0LaClc+00VVXT8OFmSbLg5vEsec=;
        b=MroLgS01pOhQpC/pp+xPXVQrqMs8XLOkLqxPk17tAOu5Cs3OEhPoEMShdtQPeEosjw
         F3AUNanSrXOyiobPVseOyHjxJO5z5tNOrnB2sBYUL3XHTHxfcJIszrkFy2dbfdEW39cI
         MZxSXIf6uep5rPfkV4d84uhWx8CMfxzwh4YHjoabcJzy2P88SurzwL0Q8PsvNrq/hvD2
         lnPYaUp09jDo6LmmaRjxvvVxesSmIxw97DTmmfJLVT+HqYeMUYrBFhLoqGKSOBB+Xl+z
         8+xQo58CzaN9HytYYkbAROuMxlUAktzBAfaRpKCHzyNvTz92xNRlc/GueajYd6NSDwag
         MqUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX6oTcPZmYot1/m36hihPpQp5ml+2jSQn+YjasQB8azrjakwPz7
	OSlI1LxVZn4LItBlfMGN/xc=
X-Google-Smtp-Source: APXvYqxL9u5sKMVTrljcWtmWe6P9wUOEyNQdGQKECACJjO3FY6lLI7Do6B4wY9eQTEW/UOLLa6I/rQ==
X-Received: by 2002:a50:89a2:: with SMTP id g31mr17468322edg.93.1565286210142;
        Thu, 08 Aug 2019 10:43:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:89f6:: with SMTP id h51ls42691edh.15.gmail; Thu, 08 Aug
 2019 10:43:29 -0700 (PDT)
X-Received: by 2002:a50:eb0b:: with SMTP id y11mr17243255edp.224.1565286209623;
        Thu, 08 Aug 2019 10:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565286209; cv=none;
        d=google.com; s=arc-20160816;
        b=sJt8nnFBgZho+e5Mz3TNTi617KKZdH7wVHSgbVMc8YvruhgC2lr/Nt2QU7jqEWEiZy
         VSHIwrQNLHUKYgOIdcREdIz3gpVFiFLypeW9GFwmMKXpVmWR57dM6t/4Sw+hvg6dGquq
         DjKnr4pAcMt+MCDSImPNZ1envg8l9CsC99TZ8YdmwigLxVAg8hQ0cV8Glaqh7ZXRwwlq
         Ly1WFLnIEBpjqD1w5zEGjdHclxqHFNXHShYthmGEn0QTAr9TnVPC0FHDjOcxVuCesKw7
         X/wiRDw5eV3D3573kt4vE3QJOSZUz3H+xb1tqQA9LaRWqWvxQ35qknG9JmkpTyHEKVSx
         GWtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=rNH82QolQNP9Pv+6bY7Cdvt8l3HvRf6sz/YqpahQXY4=;
        b=XSRU24QIWht3FBZaSdvKN74vgqLcVQG+VIUAlQIS370nhkVfdtsW4H7+CKVzl7WhCH
         plhnP+XyZ6bq2cSg1PaNz8KUxoG2RRHnphBGWBjrIDfNDWDR6FiQN4AlCI9k31bdwURp
         nwtnUS8cDfSYhuKuWwD8/qGAYxhUxdDYzGOHU6f0DD1wEJ+dYAK5y+TLTcdfkgUpe4hT
         iUL7TEHNnn9t3DpB2IkLQxfZurfAJNEx/LYWpdPrtnliEKL3HX8Uj35qpOk02RRsoKkv
         CzIWk5vlB5hN4Mz2qcRxyW3l/wbE1dVJDx8vgIRxLko2yEIBYNAR6t05gOx6ax3chSZg
         3kIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a41si5400231edc.5.2019.08.08.10.43.29
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Aug 2019 10:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EF16815A2;
	Thu,  8 Aug 2019 10:43:28 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B55B33F575;
	Thu,  8 Aug 2019 10:43:27 -0700 (PDT)
Date: Thu, 8 Aug 2019 18:43:25 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190808174325.GD47131@lakrids.cambridge.arm.com>
References: <20190731071550.31814-1-dja@axtens.net>
 <20190731071550.31814-2-dja@axtens.net>
 <20190808135037.GA47131@lakrids.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190808135037.GA47131@lakrids.cambridge.arm.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Aug 08, 2019 at 02:50:37PM +0100, Mark Rutland wrote:
> Hi Daniel,
> 
> This is looking really good!
> 
> I spotted a few more things we need to deal with, so I've suggested some
> (not even compile-tested) code for that below. Mostly that's just error
> handling, and using helpers to avoid things getting too verbose.

FWIW, I had a quick go at that, and I've pushed the (corrected) results
to my git repo, along with an initial stab at arm64 support (which is
currently broken):

https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=kasan/vmalloc

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190808174325.GD47131%40lakrids.cambridge.arm.com.
