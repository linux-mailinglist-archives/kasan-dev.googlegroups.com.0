Return-Path: <kasan-dev+bncBAABBSEZSP6QKGQE7U7P6NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C2D052A8E17
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 05:10:49 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id j17sf1667853ots.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 20:10:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604635848; cv=pass;
        d=google.com; s=arc-20160816;
        b=yHr5gar4GIwNc23zzopo/PuYlDvoxGcWG3X8NeE15ZHjMsC9kISagZ4CXIo13X1b/t
         GRZD/KXKDh/5lnsNavk3sIKHQzqnqLs5+sAKDxSrHBD3z19O9vOKzOjppi9NF6PxjJRh
         hbb1J6piFuGwawu4zR6y05ceDISQEacqF9+IBM9Ctr3ITVsr5sxn055Oaw0PhZujCiPJ
         vsiZPwLar6fwJMwQ4PEacox7STJBPRrKA4ycZQm7z2wEbctzLJ1KFSBVJhcVfqwdrhWl
         hHnxIuOkT9Cp677yyyW0UgqQwywRqaRKhrYUdIKa1xLFLYxkVrCIrnDARzsWEjYh254M
         tqFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8rlOvK96hi4604/5punY4QN9gTR28M+fk2gPflkxG+4=;
        b=kVudpzogLKb+meYuHneV4ejePD+ARMdAgwZPRahYaAlA2SDqf5H+gbreS3A1RtFhAT
         xEFWXzltYgs7b39yzA0Tayqfi590ktU4g/DgVky0tb3ds/CjkGk79ymi5d1RBDH4N/bI
         4Jku0cX6VgjlMQc/a1Bba8d4uwrRQDMlQaFNE3Wp5PMzUU1z/YB5TWm6Q2I9F9zxFtCY
         9oVexAwX/0VkkwgC2VtC3qXASjsoc4RH7mX/m3pEYviMQCWYlkuM1gwX9bh3fonMFkv+
         QpDqkeqiWgIZLA3YdnezAapTQe1cvHC06SdZKngom7P9Cn2oz8v/nMPMc5HxegfpA+R8
         6b3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oc5sl4Oy;
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8rlOvK96hi4604/5punY4QN9gTR28M+fk2gPflkxG+4=;
        b=GaBTcDexi/wgjRRciOLc5pf98mxd/xmLlX5Hr/IrfuALmCTpx2GUNtvUzy1r82CNZ0
         9ips02t1P7P2KfksRZTzAfXVhOZGU88PUnaFqDMDWKbpvo5abUpWXEl6SY8nTyklORoP
         Rw2HP7zwq8Eo4NhUKE7aEunm04n1kNAfGvhNOMUzoHmM0EuL+wsPeEKDO3GBa7fzXYCt
         XwGhCObTCjG1fwaIvCJEd/sB5+oYLaPWIxnuBueykQo0RUoJluKjCF32bpw6fP/xKkTU
         BI/dcPlMJjw/sNNc1BjuIo/CVfD07eRKgmmgv3/ZFUlWghOpU65tFanNya7DeJf3kYx6
         3VOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8rlOvK96hi4604/5punY4QN9gTR28M+fk2gPflkxG+4=;
        b=GYyppnHnVes+9nX6uxi8ehXB8QHDCT/7MfX+g62IyTFJmEMHA3wT7tgMKEgfINHlRi
         BuTvVLPb4XLyJMif/qLvkjwZMsx3xctsqJpPmyzDVf3GFlLiT6DQYdLT8U0szJRunAL7
         Zvr+bHLTX0mN1BzLy4+xqyvZ5PCdUgppbXYDnsxD2dF0uQs31zrqN0jrSn64Jd4IH9Mj
         MVEshPH/5RGN4JZvug2Tm/Td7uYwNf5ZBFpZHfvVphvnHUctWtVt6CLMDvfD2c7GHRUw
         QlGIWVp4R/pYR26cDQx+T7YT78olFOq/PO67jPTYfgTKUbWcxvTqZb1/1R/Br2rwN3kl
         yjkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531A52j4yibbe8OKUZ5/CGZM4eOPsVIXqSYeQ4GcOJP3fWfDR0Qv
	HjCmhI2Xezs629+F2zbM8DI=
X-Google-Smtp-Source: ABdhPJyPv0CLtrM8GDb9LiWlrFlhuQCyM1K6/OwllCmwu5qJ/yQWVCiXJUrbQOeD7WkT9D7BSfjyRg==
X-Received: by 2002:a4a:e04a:: with SMTP id v10mr22710oos.24.1604635848289;
        Thu, 05 Nov 2020 20:10:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:53cc:: with SMTP id i12ls994882oth.7.gmail; Thu, 05 Nov
 2020 20:10:47 -0800 (PST)
X-Received: by 2002:a9d:6641:: with SMTP id q1mr3956947otm.190.1604635847926;
        Thu, 05 Nov 2020 20:10:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604635847; cv=none;
        d=google.com; s=arc-20160816;
        b=tJtr+sS+pFzXhW9hb+JPTgG4aEVj9vDZC4k9dDAEcIkJS3SDK3/au6BCxTlTxnn+Oz
         jCOV/mmTcg8OxECNXCEOyDWS+k2JTU6hgpiO9IDd9owJ0iCe9vR06ks3JE50Zhk//yoB
         dmBOCNnO2Zhk29DVOeyawa5vzEIvImbNb1fO2b2NSrfajFcaNYAda1XymqXHA38SHJXA
         YIj+utC+cTWwE0fBTKza/T5/BsuvGjnNNBTTquUR3/MvXbPvibhvhv0aOJF7cAVeBuKa
         Le8X1GTxVZH7jyucy8/6SC8O8YOL3t5yDDzCJbFZVfQWOvxhmkX8Spbfsj+MjKGp8/n3
         qCIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BiSSz+HGcBoP248BMU9Oi+YhFQu+hZPBlQcmFxLaxTA=;
        b=auh9s1oNoW4993G5Mfr6zUlSJrtY6pJnx1cZrhLa3VZCZPj69cC4hyxVpaD8aYvn94
         Rt09dfQ7JKUvAGV0m19Ym/ztmgcepS4AtOVC92/qe8MQQORR1HBtTK1qvtUm4PlRKh3g
         B3ATXg05RXOQqFMs7K/XJniKjcfsKnqOXldFCiDHTq2KdXA8qw5/NofzUamTOBjcixae
         T9/Q1mtgVlYJqF9UZV0KAWKs6GwkUmsCg0QEVbyV6Zx81e8+su7TKVt3zGVTwq4Luzed
         XcM1UnfpajmsBVKFWVl3B0P54NQf0rjFLm3hGDz1dsZpbLcDya1Q3sMHWkpL+jW/lqea
         oPXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oc5sl4Oy;
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h8si13350oih.2.2020.11.05.20.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 20:10:47 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E7ABB208B3;
	Fri,  6 Nov 2020 04:10:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 8E7713522AAE; Thu,  5 Nov 2020 20:10:46 -0800 (PST)
Date: Thu, 5 Nov 2020 20:10:46 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: elver@google.com, dvyukov@google.com
Cc: kasan-dev@googlegroups.com
Subject: KCSAN build warnings
Message-ID: <20201106041046.GT3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=oc5sl4Oy;       spf=pass
 (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Hello!

Some interesting code is being added to RCU, so I fired up KCSAN.
Although KCSAN still seems to work, but I got the following build
warnings.  Should I ignore these, or is this a sign that I need to
upgrade from clang 11.0.0?

							Thanx, Paul

------------------------------------------------------------------------

arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106041046.GT3249%40paulmck-ThinkPad-P72.
