Return-Path: <kasan-dev+bncBDPJLN7A4MFRBBXTZSGAMGQEKHKP7TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D8A1B452949
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 05:54:31 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id d3-20020a056e02050300b0027578c6d9aasf12006237ils.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 20:54:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637038470; cv=pass;
        d=google.com; s=arc-20160816;
        b=TiMHylJfvjLqwOADBXSvvcXbuRn+2aLxflnEqhq7hcp9t9k+r08YYSLWYDUdo8cxlZ
         iu8Md9fJfz2tZHKZVN/QlHSs4pbkFueUmmwYNyTH5RTCiccV02kRk6aLFNYSFL7gb0SX
         YICiY4A7Mg/ygy97O07D0w5PvIJ/MYZlRh9DIKkpWaUITvD25q9gGcclUjdNtYVFxCUi
         p2RFhtqgJ+I7llsizlotiuimBoedY3XR5onffhQYiZeS6M+E3fFYSrWigyuUkkkxBmKr
         SJrK4DVraEZqGVICGOtRBWJh4h6ToJ75eSLrJTCzmZ1KWmCt0ooqUuNKaCbGkiYxw/2R
         oBOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:date:cc:to
         :from:subject:message-id:sender:dkim-signature:dkim-signature;
        bh=co9Voop+RmOdbaN5dj8BgM6h6mF2NQGJ+MuyNV/7OGY=;
        b=p0HQik5Y8zTwVNz1z7hwetIC8hQGjDf/Oy4Ws6F+NQhXw+vyzOnt6JWHMwr6hV97i+
         XEAv9b9jbO4mn97VCfhc8GkY0BnXm+WY92ON6OtlFgVmJ1PWycYivtWuX73NIN7oNiHh
         MIH2E8hbaYn/r/F2kGXFiRZwyyVkMm3n72g2WMPuiFZJCXFt0G49qyzPcVhNelZfigqj
         UDIkL2BX1kXZoZ9lo6VtXXwKb9l7W1iDrQdpDF2nozjE6U0asr53FZ98wj2eVAD5Eb0B
         hzUUcoDejR//qJco6t1EKXW6f3KRaBjtW24rCQ+AfPQBfF6mt2S+kRgD8Bqv+h26Wm0x
         VLMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=d8yxdZca;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co9Voop+RmOdbaN5dj8BgM6h6mF2NQGJ+MuyNV/7OGY=;
        b=Tc3uCUH5YluR+9sJqmIZKF+Dtou9Nh+i+8brAfW4QRXHjoa2eSzjuRNSx1hsoND7+H
         mU167qK9jKAHFk3fdBFIllLpsZEnBvDCr6n7NOelPhVlH22yQ1sYx+jswuZjKPWA2/sm
         s4XM1be4YIsmgrQsDJA/wjbpM7UmxsY+yawjD3IR0zmAoG4GP032uDieFR+VTz7BGAIs
         2HcXzSJQU6Bjv68otlULBg+hvcTCifo73906tFEkBT1Ik7C4MRFfTpM23Xguz8hNuoE5
         L1tcWn3PwVRthD0i0UAFAPwsyeWddXgV4WdQPV2JT3qYXZCbK6UOBz/T/YV3be2QPYR9
         JfnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:subject:from:to:cc:date:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co9Voop+RmOdbaN5dj8BgM6h6mF2NQGJ+MuyNV/7OGY=;
        b=o67ZtTKiADAkG47ZVpMIL2aeVu9z0GeZrsVbBZNP5WUb2QULA3a48X5Tclztm6/pyh
         iTz1b0jjg1k283y2M09gUmdZV5haAfc/H5JgMS7ELNXCmwwVAEN3HQWEhlUGcFvD2XOd
         5DKcoW/Dvo6c/3CubfG3Pc0Xc36OB6d2yBFbENuflYNLNEhMitkTc1REUTndqOEi0+Aa
         93Rm64UhXSotX0+IULXQWcmlMv6JkJDLHQljlhWKRbUBpCOx6xyNRGnU384mh7fYtt9a
         HIYMkxUNfuw2ozr5P3GgUPaj3ORO4qvR6vX/frgTWOD4zWvST++0wgpj23VkJNB6XIzR
         Jy4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co9Voop+RmOdbaN5dj8BgM6h6mF2NQGJ+MuyNV/7OGY=;
        b=JKlim0aqjbuRHGzmphmARkJ9z1fni/cokoq40bUu9mF90MUebhK9NaQ6lrfekhTkS2
         +5srJlo67Ry+OcuigH+i7pAqq3G1CqUsTSoPZWcXsbDpeaTpYWGy8zuj1MyhCYCs5H7y
         Q+cOEdwuWAHcYJFKW8qv4q8f/XkZsUS8cbix7UfxoOISGkDk0WUCWw7g8YAGOVUQy1K0
         cg8sr09t6Q5C8ioCl8QrogFgPNaCWNq2JYkyUfwyboGCZ5WX+IF7lWCAJDbXQDNJfDL3
         T/pbBX5jzdEs17ygzZAU83r+sJmA/qMG2G+YOyS3xkW3s9yVbchh6XAZ2r4kqfjqa8Om
         2ObQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530R9e6Quu0NDhAM4/avGg1269McsSQvPRNKZKvJVf71NliLq+dR
	LDAQZOiL2/KMOPSL4y10nx0=
X-Google-Smtp-Source: ABdhPJxezevcer0tZ8FZXmnfFaZdCBmxzfr6FAgPlYXRR3Natopzx9fJ58omPJ52Zd12P8jy14RmxA==
X-Received: by 2002:a05:6e02:1b01:: with SMTP id i1mr2589512ilv.53.1637038470685;
        Mon, 15 Nov 2021 20:54:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3401:: with SMTP id x1ls1876147jae.6.gmail; Mon, 15 Nov
 2021 20:54:30 -0800 (PST)
X-Received: by 2002:a02:cf06:: with SMTP id q6mr3132095jar.62.1637038470335;
        Mon, 15 Nov 2021 20:54:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637038470; cv=none;
        d=google.com; s=arc-20160816;
        b=ZvJEmpRdY9JhGoZ1Oi+LB1uoX8rXwZ3Utaz1RdQW/154vmeH0VWiZMtBflyyCse/52
         9nEqm/LeFE+UCvfI531mNcJ4ewYoIWXU6nost1hkRoUqvFOXfPXdcE2zrMzEWquAzjlL
         favFnaghL3UhAO0xgJl2sVJ4XAsh1yjkI8If7alW9S/7ZZIfeMRXv2YSTJLdW73vzqDW
         VETjGAnrlN9JR8AZHv5PNnqzizsjoghzBFEV38YssE3gdygbfDSgqimRBTfwKbK2Pnfk
         c7PMieBTy5vmu46XzaTv0CpGASdXsq7IQnLoD7MJp9aYMnlnJ+UQxLw5BjCN5vZnxInf
         Xqjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=aZEgCAw926fm0yLVJgfVRWVyzchDmo838PuZyVld5WU=;
        b=oAQYGdZEn04umxoEWIKobgdsEolcd4pjcXc39ExPlGAlO579OFZKHMFsckRDlJWI/j
         4bAI7c/7SZgz7yHaAHtqIH4gU5nNS1tyl6HmYXUb48JwdjrElr3SM3LqGtCabAKEatZk
         FSHkg9ltaM+tAnn4TzI5ob2doWH5zN0FJ5rUiodT3gx3c88x5cU9WxsKYAmf6rckyzD4
         JmgYeALST/OPu3+3QL7H9FtKCbS9gzD08Ny4fJE6Lcl2Cri00/YRYwulAgT3ZzPELYvD
         PeOzlcSo9lMRNmzQjz3+diOCp8Rjdn5Uh54BpSIFkg3eZ/xskIQpHE3DTdiYHBW/H0Vf
         t23A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=d8yxdZca;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id z11si944708iox.1.2021.11.15.20.54.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 20:54:30 -0800 (PST)
Received-SPF: pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id fv9-20020a17090b0e8900b001a6a5ab1392so1759436pjb.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 20:54:30 -0800 (PST)
X-Received: by 2002:a17:90a:c58e:: with SMTP id l14mr71339597pjt.214.1637038469308;
        Mon, 15 Nov 2021 20:54:29 -0800 (PST)
Received: from k7550 ([103.214.62.4])
        by smtp.gmail.com with ESMTPSA id t15sm16457886pfl.186.2021.11.15.20.54.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 20:54:28 -0800 (PST)
Message-ID: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
Subject: KASAN isn't catching rd/wr underflow bugs on static global memory?
From: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
To: kasan-dev@googlegroups.com
Cc: Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Date: Tue, 16 Nov 2021 10:24:25 +0530
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.5-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: kaiwan.billimoria@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=d8yxdZca;       spf=pass
 (google.com: domain of kaiwan.billimoria@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hello all,

I'm facing some issues when testing for read/write underflow ('left OOB') defects via KASAN, and am requesting your help...
Briefly, KASAN does not seem to catch the read/write undeflow ('left OOB') on a static global memory buffer.
First off, is this a known limitation?

More details follow, requesting your patience in reading thorugh...

1. Test Env:
x86_64 Ubuntu 20.04 LTS guest VM
Custom 'debug' kernel: ver 5.10.60
CONFIG_KASAN=y
CONFIG_UBSAN=y

Detailed configs:

$ grep KASAN /boot/config-5.10.60-dbg02
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=1
CONFIG_KASAN_VMALLOC=y
CONFIG_KASAN_KUNIT_TEST=m
CONFIG_TEST_KASAN_MODULE=m
$ 

$ grep UBSAN /boot/config-5.10.60-dbg02
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
CONFIG_UBSAN=y
# CONFIG_UBSAN_TRAP is not set
CONFIG_UBSAN_BOUNDS=y
CONFIG_UBSAN_MISC=y
CONFIG_UBSAN_SANITIZE_ALL=y
# CONFIG_UBSAN_ALIGNMENT is not set
CONFIG_TEST_UBSAN=m
$ 

2. I've written a module to perform simple test cases:
https://github.com/PacktPublishing/Linux-Kernel-Debugging/tree/main/ch7/kmembugs_test
(the book is in dev :-)...

It provides an interactive way to run various memory-related (and other) test cases; pl have a look (and try!)

Here's the test cases that KASAN does NOT seem to catch:
# 4.3 and 4.4 : OOB (Out oF Bounds) access on static global memory buffer.
I'm unsure why...

Here's the relevant code for the testcase (as of now):
https://github.com/PacktPublishing/Linux-Kernel-Debugging/blob/81a2873275bd400fd235dc51cdac352d9d5fb03a/ch7/kmembugs_test/kmembugs_test.c#L185

My testing shows that UBSAN clearly catches both the read and write underflow bugs, but KASAN doesn't. All other defects are correctly caught by KASAN..
(Am having other issues with UBSAN, which we can discuss on another thread :).

3. Also, I tried a similar testcase in userspace w/ ASAN and the global memory underflow bugs were caught... (with both gcc and clang).

Any help is appreciated!
TIA and Regards,
Kaiwan.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2ced905703ede4465f3945eb3ae4e615c02faf8.camel%40gmail.com.
