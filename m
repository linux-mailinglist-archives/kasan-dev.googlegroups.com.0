Return-Path: <kasan-dev+bncBCNIPF76U4DRBMGGWW4AMGQETLMMVOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 356B299D679
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 20:30:10 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-431159f2864sf23846265e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 11:30:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728930609; cv=pass;
        d=google.com; s=arc-20240605;
        b=DEuYJoYt5zPZyONmDj1pUEK77Z439PrS8wXa/u6nTS+jEaO7KyFBxQnCTMKOGbu5V4
         BtQcIJ8ZUXaJLnXuUh86vZKh+cFs9aTznicH6/Xkulfkg10cdCr8bPMBFq7EVIUMTC8s
         PbZmBZ0pUwC1/c4nfXDMeRC0ewbFPWacJReSzxFJNeJU7D4kwHrTwl9u0vJdYhCmHM0Y
         Zk/kdN5yrOK2hfdqduOxD3Rg5KK5S6otqinFC46Cq1BxTfi7E96RCOfGbwXDHfFP3LsP
         QxBTaaY6FH9h8na5NwVyR4UkcFYYt+PjisLi3L3EOaT4XKaryM5wOgt1AXkQZ1WjqUUP
         79kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=3nIUlGKhcO3vq4CMB5egCfKG86VC0VYjfj4M2QyrzD4=;
        fh=4yF3fnBvPlgMLHwiWFwJr3PGBVp0pjA+HT2NLqktleU=;
        b=MsTUqVQRKK3wS5gUMUDdnTOValsN3AgrrT3rpfLXOc7VZSiEaQ/n027+GIZVXfNVEV
         hw2wKI8+WhkNuOl4sfi0OGXFx8s2ANIKf3pzpxng+wlurhGdJX/AtrSQo4O5yZsL8ene
         py9N4Hv19Ou8CdMRR1OKsck1vyRlmH2UqT5MAxg4O1aN2FiC+tn1PPvtKgTZ5D2XPHl5
         oWDksW5dTBjXODW5yQKkp2QNPfJHYPtQcYMrGIYxkJWKSLJ1Mv9pG6N4mmiX/Mov3vA3
         +jbH5K/hx51ZsPq+STBNI/N4cJz1t3hvZ+jDip7zCgSdxOuLbJTAu0CGSBzWiJJ2GUNT
         gdwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JsE7Cu64;
       spf=pass (google.com: domain of pintu.ping@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=pintu.ping@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728930609; x=1729535409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3nIUlGKhcO3vq4CMB5egCfKG86VC0VYjfj4M2QyrzD4=;
        b=CGAapOxbzzI3S15zGaHKBhOm/qUHRL5RspFrbNr1KKnMokFyyPD6IIadOdCjB0SMgp
         mxgatL/c2XYbtfg4nRiZgay3vdJA5+Ktk74H2Ta0Wa4TIaJOLJPVOxgKquwwRl6/2SXq
         7meEDiy5ixdTtbMV6POE5T/SFkt0G9VutSxwDVhrN3ygQQED8SERGOU7EHg5dvvhto1Z
         QlCntYVuG0uXQd4Dk326Ew4penU50oK7z2oCaJjRI+MVgKUkJFxLfK34Qyn9/0pHOD7t
         AYg+FIApKXqaebBZvUO4vJl3AI3azrk2YQDx87SAchploz90QLg3Egd2lpEBvRGYGMci
         QNRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728930609; x=1729535409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3nIUlGKhcO3vq4CMB5egCfKG86VC0VYjfj4M2QyrzD4=;
        b=QP61sA5x3OUlasVFkCJCOVoAtLbD9mzr6/1zcNWr9geZHX6ULwygn2lF7Dor5Ccyrt
         8yhULMlm1rDE3Krd2iopn6QYv1oOHHg8pLWetUqzoVfbECFyZasw7GRgVhJ69Tl9AsRF
         SY8qZT+ybihInQKUB5P3sRq4ZYPAU+07tTrgzDspWctXfyxjM+S+9E4yVktFYmof6XT4
         rrMvoRHLJcQon6V3pGQ/zT9LbAhistsNazpYoZPTaSTxGrPYAvB0rvd5tyLoxEYOVXpI
         M9CoKyl75IoVkZRmIEIZaWU0g5UJpzILDu/TXyDAKY/1kX1ypdIw6FNMILn8W/YylpQW
         Y2bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728930609; x=1729535409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3nIUlGKhcO3vq4CMB5egCfKG86VC0VYjfj4M2QyrzD4=;
        b=PZFwWd0jrpHcmxvgBhMxUwo2tR5Rgbezz8gGToXcnPO1XbGxphW1mvRAPsKLbU/XZg
         4WBRj4Mw4CcUAiZtjpOQgvYp7MMGg3YrmrdkemF7HmBfRfaFt/joa5c9zqP7q+zvEPbi
         HUO5SFpNLERFAgGEKmPuVlT088K+X224j0uLwAh8vfgNXIW0MjrvxVWvOCLLIGR1L9XC
         eIRqIwnsCyZSwlrckn5gMSANxu1faso8G0ZKf2HeZdlqrauwHSjpgGVrbqMGnVA6Je6K
         ByWyNG75hrD1jKUUK8xNVvKAJuL45ad7AMbuvrg+635MUVXoNmrZng+WUvsVZnV9G46v
         bqIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4PV9vdYpdjU2+XGSVbu1OUjV6Ak1Cc8cG+lBxNVSCy3HYXUTDeOE5MF8J2r8G4wdDsQmqPw==@lfdr.de
X-Gm-Message-State: AOJu0Yx6gaEU17hWUzbyRu4PbLvpK6WHR4+8mbv+52iMjrOV6iWuuS4Z
	jCuo7paig5BlTzwZWrWQdQc7MEXlNKHnBXeThqJhh0T5V9J10HfQ
X-Google-Smtp-Source: AGHT+IEZ13VS248SVr8h448ncIvlhFPiCLd5X/yfxzj+VWbNXbRDmUu6FjQSE9vIdOLXuSg+f+iaYg==
X-Received: by 2002:a05:600c:3ba0:b0:42f:310f:de9 with SMTP id 5b1f17b1804b1-4311deebe1dmr93110915e9.15.1728930609241;
        Mon, 14 Oct 2024 11:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8a:b0:430:5356:acb2 with SMTP id
 5b1f17b1804b1-43115f154e5ls10128855e9.0.-pod-prod-08-eu; Mon, 14 Oct 2024
 11:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuq5+d52woPGxZt8mfS/uZcXDnvroqBjk/lcjC1RIK2MWytt6saNEo6t4gvojq//3WhEezJnrxZvc=@googlegroups.com
X-Received: by 2002:a05:600c:354d:b0:42f:8515:e482 with SMTP id 5b1f17b1804b1-4311ded53d6mr107797665e9.9.1728930607060;
        Mon, 14 Oct 2024 11:30:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728930607; cv=none;
        d=google.com; s=arc-20240605;
        b=k9O5lHXBArODDZ7IUKkFK7rYUq2isw36Cpq6QaQNOsJfCEG2wokfNMPXl/WWm493gS
         FSFCa62HQMaT+n6cQfQO4b3o403ktYh0ftxiCoHJ4V2X7CmqDDXPp+vWBY0Z2fdv2+w4
         b+mCjjtklLQTvN8MewKobmBMDUE2hs/IJeryp979VHSaYmXCU8U+HNd85rEVk0yfv2Ha
         VUjCdl2UtikKtdODqdG+p10psrH79WOyYv544prG1drhmiiC5gfm4oMcH/HGA9iWzgq4
         DYpFgqa+w3JgYlHOXYNKaMhEnDnKHpSZ3nLdqSb0SOCvKLMAVEGGK3ZnoR0pw7Nxal+3
         +XEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=3QkTnAiV+3esa+l0366W5UFrQrdTGMXa4ntu5IK1OiQ=;
        fh=synO5PTiO1n8EAk70shw2jiMLDXAWsZUCOK7aGMA3t0=;
        b=JNU4yBTDBlaE9DOJdEKdXu3jfcif6bWSKsarFGHIERMdYU5yVT1qzeK/XaDo51Z3bK
         2jPD/BefBASMVZlvnXSizfom/hi7mXUnLK0p1HDV432c8UtDezrKt0kF/d9DCEensgyp
         VeyjaXMGVQXbFSShWgHEf+xWa1hmBn+WiGmfKGYDxIqp5Zb05S3WxZwyXaGXVKOIfFlx
         Z1VdiSIg1ULzcuc6CDLlzn9h6s5cX8UWGN8RRE9919IITVzFxWtelqe12uw8MDtTvmXu
         Sf0wYgIyfMgdN7hM1EM+AClbR4UIfQQ5u09Pg9s/C9cV3CDqmlFtOPyq4I6YNo8zKLJS
         cU5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JsE7Cu64;
       spf=pass (google.com: domain of pintu.ping@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=pintu.ping@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4304ecf88d7si6230835e9.1.2024.10.14.11.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 11:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of pintu.ping@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5c96b2a10e1so2940602a12.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 11:30:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUDd+ZmKw86fJRw+R5zlbYFdBqrC6J0qKlSCt1bqsFyMvtQeAaEycho59xNy+cwjl5y6dkrxXSpOtE=@googlegroups.com
X-Received: by 2002:a17:907:9810:b0:a9a:ad8:fc56 with SMTP id
 a640c23a62f3a-a9a0ad93126mr471010966b.44.1728930606357; Mon, 14 Oct 2024
 11:30:06 -0700 (PDT)
MIME-Version: 1.0
From: Pintu Agarwal <pintu.ping@gmail.com>
Date: Mon, 14 Oct 2024 23:59:54 +0530
Message-ID: <CAOuPNLgOtRUUokXX=FvOJmfuNzkiVPaP78xHs5uC5PfaRd_1Ew@mail.gmail.com>
Subject: checkpatch issue: stuck on file mm/kmsan/kmsan_test.c
To: glider@google.com, elver@google.com, dvyukov@google.com, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Shuah Khan <skhan@linuxfoundation.org>, Joe Perches <joe@perches.com>, apw@canonical.com, 
	Dwaipayan Ray <dwaipayanray1@gmail.com>, lukas.bulwahn@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pintu.ping@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JsE7Cu64;       spf=pass
 (google.com: domain of pintu.ping@gmail.com designates 2a00:1450:4864:20::52f
 as permitted sender) smtp.mailfrom=pintu.ping@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hi,

This is to report that when I run checkpatch on a file
mm/kmsan/kmsan_test.c the checkpatch gets stuck and never returns.
I am using the latest linux-next repo.

linux-next$ ./scripts/checkpatch.pl -f mm/kmsan/kmsan_test.c
[stuck]

Not sure if it is the issue with the file or the script.
If there is any issue with the file, please let me know I will try to fix it.


Thanks,
Pintu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOuPNLgOtRUUokXX%3DFvOJmfuNzkiVPaP78xHs5uC5PfaRd_1Ew%40mail.gmail.com.
