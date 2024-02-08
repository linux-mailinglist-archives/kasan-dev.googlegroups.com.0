Return-Path: <kasan-dev+bncBDTMJ55N44FBBVVSSSXAMGQEFQEU4XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76F3584E770
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 19:11:36 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5114f2a1e81sf60407e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 10:11:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707415895; cv=pass;
        d=google.com; s=arc-20160816;
        b=M7ntE2r55K4tUri64bpfC1HDBQWZHMz42LbC8TqsSFH3zYJ0oIJ1uH/+uIwpgApBXe
         py1NnWHbfixcuaCcqIxgB/C27D/Sqm4fsaVTzhMVtfF4iEv7afsYeDne8vl5e2mmEiWw
         AGCfynzPV30OXlohz9pXUouYiVzVTRUSs2lWRJNaw+6CHSKtimMi0LLzEZDgyZe0Hd5f
         2CGGn9uXA+GG6BtaKFwaBJlwFaWBuY8c9eoo7SqXDIE4ccbWMHNSmvOBsP33H/2ANu9W
         Y9aXJwNaoyRt3DNlBBNsAkSv8ACvyEOYGbluMRBW/ZegXumMyPpWwuclY8ZstHiH/r07
         Zcmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=F3ISVOYAViADpQdr8hnWuubFlMTUF6xMxqc9G7Cdv7o=;
        fh=luc9NBebwFYceMZe0JzdRr40+KnW6LqBCilV2Y/aq3c=;
        b=BviiuM54fUl7pw1XmE8Ghbzy+YoZ1YgmnjSuOLanSVFVtO1uvEHKyTOar0YAt7v56J
         tk2xSqfW0ITlDxyW1HUfLIJBqBE0fT7BUqDSx6AK+irvqf1B+hpC27TXy1yH5jDycWzk
         TJ9DhErkiM/EBcPV9b4d+YJbl1Ei96n8Bvkd6lurxwtnoATFhTH+acFVELfHizeyxH5l
         mkE7l7M6vPGnF343/QXlkfnML98mGLVtxlMssbMf1MzVhyJ3kNTeLe8XsFzJLV5r8etl
         1uP/wLsZDLPuZsVJ80OVN+Vk0PDswjONNUsDX7q16sID68TNs8aZBRdakjOHvnEp48Us
         ft1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.51 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707415895; x=1708020695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F3ISVOYAViADpQdr8hnWuubFlMTUF6xMxqc9G7Cdv7o=;
        b=aK4scxa5T8u4tiy6oTJ5Gh94o6sg2UDU7pNdAqkzqpx7au6xt3eyTNFDyuQAvylJBD
         9rw7y9CyTwJi2ivSwPhQt03WUvzFI+X1PlAcd2N7q1wOPKsSAVP3UkxC4D/Pm6Pjtd9l
         2eSR4zdW03uCO4XGojvGRVA3u9aHgZ/Pv6LikNwM8TPkjB4eL4eNaNu9vNo6c05hBOwv
         +ZJuW+CN/kPXi0FKFcsmyvq2HFCS69Y2eDl6jdUjWx1WzB4WQfX01/rISoSFog5hPKZ9
         nQpM2KlnviVnXGMgw5F+b33Q8VPhNpfycRIDf0e1t+AKONhLQskDuYhSffqVGOOX8Mn5
         T9RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707415895; x=1708020695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F3ISVOYAViADpQdr8hnWuubFlMTUF6xMxqc9G7Cdv7o=;
        b=ZRBzZXj23IhUDhQSAOovgWOY4N5EVwx0g8lwS6ucScu7s1gxkV6dqRzYzIDfxtw/Og
         f/Z0vVxNinmpaVRFyHBCwJSHyGP9FHYFv5LGSw8IUEOQuYhcUdjuTZGif+gq1SLjHscY
         cB3vUi5pATtUtKdLEd31G/zb5fDRM994kumP7idqvg2XiefKMDIX5LoCEMOOmi6HIHie
         /0Vpsohc6YN9xYq7ecCyFUWlPnOkxU8GWwltTBNO66vsnMkGWAWWnB0kYc5gJa+a/8tD
         vFOU2pjyoYi6+ccC4KVcv+hmCOf1SFhfJNMju/qmA6xmVM923XNlzAkytqEp5tWZOQRR
         0Psg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV50eRlI/lVqGxgcFUpkmHtXIGQHmRResMNo3+Ia29+JlQvPGd+xMrr7Cx+vCgiKcXWNPZZU9GK/08agPjqyLwowlOfaw/gNg==
X-Gm-Message-State: AOJu0YyNJXnAnGJCiUVdR1SnkPa9MsuFgeCs742MhVAabdbtJNeDyS0c
	FIU53ZVewKW6LVT9U6CnvYD98aAEiph9GEvqpEiOxWgrJvgJ92FB
X-Google-Smtp-Source: AGHT+IF+KlmyKSRctP1Ub+BPQWJ3LNfgqdH29KkRiG1rzbFSX0sOTpPqZ83QnoJI+gQyu2Zk7PTBBA==
X-Received: by 2002:ac2:4d01:0:b0:511:3446:f6bf with SMTP id r1-20020ac24d01000000b005113446f6bfmr17318lfi.55.1707415894505;
        Thu, 08 Feb 2024 10:11:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:42c8:0:b0:33b:5b10:ace3 with SMTP id t8-20020a5d42c8000000b0033b5b10ace3ls14172wrr.1.-pod-prod-02-eu;
 Thu, 08 Feb 2024 10:11:32 -0800 (PST)
X-Received: by 2002:a05:6000:10d2:b0:33b:5590:c0d8 with SMTP id b18-20020a05600010d200b0033b5590c0d8mr205233wrx.8.1707415892474;
        Thu, 08 Feb 2024 10:11:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707415892; cv=none;
        d=google.com; s=arc-20160816;
        b=ol4Drhjm3vI7BAVb4TaGrLorV/1R+ZUrbI2g6blQjV6uWkPKQRlds7OvSw544Mru+7
         QiZBE7j2lCjrFNvKzkKWsNUxSIdwoB55AQFZrL/UltrqMlvXO1vKLeKU791VJbLsn8EX
         IdGY9getS/ql4T+T+jf2E12h3S+YrFEG+UgTPX5J80SyKJFmLN/H0c70yeFPsfwkIWiz
         ARzUQfnrckqemEfmwRnMfOF/a2D+aWygrHAXvFqdtFnxjzCQ0ZuBTijAwc7P8O9hS8oz
         mRh81lIDy13A/EJDOJFnhm/+HbusA8tJOrk8+lOc/W6IkeMET1OJ3VrjA/iJFheJ3Cm7
         HiPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:to:from:date;
        bh=CIN9TPXY1tGaFZdSGYZNVOfYN+oochGBiUqEQIDpAdM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=dPF7zzoM7R2v4rT6kdvI4cx89oV14LyLYPgBX+ZSz0pJVd/5Cn/sHJP2cwByimVryv
         mX4RPRi+XQyqCfX6N7f7I2egSdALZLB8nIWTst5luikylXesiZ3tla6xfhmcZhzxslaw
         QHbFaz3I0bs+FroWY3Bix+x1v5JfAjVyY+BfUoUXLWpztUuQdA+U+CSV3IYoea+K6sgp
         L7LXAaNl5aAiDHN7bBqXNHySqW2xGcJ0ansxEFzVzW95Z6ymBmEflEHo/nMADcvJ+4Ut
         HzCDze4r6Q42kZorNw7SH7HsTX4EeWCoMtTAE5xker8JOhHYK2V9qUIi915aEhVu+gqc
         H82g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.51 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f51.google.com (mail-ed1-f51.google.com. [209.85.208.51])
        by gmr-mx.google.com with ESMTPS id a16-20020a056000101000b0033b1589d9c3si259368wrx.0.2024.02.08.10.11.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Feb 2024 10:11:32 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.51 as permitted sender) client-ip=209.85.208.51;
Received: by mail-ed1-f51.google.com with SMTP id 4fb4d7f45d1cf-556c3f0d6c5so193679a12.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Feb 2024 10:11:32 -0800 (PST)
X-Received: by 2002:a05:6402:1b03:b0:55f:c995:6d69 with SMTP id by3-20020a0564021b0300b0055fc9956d69mr29749edb.10.1707415891150;
        Thu, 08 Feb 2024 10:11:31 -0800 (PST)
Received: from gmail.com (fwdproxy-lla-117.fbsv.net. [2a03:2880:30ff:75::face:b00c])
        by smtp.gmail.com with ESMTPSA id a15-20020aa7cf0f000000b0055fed0e2017sm1062564edy.16.2024.02.08.10.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Feb 2024 10:11:30 -0800 (PST)
Date: Thu, 8 Feb 2024 10:11:28 -0800
From: Breno Leitao <leitao@debian.org>
To: kasan-dev@googlegroups.com
Subject: KASAN: MemTotal 1/8 memory hide question
Message-ID: <ZcUZUIlJUsag8qMt@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.51 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello,

I am extensively using Kasan to test the kernel, and it works great.
Thanks for all the work.

Problem
=======

In a hyperscale environment, one downside of running kernel with KASAN
configured in random production machines is the fact that it hides 1/8th
of the memory from `/proc/meminfo` MemTotal.

This is a problem because a different scripts trust procinfo's MemTotal
for several reasons. 

One classical example is "machine checker" scripts, which are some random
scripts that run in production machines and assures that the machine
has the expect amount of RAM available, otherwise send the machine to
repair because some memory is missing. These scripts are looking for RAM
sticks that are unplugged, or, bad RAM sticks, etc.

Teaching these scripts to look for kernel configuration (KASAN
enabled/disabled) before reporting such problems seems hard given the
amount of scripts that trusts /proc/meminfo MemTotal.

Question
========

To make the usability easier to deploy Kasan, I am wondering if it is OK
if I add a build configuration (Kconfig) that tells KASAN to *not* hide
the available memory from MemTotal, so, whoever blindly trusts MemTotal
continue to work fine, and make the KASAN experience a bit smoother.

Thank you
Breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZcUZUIlJUsag8qMt%40gmail.com.
