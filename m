Return-Path: <kasan-dev+bncBD64ZMV5YYBRBYMKVG2QMGQETCO6QVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id ED8F79431AC
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 16:08:35 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-70932abea64sf4214680a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 07:08:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722434914; cv=pass;
        d=google.com; s=arc-20160816;
        b=UiodatsOepdXSlF7vVNCXxSF2jceRiNE5hGpz+O7kvrAhnPSWxQLOC0lYGZZENpJGs
         Li7U9TLRoVQk8buQ/Fo+Je2ElOXeyf32VKuz2l5NYRGIiT6IgreeBR99y1IUnA6ntV7R
         AAtnH4IWd5oj6k95bXj/WHjVK4McdsUbQg3h2td4cVOdEITUK0dVlNxsRUD2uzoXKocQ
         yc0EFUD7jGlVUiMkNOB6E4v8LEbUuA1L0a2yOnyneRh54HqIPs3jdgj9Zj5oc9Wns5dy
         5gaVp7JLiNkPZ3cdaUYmlS78HB7izkCW9g7vZlVdG9vQ99v22nNR5KcNoW5WYVGwHZjv
         qhtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xtRHL47cvr3qmau1QNBiuG4T/2VNbhi4JNJdmCHr1QA=;
        fh=XiI4MAPg1Te0eR3oDUsghrWuKBiKVpSR0yvlFzTNPHc=;
        b=HNbNLesP2uc4BNd569y6WnximGjHHxqb7E5Yty5Lm4hZKkkx+MOaBDxdRgtVyibWDk
         MP92bXvkwoEdeAEKoy6ks8jLdxAATNzTDuK+pXIoIFOaVmq9RJS4O0kpRBT1WPA63VvG
         MFad5GkhA3tyAL+MxY53UCCUccU0rLeQWUD6//t8Q7o1pqVSuESUYoutiABBJh8+n12y
         3II2VYzXoMPh07EB5TYZ79+pTlSmGAW6Kf/DxHGDFYJWg51qpglOpFCjTU7Efm9odCNR
         tRj7XBN4rFiJkSt/xfEoZf07Kpwuw8gu16VW7R0POd4EnPfKiavBJTSQRpaW6cpYOsDU
         LKiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rowland.harvard.edu header.s=google header.b=LB8slC+x;
       spf=pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722434914; x=1723039714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xtRHL47cvr3qmau1QNBiuG4T/2VNbhi4JNJdmCHr1QA=;
        b=deJFJf5TmwTEV47g4V+pi0xRFVOhRyWjqGtFTHo8aIBdohTxc/NCsvOsJ3AD1bYaXN
         xire6SlYW+Is2llCs3Nvk8dO1XYydqEQQhv7mgvAxqPUbGScRuCM8bZj1uWjgTEZuAMy
         M+2nqERJPcoql0tTQS99Wwsf/KHQQIOyTQTdAePlOrUE7ZzWkwnPsdBnR8ANssuYG660
         LgezcCf5CTOcsRdrKPZhc4qllG4fDa1RSVcf0IIr6DS773oK/sZ5jzN1p5SJrdauPhw2
         ni6o7UKSco8ySvbZvmTntm/RUzVgRTDitwjE+nZ0a+kzE4PpP2czBkEa93TXzgNXxSQL
         fHww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722434914; x=1723039714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xtRHL47cvr3qmau1QNBiuG4T/2VNbhi4JNJdmCHr1QA=;
        b=Wa7BpH3/6nsfol8s2NkZhFdTCdKD00FKeLQGARzRx9HjENPqQzHZlCThJGwgPpxHPs
         3+xlbg4fzlpbljmUG4YuBbqSEQj2Vclc8OmKu0WhXBNqtrwiv20Huc2PcsHrjhCqqiNH
         YZV8u6ya7B/kJUE1a10znQTuwA5ESSVzsApVuNZLY17S+yNKAq0Jplmx0f8qukwfeFf/
         Oz+97UTlTZ/vfJHEaiso0NDEiN0wQn2dHMa+qNF/P1N3/L4zLo1okvks+b7HrY6vOoTJ
         wwmDJxjklKIxULZ7jYzXhuIa8edfBjxDlnnfJAvTlY7Mb8p/BCVH+LUpyr7aDkTx4gaj
         iurw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIksvgWl4v10yURYhBOSBvdQYYe0qByzpj4x3M8DluoWmFlUVc+8/0+WjiITZWSEIwW/rKMCzG+77ApY5yPDuqQbWLGU8nKw==
X-Gm-Message-State: AOJu0Yw5iw22lakUMIW8WDne2JXogrDqYYL7bAryxBayaLlUTFzQgOH/
	bIjZQdb3VjANYmDDfAime7jmd07PASy0g2D9tYNd+JG7UCWj+uUy
X-Google-Smtp-Source: AGHT+IHIvNXzDkhZc1fAkd8SONovp89MkMipRoF4iB0SSM9fLfvF0ImHldcf87HMdmFwS31HnWRxGA==
X-Received: by 2002:a05:6830:3707:b0:703:7821:d9e with SMTP id 46e09a7af769-70940c98bbemr18501275a34.30.1722434914136;
        Wed, 31 Jul 2024 07:08:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3059:0:b0:5c2:1c26:de10 with SMTP id 006d021491bc7-5d5ae8db2b9ls6194726eaf.1.-pod-prod-04-us;
 Wed, 31 Jul 2024 07:08:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5/nXRqOAEP3DjvUEQ1os+wqW0k7mfUJgUL2ZKd8BtK9WtirdA9FM8OQGeH5S0hUuuJGcbEZTE2bzKmB2xdW6GM6ivNaM5umsx8w==
X-Received: by 2002:a05:6820:502:b0:5d6:1082:4f4d with SMTP id 006d021491bc7-5d6108252dbmr2982794eaf.4.1722434913148;
        Wed, 31 Jul 2024 07:08:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722434913; cv=none;
        d=google.com; s=arc-20160816;
        b=gwZhc9YtOTdNp/2+RYs5Io/LE3OzZoMa7vFOcN4fjQ/WEAzYBSTBMJDPM9O+ZOMrfh
         a3Kd4RlDTxOMQTMp42sufkbs1iD1V01lXZ5Q1E/sRmuiuBourwvqzdA9la0FZGdDWfbM
         YCjteY7T/bUYU199wWE8Hd2fWv+KjH88y7kmqHZkC+6YBw0M/13weS99Djla2lbVdAGt
         qyLjphqMyWzqbNq4cKSPK9ejLcTOhxGlg6HOOa2N1uP9NZqqzS1DqBvfduH76qr/3eC3
         IilRXHo60743ImhpEknXuYORzljzGfBMMXgr+qFptKdlpXphqIQ99yziJ9MTcvFxHzlC
         p1TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OmbqZ+SwBt9pWBiENqDvPp5IsdPjBdZOSucm6Q9PEz0=;
        fh=PgO7zr9u36QOF06Kr3OjqHhUomKoc2Wr8En1raDrvjY=;
        b=NMW+DufJmjxmUtZoNtndDQUGVrfPRayZ5pEypxWUSSZXVijsdpz7y2s76btC0RhViO
         wFGGxjm4XZZFfS2r0wrKMLEU+u+Szf6W+MiZ1TlNV16a8nFJvt6XtnugwaFO3LMNmP22
         VjJXgxz/iV9NwzJcUbIw9eTkOt3ZVnfINldclWGBW2kphL+/kmRoHCzAw4wOhbROQ7l8
         iPRnsjb/xNFazdkIGELHD43weYCQKJeBlZge+ZOc/vSorQsnF9yLaxfsyT6Tti+gG3V/
         3BwQAIepolNIdAXLP01mLkRbUpxL9gs7zbnKWg1uc1x0YhNAaQ5dzIPt2NKot2x9agms
         O+xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rowland.harvard.edu header.s=google header.b=LB8slC+x;
       spf=pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5d5b3650500si516981eaf.2.2024.07.31.07.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 07:08:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id af79cd13be357-7a1d81dc0beso375812385a.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 07:08:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUl4Xe+9kIHuOh+cxhkfTsAer92773IOCAL6iF0eazOjHhVEg/txo+AU0akXkKdqYV3wKqQQFJ9CVmcg2plt4vbvb8g4SWj/ckUMg==
X-Received: by 2002:a05:620a:4143:b0:79f:10e6:2ee with SMTP id af79cd13be357-7a1e5260140mr1740167585a.41.1722434912481;
        Wed, 31 Jul 2024 07:08:32 -0700 (PDT)
Received: from rowland.harvard.edu (iolanthe.rowland.org. [192.131.102.54])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7a1fdd2f90csm210796285a.24.2024.07.31.07.08.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Jul 2024 07:08:32 -0700 (PDT)
Date: Wed, 31 Jul 2024 10:08:29 -0400
From: Alan Stern <stern@rowland.harvard.edu>
To: syzbot <syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, brauner@kernel.org, davem@davemloft.net,
	dvyukov@google.com, elver@google.com, glider@google.com,
	gregkh@linuxfoundation.org, hdanton@sina.com, jhs@mojatatu.com,
	kasan-dev@googlegroups.com, keescook@chromium.org, kuba@kernel.org,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-usb@vger.kernel.org, luyun@kylinos.cn,
	netdev@vger.kernel.org, pctammela@mojatatu.com, rafael@kernel.org,
	syzkaller-bugs@googlegroups.com, victor@mojatatu.com,
	vinicius.gomes@intel.com, viro@zeniv.linux.org.uk,
	vladimir.oltean@nxp.com
Subject: Re: [syzbot] [usb?] INFO: rcu detected stall in __run_timer_base
Message-ID: <3eb71b17-33c3-42fa-86e6-459c3bfdbf29@rowland.harvard.edu>
References: <00000000000022a23c061604edb3@google.com>
 <000000000000d61bb8061e89caa5@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <000000000000d61bb8061e89caa5@google.com>
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rowland.harvard.edu header.s=google header.b=LB8slC+x;
       spf=pass (google.com: domain of stern@g.harvard.edu designates
 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 31, 2024 at 04:57:02AM -0700, syzbot wrote:
> syzbot suspects this issue was fixed by commit:
> 
> commit 22f00812862564b314784167a89f27b444f82a46
> Author: Alan Stern <stern@rowland.harvard.edu>
> Date:   Fri Jun 14 01:30:43 2024 +0000
> 
>     USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages
> 
> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=14f906bd980000
> start commit:   89be4025b0db Merge tag '6.10-rc1-smb3-client-fixes' of git..
> git tree:       upstream
> kernel config:  https://syzkaller.appspot.com/x/.config?x=b9016f104992d69c
> dashboard link: https://syzkaller.appspot.com/bug?extid=1acbadd9f48eeeacda29
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=145ed3fc980000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11c1541c980000
> 
> If the result looks correct, please mark the issue as fixed by replying with:
> 

#syz fix: USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages

> 
> For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3eb71b17-33c3-42fa-86e6-459c3bfdbf29%40rowland.harvard.edu.
